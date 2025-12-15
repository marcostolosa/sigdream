#define _GNU_SOURCE
#include "sigdream.h"

#include <elf.h>
#include <openssl/rand.h>
#include <openssl/rc4.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define ElfW(type) Elf64_##type

typedef struct mem_range {
    void *start;
    size_t size;
    int prot;
} mem_range_t;

/* mov eax, 15; syscall */
static const unsigned char sigret_gadget_eax[] = {0xb8, 0x0f, 0x00, 0x00,
                                                  0x00, 0x0f, 0x05};

/* mov rax, 15; syscall */
static const unsigned char sigret_gadget_rax[] = {0x48, 0xc7, 0xc0, 0x0f, 0x00,
                                                  0x00, 0x00, 0x0f, 0x05};

static void *g_stub_addr = NULL;
static void *g_ret_addr = NULL;
static uint64_t g_saved_rsp = 0;
static uint64_t g_saved_rbp = 0;

static void init_srop_frame(srop_frame_t *frame, uintptr_t fn, uint64_t rdi,
                            uint64_t rsi, uint64_t rdx, uint64_t rcx,
                            void *next_rsp) {
    memset(frame, 0, sizeof(*frame));
    frame->pretcode = (uint64_t)g_stub_addr;
    frame->uc.uc_mcontext.rdi = rdi;
    frame->uc.uc_mcontext.rsi = rsi;
    frame->uc.uc_mcontext.rdx = rdx;
    frame->uc.uc_mcontext.rcx = rcx;
    frame->uc.uc_mcontext.rip = fn;
    frame->uc.uc_mcontext.rsp = (uint64_t)next_rsp;
    frame->uc.uc_mcontext.cs = 0x33;
    frame->uc.uc_mcontext.ss = 0x2b;
}

static void init_restore_frame(srop_frame_t *frame, uint64_t saved_rsp,
                               uint64_t saved_rbp) {
    memset(frame, 0, sizeof(*frame));
    frame->pretcode = (uint64_t)g_stub_addr;
    frame->uc.uc_mcontext.rip = (uint64_t)g_ret_addr;
    frame->uc.uc_mcontext.rsp = saved_rsp;
    frame->uc.uc_mcontext.rbp = saved_rbp;
    frame->uc.uc_mcontext.cs = 0x33;
    frame->uc.uc_mcontext.ss = 0x2b;
}

static inline __attribute__((always_inline, noreturn)) void
trigger_sigreturn(void *frame) {
    __asm__ volatile("mov %0, %%rsp\n"
                     "xor %%rax, %%rax\n"
                     "mov $15, %%al\n"
                     "syscall\n"
                     :
                     : "r"(frame)
                     : "memory", "rax");
    __builtin_unreachable();
}

static void *find_gadget_in_region(void *start, size_t size) {
    unsigned char *p = (unsigned char *)start;
    unsigned char *end = p + size - sizeof(sigret_gadget_rax);

    for (; p < end; p++) {
        if (memcmp(p, sigret_gadget_rax, sizeof(sigret_gadget_rax)) == 0) {
            DEBUG_PRINT("found sigret gadget (mov rax) @ %p", p);
            return p;
        }
        if (memcmp(p, sigret_gadget_eax, sizeof(sigret_gadget_eax)) == 0) {
            DEBUG_PRINT("found sigret gadget (mov eax) @ %p", p);
            return p;
        }
    }

    return NULL;
}

static void *find_ret_in_region(void *start, size_t size) {
    unsigned char *p = (unsigned char *)start;
    unsigned char *end = p + size;

    for (; p < end; p++) {
        if (*p == 0xc3) {
            return p;
        }
    }
    return NULL;
}

static int scan_libc_for_gadget(void) {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps)
        return 0;

    char line[512];
    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, "r-xp") && strstr(line, "libc")) {
            uintptr_t start, end;
            if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
                size_t size = end - start;
                void *gadget = find_gadget_in_region((void *)start, size);
                if (gadget) {
                    g_stub_addr = gadget;
                    g_ret_addr = find_ret_in_region((void *)start, size);
                    fclose(maps);
                    DEBUG_PRINT("using libc gadget, ret @ %p", g_ret_addr);
                    return 1;
                }
            }
        }
    }

    fclose(maps);
    return 0;
}

static int init_stub(void) {
    if (g_stub_addr)
        return 1;

    if (scan_libc_for_gadget()) {
        return 1;
    }

    fprintf(stderr, "no sigret gadget found in libc\n");
    return 0;
}

static int get_prog_base(sigdream_ctx *ctx) {
    ElfW(Phdr) *phdr = (ElfW(Phdr) *)getauxval(AT_PHDR);
    if (!phdr)
        return 0;

    ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *)((uintptr_t)phdr - phdr->p_offset);
    ctx->prog_base = (void *)ehdr;
    DEBUG_PRINT("program base @ %p", ctx->prog_base);
    return 1;
}

static mem_range_t *get_pt_load_ranges(void *img_base, int *num_ranges) {
    ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *)img_base;

    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "invalid ELF header\n");
        return NULL;
    }

    ElfW(Phdr) *phdr = (ElfW(Phdr) *)((char *)img_base + ehdr->e_phoff);
    int count = 0;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD)
            count++;
    }

    mem_range_t *ranges = malloc(sizeof(mem_range_t) * count);
    int j = 0;
    int page_size = getpagesize();

    for (int i = 0; i < ehdr->e_phnum; i++) {
        ElfW(Phdr) *seg = &phdr[i];
        if (seg->p_type != PT_LOAD)
            continue;

        int prot = 0;
        if (seg->p_flags & PF_R)
            prot |= PROT_READ;
        if (seg->p_flags & PF_W)
            prot |= PROT_WRITE;
        if (seg->p_flags & PF_X)
            prot |= PROT_EXEC;

        ranges[j].start = (char *)img_base + (seg->p_vaddr & ~(page_size - 1));
        ranges[j].size = (seg->p_memsz + page_size - 1) & ~(page_size - 1);
        ranges[j].prot = prot;
        j++;
    }

    *num_ranges = count;
    return ranges;
}

static void get_heap_range(mem_range_t *heap_range) {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps)
        return;

    char line[256];
    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, "[heap]")) {
            uintptr_t start, end;
            if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
                heap_range->start = (void *)start;
                heap_range->size = end - start;
            }
            break;
        }
    }
    fclose(maps);
}

int sigdream_init(sigdream_ctx *ctx) {
    if (!ctx)
        return 0;

    memset(ctx, 0, sizeof(sigdream_ctx));

    if (!init_stub())
        return 0;

    if (!get_prog_base(ctx))
        return 0;

    ctx->initialized = 1;
    DEBUG_PRINT("sigdream initialized");
    return 1;
}

int sigdream_sleep(sigdream_ctx *ctx, int seconds) {
    /* capture stack state for return after srop chain */
    uint64_t frame_ptr;
    __asm__ volatile("mov %%rbp, %0" : "=r"(frame_ptr));
    g_saved_rbp = *(uint64_t *)frame_ptr;
    g_saved_rsp = frame_ptr + 8;

    if (!ctx || !ctx->initialized || seconds <= 0)
        return 0;

    int num_ranges = 0;
    mem_range_t *ranges = get_pt_load_ranges(ctx->prog_base, &num_ranges);
    if (!ranges)
        return 0;

    mem_range_t heap_range = {0};
    get_heap_range(&heap_range);

    unsigned char key_bytes[RC4_KEY_SIZE];
    if (RAND_bytes(key_bytes, RC4_KEY_SIZE) != 1) {
        fprintf(stderr, "failed to generate RC4 key\n");
        free(ranges);
        return 0;
    }
    DEBUG_PRINT("generated rc4 key for this cycle");

    RC4_KEY rc4_key;
    struct timespec ts = {.tv_sec = seconds, .tv_nsec = 0};

    /*
     * chain layout:
     * 1. mprotect regions to RW
     * 2. RC4_set_key + encrypt heap
     * 3. RC4_set_key + encrypt regions
     * 4. nanosleep
     * 5. RC4_set_key + decrypt regions
     * 6. RC4_set_key + decrypt heap
     * 7. mprotect regions back to original
     * 8. restore context and return
     */
    int total_frames = (num_ranges * 4) + 8;
    size_t frames_size = sizeof(srop_frame_t) * total_frames;

    srop_frame_t *frames = mmap(NULL, frames_size, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (frames == MAP_FAILED) {
        free(ranges);
        return 0;
    }

    int idx = 0;

    for (int i = 0; i < num_ranges; i++) {
        init_srop_frame(&frames[idx], (uintptr_t)mprotect,
                        (uint64_t)ranges[i].start, ranges[i].size,
                        PROT_READ | PROT_WRITE, 0, &frames[idx + 1]);
        idx++;
    }

    init_srop_frame(&frames[idx], (uintptr_t)RC4_set_key, (uint64_t)&rc4_key,
                    RC4_KEY_SIZE, (uint64_t)key_bytes, 0, &frames[idx + 1]);
    idx++;
    init_srop_frame(&frames[idx], (uintptr_t)RC4, (uint64_t)&rc4_key,
                    heap_range.size, (uint64_t)heap_range.start,
                    (uint64_t)heap_range.start, &frames[idx + 1]);
    idx++;

    init_srop_frame(&frames[idx], (uintptr_t)RC4_set_key, (uint64_t)&rc4_key,
                    RC4_KEY_SIZE, (uint64_t)key_bytes, 0, &frames[idx + 1]);
    idx++;
    for (int i = 0; i < num_ranges; i++) {
        init_srop_frame(&frames[idx], (uintptr_t)RC4, (uint64_t)&rc4_key,
                        ranges[i].size, (uint64_t)ranges[i].start,
                        (uint64_t)ranges[i].start, &frames[idx + 1]);
        idx++;
    }

    init_srop_frame(&frames[idx], (uintptr_t)nanosleep, (uint64_t)&ts, 0, 0, 0,
                    &frames[idx + 1]);
    idx++;

    init_srop_frame(&frames[idx], (uintptr_t)RC4_set_key, (uint64_t)&rc4_key,
                    RC4_KEY_SIZE, (uint64_t)key_bytes, 0, &frames[idx + 1]);
    idx++;
    for (int i = 0; i < num_ranges; i++) {
        init_srop_frame(&frames[idx], (uintptr_t)RC4, (uint64_t)&rc4_key,
                        ranges[i].size, (uint64_t)ranges[i].start,
                        (uint64_t)ranges[i].start, &frames[idx + 1]);
        idx++;
    }

    init_srop_frame(&frames[idx], (uintptr_t)RC4_set_key, (uint64_t)&rc4_key,
                    RC4_KEY_SIZE, (uint64_t)key_bytes, 0, &frames[idx + 1]);
    idx++;
    init_srop_frame(&frames[idx], (uintptr_t)RC4, (uint64_t)&rc4_key,
                    heap_range.size, (uint64_t)heap_range.start,
                    (uint64_t)heap_range.start, &frames[idx + 1]);
    idx++;

    for (int i = 0; i < num_ranges; i++) {
        init_srop_frame(&frames[idx], (uintptr_t)mprotect,
                        (uint64_t)ranges[i].start, ranges[i].size,
                        ranges[i].prot, 0, &frames[idx + 1]);
        idx++;
    }

    free(ranges);

    __asm__ volatile("" ::: "memory");

    init_restore_frame(&frames[idx], g_saved_rsp, g_saved_rbp);

    DEBUG_PRINT("sleeping for %d seconds", seconds);
    trigger_sigreturn(&frames[0].uc);

    __builtin_unreachable();
}
