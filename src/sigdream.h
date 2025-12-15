#pragma once

#include <stdint.h>
#include <stdio.h>

#ifdef DEBUG
#define DEBUG_PRINT(fmt, ...) printf("[DEBUG] " fmt "\n", ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...) ((void)0)
#endif

#define RC4_KEY_SIZE 16

typedef struct srop_sigcontext {
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rdi, rsi, rbp, rbx, rdx, rax, rcx, rsp, rip;
    uint64_t eflags;
    uint16_t cs, gs, fs, ss;
    uint64_t err, trapno, oldmask, cr2;
    uint64_t fpstate;
    uint64_t reserved[8];
} srop_sigcontext_t;

/* ucontext subset needed for rt_sigreturn */
typedef struct srop_ucontext {
    uint64_t uc_flags;
    uint64_t uc_link;
    uint64_t uc_stack_sp;
    uint64_t uc_stack_flags;
    uint64_t uc_stack_size;
    srop_sigcontext_t uc_mcontext;
    uint64_t uc_sigmask;
} srop_ucontext_t;

/* signal frame layout expected by rt_sigreturn */
typedef struct srop_frame {
    uint64_t pretcode;
    srop_ucontext_t uc;
} __attribute__((packed)) srop_frame_t;

typedef struct sigdream_context {
    void *prog_base;
    int initialized;
} sigdream_ctx;

/* @brief   initializes sigdream context
 * @param   ctx: sigdream context to initialize
 * @retval  1 on success, 0 on failure
 */
int sigdream_init(sigdream_ctx *ctx);

/* @brief   encrypts memory regions, sleeps, then decrypts
 * @param   ctx: initialized sigdream context
 * @param   seconds: sleep duration in seconds
 * @retval  1 on success, 0 on failure
 */
int sigdream_sleep(sigdream_ctx *ctx, int seconds);
