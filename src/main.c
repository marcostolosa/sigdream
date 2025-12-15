#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include "sigdream.h"

static void do_work(void) {
    static int counter = 0;
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[20];

    strftime(timestamp, sizeof(timestamp), "%H:%M:%S", tm_info);
    printf("(%d) im alive @ %s\n", counter++, timestamp);
}

int main(void) {
    DEBUG_PRINT("pid: %d", getpid());
    sigdream_ctx ctx = {0};

    if (!sigdream_init(&ctx)) {
        printf("failed to initialize sigdream\n");
        return 1;
    }

    while (1) {
        do_work();
        // DEBUG_PRINT("debug sleep to view mem");
        // sleep(5); /* sleep delay for debugging */
        sigdream_sleep(&ctx, 5);
    }

    return 0;
}
