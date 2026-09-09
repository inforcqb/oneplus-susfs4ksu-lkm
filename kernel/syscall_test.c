// SPDX-License-Identifier: GPL-2.0
/* Observe newfstatat without changing syscall behavior. */
#include <linux/module.h>
#include <linux/tracepoint.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <trace/events/syscalls.h>

#include "susfs_log.h"

struct syscall_test_state {
    unsigned long filename;
    unsigned long statbuf;
};

static DEFINE_PER_CPU(struct syscall_test_state, syscall_test_state);

static void syscall_test_enter(void *data, struct pt_regs *regs, long id)
{
    unsigned long args[6];
    struct syscall_test_state *state;
    const char __user *filename;
    char path[128];
    long copied;

    if (id != __NR_newfstatat)
        return;

    syscall_get_arguments(current, regs, args);
    state = this_cpu_ptr(&syscall_test_state);
    state->filename = args[1];
    state->statbuf = args[2];

    filename = (const char __user *)args[1];
    copied = strncpy_from_user(path, filename, sizeof(path) - 1);
    if (copied < 0)
        copied = 0;
    path[copied] = '\0';

    pr_info("syscall_test enter: comm=%s pid=%d dfd=%ld filename=%s statbuf=%px flags=0x%lx\n",
            current->comm, task_pid_nr(current), args[0], path,
            (void *)args[2], args[3]);
}

static void syscall_test_exit(void *data, struct pt_regs *regs, long ret)
{
    struct syscall_test_state *state;
    unsigned long ino = 0;
    unsigned long size = 0;

    if (syscall_get_nr(current, regs) != __NR_newfstatat)
        return;

    state = this_cpu_ptr(&syscall_test_state);
    if (!ret && state->statbuf) {
        if (copy_from_user(&ino, (void __user *)(state->statbuf + 8),
                           sizeof(ino)))
            ino = 0;
        if (copy_from_user(&size, (void __user *)(state->statbuf + 48),
                           sizeof(size)))
            size = 0;
    }

    pr_info("syscall_test exit: comm=%s pid=%d ret=%ld statbuf=%px ino=%lu size=%lu\n",
            current->comm, task_pid_nr(current), ret,
            (void *)state->statbuf, ino, size);
}

static int __init syscall_test_init(void)
{
    int rc;

    rc = register_trace_sys_enter(syscall_test_enter, NULL);
    if (rc)
        return rc;

    rc = register_trace_sys_exit(syscall_test_exit, NULL);
    if (rc) {
        unregister_trace_sys_enter(syscall_test_enter, NULL);
        return rc;
    }

    pr_info("syscall_test armed: newfstatat tracepoints\n");
    return 0;
}

static void __exit syscall_test_exit_module(void)
{
    unregister_trace_sys_exit(syscall_test_exit, NULL);
    unregister_trace_sys_enter(syscall_test_enter, NULL);
    tracepoint_synchronize_unregister();
    pr_info("syscall_test stopped\n");
}

module_init(syscall_test_init);
module_exit(syscall_test_exit_module);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("newfstatat syscall tracing test module");