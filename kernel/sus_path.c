// SPDX-License-Identifier: GPL-2.0
/*
 * sus_path.c - hide directory entries (SUSFS SUS_PATH feature), LKM port.
 *
 * Upstream SUSFS skips the entry in filldir64 (fs/readdir.c) when the inode is
 * flagged.  filldir64 is static and LTO-inlined here, so instead we hook the
 * getdents64 syscall exit via tracepoint and filter the already-written user
 * dirent buffer: entries whose d_name contains hide_name are dropped by
 * compacting the buffer and shrinking the returned byte count.
 *
 * This is the same "rewrite the user output buffer on sys_exit" pattern as
 * sus_kstat, just applied to a dirent chain instead of struct stat.
 */
#include <linux/module.h>
#include <linux/tracepoint.h>
#include <trace/events/syscalls.h>
#include <asm/syscall.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "susfs_abi.h"
#include "susfs_log.h"

#define DIRENT_BUF_SIZE 65536  /* getdents usually returns <= 32-64KB */

struct linux_dirent64 {
    u64 d_ino;
    s64 d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

#define D_NAME_OFF offsetof(struct linux_dirent64, d_name)

/* hide directory entries whose name contains this substring */
static char hide_name[256];
module_param_string(hide_name, hide_name, sizeof(hide_name), 0644);

static char *dirent_tmp;

/* compact the dirent chain in-place; returns the new byte count */
static long sus_path_filter(unsigned long buf, long count)
{
    long offset = 0;
    long out = 0;

    while (offset < count) {
        struct linux_dirent64 d;
        unsigned short reclen;
        char name[256];
        long nlen;
        bool hide = false;

        if (copy_from_user(&d, (void __user *)(buf + offset), sizeof(d)))
            break;
        reclen = d.d_reclen;
        if (reclen < D_NAME_OFF + 1 ||
            offset + reclen > count ||
            reclen > DIRENT_BUF_SIZE - out)
            break;

        nlen = strnlen_user((void __user *)(buf + offset + D_NAME_OFF),
                            sizeof(name) - 1);
        if (nlen == 0 || nlen >= sizeof(name))
            nlen = sizeof(name) - 1;
        if (copy_from_user(name, (void __user *)(buf + offset + D_NAME_OFF), nlen))
            break;
        name[nlen] = 0;

        if (hide_name[0])
            hide = strstr(name, hide_name) != NULL;

        if (!hide) {
            if (copy_from_user(dirent_tmp + out, (void __user *)(buf + offset), reclen))
                break;
            out += reclen;
        }
        offset += reclen;
    }

    if (out > 0 && out != count)
        if (copy_to_user((void __user *)buf, dirent_tmp, out))
            return count;   /* failed to write back: leave untouched */
    return out;
}

static void sus_path_sys_exit(void *data, struct pt_regs *regs, long ret)
{
    unsigned long args[6];
    unsigned long dirent_buf;
    long new_count;

    if (is_compat_task())
        return;
    if (syscall_get_nr(current, regs) != __NR_getdents64)
        return;
    if (ret <= 0)
        return;
    syscall_get_arguments(current, regs, args);
    dirent_buf = args[1];
    if (!dirent_buf)
        return;

    new_count = sus_path_filter(dirent_buf, ret);
    if (new_count != ret)
        regs->regs[0] = new_count;   /* shrink the returned byte count */
}

static bool path_registered;

int sus_path_init(void)
{
    int rc;

    if (!hide_name[0]) {
        pr_info("sus_path: no hide_name, hook not installed\n");
        return 0;
    }

    dirent_tmp = kmalloc(DIRENT_BUF_SIZE, GFP_KERNEL);
    if (!dirent_tmp) {
        pr_warn("sus_path: kmalloc failed\n");
        return -ENOMEM;
    }

    rc = register_trace_sys_exit(sus_path_sys_exit, NULL);
    if (rc)
        pr_warn("register_trace_sys_exit(getdents64) failed %d\n", rc);
    else {
        path_registered = true;
        pr_info("sus_path armed: hide_name=%s\n", hide_name);
    }
    return 0;
}

void sus_path_exit(void)
{
    if (path_registered) {
        unregister_trace_sys_exit(sus_path_sys_exit, NULL);
        tracepoint_synchronize_unregister();
        path_registered = false;
    }
    kfree(dirent_tmp);
    dirent_tmp = NULL;
}

/* supercall: CMD_SUSFS_ADD_SUS_PATH / _LOOP
 * Upstream hides by inode; this LKM hides by dirent name substring, so we
 * use the basename of the target path as the hide_name. */
void sus_path_supercall(void __user **arg)
{
    struct st_susfs_sus_path info = {0};
    char *base;
    int rc;

    if (copy_from_user(&info, (void __user *)*arg, sizeof(info))) {
        info.err = -EFAULT;
        goto out;
    }

    base = strrchr(info.target_pathname, '/');
    base = base ? base + 1 : info.target_pathname;
    if (!*base) {
        info.err = -EINVAL;
        goto out;
    }
    strscpy(hide_name, base, sizeof(hide_name));

    if (!dirent_tmp) {
        dirent_tmp = kmalloc(DIRENT_BUF_SIZE, GFP_KERNEL);
        if (!dirent_tmp) {
            info.err = -ENOMEM;
            goto out;
        }
    }
    if (!path_registered) {
        rc = register_trace_sys_exit(sus_path_sys_exit, NULL);
        if (rc) {
            info.err = rc;
            goto out;
        }
        path_registered = true;
    }
    info.err = 0;
    pr_info("sus_path: hide '%s' via supercall\n", hide_name);
out:
    /* upstream writes back only ->err for input-type commands */
    if (copy_to_user(&((struct st_susfs_sus_path __user *)*arg)->err,
                     &info.err, sizeof(info.err)))
        pr_warn("sus_path supercall copy_to_user failed\n");
}
