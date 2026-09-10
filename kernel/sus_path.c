// SPDX-License-Identifier: GPL-2.0
/*
 * sus_path.c - hide directory entries by inode identity (SUSFS SUS_PATH), LKM port.
 *
 * Upstream SUSFS sets AS_FLAGS_SUS_PATH on inode->i_mapping and then skips the
 * entry inside filldir64() (fs/readdir.c).  filldir64 is static and LTO-inlined
 * on this kernel, so this LKM instead records the (sb dev, inode number) of every
 * registered path in a list and rewrites the buffer returned by getdents64 on
 * sys_exit, dropping entries whose d_ino matches a registered inode.
 *
 * Matching semantics deliberately mirror upstream:
 *   - exact inode identity, not name substring matching;
 *   - an unbounded set of registered paths (upstream keeps one inode flag each);
 *   - a path registered anywhere hides that inode everywhere it is listed.
 *
 * Note: unlike upstream we do not gate on susfs_is_current_proc_umounted_app(),
 * so the entry is hidden from every process (including root) rather than from
 * app processes only.  That is intentional for this LKM's use case.
 */
#include <linux/module.h>
#include <linux/tracepoint.h>
#include <trace/events/syscalls.h>
#include <asm/syscall.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/limits.h>
#include "susfs_abi.h"
#include "susfs_log.h"

#define DIRENT_BUF_SIZE 65536  /* getdents usually returns <= 32-64KB */
#define SUS_PATH_MAX_ENTRIES 8192

struct linux_dirent64 {
    u64 d_ino;
    s64 d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

#define D_NAME_OFF offsetof(struct linux_dirent64, d_name)

/*
 * One registered path.
 *
 * An entry is matched when both the dirent's d_ino and its d_name equal the
 * recorded inode number and name.  Requiring the name as well makes a collision
 * between unrelated filesystems (independent inode number spaces can hand out
 * the same small inode number) practically impossible.  The cost is that a
 * hard link to a registered inode under a different name stays visible; upstream
 * flags the inode itself and would hide it.
 *
 * dev is kept for diagnostics only: a sys_exit tracepoint cannot recover the
 * listing's fd or superblock (regs->regs[0] already holds the return value).
 */
struct sus_path_entry {
    struct list_head list;
    u64 dev;
    u64 ino;
    char name[NAME_MAX + 1];
};

static LIST_HEAD(sus_path_list);
static DEFINE_SPINLOCK(sus_path_lock);
static unsigned int sus_path_count;

/* legacy/debug: hide a single exact filename everywhere (empty = disabled) */
static char hide_name[NAME_MAX + 1];
module_param_string(hide_name, hide_name, sizeof(hide_name), 0644);

static char *dirent_tmp;

static bool sus_path_is_hidden(u64 ino, const char *name)
{
    struct sus_path_entry *e;
    bool hidden = false;

    spin_lock(&sus_path_lock);
    list_for_each_entry(e, &sus_path_list, list) {
        if (e->ino == ino && !strcmp(e->name, name)) {
            hidden = true;
            break;
        }
    }
    spin_unlock(&sus_path_lock);

    if (!hidden && hide_name[0])
        hidden = !strcmp(name, hide_name);

    return hidden;
}

/* compact the dirent chain in-place; returns the new byte count */
static long sus_path_filter(unsigned long buf, long count)
{
    long offset = 0;
    long out = 0;

    while (offset < count) {
        struct linux_dirent64 d;
        unsigned short reclen;
        char name[NAME_MAX + 1];
        long nlen;
        bool hide;

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

        hide = sus_path_is_hidden((u64)d.d_ino, name);

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
    if (!READ_ONCE(sus_path_count) && !hide_name[0])
        return;

    /* NOTE: in a sys_exit probe regs->regs[0] already holds the return value,
     * so only args[1] (the buffer) and args[2] (the byte count) are usable. */
    syscall_get_arguments(current, regs, args);
    dirent_buf = args[1];
    if (!dirent_buf)
        return;

    new_count = sus_path_filter(dirent_buf, ret);

    if (new_count != ret)
        regs->regs[0] = new_count;   /* shrink the returned byte count */
}

/* read-only view of the registered paths, for verification */
static int sus_path_show_list(char *buf, const struct kernel_param *kp)
{
    struct sus_path_entry *e;
    int n = 0;

    spin_lock(&sus_path_lock);
    list_for_each_entry(e, &sus_path_list, list)
        n += scnprintf(buf + n, PAGE_SIZE - n, "dev=%llu ino=%llu name=%s\n",
                       e->dev, e->ino, e->name);
    spin_unlock(&sus_path_lock);

    if (!n)
        n = scnprintf(buf, PAGE_SIZE, "(empty)\n");
    return n;
}

static const struct kernel_param_ops sus_path_list_ops = {
    .get = sus_path_show_list,
};
module_param_custom(hide_list, sus_path_list_ops, 0444);

static bool path_registered;

int sus_path_init(void)
{
    int rc;

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
        pr_info("sus_path armed (inode-exact matching)\n");
    }
    return 0;
}

void sus_path_exit(void)
{
    struct sus_path_entry *e, *tmp;

    if (path_registered) {
        unregister_trace_sys_exit(sus_path_sys_exit, NULL);
        tracepoint_synchronize_unregister();
        path_registered = false;
    }
    kfree(dirent_tmp);
    dirent_tmp = NULL;

    spin_lock(&sus_path_lock);
    list_for_each_entry_safe(e, tmp, &sus_path_list, list) {
        list_del(&e->list);
        kfree(e);
    }
    sus_path_count = 0;
    spin_unlock(&sus_path_lock);
}

/* supercall: CMD_SUSFS_ADD_SUS_PATH / CMD_SUSFS_ADD_SUS_PATH_LOOP
 *
 * Upstream keeps every added path (one inode flag per path) and its _LOOP variant
 * only re-flags the same inode after a zygote-spawned app is marked umounted.
 * Since our list is permanent and the match is unconditional, both commands do
 * exactly the same thing here. */
void sus_path_supercall(void __user **arg)
{
    struct st_susfs_sus_path info = {0};
    struct sus_path_entry *e;
    struct path path;
    struct inode *inode;
    int rc;

    if (copy_from_user(&info, (void __user *)*arg, sizeof(info))) {
        info.err = -EFAULT;
        goto out;
    }

    if (!info.target_pathname[0]) {
        info.err = -EINVAL;
        goto out;
    }

    rc = kern_path(info.target_pathname, LOOKUP_FOLLOW, &path);
    if (rc) {
        pr_warn("sus_path: failed opening '%s' (%d)\n", info.target_pathname, rc);
        info.err = rc;
        goto out;
    }

    inode = d_inode(path.dentry);
    if (!inode) {
        path_put(&path);
        info.err = -ENOENT;
        goto out;
    }

    e = kmalloc(sizeof(*e), GFP_KERNEL);
    if (!e) {
        path_put(&path);
        info.err = -ENOMEM;
        goto out;
    }
    e->dev = (u64)inode->i_sb->s_dev;
    e->ino = (u64)inode->i_ino;
    strscpy(e->name, path.dentry->d_name.name, sizeof(e->name));
    INIT_LIST_HEAD(&e->list);
    path_put(&path);

    if (!e->ino) {
        /* filesystem does not expose a usable inode number: fall back to name */
        pr_warn("sus_path: '%s' has ino 0, falling back to name matching\n",
                info.target_pathname);
    }

    spin_lock(&sus_path_lock);
    if (sus_path_count >= SUS_PATH_MAX_ENTRIES) {
        spin_unlock(&sus_path_lock);
        kfree(e);
        info.err = -ENOSPC;
        goto out;
    }
    {
        struct sus_path_entry *cur;
        list_for_each_entry(cur, &sus_path_list, list) {
            if (cur->ino == e->ino && !strcmp(cur->name, e->name)) {
                spin_unlock(&sus_path_lock);
                kfree(e);
                info.err = 0;   /* already registered, upstream is idempotent */
                goto out;
            }
        }
    }
    list_add_tail(&e->list, &sus_path_list);
    sus_path_count++;
    spin_unlock(&sus_path_lock);

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
    pr_info("sus_path: hide '%s' (dev=%llu ino=%llu)\n",
            info.target_pathname, e->dev, e->ino);
out:
    /* upstream writes back only ->err for input-type commands */
    if (copy_to_user(&((struct st_susfs_sus_path __user *)*arg)->err,
                     &info.err, sizeof(info.err)))
        pr_warn("sus_path supercall copy_to_user failed\n");
}
