// SPDX-License-Identifier: GPL-2.0
/*
 * kstat_probe_test.c - layer-by-layer kprobe hit test to locate LTO inlining.
 *
 * Hooks each layer of the newfstatat path and counts hits.  Read counters from
 * /proc/susfs_probe; write "reset" to clear them.  Load, reset, run `stat` on
 * a file, then read /proc/susfs_probe to see which layers were actually hit.
 */
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/path.h>
#include "susfs_log.h"

#define NPROBES 7

struct probe_stat {
    const char *name;
    struct kprobe kp;
    atomic_t hits;
};

static struct probe_stat probes[NPROBES] = {
    { .name = "__arm64_sys_newfstatat" },
    { .name = "vfs_statx" },
    { .name = "cp_statx" },
    { .name = "cp_new_stat" },
    { .name = "vfs_getattr" },
    { .name = "vfs_getattr_nosec" },
    { .name = "generic_fillattr" },
};

static int probe_pre(struct kprobe *kp, struct pt_regs *regs)
{
    struct probe_stat *ps = container_of(kp, struct probe_stat, kp);

    atomic_inc(&ps->hits);
    if (strcmp(kp->symbol_name, "vfs_getattr") == 0) {
        const struct path *path = (const struct path *)regs->regs[0];
        if (path && path->dentry && path->dentry->d_inode &&
            path->dentry->d_inode->i_ino == 461584)
            pr_info("VFS_GETATTR TARGET 461584: name=%.*s comm=%s\n",
                    (int)path->dentry->d_name.len, path->dentry->d_name.name,
                    current->comm);
    }
    return 0;
}

static int probe_show(struct seq_file *m, void *v)
{
    int i;

    for (i = 0; i < NPROBES; i++)
        seq_printf(m, "%s: %d\n", probes[i].name, atomic_read(&probes[i].hits));
    return 0;
}

static int probe_open(struct inode *inode, struct file *file)
{
    return single_open(file, probe_show, NULL);
}

static ssize_t probe_write(struct file *file, const char __user *buf,
                           size_t len, loff_t *off)
{
    int i;
    char cmd[16];

    if (len >= sizeof(cmd))
        len = sizeof(cmd) - 1;
    if (copy_from_user(cmd, buf, len))
        return -EFAULT;
    cmd[len] = 0;
    if (strcmp(cmd, "reset") == 0) {
        for (i = 0; i < NPROBES; i++)
            atomic_set(&probes[i].hits, 0);
    }
    return len;
}

static const struct proc_ops probe_ops = {
    .proc_open = probe_open,
    .proc_read = seq_read,
    .proc_write = probe_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static struct proc_dir_entry *proc_entry;

static int __init kstat_probe_init(void)
{
    int i, rc;

    for (i = 0; i < NPROBES; i++) {
        probes[i].kp.symbol_name = probes[i].name;
        probes[i].kp.pre_handler = probe_pre;
        atomic_set(&probes[i].hits, 0);
        rc = register_kprobe(&probes[i].kp);
        if (rc)
            pr_warn("register_kprobe(%s) failed %d\n", probes[i].name, rc);
        else
            pr_info("probe armed: %s\n", probes[i].name);
    }

    proc_entry = proc_create("susfs_probe", 0666, NULL, &probe_ops);
    if (!proc_entry)
        pr_warn("proc_create(susfs_probe) failed\n");
    else
        pr_info("read /proc/susfs_probe for counters\n");

    return 0;
}

static void __exit kstat_probe_exit(void)
{
    int i;

    if (proc_entry)
        proc_remove(proc_entry);
    for (i = 0; i < NPROBES; i++)
        unregister_kprobe(&probes[i].kp);
    pr_info("kstat_probe bye\n");
}

module_init(kstat_probe_init);
module_exit(kstat_probe_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("layer-by-layer kprobe hit test for newfstatat");
