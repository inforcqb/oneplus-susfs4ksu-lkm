// SPDX-License-Identifier: GPL-2.0
/*
 * sus_map.c - hide mmapped real files from /proc/<pid>/maps (SUSFS SUS_MAP).
 *
 * Upstream SUSFS sets AS_FLAGS_SUS_MAP on the inode's address_space flags and
 * makes show_map_vma() skip the line.  An LKM cannot add a flag bit, so we
 * keep an ino set and hook show_map_vma with a kprobe: when the vma's backing
 * file inode is in the set, skip the line by returning early (regs->pc = x30).
 *
 * show_map_vma(m, vma): vma is arg #2 (regs->regs[1]); returns non-zero from
 * the pre_handler so the arm64 kprobe core skips singlestep and continues at
 * the modified pc (same trick kprg uses).
 */
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/mm_types.h>
#include "susfs_log.h"

#define SUS_MAP_MAX 64

struct sus_map_entry {
    unsigned long target_ino;
    dev_t target_dev;
};

static struct sus_map_entry map_entries[SUS_MAP_MAX];
static int nmap;

/* temporary interface: insmod susfs.ko map_ino=<n> hides that inode */
static unsigned long param_map_ino;
module_param_named(map_ino, param_map_ino, ulong, 0644);

static void sus_map_add(unsigned long ino)
{
    if (nmap >= SUS_MAP_MAX || !ino)
        return;
    map_entries[nmap].target_ino = ino;
    nmap++;
}

static bool sus_map_lookup(unsigned long ino, dev_t dev)
{
    int i;

    for (i = 0; i < nmap; i++) {
        if (map_entries[i].target_ino != ino)
            continue;
        if (map_entries[i].target_dev && map_entries[i].target_dev != dev)
            continue;
        return true;
    }
    return false;
}

static int sus_map_show_map_vma_pre(struct kprobe *kp, struct pt_regs *regs)
{
    struct vm_area_struct *vma = (struct vm_area_struct *)regs->regs[1];
    struct inode *inode;

    if (!vma || !vma->vm_file)
        return 0;
    inode = file_inode(vma->vm_file);
    if (!inode)
        return 0;
    if (sus_map_lookup(inode->i_ino, inode->i_sb->s_dev)) {
        /* skip this maps line: return early via the saved return address */
        regs->pc = regs->regs[30];
        return 1;
    }
    return 0;
}

static struct kprobe kp_map = {
    .symbol_name = "show_map_vma",
    .pre_handler = sus_map_show_map_vma_pre,
};

int susfs_sus_map_init(void)
{
    int rc;

    sus_map_add(param_map_ino);
    if (nmap == 0) {
        pr_info("sus_map: no rules, hook not installed\n");
        return 0;
    }

    rc = register_kprobe(&kp_map);
    if (rc)
        pr_warn("register_kprobe(show_map_vma) failed %d\n", rc);
    else
        pr_info("sus_map armed: %d rules\n", nmap);
    return 0;
}

void susfs_sus_map_exit(void)
{
    unregister_kprobe(&kp_map);
    nmap = 0;
}
