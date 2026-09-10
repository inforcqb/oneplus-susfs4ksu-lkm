# sus_path：SUSFS builtin vs LKM 移植版 逐项差异对比

**对比对象**

| 侧 | 文件 |
|---|---|
| builtin（内核内置） | `workfile/susfs4ksu/kernel_patches/fs/susfs.c:40-237`、`include/linux/susfs.h:39-51`、`include/linux/susfs_def.h`、`50_add_susfs_in_gki-android13-5.15.patch`、`KernelSU/10_enable_susfs_for_ksu.patch` |
| LKM | `workfile/susfs4ksu-lkm/kernel/sus_path.c`、`lsm_hook.c`、`susfs_hide_syms.c`、`susfs_supercall.c`、`susfs_abi.h` |

**行号约定**：`susfs.c:47` = builtin 源文件行号；`patch:177` / `KSU patch:2865` = **补丁文件内**行号；`sus_path.c:249` = LKM 源文件行号。

**证据边界（先说清楚）**
- 本仓库不含内核源码树，`raw.githubusercontent.com` 被网络策略拒绝（非公开 IP）。为核实"内核侧行为"，我从 `git.kernel.org` 取到了 `fs/readdir.c`（v5.15）与 `fs/open.c`（v5.15）原文，只用于核对"5.15 有哪些 filldir 回调"和"哪些 syscall 会走 `inode_permission()`"。
- 标 **(推测)** 的结论是代码推理，未在设备或内核源码树上验证；其余结论均可由 `文件:行号` 直接复核。
- `TECHNICAL_NOTES.md` 第九章已注明是"2026-09-10 重写"，其中"按 dev+ino+name 匹配""用 fdget(fd) 取 sb 的 s_dev""无上限链表"等描述**与当前代码不符**（当前实现不比对 dev，也不存在 fdget 与上限缺失），以本文的代码引用为准。

---

## 1. 上游注入点清单

### 1.1 `fs/namei.c`（`patch:116-551`，共 22 个 hunk，其中 sus_path 相关 **16 个**）

| patch 行 | 函数（hunk 头声明） | 该处作用 |
|---|---|---|
| 120 | 文件头 | 条件引入 `susfs_def.h`；`extern bool susfs_is_inode_sus_path()`、`extern const struct qstr susfs_fake_qstr_name`（`patch:131-134`） |
| 142 | `lookup_dcache` | dcache 命中但 inode 是 sus_path → 若 `d_in_lookup` 先 `d_lookup_done`，再 `dput`，**return NULL**（丢掉缓存命中，强制走慢路径）（`patch:146-153`） |
| 157 | `lookup_one_qstr_excl` | 该函数 `dentry = lookup_dcache(...)` 之后定义局部 `found_sus_path`（`patch:161-163`） |
| 167 | `lookup_one_qstr_excl` | 在 `d_alloc(base, name)` 之前插 `retry:` 标签（`patch:171-173`） |
| 177 | `lookup_one_qstr_excl` | 命中 sus_path 且 `!found_sus_path` → `d_alloc(base, &susfs_fake_qstr_name)` + `goto retry`（`LOOKUP_RCU` 时不 dput）（`patch:181-191`） |
| 195 | `lookup_fast` | 预计算 `is_nd_state_lookup_last_and_open_last = (nd->state & (ND_STATE_LOOKUP_LAST\|ND_STATE_OPEN_LAST))`（`patch:199-201`） |
| 205 | `lookup_fast` | **RCU 分支**（`__d_lookup_rcu`）：命中 sus_path 且上面两位都置位 → 丢弃 dentry，**不 dput**（`__d_lookup_rcu` 不增 refcount）（`patch:209-218`） |
| 222 | `lookup_fast` | **非 RCU 分支**（`__d_lookup`）：命中 sus_path 且两位都置位 → `dput` + 置 NULL（`patch:226-235`） |
| 239 | `__lookup_slow` | 定义 `found_sus_path` 与 `is_nd_flags_lookup_last = (flags & ND_FLAGS_LOOKUP_LAST)`（`patch:243-246`） |
| 259 | `__lookup_slow` | `d_revalidate` 失败 → `d_invalidate`/`dput`/`goto again` 这条错误分支里，若 `found_sus_path` 则改用假 qstr 的 `d_alloc_parallel` 重来（`patch:263-268`） |
| 272 | `__lookup_slow` | **核心**：慢查找命中 sus_path 且 `ND_FLAGS_LOOKUP_LAST` → `d_alloc_parallel(dir, &susfs_fake_qstr_name)` + `found_sus_path = true` + `goto retry`（`patch:276-288`） |
| 292 | `walk_component` | `lookup_fast` 返回 NULL（`!dentry`）且 `nd->state & ND_STATE_LOOKUP_LAST` → 置 `nd->flags \|= ND_FLAGS_LOOKUP_LAST`，把"这是最后一个组件"传递给 `lookup_slow`（`patch:296-300`） |
| 304 | `link_path_walk` | **每轮遍历的开头**（在 `may_lookup()` 之前）判断 `nd->path.dentry->d_inode` 是否 sus_path → `return -ENOENT`，注释原文 "walking the sub path of sus path"（`patch:308-316`） |
| 320 | `lookup_last` | `nd->state \|= ND_STATE_LOOKUP_LAST`（标记"最后一个组件"）（`patch:324-326`） |
| 330 | `lookup_open` | ①`is_nd_state_open_last`（`patch:334-337`）；②`d_lookup` 命中 sus_path 且 OPEN_LAST → `dput`/置 NULL/`found_sus_path = true`（`patch:344-354`）；③`!dentry && found_sus_path` → 假 qstr `d_alloc_parallel` 并 `goto skip_orig_flow`（`patch:357-366`） |
| 370 | `open_last_lookups` | `nd->state \|= ND_STATE_OPEN_LAST`（`patch:374-376`） |

同一文件里 `patch:380 / 413 / 473 / 505 / 517 / 536`（`do_tmpfile`、`do_o_path`、`path_openat`、`vfs_readlink`）全部是 `CONFIG_KSU_SUSFS_OPEN_REDIRECT`（open_redirect）的插桩，**与 sus_path 无关**（`patch:384-548`）。

关键机制：`susfs_fake_qstr_name = QSTR_INIT("..5.u.S", 7)`（`susfs.c:45`）——命中时不是直接报错，而是拿一个**不存在的名字**重走一次查找，让文件系统自己返回 `-ENOENT`。

### 1.2 `fs/readdir.c`（`patch:1614-1873`，共 **21 个 hunk**）

| patch 行 | 位置 | 该处作用 |
|---|---|---|
| 1618 | 文件头 | 引入 `susfs_def.h` + `extern susfs_is_inode_sus_path` |
| 1629 / 1678 / 1727 / 1776 / 1825 | `readdir_callback`、`getdents_callback`、`getdents_callback64`、`compat_readdir_callback`、`compat_getdents_callback` | 各结构体新增 `struct super_block *sb`（5 处） |
| 1639+1649 | `fillonedir` | `ilookup(buf->sb, ino)` 反查 inode，是 sus_path → `iput` + `return 0`（跳过该目录项）；`ilookup` 失败走 `orig_flow` |
| 1688+1698 | `filldir` | 同上 |
| 1737+1747 | `filldir64` | 同上（现代 Android `getdents64` 走这条） |
| 1786+1796 | `compat_fillonedir` | 同上（compat） |
| 1835+1845 | `compat_filldir` | 同上（compat） |
| 1668 / 1717 / 1766 / 1815 / 1864 | `old_readdir`、`getdents`、`getdents64`、compat `old_readdir`、compat `getdents` | 各 `SYSCALL_DEFINE` 里填 `buf.sb = f.file->f_inode->i_sb`（5 处） |

我从内核源码（v5.15 `fs/readdir.c`）确认：该版本 readdir.c **只有这 5 个 fill 回调**，**没有** `compat_filldir64`（`struct linux_dirent64` 是固定宽度布局，32 位任务不需要单独实现）——所以上游"5 个回调全打"= 该内核的**全部**目录项出口。

---

## 2. LKM 覆盖对照表

| 上游注入点 | LKM 机制 | 覆盖判定 |
|---|---|---|
| `filldir64`（`patch:1747`） | `sys_exit` tracepoint 重写 getdents64 用户缓冲（`sus_path.c:297-323`、`249-295`） | 覆盖（native 非 compat） |
| `filldir`/`fillonedir`（`patch:1698`/`1649`） | 无（不覆盖 legacy `getdents`/`old_readdir`） | **未覆盖**（现代 Android 不用，影响低） |
| `compat_fillonedir`/`compat_filldir`/compat 三个 syscall（`patch:1796/1845`） | `sus_path.c:303-304` 直接 `if (is_compat_task()) return;` | **完全未覆盖**：32 位进程列目录能看到隐藏项 |
| `lookup_dcache`（`patch:147`） | LSM `inode_getattr` + `inode_permission`（`sus_path.c:218-246`） | 部分覆盖（见下各行的语义差异） |
| `lookup_one_qstr_excl`（`patch:182`，无条件） | 无直接等价物 | 内核内部/文件系统发起的 `lookup_one_len*` 类查找不经过 LSM hook → **未覆盖**（上游此处是"连内核内部按名查找也拦"） |
| `lookup_fast`（`patch:210/227`） | `inode_getattr`（stat/statx/fstatat）+ `inode_permission`（open/exec/access/chdir/truncate…） | 覆盖（结果等价：ENOENT） |
| `__lookup_slow`（`patch:277`） | 同上 | 覆盖 |
| `walk_component` + `link_path_walk`（`patch:297/311`）"子路径不可走" | `may_lookup()` → `inode_permission(dir, MAY_EXEC)`；注册的是目录时其子路径全部 -ENOENT | 覆盖（等价） |
| `lookup_last` / `open_last_lookups`（`patch:325/375`） | 无（不需要，LKM 不依赖"最后一个组件"状态机） | 不适用 |
| `lookup_open`（`patch:345/358`） | `may_open` → `inode_permission(inode, MAY_OPEN\|acc_mode)` | 覆盖 |
| （上游无此点）`fs/stat.c` 的 `vfs_getattr` 路径 | LSM `inode_getattr`（`sus_path.c:218-233`） | LKM 独有实现手段 |

### 2.1 上游做了、LKM 完全没覆盖的路径

| 路径 / syscall | 上游（builtin） | LKM | 依据 |
|---|---|---|---|
| 32 位进程的 `getdents64` | compat 回调被插桩 | **不拦**（`is_compat_task()` 早退） | `sus_path.c:303-304` vs `patch:1796/1845` |
| legacy `getdents` / `old_readdir` | 插桩 | 不拦 | `patch:1649/1698` |
| `readlink`/`readlinkat` | 命中时 lookup 层 ENOENT（冷路径确定） | **不拦**：`vfs_readlink` 明确 "Does not call security hook"，且末组件不经过 `may_lookup` | `patch:507`（注释）+ v5.15 `fs/open.c`/namei 语义 **(推测：热 dcache 命中的细节未实测)** |
| `chmod`/`fchmodat` | 至少在冷路径经 lookup 拦下 | **不拦**：v5.15 `chmod_common()` 只调 `security_path_chmod()`，**不调 `inode_permission()`**；也不经过 getattr → 两个 hook 都不触发 | 已核对 v5.15 `fs/open.c` `chmod_common()` |
| `chown`/`lchown`/`fchownat`、`utimes` | 同上（lookup 层） | **不拦**：`chown_common()` 只调 `security_path_chown()` | v5.15 `fs/open.c` |
| `name_to_handle_at`/`open_by_handle_at` | 不拦（不经过 namei 走查） | 不拦 | 两侧同样缺失，非回归 |
| `unlink`/`rmdir`/`rename` | 上游**也不拦**（`filename_parentat` 只走父目录，末组件不作 lookup，`link_path_walk` 只检查中间组件） | 同样不拦（`sus_path.c:131-132` 自己注明） | 两侧一致，非回归 |
| `link`/`symlink`（inode 作为源） | 上游：lookup 层可能拦；创建目标是父目录 | LKM：源 inode 若经过 `may_linkat` → 多数实现走 `inode_permission`? **未验证** | 需实测 |
| 内核内部查找（overlayfs、kernfs、`lookup_one_len`、mount 源解析） | `lookup_one_qstr_excl` / `lookup_dcache` 拦截 | 多数不经过两个 LSM hook → **未覆盖** | `patch:147/182` |
| O_PATH 打开（`do_o_path`→`path_lookupat`，不经过 `lookup_open`） | 上游 `lookup_one_qstr_excl`/`lookup_dcache` 一路仍会拦 | 不确定：`do_dentry_open()` 对 `O_PATH` 在 `security_file_open()` 之前就 `return 0`（已核对 v5.15 `fs/open.c`），能否被拦取决于 `open()` 是否仍走 `may_open()`→`inode_permission()`（未取得 v5.15 namei.c 原文）**(推测：覆盖，但属 O_PATH 特例，需实测)** | v5.15 `fs/open.c` `do_dentry_open()` |

**LKM 覆盖"更宽"的地方**：`stat`/`open` 的判定不依赖 `ND_STATE_*` 状态机与 dcache 冷热，`inode_getattr`/`inode_permission` 无条件生效（`sus_path.c:225/239`），而上游的 `lookup_fast` 分支需要 `LOOKUP_LAST|OPEN_LAST` 同时置位（`patch:210/227`）——即上游在"非 open 的末组件 + dcache 命中"这一组合下是否拦下，取决于内核细节 **(推测)**；LKM 在该组合下一定拦。

---

## 3. `add` 流程逐项对比

命令入口：两者都由 `reboot()` 魔数进入，且**都要求 `current_uid().val == 0`**（builtin `KSU patch:2862-2870`；LKM `susfs_supercall.c:176-181`，由 `__arm64_sys_reboot` kprobe + task_work 执行，`susfs_supercall.c:190-210`）。LKM 把 `ADD_SUS_PATH` 与 `ADD_SUS_PATH_LOOP` 映射到**同一个函数**（`susfs_supercall.c:130-133`）。

| # | 项目 | builtin `susfs_add_sus_path`（`susfs.c:47-97`） | LKM `sus_path_supercall`（`sus_path.c:431-534`） |
|---|---|---|---|
| 1 | 结构体 ABI | `{char[256]; int err}`（`susfs.h:41-44`） | 同布局（`susfs_abi.h:73-76`，`SUSFS_MAX_LEN_PATHNAME=256` at `susfs_abi.h:52`）→ 兼容 |
| 2 | `copy_from_user` 失败 | `err=-EFAULT` 并仍然回写 err（`susfs.c:53-56`） | 同（`sus_path.c:439-442`） |
| 3 | 空路径校验 | **无**（`susfs.c:47-97` 中不存在空串检查） | **有** → `-EINVAL`（`sus_path.c:444-447`）。LKM 更严；上游同等校验只在 `_LOOP` 里（`susfs.c:108-112`） |
| 4 | `kern_path` flags | `LOOKUP_FOLLOW`（`susfs.c:58`） | `LOOKUP_FOLLOW`（`sus_path.c:449`）→ 相同（跟随符号链接） |
| 5 | 取 inode | `d_backing_inode(path.dentry)`（`susfs.c:64`） | `d_inode(path.dentry)`（`sus_path.c:456`）→ 5.15 上二者等价 |
| 6 | `i_mapping` 校验 | `!inode \|\| !inode->i_mapping` → `-ENOENT` + 日志（`susfs.c:65-69`） | **只校验 `!inode`**，不检查 `i_mapping`（`sus_path.c:457-461`）。LKM 匹配用的是 inode 指针，不需要 mapping，故对"没有 i_mapping 的 inode"上游拒绝、LKM 接受 |
| 7 | **FUSE 特判** | **有**：`s_magic == FUSE_SUPER_MAGIC` → `get_fuse_inode()`，校验 `fi->inode.i_mapping`，**同时**给 `fi->inode.i_mapping->flags` 与 `inode->i_mapping->flags` 打 `AS_FLAGS_SUS_PATH`，日志额外打印 `fi->nodeid`（`susfs.c:71-84`） | **没有**（全文无 FUSE/`FUSE_SUPER_MAGIC`/`get_fuse_inode`，已 grep 确认）。LKM 只记录 `inode` 指针 + `i_ino` + `d_name`。影响：/sdcard（MediaProvider FUSE）场景下，上游"底层 fi inode 与外壳 inode 两个 mapping 都打标"，LKM 只认内核侧解析出的那一个 inode 对象；app 侧看到的 `d_ino` 是否等于该 `i_ino` 需实测 **(推测)** |
| 8 | 写回字段 | 只回写 `->err`（`susfs.c:93-95`） | 只回写 `->err`（`sus_path.c:531-533`）→ 相同 |
| 9 | 去重 | 无去重逻辑（打的是 inode 上的 bit，天然幂等） | 按 **inode 指针** 去重 → 已存在则 `err=0` 且**静默返回**（`sus_path.c:496-505`） |
| 10 | 上限 | **无上限** | `SUS_PATH_MAX_ENTRIES = 8192` → 超出返回 `-ENOSPC`（`sus_path.c:55/487-493`） |
| 11 | 资源占用 | 只置一个 bit（`AS_FLAGS_SUS_PATH`，`susfs.c:78-79/86`），无额外引用 | 每个条目 `kmalloc` + `ihold(inode)` 永久持有 inode 引用（`sus_path.c:463-478`），卸载时 `iput`（`sus_path.c:417-422`） |
| 12 | 记录的名字 | 不记录名字（按 inode 判定） | 记录 `path.dentry->d_name.name` 到 `char name[NAME_MAX+1]`（`sus_path.c:83/476`），目录项层要求名字相等 |
| 13 | 错误码集合 | `-EFAULT` / `kern_path` 返回值 / `-ENOENT`（inode 或 mapping 空） | `-EFAULT` / `-EINVAL`（空路径）/ `kern_path` 返回值 / `-ENOENT`（`!inode`）/ `-ENOMEM` / `-ENOSPC` / tracepoint 注册错误（`sus_path.c:439-524`） |
| 14 | 日志 | `SUSFS_LOGI` 全部受 `CONFIG_KSU_SUSFS_ENABLE_LOG` + 运行期 `susfs_is_log_enabled` static key 门控（`susfs.c:31-38`，命令 `0x555a0` 开关 `susfs.c:672`） | `pr_warn`/`pr_info` **无条件打印**，其中 `pr_info("sus_path: hide '%s' ...")` 直接把被隐藏路径名写进 dmesg（`sus_path.c:451/527-528`）；`susfs_enable_log.c` 提供的开关**不被 sus_path 使用**（`susfs_log_enabled()` 未在 `sus_path.c` 出现） |
| 15 | 生效时机 | 打标立即生效（bit 已在 inode 上） | 需要 getdents tracepoint 已注册：init 时先试注册（`sus_path.c:365-371`），supercall 里再兜底注册（`sus_path.c:517-524`） |
| 16 | ino 为 0 | 不关心 | 打印"falling back to name matching"，但**没有改行为**（`sus_path.c:480-484`）；只有列出的 `d_ino` 恰好也是 0 时才会按名字命中（`sus_path.c:103`） |

---

## 4. `_LOOP` 变体差异

**上游做了什么**（`susfs.c:99-132`）
- 只做空串校验（`-EINVAL`，`susfs.c:108-112`），**不解析路径、不校验存在性**，`kzalloc` 一个 `st_susfs_sus_path_list`，把路径 `strscpy` 进 `info.target_pathname` 与 `target_pathname` 两个字段（长度参数 `SUSFS_MAX_LEN_PATHNAME - 1 = 255`，实际最多 254 字符，`susfs.c:119-120`），`list_add_tail_rcu` 进 `LH_SUS_PATH_LOOP`（`susfs.c:122-124`）。
- 用户态 `add_sus_path_loop` 同样**不做 realpath、不检查存在性**（`ksu_susfs/jni/features/sus_path.c:66-83`），帮助文本明说 "it does not check if the path is existed or not, instead it checks for empty string only"（`.../sus_path.c:29`）；而 `add_sus_path` 用 `realpath()`（`.../sus_path.c:54-57`）。

**何时被消费**
- `susfs_run_sus_path_loop()`（`susfs.c:134-172`）由 `susfs_run_extra_works()` work 调用（`susfs.c:1450-1457`，`INIT_WORK` 于 `susfs.c:1462`）。
- 该 work 由 `ksu_handle_extra_susfs_work()` 用 `schedule_work()` 排队（`KSU patch:1599-1607`，带 `work_pending()` 去重），调用点是 **zygote 系进程 `setresuid` 之后、刚被标记 `TIF_PROC_UMOUNTED` 的时刻**：`handle_zygote_setresuid()` 的 `do_umount:` 分支（`KSU patch:1663-1670`）与 `handle_zygote_next_setresuid()` 的 `do_susfs_work:` 分支（`KSU patch:1714-1720`）。
- 重打标细节：`kern_path(path, 0, &path)` —— **flags = 0，不跟随符号链接**（`susfs.c:143`，与 add 的 `LOOKUP_FOLLOW` 不同）；用 `override_creds(ksu_cred)` 以 ksu 身份解析（`susfs.c:139`），`srcu_read_lock(&susfs_srcu_sus_path_loop)` 保护链表（`susfs.c:140/170`），FUSE 时同样给两个 mapping 打标（`susfs.c:151-161`）。
- 语义：`_LOOP` = "允许先登记（可以还不存在），等 app spawn/umount 后再解析并重新打标"，用于 FUSE/媒体库等"注册时还没有 inode"或"inode 被回收后 flag 丢失"的场景。

**LKM 如何处理**
- `CMD_SUSFS_ADD_SUS_PATH_LOOP` 与 `ADD` 走同一个 `sus_path_supercall()`（`susfs_supercall.c:130-133`），注释也自认"两者在本 LKM 下完全一样"（`sus_path.c:425-430`）。
- 因此：**路径必须此刻就存在**，`kern_path` 失败即 `err = -ENOENT`（`sus_path.c:449-454`）；没有任何重试/重打标机制（全文件无 work、无 timer、无 `override_creds`）；列表常驻 + 匹配无条件（`sus_path.c:103/182`）——对"已经存在的路径"结果等价，**对"预注册不存在的路径"则完全不等价：上游会在之后的 app spawn 时生效，LKM 永远返回 -ENOENT 且不生效**。
- 另外上游 `_LOOP` 用 flags=0（不跟随末节点符号链接）而 LKM 用 `LOOKUP_FOLLOW`（`sus_path.c:449`）：注册符号链接时两侧打标的 inode 可能不是同一个。

---

## 5. 门控对比

### 5.1 上游 `susfs_is_inode_sus_path()`（`susfs.c:174-232`）

| 分支 | 条件（原文去掉空白） | 行号 |
|---|---|---|
| 前置 0 | `is_i_uid_not_allowed(uid) = likely(current_uid().val != uid)` | `susfs.c:174-176` |
| 前置 1 | `if (!susfs_is_current_proc_umounted_app()) return false;`，其中 `= test_thread_flag(TIF_PROC_UMOUNTED) && current_uid().val >= 10000` | `susfs.c:188-190` + `susfs_def.h:122-125`（flag 号 `TIF_PROC_UMOUNTED 33`，`susfs_def.h:59`） |
| 前置 2 | `if (!inode->i_mapping) { SUSFS_LOGE; return false; }` | `susfs.c:191-194` |
| FUSE 分支 | `inode->i_sb->s_magic == FUSE_SUPER_MAGIC` → `fi = get_fuse_inode(inode)`；`!fi \|\| !fi->inode.i_mapping` → 日志 + false；再测 `test_bit(AS_FLAGS_SUS_PATH, &fi->inode.i_mapping->flags)` **注意是 fi 的 mapping** | `susfs.c:195-216` |
| FUSE uid 三种写法 | 6.6+：`i_uid_into_vfsuid(idmap, &fi->inode).val`；5.15+：`i_uid_into_mnt(i_user_ns(&fi->inode), &fi->inode).val`；else：`fi->inode.i_uid.val` | `susfs.c:202-209` |
| 普通分支 uid 三种写法 | 同上，对象换成 `inode`：`i_uid_into_vfsuid(idmap, inode)` / `i_uid_into_mnt(i_user_ns(inode), inode)` / `inode->i_uid.val`，flag 取 `inode->i_mapping->flags` | `susfs.c:217-231` |
| 命中副作用 | `SUSFS_LOGI("hiding path with ino '%lu'")` | `susfs.c:212/228` |
| 函数签名随版本变 | `>= 6.6`：`(struct mnt_idmap* idmap, struct inode *inode)`；否则 `(struct inode *inode)` | `susfs.c:181-185`；`patch:132` 的 5.15 声明是不带 idmap 的版本 |

### 5.2 LKM `sus_path_gate_uid_ok()` / `sus_path_gate_ok()`

| 分支 | 条件 | 行号 |
|---|---|---|
| `hide_from_apps` 开关 | 模块参数，默认 1；**=0 时整体绕过门控（含归属检查）** | `sus_path.c:166-167`、`195-216` |
| uid 半门控（getdents 层） | `if (!hide_from_apps) return true; return current_uid().val >= 10000;` | `sus_path.c:195-200`，用于 `sus_path.c:280-281` |
| 全门控（LSM 层） | `if (!hide_from_apps) return true; if (current_uid().val < 10000) return false; return current_uid().val != inode->i_uid.val;` | `sus_path.c:209-216`，用于 `sus_path.c:225/239` |

### 5.3 差异点

1. **`TIF_PROC_UMOUNTED` 缺失**：上游要求"zygote 派生且已被 KSU umount 的 app"（`susfs_def.h:122-125`），LKM 用 `uid >= 10000` 代理（`sus_path.c:199`）。后果：对**同样是 app uid 但未被 umount 的进程**（KSU 白名单里的 su 授权 app、manager 自身、isolated service）上游**不隐藏**、LKM **隐藏** → 例如 manager app 自己就看不到这些路径 **(由代码直接推出)**。
2. **uid 命名空间映射缺失**：上游对 5.15 走 `i_uid_into_mnt(i_user_ns(inode), inode).val`（`susfs.c:206/222`），LKM 直接比较 raw `inode->i_uid.val`（`sus_path.c:215`）。在 `s_user_ns == init_user_ns` 的常见情况下二者一致；一旦涉及非 init userns 的文件系统（FUSE/sdcardfs 或容器内）结论可能不同 **(推测)**。6.6+ 的 `mnt_idmap` 参数 LKM 完全没有对应物。
3. **只做 uid 一半 vs 全门控**：目录项层拿不到 inode（注释 `sus_path.c:192-194`），只能做 `uid>=10000`；LSM 层才做归属检查。因此对"**由调用者自己拥有的**注册文件"，LKM 会出现"**列表里看不到、但 stat/open 正常**"的自相矛盾（`sus_path.c:277-281` vs `223-228`）；上游两侧都过 `susfs_is_inode_sus_path()`，永远一致。TECHNICAL_NOTES 第 331-333 行也承认这个残留不一致。
4. `hide_from_apps` 是**运行期开关**，上游没有等价物（上游的门控只能靠 thread flag，无 CLI 开关）。
5. LKM 的 FUSE 分支不存在，上游存在且走 `fi->inode.i_mapping` 的 flag（见 3.#7、5.1）。

---

## 6. LKM 独有行为（上游没有）

| 项 | 说明 | 行号 |
|---|---|---|
| `hide_name` 模块参数 | 全局"按名字隐藏"，`strcmp` 精确匹配、**不看 ino/dev**；即使列表为空也生效 | `sus_path.c:90-92`、`110-111`、`309` |
| `hide_list` 只读参数 | 打印 `hide_from_apps`、两个 ENOENT 计数器、以及每条 `inode=%px dev ino name` | `sus_path.c:326-351`。注意 sysfs 权限 **0444 = 任意进程可读**，等于把"隐藏了哪些路径 + 内核 inode 地址"暴露给 app（检测面/信息泄漏） | 
| `hide_from_apps` 开关 | 见 5.2 | `sus_path.c:166-167` |
| ENOENT 计数器 | `n_enoent_getattr`/`n_enoent_perm` 原子计数，供 hide_list 打印 | `sus_path.c:169-170`、`226/240` |
| getdents 缓冲重写 | 在 `sys_exit` tracepoint 里**原地压缩**用户缓冲：读头 + 读文件名 + 命中则跳过 + 其余 `copy_from_user` 到全局 `dirent_tmp` 再整体回写；返回字节数被改写 `regs->regs[0] = new_count` | `sus_path.c:249-295`、`314-322`；上游是 `filldir64` 内 `return 0` 跳过（`patch:1747-1762`） |
| 单次注册的"名字"约束 | 只有 `(d_ino == e->ino && name 相等)` 才在目录项层隐藏（**不比 dev/sb**） | `sus_path.c:103/277` |
| 按 inode 指针去重 | 同一 inode 用第二个路径名注册会被静默忽略（`err=0`），于是**只记住第一个名字** | `sus_path.c:496-505` |
| inode 引用钉住 | `ihold()` 持有 inode，卸载才 `iput`；可阻止 inode 回收/sb 卸载 | `sus_path.c:471-478`、`417-422` |
| 链表上限 8192 / `-ENOSPC` | 见 3.#10 | `sus_path.c:55/487-493` |
| sysfs/kallsyms 侧 | 只有 kallsyms `s_show` 被 kprobe 屏蔽（`susfs_hide_syms.c:66-93`，前缀表 `44-50`）；**没有任何地方屏蔽 `/proc/modules` 或 `/sys/module/susfs_guard_lkm`** → 模块本身可被发现（builtin 版无此问题） | 已全目录 grep 确认 |
| 卸载语义 | `sus_path_exit()` 先摘 hook、再注销 tracepoint、最后 `iput`/`kfree`（顺序有注释说明） | `sus_path.c:391-423` |

---

## 7. 缺失 / 缺陷清单（按严重度）

| # | 严重度 | 问题 | 依据 |
|---|---|---|---|
| 1 | **高** | **`_LOOP` 语义丢失**：预注册"还不存在"的路径直接 `-ENOENT`，且永不重试/重打标；上游靠 zygote setresuid → `susfs_extra_works` 反复重打标，用户态 `add_sus_path_loop` 明确允许路径不存在 | `sus_path.c:449-454`、`425-430` vs `susfs.c:143/134-172`、`susfs.c:1455`、`KSU patch:1669/1719`、`ksu_susfs/.../sus_path.c:29/79` |
| 2 | **高** | **32 位（compat）进程目录项层完全不生效**：`is_compat_task()` 早退；而 32 位 `getdents64` 缓冲布局与 64 位相同（v5.15 readdir.c 无 `compat_filldir64`），这个早退是过度保守 | `sus_path.c:303-304` vs `patch:1796/1845` |
| 3 | **中高** | **门控与上游不等价**：无 `TIF_PROC_UMOUNTED`、无 uid 命名空间映射 → 对 KSU 白名单/manager 等未 umount 的 uid≥10000 进程也隐藏；且目录项层只能做 uid 一半 → 自持文件出现"列表隐藏但可访问" | `sus_path.c:195-216/280-281/225` vs `susfs_def.h:122-125`、`susfs.c:205-209/221-225` |
| 4 | **中高** | **隐蔽性缺陷**：`hide_list`(0444) 向任意进程暴露隐藏路径清单 + `%px` 真实内核指针；`pr_info("hide '%s'")` 无条件把路径名写进 dmesg，且不接 `susfs_enable_log` 开关；模块名在 `/proc/modules`、`/sys/module` 可查 | `sus_path.c:326-351/527-528` vs `susfs.c:31-38` |
| 5 | **中** | **目录项匹配维度不足**：只比 `(ino, name)`，不比 dev/sb → 跨文件系统同 `ino+name` **误伤**；又因按 inode 去重，**硬链接/别名路径的目录项不会被隐藏**（上游 `ilookup(sb, ino)` 按 inode 隐藏所有别名） | `sus_path.c:103/277/496-505` vs `patch:1752-1760` |
| 6 | **中** | **并发安全**：全局单缓冲 `dirent_tmp` 无锁（`sus_path_filter` 只用 `sus_path_lock` 保护链表），多个进程并发 `getdents64` 会互相踩缓冲 → 目标目录条目错乱/把别的目录内容写进当前缓冲 | `sus_path.c:94/284-292` |
| 7 | **中** | **LSM 槽位失败静默降级**：`ksu_register_lsm_hook()` 失败（如 SELinux 未注册 `inode_permission`/`inode_getattr` 槽、符号解析失败、track 表 16 条满）时 `sus_path_init()` 只 `pr_warn` 后仍 `return 0`，用户态 add 依旧拿到 `err=0` → 路径层静默失效、只剩目录项层 | `sus_path.c:374-388`、`lsm_hook.c:51-54/254-258` |
| 8 | **中低** | **未覆盖 syscall 集合**：`chmod/fchmodat`、`chown`、`utimes` 不经 `inode_permission`/`inode_getattr`（v5.15 `chmod_common()`/`chown_common()` 只调 `security_path_*`）→ LKM 不拦，而上游在 lookup 层拦；`readlink` 同理（`patch:507` 注释 "Does not call security hook"） | v5.15 `fs/open.c` 核对 + `patch:507` |
| 9 | **中低** | **FUSE 特判缺失**：/sdcard(MediaProvider FUSE) 场景上游给 `fi->inode.i_mapping` 与外壳 `inode->i_mapping` **双打标**，LKM 只有一个 inode 对象；(ino,name) 匹配能否对上 app 看到的 `d_ino` 需实测 | `sus_path.c` 无 FUSE 代码 vs `susfs.c:71-84/151-161` |
| 10 | **中低** | **资源**：每个条目永久 `ihold` + 上限 8192 → 钉住 inode/superblock（影响回收与卸载），上游只置一个 bit、无上限 | `sus_path.c:471-478/487-493` vs `susfs.c:78-88` |
| 11 | **低** | **大缓冲丢条目**：`reclen > DIRENT_BUF_SIZE - out` 时 `break` 退出循环，剩余未处理条目被静默丢弃（当用户传入 >64KB 缓冲且可见内容接近 64KB 时触发） | `sus_path.c:54/266-267/283-294` |
| 12 | **低** | **回写失败仍改返回值**：`copy_to_user` 失败时 `return count`，但缓冲已被部分改写（out 字节），用户态可能解析到半新半旧的 dirent 链 | `sus_path.c:291-294` |
| 13 | **低** | legacy `getdents`/`old_readdir` 未覆盖（上游 5 个回调全覆盖）；`hide_name` 语义（全局按名）与上游完全不同、易误伤；`ino == 0` 的告警文案承诺了并未实现的"按名回退" | `patch:1649/1698`；`sus_path.c:110-111/480-484` |
| 14 | **低（需实测）** | 上游 `lookup_fast` 只在 `LOOKUP_LAST\|OPEN_LAST` 同时置位时丢弃 dentry（`patch:210/227`），LKM 的 getattr/permission 无条件生效 → 在"非 open 末组件 + dcache 命中"组合下两者可能有 errno/副作用差异（例如上游可能落到 `lookup_open` 的 `O_CREAT` 分支）**(推测，未验证)** | `patch:205-238/330-366` |

---

## 8. 结论一句话

LKM 版用"`sys_exit` 重写 getdents64 缓冲（目录项层）+ 替换 `selinux_inode_getattr`/`selinux_inode_permission` 两个 LSM 槽（路径层）"复刻了上游"`filldir64` 跳过 + `namei.c` 12 处注入"的**结果**；对 native 64 位进程的 stat/open/exec/access/truncate/chdir 基本等价，但**在 `_LOOP` 预注册语义、compat 与 legacy dirent 出口、目录项匹配维度（无 sb、按 inode 去重）、门控（无 TIF_PROC_UMOUNTED/userns 映射）、FUSE 特判、覆盖 syscall 集合（chmod/chown/readlink）**六处存在实质差异，另有并发缓冲、隐蔽性（hide_list/dmesg/模块可见）两类工程缺陷。
