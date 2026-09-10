# SUSFS builtin vs LKM 移植版：open_redirect / sus_map 逐项差异报告

对比对象：

- 上游（内核内建，GKI android13-5.15）：`susfs4ksu/kernel_patches/fs/susfs.c`、`kernel_patches/include/linux/susfs.h`、`kernel_patches/include/linux/susfs_def.h`、`kernel_patches/50_add_susfs_in_gki-android13-5.15.patch`（下称 `patch:N`）
- LKM 移植版：`susfs4ksu-lkm/kernel/susfs_open_redirect.c`、`susfs4ksu-lkm/kernel/sus_map.c`、`susfs4ksu-lkm/kernel/susfs_abi.h`
- 基线内核旁证（结构对照用，非 patch 目标树）：`workspace/android_kernel_oneplus_sm8550/fs/namei.c`、`fs/open.c`、`fs/proc/task_mmu.c`、`fs/proc/base.c`

标注约定：未标注的结论均可在所引 `文件:行号` 直接读到；带 **（推测）** 的是基于代码结构推出的行为，未实测。

---

## A. open_redirect

### A1. 5 档 uid_scheme

**上游枚举**（`susfs.h:28-34`）：`UID_NON_APP_PROC=0, UID_ROOT_PROC_EXCEPT_SU_PROC=1, UID_NON_SU_PROC=2, UID_UMOUNTED_APP_PROC=3, UID_UMOUNTED_PROC=4`。

`uid_scheme` 只在**正向重定向**路径里被判定，位置是 `susfs_open_redirect_spoof_do_sys_openat()` 的 switch（`susfs.c:941-964`）。每个 case 的判定原文与语义：

| scheme | 原文判定（`susfs.c`） | 语义 | 命中后动作 |
|---|---|---|---|
| 0 `UID_NON_APP_PROC` | `943: if (current_uid().val % 100000 < 10000)` → `break`；否则 `945: goto out_srcu_read_unlock` | 非 app 进程（uid < 10000，或 uid%100000<10000 的 Android 多用户映射） | 继续到 `967` 生成伪 filename |
| 1 `UID_ROOT_PROC_EXCEPT_SU_PROC` | `947: if (current_uid().val == 0 && !susfs_is_current_ksu_domain())`；否则 `949: goto` | uid==0 且**不在** KernelSU su 域 | 同上 |
| 2 `UID_NON_SU_PROC` | `951: if (!susfs_is_current_ksu_domain())`；否则 `953: goto` | 任何非 su 域进程（含普通 app） | 同上 |
| 3 `UID_UMOUNTED_APP_PROC` | `955: if (susfs_is_current_proc_umounted_app())`；否则 `957: goto` | 被标记为 umounted 的 app 进程 | 同上 |
| 4 `UID_UMOUNTED_PROC` | `959: if (susfs_is_current_proc_umounted())`；否则 `961: goto` | 所有被标记 umounted 的进程（含 init 派生） | 同上 |
| 默认 | `962-963: default: goto out_srcu_read_unlock` | 非法值不重定向 | 返回 NULL |

补充要点：

- 判定的入口门控是 `SUSFS_IS_INODE_OPEN_REDIRECT_WITHOUT_UID_CHECK`（`susfs_def.h:144-146`，只有 flag 位、无 uid 检查），**uid 检查被刻意推迟到 susfs.c 的 switch 内**（`patch:395`、`patch:436`、`patch:479`）。
- **反向伪装完全不看 `uid_scheme`**：读侧 6 处注入点用的都是 `SUSFS_IS_INODE_OPEN_REDIRECT`（`susfs_def.h:148-151` = flag 位 **且** `susfs_is_current_proc_umounted_app()`）。也就是说哪怕规则是 scheme 0，readlink/statfs/fdinfo/maps 的伪装也只在 umounted app 进程里生效——这是一个容易被忽略的硬编码门控。
- `susfs.c:937-940` 命中还需 `entry->target_dev == inode->i_sb->s_dev` 且 `!entry->reversed_lookup_only`。

**LKM（`or_uid_matches()`，`susfs_open_redirect.c:68-77`）**

- 只有 `case UID_NON_APP_PROC:` 返回 `current_uid().val % 100000 < 10000`（`:71-72`），与上游 scheme 0 判定完全一致。
- `default:` 返回 `false`（`:73-76`）——**返回的是布尔 false，不是错误码**。
- 但实际运行时 `default` 分支对已存规则**不可达**：`or_add()` 在更早的地方就把 scheme 1..4 挡掉了——`scheme < 0 || scheme > 4 → -EINVAL`（`:246-247`），`scheme != 0 → -EOPNOTSUPP`（`:248-249`）。所以：**越界返回 `-EINVAL`，1..4 档返回 `-EOPNOTSUPP`（95）**。
- 附带影响：用户态 `PRT_MSG_IF_CMD_NOT_SUPPORTED` 只在 `err == ERR_CMD_NOT_SUPPORTED(126)` 时提示（`ksu_susfs/jni/features/open_redirect.c:97-99`），故 `-EOPNOTSUPP` 会以裸错误码 95 静默返回。**（推测：`ksu_susfs add_open_redirect ... 1..4` 会返回 95 而无任何提示。）**

### A2. 上游注入点清单（含正/反两类条目）

先说明数据模型：一次 `add` 会生成**两条 hlist 条目**（`susfs.c:844-863`）——正向条目 `reversed_lookup_only=false`（`:849`），反向条目 `reversed_lookup_only=true`（`:859`），反向条目的 `target_pathname`/`redirected_pathname` 被对调（`:862-863`），并把 target 侧的 `mnt_id` 快照为 `spoofed_mnt_id`（`:850`、`:860`）、把 target 的 `kstatfs` 快照为 `spoofed_kstatfs`（`:851`、`:861`）。两条条目的 `AS_FLAGS_OPEN_REDIRECT`（位号 36，`susfs_def.h:66`）被同时打在 target 与 redirected 两个 inode 的 `i_mapping->flags` 上（`:898-899`、`:916-917`）。

**正向（重走 lookup 换 filename）**

| # | 注入点 | 行号 | 门控 | 作用 |
|---|---|---|---|---|
| 1 | `path_openat()` | `patch:465-501`（门控 `478-479`，重走 `484-490`，`do_open` 仍在 `494-495`） | `..._WITHOUT_UID_CHECK(nd->path.dentry->d_inode)` + `!is_nd_state_root_preset` | 常规 open/openat/execve 主路径：命中后 `terminate_walk` → `restore_nameidata` → `set_nameidata(nd, old_dfd, fake_filename, NULL)` → `path_init` + `link_path_walk`/`open_last_lookups` 重走 |
| 2 | `do_tmpfile()` | `patch:384-409`（门控 `395`，重走 `399-406`） | 同上（此处 inode 是**目录**） | O_TMPFILE：在**重定向后的目录**里建临时文件 |
| 3 | `do_o_path()` | `patch:426-458`（门控 `435-436`，重走 `440-447`，`vfs_open` 在 `452`） | 同上 | O_PATH：重走后 `vfs_open(&path)` 用重走结果 |
| — | extern 声明 | `patch:135-137` | — | `susfs_open_redirect_spoof_do_sys_openat()`（实现 `susfs.c:932-975`） |

三处都带 `is_nd_state_root_preset` 保护（`patch:386`、`428`、`467` 取自 `nd->state & ND_ROOT_PRESET`）→ **root 预设（如 openat2 的 RESOLVE_IN_ROOT 类场景）下上游故意不重定向**。

**反向（把 redirected 文件伪装成 target）**

| # | 注入点 | 行号 | 作用 / 读取的伪装数据 |
|---|---|---|---|
| 4 | `vfs_readlink()` 两处 | `patch:510-548`（FS 自带 readlink 分支 `521-529`；通用分支 `540-548`） | 对 redirected inode 的 readlink 返回伪路径 `info.redirected_pathname`（反向条目里已被对调成**原 target 路径**，`susfs.c:862-863`）；实现 `susfs.c:977-1003`，buffer 不足返回 `-ENAMETOOLONG`（`:987-991`），无匹配返回 `-ENOENT`（`:1002`） |
| 5 | `fs/proc/base.c: do_proc_readlink()` | `patch:1062-1083` | `/proc/pid/{fd/N, exe, cwd, root}` 等 readlink（调用者 `proc_pid_readlink`，旁证 `fs/proc/base.c:1849`、`:1863`）返回伪路径；实现 `susfs.c:1005-1027`（`strscpy` 到内核 tmp buf，`:1020`） |
| 6 | `fs/proc/fd.c: seq_show()`（fdinfo） | `patch:1145-1217`（门控 `1208`，伪造输出 `1211-1214`） | `/proc/pid/fdinfo/N` 的 `pos/flags/mnt_id/ino`：`mnt_id` 用 `spoofed_mnt_id`（=target 的 mnt_id），`ino` 用反向条目的 `redirected_ino`（=**原 target 的 ino**）；实现 `susfs.c:1048-1064` |
| 7 | `fs/proc/task_mmu.c: show_map_vma()` | `patch:1257-1288`（extern/srcu `1258-1259`，命中分支 `1270-1288`） | `/proc/pid/maps`：把 mmap 的 redirected 文件的 `dev/ino/路径名` 改写成 target 的（`out_ino/out_dev/out_spoofed_name`，`susfs.c:1081-1083`）。调用方需自持 `susfs_srcu_open_redirect`（`susfs.c:1066`） |
| 8 | `fs/stat.c: vfs_statfs()` | `patch:2038-2056` | 对 redirected 路径的 `statfs` 返回 add 时快照的 target `kstatfs`（`susfs.c:1029-1046`，`memcpy` 在 `:1039`；无匹配返回 `-EINVAL` `:1045`） |
| — | 头文件包含 | `patch:1051-1053`（base.c）、`1133-1135`（fd.c）、`1244-1246`（task_mmu.c）、`2023-2025`（stat.c） | 引入 `susfs_def.h` 的宏 |

### A3. 覆盖对照表：LKM 只挂 `vfs_open` kprobe

LKM 的全部实现就是 `or_vfs_open_pre()`（`susfs_open_redirect.c:102-123`）+ kprobe 注册（`:125-128`、`:132-153`）。因此：

| 上游能力 | 上游位置 | LKM | 依据 |
|---|---|---|---|
| 常规 open 重定向 | `patch:477-493` | ✅ 覆盖（`vfs_open` 在 `do_open` 内被调用：`namei.c:3608`） | `susfs_open_redirect.c:121` |
| O_PATH 打开重定向 | `patch:434-449` | ✅ 覆盖（`do_o_path` 也调 `vfs_open(&path)`：`namei.c:3716`） | 同上 |
| **O_TMPFILE 重定向** | `patch:393-408` | ❌ **不能覆盖**：`do_tmpfile` 里 `vfs_open(&path)` 拿到的是**刚创建的 tmpfile 子 inode**（`namei.c:3692-3702`），而规则记的是**目录 inode**（`susfs_open_redirect.c:284-285`）→ 永不相交 | `namei.c:3685-3702`、`susfs_open_redirect.c:89-98` |
| 目录打开重定向 | 三处正向 | ✅ 覆盖（比对条件相同，均为 inode 匹配） | `namei.c:3591`、`3716` |
| 反向整条链路（readlink / proc_readlink / fdinfo / maps / statfs） | 上表 #4–#8 | ❌ **全部缺失**：LKM 里 grep 不到任何 readlink/statfs/seq_show/show_map_vma 相关代码，也没有 `reversed_lookup_only` 概念 | `susfs_open_redirect.c` 全文（仅 375 行，唯一 hook 是 `vfs_open`） |
| `AS_FLAGS_OPEN_REDIRECT` 位（36）标记 | `susfs.c:898-899`、`916-917` | ❌ 不存在（LKM 不能占用 address_space flag 位；改 (ino,dev) 数组匹配） | `susfs_open_redirect.c:54-66` |
| `uid_scheme` 1..4 | `susfs.c:946-961` | ❌ 拒绝 add（`-EOPNOTSUPP`） | `:246-249` |
| `ND_ROOT_PRESET` 保护 | `patch:386/394`、`428/435`、`467/478` | ❌ 无（LKM 不感知 nameidata） | — |
| `spoofed_mnt_id` / `spoofed_kstatfs` 快照 | `susfs.c:850-851`、`860-861` | ❌ 无 | — |

**实际后果（LKM 侧）**：app 打开 target 得到的是 redirected 文件，但

- `readlink("/proc/self/fd/N")` 与 `readlink(target)` 会显示 redirected 路径（`d_path(f_path)`），
- `/proc/self/fdinfo/N` 的 `mnt_id/ino` 是 redirected 的，
- `/proc/self/maps` 里该映射显示为 redirected 的路径/ino/dev，
- `statfs(redirected 所在 fs)` 不伪装，
→ 与上游"处处表现为 target"完全相反，检测成本极低。

**还要注意 LKM 是"过度覆盖"**：`vfs_open` 是 `dentry_open()` 的内部实现（`fs/open.c:1049`），而 `dentry_open()` 在内核里被大量子系统直接调用（fanotify `fs/notify/fanotify/fanotify_user.c:233`、ecryptfs `fs/ecryptfs/file.c:276`、incfs `fs/incfs/pseudo_files.c:252`、unix socket `net/unix/af_unix.c:2994`、`open_tree`/`fsopen` 类 `fs/namespace.c:2452`、`:2500`、`:3706`、pty `drivers/tty/pty.c:626`、IMA `security/integrity/ima/ima_crypto.c:558` 等）。这些路径**不经过 `path_openat`**，上游不会重定向，LKM 会。**（推测：若 target 落在被这些子系统内部打开的对象上——例如 overlayfs/incfs 后端文件、或对 mountpoint 目录调用 `open_tree()`——LKM 会把内核内部语义一起改掉，属语义污染。）**

### A4. add 校验对比

| 校验项 | 上游 `susfs_add_open_redirect()` | LKM `or_add()` |
|---|---|---|
| `copy_from_user` 失败 | `susfs.c:781-784` → `-EFAULT` | 调用方处理：`:320-324`(proc) / `:360-363`(supercall) |
| `target_pathname` 为空 | ✅ `:786-790` → `-EINVAL` | ❌ 无显式检查（空串会让 `kern_path` 失败） |
| `redirected_pathname` 为空 | ❌ 不检查（靠 `kern_path` 失败） | ❌ 不检查 |
| `uid_scheme ∈ [0,4]` | ✅ `:792-796` → `-EINVAL` | ✅ `:246-247` → `-EINVAL`；**并额外 `:248-249` 把 1..4 拒为 `-EOPNOTSUPP`** |
| 解析顺序 | **先 redirected**（`:798-802`）**后 target**（`:804-808`） | **先 target**（`:252-259`）**后 redirected**（`:262-266`）——顺序对调，错误码优先级不同 |
| 解析 flags | `kern_path(..., 0, ...)` → **不跟随最后一级符号链接** | `kern_path(..., LOOKUP_FOLLOW, ...)`（`:252`、`:262`）→ **跟随**。差异：target/redirected 是符号链接时，上游记录**链接自身 inode**，LKM 记录**链接目标 inode** |
| inode / `i_mapping` 非空 | ✅ 两侧都查，`-ENOENT`（`:810-822`） | ⚠️ 只查 `d_backing_inode(tp.dentry)`（`:255-259`），不查 `i_mapping`；redirected 侧完全不查 |
| 排除 FUSE | ✅ 两侧 `s_magic == FUSE_SUPER_MAGIC` → `-EINVAL`（`:824-829`） | ❌ 无任何 FUSE 检查 |
| 分配失败 | `-ENOMEM`（`:831-842`） | 不适用（静态数组） |
| 容量上限 | 无上限（hlist 动态） | `SUS_OR_MAX = 64`（`:48`、`:270-274`）→ `-ENOSPC` |
| 路径长度 | `strscpy(..., SUSFS_MAX_LEN_PATHNAME - 1)` = 255（`:862-863`），与 ABI 256 一致 | `strscpy(e->target_pathname, target, OR_PATH_MAX)`，**`OR_PATH_MAX = 128`（`:49`、`:276`、`:283`）**，静默截断 |
| 去重语义 | 同 target_pathname 命中即替换；若命中的是**反向条目**则拒绝（`:867-881` → `-EINVAL`）；替换时先 `hash_del_rcu` 再 `hash_add_rcu`，并 `synchronize_srcu`（`:901`）后才 `kfree` | 同目标路径替换（`:268`、`:278-281`）；无反向条目概念；无同步屏障，直接 `path_put` 旧缓存 |
| 无匹配时 | 直接新增两条 | 新增一条（`:275-277`） |
| path 引用 | add 后 `path_put(&target_path)`、`path_put(&redirected_path)`（`:921-924`），**不长期持有** | **长期持有 redirected 的 `struct path` 基引用**（`:60`、`:286`，`del`/`exit` 时 put：`:305`、`:191`） |
| err 回写 | 只回写 `err` 字段（`:926-928`） | 只回写 `err` 字段（`:372-374`、`:163-165`）✅ 一致 |

### A5. 机制差异（重走 lookup vs 替换 vfs_open 参数）

上游：命中后 `restore_nameidata` + `set_nameidata(nd, old_dfd, fake_filename, NULL)` 重走（`patch:484-490`），redirected 路径在**打开时、在调用方上下文里按名字解析**。
LKM：add 时 `kern_path` 缓存 `struct path`（`:262`、`:286`），open 时把 `regs->regs[0]` 换成 `&e->redirected_path`（`:121`），`vfs_open` 做 `file->f_path = *path`（`fs/open.c:1032`）。

| 维度 | 上游 | LKM | 实际差别 |
|---|---|---|---|
| redirected 被删除 | 重走失败 → `error` 直接 **向上返回，open 失败**（`patch:403-406`、`444-447`） | 缓存 dentry 仍被基引用钉住 → **照旧打开已 unlink 的 inode** | LKM：静默成功且拿到"已删除文件"；上游：失败（甚至 O_CREAT 时会按 `op` 在 redirect 名上**新建**文件——**（推测）**） |
| redirected 被替换（rm+重建/模块重装同名文件） | 按名字重走 → 打开**新文件** | 仍指向**旧 inode**，规则不重加就永远读旧文件 | 典型场景（zygisk 模块热更新 so）行为相反 |
| inode 被释放 / ino 复用 | 门控在 inode flag 上（`susfs_def.h:148-151`），inode 释放后 flag 消失 → **天然免疫 ino 复用** | 规则永久持有 (ino,dev)（`:57-58`）；同 dev 内 ino 复用会把**无关文件**重定向过去 | LKM 正确性/隐蔽性缺陷 |
| 挂载点生命周期 | 不留引用 | 长期持有 `struct path` → **钉住 vfsmount/dentry**，模块不卸载则挂载点无法消失 | 内存/挂载泄漏，且卸载时机受限 |
| 权限检查对象 | 重走后的路径经 `do_open` → `may_open(&nd->path)`，检查的是 **redirected**（`namei.c:3606` 语义，patch 下 `nd->path` 已换） | `may_open`/O_CREAT/O_EXCL/EISDIR/sticky 检查都在 **target** 上（`namei.c:3581-3606`），`vfs_open` 之后才换成 redirected；`do_dentry_open` 只做 `get_write_access`（`fs/open.c:810`）与 `security_file_open`（`:832`），**不复查读权限** | ①SELinux/LSM 的 `inode_permission` 落在 target，`file_open` 落在 redirected → 检查被拆成两半；②**（推测）**可读到"调用方无读权限的 redirected 文件"（属权限绕过窗口，需能改规则者=root）；③反之 target 不可读时即使 redirected 可读也会被拒 |
| 路径遍历权限 | 重走要对 redirected 每一级目录做 `MAY_EXEC` 检查 | 直接用缓存 path，**完全不做**目录遍历检查 | LKM 可打开调用方无法 `cd` 进去的目录里的文件 |
| 命名空间/root | 在**调用方**的 `nd`（含 `old_dfd`、root、mnt ns）里解析（`patch:486`） | 使用**add 时那个进程**的 mnt/dentry 对象 | 跨 mount namespace 场景下 LKM 会把另一个命名空间的挂载对象塞给调用方 |
| 审计 | `audit_inode()` 记录的是重走后的**伪名**（`namei.c:3579` 在 do_open 内，此时 `nd->path/nd->name` 已换） | `audit_inode(nd->name, nd->path.dentry, 0)` 在换参**之前**执行（`namei.c:3579`）→ 审计日志暴露**真实 target** | 隐蔽性差异，且属旁路泄露 |
| O_TRUNC | `mnt_want_write(nd->path.mnt)` + `handle_truncate(file)` 都在 redirected mount 上 | `mnt_want_write(nd->path.mnt)` 取的是 **target 的 mount**（`namei.c:3601`），而 `handle_truncate(file)` 截断的是 **redirected** 文件（`namei.c:3612`，`file->f_path` 已被换） | 写计数/RO-mount/freeze 守卫落在**错误的挂载**上；**（推测）**可能截断刚被 remount-ro 的文件系统的文件 |
| fd 的 `f_path` | redirected 的真实路径（但反向伪装让 readlink/maps/fdinfo 看起来是 target） | redirected 的 add-time 缓存路径，**无任何伪装** | 见 A3 后果 |
| `FMODE_CREATED`/O_CREAT | 重走路径下 O_CREAT/O_EXCL 语义作用于 redirect 名 | 新文件创建判断在 target 上（target 必存在，故不可达），`vfs_open` 只在非 created 时调用 | 边界差异极小 |

---

## B. sus_map

### B6. 上游注入点

上游 `sus_map` 没有任何独立数据结构：add 时只在 inode 的 `i_mapping->flags` 上 `set_bit(AS_FLAGS_SUS_MAP)`（位号 39，`susfs_def.h:67`；`susfs.c:1115`）。

| # | 注入点 | 行号 | 作用 |
|---|---|---|---|
| 1 | `fs/proc/task_mmu.c: show_map_vma()` | `patch:1289-1292` | `/proc/pid/maps`：命中直接 `return`，整行不输出 |
| 2 | `fs/proc/task_mmu.c: show_smap()` | `patch:1306-1311`（插在函数开头、`memset` 之前） | `/proc/pid/smaps`：整块（header+统计）都不输出 |
| 3 | `fs/proc/task_mmu.c: show_smaps_rollup()` 两处 | `patch:1319-1327`（跳过 `smap_gather_stats`）与 `patch:1335-1342`（Case 4 分支同样跳过） | `/proc/pid/smaps_rollup` 聚合值里**不计入**被隐藏 vma（否则聚合值>明细和，会露馅） |
| 4 | `fs/proc/task_mmu.c: pagemap_read()` | `patch:1350-1368` | `/proc/pid/pagemap`：该 vma 范围不做 `walk_page_range` |
| 5 | `fs/proc/base.c: proc_map_files_readdir()` | `patch:1088-1095` | `/proc/pid/map_files/` 目录项不列出 |
| 6 | `mm/memory.c: __access_remote_vm()` | `patch:2216-2239` | `/proc/pid/mem` 与 `process_vm_readv/writev`：命中即 `break`，读不到 |
| — | 头文件包含 | `patch:1051-1053`（base.c）、`1244-1246`（task_mmu.c）、`2216-2218`（memory.c） | — |

（`/proc/pid/numa_maps` 在本仓库目标树中不存在实现——`mm/mempolicy.c` 内 grep 不到 `numa_maps`/`show_numa_map`——故两侧都未覆盖，不构成差异。）

### B7. LKM 覆盖与缺口

LKM 只挂 `show_map_vma`（`sus_map.c:78-81`，注册 `:95`、懒注册 `:151-159`），命中时 `regs->pc = regs->regs[30]` 跳过整行（`:72-73`）。

- ✅ `/proc/pid/maps`：`show_map()` 调用 `show_map_vma(m, vma)`（旁证 `fs/proc/task_mmu.c:355-366`），`vma` 取 `regs->regs[1]`（`sus_map.c:62`）正确。
- ❌ `/proc/pid/smaps`：**不是"不隐藏"，而是可能"输出畸形"**。`show_smap()` 内部同样调用 `show_map_vma(m, vma)`（`fs/proc/task_mmu.c:903`），而 LKM 只让被调函数提前返回，外层 `show_smap` 仍会打印 `Size:/KernelPageSize:/Rss/Pss/...`（`:905-913`）→ 出现**无标题的统计块**；上游是在 `show_smap` 入口 `return 0`（`patch:1306-1311`）。**（推测：若该调用点被 LTO 内联到 `show_smap`，则 kprobe 不命中、smaps 里整条 vma 完全可见——两种结果都与上游不同，需实测确认。）**
- ❌ `/proc/pid/smaps_rollup`：无任何"聚合时排除"逻辑 → 明细被隐藏而聚合值仍计入，可直接对比出隐藏 vma 的体量；上游有双重跳过（`patch:1319-1342`）。
- ❌ `/proc/pid/pagemap`
- ❌ `/proc/pid/map_files/`
- ❌ `/proc/pid/mem` 与 `process_vm_readv/writev`（`__access_remote_vm`）
- ❌ 无 `AS_FLAGS_SUS_MAP` 位机制 → 见 B8 门控差异
- ❌ 无 remove/del（与上游一致，上游也只有 add）

### B8. 门控对比

- 上游宏（`susfs_def.h:139-142`）：
  `inode && inode->i_mapping && test_bit(AS_FLAGS_SUS_MAP, &inode->i_mapping->flags) && susfs_is_current_proc_umounted_app()`
  → **flag 位（属于 inode）+ 每个调用点实时判定"当前进程是否为 umounted app"**。
- LKM（`sus_map_lookup()`，`sus_map.c:46-58`，调用点 `:70`）：只看 `(ino,dev)` 是否在数组里，**没有任何进程/uid/umounted 门控**。
- 后果：LKM 对**所有**进程隐藏（含 root shell、system_server、init）；上游只对 umounted app 隐藏（用户态文档亦如此描述：`ksu_susfs/jni/features/sus_map.c:28`）。**（推测：LKM 下 `su` shell 自己 `cat /proc/self/maps` 也会少一行，反而不利于"仅对 app 生效"的既定语义。）**
- 另：LKM 里也 grep 不到 `TIF_PROC_UMOUNTED`/umounted 相关判定（整个 LKM 仓库只有 `sus_path.c` 注释提到用 uid≥10000 代理该门控）→ **sus_map 连代理门控都没有**。

### B9. add 校验与数据结构对比

| 维度 | 上游 | LKM |
|---|---|---|
| 数据结构 | **无**：inode `i_mapping->flags` 的 `AS_FLAGS_SUS_MAP` 位（`susfs.c:1115`） | 定长数组 `map_entries[64]`，每项 `{target_ino, target_dev}`（`sus_map.c:24-32`） |
| 匹配 | inode 指针级（flag 随 inode 生命周期存在/消失） | `(ino, dev)` 数值匹配（`:46-58`、`:89-98`）→ 受 **ino 复用**影响：目标删除后 ino 被别的文件复用即误隐藏（同 dev 内），上游无此问题 |
| dev 处理 | 不涉及 | supercall 路径记录真实 `inode->i_sb->s_dev`（`:145`）；**insmod 参数路径 `sus_map_add(param_map_ino)` 只写 ino，dev 保持 0**（`:38-44`、`:35-36`）。而 `sus_map_lookup()` 对 `target_dev == 0` **跳过 dev 比较**（`:53-54`）→ **纯 ino 通配，跨文件系统误伤**（合理解释：调试用途） |
| 去重 | `set_bit` 天然幂等 | 无去重：重复 add 同一 ino 占多条，`map_ino` 与 supercall 也可重复 |
| 上限 | 无 | 64（`:24`、`:40`、`:139-143`）→ 满时 `-ENOSPC` |
| 路径解析 | `kern_path(target, LOOKUP_FOLLOW)`（`susfs.c:1103`）→ 跟随符号链接 | 同 `LOOKUP_FOLLOW`（`:127`）✅ 一致 |
| inode/mapping 校验 | `!inode \|\| !inode->i_mapping` → `-ENOENT`（`susfs.c:1109-1114`） | 只查 `!inode`（`:132-137`），不查 `i_mapping` |
| 路径名 | 只用一次，不保存 | supercall 保存 ino/dev，不存路径（`:144-145`）；`/proc` 无读接口，无法列出规则（`sus_map.c` 里没有 `_show`） |
| err 回写 | 只回写 `err`（`susfs.c:1121`） | 只回写 `err`（`:163-165`）✅ 一致 |
| 潜在缺陷 | — | `sus_map_add()` 对 `ino == 0` 会**提前 return 不入表**（`:40-41`），但 supercall 随后无条件写 `map_entries[nmap - 1].target_dev = ...`（`:145`）→ `nmap==0` 时**越界写 `map_entries[-1]`**；`nmap>0` 时会篡改**上一条**规则的 dev。**（推测：需 `i_ino == 0` 的文件系统对象才可达，概率低但为真实缺陷。）** |

---

## 缺失/缺陷清单（按严重度排序）

| # | 严重度 | 问题 | 证据 |
|---|---|---|---|
| 1 | **严重（内存安全）** | open_redirect 规则表**无 RCU/SRCU 保护**：pre_handler 在中断上下文无锁遍历 `or_entries`（`susfs_open_redirect.c:89-98`、`:114-121`），而 `or_add` 替换规则时**先 `path_put` 旧缓存、再赋新值**（`:280`→`:286`），`or_del` 也先 `path_put` 再移动条目（`:305-307`）→ 并发窗口内 `vfs_open` 可对**已释放的 dentry/mount** 做 `path_get`（UAF），且 `nor`/条目字段的更新对读侧非原子。上游用 `DEFINE_SRCU`（`susfs.c:770`）+ `hash_del_rcu` + `synchronize_srcu`（`:878`、`:901`）后才 `kfree`（`:903-904`）。 | `susfs_open_redirect.c:102-123` vs `:280`/`:305-307` |
| 2 | **严重（功能缺失）** | open_redirect **反向伪装 0 覆盖**：readlink、`/proc/*/fdinfo`、`/proc/*/maps`、`statfs`、`proc_readlink` 全不伪装 → redirected 的真实路径/ino/dev/mnt_id 直接暴露，功能目标（伪装成 target）未达成。 | `patch:510-548`、`1145-1217`、`1257-1288`、`2038-2056` vs `susfs_open_redirect.c` 全文 |
| 3 | **高（语义）** | 用 add-time 缓存 `struct path` 代替打开时按名重走：redirected 被删除仍成功打开陈旧 inode、被替换后永远读旧文件、长期钉住 mount、跨 mnt namespace 传递 add 时的挂载对象、不做目录遍历权限检查、`mnt_want_write` 落在 target mount 而截断发生在 redirected（`namei.c:3601` vs `3612`）。 | `susfs_open_redirect.c:262-266`、`:286`、`:121`；上游 `patch:484-490` |
| 4 | **高（语义/权限）** | 权限检查被拆成两半：`may_open`/O_CREAT/O_EXCL/EISDIR/sticky 在 **target**（`namei.c:3581-3606`）后才换参，`do_dentry_open` 只做 `get_write_access`（`fs/open.c:810`）与 `security_file_open`（`:832`）→ 可能把**调用方无读权限**的 redirected 文件交出去（SELinux `inode_permission` 与 `file_open` 也会落在不同 inode 上）。 | `namei.c:3606-3612`、`fs/open.c:788-832` |
| 5 | **高（过度覆盖）** | hook `vfs_open` 会连带重定向所有 `dentry_open()` 调用者（fanotify/ecryptfs/incfs/`open_tree`/pty/IMA/…），这些路径上游不覆盖 → 内核内部语义被改（**（推测）**：target 落在 overlayfs/incfs 后端、或对 mountpoint 调 `open_tree()` 时行为异常）。 | `fs/open.c:1049` + 上述调用点列表 |
| 6 | **中（功能缺失）** | uid_scheme 仅支持 0；1..4 直接 `-EOPNOTSUPP`（`:248-249`），且错误码不会触发用户态提示；`or_uid_matches` 的 `default` 分支对已存规则不可达（`:73-76`）。 | `susfs_open_redirect.c:68-77`、`:246-249` |
| 7 | **中（功能缺失）** | O_TMPFILE 无法重定向（LKM 匹配的是子 inode，`namei.c:3692-3702`；上游匹配目录 inode，`patch:394-397`）；`ND_ROOT_PRESET` 场景也无上游的"故意不重定向"保护。 | `namei.c:3685-3702` |
| 8 | **中（功能缺失）** | sus_map 只覆盖 `/proc/pid/maps`；`smaps`（且可能输出**畸形/无标题统计块**）、`smaps_rollup`（聚合值露馅）、`pagemap`、`map_files`、`/proc/pid/mem`+`process_vm_readv` 全缺。 | `sus_map.c:78-81`；上游 `patch:1289-1392`、`1088-1095`、`2216-2239`；`task_mmu.c:903` |
| 9 | **中（门控）** | sus_map 无 `susfs_is_current_proc_umounted_app()` 等价门控（`susfs_def.h:139-142`）→ 对所有进程生效，与上游/用户态文档语义相反。 | `sus_map.c:46-58`、`:70` |
| 10 | **中（数据一致性）** | 规则路径截断：`OR_PATH_MAX = 128`（`:49`）而 ABI 字段 256（`susfs_abi.h:146-147`）；`strscpy` 静默截断（`:276`、`:283`）→ 路径 >127 字符时 `del`/替换**静默失效**（`or_find_by_path` 比对的是截断串，`:79-87`、`:302`），旧规则仍持有缓存 path 且 `or_find_by_inode` 命中**旧条目**（`:89-98`）→ 更新重定向目标无效；`/proc` 显示也为截断值（`:204-209`）。 | `susfs_open_redirect.c:48-49`、`:79-87`、`:276`、`:283` |
| 11 | **中（误伤）** | 数值匹配无 inode 生命周期绑定：open_redirect 与 sus_map 都会因 **ino 复用**（同 dev）误伤无关文件；sus_map 的 insmod `map_ino` 路径 dev=0 → **纯 ino 通配、跨文件系统误伤**（`:42`、`:53-54`）。上游靠 inode flag 天然免疫。 | `susfs_open_redirect.c:57-58`、`sus_map.c:42`、`:53-54` |
| 12 | **低** | sus_map 潜在越界写：`sus_map_add()` 因 `ino == 0` 提前返回后，supercall 仍写 `map_entries[nmap - 1].target_dev`（`:145`）→ `nmap==0` 时写 `map_entries[-1]`。 | `sus_map.c:38-44`、`:144-145` |
| 13 | **低** | add 校验缺失项：无 FUSE 排除（上游 `susfs.c:824-829`）、无 `i_mapping` 校验（上游 `:810-822`）、无 target 空串检查（上游 `:786-790`）；解析顺序与上游相反（`:252`/`:262` vs `:798`/`:804`）；`LOOKUP_FOLLOW` 与上游 `flags=0` 不一致（符号链接目标语义不同）。 | `susfs_open_redirect.c:239-295` |
| 14 | **低** | `/proc/susfs_open_redirect` 写接口把错误吞掉：`or_proc_write()` 无论 `err` 为何都 `return len`（`:349-351`），用户态只能从 `pr_warn` 或 dmesg 判断失败；`cmd[640]` 超长静默截断（`:320-324`）；路径含空格会被 `split_ws` 拆开（`:220-237`）。 | `susfs_open_redirect.c:312-352` |
| 15 | **低** | `or_register()` 失败时规则已入表（`:275-287` 先入表，`:291-293` 才注册）→ 规则出现在 `/proc` 但完全不生效，且下次 add 会重试注册；`sus_map.c` 同类问题不存在（先注册失败才回写 err，但 ino 也已入表，`:144-160`）。 | `susfs_open_redirect.c:291-293`、`sus_map.c:139-160` |
| 16 | **低（能力宣称）** | `SHOW_ENABLED_FEATURES` 无条件输出 `CONFIG_KSU_SUSFS_OPEN_REDIRECT` / `CONFIG_KSU_SUSFS_SUS_MAP`（`susfs_supercall.c:85-86`），上游是按 `#ifdef CONFIG_*` 真实能力输出（`susfs.c:1220-1226`）→ 用户态会认为功能完整（实际 1..4 档、反向伪装、smaps 等均缺失）。 | `susfs_supercall.c:77-87` vs `susfs.c:1220-1226` |
| 17 | **低** | 规则只在内存：模块 `rmmod`/重载即清空（`susfs_open_redirect.c:190-192`、`sus_map.c:111`），上游重启清空；但 LKM 超级调用没有像 upstream 那样由 KernelSU 在启动阶段注入持久规则，需外部脚本重新下发。 | `susfs_open_redirect.c:181-193`、`sus_map.c:105-112` |

**LKM 相对上游的增强（非缺陷）**：`/proc/susfs_open_redirect` 提供 `del` / `clear` 与规则列举（`:195-213`、`:338-345`），上游无对应命令（用户态只有 `add_open_redirect`，`ksu_susfs/jni/features/open_redirect.c:51-101`）；sus_map 增加 insmod 参数 `map_ino` 便于调试（`sus_map.c:35-36`）。
