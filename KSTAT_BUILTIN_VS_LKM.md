# SUSFS `sus_kstat`（stat 伪装）：builtin 与 LKM 移植版逐项对比

对比对象
- 上游 builtin：`workfile/susfs4ksu/kernel_patches/fs/susfs.c`、`include/linux/susfs.h`、`include/linux/susfs_def.h`、`50_add_susfs_in_gki-android13-5.15.patch`、`KernelSU/10_enable_susfs_for_ksu.patch`；用户态 `ksu_susfs/jni/features/sus_kstat.c`，以及 `workfile/SukiSU-Ultra/userspace/ksud/src/susfs/{abi/consts.rs,cmd/kstat.rs}`（现代调用方）
- LKM 移植版：`workfile/susfs4ksu-lkm/kernel/{susfs_kstat.c,susfs_abi.h,susfs_supercall.c,sus_map.c,sus_path.c,TECHNICAL_NOTES.md}`

结论速览
1. 上游只有 **3 个注入点**：`fs/stat.c` 的 `generic_fillattr()`、`fs/stat.c` 的 `vfs_getattr_nosec()`、`fs/proc/task_mmu.c` 的 `show_map_vma()`。LKM 只覆盖前两个的“等价位置”，**第 3 个（/proc/pid/maps 的 dev:ino）完全没有对应实现**。
2. LKM 的主 hook 是 `sys_exit` tracepoint 且只认 `newfstatat`/compat `fstatat64`，其余（`fstat`、`statx`、compat `fstat64`…）**全部依赖一个 kretprobe 后备**；kretprobe 注册失败时没有任何用户可见状态。
3. LKM 无任何门控（上游要求 `AS_FLAGS_SUS_KSTAT` 位 + `susfs_is_current_proc_umounted_app()`），即 root/init/ksud 也看到伪装值。
4. LKM 把 `KSTAT_SPOOF_CTIME_TV_SEC` 修正为 `(1 << 8)`（上游 typo `(1 < 8)` = 1），因此**用带同样 typo 的 C 版 `ksu_susfs` 做静态 add 时，ctime.tv_sec 不再被伪装**（ksud 用 `1 << 8`，无此问题）。
5. `update_sus_kstat_full_clone` 语义分叉：上游该命令的 flags 在核里被丢弃（等价于普通 update），LKM 的 /proc 版真的加上了 NLINK|SIZE。

---

## 1. 上游注入点（patch 行号）

补丁文件：`susfs4ksu/kernel_patches/50_add_susfs_in_gki-android13-5.15.patch`

| 注入点 | patch 行 | 作用 |
|---|---|---|
| `fs/stat.c` include + `extern susfs_sus_kstat_spoof_generic_fillattr` | 1878–1894（`@@ -18,12 +18,23 @@`） | 声明 |
| `generic_fillattr()` 末尾（`stat->blocks = inode->i_blocks;` 之后）加 `susfs_sus_kstat_spoof_generic_fillattr(inode, stat)` | 1902–1909（`@@ -56,6 +67,9 @@`，调用在 1907） | **主路径**：所有走通用填充的文件系统（ext4/f2fs/tmpfs 等，`vfs_getattr_nosec` 的 fallback）在返回前被改写 |
| `vfs_getattr_nosec()`：把 `return inode->i_op->getattr(...)` 改成块语句，成功后再调一次 spoof | 1912–1927（`@@ -120,8 +134,18 @@`，调用在 1921） | **外层/叠加文件系统路径**：文件系统自带 `->getattr`（overlayfs、ecryptfs、FUSE 等）返回后、以及 `generic_fillattr` 之外的情况，在“最终 kstat”上再改写一次 |
| `vfs_fstat()`：`ksu_handle_vfs_fstat(fd, &stat->size)` | 1945–1955（`@@ -180,10 +211,20 @@`） | **与 sus_kstat 无关**，是 KernelSU 自己的 init-rc size 钩子；sus_kstat 覆盖 fstat 靠的是 1948 行的 `vfs_getattr()` 内部的上面两个注入点 |
| `vfs_statx()`：`getname_flags`+`ksu_handle_stat`（1980–1993）、`stat->mnt_id` 伪装（2002–2010） | 1976–2014（`@@ -218,12 +262,38 @@`） | 前者是 KSU 的 sus-compat 路径、后者属于 **SUS_MOUNT**；sus_kstat 覆盖 statx 靠 2000 行 `vfs_getattr(&path, stat, ...)` 内部的注入点 |
| `fs/proc/task_mmu.c` `extern susfs_sus_kstat_spoof_show_map_vma` | 1250–1256 | 声明 |
| `show_map_vma()`：`dev = inode->i_sb->s_dev; ino = inode->i_ino;` 之后调用 `susfs_sus_kstat_spoof_show_map_vma(inode, &dev, &ino)` | 1265–1298（调用在 1297） | 让 `/proc/pid/maps` 头部（以及 5.15 里同样调用 `show_map_vma()` 的 `show_smap()`，即 smaps 头部；此点未在本仓库内核源码中复核，推测）显示伪装的 `dev:ino` |
| `show_smap()` / `show_smaps_rollup()` / `pagemap_read()` 的过滤 | 1302–1371 | 属于 **SUS_MAP**，与 sus_kstat 无关 |

未被 patch 的相关函数（重要）：`cp_new_stat()`、`cp_compat_stat()`、`cp_statx()`、`vfs_fstatat()` 都没有 sus_kstat 注入——上游是在 **kstat 结构被填好之后、编码进用户缓冲区之前**改写，所以一条注入覆盖 stat/lstat/fstatat/fstat/statx 及其 compat 变体。

上游实现（`susfs4ksu/kernel_patches/fs/susfs.c`）
- 数据结构：`susfs_mutex_lock_sus_kstat` + 10 桶 hashtable（271–272），每条 entry 保存完整 `st_susfs_sus_kstat` + `target_ino/target_dev/is_fuse`。
- `susfs_mark_inode_sus_kstat()`（274–318）：`kern_path` → 在 `inode->i_mapping->flags` 上 `set_bit(AS_FLAGS_SUS_KSTAT)`（309，位号见 `susfs_def.h:65` = 35）；FUSE 分支改打在 `fi->inode.i_mapping`（300）并记 `is_fuse=true`、`target_dev=fi->inode.i_sb->s_dev`（301–302）。
- `susfs_add_sus_kstat()`（320–432）：`spoofed_dev` 先按架构解码（341–349）、`target_ino` 直接用调用方给的值（351）、`memcpy` 整个 info（352）、按 pathname 去重（356–391）、`hash_add_rcu`（420）。
- `susfs_update_sus_kstat()`（434–486）：按 pathname 找旧条目（454–455）→ `memcpy` 旧 info（456）→ 只替换 `target_ino`（457/460）→ 重新打标（461）→ 旧条目 RCU 删除（469–473）；找不到返回 `-ENOENT`（479）。
- `susfs_sus_kstat_spoof_generic_fillattr()`（488–560）：FUSE 分支 496–509；**门控** 502–504 / 516–518；按 `(target_ino, target_dev, is_fuse)` 匹配（525–528）；12 个字段**逐位判断**后写 `stat->xxx`（531–554）。
- `susfs_sus_kstat_spoof_show_map_vma()`（562–610）：同样门控（575–577/589–591），匹配后**无条件**写 `*out_dev/*out_ino`（603–604，不看 flags）。

LKM 实现（`susfs4ksu-lkm/kernel/susfs_kstat.c`）
- 规则表：定长数组 32 条 + 路径字符串 128 字节（66–67、90–92），无 RCU；按 `(target_ino, target_dev)` 线性查（127–136）。
- 主 hook：`register_trace_sys_exit(kstat_sys_exit)`（311–332、684），只有在 `ret==0` 且 nr 为 `__NR_newfstatat`（native）或 `327`（compat fstatat64，125/324）时才改写用户 statbuf（native 偏移 95–106，compat 偏移 110–121）。
- 后备 hook：`register_kretprobe("vfs_getattr")`（336–403、690），entry 取 x0/x1，return 时若成功则按 `(inode->i_ino, new_encode_dev(inode->i_sb->s_dev))` 查表并改写 `struct kstat`（350–395）。
- 写回：native 直接 `copy_to_user` 到 asm-generic `struct stat` 偏移；compat 写 ARM EABI `struct compat_stat` 偏移。

---

## 2. 覆盖对照表

| 上游注入点 | 覆盖的场景 | LKM 用哪个机制覆盖 | LKM 覆盖不到 / 有差异的场景 |
|---|---|---|---|
| `generic_fillattr()`（stat.c:1907） | 无 `->getattr` 的文件系统的 `stat/lstat/fstatat/fstat/statx` 全部 | ① `sys_exit`+`newfstatat` tracepoint（311–332）；② `vfs_getattr` kretprobe（385–395） | 在 `newfstatat` 被 LTO 内联链里，`generic_fillattr` 与 `vfs_getattr` 都在 syscall 入口内联（`TECHNICAL_NOTES.md:8-19` 实测 `vfs_statx/cp_new_stat/vfs_getattr_nosec/generic_fillattr` 命中 0），所以此时**只有 tracepoint 生效**；tracepoint 不认 nr 的场景全靠 kretprobe |
| `vfs_getattr_nosec()`（stat.c:1921） | 自带 `->getattr` 的文件系统 / 叠加层（overlayfs、FUSE、ecryptfs）的“最终 kstat” | kretprobe 打在**同一个函数的外层入口** `vfs_getattr` 上（397–403），语义位置等价 | 若 `vfs_getattr` 的调用点被内联（`TECHNICAL_NOTES.md:16` 只说“有命中，但只覆盖 fstat/statx 等其它路径”，未按 syscall 分解），该途径整体失效；此时 LKM 对非 newfstatat 的 syscall 无任何覆盖 |
| `vfs_fstat()` / `fstat(2)`（fd 的 stat） | ✅ | 仅 kretprobe（tracepoint 只认 `__NR_newfstatat`，328 行） | `fstat(fd)`、`fstat(O_PATH fd)`、compat `fstat64`/`fstat` 都**不在 tracepoint 的 nr 白名单里** |
| `vfs_statx()` / `statx(2)` | ✅（`statx` 的所有 inode 字段） | 仅 kretprobe | tracepoint 不匹配 `__NR_statx`；`stx_mnt_id` 的伪装是上游 **SUS_MOUNT** 的活（patch 2003–2007），LKM 的 `sus_mount.c:43` 只用 `mnt_id` 决定“跳过 mountinfo 行”，**两端都没有 statx mnt_id 伪装**（差异存在于两个 feature，不只是 kstat） |
| `newfstatat(2)` + `AT_EMPTY_PATH`（对 O_PATH fd） | ✅ | ✅ tracepoint（syscall 层，路径形式无关） | 无（这一点 LKM 与上游等价；相对路径/符号链接/硬链接也都等价，因为匹配键是 inode 号） |
| compat（32 位 AArch32）`fstatat64` | ✅ | ✅ tracepoint（`COMPAT_FSTATAT64_NR=327`，125/324） | 只覆盖 `fstatat64`；compat `fstat64(197)`、`fstat(108)`、`statx` 不在白名单，只能靠 kretprobe |
| compat 语义细节 | 由 `cp_compat_stat()` 处理 32 位截断与 `EOVERFLOW` 校验 | LKM 自己往 compat struct 里写，`spoofed_ino` 被 `(unsigned int)` 截断（247） | `st_size/blocks/blksize/ino` 超出 32 位时，上游会由 `cp_compat_stat` 报 `-EOVERFLOW`（进程收到错误、缓冲区不被改写），LKM 静默截断并成功返回（推测，本地无内核源码可核对 `cp_compat_stat` 细节） |
| `show_map_vma()`（task_mmu.c:1297） | `/proc/<pid>/maps` 与 `/proc/<pid>/smaps` 头部的 `dev:ino` | **无**：`susfs_kstat.c` 全文没有 `show_map_vma`/task_mmu 相关代码；`sus_map.c:60-81` 的 `show_map_vma` kprobe 只按 **SUS_MAP 自己的 ino 集合**整行跳过（24–58、144–145） | 同一个文件：`stat()` 显示伪装 ino/dev，而 `maps` 显示真实 ino/dev → 这是**最容易被检测的不一致**，也是上游本注入点存在的理由。smaps 头部同理（推测：5.15 的 `show_smap()` 会调用 `show_map_vma()`） |
| `statfs(2)` / `fstatfs(2)` | sus_kstat 本来就不碰（上游 `fs/statfs.c` 的 patch 属 SUS_MOUNT/OPEN_REDIRECT 的 fsid） | 不适用 | 不适用（不计入差异） |

LKM 相对上游“多出来”的覆盖方式
- 规则匹配不再依赖 inode 上的标志位，而是纯 `(ino,dev)` 查表（127–136），因此**不需要** `kern_path` 之外的任何 inode 状态；代价见第 8 节（inode 号复用误伤、无 is_fuse 判别）。
- 额外提供 `/proc/susfs_kstat` 运行时接口（`add_sus_kstat` / `add_sus_kstat_statically` / `update_sus_kstat` / `update_sus_kstat_full_clone` / `del` / `clear`，772–813）；上游 kstat **没有** proc 接口，也没有 del/clear 命令（只有同 path 覆盖与 UPDATE）。

---

## 3. 三个命令的语义对比

上游分发：`KernelSU/10_enable_susfs_for_ksu.patch:2878-2886` —— `ADD_SUS_KSTAT`→`susfs_add_sus_kstat`、`UPDATE_SUS_KSTAT`→`susfs_update_sus_kstat`、`ADD_SUS_KSTAT_STATICALLY`→**同一个** `susfs_add_sus_kstat`。
LKM 分发：`susfs_supercall.c:137-141` → `susfs_kstat_supercall(cmd,...)`（622–655）。

### 3.1 `ADD_SUS_KSTAT` (0x55570)

| 项 | 上游 | LKM | 差异 |
|---|---|---|---|
| 语义 | “在 bind mount/overlay **之前**调用，把当时的 stat 存进内核” | 同（注释 8–11） | 等价 |
| `target_ino` 来源 | **调用方给的值**（susfs.c:351），同时作为 hash key | 内核 `kern_path`+`d_backing_inode` 取 `i_ino`（424） | 上游信任用户态（stale 就静默失效）；LKM 自己解析 |
| `target_dev` | 用户态值经解码（341–349）后由 `mark` 覆盖为 `inode->i_sb->s_dev`（311） | `new_encode_dev(inode->i_sb->s_dev)`（425） | LKM 存**编码值**并在热路径直接与用户 statbuf 逐字节比对（注释 72–73），省一次解码；等价但两套编码约定并存（见 §4/§8） |
| `spoofed_*` 12 个值 | **完全来自用户态 struct**（352），内核不 stat | 内核读 inode 字段（426–437，`blksize = 1 << i_blkbits`） | 通常一致；对 overlay/FUSE 等“用户态 stat 输出 ≠ inode 字段”的场景可能不同（推测） |
| `flags` | 拷贝调用方的 flags（352） | 强制 `= KSTAT_AUTO_SPOOF`（481，本文件自己的宏 58–62） | 见 §4 位对比 |
| dev 解码 | `old_decode_dev`/`new_decode_dev`/`huge_decode_dev` 按架构（341–349） | 不解码，原样存 | 见 §8-12 |
| inode 打标 | `set_bit(AS_FLAGS_SUS_KSTAT, inode->i_mapping->flags)`（309）+ `is_fuse`/`target_dev` | **无** | LKM 的匹配不靠标志位，见 §2/§8 |
| 重复条目 | 同 pathname 时替换（356–391，`kfree` 旧条目，旧条目按 `info.target_ino` 桶查找） | 同 pathname 原地覆盖（469–476） | LKM 去重更严（上游只在同一个 ino 桶里比对 pathname，ino 变了会留两条） |
| 空 pathname | `-EINVAL`（330–333） | 无校验 → `kern_path("")` 的错误（-ENOENT 之类），且**槽位已先占**（473–475 在 478 的 fill 之前） | 错误码不同 + 失败后残留一条空条目 |
| 容量/内存失败 | 每次 `kzalloc`，失败 `-ENOMEM`（335–339）；条数无上限 | 定长 32 条，满 `-ENOSPC`（471–472） | 上限差异；LKM 无动态分配失败 |
| 错误码 | `-EFAULT/-EINVAL/-ENOMEM/kern_path 错误/0`；注意 `mark` 的内部 `-ENOENT` 是**死代码**（287–291 设 err 后 315–317 仍 `return 0`），所以 inode 没打上标也报成功 | `-EFAULT/-EINVAL(默认)/-ENOSPC/kern_path 错误/0`（622–655） | 上游“假成功”行为 LKM 不模仿 |

### 3.2 `UPDATE_SUS_KSTAT` (0x55571)

| 项 | 上游 | LKM | 差异 |
|---|---|---|---|
| 入口 | `susfs_update_sus_kstat`（434–486） | `susfs_kstat_update(path, full_clone=false)`（485–498；ABI 走 641） | 等价 |
| 查找键 | 全表按 **pathname strcmp**（454–455） | 按 pathname（490） | 等价（都要求字符串完全一致） |
| target_ino/target_dev 更新 | `target_ino = 调用方给的 info.target_ino`（457/460）；`target_dev` 由 `mark` 重新解析（458→311） | `kern_path(path)` 重新解析 **ino+dev 两个**（444–462） | 上游信任用户态 ino；LKM 以路径为准（用户态给了 stale ino 时上游静默失效，LKM 仍生效） |
| `spoofed_*` 保留 | `memcpy` 旧 info（456）→ size/blocks/nlink 等**全部保留 add 时的值**（这就是“size/blocks 保持当前 stat”的实现方式） | 只改 target_ino/dev，`spoofed_*` 不动（444–462） | 等价 |
| `flags` 保留 | 旧 flags 一起 memcpy（456）→ **调用方 UPDATE 时传的 flags 被丢弃** | `e->flags \|= full_clone ? FULL_CLONE : AUTO`（496） | **同 ABI 调用（641 传 false）时效果等价；但 LKM 的 /proc `update_sus_kstat_full_clone`（798–799）会真的加上 `NLINK\|SIZE`，而上游的 `update_sus_kstat_full_clone` 因 flags 被丢弃实际等价于普通 update**——上游这份实现里“full clone 让 stat 与原文件完全一致”只能靠 `ADD_SUS_KSTAT_STATICALLY` 或旧版本核实现 |
| 未找到 | `-ENOENT`（479） | `-ENOENT`（491–492） | 等价 |
| 打标 | 对新 inode 重新 `set_bit`（461） | 无 | 同 §5/§6 |

### 3.3 `ADD_SUS_KSTAT_STATICALLY` (0x55572)

| 项 | 上游 | LKM | 差异 |
|---|---|---|---|
| 实现 | **与 ADD 同一函数**（dispatch 2884–2886），`is_statically` 唯一作用见 §7（只影响日志 427–431） | 独立函数 `susfs_kstat_add_statically_abi`（586–619） | 机制不同、语义同 |
| spoofed_* | 调用方给的 12 个值（352） | 调用方给的 12 个值（605–616） | 等价 |
| `flags` | 调用方给（352） | 调用方给（617） | 等价公式，但**位定义不同**见 §4 |
| `target_ino/target_dev` | 调用方 target_ino（351）+ 路径解析出的 s_dev（311） | 路径解析出的 i_ino + `new_encode_dev(i_sb->s_dev)`（601→424–425） | 上游若调用方 `target_ino` 写错就静默失效 |
| 先决条件 | 路径必须能被 `kern_path` 解析（280–284） | 同（415–422） | 等价 |
| 上游用户态行为 | C 工具（`sus_kstat.c:109-269`）：逐字段 `strcmp("default")`，非 default 才置位；`ksud/kstat.rs:109-158`：**`flags: 0` 全传**（149 行） | LKM 的 /proc 版自己解析 12 个字段并置位（525–582，`default` 语义 512–521） | 对 `ksud` 的静态 add，上游与 LKM **都因 flags=0 而实际不伪装任何字段**（等价，都是 no-op）；对 C 工具，LKM 少伪装 ctime.tv_sec（见 §4） |

---

## 4. `KSTAT_SPOOF_*` 12 位对比

| 位 | 名称 | 上游 `susfs.h:63-74` | LKM `susfs_abi.h:91-102` | 一致? |
|---|---|---|---|---|
| 0 | INO | `1 << 0` | `1 << 0` | ✅ |
| 1 | DEV | `1 << 1` | `1 << 1` | ✅ |
| 2 | NLINK | `1 << 2` | `1 << 2` | ✅ |
| 3 | SIZE | `1 << 3` | `1 << 3` | ✅ |
| 4 | ATIME_TV_SEC | `1 << 4` | `1 << 4` | ✅ |
| 5 | ATIME_TV_NSEC | `1 << 5` | `1 << 5` | ✅ |
| 6 | MTIME_TV_SEC | `1 << 6` | `1 << 6` | ✅ |
| 7 | MTIME_TV_NSEC | `1 << 7` | `1 << 7` | ✅ |
| 8 | **CTIME_TV_SEC** | `(1 < 8)` → **值为 1（= bit0 的别名）**（`susfs.h:71`） | `1 << 8` → 256（`susfs_abi.h:99`，显式注明是“修正上游 typo”） | ❌ **故意分叉** |
| 9 | CTIME_TV_NSEC | `1 << 9` | `1 << 9` | ✅ |
| 10 | BLOCKS | `1 << 10` | `1 << 10` | ✅ |
| 11 | BLKSIZE | `1 << 11` | `1 << 11` | ✅ |

`KSTAT_AUTO_SPOOF` 只是**用户态**宏（核里没有）：上游核只逐位判断 `flags & KSTAT_SPOOF_*`。
- C 工具版（`ksu_susfs/jni/features/sus_kstat.c:17-32`）同样带 typo `(1 < 8)`，故其 AUTO = `0xEF3`（bit8 空、bit0 重复）。
- ksud 版（`SukiSU-Ultra/userspace/ksud/src/susfs/abi/consts.rs:46-59`）用正确的 `1 << 8`，AUTO = `0xFF3`、FULL_CLONE 再加 bit2|bit3。
- LKM 自己的宏（`susfs_kstat.c:58-64`）等于 ksud 的 `0xFF3` / `0xFF3|NLINK|SIZE`，且 LKM 核内判定用 bit8。

行为后果（逐调用方）

| 调用方/命令 | 上游核 | LKM | 一致? |
|---|---|---|---|
| ksud `add_sus_kstat`（AUTO=0xFF3） | bit0 命中 → ctime.tv_sec **被**伪装（巧合正确） | LKM 重算 AUTO(bit8) → ctime.tv_sec 被伪装 | ✅ 结果一致 |
| C 工具 `add_sus_kstat`（AUTO=0xEF3） | bit0 命中 → ctime.tv_sec 被伪装 | LKM 重算 AUTO → ctime.tv_sec 被伪装 | ✅ 结果一致 |
| ksud `update_sus_kstat_full_clone`（FULL_CLONE） | flags 被丢弃（456）→ size/nlink **不**伪装 | ABI UPDATE 传 false（641）→ 同样不伪装 | ✅（都与 ksud 文档不符） |
| LKM `/proc` `update_sus_kstat_full_clone`（798–799） | 无此接口 | `flags \|= FULL_CLONE` → size/nlink 被伪装（add 时的值） | ❌ /proc 专有行为 |
| C 工具 `add_sus_kstat_statically` 只填了 ctime（例：`... default default default 1712592355 ...`） | `flags` 得到 bit0 → **ctime.tv_sec 被伪装**（同时 INO 位被置，但 spoofed_ino 就是当前 ino，无副作用） | `flags` 得到 bit0 → LKM 判定 bit8 未置 → **ctime.tv_sec 不伪装** | ❌ LKM 少伪装 |
| 只发 bit8（未来按“正确位”实现的第三方工具） | 无任何字段被伪装 | ctime.tv_sec 被伪装 | ❌ 反方向分叉 |
| 只发 bit0 但没要求 ctime | 顺带伪装 ctime.tv_sec（上游 bug） | 不伪装 ctime.tv_sec | ❌（LKM 是“正确”的，但不等价） |

`is_statically` 字段在两侧都没参与语义：上游只用于选择日志文案（427–431）与 hash 日志（365–382）；LKM 的 `st_susfs_sus_kstat.is_statically`（`susfs_abi.h:105`）**在任何地方都没被读取**（全仓库 grep 只命中定义处），LKM 用命令号（637–639）区分静态/动态，效果与上游一致（都只看 flags + 调用方给的字段）。

---

## 5. FUSE 特判

上游有两处 FUSE 分支，LKM 一处都没有（LKM 全仓库无 `FUSE_SUPER_MAGIC` / `get_fuse_inode`）。

| 环节 | 上游 | LKM |
|---|---|---|
| 打标（ADD/UPDATE） | `inode->i_sb->s_magic == FUSE_SUPER_MAGIC` → 用 `get_fuse_inode(inode)`，把 `AS_FLAGS_SUS_KSTAT` 打在 `fi->inode.i_mapping->flags`（susfs.c:293-307）；`target_dev = fi->inode.i_sb->s_dev`（302）；日志打印 `fi->nodeid`（303-304） | 无；只记 `(inode->i_ino, new_encode_dev(inode->i_sb->s_dev))`（424-425） |
| 匹配判别 | hash 命中后还要求 `entry->is_fuse == is_fuse`（527、600）——FUSE 与普通 inode 用两条独立命名空间 | 无 `is_fuse`，只有 `(ino,dev)` |
| 伪装时的目标键 | FUSE：`target_ino = fi->inode.i_ino`、`target_dev = fi->inode.i_sb->s_dev`（505-507、578-580）；普通：`inode->i_ino/i_sb->s_dev`（520-521、593-594） | 只有普通分支的 `inode->i_ino / inode->i_sb->s_dev`（356，kretprobe 路径） |
| 适用场景 | 让“叠加在 FUSE 之上的路径”（如 Android 的 FUSE 存储/overlay 组合）在两种 inode 视图下都能匹配 | 依赖 `kern_path` 解析出的那个 inode 与 stat 报告的 ino/dev 恰好一致 |

影响评估（标注推测）：纯 FUSE 文件系统上 `d_backing_inode()` 与 FUSE 自身的 inode 是同一对象，(ino,dev) 大概率能对上；但**FUSE + overlay（或 `fi->inode` 与 VFS inode 不同）时，上游靠 `fi->inode` 归一化，LKM 没有归一化手段**，可能出现“规则加了但 stat 不伪装”。另外缺少 `is_fuse` 判别意味着一旦同 dev 下出现 ino 相同的 FUSE/非 FUSE 组合，LKM 会误伪装（上游不会）。

---

## 6. 门控对比

上游（`susfs_def.h:122-125`）：
```c
static inline bool susfs_is_current_proc_umounted_app(void) {
	return (likely(test_thread_flag(TIF_PROC_UMOUNTED)) && current_uid().val >= 10000);
}
```
- `susfs_sus_kstat_spoof_generic_fillattr()` 的 4 个返回点里，两组门控写成 `test_bit(AS_FLAGS_SUS_KSTAT, ...) && susfs_is_current_proc_umounted_app()`（502-504、516-518）；
- `susfs_sus_kstat_spoof_show_map_vma()` 同样（575-577、589-591）。
即：**inode 位 + 线程位（TIF_PROC_UMOUNTED）+ uid>=10000** 三重条件，缺一不伪装；root/adb shell/init/zygote（未打 umounted 标志时）看到的是真实 stat。

LKM：`susfs_kstat.c` 的 tracepoint（311-332）、kretprobe（385-395）与改写函数（149-227、230-306、350-383）**没有任何门控**——不查 uid、没有线程标志、没有模块参数开关（对比 `sus_path.c:161-216` 至少有 `hide_from_apps` + uid 代理）。唯一的 uid 检查在 supercall 层：只允许 `current_uid().val == 0` 下发命令（`susfs_supercall.c:180`），那是“谁能改规则”，不是“谁能看到伪装”。

后果
1. **伪装对所有进程生效**：root shell、ksud、init、zygote 全部看到伪装值（上游刻意不这样，以免 post-fs-data 阶段的 mount 逻辑被自己的伪装干扰）。
2. 无法复现上游“app 看不到、root 看得到”的双视图语义；任何以 root 身份做的校验都只能看到伪装值（既可能更隐蔽，也可能让依赖真实 ino 的 root 工具行为异常）。
3. LKM 侧也没有等价于 `TIF_PROC_UMOUNTED` 的实现路径（该线程标志由上游 patch 的 `fs/exec.c`/zygote 逻辑设置），所以即使想对齐也只能用 uid 近似（`TECHNICAL_NOTES.md:258-262` 对 sus_path 就是这么处理的，kstat 连 uid 近似都没做）。

---

## 7. 错误码与写回字段

| 路径 | 上游 | LKM |
|---|---|---|
| 读 payload 失败 | `info.err = -EFAULT`（325-327 / 440-443），仍走 `copy_to_user` 只写 `err` | 同（627-630 → 652-654），且注释明说要与上游一致（647-651） |
| 空 pathname | `-EINVAL`（330-333，仅 ADD 分支） | 无校验 → `kern_path` 的错误码；槽位已占（473-475 / 548-550 / 595-598） |
| 分配/容量 | `-ENOMEM`（335-339 / 445-449）；条数无上限 | `-ENOSPC`（471、546、594）；上限 32 |
| 路径解析失败 | `kern_path` 错误码直接 `return`（280-284） | `kern_path` 错误码（415-422、450-457、601-603） |
| inode 为空 / 无 i_mapping | `-ENOENT` 被吞掉（287-291 + 315-317 永远 `return 0`）→ ADD 报**成功**但没打标 | `-ENOENT`（419-422、454-457）→ 真实报错（且槽位残留） |
| UPDATE 未跟踪 | `-ENOENT`（479） | `-ENOENT`（491-492） |
| 未知 cmd | KSU 层 `default` 落到 reboot 正常流程（`10_enable_susfs_for_ksu.patch:2925+` 之外） | `err = -EINVAL` 初值（625），switch 不命中就保持 -EINVAL（633-643） |
| 成功 | `info.err = 0`（388/422/474） | `err = 0`（482/497/581/618） |
| 回写 | **只写 `->err`**（424-426、482-484；注释在 LKM 647-654 复述） | ✅ 只写 `->err`（652-654），未回写整个结构体（这是刻意的 ABI 对齐，`TECHNICAL_NOTES.md:217-219`） |
| `/proc` 接口（LKM 独有） | — | 无论成败都 `return len`（810-812），失败只 `pr_warn`（810-811）→ 调用方（`test_kstat.sh:12` 等）**拿不到 errno**，脚本无法判断失败 |

`is_statically` 的实际作用
- 上游：**只影响日志**。`susfs_add_sus_kstat` 结尾 `if (!info.is_statically) 日志"CMD_SUSFS_ADD_SUS_KSTAT" else 日志"CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY"`（427-431），另外出现在 365-382 的 SUS_KSTAT_HLIST 日志里；**不参与任何分支/字段选择**，且 3 个命令中它真正的行为差异来自调用方填的 `flags`/`spoofed_*`。
- LKM：`st_susfs_sus_kstat.is_statically`（`susfs_abi.h:105`）**从未被读取**；静态/动态由命令号决定（634-642）。所以“影响日志 vs 影响语义”在两侧都是“只影响日志”，LKM 连日志都没用。

---

## 8. 缺失/缺陷清单（按严重度）

### 高
1. **`/proc/<pid>/maps`、`smaps` 的 `dev:ino` 完全不伪装**。上游有专门注入点（patch 1265-1298）；LKM 的 `show_map_vma` kprobe 只服务于 SUS_MAP 的“整行跳过”（`sus_map.c:6-13, 60-81`），与 kstat 规则无关。后果：同一文件 `stat` 与 `maps` 互相矛盾，是最直接的检测面。
2. **非 `newfstatat` 的 syscall 全部押注在 kretprobe 上，且失败无感知**。tracepoint 只认 `__NR_newfstatat`/327（324-330）；`fstat`、`fstat(O_PATH)`、`statx`、compat `fstat64`/`fstat` 只能靠 `vfs_getattr` kretprobe（384-403），而该内核把 `newfstatat` 链整体内联（`TECHNICAL_NOTES.md:8-19`），`vfs_getattr` 只对“未内联的调用者”生效（同文件 16 行，未给出按 syscall 的命中分解 → 这几类 syscall 的覆盖属**未经直接验证**）。注册失败时只 `pr_warn`（691-692），`/proc/susfs_kstat` 不显示 hook 状态，用户无法察觉功能静默降级。
3. **没有任何门控**（对比上游 `susfs_def.h:122-125` + `susfs.c:516-518`）：root/init/zygote/ksud 也看到伪装值；无 `TIF_PROC_UMOUNTED` 等价物，也没有 `hide_from_apps` 式开关（`sus_path.c:166-216` 有）。既偏离上游语义，也可能干扰以 root 运行的挂载/校验逻辑。
4. **读路径无锁**：tracepoint（311）与 kretprobe（385）在无锁状态下遍历 `kstat_entries`/`nkstat`（127-136），而写路径 `/proc` 的 add/update/del/clear 会整体搬移结构体（509 的 `kstat_entries[i] = kstat_entries[--nkstat]`）——这是**内核数据竞争**，可能出现“flags 已是新值、spoofed_* 还是旧值”甚至读到正在被覆盖的条目，把真实 ino/dev 或半更新的值写进用户 statbuf。上游用 mutex + hashtable + `synchronize_rcu()`（271-272、383-386、469-473）规避。

### 中
5. **bit8 语义分叉导致 C 工具静态 add 少伪装 ctime.tv_sec**（`susfs_abi.h:99` vs `susfs.h:71`，LKM 判定在 217-221，flags 逐字复制在 617）。反向分叉同样存在（只发 bit8 的调用方在上游无效、在 LKM 有效）。若要严格 ABI 兼容，需要按调用方区分或同时接受 bit0/bit8。
6. **FUSE 特判整体缺失**（上游 293-307/496-509/527/600；LKM 无）：无 `fi->inode` 归一化、无 `is_fuse` 判别，FUSE/叠加场景可能匹配不上或误匹配（推测）。
7. **规则键是 `(ino,dev)` 而非 inode 标志位**：inode 号被复用（原目标被删除/换文件）后，新的无关文件会继承伪装值（上游的位打在 inode mapping 上，随 inode 消亡而失效）。
8. **写路径失败时槽位泄漏 + 路径截断**：`add`/`add_statically` 先 `nkstat++` 再 fill（473-478、548-556、595-603），fill 失败留下一条 `flags=0` 的残条目占位；`KSTAT_PATH_MAX=128`（67）而 ABI 路径字段 256（`susfs_abi.h:52`），长路径被 `strscpy` 截断（474/549/596，返回值未检查）→ `del`/去重按完整字符串比较会失配，重复 add 可能累积多条。
9. **`update_sus_kstat_full_clone` 与上游不一致**：上游 UPDATE 丢弃调用方 flags（susfs.c:456-460），LKM 的 /proc 版会真的加上 NLINK|SIZE（496）。要么算“实现了上游文档意图”，要么算“ABI 语义偏离”，取决于对齐目标；ABI 路径（641）与上游一致。
10. **`/proc` 写接口没有错误反馈**：失败只 `pr_warn` 并仍 `return len`（810-812），`test_kstat.sh` 这类脚本无法区分成功/失败。
11. **卸载/注册路径的脆弱性（已有前科）**：设备日志 `last_kmsg.txt:11324` 记录过一次 `susfs_kstat_exit() → unregister_kretprobe() → unregister_kretprobes` 的**内核 panic**（当时的 init 日志串是 `susfs: kstat spoof: no rules, hook not installed`，见 `last_kmsg.txt:111596`，与当前代码的 `kstat armed: %d rules` 不同，说明是旧构建）。当前版本已用 `kstat_krp_registered`/`kstat_tp_registered` 守卫（673-716，git 提交 `8ced16a`“fix: kstat guard kretprobe/tracepoint unregister with registered flags”），但每次改这块都应在设备上回归 rmmod。

### 低
12. **dev 编码不走上游的解码链**（上游 341-349 的 `old_decode_dev`/`huge_decode_dev`）：LKM 的 ABI/`/proc` 接口把用户给的值当**编码值**直接写进 statbuf（tracepoint 路径），kretprobe 路径则 `new_decode_dev`（362）。对 minor<256 的常见设备两者等价；minor≥256 或调用方给 old-style dev 时会与上游不同（理论差异，本机无法复核 arm64 走的是哪个上游分支 → 推测）。
13. **compat 截断 vs 内核 `EOVERFLOW`**：LKM 直接把 `spoofed_ino/size/blocks` 截成 32 位（247、262-263、272-273），上游交给 `cp_compat_stat` 校验并可能返回 `-EOVERFLOW`（推测，未核对内核源码）。
14. **每次 stat 都走一次 syscall 退出 tracepoint，且无规则时仍做两次 `copy_from_user`**（149-166，`nkstat==0` 没有短路）；有规则时对每个进程的每次 `newfstatat` 线性扫 32 条（131-136）。上游是 inode 位测试，O(1) 且带门控。可在 `kstat_sys_exit` 首行加 `if (!nkstat) return;` 并考虑用有序数组/哈希。
15. **覆盖率验证脚本不完整**：`test_kstat.sh:9-27` 只用 `stat`（即 newfstatat）验证，未覆盖 `fstat`/`statx`/compat/`maps`；建议用现有 `kstat_probe_test.c`（26-34 行已列出 `vfs_statx/cp_statx/cp_new_stat/vfs_getattr/vfs_getattr_nosec/generic_fillattr` 计数）补一份按 syscall 的命中表，把第 2 条的“未验证”变成实测结论。

---

## 附：可复用的对齐/修补方向（基于仓库内已有的机制）
- LKM 已经有 `ksu_patch_text()` + `scan_call_to()`（`patch_memory.c:142-176`）和运行时 LSM hook 替换（`lsm_hook.c:73-96`、`sus_path.c:153-159` 已用 `inode_getattr`/`inode_permission`）。也就是说，“像上游那样在 VFS 层改 kstat”在技术上可行（例如替换/补丁 `generic_fillattr` 或 `vfs_getattr_nosec` 的调用点），而不必依赖 tracepoint 的 nr 白名单。
- `inode_getattr` 这类 LSM hook 的签名只有 `struct path *`（`sus_path.c:146-148`），拿不到 `struct kstat`，因此**不能**用它做 kstat 值伪装——想补覆盖仍要回到 VFS 层或 syscall 层。
- 若要补 maps：`sus_map.c` 的 `show_map_vma` kprobe 已经拿到了 `struct vm_area_struct`，把它从“整行跳过”扩展成“改写 `show_vma_header_prefix` 的 dev/ino 参数”即可覆盖上游 task_mmu 注入点的语义（上游就是改写 `dev/ino` 两个局部变量，patch 1293-1298）。
