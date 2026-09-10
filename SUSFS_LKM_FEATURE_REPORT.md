# SUSFS LKM 移植版：完整功能清单与门控逻辑调研报告

调研对象：`C:\Users\ASUS\dsh\workfile\susfs4ksu-lkm\`（模块名 `susfs_guard_lkm`，目标 GKI 5.15，Full LTO + CFI + BTI + PAC + SCS）
调研方法：只读源码 + 注释。**所有结论均给出文件名与行号**；无法从本仓库代码证实、需要上游源码才能确认的，明确标注【推测】。

参与编译进 `susfs_guard_lkm.ko` 的源文件（`kernel/Makefile:20-23`）：
`susfs_main.o patch_memory.o symbol_resolver.o lsm_hook.o susfs_uname.o susfs_kstat.o sus_map.o sus_path.o sus_mount.o spoof_cmdline.o susfs_open_redirect.o susfs_enable_log.o susfs_avc_spoof.o susfs_supercall.o susfs_hide_syms.o`

其余 `.c`（`syscall_test / kstat_probe_test / open_probe_test / inode_perm_probe_test / enoent_probe_test / selinux_probe_test / selinux_hide_probe`，`Makefile:11-18`）是**独立探测/验证模块**，不属于 `susfs_guard_lkm`，本报告在第 3 节末尾单列。

---

## 1. 命令分发表

### 1.1 分发链路

- 通道：`syscall(SYS_reboot, 0xDEADBEEF, 0xFAFAFAFA, cmd_id, &payload)`（`susfs_abi.h:9-11`）。
- 挂点：kprobe `__arm64_sys_reboot`（`susfs_supercall.c:213-216`，注册在 `:224`）。
- 入口判定（`susfs_supercall.c:167-211`）：`magic1 == KSU_INSTALL_MAGIC1`（`:176`）、`magic2 == SUSFS_MAGIC`（`:178`）、`current_uid().val == 0`（`:180-181`）三者全过才处理。
- 延迟执行：`task_work_add(current, &tw->cb, TWA_RESUME)`（`:190`），真正分发在 `susfs_tw_func()`（`:115-165`）——kprobe pre_handler 在中断上下文不能 `copy_from_user`。
- 对 `reboot(2)` 返回值的镜像：`regs->pc = regs->regs[30]; regs->regs[0] = 0; return 1;`（`:208-210`），即处理成功让 reboot 返回 0。

### 1.2 switch 覆盖的命令（15 个）

dispatch 处为 `susfs_supercall.c:120-162`。

| CMD 宏 | 值 | 定义行 | 调用函数 | dispatch 行 |
|---|---|---|---|---|
| `CMD_SUSFS_SHOW_VERSION` | 0x555e1 | `susfs_abi.h:41` | `susfs_show_version()`（本地 static，`:46`） | `:121-123` |
| `CMD_SUSFS_SHOW_VARIANT` | 0x555e3 | `susfs_abi.h:43` | `susfs_show_variant()`（`:61`） | `:124-126` |
| `CMD_SUSFS_SHOW_ENABLED_FEATURES` | 0x555e2 | `susfs_abi.h:42` | `susfs_show_enabled_features()`（`:89`） | `:127-129` |
| `CMD_SUSFS_ADD_SUS_PATH` | 0x55550 | `susfs_abi.h:26` | `sus_path_supercall()` | `:130-133` |
| `CMD_SUSFS_ADD_SUS_PATH_LOOP` | 0x55553 | `susfs_abi.h:29` | 同上（**完全同路径**） | `:130-133` |
| `CMD_SUSFS_ADD_SUS_MAP` | 0x60020 | `susfs_abi.h:48` | `susfs_sus_map_supercall()` | `:134-136` |
| `CMD_SUSFS_ADD_SUS_KSTAT` | 0x55570 | `susfs_abi.h:33` | `susfs_kstat_supercall(cmd, &arg)` | `:137-141` |
| `CMD_SUSFS_UPDATE_SUS_KSTAT` | 0x55571 | `susfs_abi.h:34` | 同上（按 cmd 分支） | `:137-141` |
| `CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY` | 0x55572 | `susfs_abi.h:35` | 同上 | `:137-141` |
| `CMD_SUSFS_SET_UNAME` | 0x55590 | `susfs_abi.h:37` | `susfs_uname_supercall()` | `:142-144` |
| `CMD_SUSFS_ENABLE_LOG` | 0x555a0 | `susfs_abi.h:38` | `susfs_enable_log_supercall()` | `:145-147` |
| `CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING` | 0x60010 | `susfs_abi.h:47` | `susfs_avc_spoof_supercall()` | `:148-150` |
| `CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG` | 0x555b0 | `susfs_abi.h:39` | `susfs_spoof_cmdline_supercall()` | `:151-153` |
| `CMD_SUSFS_ADD_OPEN_REDIRECT` | 0x555c0 | `susfs_abi.h:40` | `susfs_open_redirect_supercall()` | `:154-156` |
| `CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS` | 0x55561 | `susfs_abi.h:31` | `susfs_sus_mount_supercall()` | `:157-159` |

### 1.3 有定义但**没有 handler** 的命令（8 个，全部是 deprecated）

`susfs_abi.h` 一共定义 23 个 `CMD_SUSFS_*`（`:26-48`），15 个有 handler，8 个走 `default` 分支（`susfs_supercall.c:160-162`）：

| CMD 宏 | 值 | 定义行 | 上游标记 |
|---|---|---|---|
| `CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH` | 0x55551 | `susfs_abi.h:27` | deprecated |
| `CMD_SUSFS_SET_SDCARD_ROOT_PATH` | 0x55552 | `susfs_abi.h:28` | deprecated |
| `CMD_SUSFS_ADD_SUS_MOUNT` | 0x55560 | `susfs_abi.h:30` | deprecated |
| `CMD_SUSFS_UMOUNT_FOR_ZYGOTE_ISO_SERVICE` | 0x55562 | `susfs_abi.h:32` | deprecated |
| `CMD_SUSFS_ADD_TRY_UMOUNT` | 0x55580 | `susfs_abi.h:36` | deprecated |
| `CMD_SUSFS_SHOW_SUS_SU_WORKING_MODE` | 0x555e4 | `susfs_abi.h:44` | deprecated |
| `CMD_SUSFS_IS_SUS_SU_READY` | 0x555f0 | `susfs_abi.h:45` | deprecated |
| `CMD_SUSFS_SUS_SU` | 0x60000 | `susfs_abi.h:46` | deprecated |

文件头注释明确说明这是有意为之：deprecated 命令"defined for ABI completeness only: no handler is wired for them, exactly like upstream kernels"（`susfs_abi.h:22-25`）。

### 1.4 分发层的三处行为细节（与上游的差异）

1. **不支持的命令不会回写 `ERR_CMD_NOT_SUPPORTED`**。`default` 分支只 `pr_info`（`susfs_supercall.c:161`），既不写 `payload->err`，也不返回错误——reboot syscall 仍然返回 0。`ERR_CMD_NOT_SUPPORTED 126` 虽在 `susfs_abi.h:50` 定义，但**全仓库没有任何引用点**（grep 仅命中定义行本身）。调用方若依赖 err==126 判定"命令不支持"（`test_sc.c:96,101,107` 就以 126 作为初值占位），将看到 err 保持原值。
2. **`susfs_show_enabled_features()` 在 `kzalloc` 失败时静默返回**（`:95-97`），不写回 err。
3. **`enabled_features` 列表 9 项，但缺 AVC spoofing**。列表（`susfs_supercall.c:77-87`）为 SUS_PATH / SUS_MOUNT / SUS_KSTAT / SPOOF_UNAME / ENABLE_LOG / HIDE_KSU_SUSFS_SYMBOLS / SPOOF_CMDLINE_OR_BOOTCONFIG / OPEN_REDIRECT / SUS_MAP = **9 项**，而 `CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING` 已实现（`susfs_avc_spoof.c`）却未列入。`TECHNICAL_NOTES.md:193` 又写设备上"返回 …8 个 feature"，与代码的 9 项不一致【推测：笔记写在把 `SUS_MAP` 加进列表之前，属文档过期】。也没有 `CONFIG_KSU_SUSFS_AVC_LOG_SPOOFING` 这一项。

---

## 2. 每个功能的实现方式与生效条件

### 2.0 生效条件总览

| 功能 | 默认是否生效 | 生效条件 | uid 门控 |
|---|---|---|---|
| supercall 通道 | 是（kprobe 常驻） | magic1/magic2 匹配 **且 uid==0** | 仅"必须 uid 0"（`susfs_supercall.c:180`） |
| SUS_PATH（两层） | hook 常驻，注册后生效 | `ADD_SUS_PATH` / `ADD_SUS_PATH_LOOP` 注册条目 | `hide_from_apps`，见 2.1 |
| SUS_KSTAT | hook 常驻 | 存在规则时才改写 | **无任何 uid 判断** |
| SPOOF_UNAME | **默认关** | insmod `release`+`version`+`uname_spoof_enabled=1`，或 `CMD_SET_UNAME`（**启用后全局对 root/app 都生效**） | 无 |
| ENABLE_LOG | flag 默认 false | `/proc/susfs_enable_log` 或 `CMD_ENABLE_LOG`；**但没有消费者**（见 2.6） | 无 |
| HIDE_SUS_MNTS | **默认关**（不注册 kprobe） | `CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS` 且 `enabled=1` | 无（**对全部进程隐藏**，非"仅非 su 进程"） |
| SPOOF_CMDLINE_OR_BOOTCONFIG | 默认关 | insmod `bootconfig=` 或 `CMD_SET_CMDLINE_OR_BOOTCONFIG` | 无（全局） |
| OPEN_REDIRECT | `vfs_open` kprobe 常驻 | `ADD_OPEN_REDIRECT`，且 uid_scheme 只能是 0 | scheme 0 → `uid % 100000 < 10000` |
| SUS_MAP | 有规则才注册 kprobe | insmod `map_ino=` 或 `CMD_ADD_SUS_MAP` | 无 |
| AVC spoof | **默认关** | `/proc/susfs_avc_spoof` 写 `1` 或 `CMD_ENABLE_AVC_LOG_SPOOFING` | 无 |
| HIDE_KSU_SUSFS_SYMBOLS | **默认开**，无常驻开关 | 无条件注册 kprobe（`susfs_hide_syms.c:101`） | 无 |

模块加载顺序：`susfs_main.c:20-37`（symbol_resolver → lsm_hook → uname → kstat → sus_map → sus_path → sus_mount → spoof_cmdline → open_redirect → enable_log → avc_spoof → supercall → hide_syms），卸载反序（`:39-54`）。

---

### 2.1 `susfs_supercall.c` — 命令分发

- **实现**：kprobe `__arm64_sys_reboot` 的 pre_handler（`susfs_supercall.c:167`，注册 `:224`）。
- **独立于上游的机制**：上游 patch `kernel/reboot.c` 的 `SYSCALL_DEFINE4(reboot)` 分支进 `ksu_handle_sys_reboot()`；LKM 无法 patch，改成 kprobe + `task_work`（文件头 `:9-11`、`:18-20` 自述）。arm64 syscall-wrapper quirk 处理见 `:14-17` 与 `:169`（`real_regs = (struct pt_regs *)regs->regs[0]`）。
- **门控**：见 1.1。**只校验 uid==0，没有任何 KSU 域/manager 身份校验**（`susfs_supercall.c:180` 是全文件唯一的凭证判断）。【推测】上游 `ksu_handle_sys_reboot` 是否额外校验 KSU 域或 manager 应用，本仓库代码中无对应实现，需查上游确认。
- **简化/缺失**：不支持的命令静默（1.4 第 1 点）。

### 2.2 `sus_path.c` — SUS_PATH（双层实现）

**实现了什么**：让注册过的 inode 在目录列表里消失（层 1），并让按路径访问返回 `-ENOENT`（层 2）。

**挂点（两条独立链路）**：

| 层 | 机制 | 挂点 | 代码 |
|---|---|---|---|
| 1 目录项 | **sys_exit tracepoint** | `register_trace_sys_exit(sus_path_sys_exit)`，只处理 `__NR_getdents64` | `:365`,`:517`,`:297-323`,`:305` |
| 2 路径 | **LSM hook 槽位替换** | `inode_getattr` ← 替换 `selinux_inode_getattr` | `:153-155`,`:374` |
| 2 路径 | **LSM hook 槽位替换** | `inode_permission` ← 替换 `selinux_inode_permission` | `:157-159`,`:381` |

层 1 重写用户 dirent 缓冲区并缩小返回字节数（`sus_path_filter()` `:249-295`；`regs->regs[0] = new_count` `:322`）。层 2 命中即 `return -ENOENT`（`:227`、`:241`）。

**独立于上游的机制**：上游用 `AS_FLAGS_SUS_PATH` inode flag + patch `filldir64()` + patch `fs/namei.c` 三处；LKM 无法 patch，改为上述两条链路（`:3-33`、`:116-133` 自述）。

**门控条件**：

| 判定 | 位置 | 语义 |
|---|---|---|
| `hide_from_apps` module param，默认 `1` | `:166-167` | 总开关 |
| `sus_path_gate_uid_ok()` | `:195-200` | `!hide_from_apps` → true；否则 `current_uid().val >= 10000` |
| `sus_path_gate_ok()` | `:209-216` | `!hide_from_apps` → true（**整体绕过，含归属检查**）；`uid < 10000` → false；再要求 `current_uid().val != inode->i_uid.val`（不隐藏调用者自己拥有的文件） |
| getdents 层 | `:280-281` | 只用 `sus_path_gate_uid_ok()`（只有 inode 号、拿不到 inode，无法做归属检查） |
| LSM 层 | `:225`、`:239` | 用完整 `sus_path_gate_ok()` |
| `hide_name` module param | `:91-92`、`:110-111` | legacy/debug：单一 basename 全局 `strcmp` 命中；**只作用于 getdents 层**（`sus_path_inode_hidden()` `:172-190` 不查 `hide_name`） |
| 上限 / 去重 | `:55`,`:487`（8192）；`:496-505`（按 inode 指针去重，重复 add 返回 err=0） | — |
| `hide_list` 只读参数 | `:326-351` | 打印 `hide_from_apps`、getattr/perm 命中计数与全部条目 |
| ihold | `:475` | inode 必须被引用住，否则 dentry 释放后指针悬空 |

**被简化或缺失的上游判定**：

1. **上游 `susfs_is_current_proc_umounted_app()`（`TIF_PROC_UMOUNTED` 线程标志）被 `uid >= 10000` 代理**（`:161-165` 注释明说 LKM 没有该线程标志）。这是最核心的门控语义偏差：上游是"zygote 派生且已 umount 的 app"，本实现是"任何 uid≥10000 的进程"。
2. 上游的 `AS_FLAGS_SUS_PATH` inode flag 机制整体不存在，改为链表 + 指针比较。
3. **`unlink` / `rename` 拦不住**（作用于父目录 inode，不是目标文件，`:131-132`）。
4. `ADD_SUS_PATH_LOOP` 与 `ADD_SUS_PATH` 完全同路径（`:425-430`），上游 `_LOOP` 的"zygote 起 app 后重新打 flag"语义在此被"链表常驻 + 无条件匹配"替代。
5. **文档与代码不一致**：`TECHNICAL_NOTES.md:258-262` 写"本 LKM 无条件隐藏，root 也看不到"，但当前代码已有 `hide_from_apps` 门控（默认 app-only）——该段笔记已过期。

### 2.3 `susfs_kstat.c` — SUS_KSTAT

**实现了什么**：按 `(target_ino, target_dev)` 匹配，改写 stat 输出的 12 个字段（ino/dev/nlink/size/atime/atime_nsec/mtime/mtime_nsec/ctime/ctime_nsec/blocks/blksize），每字段有独立 `KSTAT_SPOOF_*` 位（`susfs_abi.h:91-102`）。

**挂点（两条）**：

| 机制 | 挂点 | 覆盖 | 代码 |
|---|---|---|---|
| **sys_exit tracepoint** | native `__NR_newfstatat` | 直接改写用户 statbuf（native 偏移 `:95-106`） | `:311-332`,`:328-331`,`:684` |
| **sys_exit tracepoint** | compat `COMPAT_FSTATAT64_NR = 327` | 改写 `struct compat_stat`（偏移 `:110-121`） | `:323-326`,`:125` |
| **kretprobe** | 导出符号 `vfs_getattr` | 改写内核 `struct kstat`（覆盖 fstat/statx/direct caller） | `:397-403`,`:690`,`:350-395` |

**独立于上游的机制**：上游在 `cp_new_stat`/`generic_fillattr` 一侧打补丁；本实现走 syscall 出口 + `vfs_getattr` 后备（文件头 `:30-34` 说明 LTO 把 `vfs_fstatat→vfs_statx→vfs_getattr→cp_new_stat` 全内联，VFS 层 kprobe 不可靠，`TECHNICAL_NOTES.md:8-22` 有实测数据）。

**门控条件**：**没有 uid 门控，没有 module 参数开关**。唯一"条件"是：必须存在规则、`ret == 0`（`:316`）、`statbuf != 0`（`:320`）。规则的增删改由两个接口提供：
- supercall（`susfs_kstat_supercall()` `:622-655`，按 cmd 三分支）；
- `/proc/susfs_kstat`（0666，`:680`）命令式接口：`add_sus_kstat <path>`、`add_sus_kstat_statically <path> +12 字段`、`update_sus_kstat <path>`、`update_sus_kstat_full_clone <path>`、`del <path>`、`clear`（`:792-806`；`add_sus_kstat_statically` 要求 `argc==14` `:794`）。上限 `SUS_KSTAT_MAX 32`（`:66`）。

**简化/缺失**：

1. **`st_susfs_sus_kstat.is_statically` 字段在 supercall 路径里完全没被读取**——`susfs_kstat_supercall()` 只 `switch (cmd)`（`:633-643`），文件名 `susfs_kstat_add_statically_abi()` 的注释写 "is_statically=1"（`:584-585`）但代码不检查该字段。上游按该字段决定"存当前 stat"还是"用调用方给的值"。当前实现以 **cmd id** 作为唯一判据（功能上可用，但 ABI 字段语义被忽略）。
2. 上游 typo 被**故意修正**：`KSTAT_SPOOF_CTIME_TV_SEC` 用 `(1 << 8)` 而非上游的 `(1 < 8)`（`susfs_abi.h:83-99`，`TECHNICAL_NOTES.md:100,212-213`）。
3. 无"路径规则数量/内存"以外的上游级校验；无 umounted-app 门控（上游 kstat 是否门控【推测】：观其功能定位应无 uid 门控，本实现与之行为一致）。

### 2.4 `sus_map.c` — SUS_MAP

- **实现**：按 `(ino, dev)` 匹配，隐藏 `/proc/<pid>/maps` 里的映射行。
- **挂点**：kprobe `show_map_vma` 的 pre_handler（`:78-81`，注册 `:95`；有规则时懒注册 `:151-159`），命中时 `regs->pc = regs->regs[30]` 跳过整行（`:72-73`）。vma 取 `regs->regs[1]`（`:62`）。
- **独立于上游的机制**：上游在 inode 的 `address_space` 上打 `AS_FLAGS_SUS_MAP` 让 `show_map_vma()` 自己跳过（`:5-8` 注释）；LKM 不能加 flag 位，改 kprobe 短路。
- **门控**：**无 uid 门控**。规则来源：module param `map_ino`（`:35-36`，dev 记 0 → 按 `:53` 的 `target_dev && ...` 逻辑退化为**按 ino 通配任意 dev**）；supercall `CMD_SUSFS_ADD_SUS_MAP`（`:115-166`，解析路径取 `(ino, dev)`）。
- **上限** `SUS_MAP_MAX 64`（`:24`）；`nmap == 0` 时不装 hook（`:90-93`）。
- **简化/缺失**：只挂 `show_map_vma` 一个符号，**没有针对 `smaps`/`numa_maps` 等其它 maps 输出路径的验证或 hook**【推测：若这些路径不经过该函数则不会被隐藏——本仓库代码与注释都没有声明覆盖范围】。另外 `map_ino` 路径不设 `target_dev`（`sus_map_add()` `:38-44` 只写 ino），比 supercall 路径的匹配更宽松。

### 2.5 `sus_mount.c` — HIDE_SUS_MNTS_FOR_NON_SU_PROCS

- **实现**：隐藏 `/proc/mounts` / `/proc/mountinfo` 里的 KSU 挂载行。
- **挂点**：kprobe `show_vfsstat`（`:50-53`）与 `show_mountinfo`（`:55-58`），共用一个 pre_handler `sus_mount_show_pre()`（`:35-48`）；`mnt` 取 `regs->regs[1]`，用 `real_mount(mnt)->mnt_id >= param_min_mnt_id` 判定并短路（`:43-46`）。挂载点选型依据：这两个函数虽 static 但在 `proc_ops` 函数指针后面，未被 LTO 内联（`:6-8`）。
- **默认不注册**：`susfs_sus_mount_init()` 只打印日志（`:62-69`）；由 supercall 的 `enabled` 布尔控制注册/注销（`:109-119`）。
- **门控**：module param `min_mnt_id`（`ulong`，默认 `DEFAULT_KSU_MNT_ID = 2000000000ULL`，`:24`,`:32-33`）。
- **重大简化（代码自己承认）**：**没有 patch `mnt_alloc_id()`**，所以 stock KernelSU 设备上 KSU 挂载的 `mnt_id` 仍是普通小数值，`>= 2000000000` 永远不成立，功能形同关闭（`:26-31` 注释）。上游是通过 patch `ida_alloc_min(&mnt_id_ida, DEFAULT_KSU_MNT_ID)` 让 KSU 挂载拿到大 id。
- **另外两点缺失**：
  - **上游的"仅非 su 进程"门控不存在**：本实现对**所有进程**（含 root 与 su 域）隐藏，因为 kprobe 里只做数值比较，没有任何 uid / 进程域判断。
  - 上游的 static key 开关机制不存在（改为 register/unregister kprobe）。

### 2.6 `susfs_uname.c` — SPOOF_UNAME

- **实现**：伪造 `uname(2)` 的 `release` / `version`。
- **挂点**：kretprobe `__arm64_sys_newuname`（`:76-82`，注册 `:92`），在返回前 `copy_to_user` 改写两个字段（`:58-74`）。arm64 wrapper quirk：`regs->regs[0]` 是 `struct pt_regs *`，用户参数在里面（`:50-54`）。
- **独立于上游的机制**：上游 patch `SYSCALL_DEFINE1(newuname)` 函数体（memcpy 与 copy_to_user 之间）；本实现用 kretprobe 在出口改用户缓冲区（`:5-8`）。
- **门控 / 生效条件**：
  - 默认**关闭**（`uname_spoof_enabled` 默认 false，`:33`,`:38`；init 仅在 insmod 参数齐全时注册，`:111-120`）。
  - 开启路径 1：insmod 参数 `release` + `version` + `uname_spoof_enabled=1`（`:36-41`）。
  - 开启路径 2：`CMD_SUSFS_SET_UNAME`（`:129-166`），空字符串 → `-EFAULT`（`:138-141`）；字面量 `"default"` → 取设备当前 `utsname()->release/version`（`:144-151`）。
  - 惰性注册 kretprobe（`:86-99`），未启用时对 uname 热路径零开销。
- **门控缺失**：**没有任何 uid 判断**——一旦启用，root、app、所有进程看到的 `uname` 都被改写。【推测】上游是否有 app-only 门控需查上游源码确认；本实现缺失。

### 2.7 `spoof_cmdline.c` — SPOOF_CMDLINE_OR_BOOTCONFIG

- **实现**：伪造 `/proc/bootconfig` 内容。
- **机制（不是 hook，是数据指针改写）**：直接改写内核静态指针 `saved_boot_config`（`extern char *saved_boot_config;` `:23`；`saved_boot_config = dup;` `:45`），假字符串由 `kstrdup` 堆分配（`:41`）。符号未导出，靠 `ksud insmod` 的 kallsyms 重定位（`:7-9`）。卸载时恢复原指针（`:60-68`）。
- **门控 / 生效条件**：insmod 参数 `bootconfig`（`charp[256]`，`:25-26`；仅当非空才 `spoof_set()` `:51-56`）；或 `CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG`（`:71-93`，ABI 上限 8192 字节）。
- **独立于上游的机制**：上游 patch `fs/proc/bootconfig.c` 的 show 函数；本实现改写被 show 函数读取的数据指针（`:5-10` 自述）。
- **简化/缺失**：
  1. **只覆盖 `/proc/bootconfig`**。全文件没有任何 `boot_command_line` 引用，也没有 `/proc/cmdline` 相关处理——虽然命令名是 `CMDLINE_OR_BOOTCONFIG`。【推测：上游同时改写 `/proc/cmdline` 的数据源，本移植版这一半缺失；需查上游确认】
  2. insmod 参数上限 256 字节（`:25`），远小于 ABI 的 8192。
  3. **潜在缺陷（代码级，非门控）**：`spoof_set()` 在 `spoof_active` 为真时先 `kfree(fake_boot_config)`（`:36-37`），若随后的 `kstrdup` 失败则直接 `return`（`:41-43`），此时 `saved_boot_config` 仍指向已释放内存 → 悬空读。仅在内存分配失败时触发。

### 2.8 `susfs_open_redirect.c` — OPEN_REDIRECT

- **实现**：把对 target 路径的 open 重定向到另一路径。
- **挂点**：kprobe `vfs_open` 的 pre_handler（`:125-128`，注册 `:138`），命中时把第一个参数换成缓存的 `struct path`：`regs->regs[0] = (unsigned long)&e->redirected_path;`（`:121`）。选点依据：`do_sys_openat2/do_filp_open/path_openat` 全被 LTO 内联，`vfs_open` 是用户 open 路径上唯一保留 out-of-line 副本的中间符号（`:8-11`，实测数据见 `TECHNICAL_NOTES.md:105-126`）。
- **独立于上游的机制**：上游 hook `path_openat()` 并在 inode 解析后换 filename 重新 walk；本实现改为 inode 层匹配 + **在 add 时（进程上下文）就 `kern_path` 解析并缓存 redirected 的 `struct path`**（`:16-21`,`:261-266`,`:286`），因为 kprobe pre_handler 在中断上下文不能 sleep。引用计数：缓存基引用由 entry 持有，`del`/`clear` 时 `path_put`（`:305`,`:191`），file 自己通过 `do_dentry_open` 的 `path_get` 拿引用（`:19-21`）。**不需要 kretprobe**。
- **门控 —— `or_uid_matches()` 支持的 uid_scheme 档位**（`:68-77`）：

| uid_scheme | 枚举名（`susfs_abi.h:63-69`） | 本实现 |
|---|---|---|
| 0 | `UID_NON_APP_PROC` | **支持**：`current_uid().val % 100000 < 10000`（`:71-72`） |
| 1 | `UID_ROOT_PROC_EXCEPT_SU_PROC` | `default:` → 返回 false（`:73-76`），且 `or_add()` 直接拒绝 `-EOPNOTSUPP`（`:248-249`） |
| 2 | `UID_NON_SU_PROC` | 同上 |
| 3 | `UID_UMOUNTED_APP_PROC` | 同上 |
| 4 | `UID_UMOUNTED_PROC` | 同上 |

  即**实际可用档位只有 0**；scheme 越界（<0 或 >4）→ `-EINVAL`（`:246-247`），scheme 1..4 → `-EOPNOTSUPP`（`:248-249`）。
- 接口：`/proc/susfs_open_redirect`（0666，`:173`）`add_open_redirect <target> <redirected> <uid_scheme>` / `del <target>` / `clear`（`:333-345`）；supercall `CMD_SUSFS_ADD_OPEN_REDIRECT`（`:355-375`）。上限 `SUS_OR_MAX 64`（`:48`）。
- **简化/缺失**：1..4 档缺失的原因是它们依赖 KernelSU 内部 su-domain / umount 状态，LKM 看不到（`:32-34`,`:74-75` 自述）。上游这些档位的具体判定条件（`is_ksu_domain()`、`susfs_is_current_proc_umounted()` 之类）在本实现里**完全不存在**。

### 2.9 `susfs_enable_log.c` — ENABLE_LOG

- **实现**：全局布尔 + `/proc/susfs_enable_log`（0666，`:67`）：写 `'1'`/`'0'` 开关，读返回 `0`/`1`（`:38-53`）；supercall `CMD_SUSFS_ENABLE_LOG`（`:85-102`）。导出 `susfs_log_enabled()`（`EXPORT_SYMBOL` `:25`，声明于 `susfs.h:29`）。
- **独立于上游的机制**：上游用 static branch（`DEFINE_STATIC_KEY_FALSE`）做零开销门控（文件头 `:5-10` 自述）；LKM 没有 static branch，改为普通全局 flag。
- **门控**：无 uid 门控。
- **关键缺失（实质性问题）**：`susfs_log_enabled()` **在整个模块里没有任何调用者**（grep 仅命中定义 `susfs_enable_log.c:21`、`EXPORT_SYMBOL` `:25`、声明 `susfs.h:29`）。各功能文件输出日志一律用无条件 `pr_info`/`pr_warn`。因此这个开关**目前不控制任何输出**，与上游"日志默认静默"的语义不符（`susfs_enable_log.c:8-10` 的注释写 "Feature hit-path logs should check susfs_log_enabled()"，属未完成的约定）。

### 2.10 `susfs_avc_spoof.c` — ENABLE_AVC_LOG_SPOOFING

- **实现**：把 SELinux AVC 审计日志里作为 target（`tsid`）的 su 域换成 priv_app 域。
- **挂点**：kprobe `slow_avc_audit` 的 pre_handler（`:70-73`，注册 `:81`），命中时 `regs->regs[2] = avc_priv_app_sid`（`:58-68`，tsid 是第 3 个参数）。
- **独立于上游的机制**：上游 hook `avc_audit_post_callback()` 并替换字符串；本实现发现该符号被 LTO 内联（kallsyms 里是残留），改挂 `noinline` 的 `slow_avc_audit` 并直接改 `tsid` 参数，让函数体自己用新 sid 查 context（`:50-54`、`:16-18`；`TECHNICAL_NOTES.md:149-158`）。
- **门控 / 生效条件**：默认 `avc_spoof_enabled = false`（`:45`）；由 `/proc/susfs_avc_spoof` 写 `1`（`:121-126`）或 `CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING` 且 `enabled`（`:194-207`）打开。**无 uid 门控**（对全部进程的 AVC 日志生效）。
- **参数**：`avc_su_ctx` 默认 `"u:r:ksu:s0"`（`:38`，注释说明这是 SukiSU 变体，stock KernelSU 是 `u:r:su:s0`）；`avc_priv_app_ctx` 默认 `"u:r:priv_app:s0:c512,c768"`（`:39`）。两者在 init 时用导出符号 `security_secctx_to_secid()` 解析成 sid（`:151-162`），解析失败则 sid=0。
- **简化/缺失**：无 uid/进程门控；无"仅对某类 audit 记录生效"的细分（上游是否有【推测】：不确定）。另外 `/proc` 读出里带 enter/hits 计数器（`:99-105`），这是调试加料，上游没有。

### 2.11 `susfs_hide_syms.c` — HIDE_KSU_SUSFS_SYMBOLS

- **实现**：从 `/proc/kallsyms` 隐藏 ksu/susfs 相关符号。
- **挂点**：kprobe `s_show` 的 pre_handler（`:90-93`，注册 `:101`），命中时 `regs->regs[0] = 0; regs->pc = regs->regs[30];`（`:83-84`），在内核区分 core/module 之前就整行跳过（`:11-15` 注释）。
- **独立于上游的机制**：上游 patch `kernel/kallsyms.c` 的 `s_show()`；本实现 kprobe 同一个函数（它被 `kallsyms_op.show` 函数指针引用，LTO 保留 out-of-line 副本）。
- **门控**：**无任何开关、无 module 参数、无 supercall handler**——默认且永远生效（`:16-17` 注释：上游是编译期 CONFIG，无运行时开关）。这与 `enabled_features` 列表里列出 `CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS`（`susfs_supercall.c:83`）是自洽的。
- 判定依据：`hide_prefixes[]` 18 条前缀（`:44-50`，含 `ksu_`/`__ksu_`/`susfs_`/`ksud`/`kernelsu`/`is_zygote` 等）；**外加** `!strcmp(iter->module_name, "susfs_guard_lkm")` 整模块名过滤（`:81`）。本地镜像了 `struct kallsym_iter` 布局（`:28-41`）。

### 2.12 支撑层（非功能，但决定 hook 能力）

- `lsm_hook.c`：**不是新挂 hook，而是运行时替换已有 LSM 槽位里的函数指针**。5.15 路径遍历 `security_hook_heads`（`:289-394`），6.12+ 路径遍历 `static_calls_table`（`:147-287`），用 `ksu_patch_text()` 改写槽位（`:73-83`）并在卸载时 `synchronize_rcu()`（`:445`）。跟踪表上限 16（`:31`）。**注意**：`:6-7` 注释写 "Replaces … with an `__nocfi` replacement"，但 `TECHNICAL_NOTES.md:357-358` 明确记载该说法在本内核**不成立**（加 `__nocfi` 会 `__cfi_check_fail` panic）——注释是 KernelSU 原文照搬，与实测结论矛盾。`sus_path.c:138-151` 用 `static_assert` + `LSM_HOOK_FN_TYPE` 在编译期卡签名，正是这一教训的产物。
- `patch_memory.c` / `symbol_resolver.c`：`ksu_patch_text()`（改只读内核文本/fixmap，`patch_memory.h:31-33`）、`ksu_resolve_symbol_for_functable_hook()` / `find_kernel_symbol_exact()`（kallsyms 解析，`symbol_resolver.h:5-7`）。
- `susfs.h`：全部功能的 init/exit 与 supercall handler 声明（`:6-49`）；**注意 `show_*` 三个 handler 不在其中**（它们 static 于 `susfs_supercall.c`）。

---

## 3. 对外接口清单

### 3.1 module 参数（`grep module_param`）

全部属于 `susfs_guard_lkm.ko`（同一模块，因此内核会把它们暴露在 `/sys/module/susfs_guard_lkm/parameters/` 下【推测：内核通用行为，非本代码显式创建】）。

| 注册名 | 类型 | 默认值 | 权限 | 文件:行 | 作用 |
|---|---|---|---|---|---|
| `hide_name` | string（`char[257]`，NAME_MAX+1） | 空（禁用） | 0644 | `sus_path.c:91-92` | legacy/debug：精确 basename 全局隐藏（仅 getdents 层） |
| `hide_from_apps` | int | `1` | 0644 | `sus_path.c:166-167` | SUS_PATH 门控总开关 |
| `hide_list` | 只读（`module_param_cb` + 自定义 ops） | — | 0444 | `sus_path.c:348-351` | 打印已注册条目 + getattr/perm 命中计数 |
| `min_mnt_id` | ulong（变量名 `param_min_mnt_id`） | `2000000000` | 0644 | `sus_mount.c:32-33` | 判定 KSU 挂载的 mnt_id 阈值 |
| `map_ino` | ulong（变量名 `param_map_ino`） | `0`（不添加） | 0644 | `sus_map.c:35-36` | insmod 时直接加一条 SUS_MAP 规则（dev 通配） |
| `release` | string（`char[65]`） | 空 | 0644 | `susfs_uname.c:36` | 假 uname release |
| `version` | string（`char[65]`） | 空 | 0644 | `susfs_uname.c:37` | 假 uname version |
| `uname_spoof_enabled` | bool | `false` | 0644 | `susfs_uname.c:38` | insmod 时启用 uname spoof |
| `bootconfig` | string（`char[256]`） | 空（不启用） | 0644 | `spoof_cmdline.c:25-26` | 假 bootconfig 内容 |
| `avc_su_ctx` | string（`char[128]`） | `"u:r:ksu:s0"` | 0644 | `susfs_avc_spoof.c:38`,`:40` | su 域 SELinux context |
| `avc_priv_app_ctx` | string（`char[128]`） | `"u:r:priv_app:s0:c512,c768"` | 0644 | `susfs_avc_spoof.c:39`,`:41` | 伪装目标 context |

`MODULE_PARM_DESC` 只给了 `release`/`version`/`uname_spoof_enabled` 三条（`susfs_uname.c:39-41`），其余参数无描述。

### 3.2 `/proc` / `/sys` / debugfs 条目

本模块创建的 `/proc` 条目共 4 个（全部 perm `0666`，父目录 `NULL` 即 `/proc` 根）：

| 路径 | 权限 | 文件:行 | 读写语义 |
|---|---|---|---|
| `/proc/susfs_kstat` | 0666 | `susfs_kstat.c:680` | 读：规则列表（`kstat_proc_show` `:718-746`）；写：`add_sus_kstat` / `add_sus_kstat_statically`(argc=14) / `update_sus_kstat` / `update_sus_kstat_full_clone` / `del` / `clear`（`:772-813`） |
| `/proc/susfs_open_redirect` | 0666 | `susfs_open_redirect.c:173` | 读：规则列表（`:195-213`）；写：`add_open_redirect <t> <r> <scheme>` / `del` / `clear`（`:312-352`） |
| `/proc/susfs_enable_log` | 0666 | `susfs_enable_log.c:67` | 读 `0`/`1`；写 `'1'`/`'0'`（`:38-53`） |
| `/proc/susfs_avc_spoof` | 0666 | `susfs_avc_spoof.c:166` | 读 `启用位 + su_sid + priv_app_sid + enter/hits`；写 `'1'`/`'0'`（`:112-135`） |

- **debugfs / sysfs：无**。`grep debugfs_create|kobject|device_create|misc_register|proc_mkdir` 在功能源码里零命中。

### 3.3 哪些是本移植版自己加的

- **全部 11 个 module 参数都是新增的**：上游是编译进内核的补丁，不存在 insmod 参数机制（`README.md:7-11` 描述本仓库把它做成独立 `.ko`）。其中 `min_mnt_id`、`map_ino`、`bootconfig`、`avc_su_ctx`、`avc_priv_app_ctx`、`uname_spoof_enabled`、`hide_from_apps`、`hide_name` 属纯 LKM 调试/适配旋钮。
- **4 个 `/proc` 条目的定位**：代码注释自述是把上游命令行工具语义"逐命令镜像"到 proc（`susfs_kstat.c:5-6`、`susfs_open_redirect.c:27`、`TECHNICAL_NOTES.md:78-91`）。即：**主干 ABI 仍是 supercall**，proc 是 LKM 额外提供的第二入口（也是唯一能在不依赖用户态工具时配置 kstat/open_redirect 的入口）。【推测：上游是否也有同名 `/proc/susfs_*` 节点，本仓库代码未作说明；需查上游确认】
- `hide_list`（只读状态回显）与 `/proc/susfs_avc_spoof` 的 enter/hits 计数器是纯调试加料。
- `susfs_hide_syms.c:81` 的 `module_name == "susfs_guard_lkm"` 整模块过滤是新增判定（上游内建无独立模块名）。

### 3.4 测试/探测模块（不属于 `susfs_guard_lkm`，单独列出）

`Makefile:11-18` 单独编译为独立 `.ko`：

| 模块 | proc 条目 | module 参数 |
|---|---|---|
| `kstat_probe_test` | `/proc/susfs_probe`（`kstat_probe_test.c:109`） | — |
| `open_probe_test` | `/proc/susfs_open_probe`（`open_probe_test.c:106`） | — |
| `inode_perm_probe_test` | `/proc/susfs_perm_probe`（`:228`） | — |
| `enoent_probe_test` | `/proc/susfs_enoent_probe`（`:169`） | `target_path`（`:57`）、`short_error`（`:60`） |
| `selinux_probe_test` | `/proc/susfs_selinux_probe`（`:314`） | `gate_apps_only`（`:85`） |
| `selinux_hide_probe` | `/proc/susfs_hide_probe`（`selinux_hide_probe_main.c:259`） | `gate_apps_only`（`:94`） |
| `syscall_test` | — | — |

---

## 4. ABI 对齐情况（`susfs_abi.h`）

### 4.1 头文件里定义了什么

| 类别 | 内容 | 行号 |
|---|---|---|
| 版本字符串 | `SUSFS_VERSION_STR "v2.3.0"` | `:58` |
| 变体字符串 | `SUSFS_VARIANT_STR "GKI"`（大写） | `:59` |
| magic | `KSU_INSTALL_MAGIC1 0xDEADBEEF`、`SUSFS_MAGIC 0xFAFAFAFA` | `:19`,`:20` |
| 错误码 | `ERR_CMD_NOT_SUPPORTED 126`（**定义但全仓库未使用**） | `:50` |
| 长度宏 | `SUSFS_MAX_LEN_PATHNAME 256`、`SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE 8192`、`SUSFS_ENABLED_FEATURES_SIZE 8192`、`SUSFS_MAX_VERSION_BUFSIZE 16`、`SUSFS_MAX_VARIANT_BUFSIZE 16` | `:52-56` |
| 命令号 | 23 个 `CMD_SUSFS_*`，0x55550–0x60020，**含 8 个 deprecated** | `:26-48` |
| 枚举 | `enum UID_SCHEME` 5 档（`UID_NON_APP_PROC`…`UID_UMOUNTED_PROC`） | `:63-69` |
| 位标志 | `KSTAT_SPOOF_*` 12 位（INO/DEV/NLINK/SIZE/ATIME_(NSEC)/MTIME_(NSEC)/CTIME_(NSEC)/BLOCKS/BLKSIZE） | `:91-102` |
| 结构体 | 12 个 `struct st_susfs_*`：`sus_path`、`sus_map`、`sus_kstat`、`uname`、`log`、`avc_log_spoofing`、`hide_sus_mnts_for_non_su_procs`、`open_redirect`、`spoof_cmdline_or_bootconfig`、`version`、`variant`、`enabled_features` | `:73-170` |

### 4.2 与上游对齐的声明与验证结论

**头文件内的声明**：
- 顶部：`Mirrors upstream susfs_def.h + susfs.h struct layouts exactly, so the prebuilt ksu_susfs tool (and SukiSU's ksud susfs bindings) can drive this LKM unmodified. Field order / types / sizes MUST match the userspace side.`（`:5-7`）
- deprecated 命令为何保留：`:22-25`。
- kstat 位标志**故意偏离上游 typo**：`:83-90` 说明上游 `KSTAT_SPOOF_CTIME_TV_SEC` 写作 `(1 < 8)`（值为 0），用户态（ksu_susfs 与 ksud `KSTAT_AUTO_SPOOF`）用 `(1 << 8)`，因此本头文件保留修正值并注明 "do NOT resync this to the upstream typo"。

**仓库内的验证结论（`TECHNICAL_NOTES.md:198-231`，标题"ABI 对齐上游 builtin 的要点"）**：明确写"已对齐并通过**三种独立方法**验证（真实编译器逐字段 offset/size 断言、LP64 模型、Python packing 引擎）"，并给出结构体尺寸表：

| 结构体 | sizeof | 关键偏移 |
|---|---|---|
| `st_susfs_sus_path` / `st_susfs_sus_map` | 260 | err@256 |
| `st_susfs_sus_kstat` | 376 | err@372 |
| `st_susfs_uname` | 136 | err@132 |
| `st_susfs_log` / `avc_log_spoofing` / `hide_sus_mnts_for_non_su_procs` | 各 8 | err@4 |
| `st_susfs_open_redirect` | 520 | err@516 |
| `st_susfs_spoof_cmdline_or_bootconfig` | 8196 | err@8192 |
| `st_susfs_version` / `st_susfs_variant` | 各 20 | err@16 |
| `st_susfs_enabled_features` | 8196 | err@8192 |

（另注：结构体名要与上游一致，如 `st_susfs_hide_sus_mnts_for_non_su_procs`；uname 用 `__NEW_UTS_LEN+1` 不硬编码 65——`TECHNICAL_NOTES.md:210-211`。）

**验证代码实体**（`abi_layout_check/`）：
- `host_layout_check.c`：编译期 `_Static_assert` 逐结构体断言 sizeof/offset（LLP64 与 LP64 双模型，`:82-145`），并与"预编译 ksu_susfs 工具"的结构体逐字段交叉比对（`:147-209`），另外做 wire round-trip（`bool` vs `u32`、`int` vs `bool` 的双向解释，`:377-416`），最终打印 `RESULT: PASS - all layouts match` / `FAIL`（`:434-436`）。
- `lp64_check.c`：在"宿主是 LLP64（Windows，long=4）"的限制下，用生成的 `lp64_model.h`（`long→long long` 镜像）以**真实编译器**证明 aarch64 LP64 布局，并与两个用户态对端比对：`TOOL` = 预编译 ksu_susfs（`jni/features` C 源码），`RS` = SukiSU ksud 的 `#[repr(C)] types.rs`（`:2-25`）。
- `gen_lp64_model.py`：重新解析生成的镜像文件，断言字段序列未被改动（`host_layout_check.c:15-17` 说明其角色）。
- `test_sc.c`：无 libc 的 arm64 supercall 冒烟测试客户端，内嵌 `struct susfs_kstat` 的 376 字节布局注释（`test_sc.c:64-83`）。

**行为层对齐**（`TECHNICAL_NOTES.md:215-224`，代码里逐处落实）：
1. **输入型命令只回写 `->err`**，不回写整个结构体。实现点：`sus_path.c:531-533`、`sus_map.c:163-165`、`susfs_kstat.c:646-654`、`susfs_uname.c:163-165`、`susfs_enable_log.c:99-101`、`susfs_avc_spoof.c:212-214`、`susfs_open_redirect.c:372-374`、`sus_mount.c:124-126`、`spoof_cmdline.c:89-91`。`show_*` 类才回写整结构体（`susfs_supercall.c:57`、`:72`、`:109`）。理由（`susfs_kstat.c:647-651`）：整结构体回写会越界写调用方栈。
2. **处理成功后 `reboot(2)` 返回 0**（`susfs_supercall.c:196-210` 注释 + `:208-209` 实现）。

### 4.3 已记录的 ABI 消费者差异

`TECHNICAL_NOTES.md:226-231`：sidex15 模块里预编译的 `ksu_susfs` 对应 **SUSFS 1.5.x** 时代的 ABI，其 `st_susfs_sus_kstat` 字段顺序与 v2.3.0 不同（时间是 sec 三连排、nsec 三连排，`blksize` 在 `blocks` 之前），因此它对 kstat / open_redirect 会报 `SUSFS operation not supported`——"这是工具版本问题，不是 LKM 的问题"；与 v2.3.0 布局一致的调用方（SukiSU ksud 或 `test_sc`）实测全部命令 `err=0`。

### 4.4 ABI 相关的未闭合点

1. `ERR_CMD_NOT_SUPPORTED` 定义但不使用（见 1.4）—— 严格说这是**行为**与上游不对齐，不是布局。
2. `is_statically` 字段在 supercall 分发中未被读取（见 2.3）。
3. **`abi_layout_check/` 不在 CI 门禁里**：`.github/workflows/build-ddk.yml:43-73` 只做 `make modules` + 编译 `test_sc` + `readelf`/`modinfo` 检查，没有运行 `host_layout_check` / `lp64_check` / `gen_lp64_model.py`。布局断言目前依赖本地手工执行。
4. `test_sc.c` 只覆盖 7 个命令（`show_version`、`add_sus_path`、`add_sus_kstat`、`add_open_redirect`、`set_uname`、`enable_log`，`test_sc.c:96-131`），未覆盖 `ADD_SUS_MAP`、`ADD_SUS_KSTAT_STATICALLY`、`UPDATE_SUS_KSTAT`、`SET_CMDLINE_OR_BOOTCONFIG`、`ENABLE_AVC_LOG_SPOOFING`、`HIDE_SUS_MNTS_FOR_NON_SU_PROCS`、`SHOW_VARIANT`、`SHOW_ENABLED_FEATURES`、`ADD_SUS_PATH_LOOP`。

---

## 5. 结论摘要（LKM 版 vs 上游 builtin 的主要能力缺口）

| # | 缺口 | 证据 |
|---|---|---|
| 1 | **没有 `TIF_PROC_UMOUNTED` / su-domain / umount 状态**，多处上游门控被 `uid>=10000` 或"无门控"替代 | `sus_path.c:161-165`；`susfs_open_redirect.c:32-34`,`:74-75`；`sus_mount.c:26-31` |
| 2 | **SUS_MOUNT 实质失效**：不 patch `mnt_alloc_id()`，仅按 `mnt_id >= 2000000000` 数值阈值匹配，stock KSU 设备上永不命中 | `sus_mount.c:26-33`,`:43` |
| 3 | **ENABLE_LOG 开关无消费者**：`susfs_log_enabled()` 导出但无人调用 | `susfs_enable_log.c:21-25`（grep 无调用点） |
| 4 | **OPEN_REDIRECT 仅 1/5 档可用**：uid_scheme 0 可用，1–4 返回 `-EOPNOTSUPP` | `susfs_open_redirect.c:68-77`,`:246-249` |
| 5 | **SPOOF_CMDLINE_OR_BOOTCONFIG 只覆盖 bootconfig**，无 `/proc/cmdline` 侧处理 | `spoof_cmdline.c:23`,`:45`（无 `boot_command_line` 引用） |
| 6 | **不支持的命令不回 `ERR_CMD_NOT_SUPPORTED`**，err 保持调用方原值，reboot 仍返回 0 | `susfs_supercall.c:160-162`；`susfs_abi.h:50` 未被引用 |
| 7 | **`unlink`/`rename` 不被 SUS_PATH 拦截**（作用父目录 inode） | `sus_path.c:131-132` |
| 8 | **supercall 只校验 uid==0**，无 KSU 域/manager 身份校验 | `susfs_supercall.c:180`（全模块唯一凭证判断） |
| 9 | **文档过期两处**：`TECHNICAL_NOTES.md:258-262` 称"无条件隐藏、root 也看不到"（已被 `hide_from_apps` 门控取代）；`:193` 称"8 个 feature"（代码列表为 9，且缺 AVC） | `sus_path.c:166-167`；`susfs_supercall.c:77-87` |
| 10 | **`is_statically` ABI 字段未参与分发**（用 cmd id 判分支） | `susfs_kstat.c:633-643`，`:584` 仅注释 |
| 11 | 代码级潜在缺陷：`spoof_set()` 在 `kstrdup` 失败时留下悬空 `saved_boot_config` | `spoof_cmdline.c:36-46` |
| 12 | `lsm_hook.c:6-7` 注释与实测矛盾（`__nocfi` 在本内核会 panic） | `TECHNICAL_NOTES.md:357-358`；`sus_path.c:138-151` 的 static_assert 是补救 |
