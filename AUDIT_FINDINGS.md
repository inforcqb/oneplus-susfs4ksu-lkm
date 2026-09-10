# SUSFS-LKM 审计发现（2026-09-10，逐函数级扫描）

> **修复状态（最新 commit `15b3ff4`，真机验证通过）**
>
> 已修：P0 全部 5 条（0600 控制节点 / 0400 `hide_list` + 去 `%px` /
> 动态 `enabled_features` / supercall init 失败即拒绝加载 / 未识别命令）；
> P1 全部内存安全问题（`sus_map[-1]`、bootconfig 悬垂、open_redirect UAF、
> **ABI 路径字段越界读**、**kstat 表读写竞争**）；
> P2 三条（`show_vfsmnt` 补挂、compat getdents64、**`expose_proc` 误伤钩子**）；
> P4 两处文档错误（`mnt_alloc_id`、ctime typo）。
>
> 真机验证：控制节点 `-rw-------`；`hide_list` `-r--------` 且无内核指针；
> app(uid 10378) 读两者均 Permission denied；app 视角 stat/cat 均 ENOENT 而
> root 正常；临时把 `min_mnt_id` 设成 max(37270) 后 **mountinfo / mounts /
> mountstats 三者同时 238→237**（证明 `show_vfsmnt` 生效），恢复后回到 238。
>
> `15b3ff4` 真机验证（默认参数 `expose_proc=0`，全新加载）：
> `kstat armed: 0 rules (tp=1 krp=1 proc=0)` —— 钩子确实 armed；
> 仅用 supercall 静态伪装后 `stat` 得 `ino=11111 dev=22222 size=4242`（修复前
> 该路径下钩子根本没注册，规则只入库不生效）；300 轮 add/update 与 383 次
> `stat` 并发churn，`BUG:/WARNING:/Call trace` 计数 0，最终表项一致；
> sus_path getdents 过滤对 app(uid 10123) 仍生效（`ls` 只剩可见项、`cat` ENOENT）、
> root 不受影响；`rmmod rc=0`。
>
> `543b369` 追加（kstat 门控 + maps 覆盖），真机验证：
> root 视角 `stat` 得真值（`ino=931980`）而 app(10123) 得伪装值
> （`ino=11111 dev=22222 size=4242`）—— 门控按上游 `umounted_app` 的
> `uid>=10000` 代理生效；对 `libc.so` 设 ino 伪装后，app 的
> `/proc/self/maps` 里 `libc.so` 行数 4 → **0**（总行数仍 87，证明是丢行不是读不到），
> root 仍为 4，`rmmod` 后 app 恢复 4 行。
>
> **未修**（按优先级见 C 节）：P2 其余（sus_mount 域门控与阈值、sus_map 门控、
> open_redirect 反向伪装与 scheme 1-4、`_LOOP` 语义）、P3 细节。
>
> **已确认无法在 LKM 内复刻**：`TIF_PROC_UMOUNTED`。上游由 KernelSU 的
> setuid hook 设置（`kernel_umount.c:75-109`：`ksu_module_mounted` &&
> `ksu_kernel_umount_enabled` && `is_appuid` && `ksu_uid_should_umount` &&
> `is_zygote(current_cred())`），本机内核无 SUSFS 集成、且 `dmesg` 中没有任何
> `handle umount for uid` 记录（即 `ksu_uid_should_umount()` 对所有 app 都是
> false），照搬会让伪装对所有进程失效。SELinux 域（`is_zygote` 用的 sid）
> 只是该链条的最后一个必要条件，代替不了它。故门控继续用 `uid>=10000` 代理。

对比基准：`susfs4ksu/kernel_patches/`（builtin，v2.3.0）
被审计对象：`susfs4ksu-lkm/kernel/`

图例：🔴 已自行核实为真实缺陷 · 🟡 子代理报告，待核实 · ✅ 已核实一致

---

## A. 已核实为真实缺陷

### A1 🔴 open_redirect 规则表无 RCU 保护 → UAF（严重，内存安全）

**证据**（`susfs_open_redirect.c`）：

```c
static int or_vfs_open_pre(struct kprobe *kp, struct pt_regs *regs)   // :102
{
    ...
    e = or_find_by_inode(inode->i_ino, inode->i_sb->s_dev);   // :114 — 无锁遍历数组
    ...
    regs->regs[0] = (unsigned long)&e->redirected_path;       // :121 — 把 entry 内的 path 交给 vfs_open
    return 0;
}
```

- pre_handler 在**中断上下文**执行，无锁遍历 `or_entries[]`（`:89-98`）
- `or_add` 替换规则时**先 `path_put` 再赋新值**（`:280` → `:286`）
- `or_del`/`clear` 同样先 `path_put`（`:305-307`）
- → 并发窗口内 `vfs_open` 会对**已释放的 dentry/mount** 执行 `path_get` → **UAF**

**上游做法**：`DEFINE_SRCU`（`susfs.c:770`）+ `hash_del_rcu` + `synchronize_srcu`（`:901`）之后才 `kfree`（`:903-904`）；且**不长期持有 path**（add 后即 `path_put`，靠重走 lookup 实现）。

**修复方向**：entry 一旦创建，`redirected_path` **永不释放**（规则表上限 64，内存代价可接受）；删除/替换只标记失效位，pre_handler 跳过失效项；`nor`/字段读用 `READ_ONCE`。彻底方案是引入 SRCU，但注意 pre_handler 返回后 `vfs_open` 仍在使用该 path，RCU 宽限期**不覆盖**那一段，所以"延迟释放 + 永不释放"才是安全的。

### A2 🔴 sus_map 越界写 `map_entries[-1]`（低，但真实）

**证据**（`sus_map.c`）：

```c
static void sus_map_add(unsigned long ino)      // :38
{
    if (nmap >= SUS_MAP_MAX || !ino)
        return;                                  // :40-41 — ino==0 时提前返回，nmap 不变
    map_entries[nmap].target_ino = ino;
    nmap++;
}

// supercall 路径
sus_map_add(inode->i_ino);                       // :144
map_entries[nmap - 1].target_dev = inode->i_sb->s_dev;   // :145 — nmap==0 时索引 -1
```

- `nmap == 0` 且 `i_ino == 0` → **越界写 `map_entries[-1]`**
- `nmap > 0` 且 `i_ino == 0` → **篡改上一条规则的 dev**

`i_ino == 0` 罕见但可达（部分伪文件系统）。`sus_map.c:132-137` 只检查 `!inode`，没检查 `i_ino`。

### A3 🔴 open_redirect 路径长度上限 128 < ABI 256（中）

`OR_PATH_MAX = 128`（`susfs_open_redirect.c:49`）而 ABI 是 `SUSFS_MAX_LEN_PATHNAME = 256`。
`strscpy` 静默截断（`:276`、`:283`）→ 超过 127 字符的路径会导致 **del / 替换静默失效**。

### A4 🔴 open_redirect 的 uid_scheme 只有 0 档（⚠️ 门槛）+ 反向伪装 0 覆盖（中）

- scheme 1–4 在 `or_add` 即被拒为 `-EOPNOTSUPP`（`:248-249`）
- 上游的**反向伪装链路**（readlink / proc_readlink / fdinfo / maps / statfs）**完全没实现**
  → LKM 下 `readlink("/proc/self/fd/N")`、maps、fdinfo 暴露 **redirected 的真实路径与 ino**，
  与上游"处处表现为 target"完全相反

### A5 🟡 入口对未识别命令的 reboot 返回值不同（低）

- 上游：`ksu_handle_sys_reboot` 的 `default: return -EINVAL` → `goto orig_flow` → **reboot(2) 返回 -EINVAL**
- LKM：`reboot_pre`（`susfs_supercall.c:176-210`）只要 magic + uid==0 匹配就**无条件短路返回 0**

用户态可见行为一致（`err` 都没被回写，保持 126 → 打印 "not supported"），
但**检查 syscall 返回值的调用方**会看到差异。

### A6 🟡 enabled_features 列表可能漏列 AVC（低）

`susfs_supercall.c:77-87` 列 9 项，子代理称缺 AVC（`CONFIG_KSU_SUSFS_ENABLE_AVC_LOG_SPOOFING`）。
上游按真实 `#ifdef` 输出（`susfs.c:1220-1226`）。

### A7 🔴 两个 init 的返回值被忽略 → 静默失效（高，反检测致命）

`susfs_main.c`：

```c
susfs_avc_spoof_init();      // :33
susfs_supercall_init();      // :34
susfs_hide_syms_init();      // :35
```

三者返回值全部被丢弃。后果：

- **`susfs_supercall_init()` 失败** → `register_kprobe(__arm64_sys_reboot)` 没装上
  → **所有 CMD 全部不可达**，但模块仍"加载成功"，用户态只看到超时/无响应。
- **`susfs_hide_syms_init()` 失败** → `s_show` kprobe 没装上 → **`/proc/kallsyms` 里
  `ksu_`/`susfs_` 符号全部暴露**，而 `SHOW_ENABLED_FEATURES` **照样上报
  `CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS`** → **对外宣称与事实相反**，
  这正是检测方最容易抓的矛盾点。
- `susfs_avc_spoof_init()` 的 sid 解析失败（`susfs_avc_spoof.c:151-161` 清 0）时，
  开关仍返回成功但 spoof 永不命中。

**修复方向**：init 失败要么让模块加载失败，要么把失败状态反映到 `enabled_features` /
`/proc` 输出里，绝不能静默。

### A8 🟠 AVC spoof 域名解析失败时静默半失效

`avc_su_ctx` / `avc_priv_app_ctx` 用 `security_secctx_to_secid()` 解析
（`susfs_avc_spoof.c:151-162`），失败则两者为 0；此时 `/proc` 开关照常返回成功，
但 pre_handler 里改写后的 tsid 仍是 0 → 不产生任何伪装。

**注**：LKM 用 module 参数补上游由 KernelSU 提供的 `susfs_ksu_sid`/`susfs_priv_app_sid`
（`50 patch:2252-2274`），默认值 `u:r:ksu:s0` 是 **SukiSU 变体**的域名，
stock KernelSU 是 `u:r:su:s0` —— 默认值不匹配时会静默失效。

### A9 🟡 `/proc` 入口不对称

有写入口的：`susfs_kstat`、`susfs_open_redirect`、`susfs_enable_log`、`susfs_avc_spoof`。
**没有**写入口的：**`sus_path`、`sus_map`、`sus_mount`** —— 只能靠 supercall。
一旦 supercall 通道失效（例如用户态工具 ABI 版本不匹配），这三个功能**完全无法配置**。
其中 kstat/open_redirect 的 `/proc` 入口是"不依赖用户态工具的唯一途径"，属**功能必需**而非调试。

---

## B. 已核实与上游一致（推翻子代理结论）

| 子代理结论 | 核实结果 |
|---|---|
| "`ERR_CMD_NOT_SUPPORTED`(126) 未使用 = 行为不对齐" | ❌ **错**。126 是**用户态**初值（`ksu_susfs/jni/includes/susfs_defs.h:16`），用户态靠 `err` 保持 126 打印 "not supported"。上游 `ksu_handle_sys_reboot` 的 `default: return -EINVAL` **也不回写 err**（已读 patch:2855-2934 确认）。**我们一致** |
| "`is_statically` 未参与分发 = 缺陷" | ❌ **错**。上游 `ADD_SUS_KSTAT_STATICALLY` 与 `ADD_SUS_KSTAT` 走**同一个** handler，该字段只影响日志（`susfs.c:427-431`） |
| "bootconfig 缺 /proc/cmdline 侧" | ❌ **错**。上游 5.15 patch **也只改 `/proc/bootconfig`** |
| "uname 门控缺失" | ❌ **错**。上游 uname **也无 uid 门控** |
| "LKM open_redirect 不覆盖 O_PATH / 目录打开" | ❌ **错**（子代理自己纠正）。`do_o_path` 与 `do_open` 都调 `vfs_open`。真正漏的是 **O_TMPFILE** |
| "enabled_features 漏列 AVC = 缺陷" | ❌ **错**。上游**也不在列表里**（`susfs.c:1185-1229`），9 项内容与顺序**两侧完全一致** |
| "`ERR_CMD_NOT_SUPPORTED` 的定义是死代码、会误导" | ⚠️ **部分对**。上游 kernel 确实没有这个宏（它是用户态常量），我们在 `susfs_abi.h:50` 定义它属多余；但**不影响行为**，只是注释应说明它是用户态约定 |
| 我们的技术笔记称"上游是 typo `(1 < 8)`，用户态用正确的 bit 8" | ❌ **我们的笔记错了**。见下一节 |

---

## B2. 🔴 需要修正的既有文档错误：`KSTAT_SPOOF_CTIME_TV_SEC`

**实测三方分布**：

| 位置 | 值 |
|---|---|
| 上游 kernel `susfs.h:71` | `(1 < 8)` → **0**（typo） |
| 上游**用户态** `ksu_susfs/jni/features/sus_kstat.c:25` | `(1 < 8)` → **0**（**同样有 typo**） |
| 我们的 `susfs_abi.h:99` | `(1 << 8)` → **256**（修正值） |

**结论**：

- 我们 `TECHNICAL_NOTES.md` 里写的"上游是 typo……用户态 ksu_susfs / ksud 用的都是正确的
  bit 8，不要同步回去" —— **前半句错**：上游用户态**也是** typo。`sus_kstat.c:230` 的
  `info.flags |= KSTAT_SPOOF_CTIME_TV_SEC` 等于什么都没置。
- 因此**上游的 ctime spoof 两侧都不生效**；我们的 `1<<8` 只在**自己 `/proc/susfs_kstat`**
  路径上产生真实 ctime 伪装 → **行为比上游"更好"，但已经分叉**。
- 风险：如果将来上游修 typo，用户态会开始置 bit 8，届时我们的行为才与上游合流；
  在此之前，通过 supercall 走 `KSTAT_AUTO_SPOOF` 的调用方**不会**触发 ctime 伪装（两侧一致）。
- **必须修**：`susfs_abi.h:86-90` 的注释（误称用户态已用 `1<<8`）与
  `TECHNICAL_NOTES.md` 里的对应段落。

---

## B3. 其它已核实差异（非缺陷，但需知晓）

| 项 | 上游 | LKM |
|---|---|---|
| `is_statically` 字段类型 | kernel `int`（`susfs.h:77`）/ 用户态 `bool` | `int`（`abi.h:105`）——布局等价（8 字节对齐），且读入后**从不使用** |
| `ADD_SUS_KSTAT_STATICALLY` 的分派依据 | `is_statically` 字段 | `cmd` ID（`susfs_kstat.c:633-643`）——效果等价 |
| variant 字符串 | 随内核版本（`<5.0` → NON-GKI） | 硬编码 `"GKI"` |
| `show_*` 溢出行为 | 返回 `-EINVAL`（`susfs.c:1160-1163`） | 静默 break（`susfs_supercall.c:102-103`） |
| 上游 OOM 路径 | 有 NULL deref bug（`susfs.c:1173-1176` 未判空即写 `info->err`） | 已修（`susfs_supercall.c:96-97`） |
| hide_syms 覆盖 | 只拦**核心符号**分支，17 条前缀，编译期门控 | 短路整个 `s_show`（含模块符号），19 条前缀 + 模块名过滤 |
| `/proc/modules` | 不处理 | 不处理（**两侧一致**，都不是完整隐蔽） |
| `susfs_hide_syms` 的模块名过滤 | 无 | 硬编码 `"susfs_guard_lkm"` → 改名加载即失效 |
| `bootconfig` module 参数长度 | ABI 8192 | **256**（insmod 路径上限） |

---

## B4. sus_kstat 专项发现（子代理 53454933）

### 🔴 最直接的检测面：`/proc/pid/maps` 的 dev:ino 完全没伪装

上游有 **3 个** kstat 注入点，第 3 个是 `fs/proc/task_mmu.c: show_map_vma()`
（`patch:1265-1298`，调 `susfs_sus_kstat_spoof_show_map_vma` 改写 `dev`/`ino` 局部变量）。

LKM **完全没有**（`susfs_kstat.c` 全文无 task_mmu / show_map_vma）；
`sus_map.c` 的那个 `show_map_vma` kprobe 是 **SUS_MAP 自己的**整行跳过逻辑。

**后果**：同一个文件 `stat` 显示伪装 ino、`maps` 显示真实 ino →
**两边一对就暴露**。上游的 `sus_kstat` + `show_map_vma` 是配套的，
这正是我在 `TECHNICAL_NOTES.md` 里写过"伪造 ino 骗不过 /proc/self/maps"的那件事 ——
**上游解决了，我们没解决**。

**修复路径**：把 `sus_map.c` 的 `show_map_vma` kprobe 从"整行跳过"扩展成
"改写 `show_vma_header_prefix` 的 dev/ino 参数"（等价上游改局部变量的做法）。

### 🔴 kstat 覆盖缺口：`fstat` / `statx` / compat 变体

LKM 的 sys_exit tracepoint 白名单只有 `newfstatat`(79) 与 compat `fstatat64`(327)，
**`fstat`(fd 的 stat)、`statx`、compat `fstat64`/`fstat`/`statx` 全靠一个 `vfs_getattr`
kretprobe 兜底**，而该 kretprobe 注册失败时**只 `pr_warn`**（`susfs_kstat.c:691-692`），
`/proc` 也不显示 hook 状态 → 静默降级。

上游在 `generic_fillattr` + `vfs_getattr_nosec` 两处注入，
**一次覆盖 stat/lstat/fstatat/fstat/statx 及全部 compat 变体**。

### 🟠 kstat 无任何门控

上游 = `test_bit(AS_FLAGS_SUS_KSTAT) && susfs_is_current_proc_umounted_app()`。
LKM 的三个改写函数**没有门控**、没有 `hide_from_apps` 之类的开关
（`sus_path` 至少有 uid 代理，kstat 连代理都没有）→ root/init/zygote 也看到伪装值，
无法复现上游"app 看伪装、root 看真实"的双视图。

### 🟠 读路径无锁 → 数据竞争

tracepoint / kretprobe 侧**无锁**遍历 `kstat_entries`/`nkstat`（`susfs_kstat.c:127-136`），
而 `/proc` 写路径会整体搬移结构体（`:509`）→ 读到半更新条目。
上游是 `mutex` + hashtable + `synchronize_rcu`（`susfs.c:271-272,383-386,469-473`）。

### 🟡 bit8 分叉的**精确**结论（修正我先前的理解）

| 实现 | `KSTAT_SPOOF_CTIME_TV_SEC` | AUTO 掩码 |
|---|---|---|
| 上游 kernel `susfs.h:71` | `(1 < 8)` = **1** → **是 bit0 的别名** | — |
| 上游 C 工具 `ksu_susfs` | `(1 < 8)` = **1**（同样 typo） | `0xEF3` |
| SukiSU `ksud`（Rust） | `1 << 8` = 256 | `0xFF3` |
| **我们** | `1 << 8` = 256 | 同 ksud |

- C 工具想置 ctime 位 → 实际置的是 **bit0(INO)** → 上游与我们**行为一致**（都伪装 ino）✓
- **ksud 发 bit8** → **上游 kernel 忽略**（它的宏是 1，不认 bit8），**我们处理** →
  **我们比上游多伪装了 ctime.tv_sec** ← 真实分叉
- `susfs_abi.h:86-90` 的注释**必须改**（它误称"用户态已用 `1<<8`"；实际是
  C 工具有 typo、ksud 用 `1<<8`）

### 🟡 其它

- **ADD 失败残留槽位**：`nkstat++` 在 fill 之前（`susfs_kstat.c:473-478`），
  路径不存在时留下空槽
- **`KSTAT_PATH_MAX=128`** vs ABI 256（`susfs_abi.h:52`）→ 长路径 del/去重失配、重复累积
- **FUSE 特判整体缺失**（上游打 `fi->inode.i_mapping` 并比对 `is_fuse`）
- **dev 编码**不走上游 `old/huge_decode_dev` 链（minor≥256 时可能不同）
- `update_sus_kstat_full_clone` 在我们的 `/proc` 路径真加 `NLINK|SIZE`，上游 UPDATE
  会丢弃调用方 flags → 分叉（但上游无对应命令，属我们自加接口的语义）
- 历史上 `susfs_kstat_exit → unregister_kretprobes` 出过 panic 前科
  （现由 `kstat_krp_registered`/`kstat_tp_registered` 守卫，git `8ced16a`）
- `nkstat == 0` 时仍在每个 syscall 退出做两次 `copy_from_user`（`:149-166`）
  → 建议首行加 `if (!nkstat) return;`

---

## B6. sus_path 专项发现（子代理 07fb8d15）

### 🔴 `_LOOP` 语义完全丢失（最高严重度）

**上游** `susfs_add_sus_path_loop`（`susfs.c:99-132`）：**只做空串校验，不解析路径、不校验存在性**，
`strscpy` 后挂进 `LH_SUS_PATH_LOOP`。真正生效靠 `susfs_run_sus_path_loop()`（`:134-172`）——
它由 `susfs_extra_works`（`:1450-1457`）在 **zygote 系进程 setresuid 后被标记
`TIF_PROC_UMOUNTED` 的那一刻**执行（`KSU patch:1663-1670` / `:1714-1720`），
用 `kern_path(path, 0, ...)`（**flags=0，不跟随符号链接**）+ `override_creds(ksu_cred)` 重新打标。

语义 = **"先登记（可以还不存在），等 app spawn / umount 之后再解析并打标"**，
专治"注册时尚无 inode / inode 回收后 flag 丢失"（FUSE、媒体库场景）。

**LKM**：两个 CMD 走**同一函数**（`susfs_supercall.c:130-133`），
`kern_path` 失败即 `-ENOENT`（`sus_path.c:449-454`），全文件**无 work/timer/重试**。

→ 对**已存在**的路径结果等价；对**预注册的不存在路径**：
**上游之后会生效，我们永远 `-ENOENT` 且永不生效。**

### 🔴 反检测自杀：`hide_list` 与 dmesg 暴露

- `hide_list` 是 **0444（任意进程可读）**，内容包含**隐藏路径清单** +
  `inode=%px`（**真实内核指针**）（`sus_path.c:326-351`）。
  这个 sysfs 节点在 `/sys/module/susfs_guard_lkm/parameters/` 下**人人可读** ——
  检测方只要 `cat` 一下就知道你隐藏了什么、连内核地址都拿到了。
- `pr_info("sus_path: hide '%s' ...")` **无条件**把路径写进 dmesg
  （`sus_path.c:451/527-528`），且不接 `susfs_log_enabled()`。
- 模块名在 `/proc/modules`、`/sys/module/` 可查（`susfs_guard_lkm`），
  `hide_syms` 只挡 `s_show`（kallsyms），**不挡 `/proc/modules`**。

### 🔴 并发不安全：全局单缓冲 `dirent_tmp` 无锁

`dirent_tmp` 是**全局唯一**缓冲（`sus_path.c:94`），getdents64 sys_exit 时先读入再压缩写回
（`:249-295`），而 `sus_path_lock` **只保护链表、不保护这个缓冲** →
**并发的两个 getdents64 会互相踩缓冲**，可能把别的目录条目写进当前进程的缓冲。

### 🟠 compat(32 位) 完全不做目录项过滤

`sus_path.c:303-304` 直接 `if (is_compat_task()) return;` 早退。
但 v5.15 的 32 位 `getdents64` **缓冲布局与 64 位完全相同**
（`fs/readdir.c` 里没有 `compat_filldir64`，已核对内核源码）→ **这个早退是过度保守**，
32 位进程（含部分 app）能直接列出被隐藏的条目。

### 🟠 上游 16 处 namei 注入点 vs 我们的 2 个 LSM 槽

上游 `patch` 的 `fs/namei.c` 有 22 个 hunk，其中 **sus_path 相关 16 个**：
`lookup_dcache` / `lookup_one_qstr_excl` / `lookup_fast`×3 / `__lookup_slow`×3 /
`walk_component` / `link_path_walk` / `lookup_last` / `lookup_open`×3 / `open_last_lookups`。
`fs/readdir.c` 有 **21 个 hunk**，打满 5 个 fill 回调 + 3 个 syscall 的 `buf.sb`。

（我先前在 `TECHNICAL_NOTES.md` 里写"namei.c 三处"是不完整的 —— 那三处是**关键机制**，
不是全部注入点。）

**LKM 未覆盖的路径**：

| 路径 | 上游 | LKM |
|---|---|---|
| 32 位 getdents64 | ✅ compat 回调 | ❌ 早退 |
| legacy `getdents` / `old_readdir` | ✅ | ❌ |
| 内核内部查找（`lookup_one_qstr_excl`、overlayfs、`lookup_one_len`、mount 源解析） | ✅ | ❌ 不经两个 LSM hook |
| `readlink` / `readlinkat` | ✅ lookup 层 | ⚠️ `vfs_readlink` 明确 "Does not call security hook"（**待实测**） |
| `chmod` / `chown` / `utimes` | ✅ lookup 层 | ⚠️ 子代理据 v5.15 `fs/open.c` 推断不调 `inode_permission` → 不拦。**但我实测 `chmod 600 hid3` 返回 ENOENT**（toybox 可能先 stat），**需用纯 syscall 复测** |

### 🟠 目录项匹配维度不足

- 目录项层只按 `(d_ino, name)` 匹配，**不比 dev/sb**（`sus_path.c:103/277`）
  → 跨文件系统同名同 ino 会误伤
- 按 **inode 指针去重**（`:496-505`）→ 同一个 inode 的**硬链接/别名条目被静默忽略**
  （上游 `ilookup(sb, ino)` 是对 inode 判定，**所有别名都隐藏**）
- `ino == 0` 时打印"falling back to name matching"但**代码并未实现该回退**（`:480-484`）

### 🟠 LSM 槽位注册失败静默降级

`ksu_register_lsm_hook()` 失败（SELinux 未注册槽、符号解析失败、track 表 16 条满）时
`sus_path_init()` 只 `pr_warn` 然后 `return 0`（`:374-388`），
用户态 `add_sus_path` **仍然得到 `err=0`** → **路径层静默失效**，
表现为"加进去了、列表也没了，但 `cat` 还能读"。

### 🟡 其它

- **FUSE 特判缺失**：上游命中 `FUSE_SUPER_MAGIC` 时给 `fi->inode.i_mapping` **和**
  `inode->i_mapping` 两个都打标（`susfs.c:71-84`）；纯 FUSE 的 `d_ino` 是否等于
  `i_ino` 需实测
- **>64KB 缓冲丢条目**：`reclen > DIRENT_BUF_SIZE - out` 时 `break`
  → 剩余条目**静默丢弃**（`:266-267`）
- **回写失败仍改返回值**：`copy_to_user` 失败 `return count`，但缓冲已被部分改写
  → 用户态可能解析到半新半旧的 dirent 链（`:291-294`）
- **每条目永久 `ihold`** → 钉住 inode/sb；上限 8192
- 空路径校验：LKM 的 `add` **有** `-EINVAL`（`:444-447`），上游 `add` 反而**没有**
  （只有 `_LOOP` 有）

---

## B8. avc / bootconfig / enable_log / uname 专项（子代理 4574de79）

### 🔴 HIGH `enable_log` 是只有接口的空壳

- **上游**：`DEFINE_STATIC_KEY_TRUE(susfs_is_log_enabled)` → **默认开**，
  `SUSFS_LOGI/LOGE` 宏被它门控，覆盖 `fs/susfs.c` 内 **93 个日志点**。
- **LKM**：`/proc` + supercall + `EXPORT_SYMBOL` 都有，但**全仓库 grep 实际调用点为 0**
  （只命中定义/导出/声明/init-exit/分发）→ **不控制任何输出**。
- 反向影响：我们的日志**无条件**打印，**无法像上游那样用 `ENABLE_LOG=0` 静音**。
  对反检测来说这是体验上的缺陷（用户以为自己关了日志，其实没关）。
- 文件头 `susfs_enable_log.c:9-10` 自己写着 "should check susfs_log_enabled()"，
  是**未完成的约定**。

### 🔴 HIGH bootconfig：UAF 竞态 + 悬空指针 + 二次释放

`spoof_cmdline.c` 直接改写内核静态 `saved_boot_config` 指针（机制本身正确 —— 5.15 里该变量
唯一消费者就是 `boot_config_proc_show()`）：

```c
static int spoof_set(const char *s)
{
    if (spoof_active)
        kfree(fake_boot_config);          // :36-37 —— 先释放旧串
    fake_boot_config = kstrdup(s, GFP_KERNEL);   // :41
    if (!fake_boot_config)
        return -ENOMEM;                   // :41-43 —— 直接返回：saved_boot_config 仍指向已释放内存！
    saved_boot_config = fake_boot_config; // :45 —— 发布新指针
    ...
}
```

1. **UAF 竞态**：`kfree` 旧串与发布新指针之间，读者可能正在 `seq_puts` 旧串
2. **悬空指针**：`kstrdup` 失败时 `saved_boot_config` 仍指向**已释放**内存
3. **二次释放**：此时 `spoof_active` 仍为 true → 下次 `spoof_set` 会再 `kfree` 同一指针
4. **失败仍上报 `err=0`**（`:84-85`）→ 调用方不知道失败了

上游规避方式：**只分配一次**（`kzalloc(8192)`），读侧持 **seqlock**，**永不 free**。

### 🔴 AVC：sid 靠猜 + 解析失败无兜底（静默失效）

**先纠正一个我先前写错的地方**：`tsid == ksu_sid` 这条判定**我们是有的**
（`susfs_avc_spoof.c:63`），子代理 B 说"缺了它"不成立。

**真正的问题在 sid 的来源**：

| | 上游 | LKM |
|---|---|---|
| 注入点 | `avc_audit_post_callback()`（`avc.c:731-736`） | `slow_avc_audit` kprobe（因前者 static + LTO 内联） |
| ksu sid 来源 | **KSU 自报**：`susfs_set_sid(KERNEL_SU_CONTEXT, &susfs_ksu_sid)`（`KSU_patch:2496`） | **硬编码 module 参数默认值**（`avc_su_ctx = "u:r:ksu:s0"`） |
| 伪装目标 | **硬编码字面量** `"u:r:priv_app:s0:c512,c768"`（转换失败才退化） | 由 `avc_priv_app_ctx` 解析出的 sid |
| 改动范围 | 只改**打印的字符串**，`sad->tsid` **不变** | **改 `regs->regs[2]`（tsid 参数）** → 连带影响 tracepoint 与 `trawcon` |
| 门控成本 | static key（零成本） | 每次 denial 一次 int3 + kprobe |

**后果**：

- 默认 `u:r:ksu:s0` 只对 **SukiSU** 成立；**stock KernelSU 是 `u:r:su:s0`** →
  换变体后判定**永不命中** → supercall 返回 0、`/proc` 显示 `enabled=1`，
  **但一条都没改** → 静默失效。
- **sid 解析失败无兜底**：失败只把 sid 置 0 且不阻止启用（`:151-162,194-203`）→
  `priv_app_sid = 0` 时把 tsid 改成 0，输出垃圾 `tsid=0`（比不伪装**更显眼**）；
  上游的硬编码字面量兜底**永不出错**。
- 我们改的是**参数**而非打印串 → 超出"日志伪装"语义，属设计取舍，需明确知晓。

### 🟠 0666 的 `/proc` 控制节点 = 反检测暴露面

`proc_create(... 0666 ...)` 共 13 处，其中：

- `/proc/susfs_avc_spoof`(0666)、`/proc/susfs_enable_log`(0666)、
  `/proc/susfs_kstat`(0666)、`/proc/susfs_open_redirect`(0666)
- **任意 uid 可读内部状态（含 su_sid、计数器、隐藏路径清单）**
- **任意 uid 可写** → 检测方（或恶意 app）**直接把伪装关掉**

上游**没有**任何 `/proc` 节点，只走 supercall（而我们的 supercall 有 `uid==0` 校验）。

配合 `hide_list` 的 0444（见 B6），**我们有多个"把底牌摊开给 app 看"的接口**。

### 🟢 uname：与上游一致，且有微小优势

- **上游确实只 patch `newuname` 一处**（`50_patch:2195-2207`；23 个改动文件里
  **没有** `fs/proc/version.c`、`kernel/utsname_sysctl.c`）→
  **不存在"上游覆盖而我们覆盖不到"的 utsname 出口**
- arm64 上 32 位 compat 的 `__NR_uname(122)` 也映射到同一个 `__arm64_sys_newuname`
  （`arch/arm64/kernel/sys32.c:126,130`）→ 两侧作用在同一批调用者上
- 我们的出口**晚于** `override_release()`（UNAME26 personality 下会覆盖 release）
  → **在 UNAME26 边界下我们比上游更强**
- **共同盲区（非差异）**：`/proc/version`、`/proc/sys/kernel/{osrelease,ostype,version}`
  双方都不覆盖 → uname 伪装只在 `uname(2)` 一条路上成立
- 默认关、无 uid 门控、空串 `-EFAULT` —— 三项与上游一致 ✓
- 我们的机制新增风险：kretprobe `maxactive=32` 会漏、原子上下文 `copy_to_user`、
  **无 seqlock**（上游有）；`uname_register()` 失败仍留 `enabled=true`

### 🟡 cmdline 与上游的语义差异（非缺陷）

**上游只处理 `/proc/bootconfig`**，数据来自 SUSFS 自持的 8192 假缓冲
（截获 show 输出，**内核变量 `saved_boot_config` 保持原样**）。
我们直接改写内核变量本身 —— 在 5.15 里该变量唯一消费者就是 `boot_config_proc_show()`，
所以**机制成立且等价**，且 `saved_boot_config == NULL` 时我们能伪装而上游不能。

命令名 `SET_CMDLINE_OR_BOOTCONFIG` 有误导性：**`/proc/cmdline` 双方都不处理**（共同盲区）。

---

## B10. sus_mount 专项（子代理 e4a7d0db，**含真机实测**）

### ⚠️ 测试期间设备掉线

子代理在真机上做了 A/B 实验（自建 ksu 域 tmpfs 挂载、改 `min_mnt_id`、对比
`/proc/self/{mounts,mountinfo,mountstats}`），**测试做完后设备从 USB 上消失了**
（`adb devices` 空、主机已无该机 VID），最后一次「`min_mnt_id=1` 压力测试」因此未执行。

**消失前的设备状态已还原**：`min_mnt_id=2000000000`、探针挂载已 `umount`+`rmdir`、
`hide_sus_mnts` 保持 enabled（与 `/data/adb/susfs4ksu/config.sh` 一致）。
**需要你检查一下线缆/端口/手机 USB 模式。**

### 🔴 机制解释修正：上游**从未 patch `mnt_alloc_id`**

我们代码注释（`sus_mount.c:26-27`）说"上游 patch 了 `mnt_alloc_id()` 去调 `ida_alloc_min`" ——
**与上游源码不符**。`patch:578` 的 `@@ ... @@ static int mnt_alloc_id(...)` 只是 git 的
"所在函数名"提示行，补丁正文**只改了 `mnt_free_id`**。

上游的真实做法是：
- **新写 alloc 副本** `susfs_alloc_non_unshare_ksu_vfsmnt()`，内部用
  `ida_alloc_min(&mnt_id_ida, DEFAULT_KSU_MNT_ID, GFP_KERNEL)`（`patch:682`）
- 在 **`vfs_create_mount()` / `clone_mnt()` 的调用点**替换成这个副本（ksu 域才走）
- `mnt_free_id()` 对 `VFSMOUNT_MNT_FLAGS_KSU_UNSHARED_MNT` 位**不还 id**（`patch:583-584`）

### 🔴 致命：默认阈值恒假 → 功能 100% 不生效（真机复现）

- 本机 `mnt_alloc_id()` 用 `ida_alloc()`（**取最小空闲 id**），`sysctl_mount_max = 100000`
- 实测 `/proc/self/mountinfo` 的 mnt_id 区间 **91…37270**（238 个挂载），
  ksu 域自建挂载拿到 `27361`，meta-overlayfs 是 `37270`
- 结构性论证：ida 复用最小空闲槽，上限 ≈ 同时存活的 mount 数 ≤ mount-max，
  **要到 2e9 需要同时存在约 20 亿个 mount → 物理不可能**
- 真机 A/B：设 `hide_sus_mnts_for_non_su_procs 1` 后 mountinfo **行数 239 不变**（=失效）；
  把 `min_mnt_id` 改成 27361 → **239→237**（正好少了 27361 和 37270）；
  改回 2e9 → 恢复 239

**结论**：kprobe 短路、`real_mount()` 偏移**都是对的**，坏的只是"阈值语义"。
没有内核侧 `ida_alloc_min(..., 2e9)` 就**必然到不了**那个区间。

### 🔴 致命·纯遗漏：漏挂 `show_vfsmnt` → `/proc/mounts` 完全没隐藏

上游挂三处：`show_vfsmnt`（mounts）/ `show_mountinfo` / `show_vfsstat`（mountstats）。
我们只挂了**后两个**，而头注释（`sus_mount.c:3,5-6`）**声称隐藏 `/proc/mounts`**。

真机验证（阈值 37270）：`/proc/self/mountinfo` 里 meta-overlayfs **1→0**，
`/proc/self/mountstats` **1→0**，而 **`/proc/self/mounts` 仍是 1**。

`show_vfsmnt` 在设备 kallsyms 里**存在** → 纯属漏挂，**修复成本最低，建议优先**。

### 🔴 高·语义：无域门控 → 对 su/ksu 域也隐藏

上游打开后**只对非 ksu 域**替换 show 函数（`patch:1561-1563`），
su/ksu 域进程**仍看得到真实挂载**（好让 zygisk 在 post-fs-data 读到）。

我们**没有任何域/uid/umounted 判断**，对所有进程生效 —— **真机验证：`u:r:ksu:s0` 的 root
自己也看不到那两条挂载**。

而且**这不是能力所限**：本仓库已有解析 SID 的能力
（`susfs_avc_spoof.c:151-157` 用 `security_secctx_to_secid`），域门控**可实现，只是没做**。

### 🟠 ③ 组 4 个注入点全缺

`fdinfo` 的 mnt_id、inotify fdinfo、`statx` 的 `stx_mnt_id`、`statfs` ——
即便挂载行被隐藏，mnt_id/ino/dev 仍从这些路径泄漏
（上游 `patch:942-978 / 1169-1205 / 2002-2010 / 2058-2073`）。

**可行性结论**：这一组**在纯 kprobe 层无法实现** ——
`vfs_statx` 是 `static`（无符号）；fdinfo 的 `seq_printf` 是**函数体内直接打印**，
kprobe 改不了已打印的数字，只能把整行删掉；inotify 还缺 `struct file*` 形参
（上游是靠改回调签名拿到的，`patch:896-917`）。

### 🟡 其它

- `mnt_group_id` 伪装全缺 → mountinfo 的 `shared:N`/`master:N` 仍暴露组关系
- unshare / `copy_mnt_ns` 语义全缺（我们无 `VFSMOUNT_MNT_FLAGS_KSU_UNSHARED_MNT` 概念）
- `__lookup_mnt` 路径隐藏缺失（zygote_next 系进程仍能解析到 sus 挂载）
- **短路时未设 `regs->regs[0] = 0`**（`sus_mount.c:44-45`；对比自家
  `susfs_hide_syms.c:83` 是设了的）。`fs/seq_file.c:230-234` 里 `err < 0` 是 **hard error**，
  `err > 0` 只是"跳过该条"；而 x0 仍持有 `seq_file*`，低 32 位被当 int 返回，
  **若为负会导致整份 mountinfo 读取报错**（推测；本机 4 次短路实测未触发）
- `min_mnt_id` **无下限钳制**：设 0/1 会让所有 `/proc/*/mountinfo`、`mountstats`
  对所有进程近乎为空
- 每行一次 kprobe trap（上游是编译期内联 + static key，关掉零成本）

### ⛔ 在 LKM 里不可能/极难实现的部分（设备 kallsyms 实测）

| 符号 | kallsyms | 结论 |
|---|---|---|
| `mnt_alloc_id` / `mnt_free_id` / `mnt_alloc_group_id` / `ida_alloc_min` / `real_mount` | **0 命中** | static/inline 已被内联消除 → **不能 kprobe 也不能 patch** |
| `alloc_vfsmnt` / `clone_mnt` / `vfs_create_mount` / `__lookup_mnt` | 1 命中 | **可 kretprobe 拿返回值改 `mnt_id`** |
| `mnt_id_ida`（数据符号） | 1 命中 | 可访问 |

要造真"假 mnt_id"，只能在**调用点**下手：kretprobe 拿到 `struct vfsmount *` 后写
`real_mount(ret)->mnt_id = <自己 ida 分配的 id>`，同时自带 IDA、自带 su 域判定、
处理 unshare 复用与 `mnt_free_id` 不回收、避开 attach 竞争窗口 ——
**这已是重写上游第 ① 组，不是"加个 kprobe"**。

---

## C. 汇总：修复优先级（7 份报告合并后）

### P0 — 反检测自杀（我们自己在暴露自己）

| # | 问题 | 依据 |
|---|---|---|
| 1 | **`hide_list` 是 0444，内容含隐藏路径清单 + `%px` 真实内核指针**，`/sys/module/...` 下人人可读 | `sus_path.c:326-351` |
| 2 | **13 处 `proc_create(... 0666 ...)`**：任意 uid 可读内部状态（su_sid、计数器、隐藏清单），**可写 → 能直接关掉伪装** | `susfs_avc_spoof.c:166`、`susfs_enable_log.c:67`、`susfs_kstat.c:680`、`susfs_open_redirect.c:173` |
| 3 | **`enable_log` 是空壳**：用户以为关掉了日志，实际模块内 0 消费者，日志无条件打印 | `susfs_enable_log.c:21-25` |
| 4 | **`susfs_supercall_init()` / `susfs_hide_syms_init()` 返回值被丢弃** → 注册失败时"加载成功"但功能全失效；`hide_syms` 失败时 `enabled_features` **仍上报 `HIDE_KSU_SUSFS_SYMBOLS`（对外宣称与事实相反）** | `susfs_main.c:34-35` |
| 5 | **隐藏路径名被无条件 `pr_info` 写进 dmesg** | `sus_path.c:451/527-528` |

### P1 — 内存安全 / 数据竞争

| # | 问题 | 依据 |
|---|---|---|
| 6 | **open_redirect 无 RCU 保护 → UAF**：中断上下文无锁遍历，`or_add`/`or_del` 先 `path_put` 再赋新值 | `susfs_open_redirect.c:89-121` vs `:280/:305` |
| 7 | **bootconfig：UAF 竞态 + 悬空指针 + 二次释放**（`kfree` 旧串后 `kstrdup` 失败直接 return，且仍上报 `err=0`） | `spoof_cmdline.c:36-45` |
| 8 | **sus_map 越界写 `map_entries[-1]`**（`i_ino==0` + `nmap==0`） | `sus_map.c:40-41,144-145` |
| 9 | **sus_kstat 读路径无锁**（tracepoint/kretprobe 遍历，`/proc` 写会搬移结构体） | `susfs_kstat.c:127-136` vs `:509` |
| 10 | **sus_path 全局 `dirent_tmp` 无锁**（并发 getdents64 互相踩缓冲） | `sus_path.c:94,249-295` |

### P2 — 功能与门控语义（"贴合 susfs 设计"）

| # | 问题 | 成本 |
|---|---|---|
| 11 | **sus_mount 漏挂 `show_vfsmnt`** → `/proc/mounts` 完全没隐藏（真机验证） | **最低，符号存在，加一个 kprobe** |
| 12 | **sus_mount 无域门控** → 对 su/ksu 域也隐藏（真机验证）；上游只对非 su 域 | 低（已有 SID 解析先例） |
| 13 | **sus_mount 阈值恒假** → 功能 100% 不生效（真机验证） | 高（要重写上游第 ① 组） |
| 14 | **sus_kstat 缺 `show_map_vma`** → `stat` 伪装而 `/proc/pid/maps` 暴露真实 ino（最直接的检测面） | 中（扩展现有 `show_map_vma` kprobe 改参数） |
| 15 | **sus_kstat / sus_map 无任何门控** → root/init 也看到伪装值 | 低 |
| 16 | **sus_path `_LOOP` 语义丢失** → 预注册不存在的路径永远 `-ENOENT` | 中（需要 work + 重试机制） |
| 17 | **sus_path compat(32 位) 早退** → 32 位进程能列出被隐藏条目（布局其实相同） | **最低，删掉 `is_compat_task()` 早退即可** |
| 18 | **open_redirect 仅 1/5 档 + 反向伪装 0 覆盖** | 高 |

### P3 — 细节与一致性

- 路径长度截断 `128 < 256`（`open_redirect`、`kstat` 各一处）
- `fstat`/`statx`/compat 变体不在 tracepoint 白名单，只靠 kretprobe 兜底且失败静默
- `sus_mount` 短路时**未设 `regs->regs[0] = 0`**（可能让整份 mountinfo 报错）
- `min_mnt_id` 无下限钳制（设 0/1 会让所有 mountinfo 近乎为空）
- 未识别命令的 reboot 返回值（上游 `-EINVAL`，我们 `0`）
- `sus_path` >64KB 缓冲丢条目、回写失败仍改返回值、`ino==0` 的"按名回退"承诺未实现
- `sus_kstat` ADD 失败残留槽位；`nkstat==0` 时仍做两次 `copy_from_user`
- FUSE 特判缺失（`sus_path`、`sus_kstat` 两处）
- 每条目永久 `ihold` / 长期持 `struct path`

### P4 — 文档与注释修正（我们写错了的）

| 位置 | 错误内容 | 事实 |
|---|---|---|
| `sus_mount.c:26-27` | "上游 patch 了 `mnt_alloc_id()` 调 `ida_alloc_min`" | 上游**从未** patch 它（`patch:578` 是 hunk 头），而是**在调用点替换 alloc 副本** |
| `susfs_abi.h:86-90` | "上游是 typo，用户态用的是 `1<<8`" | 上游**用户态 C 工具同样有 typo**；只有 ksud(Rust) 用 `1<<8` |
| `TECHNICAL_NOTES.md` | "sus_path 无条件隐藏、root 也看不到" | 已有 `hide_from_apps` 门控 |
| `TECHNICAL_NOTES.md` | "8 个 feature" | 代码是 9 项 |
| `TECHNICAL_NOTES.md` | "namei.c 三处" | sus_path 相关共 **16 个 hunk**（那三处是关键机制，不是全部） |
| `susfs_abi.h:50` | `ERR_CMD_NOT_SUPPORTED` 无注释说明来源 | 它是**用户态**约定，kernel 只需"不回写 err" |

---

## D. 扫描方法

7 个子代理并行逐函数比对（上游 3 个文件 + patch + 用户态；LKM 15 个源文件），
其中 `sus_mount` 子代理另做了**真机 A/B 实验**并核对了本机内核源码树
`workspace/android_kernel_oneplus_sm8550`（5.15.180，与设备 uname 一致）。

子代理产出的 7 份详细报告：

| 报告 | 内容 |
|---|---|
| `SUSFS_LKM_FEATURE_REPORT.md` | LKM 功能与门控总览 |
| `SUSFS_builtin_功能与门控调研.md` | 上游总览（含 KSU 依赖逐条落点） |
| `SUSFS_builtin_vs_LKM_diff.md` | 入口 / ABI / 接口 / hide_syms |
| `SUS_PATH_LKM_vs_builtin.md` | sus_path 逐注入点 |
| `KSTAT_BUILTIN_VS_LKM.md` | sus_kstat 逐注入点 |
| `OPEN_REDIRECT_SUS_MAP_DIFF.md` | open_redirect + sus_map |
| `SUSFS_LKM_VS_UPSTREAM_4FEATURES.md` | uname / cmdline / avc / enable_log |

**本文件（`AUDIT_FINDINGS.md`）是汇总与核实结论**，其中标 🔴 的条目我已**自行读代码复核**，
标 ↔ 的纠正是**推翻子代理结论**的部分。


---

## C. 设备环境事实（实测，影响一切门控设计）

```
grep -c susfs /proc/kallsyms  →  0
MISS susfs_ksu_sid / susfs_set_batch_sid / susfs_init / susfs_add_sus_path
MISS ksu_handle_setresuid / ksu_handle_extra_susfs_work
OK   cached_zygote_sid  [kernelsu]
```

**设备内核没有编译 SUSFS 集成**，只有 KernelSU（SukiSU）。
→ `TIF_PROC_UMOUNTED`（bit 33）永远不会被置位
→ 上游以 `susfs_is_current_proc_umounted_app()` 为前提的**所有**门控在 LKM 里**不可能原样复现**
→ `uid >= 10000` 代理是当前唯一可得的近似（`sus_path` 已用；`sus_kstat`/`sus_map`/`sus_mount` 连代理都没有）

---

## D. 待补（子代理报告已到，待汇总）

- `sus_path` 逐注入点覆盖度（子代理 07fb8d15）
- `sus_kstat` 逐注入点 + flags 位（子代理 53454933）
- `sus_mount` 4 组机制核证（子代理 e4a7d0db）
- `uname` / `cmdline` / `avc` / `enable_log`（子代理 4574de79）
- 入口 / ABI / 接口 / hide_syms（子代理 ffec743e）
