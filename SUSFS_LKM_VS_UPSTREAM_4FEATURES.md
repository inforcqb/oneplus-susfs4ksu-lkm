# SUSFS builtin（上游补丁） vs LKM 移植版：4 个功能逐项对比

对比对象
- 上游（编译进内核）：`susfs4ksu/kernel_patches/fs/susfs.c`
  `susfs4ksu/kernel_patches/50_add_susfs_in_gki-android13-5.15.patch`（下称 `50_patch`）
  `susfs4ksu/kernel_patches/KernelSU/10_enable_susfs_for_ksu.patch`（下称 `KSU_patch`）
- LKM：`susfs4ksu-lkm/kernel/*.c`（下称 `LKM/`）
- 用于核实注入点上下文的**真机内核源码树**（未打 SUSFS 补丁）：
  `android_kernel_oneplus_sm8550/`（Linux 5.15.180，`Makefile:2-4`），下称 `dev-tree/`

---

## A. uname 伪装

### A1. 上游

| 项 | 结论 | 依据 |
|---|---|---|
| 注入点 | 只有一处：`kernel/sys.c` 的 `SYSCALL_DEFINE1(newuname)` 函数体内，`memcpy(&tmp, utsname(), sizeof(tmp))` 之后、`up_read(&uts_sem)` 之前 | `50_patch:2195-2207`（hunk `@@ -1291,12 +1298,20 @@`）；真机源码位置 `dev-tree/kernel/sys.c:1294-1309` |
| 覆盖字段 | 仅 `tmp->release`、`tmp->version` | `susfs.c:664-665` |
| static key | `DEFINE_STATIC_KEY_FALSE(susfs_is_uname_spoof_buffer_set)`（默认**关**）；首次 `CMD_SUSFS_SET_UNAME` 成功时 `static_branch_enable` | 定义 `susfs.c:616`；enable `susfs.c:645-646`；消费 `50_patch:2202` |
| uid 门控 | **无**。`susfs_spoof_uname()` 只有 seqlock，没有任何 uid/进程判定 → root、app 一律生效 | `susfs.c:659-667` |
| 数据写入 | 用户态 `st_susfs_uname`（136B，`susfs.h:107-111`）→ 空串返回 `-EFAULT`（`susfs.c:627-630`）→ `"default"` 取**当前** `utsname()->release/version` 快照（`susfs.c:633-642`）→ `strscpy(..., __NEW_UTS_LEN)`，有效长度 ≤ **63** 字符（`susfs.c:634-641`）→ seqlock 写入 |

补充（影响"覆盖是否最终生效"）：`newuname` 在 `copy_to_user` **之后**还会调用
`override_release()`（`dev-tree/kernel/sys.c:1304-1305`，仅当 `current->personality & UNAME26`，实现见 `:1268-1292`）再写一次用户态 `name->release`，会覆盖上游 spoof 的 release；
`override_architecture()`（`:1254-1257`，`COMPAT_UTS_MACHINE` + `PER_LINUX32`）只改 `machine`，与 release/version 无关。

### A2. LKM

| 项 | 结论 | 依据 |
|---|---|---|
| hook | kretprobe `__arm64_sys_newuname`；entry handler 保存用户指针（arm64 syscall wrapper quirk：`regs->regs[0]` 是 `struct pt_regs *`，真参数在 `user->regs[0]`），return handler 在 `regs_return_value()==0` 时 `copy_to_user` 改写两个字段 | `LKM/susfs_uname.c:76-82`、`:47-56`、`:58-74` |
| 覆盖字段 | 仅 `offsetof(new_utsname, release)` / `version`，各写 `SUSFS_UNAME_LEN = __NEW_UTS_LEN+1 = 65` 字节 | `LKM/susfs_uname.c:29`、`:67-72` |
| 注册时机 | **惰性**：默认不注册；init 仅在 insmod 同时给了 `release`+`version`+`uname_spoof_enabled=1` 时注册；否则等首次 `CMD_SUSFS_SET_UNAME` | `:33`、`:38`、`:111-120`、`:153-154`、`:86-99` |
| `"default"` 语义 | 与上游同义（set 时刻快照 `utsname()`），但用 `sizeof(fake_release)`=65 → 最多 **64** 字符 | `:143-151` |
| 默认开关 | **关**（与上游一致） | `:33` |
| 门控 | **无 uid 门控**（与上游一致）；空串 → `-EFAULT`（与上游一致） | `:138-141` |

### A3. 差异表：覆盖到的 utsname 出口

**先回答核实问题：上游也只 patch 了 newuname 一处。**
`50_patch` 全文 uname 相关 hunk 只有 `2191-2207` 一段；patch 涉及的 23 个文件清单里
**没有** `fs/proc/version.c`、`kernel/utsname_sysctl.c`、`fs/proc/cmdline.c`。

arm64 上 `uname(2)` 只有 `__arm64_sys_newuname` 一个入口：
64 位走 `sys_call_table`；32 位 compat 表把 `__NR_uname(122)` 映射成 `sys_newuname`，
再经 `__arm64_##sym` 展开为 `__arm64_sys_newuname`
（`dev-tree/arch/arm64/include/asm/unistd32.h:257-258`、`dev-tree/arch/arm64/kernel/sys32.c:126,130-134`）。

结论：**不存在"上游覆盖而 LKM 覆盖不到"的 utsname 出口**——两者作用在同一批调用者上。

| 出口 | 上游 | LKM | 说明 |
|---|---|---|---|
| `uname(2)` / `newuname(2)`（64 位） | ✅ 改 `tmp` | ✅ 出口改写用户缓冲 | 等效 |
| 32 位 compat `__NR_uname` | ✅ 同一函数体 | ✅ 同一 `__arm64_sys_newuname` 符号 | 等效（已核实符号展开） |
| `UNAME26` personality 下的 `release` | ⚠️ 会被后置的 `override_release()` 冲掉（`dev-tree/kernel/sys.c:1304`） | ✅ 最终生效（晚于 override_release） | LKM 反而更强（边界情形） |
| `/proc/version` | ❌ 未覆盖（`dev-tree/fs/proc/version.c:12-14` 直读 `utsname()`） | ❌ 未覆盖 | **共同盲区** |
| `/proc/sys/kernel/{osrelease,ostype,version}` | ❌ 未覆盖（`dev-tree/kernel/utsname_sysctl.c:77-93` 直读 `init_uts_ns.name.*`） | ❌ 未覆盖 | **共同盲区** |

LKM 机制引入的额外差异/风险（上游机制不存在）：
1. `maxactive = 32`（`:81`）——并发 in-flight `newuname` 超过 32 次时 kretprobe 会 miss，那一次调用返回**真实** uname。上游不可能 miss。【推测：实际触发概率极低】
2. return handler 在 kprobe（原子）上下文里调用 `copy_to_user`（`:67-71`）。注释（`:10-11`）依赖"原 syscall 刚 fault-in 过这些页"；一旦缺页即违反"不可睡眠"约束。【推测：实际未见到故障】
3. **无锁**：`strscpy` 写 `fake_release/version` 与 kretprobe 读之间没有 seqlock（上游 `susfs.c:617`、`:662-666` 有）→ 并发 set+uname 可能读到撕裂字符串。【推测概率低】
4. 长度上限不一致：LKM 有效 64 字符（`strscpy(...,65)`，`:145-151`），上游 63（`strscpy(...,__NEW_UTS_LEN)`，`susfs.c:636,639`）。
5. `uname_register()` 失败时 `uname_spoof_enabled` 已被置 `true`（`:153-158`）→ "开关=开但无 hook" 的不一致状态。
6. 依赖 amd64/arm64 syscall wrapper 细节（`:47-56`），换架构或 wrapper 行为变化即失效（设计取舍）。

---

## B. cmdline / bootconfig 伪装

### B4. 上游：注入点与数据来源

- 注入点：**只有 `fs/proc/bootconfig.c` 的 `boot_config_proc_show()`**
  （`50_patch:1099-1124`；真机源码 `dev-tree/fs/proc/bootconfig.c:16-19`）。
  **没有 `/proc/cmdline` 一侧**：`50_patch` 文件清单无 `fs/proc/cmdline.c`，全文也**没有** `saved_command_line` / `boot_command_line` 的引用（grep 0 命中）。
  → `CMDLINE_OR_BOOTCONFIG` 这个名字有误导性；`/proc/cmdline` 上游同样不伪装。
- 门控：`static_branch_likely(&susfs_is_fake_cmdline_or_bootconfig_buffer_set)` **且** `saved_boot_config` 非空（`50_patch:1115-1120`）。
  key 定义：`DEFINE_STATIC_KEY_FALSE`（默认关，`susfs.c:700`），首次 set 时 enable（`susfs.c:739-740`）。
- 数据来源：**不是** `boot_command_line`，而是 SUSFS 自己的
  `static char *fake_cmdline_or_bootconfig`（`susfs.c:699`）：首次 set 时 `kzalloc(8192)`（`susfs.c:725-731`），
  在 seqlock 保护下 `seq_puts(m, fake_cmdline_or_bootconfig)`（`susfs.c:756-763`，永不释放该缓冲）。
- 写入校验：空串 `-EINVAL`（`susfs.c:720-723`）；`strscpy(..., 8191)` → 最多 **8190** 字符（`susfs.c:734-736`）。
- 也就是说：上游是"**截获 show 的输出**"，内核变量 `saved_boot_config` 保持原样。

### B5. LKM：机制、生效条件、覆盖范围

- 机制：不用 hook，**直接改写内核静态指针** `saved_boot_config`
  （`extern char *saved_boot_config;` `LKM/spoof_cmdline.c:23`；赋值 `:45`）。
  核实：5.15 该变量是 `static char *`，唯一读取点就是 `boot_config_proc_show()`（`dev-tree/fs/proc/bootconfig.c:13,17-18`），
  在 `fs_initcall` 阶段由 `proc_boot_config_init()` 赋值（`dev-tree/fs/proc/bootconfig.c:75-95`）→ 模块加载时它已就绪。
  LKM 注释（`:5-7`）描述准确。
- 符号解析：靠 `ksud insmod` 加载时用 kallsyms 重定位未导出符号（`:7-9`；`LKM/README.md:10`）。
  前提已满足：本机内核 `dev-tree/arch/arm64/configs/gki_defconfig:45` = `CONFIG_KALLSYMS_ALL=y`，
  static 数据符号在 `/proc/kallsyms` 可见。【推测：无 KALLSYMS_ALL 的内核上，模块会因该未解析符号**整体**加载失败，而非单功能失效；未实测】
- 生效条件：insmod `bootconfig=` 非空（`char[256]`，`:25-26`、`:51-56`）或 `CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG`（`:71-93`）。
- 覆盖范围：全局（无 uid 门控，与上游一致）；exit 时把原指针写回并释放假串（`:60-68`）。

### B6. 差异表 + 代码缺陷

| 维度 | 上游 | LKM | 评价 |
|---|---|---|---|
| 作用层面 | 只替换 `/proc/bootconfig` 的输出 | 改写内核全局 `saved_boot_config` | 本树内等价（唯一消费者是 show）；若有厂商补丁另读该变量则 LKM 副作用更大【推测】 |
| `/proc/cmdline` | 不处理 | 不处理 | **共同盲区（非差异）** |
| 缓冲生命周期 | 只分配一次、永不释放、读侧 seqlock（`susfs.c:725-731`、`:756-763`） | **每次 set 先 `kfree` 旧缓冲**（`:36-37`）再发布新指针（`:45`）；exit 也 `kfree`（`:62-64`） | ❌ LKM 独有 **UAF 竞态**：读者已把旧指针读入寄存器后继续读 → use-after-free |
| 分配失败 | `-ENOMEM` 上报（`susfs.c:726-730`） | `kstrdup` 失败直接 `return`（`:41-43`），调用方仍写 `err=0`（`:84-85`） | ❌ LKM 独有 **悬空指针 + 二次释放**：`saved_boot_config` 仍指向已释放内存、`spoof_active` 仍 true，下次 set 会再 kfree 同一指针 |
| 空串校验 | `-EINVAL`（`susfs.c:720-723`） | 无 → 把 `/proc/bootconfig` 变成空串并报成功 | ❌ 纯遗漏 |
| 长度上限 | 8190（`strscpy 8191`） | insmod 参数上限 **255** 字符（`:25`）；supercall 侧 kstrdup 全串（≤8191） | ❌ insmod 参数与 ABI（8192，`susfs_abi.h:53,152-155`）不一致；代码注释（`:12-14`）把它含糊带过 |
| `saved_boot_config == NULL`（无 bootconfig 内容） | 不伪装（`50_patch:1116` 判空） | 能把 NULL 换成假串 → 有输出 | 语义不同，LKM 更强（非缺陷） |
| 并发一致性 | seqlock + 定长缓冲 | 指针换写（原子）+ 上面的 UAF 问题 | ❌ 见上 |

---

## C. avc log spoofing

### C7. 上游

- 注入点：`security/selinux/avc.c` 的 `static void avc_audit_post_callback(struct audit_buffer *ab, void *a)`
  （真机源码 `dev-tree/security/selinux/avc.c:713`），改的是
  `security_sid_to_context(sad->state, sad->tsid, ...)` 之后那段 tcontext 打印（`avc.c:731-736`；`50_patch:2261-2285`）。
  **不是** `slow_avc_audit`。
- 门控：`static_branch_likely(&susfs_is_avc_log_spoofing_enabled)`（`50_patch:2266`；key 定义 `susfs.c:1129` `DEFINE_STATIC_KEY_FALSE` = 默认关，开关 `susfs.c:1139-1145`）
  **且** `unlikely(sad->tsid == susfs_ksu_sid)`（`50_patch:2267`）。
- `susfs_ksu_sid` 的来源：KernelSU 自己解析 `susfs_set_sid(KERNEL_SU_CONTEXT, &susfs_ksu_sid)`
  （`KSU_patch:2496`；`KERNEL_SU_CONTEXT = "u:r:" KERNEL_SU_DOMAIN ":s0"`，本机 SukiSU 的 `KERNEL_SU_DOMAIN="ksu"`
  → `u:r:ksu:s0`，`SukiSU-Ultra/kernel/selinux/selinux.h:8,11`）。
- 伪装成什么：**硬编码字面量** `"u:r:priv_app:s0:c512,c768"`（`50_patch:2271`）；
  只有 context 转换失败时才退化成 `tsid=<susfs_priv_app_sid>`（`50_patch:2269`，该 sid 同样来自 KSU：`KSU_patch:2415,2498`）。
- 作用域很窄：`goto bypass_orig_flow` 只跳过那一行 tcontext 打印；`sad->tsid` 本身**没有**被改，
  因此 `tclass`/`permissive`/`trace_selinux_audited()`（`avc.c:744`）/`trawcon`（`avc.c:759-767`）照旧输出真值。

### C8. LKM

- hook：kprobe `slow_avc_audit`（`LKM/susfs_avc_spoof.c:70-73`）。该函数是 `noinline` 的全局符号
  （`dev-tree/security/selinux/avc.c:775`），`common_lsm_audit(a, avc_audit_pre_callback, avc_audit_post_callback)` 在其内（`:802`）。
- 改什么：pre_handler 把第 3 个参数 `regs->regs[2]`（`slow_avc_audit(state, ssid, tsid, ...)` 的 tsid）
  从 su sid 改写为 priv_app sid（`:58-68`），函数体随后 `sad.tsid = tsid`（`dev-tree/.../avc.c:794`）自然输出假 context。
- 为什么换符号：`avc_audit_post_callback` 是 static 且调用点被 LTO 内联，kallsyms 里的 `t` 符号是残留，
  挂上去 enter 恒 0（`LKM/kernel/TECHNICAL_NOTES.md:149-158`）。
- 默认 sid：`avc_su_ctx = "u:r:ksu:s0"`（`:38`）、`avc_priv_app_ctx = "u:r:priv_app:s0:c512,c768"`（`:39`，与上游字面量一致），
  init 时用 `security_secctx_to_secid()` 解析（`:151-162`），两个 module_param 可覆盖
  （`TECHNICAL_NOTES.md:160-162` 实测本机 su 域就是 `u:r:ksu:s0`）。
- 开关：默认关（`:45`）；`/proc/susfs_avc_spoof` 写 1/0（`:112-135`，**0666**）或 supercall（`:185-209`）；**启用时才注册 kprobe**（`:75-87`）。

### C9. 差异表：LKM 缺了哪些判定

先说 `tsid == ksu_sid` 这条判定的意义：`slow_avc_audit` 是所有 AVC denial 的公共出口。
**若没有这条判定，命中就会把每一次 denial 的 target context 都写成 priv_app**——
全系统日志里所有 `denied` 的 tcontext 变成同一个值（app 之间的 denial 也失去真实 target），
既是功能破坏，也是极显眼的异常特征（比不伪装更容易被统计发现）。

结论：这条判定 LKM **有对应物**（`:63` `tsid == avc_su_sid`），但差在以下几处：

| 差异 | 上游 | LKM | 后果 |
|---|---|---|---|
| sid 来源的权威性 | KSU 自报 `susfs_ksu_sid`（`KSU_patch:2496`） | 硬编码/参数化猜 `"u:r:ksu:s0"`（`:38`） | 换 KSU 变体（官方 KernelSU 是 `u:r:su:s0`）或自定义 su 域时判定永不命中 → **伪装静默失效**（supercall 返回 0、/proc 显示 enabled=1，但一条都不改） |
| sid 解析失败的兜底 | 打印硬编码字面量，永不出错（`50_patch:2269-2271`） | 失败只把 sid 置 0 且**不阻止启用**（`:151-162`、`:194-203`） | su_sid=0 → 静默失效；priv_app_sid=0 → 把 tsid 改成 0，日志退化成 `tsid=0`（垃圾值） |
| 改写范围 | 只改"打印出来的那一个字符串"，`sad->tsid` 保留真值 | 改参数本身，`sad->tsid` 变假 | LKM 额外覆盖了 `trace_selinux_audited()`（`avc.c:744`）与 `trawcon`（`avc.c:759`）两处泄漏；但超出"日志伪装"语义（tracepoint/perf 消费者拿到假数据）——设计取舍 |
| 门控成本 | static key，开启后仅一次静态分支 | 开启后每次 denial 都走 int3 + kprobe handler | 性能差异（量级小）【推测：高 denial 频率设备上可测】 |
| 控制面暴露 | 无 /proc 节点（`50_patch` 里 `proc_create` 0 命中），只走 supercall | `/proc/susfs_avc_spoof` **0666**（`:166`） | 任何 uid 可读内部 `su_sid/priv_app_sid/enter/hits`（暴露模块存在与状态），并可写 1/0 关掉伪装；supercall 路径反而有 `current_uid()!=0` 校验（`LKM/susfs_supercall.c:180`）。Android SELinux 是否默认拦 untrusted_app 写 procfs 需实测【推测】 |
| 文档自相矛盾 | — | 文件头说隐藏的是 dmesg 里的行（`:8-9`），实测结论是 avc denied 走 logcat/auditd（`TECHNICAL_NOTES.md:165-166`） | 仅注释问题 |

---

## D. enable_log

### D10. 上游

- static key 初值：`DEFINE_STATIC_KEY_TRUE(susfs_is_log_enabled)` → **TRUE，默认就是开的**（`susfs.c:32`）；
  `CMD_SUSFS_ENABLE_LOG` 的 `enabled=0` 才是关（`susfs.c:680-686`）。
- 消费宏（`susfs.c:33-34`）：
  `SUSFS_LOGI(...)` → `if (static_branch_likely(&susfs_is_log_enabled)) pr_info("susfs:[%u][%d][%s] " fmt, current_uid().val, current->pid, __func__, ...)`，
  `SUSFS_LOGE(...)` → 同门控、`pr_err(...)`；
  `CONFIG_KSU_SUSFS_ENABLE_LOG` 未开时两宏展开为空（`susfs.c:36-37`）。
- 覆盖范围：`fs/susfs.c` 内 **93 个调用点**（grep 命中 97 行 − 4 行宏定义）。
  `50_patch` 里**没有** `SUSFS_LOGI` 命中 → 上游这个开关也只控制 `fs/susfs.c` 自己的日志，patch 进内核的其它文件（namei.c/stat.c…）不参与。

### D11. LKM

- 开关：`static bool log_enabled`（`:19`）；`/proc/susfs_enable_log` 写 '1'/'0'、读回 `0/1`（`:38-53`，**0666**，`:67`）；supercall `CMD_SUSFS_ENABLE_LOG`（`:85-102`）。
- 导出符号：`bool susfs_log_enabled(void)` + `EXPORT_SYMBOL`（`:21-25`），声明在 `LKM/kernel/susfs.h:29`。
- **模块内实际调用点 = 0**（已全仓库 grep，不只单文件）：
  全部命中只有 `susfs_enable_log.c:21`（定义）、`:25`（`EXPORT_SYMBOL`）、`susfs.h:29`（声明）、
  `susfs_main.c:32,44`（init/exit 调用的是 `susfs_enable_log_init/exit`）、`susfs_supercall.c:146`（分发到 `*_supercall`），
  以及报告文档与 Makefile 里的文件名。**没有任何 `.c` 调用 `susfs_log_enabled()`。**
- LKM 各功能其实是"无条件 pr_*"：全 `kernel/` 目录 162 处 `pr_*`（含探测模块），日志集中在加载/配置/错误路径（无热路径，例如 `sus_path.c:527` 是**加规则**时打印，不是每次命中）。
- 顺带核实的格式差异：LKM 编好的 `.ko` 里字符串带 `susfs_guard_lkm: ` 前缀（由 `susfs_log.h:7-10` 的 `pr_fmt` 生效，已在 `artifacts/kernel/susfs_guard_lkm.ko` 二进制里验证），
  但没有上游的 `[uid][pid][func]` 上下文信息。

### D12. 差异表 + 结论

| 维度 | 上游 | LKM |
|---|---|---|
| 默认状态 | **开**（`DEFINE_STATIC_KEY_TRUE`，`susfs.c:32`） | **关**（`log_enabled=false`，`:19`） |
| 实际控制 | 93 个日志点（`susfs.c`） | **0 个** |
| 接口 | 仅 supercall | supercall + `/proc/susfs_enable_log`(0666) + 导出函数 |
| 日志内容 | `susfs:[uid][pid][func] …` | `susfs_guard_lkm: …`（无 uid/pid/func） |
| 关闭后 | 全部静默 | 无任何变化（本来就没有消费者） |

**结论：LKM 的 enable_log 是空壳——只有接口，不控制任何输出。**
既不是"部分实现"，而是"0 消费者"；文件头注释自己写着 "Feature hit-path logs should check susfs_log_enabled()"，属未完成的约定（`:9-10`）。
反向影响也要说清：因为 LKM 的日志都无条件打印，它**无法**按上游那样被 `ENABLE_LOG=0` 静音。

---

## 缺失/缺陷清单（合并四个功能，按严重度）

**高**

1. **[纯遗漏] ENABLE_LOG 0 消费者**：`susfs_log_enabled()` 全仓库无调用点（`LKM/susfs_enable_log.c:21-25`），
   开关不控制任何输出；上游默认开且控制 93 个日志点（`susfs.c:32-34`）。要真正对齐，需要给各功能日志套上层门控宏（等价 `SUSFS_LOGI/LOGE`）。
2. **[纯遗漏] bootconfig 更新的 UAF / 二次释放**：`spoof_set()` 先 `kfree` 旧假串再发布新指针（`LKM/spoof_cmdline.c:36-45`），
   exit 路径同理（`:60-68`）；`kstrdup` 失败直接 `return`（`:41-43`）会留下**悬空 `saved_boot_config`** 且 `spoof_active` 仍 true → 下次 set 二次 `kfree`，
   且失败被上报为 `err=0`（`:84-85`）。上游用"只分配一次 + seqlock"规避（`susfs.c:725-731`、`:756-763`）。
3. **[设计取舍 + 纯遗漏] AVC 的 su sid 靠猜、且失败无反馈**：
   默认 `"u:r:ksu:s0"`（`LKM/susfs_avc_spoof.c:38`）只对本机 SukiSU 成立；
   sid 只解析一次、失败即置 0 且不阻止启用（`:151-162`、`:194-203`）→ 换 KSU 变体/策略时伪装**静默失效**（返回成功、状态显示 enabled）。
   "LKM 拿不到 KSU 内部 sid" 是设计取舍，但"解析失败仍允许启用且不给错误"是纯遗漏（至少应把失败反映到 supercall 返回或 /proc 状态）。

**中**

4. **[纯遗漏] 控制节点 0666**：`/proc/susfs_avc_spoof`（`LKM/susfs_avc_spoof.c:166`）、`/proc/susfs_enable_log`（`LKM/susfs_enable_log.c:67`）等全部 0666（`proc_create` 共 13 处）
   → DAC 层面任何 uid 可读（暴露模块存在、内部 sid、命中计数）可写（可关掉伪装）。上游没有这些节点（`50_patch` 无 `proc_create`），控制只走 reboot supercall。
5. **[纯遗漏] 校验/上限不一致**：cmdline 空串上游 `-EINVAL` 而 LKM 接受（`LKM/spoof_cmdline.c:84`）；
   insmod `bootconfig=` 上限 255 字符 vs ABI 8192（`:25` vs `susfs_abi.h:53,152-155`）；
   uname 有效长度 64 vs 上游 63（`LKM/susfs_uname.c:145-151` vs `susfs.c:636,639`）。
6. **[设计取舍] LKM uname 用 kretprobe 的固有风险**：`maxactive=32` 会漏（`LKM/susfs_uname.c:81`）；
   return handler 在原子上下文 `copy_to_user`（`:67-71`）；无 seqlock（对照上游 `susfs.c:617`、`:662-666`）。
   上游机制上不存在这些限制（代价是必须改内核源码）。

**低**

7. **[语义差异] AVC 改写范围大于"日志"**：改 tsid 参数会同时改掉 `trace_selinux_audited()`（`dev-tree/security/selinux/avc.c:744`）与 `trawcon`（`:759`），
   上游保留真值只换打印串。隐藏更彻底，但超出"日志伪装"语义，属需要显式确认的取舍。
8. **[共同盲区，非差异] utsname / cmdline 的其它出口双方都没覆盖**：`/proc/version`（`dev-tree/fs/proc/version.c:12-14`）、
   `/proc/sys/kernel/{osrelease,ostype,version}`（`dev-tree/kernel/utsname_sysctl.c:77-93`）、`/proc/cmdline`（双方都不碰 `saved_command_line`/`boot_command_line`）。
   → "uname 伪装"实际只在 `uname(2)` 一条路成立（**上游也只 patch 了 newuname**，已核实），常规检测可直接绕过。
9. **[低] 状态一致性 / 文档**：uname 注册失败仍保留 `enabled=true`（`LKM/susfs_uname.c:153-158`）；
   avc 文件头说 dmesg、实测是 logcat（`LKM/susfs_avc_spoof.c:8-9` vs `TECHNICAL_NOTES.md:165-166`）；
   `spoof_cmdline.c:12-14` 对 insmod 参数优先级的注释含糊。
10. **[平台前提] 依赖 `CONFIG_KALLSYMS_ALL`**：`LKM/spoof_cmdline.c:23` 直接 `extern` 一个 static 数据符号，
    本机满足（`dev-tree/arch/arm64/configs/gki_defconfig:45`）；换内核若不满足，模块会整体加载失败（全部功能不可用），而非只有该功能失效。【推测，未实测】
