# 变更记录

本文件只记录已落地的主要变更。当前版本处于 0.1 开发阶段，尚未发布正式版本；验证范围以兼容矩阵为准。

## 未发布

### 兼容模块

- 默认启用原生 relay，支持 WoW64 原生首进程及 AMD64/WoW64 混合启动链。可通过 `--no-native-relay` 关闭。
- 分离进程传播、堆窗口、EXE 与 DLL 布局、MSYS IPC 和两类 DACL 处理。用可重复的 `--disable-module NAME` 进行组合对照，关闭时跳过相应预检、元数据读取和 hook 安装。`--trace` 显示实际启用的模块。见[兼容模块对照](docs/getting-started.md#兼容模块对照)。

### 构建

- `build.ps1` 支持 Windows PowerShell 5 和 PowerShell 7。CTest 的 PowerShell 集成测试继续使用 pwsh。

### MSYS 内存布局

- 为已识别的 MSYS 进程在创建时暂留堆窗口，并在恢复执行前释放。原版 MSYS 自行预留和提交 cygheap 与 userheap，删除 `NtAllocateVirtualMemory` hook。
- 冷启动和 exec 时可为未设置 `DYNAMIC_BASE` 的 MSYS 主 EXE 尝试一次 PE 首选基址，失败时沿用原选址。fork 仍按父进程实载地址对齐。
- 按 EXE 自身的普通导入表识别直接依赖 `msys-2.0.dll` 的程序。DLL 映射从现有 section 查询标志、映像长度和首选基址，取消路径检查和临时视图。对基址未指定、未设置 `DYNAMIC_BASE` 且整个首选区间满足 `ZeroBits` 的 AMD64 映像 DLL 尝试首选址，失败时恢复原请求并重试。见 [ADR-0012](docs/decisions/0012-prefer-dll-image-base-at-map.md)。

### 终端转发

- 自动 ConPTY 逐路保留文件、管道和 `NUL` 重定向。有可用的外层控制台且至少一路接着控制台时启用桥，以兼容 Low IL 目标读屏幕和写输入事件。见 [ADR-0014](docs/decisions/0014-conpty-preserve-redirected-stdio.md)。
- 修正控制台方向的 UTF-8 代码页与 VT 模式，并在输出排空和启动失败后恢复外层状态。
- 兼容宿主和 PSEC 演示工具的等待进程处理 Ctrl+C 通知，保留前台应用自己的中断处理。
- MSYS 冷启动设置当前进程对象的 DACL 时沿用现有 ACL 转换规则，使新运行时能检查控制台所有者是否存活。
- 演示入口为默认交互 Bash 初始化 GNU 工具 PATH、TERM 和 UTF-8 locale。
- 交互 PowerShell 演示入口使用项目内可写的 PSReadLine 历史文件，并验收实际交互命令的持久化。
- ConPTY 双向转发遇到短写时继续写入剩余字节，并在写入失败或零进展时结束该方向的转发。
- 交互式 ConPTY 默认跟随外层控制台窗口的初始尺寸和后续变化，显式 `--conpty-size` 固定会话尺寸。
- 回归覆盖 ConPTY UTF-8 往返、继承标准流时的混合重定向和下游提前关闭。

### Git 工作流回归

- 覆盖 PSEC 和两种固定受限令牌中原生 Git 经 relay 自动触发 `pre-commit` 的正常提交与拒绝提交。

### 精简初始化与失败处理

- 移除生产入口的默认 Git 安装路径。旧命令的 `--runtime DLL` 参数仍可解析，参数值被忽略。
- 默认策略快照与策略锁仅用于 relay，其他 token 的设置在拿锁前透传；普通模式只适配当次 ACL。
- 移除 `MSYS_SANDBOX_COMPAT_SESSION`。非 AppContainer 受限进程树的兼容目录按创建宿主 PID 命名，目录路径由 agent 传给支持的后代。
- 将正式兼容初始化移至子进程首次进入加载器时，保留应用启动上下文和调用方的初始挂起语义。见 [ADR-0015](docs/decisions/0015-initialize-at-child-loader-entry.md)。
- 安装失败统一终止挂起的新进程，删除跨入口回滚及无消费者的计划字段；ACL 结果复用已预留空间的输入副本。
- ACL 拒绝用例按未执行和恢复后的正对照验收，Win32 错误码仅记录；设计细节归并到实现说明，测试文档不维护固定数量。
- 移除原生 PSEC 的原版 Bash 拒绝诊断断言。PSEC 继续检查真实兼容负载与权限边界，非 AppContainer 受限令牌的进程链保留原版执行记录。

### ntdll 入口搬迁

- 用固定版本 MinHook 的 HDE64 与适配搬迁核心替代固定八字节 syscall 前导假设，保留已有入口跳转执行路径。
- 分开纯搬迁计划与远程安装接口，CMake 集中选择后端，为后续切换 Detours 保留边界；无额外运行时 DLL。
- 增加位移/输入边界检查、源字节复核、失败回滚和执行测试，保留 native relay 的单入口修改范围；随包交付 MinHook/HDE 完整许可证。

### 对象授权适配

- 显式对象 ACL 与 TokenDefaultDacl 均基于当次输入补受限主体，不再用统一 SD/启动快照覆盖；保留 owner/group/SACL/control，按用户及 enabled groups 的原有权限追加，deny/空/复杂输入不补权。NULL DACL 用 Everyone 与受限主体表达开放意图。
- 默认策略设置与创建/克隆串行化，成功后更新 relay 比较基准；原生 relay 的未观察策略变化仍拒绝。支持仅含 TOKEN_ADJUST_DEFAULT 的设置句柄，其他 token 和查询句柄权限保持系统语义。
- 记录 ntdll 通用接入、分问题适配与早期 agent 无 CRT/导入/TLS 依赖的原则；新增对象 SD/ACL 单测与真实 MSYS 设置回归。

### 精简与结构

- 生产包收敛为 msys-sandbox-compat.exe/DLL；psec-run 移为可选开发工具，不再安装。默认构建只生成生产兼容层，开发工具和回归分别通过 -Tools/-Tests 开启；安装暂存迁到 build/package。
- core 明确宿主/agent 共享源码，独立内部识别与 agent 头文件；测试源码、夹具和输出分开，统一 Windows 参数转义实现。
- trampoline 批量初始化并统一保护，继承 relay 复用现有状态。
- ConPTY 输入脚本与标准输入共用句柄循环；历史诊断退出默认回归，常规重复次数与压力参数分离，保留功能和权限边界矩阵。

### 修复

- 修复 MSYS 冷启动重设默认对象 DACL 后的原生桥接回入；当前按 ADR-0008 基于当次输入适配，恢复真实 fork、管道与退出码行为。
- 新增进程链端到端回归，验证一层/三层未注入原生桥接、10 次线程中 fork、初始 ACL 保留与读写拒绝边界；成功验收替代该链路原先的预期拒绝。

- 宿主使用当前主 token 的只读伪句柄与直接命名空间查询，MSYS 创建的原生后代可通过兼容入口启动原生目标，无需重开 token 或创建命名事件探针。
- 冷启动 MSYS 根进程前检查真实 token 查询权限；受限后代 token 不可重开时，在恢复前明确报错并回收目标，避免进入已复现的初始化等待。
- 作用范围回归补充原生目标无补丁、默认 token DACL 保持一致，以及 MSYS 冷启动预期拒绝的检查。

### 新增

- `--native-relay` / `run.ps1 -NativeRelay` 可显式选择原生传播，原生根及中间进程只启用创建 hook。
- relay 传播只读核对安全上下文与已观察的默认对象策略，遇到不一致时拒绝，不补授权限；支持链内显式兼容入口、ConPTY 和调用者原有挂起状态。
- PSEC 和两种固定受限令牌各新增自动链路与交互回归，覆盖真实 fork、直接回入、单 hook 原生范围、挂起语义及策略收紧负例。
- 两种固定非 AppContainer 受限令牌的 ConPTY 交互验收：TTY、尺寸、Perl/线程 fork、原生命令、Ctrl+C、STOP/bg/fg、退出码与会话前后权限拒绝；复用既有生产实现和原测试策略。
- 交互测试提供 `Existing` 模式，直接验证调用者已有受限上下文，不创建替代环境或配置文件 ACL；实际策略的拒绝边界另行核验。
- 兼容宿主接受非 AppContainer 受限令牌，复用启动器默认对象 ACL，并用可沿原生进程链继承的每次启动私有命名空间隔离 MSYS 对象。
- 两种固定受限令牌夹具的端到端回归：Bash/Perl、fork、原生桥接回入、管道、文件写入及 WRITE_DAC 拒绝、普通 MSYS 会话共存；记录原版失败基线。
- 原生 PSEC 创建工具、现有 PSEC 内的兼容宿主，以及无 CRT 的 AMD64 agent。
- 在初始线程恢复前按实际普通导入表识别 MSYS，按需安装 hook 处理对象授权、地址布局及连续 MSYS 子进程传播。
- 基于公开 ConPTY API 的交互路径，由原生会话宿主持有自动初始标准句柄。
- fork、二级线程 fork、shell、权限边界、作用范围、运行中新包和分发包完整性回归。
- 独立识别器测试覆盖直接导入、创建前预检和准备失败语义。

### 项目组织

- 项目、仓库和生产产物统一采用 MSYS Sandbox Compat / `msys-sandbox-compat`；同步 CMake 标识、内部 `msys_sandbox_compat` 命名空间与头文件目录、`MSYS_SANDBOX_COMPAT_SESSION` 会话标记、对象名前缀、脚本和文档。
- 明确生产兼容约束：不修改任何磁盘文件/目录 ACL，不放宽原 restricted token 限制；测试夹具授权只定义测试初始条件，不能作为生产补权步骤。
- 统一产物名为 `psec-run.exe`、`msys-sandbox-compat.exe`、`msys-sandbox-compat.dll`，正式构建与本地研究分开。
- 公开文档采用当前设计、使用/测试说明与编号 ADR；演进计划和专题研究保存在本地。
