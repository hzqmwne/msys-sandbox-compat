# 变更记录

[English](CHANGELOG.md)

项目处于 0.1 开发阶段，尚未正式发布。[兼容矩阵](docs/zh-CN/compatibility.md)记录了实际验收的环境。以下包含当前行为，也保留较早的开发记录。

## 未发布

### 兼容模块

- 默认启用 native relay，支持 WoW64 原生首进程和 AMD64/WoW64 混合启动链。用 `--native-relay=off` 关闭。
- 分离进程传播、堆窗口、EXE 和 DLL 定址、MSYS IPC 及两类 DACL 适配。`--disable-modules=NAME[,NAME...]` 同时跳过对应的预检、元数据读取和 hook 安装。`--log-level=trace` 报告启用的模块。 [模块参考](docs/zh-CN/getting-started.md#兼容模块对照)

### 构建与命令行

- 交付内嵌 agent DLL 的 `msys-sandbox-compat-shim.exe`。开发构建也保留独立的 EXE 和 DLL。
- shim 用 `--` 分隔原生命令，支持透明标准流和独立诊断文件。日志默认关闭。
- shim 和 `psec-run.exe` 支持 `-h` 与 `--help`。shim 另支持 `--version`。
- 独立 `psec-run.exe` 支持原生 PSEC 1.0 和 1.1，以及 MXC 形状的文件、枚举和直接网络策略字段。
- 构建、演示和测试脚本支持 Windows PowerShell 5.1 和 PowerShell 7。CTest 优先选 PowerShell 7。
- `run.ps1` 写入无 BOM 的 UTF-8 策略文件，并在旧版 PowerShell 调用原生程序时保留引号和空参数。

### MSYS 内存布局

- 创建已识别的 MSYS 进程时暂留堆窗口，恢复线程前释放。原版 MSYS 自行预留并提交 cygheap 和 userheap。移除 `NtAllocateVirtualMemory` hook。
- 冷启动和 exec 时，对符合条件且未设置 `DYNAMIC_BASE` 的 MSYS EXE 尝试一次 PE 首选基址，失败时保留原基址。fork 继续按父进程实载地址对齐。
- 从 EXE 自身的导入表识别对 `msys-2.0.dll` 的直接导入。从现有 section 查询 DLL 标志、大小和首选地址。调用者未指定基址且完整区间满足 `ZeroBits` 时，符合条件且未设置 `DYNAMIC_BASE` 的 AMD64 DLL 可尝试首选地址。失败时重试原请求。 [ADR-0012](docs/zh-CN/decisions/0012-prefer-dll-image-base-at-map.md)

### 终端转发

- 自动 ConPTY 逐路保留文件、管道和 `NUL` 重定向。有可用外层控制台且至少一路接着控制台时启用桥，兼容 Low IL 目标的读屏和输入事件写入。 [ADR-0014](docs/zh-CN/decisions/0014-conpty-preserve-redirected-stdio.md)
- 设置相应的 UTF-8 代码页和 VT 模式，在输出排空后恢复，包括启动失败时。
- 内层 ConPTY 在可用时继承外层光标并保留启动前的画面。
- 等待中的 shim 和 PSEC 演示宿主处理自身的 Ctrl+C 通知，前台应用保留自己的中断行为。
- MSYS 在启动时设置自身进程 DACL，复用 ACL 转换规则，使受测运行时能检查控制台所有者是否仍存活。
- 为默认交互式 Bash 演示初始化 GNU 工具路径、TERM 和 UTF-8 locale。
- 为交互式 PowerShell 演示提供可写的 PSReadLine 历史文件，并检查命令持久化。
- ConPTY 双向转发在短写后继续写入，失败或零进展时结束该方向。
- 按外层窗口启动并跟随尺寸变化。`--conpty-size` 选择固定尺寸。
- 两种尺寸参数写法共用十进制解析，Release shim 移除了通用扫描器依赖。
- 收尾时立即唤醒尺寸线程，缩短最后一批输出后的等待。
- 回归覆盖 UTF-8 往返、混合继承重定向和下游提前关闭。

### Git 工作流

- 在 PSEC 和两种固定受限令牌下，验证原生 Git 经 relay 调用 MSYS `pre-commit`，覆盖接受和拒绝提交。

### 初始化与失败处理

- 删除父子 token 全量比较和根进程 token 预检。各进程自行确定 ACL 主体，进程树保留其 IPC 目录名。 [ADR-0018](docs/zh-CN/decisions/0018-resolve-acl-context-in-each-process.md)
- 移除 relay 的默认 DACL 基准、读回和创建锁。默认 DACL 由 Windows 继承。独立冷启动传入空的父映像数据。 [ADR-0016](docs/zh-CN/decisions/0016-drop-relay-default-dacl-baseline.md)
- 移除生产入口内置的 Git 安装路径。旧 `--runtime DLL` 参数仍可解析，参数值被忽略。
- 移除 `MSYS_SANDBOX_COMPAT_SESSION`。非 AppContainer 进程树使用按宿主 PID 命名的兼容目录，由 agent 把路径传给受支持的后代。
- 在子进程首次进入加载器时初始化兼容层，保留应用启动上下文和调用者的挂起请求。 [ADR-0015](docs/zh-CN/decisions/0015-initialize-at-child-loader-entry.md)
- 准备失败时终止新建的挂起进程，移除无引用的计划字段和跨入口回滚。ACL 调整使用已预留容量的输入副本。
- 分开测试创建返回的句柄与按 PID 重新打开时的 ACL 拒绝，并保留恢复初始策略后的成功对照。
- 原生 PSEC 验证真实负载和文件访问边界。非 AppContainer 的进程链仍记录原版 Bash 基线。

### ntdll 入口搬迁

- 使用 MinHook HDE64 和适配后的搬迁核心，去掉固定八字节 syscall 前导假设。保留已有入口跳转。
- 将搬迁计划和远程安装分开，由 CMake 选择后端。后端无需额外运行时 DLL。
- 检查位移及输入边界、复核源字节并测试实际执行。原生 relay 仍只修改一个入口。安装包含 MinHook 和 HDE 许可声明。

### 对象访问

- 在创建时适配调用者提供的进程和初始线程 DACL。同类原生请求适用，无需识别目标映像，也无需创建后读回再写入。 [ADR-0017](docs/zh-CN/decisions/0017-adapt-process-dacl-at-creation.md)
- 显式对象 ACL 和 `TokenDefaultDacl` 均基于本次请求适配。保留 owner、group、SACL 和 control 字段，只追加原用户和 enabled groups 已有的权限位。deny、空和复杂输入交给 Windows。显式 NULL DACL 用 Everyone 和受限主体表达。
- 接受仅含 `TOKEN_ADJUST_DEFAULT` 的设置句柄。其他 token 和仅查询句柄遵循 Windows 的检查。
- 记录通用 ntdll 入口和早期 agent 的 CRT、导入、TLS 约束。增加安全描述符单测和真实 MSYS 回归。

### 较早的开发记录

- 分离生产 EXE/DLL 和可选 PSEC 工具。安装暂存迁到 `build/package`，工具和测试分别由 `-Tools` 和 `-Tests` 开启。当前的生产产物为上文所述的单文件 shim。
- 分开宿主和 agent 的共享代码、内部头文件、夹具和输出。共用 Windows 参数引用实现。
- 批量初始化跳板并设置页面保护。嵌套 relay 复用已有状态。
- 脚本和实时 ConPTY 输入共用句柄循环。将压力重复次数和常规用例分开，权限检查随相关负载运行。
- 恢复 MSYS 重设默认 DACL 后经过原生工具的显式回入。端到端回归覆盖一层和三层原生工具、二级线程 fork、初始 ACL 保留、文件拒绝及退出码。
- 宿主使用只读 token 伪句柄直接查询命名空间。范围回归验证关闭 relay 的原生目标和默认 ACL 继承。
- 原生 relay 最初作为显式选项，后改为默认开启。覆盖嵌套入口、ConPTY、调用者指定的挂起状态和三种受限环境。
- 两种固定非 AppContainer 令牌加入交互回归，覆盖 TTY、尺寸、Perl fork、原生命令、Ctrl+C、作业控制、退出码和权限拒绝。增加调用者已有环境的 Existing 模式。
- 非 AppContainer 进程树采用每次启动的私有命名空间。对照验证 Bash、Perl、原生回入、管道、并存、文件写入和 WRITE_DAC 拒绝，并记录原版基线。
- 增加原生 PSEC 工具、挂起 MSYS 里的 AMD64 agent 准备和由独立宿主持有初始句柄的 ConPTY。加入 fork、作用范围、晚装映像和安装完整性检查。
- 统一项目、仓库、产物、命名空间、头文件及对象前缀；维护设计、使用和测试文档及编号 ADR。生产沿用既有 token 和磁盘 ACL 策略。
