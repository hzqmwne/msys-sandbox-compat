# 兼容范围

当前项目为 0.1 开发版本。生产部署仅需兼容 EXE/DLL，运行于启动器已经提供的受限上下文；psec-run 仅为可选开发验证工具。已验证组合为 Windows 26300.9974 x64、原生 PSEC 1.0、MSYS 3.6.10，目标包含真实内部 Bash、Perl 和 GNU 工具。

| 能力 | 当前范围 |
|---|---|
| 原版 EXE 与 `msys-2.0.dll` | 使用原安装文件，不修改分发包 |
| fork、exec、管道、信号及线程中 fork | 受测组合通过回归与压力测试 |
| MSYS 连续子进程链 | 通过创建 hook 传播 |
| 进程链中的原生子进程 | 默认不注入；显式 relay 模式仅安装创建 hook |
| 原生根显式调用兼容入口 | 已由公开作用范围测试验证 |
| MSYS 原生后代调用兼容入口启动原生目标 | 已验证；原生目标无兼容补丁，继承的 token 默认 DACL 不变 |
| MSYS 创建原生中间程序后显式回入 MSYS | 一层/三层原生桥接后 Bash、Perl、线程中 fork、管道与退出码通过回归 |
| 原生中间程序直接创建 MSYS | `--native-relay` 下，一层/三层原生桥接后直接进入 Bash/Perl 已通过；默认模式仍需显式入口 |
| relay 的原生根、显式嵌套入口及挂起创建 | 受测 PSEC 和两种固定令牌均通过；仅创建入口被修改，保留退出码与挂起状态 |
| 运行中新出现的 EXE/DLL | 按首次创建或映射时的实际依赖识别 |
| ConPTY | 公开 API 路径在 PSEC 和两种固定非 AppContainer 受限令牌中通过交互回归。尺寸跟随通过 PSEC 内外两层 ConPTY 的原生探针验收 |
| Git `pre-commit` | 在已初始化的工作区，原生 Git 通过 `--native-relay` 自动启动 MSYS hook。PSEC 和两种固定受限令牌通过提交成功、hook 拒绝提交及文件边界回归 |
| 非 AppContainer write-restricted 令牌 | 固定夹具通过 Bash/Perl、fork、原生桥接、管道、文件边界及普通 MSYS 共存回归 |
| 非 AppContainer 完整 restricting SID 检查令牌 | 同一固定夹具通过上述工作负载与边界回归 |
| 验收依据 | 参照相关配置构造的 PSEC 与两种受限令牌模型；按有效安全策略与进程创建条件判断适用性 |
| 只复制旁置文件即可自动生效 | 尚未提供可靠通用加载入口 |

验证按底层隔离机制与配置组织；在相关安全策略、进程创建与控制台条件一致时，现有模型可代表上层启动环境。当前验收不要求先接入上层 harness，也不按产品名称分别建立兼容实现。

识别覆盖普通导入，以及应用目录、模块目录和 `--runtime` 所给目录中的传递依赖。`--runtime` 可省略。纯原生根在启动后才 LoadLibrary MSYS、仅 delay import，以及任意 SxS 或自定义 DLL 搜索规则不在当前预先识别保证内。

relay 覆盖经受支持的 AMD64 `NtCreateUserProcess` 入口创建的后代，不接管已有进程、树外进程、绕过该入口的直接系统调用或纯原生进程运行后才动态加载 MSYS 的场景。它要求父子安全上下文与最近已观察的默认对象策略一致。完整 agent 内的默认 DACL 设置成功后会更新基准；未观察的策略改变在创建前拒绝。子进程切换凭据、限制、完整性或 package，默认 DACL 与基准不符，或必要查询失败时，已创建目标在恢复前回收。原生中间进程会驻留 agent 代码，但仅一个创建入口被修改；关闭该模式的默认行为保持不变。

两种受限令牌夹具均使用 `DISABLE_MAX_PRIVILEGE | LUA_TOKEN`、禁用 Administrators，并将当前 logon SID、Everyone、Builtin Users、Authenticated Users 放入 restricting SID 列表；write 模式另加 `WRITE_RESTRICTED`。启动器为对象保留 logon/SYSTEM 授权和 OWNER RIGHTS 限制。测试只在带标记的独立工作目录配置 ACL，将兼容产物和夹具暂存为只读；Git/MSYS 仍从原安装位置加载。完整检查模式的读取也必须通过 restricting SID 检查，生产所需文件读取与执行必须在原策略允许范围内。

上述文件授权是合成夹具的初始策略，不是生产兼容层执行的补权。生产不修改任何磁盘文件或目录 ACL，也不放宽既有 restricted token 的限制；只有原策略已允许的文件位置与访问才可使用。若真实 harness 原策略拒绝某个必要文件，本轮夹具结果不证明该环境已兼容，不能通过额外授权或非受限代理代读取得成功。

`restricted-run.exe` 是测试夹具，不随产品安装，也不是通用沙箱工具。回归验证明确配置的只读文件、拒绝文件、可写目录与对象策略，没有认证任意路径、网络或外部产品的隔离策略。两种令牌的 ConPTY 均复用既有实现及初始策略，已验证终端内 Perl/线程 fork、TTY、尺寸、原生命令、Ctrl+C、作业控制和退出码；交互前后的权限 probe 均要求原有拒绝保持有效。

兼容实现依赖 AMD64 ntdll 系统调用入口、Native API 和 MSYS 内部地址布局。入口或目标布局变化时需要重新验证，不承诺所有 Windows/MSYS 版本自动适用。

创建时暂留堆窗口、恢复执行前释放的路径已在 Windows 11 `26300.9974` x64 与 Git for Windows 的 MSYS 3.6.10 验证。`PS_ATTRIBUTE_MEMORY_RESERVE` 属于 Windows Native 进程创建接口。旧 Windows 上能否通过宿主使用的导入槽和实际运行时布局完成同一创建路径，需要独立验证。

测试策略保留安装目录只读和 canary 拒绝边界。项目不创建普通非隔离回退路径，也不通过改写安装目录 ACL 来解决 IPC 授权问题。识别范围与沙箱策略是不同职责；命中 MSYS 不会自动取得额外文件写权限。
