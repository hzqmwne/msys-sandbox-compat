# 兼容范围

当前项目为 0.1 开发版本。已验证组合为 Windows 26300.9711 x64、原生 PSEC 1.0、MSYS 3.6.10，目标包含真实内部 Bash、Perl 和 GNU 工具。

| 能力 | 当前范围 |
|---|---|
| 原版 EXE 与 `msys-2.0.dll` | 使用原安装文件，不修改分发包 |
| fork、exec、管道、信号及线程中 fork | 受测组合通过回归与压力测试 |
| MSYS 连续子进程链 | 通过创建 hook 传播 |
| 进程链中的原生子进程 | 不注入，不安装兼容补丁 |
| 原生根显式调用兼容入口 | 已由公开作用范围测试验证 |
| MSYS 原生后代调用兼容入口启动原生目标 | 已验证；原生目标无兼容补丁，继承的 token 默认 DACL 不变 |
| MSYS 创建原生中间程序后显式回入 MSYS | 一层/三层原生桥接后 Bash、Perl、线程中 fork、管道与退出码通过回归 |
| 原生中间程序直接创建 MSYS | 默认模式无自动传播，需显式兼容入口 |
| 运行中新出现的 EXE/DLL | 按首次创建或映射时的实际依赖识别 |
| ConPTY | 公开 API 路径在 PSEC 和两种固定非 AppContainer 受限令牌中通过交互回归 |
| 非 AppContainer write-restricted 令牌 | 固定夹具通过 Bash/Perl、fork、原生桥接、管道、文件边界及普通 MSYS 共存回归 |
| 非 AppContainer 完整 restricting SID 检查令牌 | 同一固定夹具通过上述工作负载与边界回归 |
| 任意外部 restricted token harness | 尚未集成验收；实际令牌、ACL、完整性等级、创建参数及控制台条件需要分别验证 |
| 只复制旁置文件即可自动生效 | 尚未提供可靠通用加载入口 |

识别覆盖普通导入及常规应用目录、模块目录和运行时目录的传递依赖。纯原生根在启动后才 LoadLibrary MSYS、仅 delay import，以及任意 SxS 或自定义 DLL 搜索规则不在当前预先识别保证内。

两种受限令牌夹具均使用 `DISABLE_MAX_PRIVILEGE | LUA_TOKEN`、禁用 Administrators，并将当前 logon SID、Everyone、Builtin Users、Authenticated Users 放入 restricting SID 列表；write 模式另加 `WRITE_RESTRICTED`。启动器为对象保留 logon/SYSTEM 授权和 OWNER RIGHTS 限制。测试只在带标记的独立工作目录配置 ACL，将兼容产物和夹具暂存为只读；Git/MSYS 仍从原安装位置加载。完整检查模式的读取也必须通过 restricting SID 检查，生产所需文件读取与执行必须在原策略允许范围内。

上述文件授权是合成夹具的初始策略，不是生产兼容层执行的补权。生产不修改任何磁盘文件或目录 ACL，也不放宽既有 restricted token 的限制；只有原策略已允许的文件位置与访问才可使用。若真实 harness 原策略拒绝某个必要文件，本轮夹具结果不证明该环境已兼容，不能通过额外授权或非受限代理代读取得成功。

`restricted-run.exe` 是测试夹具，不随产品安装，也不是通用沙箱工具。回归验证明确配置的只读文件、拒绝文件、可写目录与对象策略，没有认证任意路径、网络或外部产品的隔离策略。两种令牌的 ConPTY 均复用既有实现及初始策略，已验证终端内 Perl/线程 fork、TTY、尺寸、原生命令、Ctrl+C、作业控制和退出码；交互前后的权限 probe 均要求原有拒绝保持有效。

兼容实现依赖 AMD64 ntdll 系统调用入口、Native API 和 MSYS 内部地址布局。入口或目标布局变化时需要重新验证，不承诺所有 Windows/MSYS 版本自动适用。

测试策略保留安装目录只读和 canary 拒绝边界。项目不创建普通非隔离回退路径，也不通过改写安装目录 ACL 来解决 IPC 授权问题。识别范围与沙箱策略是不同职责；命中 MSYS 不会自动取得额外文件写权限。
