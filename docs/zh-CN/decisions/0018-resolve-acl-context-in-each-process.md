# ADR-0018 各进程按自身主 token 初始化 ACL 适配

[English](../../decisions/0018-resolve-acl-context-in-each-process.md)

Status: Accepted
Date: 2026-11-23
Partially supersedes: [ADR-0003](0003-read-only-security-context.md) 的根进程 token 预检，以及 [ADR-0006](0006-opt-in-native-relay.md)、[ADR-0013](0013-default-relay-with-wow64.md) 和 [ADR-0016](0016-drop-relay-default-dacl-baseline.md) 的父子 token 核对。

## 背景

原实现把普通/受限标记、用户 SID 和兼容 SID 随 agent 一起转发。创建端为此打开挂起子进程的 token，比较父子各 15 类信息。默认 DACL 基准已在 ADR-0016 移除，ACL 主体仍由根启动器选择。

## 决定

删除父子 token 比较、WoW64 比较特例及根进程的 `TOKEN_QUERY` 预检。Windows 决定新进程的 token、默认 DACL 和访问权限。agent 使用自身主 token 的只读伪句柄确定 ACL 主体，沿用原先针对 AppContainer 和非 AppContainer 限制 SID 的选择规则。相关 MSYS 映像在启用 ACL 模块时完成初始化。原生 relay 在实际处理显式 DACL 时才初始化。结果存于当前进程，克隆后只保留启动数据，新的进程本地状态从空值开始。设置 `TokenDefaultDacl` 时对传入句柄与本进程主 token 的对象身份检查仍作用于该次设置。

启用 IPC 时，独立启动器仍负责准备启动树的目录，注入数据只携带其名称和长度。目录的访问由 Windows 依其实际 ACL 判定。启动数据没有目录名时，命名对象沿用系统路径，符合条件的管道仍可适配 DACL。

## 验证

定向回归覆盖普通及 WoW64 启动、PSEC、WriteRestricted 和 FullRestricted 进程链、PSEC ConPTY 和 ACL。普通原生 relay 通过 Windows 显式创建 FullRestricted 子进程，子端保留受限 token 并通过文件权限对照。`SYSTEM`-only 默认 DACL 用例验证创建返回的句柄、挂起状态及 Windows 对按 PID 重新打开的拒绝。
