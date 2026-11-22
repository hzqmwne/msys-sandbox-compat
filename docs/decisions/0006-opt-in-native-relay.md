# ADR-0006：显式原生创建 relay 覆盖 MSYS 自动回入

Status: Accepted
Partially superseded by: ADR-0008 更新默认 DACL 比较基准，[ADR-0013](0013-default-relay-with-wow64.md) 更新默认值并覆盖 WoW64。
Date: 2026-10-20
Partially supersedes: ADR-0001 的所有模式均不注入原生进程的约定；默认行为仍保留。
Related: ADR-0004、ADR-0005

## Context

默认模式在 MSYS 创建边界传播，原生工具不带兼容 hook，其后直接启动的 MSYS 不受祖先 hook 覆盖。显式兼容入口已经能工作，但要求修改中间命令。用户要求评估一个让必要创建 hook 驻留原生中间进程的选项，并明确生产不得修改磁盘 ACL 或放宽原 token 限制。

## Decision

增加 `--native-relay`，只影响本次启动的进程树。仍映射同一无 CRT agent，原生映像只安装 `NtCreateUserProcess` hook；不应用 MSYS 地址、对象 ACL 或默认 DACL 修复。已确认的 MSYS 映像安装完整九个 hook。后代在初始挂起期间分类、准备并继续传播，保留调用者的挂起状态。

传播只读核对原默认对象策略和父子安全上下文，不一致或不可查询时明确拒绝；不改用更大权限 token、不添加 SID 授权、不修改磁盘 ACL。无法分类或准备时拒绝本次创建，避免静默丢失传播。仅覆盖受支持的 AMD64 创建入口，不承诺跨安全上下文或绕过入口的创建方式。

链内显式启动器识别本进程已有的 relay agent，复用原上下文并避免对已由创建 hook 准备的子进程重复注入。ConPTY 原生会话宿主使用同一路径。默认模式仍保持原生进程无注入。

## Consequences

受测 PSEC 和两种非 AppContainer 固定令牌中，原生/MSYS 根、一层/三层普通原生桥接后直接进入 Bash/Perl、fork、线程 fork、管道、退出码和 ConPTY 已通过；原生侧验证只有一个创建 hook，其他八个入口及 MSYS 地址区保持原样。

接受显式模式内原生进程驻留兼容代码和创建检查的成本。安全上下文或默认对象策略变化是支持边界，拒绝时不能恢复父策略凑过验收。原生旁路直接系统调用、既有树外进程、纯原生动态加载 MSYS 不由本决定解决。
