# ADR-0005：受限令牌使用启动器对象 ACL 与每次启动的 MSYS 命名空间

Status: Accepted
Partially superseded by: ADR-0008；对象 ACL 改为基于当次输入适配，命名空间和受限令牌路径继续保留。
Date: 2026-10-20
Extends: ADR-0001、ADR-0003、ADR-0004；增加非 AppContainer 受限令牌路径，保留 PSEC 处理和严格原生边界。

## Context

目标包括非 AppContainer 的受限执行环境。原有宿主要求 package SID，不能进入这一路径。固定 write-restricted 和完整 restricting SID 检查令牌中的原版 Bash 均在信号管道初始化时拒绝；仅让宿主查询成功不足以完成 fork 和原生桥接后的重新启动。

受限令牌没有 AppContainer 专有对象目录。直接复用普通 MSYS 命名空间会受先前对象及其 ACL 影响。完整 restricting SID 检查还约束文件读取，不能用修改原安装目录 ACL 的方式掩盖启动器缺少文件授权。

## Decision

兼容宿主接受已有 AppContainer SID 或实际受限令牌。非 AppContainer 路径沿用启动器默认对象 DACL 创建 MSYS 对象描述符，不给所有 restricting SID 增加通用授权。ADR-0004 的默认 DACL 保留同样适用。

在当前 Windows 会话的 BaseNamedObjects 下按创建者宿主 PID 命名私有目录，由宿主保持句柄直至进程树退出。agent 在兼容树内传递目录路径。关闭 native relay 时，经过原生中间程序后的显式兼容入口建立新树和新目录。PSEC 继续使用 Windows 提供的 AppContainer 命名空间。

隔离启动器负责 token、文件和对象策略；生产兼容层不创建替代 token 或补授文件访问。固定测试夹具在标记工作目录内准备只读兼容产物及权限 canary，原版 MSYS 仍从原安装位置加载。

## Consequences

两种受测令牌下的 Bash/Perl、fork、线程中 fork、多层未注入原生桥接、管道、默认 ACL 保留、退出码和受控文件边界可作为成功验收。普通 MSYS 会话与受限工作负载同时保持运行。

这证明固定令牌配置下的运行时兼容，不等于任意外部 harness 或完整沙箱策略已经验收。启动器仍需提供所需文件读取与执行权限；受限令牌 ConPTY 和外部产品集成没有纳入本次结果。
