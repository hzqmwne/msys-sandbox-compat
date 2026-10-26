# ADR-0008：基于当次输入适配对象 ACL 与默认对象策略

Status: Accepted
Date: 2026-10-26
Supersedes: ADR-0004 的整份默认 DACL 恢复策略，以及显式对象 SD/已识别进程线程的模板替换。识别、命名空间、地址准备与默认原生边界保持原设计。

## Context

兼容层以合理适配受限环境的运行时源码行为为参照，完成正常工作负载。默认值、hook 数量、进程数量和残余影响均属取舍，不以零副作用作为候选条件，由维护者最终决策。原实现整份替换 SD 或恢复默认 ACL 快照，可能覆盖调用者本次权限意图；原型已证明可保留输入再补受限主体。

## Decision

### 授权转换

保留 ntdll hook，不限定调用来自 MSYS 模块、IAT 或内部 RVA。沿用现有对象路径选择；已识别进程/线程读取实际 DACL 后适配。共享 core 转换器可复用于同类程序，但不自动扩大当前识别/注入范围。

保留普通 allow ACL 的原 ACE 顺序、内容与掩码，合并当次对当前用户及其 enabled、非 deny-only 组的授权，仅给受限主体追加尚未具有的位。AppContainer 使用 package SID；非 AppContainer 优先使用同时属于 enabled/restricting 列表的 logon SID，否则要求初始 ACL 中唯一可确定的非宽泛 restricting 主体。不批量授权全部 restricting SID。

当前只解释 ACL_REVISION、无 flags 的 ACCESS_ALLOWED_ACE。deny、继承、object/callback/conditional 等其他 ACE 原样交给系统，不猜测一般有效权限。空 DACL 保持为空。ACL/SID 有界验证，先复制输入，不修改调用者缓冲。无效/不支持输入由原 Native API 验证；适配存储失败直接失败，不恢复旧模板。

显式 NULL DACL 表达允许所有人，但受测 PSEC 的共享 section 在此形式下不能被后代重开。因此用 Everyone:GA 与受限主体:GA 表达其开放意图，不缩减为 user/SYSTEM 模板。TokenDefaultDacl 的 NULL 输入使用同一规则。未提供 SD 或没有 DACL 的创建调用仍使用系统默认/继承规则。

支持 absolute/self-relative SD，保留 owner/group/SACL/control 语义，输出临时 absolute SD。已有进程/线程只设置 DACL_SECURITY_INFORMATION。

### 默认策略与传播

仅适配当前主 token 的 TokenDefaultDacl，其他 token/信息类原样。NtCompareObjects 判断身份，不要求输入句柄额外具有 TOKEN_QUERY；原 NtSetInformationToken 仍检查真实设置权限。

设置成功后查询实际默认 ACL，更新 agent 传播比较基准；设置与创建/克隆在进程内串行化，新子进程恢复前重置局部锁。原生 relay 只有创建 hook，未被观察的默认策略变化仍在创建前拒绝。父子上下文比较项不减少。

基准最多容纳 8 KiB ACL。成功设置更大策略或查询失败时，保留设置调用的真实成功结果，将基准标记不可用并拒绝后续 relay 传播。锁只协调经过兼容入口的调用，不是抵抗直接 syscall/主动绕过的安全边界。

### 早期依赖

保留 ntdll 通用接入，hook 库另行评估，最终仍只交付兼容 EXE/DLL。agent 在 loader 前执行，无 CRT、普通导入、TLS、全局构造、DllMain 或额外运行时 DLL 依赖。宿主静态链接 CRT；agent 使用已解析 Native API 与有界存储。允许适量实现复杂度换取确定的早期条件，不能仅凭静态链接认为第三方库满足这些要求。

## Consequences

不再整份恢复启动 ACL，也不再用统一 SD 覆盖显式输入。deny/不支持形式可能继续失败，不会被旧模板改成成功。默认适配仍可能影响后续采用默认 SD 的其他对象，作为接受的兜底取舍记录。生产不修改磁盘/目录或注册表 ACL，不改变 token 身份、权限、restricting SID 或外部资源策略。

验证包含 SD 字段保留、空/NULL、有限权限、enabled/deny-only 组、其他 token、adjust-only/query-only 句柄、真实 MSYS 后续设置，以及默认/relay 的三种隔离模型。进程链比较 MSYS 设置后的后代策略，不再要求与首次 native 入口启动快照逐字节相同。
