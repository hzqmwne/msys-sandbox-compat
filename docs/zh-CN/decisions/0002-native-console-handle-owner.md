# ADR-0002：PSEC 内公开 ConPTY 与原生标准句柄所有者

[English](../../decisions/0002-native-console-handle-owner.md)

Status: Accepted
Date: 2026-10-20
Related: ADR-0001、[ADR-0014](0014-conpty-preserve-redirected-stdio.md)
Partially superseded by: [ADR-0013](0013-default-relay-with-wow64.md) 在原生会话宿主默认启用 relay。

## Context

受测环境中，重定向宿主的标准句柄可能影响 ConPTY 的初始句柄来源；首次 PSEC 创建同时指定外部 ConPTY 还出现控制台引用不一致。外部普通 conhost 即使具备可读写句柄，也不能完成 MSYS 所需的输入事件写回。

Windows 自动生成的初始控制台标准句柄还被控制台清理状态持有。MSYS 关闭并复用句柄值后，退出清理可能再次关闭该值；只验证交互输出不能发现这一问题。

## Decision

正式路径在 PSEC 内调用公开 ConPTY API，由兼容宿主 EXE 的另一个原生实例连接控制台并持有自动初始标准句柄。真实 MSYS 目标通过明确的启动参数和继承句柄获得副本。

agent 不重开 `CONIN$`/`CONOUT$`，不安装额外控制台 hook。原生会话宿主和 conhost 不注入。完全外部创建、复制受限主令牌与修正 reference 的私有接口路线留在本地实验。

## Consequences

标准句柄所有权清楚，MSYS 可关闭自身副本而不与初始句柄清理冲突；正式路径使用公开 API，增加一个原生宿主实例而不增加产品文件。控制台、管道、fork、作业控制和退出码需一起回归；当前不提供完整终端 GUI、VT 渲染器或动态 resize 事件循环。
