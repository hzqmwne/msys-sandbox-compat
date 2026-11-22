# ADR-0013：默认启用原生创建 relay，覆盖混合位数启动链

Status: Accepted

Date: 2026-11-23

Partially supersedes: [ADR-0006](0006-opt-in-native-relay.md) 的默认值和位数范围。

## 背景

原生首进程或中间进程可能是 AMD64，也可能是 WoW64。默认自动传播需要覆盖两种位数交替的启动链，并保留调用者请求的挂起状态。

## 决定

默认启用原生 relay。用 `--no-native-relay` 关闭，或关闭整个 `propagation` 模块。ConPTY 内层宿主沿用外层选项。链内显式调用 compat 时复用继承的 relay。

WoW64 的 AMD64 转换层调用原生进程创建入口，沿用同一份 AMD64 agent。原生进程只启用创建 hook。MSYS 运行时适配仍适用于 AMD64 MSYS 映像。

对于涉及 WoW64 的父子令牌比较，只接受经 `TokenVirtualizationEnabled` 确认的 UAC 虚拟化启用位差异。其他访问标志、令牌字段及受限环境的默认 DACL 仍参与比较。

## 验证

普通令牌与原生 PSEC 1.0 下，WoW64 首进程、AMD64 经 WoW64 回入、WoW64 与 AMD64 交替三种链路均通过 Bash fork 和退出码检查。两种位数的调用者均保留请求的初始挂起状态。
