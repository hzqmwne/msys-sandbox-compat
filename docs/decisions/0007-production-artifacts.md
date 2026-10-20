# ADR-0007：生产兼容层与隔离验证工具分开交付

Status: Accepted
Date: 2026-10-20
Related: ADR-0001、ADR-0005、ADR-0006

## Context

生产接入由外部启动器提供既有受限环境。psec-run 只负责从普通宿主构造 PSEC，原先与兼容层一起安装，容易让部署依赖与验证工具混淆。宿主和 agent 共享的底层实现也曾全部位于 agent 源码目录。

## Decision

默认构建和安装只交付 msys-compat.exe、msys-compat.dll 及文档/许可。psec-run 位于 tools，显式开启开发工具或测试时构建，不随生产安装；测试夹具拥有独立源码与输出目录。

core 保存共享识别、进程准备与 token 检查，分别按宿主和无 CRT agent 的约束编译，不新增运行库或公共 SDK。生产仍在原策略允许的位置与权限内运行。

## Consequences

已有隔离启动器只需部署兼容 EXE/DLL。仓库演示入口需先构建工具；集成回归需开启测试。调整构建和安装边界，不改变默认原生范围、relay 安全上下文限制或测试初始权限。
