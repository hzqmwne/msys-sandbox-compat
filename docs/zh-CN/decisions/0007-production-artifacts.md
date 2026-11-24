# ADR-0007：生产兼容层与隔离验证工具分开交付

Status: Accepted
Date: 2026-10-20
Related: ADR-0001、ADR-0005、ADR-0006

## Context

生产接入由外部启动器提供既有受限环境。psec-run 只负责从普通宿主构造 PSEC，原先与兼容层一起安装，容易让部署依赖与验证工具混淆。宿主和 agent 共享的底层实现也曾全部位于 agent 源码目录。

## Decision

默认构建输出开发宿主 `msys-sandbox-compat.exe`、同目录的 `msys-sandbox-compat-agent.dll`，以及单文件 `msys-sandbox-compat-shim.exe`。shim 将校验后的 agent 作为 PE 资源嵌入。发布 ZIP 交付 shim 与许可声明。显式开启开发工具或测试时独立构建 `psec-run.exe`，测试夹具有独立源码与输出目录。从 v0.1.0 起，发布构建显式启用工具，将 `psec-run.exe` 作为独立程序交付。

core 保存共享识别、进程准备与 token 检查，分别按宿主和无 CRT agent 的约束编译，不新增运行库或公共 SDK。生产仍在原策略允许的位置与权限内运行。

## Consequences

已有隔离启动器只需部署 shim EXE。仓库演示入口需先构建工具，集成回归需开启测试。嵌入资源随 DLL 校验构建更新，单文件测试从独立目录启动改名后的 shim。
