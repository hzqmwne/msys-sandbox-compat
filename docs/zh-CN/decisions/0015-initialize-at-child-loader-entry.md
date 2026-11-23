# ADR-0015：在子进程加载器入口初始化兼容层

[English](../../decisions/0015-initialize-at-child-loader-entry.md)

Status: Accepted

Date: 2026-11-23

Partially supersedes: [ADR-0001](0001-suspended-msys-preparation.md) 的初始化时机与父子职责分配。

## 背景

创建调用者可能要求子进程保持初始挂起，并在恢复前检查或更新应用启动上下文。MSYS 又要求在加载器利用其映像和运行时前完成布局适配及 hook 安装。

## 决定

父进程在初始挂起阶段完成创建对象所需的适配，映射 agent 和同一构建内共享的 `ParentStartData`，安排子进程首次进入 `LdrInitializeThunk` 时运行初始化。该结构携带父进程实际 EXE 基址和原生路径，由子进程按需使用。父进程在恢复线程或交回挂起进程前释放自己的创建期地址预留。 [堆窗口释放决策](0011-release-heap-reservations-before-start.md)

子进程先恢复加载器入口，再按实际映像和令牌选择兼容模块，完成所需 EXE 布局处理及正式 hook 安装，随后交还加载器。应用启动上下文与加载器接入口分别处理。早期初始化沿用 agent 的无 CRT、普通导入、TLS 和全局构造依赖约束。新 EXE 视图验证成功后才切换应用入口，原视图继续保留。

## 验证与后果

创建者保留原有挂起语义。恢复前的准备错误通过创建调用报告，恢复后的初始化错误通过目标退出状态报告。普通令牌和 PSEC 1.0 均验证了挂起调用者观察到的应用启动上下文。受测 PSEC 下卸载原 EXE 视图会导致 Perl fork 子进程启动失败，因此本次保留原视图。上游 MSYS2 #403 的实际组合仍待联合验证。
