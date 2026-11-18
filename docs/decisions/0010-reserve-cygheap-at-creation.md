# ADR-0010 在 Windows 创建进程时预留 MSYS cygheap 原址

Status: Accepted
Date: 2026-11-18
Related: [ADR-0001](0001-suspended-msys-preparation.md)

## Context

MSYS x64 的 fork 和 exec 在子进程里重建父进程的 cygheap，运行时计算提交长度时使用编译期基址。此前移动整个 cygheap，再用分配 hook 改写基址和长度，子进程必须始终遵循两套地址之间的换算。

## Decision

为已识别的 MSYS 进程追加 Native 创建属性 `PS_ATTRIBUTE_MEMORY_RESERVE`，覆盖 `[0x800000000, 0xA00000000)`。原版 MSYS 再次请求 reserve 时会遇到已预留区间，随后照常在原址执行 commit。兼容层只核对预留状态，提交的地址、长度与页面权限由运行时决定。

按创建请求中的映像路径做有界导入预检，随后复核挂起进程的实际映像。保留调用者的创建属性和已有预留。独立宿主通过本进程 KernelBase 的 `NtCreateUserProcess` 导入槽接入本次创建，子进程和继承 relay 的宿主复用 agent 的创建入口。预检不可用且实际映像确认为 MSYS 时，尝试在恢复线程前预留同一原址。

## Consequences

原址预留晚于内核映射 EXE 和系统 DLL，早于 PEB 和初始线程栈。地址若已被更早的映射占用，回报创建或准备失败。预留是虚拟地址空间，区间在运行时提交或释放之前仍为其保留。PSEC token、ASLR 标志及常规 Win32 进程创建语义沿用原调用。

cygheap 范围来自支持的 AMD64 MSYS 运行时布局，无公开布局查询 ABI。PE 映像首选基址仍来自 PE。userheap 首次使用要求自己取得 reservation，继续沿用原有起点调整。共享映射、线程栈和 mmap 池由各自的分配机制管理。
