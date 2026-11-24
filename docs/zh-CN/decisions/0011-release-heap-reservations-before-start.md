# ADR-0011 在 MSYS 执行前释放创建时的临时堆预留

Status: Accepted
Supersedes: [ADR-0010](0010-reserve-cygheap-at-creation.md)
Date: 2026-11-18

## Context

此前把 cygheap 的原址预留保留到进程启动，再由运行时提交页面。userheap 初始化需要自己的 reserve 成功，因此仍依赖分配 hook 调整起点。

## Decision

已识别的 AMD64 MSYS 映像在创建时暂留 `[0x200000000, 0x1000000000)`，即 `[8,64)` GiB。最初的 `[24,64)` GiB 覆盖运行时线程栈池、cygheap 和直到 mmap 池下界的 userheap 起始区。2026-11-25 扩大后的窗口还覆盖在受测 MSYS2 和 Git for Windows 安装中观察到的低位 DLL 首选地址。父进程完成挂起准备后，核对自己追加的预留并以 `MEM_RELEASE` 释放，在初始线程恢复或交还调用者前交回整个区间。调用者自己的预留继续由调用者管理。 [fork 压测和地址采样](../testing.md#psec-fork-压测与地址采样)

两个堆的 reserve 和 commit 均交给原版 MSYS。删除 `NtAllocateVirtualMemory` hook 及记录运行时映射完成的状态。仅在创建后识别到 MSYS 时继续准备映像和对象，兼容层无需再预留地址。

## Consequences

窗口只占用虚拟地址空间。在受测 Windows 上，初始映像先于预留建立，映像与窗口相交可导致进程创建失败。PEB 和初始线程在预留之后分配。预留释放后，加载器和新建线程仍可能占用 MSYS 需要的地址。

DLL 映像同址是 fork 的独立要求。在相同 PSEC 和 ASLR 条件下，关闭映像映射处理会破坏 Bash 和 Perl fork。继续保留只修改已识别 `SEC_IMAGE` 基址的映射 hook。
