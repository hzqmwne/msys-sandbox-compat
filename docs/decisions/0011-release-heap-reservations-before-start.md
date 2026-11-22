# ADR-0011 在 MSYS 执行前释放创建时的临时堆预留

Status: Accepted
Supersedes: [ADR-0010](0010-reserve-cygheap-at-creation.md)
Date: 2026-11-18

## Context

此前把 cygheap 的原址预留保留到进程启动，再由运行时提交页面。userheap 初始化需要自己的 reserve 成功，因此仍依赖分配 hook 调整起点。

## Decision

已识别的 AMD64 MSYS 映像在创建时暂留 `[0x600000000, 0x1000000000)`。窗口覆盖 24–32 GiB 的运行时线程栈地址池、32–40 GiB 的 cygheap 和从 40 GiB 到 mmap 地址池下界 64 GiB 的 userheap 起始区间。父进程完成挂起准备后，核对自己追加的 reservation 并以 `MEM_RELEASE` 释放，在初始线程恢复或交还调用者前交回整个区间。调用者自己的预留继续由调用者管理。

两个堆的 reserve 和 commit 均交给原版 MSYS。删除 `NtAllocateVirtualMemory` hook 及记录运行时映射完成的状态。仅在创建后识别到 MSYS 时继续准备映像和对象，兼容层无需再预留地址。

## Consequences

窗口只占用虚拟地址空间。映像早期映射造成的冲突仍会反映为创建失败。预留释放后，用户态加载器或其他线程若先占用地址，MSYS 仍受自身的固定地址条件约束。

DLL 映像同址是 fork 的独立要求。在相同 PSEC 和 ASLR 条件下，关闭映像映射处理会破坏 Bash 和 Perl fork。继续保留只修改已识别 `SEC_IMAGE` 基址的映射 hook。
