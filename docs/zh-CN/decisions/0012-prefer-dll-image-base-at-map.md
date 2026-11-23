# ADR-0012 在 DLL 映射时按 section 元数据尝试 PE 首选基址

[English](../../decisions/0012-prefer-dll-image-base-at-map.md)

Status: Accepted
Partially supersedes: [ADR-0001](0001-suspended-msys-preparation.md) 的 EXE 传递依赖识别
Related: [ADR-0011](0011-release-heap-reservations-before-start.md)
Date: 2026-11-19

## 背景

MSYS fork 会按运行时登记的模块核对父子实载地址。只处理运行时 DLL 或主 EXE 直接导入的 DLL，会漏掉 Perl 的传递依赖。即使覆盖全部静态 MSYS 依赖，完整负载仍有动态 XS 模块重载失败。静态导入关系与 fork 登记有出入，MSYS 也会核对登记为 `DLL_NATIVE` 的原生 DLL。见 [映像地址对照](../testing.md#映像地址对照)。

EXE 识别决定是否启用完整兼容，DLL 映射决定本次请求能否优先使用 PE 首选基址。到达 `NtMapViewOfSection` 时，Windows 加载器已选中映像，现有 section 可以提供判断所需的元数据。按安装根筛选曾需要为查询路径建立临时视图，也会跳过根外的模块。传递导入探测涉及打开和解析依赖。父进程 DLL 快照可以表达已经换址的父模块，但还需要跨进程传递、匹配实际文件，以及为首次加载和晚装模块单独定义行为。

## 决定

EXE 只按自身普通导入表中是否直接声明 `msys-2.0.dll` 识别。创建前的识别用于暂留堆窗口，初始线程恢复前仍按实际映像决定是否启用完整兼容。

完整兼容进程的 `NtMapViewOfSection` hook 直接查询当前 section 的映像属性、长度和 PE 首选地址。对 `*BaseAddress == 0`、未设置 `DYNAMIC_BASE` 的 AMD64 `SEC_IMAGE` DLL，当整个首选映像区间符合原请求的 `ZeroBits` 时，用首选基址尝试一次。DLL 路径、名称和依赖关系均不参与判定。映射路径无需重开文件、建立临时视图或接收父进程的 DLL 清单。

显式基址、无法安全读取的入参、条件不符及 section 查询失败均使用原请求。首选址尝试失败时，先恢复原基址入参，再将原请求交给 Windows 选址一次。`ZeroBits` 和其他映射参数沿用原值。

## 后果

完整兼容进程中符合条件的原生 DLL 和 MSYS DLL 都能尝试首选址。首选地址受占用时仍允许加载器自动选址；后续 fork 能否成功仍取决于父子实载地址。使用 `DYNAMIC_BASE` 的运行时版本需要单独验收。此决定覆盖 `NtMapViewOfSection`，`NtMapViewOfSectionEx` 尚无对应介入。

常规路径只调用一次映射。首选址尝试失败且恢复原基址后，才会发起第二次映射调用。查询依赖 AMD64 Native API 返回的 section 信息，不同 Windows 版本需验证。PSEC 下的 `late-package` 在 Perl 父子进程内覆盖根外晚装模块、两种 `ZeroBits` 编码、显式基址、动态基址标志和首选址冲突回退。见 [当前设计](../design.md#dll-映射范围)和 [测试说明](../testing.md#映像地址对照)。

PE 可写共享节仍随文件流共享。`BaseNamedObjects` 重定向确定命名 IPC 的范围，`.cygwin_` 的跨域共享是独立的兼容限制。见 [共享映像节](../compatibility.md#msys-运行时的共享映像节)。
