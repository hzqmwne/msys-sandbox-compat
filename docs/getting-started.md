# 使用说明

## 构建

在 Windows AMD64 上安装 PowerShell 7、Visual Studio 的 C++ AMD64 工具与 Windows SDK，然后运行：

```powershell
.\build.ps1
.\build.ps1 -Configuration Release -Install
```

CMake 缓存、中间文件和二进制都在 `build`，不需要复制历史构建缓存。`-Install` 将运行时文件、公开文档和第三方许可整理到 `unused/package`；测试夹具不会安装。手动 CMake 构建同样支持 `-DBUILD_TESTING=OFF`。

## 示例入口

`run.ps1` 创建 PSEC 策略，将 Windows 与所选 Git 根目录设为只读，项目根目录设为可写，进程工作目录继承调用者，并明确拒绝测试 canary。HOME、临时文件和运行状态位于 `unused/runtime`。

```powershell
.\run.ps1 -GitRoot 'C:\Program Files\Git'
.\run.ps1 -ConPty -TerminalSize '120x40'
.\run.ps1 -NativeRelay
.\run.ps1 -Raw  # 不启用兼容层，用于失败基线对照
```

默认目标是 Git 的 `usr/bin/bash.exe`。不要将 Git 根目录或 `bin` 中的外层 Bash 壳启动器当作真实 MSYS 目标。

## 低层入口

```text
psec-run.exe policy.json program.exe [arguments...]
msys-compat.exe [--trace] [--native-relay] [--runtime msys-2.0.dll]
    [--conpty | --conpty-script input.txt] [--conpty-size WIDTHxHEIGHT]
    program.exe [arguments...]
```

`psec-run.exe` 由普通宿主调用，负责创建原生 PSEC。`msys-compat.exe` 在既有 PSEC 或非 AppContainer 受限令牌上下文内调用，负责兼容准备；它从自身目录定位 `msys-compat.dll`。`--runtime` 为传递依赖解析提供运行时所在目录，不进行文件身份认证。

接入受限令牌启动器时，将其启动目标设为 `msys-compat.exe --runtime DLL PROGRAM ...`，保留启动器既有 token、对象和文件策略。兼容 EXE/DLL 应部署在原策略已允许读取/执行的位置；原版 MSYS 安装文件也必须已具备原策略允许的访问。兼容层不修改任何磁盘 ACL、不放宽 restricted token，也不借非受限进程代读被拒绝的文件。缺少访问时记录该配置下的兼容阻碍，不能通过补权把它算作成功。已验收配置见 [兼容范围](compatibility.md)，测试用 `restricted-run.exe` 不作为产品启动器分发。

在实际 harness 内可直接执行 `tests/conpty.ps1 -Environment Existing` 验证继承的上下文。它不创建新的隔离环境或配置文件 ACL；初始策略与拒绝边界的验收要求见 [测试说明](testing.md)。

兼容宿主通过 job 等待进程树退出并返回根进程退出码。ConPTY 模式收发 VT 字节流，初始尺寸可配置；当前没有终端 GUI、VT 渲染器或宿主窗口 resize 事件循环。

`--native-relay` 是显式选择的进程树传播模式，也可由 `run.ps1 -NativeRelay` 启用，并可与 ConPTY 组合。原生进程仅保留创建 hook，直接启动后续 MSYS 时自动完成兼容准备；默认仍不注入原生进程。已处于该树中的嵌套兼容入口复用已有 relay，无需重复加选项。该模式不修改磁盘 ACL 或放宽 token，遇到安全上下文或默认对象策略变化时拒绝传播。覆盖入口和限制见 [兼容范围](compatibility.md)。`-Raw` 与 `-NativeRelay` 不能同时使用。

## 创建环境失败

若调用者已经处于禁止创建新 PSEC 的环境，创建 API 可能失败，例如返回 `0x800706d9`。这时应从允许该 API 的宿主执行测试，或在已经创建的 PSEC 内使用兼容入口。工具不会切换到普通非隔离进程。

其他集成边界见 [兼容范围](compatibility.md)。
