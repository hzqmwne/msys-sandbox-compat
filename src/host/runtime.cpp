#include "host.h"

namespace msys_compat {
namespace {
std::wstring native_directory(const std::filesystem::path &path) {
    HANDLE directory = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                   OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    check(directory != INVALID_HANDLE_VALUE, "open dependency search directory");
    auto result = file_path(directory) + L"\\";
    CloseHandle(directory);
    check(result.size() < image_path_chars, "dependency directory capacity");
    return result;
}
} // namespace

void configure_runtime_paths(const std::filesystem::path &runtime, AgentState &state) {
    // --runtime supplies a dependency-search directory, not a file identity.
    auto directory_path = native_directory(runtime.parent_path());
    memcpy(state.runtime.directory, directory_path.c_str(), (directory_path.size() + 1) * 2);
    wchar_t directory[image_path_chars];
    auto chars = GetSystemDirectoryW(directory, _countof(directory));
    check(chars && chars < _countof(directory), "system directory");
    auto system_path = native_directory(directory);
    memcpy(state.runtime.system_directory, system_path.c_str(), (system_path.size() + 1) * 2);
}
} // namespace msys_compat
