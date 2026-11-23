#pragma once

#include <string>
#include <string_view>

namespace msys_sandbox_compat {
// Find an argv boundary without reconstructing the target's native command line.
inline std::wstring_view command_tail(std::wstring_view line, int first) {
    const auto space = [](wchar_t c) { return c == L' ' || c == L'\t'; };
    size_t pos = 0;
    for (int index = 0; index < first; ++index) {
        bool quoted = false;
        size_t slashes = 0;
        while (pos < line.size()) {
            const wchar_t ch = line[pos];
            if (space(ch) && !quoted)
                break;
            ++pos;
            if (ch == L'\\' && index != 0) {
                ++slashes;
                continue;
            }
            if (ch == L'"' && !(slashes & 1)) {
                if (index != 0 && quoted && pos < line.size() && line[pos] == L'"')
                    ++pos;
                else
                    quoted = !quoted;
            }
            slashes = 0;
        }
        while (pos < line.size() && space(line[pos]))
            ++pos;
    }
    return line.substr(pos);
}

inline std::wstring quote(const std::wstring &text) {
    std::wstring out = L"\"";
    size_t slashes = 0;
    for (auto c : text) {
        if (c == L'\\') {
            ++slashes;
            continue;
        }
        out.append(slashes * (c == L'"' ? 2 : 1), L'\\');
        slashes = 0;
        if (c == L'"')
            out += L'\\';
        out += c;
    }
    out.append(slashes * 2, L'\\');
    return out + L'"';
}
} // namespace msys_sandbox_compat
