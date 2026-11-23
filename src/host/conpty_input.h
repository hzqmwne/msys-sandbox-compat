#pragma once
#include <algorithm>
#include <optional>
#include <string>
#include <string_view>

namespace msys_sandbox_compat {

// With VT input and Win32 input mode both enabled, older console hosts can
// wrap each character of an SGR mouse report in a synthetic key event.
class ConptyInput {
    static constexpr std::string_view key_prefix = "\x1b[0;0;";
    static constexpr std::string_view key_down = ";1;0;";
    static constexpr std::string_view mouse_prefix =
        "\x1b[0;0;27;1;0;1_\x1b[0;0;91;1;0;1_\x1b[0;0;60;1;0;1_";
    static constexpr unsigned max_field_digits = 5; // ConPTY coordinates fit in a signed 16-bit COORD.
    struct MouseReport {
        char bytes[3 + 3 * max_field_digits + 2 + 1]; // CSI <, three fields, and M/m.
        size_t size;
    };
    std::string pending;
    std::string joined;
    std::string translated;

    // Return zero for a mismatch and no value if the next read may complete it.
    static std::optional<size_t> match(std::string_view input, std::string_view prefix) {
        if (input.substr(0, prefix.size()) == prefix)
            return prefix.size();
        if (prefix.substr(0, input.size()) == input)
            return std::nullopt;
        return 0;
    }

    static std::optional<size_t> mouse_report(std::string_view input, MouseReport &report) {
        const auto start = match(input, mouse_prefix);
        if (!start || !*start)
            return start;

        std::copy_n("\x1b[<", 3, report.bytes);
        report.size = 3;
        size_t offset = *start;
        unsigned field = 0, digits = 0;
        for (;;) {
            const auto prefix = match(input.substr(offset), key_prefix);
            if (!prefix || !*prefix)
                return prefix;
            offset += *prefix;

            // Only decimal digits, separators and M/m in the mouse report are encoded here.
            unsigned code = 0, code_digits = 0;
            while (offset < input.size() && input[offset] >= '0' && input[offset] <= '9') {
                if (++code_digits > 3)
                    return 0;
                code = code * 10 + (input[offset++] - '0');
            }
            if (!code_digits && offset < input.size())
                return 0;
            const auto down = match(input.substr(offset), key_down);
            if (!down || !*down)
                return down;
            offset += *down;

            // conhost can coalesce adjacent copies of the same digit into one key event.
            if (offset == input.size())
                return std::nullopt;
            const char repeat = input[offset++];
            if (repeat < '1' || repeat > '5')
                return 0;
            if (offset == input.size())
                return std::nullopt;
            if (input[offset++] != '_')
                return 0;

            if (code >= '0' && code <= '9') {
                const auto copies = repeat - '0';
                digits += copies;
                if (digits > max_field_digits)
                    return 0;
                std::fill_n(report.bytes + report.size, copies, static_cast<char>(code));
                report.size += copies;
            } else if (repeat != '1') {
                return 0;
            } else if (code == ';' && digits && field < 2) {
                ++field;
                digits = 0;
                report.bytes[report.size++] = ';';
            } else if ((code == 'M' || code == 'm') && digits && field == 2) {
                report.bytes[report.size++] = static_cast<char>(code);
                return offset;
            } else {
                return 0;
            }
        }
    }

  public:
    // The returned view borrows the caller's input or this translator's storage.
    // Consume it before reusing the input buffer or calling translate again.
    std::string_view translate(std::string_view bytes) {
        if (!pending.empty()) {
            joined.swap(pending);
            pending.clear();
            joined.append(bytes);
            bytes = joined;
        }
        size_t copied = 0;
        auto input = bytes;
        while (!input.empty()) {
            const auto escape = input.find('\x1b');
            if (escape == std::string_view::npos)
                break;
            input.remove_prefix(escape);
            const auto offset = bytes.size() - input.size();
            MouseReport report;
            const auto consumed = mouse_report(input, report);
            if (!consumed) {
                pending.assign(input);
                bytes = bytes.substr(0, offset);
                break;
            }
            if (*consumed) {
                if (!copied)
                    translated.clear();
                translated.append(bytes.substr(copied, offset - copied));
                translated.append(report.bytes, report.size);
                copied = offset + *consumed;
            }
            input.remove_prefix(*consumed ? *consumed : 1);
        }
        if (!copied)
            return bytes;
        translated.append(bytes.substr(copied));
        return translated;
    }

    std::string_view remainder() const { return pending; }
};

} // namespace msys_sandbox_compat
