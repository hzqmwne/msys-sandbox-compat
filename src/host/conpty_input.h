#pragma once
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
    std::string pending;

    // Return zero for a mismatch and no value if the next read may complete it.
    static std::optional<size_t> match(std::string_view input, std::string_view prefix) {
        if (input.substr(0, prefix.size()) == prefix)
            return prefix.size();
        if (prefix.substr(0, input.size()) == input)
            return std::nullopt;
        return 0;
    }

    static std::optional<size_t> mouse_report(std::string_view input, std::string &output) {
        const auto start = match(input, mouse_prefix);
        if (!start || !*start)
            return start;

        std::string report = "\x1b[<";
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
                digits += repeat - '0';
                if (digits > 5) // ConPTY's mouse coordinates fit in a signed 16-bit COORD.
                    return 0;
                report.append(repeat - '0', static_cast<char>(code));
            } else if (repeat != '1') {
                return 0;
            } else if (code == ';' && digits && field < 2) {
                ++field;
                digits = 0;
                report += ';';
            } else if ((code == 'M' || code == 'm') && digits && field == 2) {
                report += static_cast<char>(code);
                output += report;
                return offset;
            } else {
                return 0;
            }
        }
    }

  public:
    std::string translate(std::string_view bytes) {
        pending.append(bytes);
        std::string_view input = pending;
        std::string output;
        output.reserve(input.size());
        while (!input.empty()) {
            const auto escape = input.find('\x1b');
            output.append(input.substr(0, escape));
            if (escape == std::string_view::npos) {
                input = {};
                break;
            }
            input.remove_prefix(escape);
            const auto report = mouse_report(input, output);
            if (!report)
                break;
            if (!*report)
                output += input.front();
            input.remove_prefix(*report ? *report : 1);
        }
        pending.erase(0, pending.size() - input.size());
        return output;
    }

    std::string_view remainder() const { return pending; }
};

} // namespace msys_sandbox_compat
