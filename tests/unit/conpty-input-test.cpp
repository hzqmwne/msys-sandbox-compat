#include "conpty_input.h"
#include <cstdio>

using msys_sandbox_compat::ConptyInput;

static std::string wrap(std::string_view bytes) {
    std::string result;
    for (unsigned char byte : bytes)
        result += "\x1b[0;0;" + std::to_string(byte) + ";1;0;1_";
    return result;
}

static bool check_splits(std::string_view input, std::string_view expected) {
    for (size_t split = 0; split <= input.size(); ++split) {
        ConptyInput translator;
        std::string output(translator.translate(input.substr(0, split)));
        output += translator.translate(input.substr(split));
        output += translator.remainder();
        if (output != expected) {
            fprintf(stderr, "Unexpected mouse translation at split %zu\n", split);
            return false;
        }
    }
    return true;
}

int main() {
    constexpr std::string_view keys = "\x1b[27;1;27;1;0;1_\x1b[67;46;3;1;8;1_";
    constexpr std::string_view hover = "\x1b[<35;10;5M";
    constexpr std::string_view release = "\x1b[<0;112;36m";
    const auto wrapped = wrap(hover) + wrap("\x1b[<0;") + "\x1b[0;0;49;1;0;2_" +
                         wrap("2;36m");
    std::string input(keys);
    input += wrapped;
    input += hover; // A console host with raw VT pass-through sends this form.
    input += keys;
    std::string expected(keys);
    expected += hover;
    expected += release;
    expected += hover;
    expected += keys;
    if (!check_splits(input, expected))
        return 1;

    ConptyInput translator;
    std::string output;
    for (char byte : input)
        output += translator.translate({&byte, 1});
    if (output != expected || !translator.remainder().empty())
        return 1;

    const auto other_input = wrap("\x1b[<35;1;xM") + wrap("\x1b[<35;123456;1M") +
                             wrap("\x1b[I") + wrap("\x1b[<35;");
    if (!check_splits(other_input, other_input))
        return 1;

    constexpr std::string_view max_report = "\x1b[<12345;12345;12345M";
    if (!check_splits(wrap(max_report).append(keys), std::string(max_report).append(keys)))
        return 1;

    // Plain text, native key reports and raw mouse VT can borrow the read buffer.
    std::string unchanged(512, 'x');
    unchanged += keys;
    unchanged += hover;
    const auto borrowed = translator.translate(unchanged);
    return borrowed == unchanged && borrowed.data() == unchanged.data() ? 0 : 1;
}
