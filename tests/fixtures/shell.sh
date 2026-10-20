set -euo pipefail
export PATH=/usr/bin:/bin
v=parent
(v=child; test "$v" = child)
test "$v" = parent
test "$(printf '%s' substitution)" = substitution
test "$(printf 'c\nb\na\n' | sort | tr 'a-z' 'A-Z')" = $'A\nB\nC'
for i in {1..32}; do test "$(printf '%s' "$i")" = "$i"; done
printf 'input\n' > shell-input.tmp
exec 3<shell-input.tmp
(read -r -u 3 text; test "$text" = input)
exec 3<&-
rm shell-input.tmp
test "$(cat <(printf process-substitution))" = process-substitution
bash --noprofile --norc -c 'exit 37' &
p=$!
set +e
wait "$p"
status=$?
set -e
test "$status" = 37
awk 'BEGIN { print "awk-ok" }' | grep '^awk-ok$'
find . -maxdepth 0 -type d | grep '^\.$'
printf 'SHELL-PASS\n'
