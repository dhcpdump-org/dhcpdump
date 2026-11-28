#!/bin/sh
# Regression tests: decode generated captures and compare with tests/expected.
#
#   tests/run.sh       run the tests against ./dhcpdump
#   tests/run.sh -u    rewrite tests/expected from the current output instead
#
# DHCPDUMP overrides the binary under test (autopkgtest uses the installed
# one). The capture generator and the JSON checker are small C programs,
# compiled here with $CC (default cc).

set -u

here=$(cd "$(dirname "$0")" && pwd)
bin=${DHCPDUMP:-$here/../dhcpdump}
exp=$here/expected
update=0
[ "${1:-}" = "-u" ] && update=1

tmp=$(mktemp -d "${AUTOPKGTEST_TMP:-${TMPDIR:-/tmp}}/dhcpdump-test.XXXXXX") || exit 1
trap 'rm -rf "$tmp"' EXIT INT TERM

# decoded times are local time; pin the zone and the locale
TZ=UTC
LC_ALL=C
export TZ LC_ALL

pass=0
fail=0

ok() {
	pass=$((pass+1))
	echo "ok   $1"
}

ko() {
	fail=$((fail+1))
	echo "FAIL $1"
}

# golden NAME ARGS...: run dhcpdump, compare stdout and stderr with expected/NAME.{out,err}
golden() {
	name=$1
	shift
	"$bin" "$@" >"$tmp/$name.out" 2>"$tmp/$name.err"
	rc=$?
	if [ $rc -ne 0 ]; then
		ko "$name: exit status $rc"
		cat "$tmp/$name.err"
		return
	fi
	if [ $update -eq 1 ]; then
		cp "$tmp/$name.out" "$exp/$name.out"
		cp "$tmp/$name.err" "$exp/$name.err"
		ok "$name (updated)"
		return
	fi
	if diff -u "$exp/$name.out" "$tmp/$name.out" >"$tmp/diff"&&diff -u "$exp/$name.err" "$tmp/$name.err" >>"$tmp/diff"; then
		ok "$name"
	else
		ko "$name: output differs"
		head -n 60 "$tmp/diff"
	fi
}

# json NAME ARGS...: run dhcpdump -j, check every line is valid JSON
json() {
	name=$1
	shift
	"$bin" "$@" >"$tmp/$name.json" 2>/dev/null
	rc=$?
	if [ $rc -ne 0 ]; then
		ko "$name: exit status $rc"
	elif "$tmp/jsoncheck" <"$tmp/$name.json"; then
		ok "$name"
	else
		ko "$name: invalid JSON"
	fi
}

# clean NAME ARGS...: run dhcpdump, only require a clean exit
clean() {
	name=$1
	shift
	if "$bin" "$@" >/dev/null 2>&1; then
		ok "$name"
	else
		ko "$name: exit status $?"
	fi
}

# refused NAME ARGS...: dhcpdump must reject the command line
refused() {
	name=$1
	shift
	if "$bin" "$@" >/dev/null 2>&1; then
		ko "$name: accepted"
	else
		ok "$name"
	fi
}

if [ ! -x "$bin" ]; then
	echo "$bin: not found; build it first (make)"
	exit 1
fi
for h in mkpcap jsoncheck; do
	${CC:-cc} -O2 -o "$tmp/$h" "$here/$h.c" || exit 1
done
"$tmp/mkpcap" "$tmp" || exit 1

golden options-text -r "$tmp/options.pcap"
golden options-json -r "$tmp/options.pcap" -j
golden frames-text -r "$tmp/frames.pcap"
golden frames-text-H -r "$tmp/frames.pcap" -H
golden frames-json -r "$tmp/frames.pcap" -j
golden frames-json-H -r "$tmp/frames.pcap" -j -H
golden filter-text -r "$tmp/frames.pcap" -h '^00:01:02:03'
golden filter-json -r "$tmp/frames.pcap" -j -h '^00:01:02:03'
json options-json-valid -r "$tmp/options.pcap" -j -H
json frames-json-valid -r "$tmp/frames.pcap" -j -H
json fuzz-json -r "$tmp/fuzz.pcap" -j
json fuzz-json-H -r "$tmp/fuzz.pcap" -j -H
clean fuzz-text -r "$tmp/fuzz.pcap"
clean fuzz-text-H -r "$tmp/fuzz.pcap" -H
refused json-tui -r "$tmp/frames.pcap" -j -t
refused no-source -j
refused missing-file -r "$tmp/does-not-exist.pcap"

echo "$pass passed, $fail failed"
[ $fail -eq 0 ]
