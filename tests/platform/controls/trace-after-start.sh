#!/bin/sh
# Proves that the worker catches an attacker that arrives after start.
#
#     trace-after-start.sh <example> <attacker> [attacker argument...]
#
# The other controls start a process under an attacker, so the initial scan
# finds it. This one is the realistic attack: the application already runs, and
# an attacker reaches it. Only the worker catches that, and the time it takes
# is the time a host is exposed for.
#
# The attacker takes the process identifier as its last argument, and it reads
# `continue` on standard input. That is `lldb -p` on macOS, the `attach`
# control beside this file on Linux and on Android, and `attach-windows` on
# Windows. `inject-windows` uses the same contract to map memory instead of to
# trace, because the driver is the same: start, read the identifier, attack.
#
# It exits with the code that the example reports: zero when the worker caught
# the tracer, and non-zero when the deadline passed first.
set -u

SUBJECT=$1
shift

# How long the tracer holds the process. The example gives up before this, so
# the tracer never outlives what it traces.
HOLD=25

LOG=${TMPDIR:-/tmp}/trace-after-start.$$
trap 'rm -f "$LOG" "$LOG.tracer"' EXIT

: > "$LOG"
"$SUBJECT" > "$LOG" 2>&1 &
subject=$!

# The example prints its own process identifier first, and it prints nothing
# before the runtime started, so this also waits for the baseline to exist.
pid=''
for _ in 1 2 3 4 5 6 7 8 9 10; do
    pid=$(sed -n 's/^pid //p' "$LOG" | head -1)
    [ -n "$pid" ] && break
    sleep 1
done
if [ -z "$pid" ]; then
    kill "$subject" 2> /dev/null
    echo "the attach example printed no process identifier"
    exit 1
fi

(
    echo continue
    sleep "$HOLD"
) | "$@" "$pid" > "$LOG.tracer" 2>&1 &
tracer=$!

wait "$subject"
status=$?
kill "$tracer" 2> /dev/null

if [ "$status" -ne 0 ]; then
    cat "$LOG.tracer"
fi

cat "$LOG"
exit "$status"
