#!/bin/sh
# Proves that the worker scans as soon as the machine continues a frozen process.
#
#     resume-after-freeze.sh <subject>
#
# A mobile system suspends an application and resumes it later, and
# docs/plan/03-runtime-and-api.md makes a full scan the worker's first work item
# after that resume. An attacker that acts while the application sleeps must not
# hold a window afterwards, so the delay between the resume and the first scan
# is the time that a host is exposed for.
#
# SIGSTOP is the model of the suspension. It stops every thread and it leaves
# the clock running, which is what Android gives a cached process and what iOS
# gives a suspended application. The Android freezer is the real mechanism, and
# tests/platform/README.md holds the run that measured it and found the same
# answer.
#
# The subject measures the delay itself, because only it holds the resume and
# the scan on one clock. This script owns the freeze and nothing else. It exits
# with the code that the subject reports: zero when the first scan after the
# resume landed inside the budget.
set -u

SUBJECT=$1

# How long to hold the freeze. The worker waits 5 seconds plus jitter between
# scans, so this outlasts any wait that it started before the freeze. That is
# the case the promise is about: the wait expired while the process was frozen.
HOLD=20

LOG=${TMPDIR:-/tmp}/resume-after-freeze.$$
trap 'rm -f "$LOG"' EXIT

: > "$LOG"
"$SUBJECT" > "$LOG" 2>&1 &
subject=$!

# The subject asks for the freeze once it holds a scan to compare against, and
# once its own poll loop runs. A freeze before that line leaves the loop with no
# gap to measure, because the loop would start its clock after the resume.
ready=''
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    if grep -q 'freeze this process now' "$LOG" 2> /dev/null; then
        ready=yes
        break
    fi
    sleep 1
done
pid=$(sed -n 's/^pid //p' "$LOG" | head -1)
if [ -z "$ready" ] || [ -z "$pid" ]; then
    kill "$subject" 2> /dev/null
    cat "$LOG"
    echo "the resume example never asked for the freeze"
    exit 1
fi

kill -STOP "$pid"
sleep "$HOLD"
kill -CONT "$pid"

wait "$subject"
status=$?

cat "$LOG"
exit "$status"
