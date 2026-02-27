#!/bin/sh
# Health check for celery-beat
# Beat doesn't respond to inspect ping — check the PID file instead.
# Exit 0 = healthy, Exit 1 = unhealthy
PIDFILE="/tmp/celerybeat.pid"

if [ ! -f "$PIDFILE" ]; then
    echo "Beat PID file not found: $PIDFILE"
    exit 1
fi

PID=$(cat "$PIDFILE")
if kill -0 "$PID" 2>/dev/null; then
    exit 0
else
    echo "Beat process $PID is not running"
    exit 1
fi
