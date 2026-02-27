#!/bin/sh
# Health check for celery-worker
# Sends a ping via Redis broker and expects a response within 5s.
# Exit 0 = healthy, Exit 1 = unhealthy (Railway will restart the container)
exec celery -A app.core.celery_app:celery_app inspect ping \
    --destination celery@$(hostname) \
    --timeout 5 \
    --quiet 2>&1 | grep -q "pong"
