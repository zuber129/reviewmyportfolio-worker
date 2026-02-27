"""
Celery beat wrapper with HTTP health check server.

Starts celery beat as a subprocess and exposes a minimal HTTP server
on HEALTH_PORT (default 8001) that Railway can use as a healthcheck.

GET /health  -> 200 if beat process is alive, 503 otherwise
"""
import http.server
import os
import signal
import subprocess
import sys
import threading


HEALTH_PORT = int(os.environ.get("PORT", os.environ.get("HEALTH_PORT", "8001")))
CELERY_APP = "app.core.celery_app:celery_app"
PIDFILE = "/tmp/celerybeat.pid"
STARTUP_GRACE_SECONDS = 30

_beat_proc: subprocess.Popen | None = None
_startup_time: float = 0.0


def check_beat_alive() -> bool:
    """Return True during grace period or while beat process is running."""
    import time
    if _beat_proc is None or (time.time() - _startup_time) < STARTUP_GRACE_SECONDS:
        return True
    return _beat_proc.poll() is None


class HealthHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/health", "/"):
            alive = check_beat_alive()
            code = 200 if alive else 503
            body = b'{"status":"ok"}' if alive else b'{"status":"unhealthy"}'
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # suppress access logs


def start_health_server():
    server = http.server.HTTPServer(("0.0.0.0", HEALTH_PORT), HealthHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"Health server listening on :{HEALTH_PORT}", flush=True)


def main():
    import time
    global _beat_proc, _startup_time

    start_health_server()

    cmd = [
        sys.executable, "-m", "celery",
        "-A", CELERY_APP,
        "beat",
        "--loglevel=info",
        "--scheduler", "celery.beat:PersistentScheduler",
        f"--pidfile={PIDFILE}",
    ]

    _beat_proc = subprocess.Popen(cmd)
    _startup_time = time.time()

    def shutdown(signum, frame):
        _beat_proc.terminate()
        try:
            _beat_proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            _beat_proc.kill()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    sys.exit(_beat_proc.wait())


if __name__ == "__main__":
    main()
