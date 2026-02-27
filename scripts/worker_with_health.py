"""
Celery worker wrapper with HTTP health check server.

Starts the Celery worker as a subprocess and exposes a minimal HTTP
server on PORT that Railway uses as a healthcheck.

GET /health -> 200 while worker process is running, 503 if it exits
"""
import http.server
import os
import signal
import subprocess
import sys
import threading
import time


HEALTH_PORT = int(os.environ.get("PORT", os.environ.get("HEALTH_PORT", "8001")))
CELERY_APP = "app.core.celery_app:celery_app"
QUEUES = os.environ.get("CELERY_QUEUES", "pdf_parsing,portfolio_processing")
CONCURRENCY = os.environ.get("CELERY_CONCURRENCY", "4")
STARTUP_GRACE_SECONDS = 30

_worker_proc: "subprocess.Popen | None" = None
_startup_time: float = 0.0


def check_worker_alive() -> bool:
    """Return True during grace period or while worker process is running."""
    if _worker_proc is None or (time.time() - _startup_time) < STARTUP_GRACE_SECONDS:
        return True
    return _worker_proc.poll() is None


class HealthHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/health", "/"):
            alive = check_worker_alive()
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
        pass


def start_health_server():
    server = http.server.HTTPServer(("0.0.0.0", HEALTH_PORT), HealthHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"Health server listening on :{HEALTH_PORT}", flush=True)


def main():
    global _worker_proc, _startup_time
    start_health_server()

    cmd = [
        sys.executable, "-m", "celery",
        "-A", CELERY_APP,
        "worker",
        "--loglevel=info",
        f"--queues={QUEUES}",
        f"--concurrency={CONCURRENCY}",
    ]

    proc = subprocess.Popen(cmd)
    _worker_proc = proc
    _startup_time = time.time()

    def shutdown(signum, frame):
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    sys.exit(proc.wait())


if __name__ == "__main__":
    main()
