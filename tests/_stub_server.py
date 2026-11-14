"""Tiny stdlib HTTP stub for manually exercising scripts/eval.py.

Run in one terminal:  py -3.13 tests/_stub_server.py
Then: py -3.13 scripts/eval.py --base-url http://127.0.0.1:8765 --set redteam --fail-under 1.0
The fixed answer deliberately satisfies almost none of the fixtures, so the
runner demonstrates concise per-check failures and a non-zero exit status.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json

ANSWER = {
    "answer": "Stub answer: not enough evidence in the logs.",
    "structured": {"labels": {"confirmed": [], "suspected": [], "not_enough_evidence": []},
                   "severity": "P4", "severity_steps": [], "citations": [], "entities": [],
                   "actions": [], "notify": []},
    "meta": {"route": "rules"},
}

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/ask":
            self.send_error(404)
            return
        _ = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        body = json.dumps(ANSWER).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *_):
        pass

if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8765), Handler).serve_forever()
