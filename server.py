import http.server
import socketserver
import json
import random
import time
from urllib.parse import urlparse

PORT = 8080

valid_sessions = set()

CHALLENGES = {
    "cat": ["cat", "cats", "a cat", "kitten", "kitty", "feline"]
}

pending_challenges = {}
blocked_ips = {}
MAX_ATTEMPTS = 5

BAD_AGENTS = ["curl", "wget", "python", "scrapy", "bot", "crawler",
              "spider", "axios", "httpx", "requests", "go-http", "libwww"]

try:
    CAPTCHA_PAGE = open("captcha.html").read()
    CONTENT_PAGE = open("content.html").read()
except FileNotFoundError as e:
    print(f"Error: {e}")
    print("Make sure captcha.html and content.html are in the same folder as server.py")
    exit(1)


def get_ip(handler):
    return handler.client_address[0]

def is_bad_agent(handler):
    ua = handler.headers.get("User-Agent", "").lower()
    return any(bad in ua for bad in BAD_AGENTS)

def has_valid_session(handler):
    cookies = handler.headers.get("Cookie", "")
    for part in cookies.split(";"):
        part = part.strip()
        if part.startswith("session="):
            token = part.split("=", 1)[1].strip()
            return token in valid_sessions
    return False

def serve_html(handler, html):
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html")
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(html.encode())


class CaptchaHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        ip = get_ip(self)
        ua = self.headers.get("User-Agent", "unknown")[:80]
        print(f"  [{ip}] {format % args}  |  {ua}")

    def block(self, reason="blocked"):
        print(f"  [BLOCKED] {get_ip(self)} — {reason}")
        self.send_response(403)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"403 Forbidden")

    def json_resp(self, data, cookie=None):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_GET(self):
        ip = get_ip(self)

        if is_bad_agent(self):
            self.block("bad-user-agent")
            return

        if blocked_ips.get(ip, 0) >= MAX_ATTEMPTS:
            self.block("ip-blocked")
            return

        if has_valid_session(self):
            serve_html(self, CONTENT_PAGE)
            return

        # Issue challenge
        token = f"{ip}-{int(time.time())}-{random.randint(1000,9999)}"
        pending_challenges[token] = "cat"
        page = CAPTCHA_PAGE \
            .replace("__CHALLENGE_TOKEN__", token) \
            .replace("__ANIMAL_TYPE__", "cat")
        serve_html(self, page)

    def do_POST(self):
        ip = get_ip(self)
        path = urlparse(self.path).path

        if path != "/verify":
            self.block("unknown-endpoint")
            return

        if blocked_ips.get(ip, 0) >= MAX_ATTEMPTS:
            self.block("ip-blocked")
            return

        length = int(self.headers.get("Content-Length", 0))
        try:
            data = json.loads(self.rfile.read(length).decode())
        except Exception:
            self.block("bad-json")
            return

        token    = data.get("token", "")
        answer   = data.get("answer", "").strip().lower()
        honeypot = data.get("hp", "")

        if honeypot:
            self.block("honeypot")
            return

        if token not in pending_challenges:
            blocked_ips[ip] = blocked_ips.get(ip, 0) + 1
            self.json_resp({"ok": False, "reason": "invalid-token"})
            return

        animal   = pending_challenges[token]
        accepted = [a.lower() for a in CHALLENGES[animal]]
        correct  = answer in accepted
        del pending_challenges[token]

        if correct:
            sess = f"sess-{ip}-{int(time.time())}-{random.randint(10000,99999)}"
            valid_sessions.add(sess)
            print(f"  [PASS] {ip} — session granted")
            self.json_resp(
                {"ok": True},
                cookie=f"session={sess}; Path=/; HttpOnly; SameSite=Strict"
            )
        else:
            blocked_ips[ip] = blocked_ips.get(ip, 0) + 1
            remaining = MAX_ATTEMPTS - blocked_ips[ip]
            print(f"  [FAIL] {ip} answered '{answer}' — {remaining} left")
            self.json_resp({"ok": False, "reason": "wrong", "remaining": remaining})


print(f"  Running at http://localhost:{PORT}")
print(f"  CAPTCHA always on")
print("──────────────────────────────────────────")

with socketserver.TCPServer(("", PORT), CaptchaHandler) as httpd:
    httpd.allow_reuse_address = True
    httpd.serve_forever()