"""Self-hosted LAN file transfer: PC <-> iPhone, no size limit.

Run:  python playdrop.py [folder] [port]
Open the printed URL in Safari on the iPhone (same Wi-Fi).
"""
import glob, hashlib, hmac, html, os, secrets, shutil, socket, ssl, subprocess, sys, urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

ROOT = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "shared"))
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8765
CHUNK = 1024 * 1024
HERE = os.path.dirname(os.path.abspath(__file__))
CERT, KEY = os.path.join(HERE, "cert.pem"), os.path.join(HERE, "key.pem")
TOKEN = secrets.token_urlsafe(16)  # new access key every run
os.makedirs(ROOT, exist_ok=True)

PAGE = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "page.html"), encoding="utf-8").read()


def human(n):
    for u in "B KB MB GB TB".split():
        if n < 1024: return f"{n:.1f} {u}"
        n /= 1024


def safe_path(name):
    p = os.path.abspath(os.path.join(ROOT, name))
    if os.path.commonpath([p, ROOT]) != ROOT: raise PermissionError
    return p


class H(BaseHTTPRequestHandler):
    timeout = 60  # drop idle/stalled connections

    def authed(self):
        """Key arrives once via ?k=... and is then kept in an HttpOnly cookie."""
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get("k", [""])[0]
        c = dict(p.strip().split("=", 1) for p in self.headers.get("Cookie", "").split(";") if "=" in p).get("k", "")
        if hmac.compare_digest(q, TOKEN):
            self.send_response(303); self.send_header("Location", "/")
            self.send_header("Set-Cookie", f"k={TOKEN}; HttpOnly; Secure; SameSite=Strict; Path=/")
            self.send_header("Content-Length", 0); self.end_headers(); return None
        if hmac.compare_digest(c, TOKEN): return True
        self.send_error(401, "Open the link with the key printed on the PC"); return None

    def do_GET(self):
        if not self.authed(): return
        path = urllib.parse.unquote(self.path.split("?")[0]).lstrip("/")
        if not path:
            files = [n for n in sorted(os.listdir(ROOT)) if os.path.isfile(os.path.join(ROOT, n)) and not n.endswith(".part")]
            rows = "".join(
                f'<a href="/{urllib.parse.quote(n)}" download><span class=ic2>{html.escape(os.path.splitext(n)[1][1:5].upper() or "FILE")}</span>'
                f'<span class=nm>{html.escape(n)}<br><span class=sz>{human(os.path.getsize(os.path.join(ROOT, n)))}</span></span><span class=dl>↓</span></a>'
                for n in files) or "<div class=empty>Drop files into the shared folder on your PC</div>"
            body = (PAGE.replace("{{HOST}}", html.escape(socket.gethostname())).replace("{{COUNT}}", str(len(files)))
                    .replace("{{ROWS}}", rows)).encode()
            self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", len(body)); self.end_headers(); self.wfile.write(body); return
        try: fp = safe_path(path)
        except PermissionError: return self.send_error(403)
        if not os.path.isfile(fp): return self.send_error(404)
        size = os.path.getsize(fp); start, end = 0, size - 1
        rng = self.headers.get("Range")
        if rng and rng.startswith("bytes="):  # resume / streaming support
            a, _, b = rng[6:].partition("-")
            start = int(a) if a else size - int(b)
            end = int(b) if a and b else size - 1
            self.send_response(206); self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
        else:
            self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Disposition", "attachment; filename*=UTF-8''" + urllib.parse.quote(os.path.basename(fp)))
        self.send_header("Accept-Ranges", "bytes"); self.send_header("Content-Length", end - start + 1); self.end_headers()
        with open(fp, "rb") as f:
            f.seek(start); left = end - start + 1
            try:
                while left > 0:
                    buf = f.read(min(CHUNK, left))
                    if not buf: break
                    self.wfile.write(buf); left -= len(buf)
            except (ConnectionResetError, BrokenPipeError): pass

    def do_PUT(self):
        if not self.authed(): return
        if not self.path.startswith("/upload/"): return self.send_error(404)
        try: fp = safe_path(os.path.basename(urllib.parse.unquote(self.path[8:])))
        except PermissionError: return self.send_error(403)
        left = int(self.headers.get("Content-Length", 0))
        with open(fp + ".part", "wb") as f:
            while left > 0:
                buf = self.rfile.read(min(CHUNK, left))
                if not buf: break
                f.write(buf); left -= len(buf)
        if left: os.remove(fp + ".part"); return self.send_error(400, "Incomplete upload")
        os.replace(fp + ".part", fp)
        self.send_response(200); self.send_header("Content-Length", 0); self.end_headers()


def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try: s.connect(("10.255.255.255", 1)); return s.getsockname()[0]
    except OSError: return "127.0.0.1"
    finally: s.close()


def openssl():
    return shutil.which("openssl") or next(iter(glob.glob(r"C:\Program Files\Git\*\bin\openssl.exe")), None)


def ensure_cert(ip):
    if os.path.exists(CERT) and os.path.exists(KEY): return
    exe = openssl()
    if not exe: sys.exit("openssl not found (install Git for Windows) - needed to create the HTTPS certificate")
    subprocess.run([exe, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                    "-keyout", KEY, "-out", CERT, "-days", "3650", "-subj", "/CN=PlayDrop",
                    "-addext", f"subjectAltName=IP:{ip},IP:127.0.0.1,DNS:localhost"], check=True, capture_output=True)


if __name__ == "__main__":
    ip = lan_ip(); ensure_cert(ip)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(CERT, KEY)
    with open(CERT) as f: der = ssl.PEM_cert_to_DER_cert(f.read())
    fp = hashlib.sha256(der).hexdigest().upper()
    class TLSServer(ThreadingHTTPServer):
        daemon_threads = True

        # TLS handshake runs in the per-connection thread, so a stalled client
        # (e.g. Safari sitting on the cert warning) can't block everyone else.
        def finish_request(self, request, client_address):
            request.settimeout(30)
            try: request = ctx.wrap_socket(request, server_side=True)
            except (ssl.SSLError, OSError): return request.close()
            super().finish_request(request, client_address)

    srv = TLSServer(("0.0.0.0", PORT), H)
    print(f"Sharing: {ROOT}\nOpen on iPhone: https://{ip}:{PORT}/?k={TOKEN}\n"
          f"Cert SHA-256: {':'.join(fp[i:i+2] for i in range(0, 16, 2))}...")
    srv.serve_forever()
