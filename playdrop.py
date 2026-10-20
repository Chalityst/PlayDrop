"""Self-hosted LAN file transfer: PC <-> iPhone, no size limit.

Run:  python playdrop.py [folder] [port]
Open the printed URL in Safari on the iPhone (same Wi-Fi).
"""
import html, json, os, socket, sys, threading, time, urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

ROOT = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "shared"))
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8765
CHUNK = 1024 * 1024
HERE = os.path.dirname(os.path.abspath(__file__))
os.makedirs(ROOT, exist_ok=True)
PEERS, HOST_INBOX, LOCK = {}, [], threading.Lock()  # id -> {name, type, seen, local, inbox}

PAGE = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "page.html"), encoding="utf-8").read()


def human(n):
    for u in "B KB MB GB TB".split():
        if n < 1024: return f"{n:.1f} {u}"
        n /= 1024


def list_files():
    return [n for n in sorted(os.listdir(ROOT)) if os.path.isfile(os.path.join(ROOT, n)) and not n.endswith(".part")]


def file_rows():
    return "".join(
        f'<a href="/{urllib.parse.quote(n)}" download><span class=ic2>{html.escape(os.path.splitext(n)[1][1:5].upper() or "FILE")}</span>'
        f'<span class=nm>{html.escape(n)}<br><span class=sz>{human(os.path.getsize(os.path.join(ROOT, n)))}</span></span><span class=dl>↓</span></a>'
        for n in list_files()) or "<div class=empty>Drop files into the shared folder on your PC</div>"


def safe_path(name):
    p = os.path.abspath(os.path.join(ROOT, name))
    if os.path.commonpath([p, ROOT]) != ROOT: raise PermissionError
    return p


class H(BaseHTTPRequestHandler):
    timeout = 60  # drop idle/stalled connections

    def do_GET(self):
        if self.path == "/favicon.ico":
            self.send_response(204); self.end_headers(); return
        path = urllib.parse.unquote(self.path.split("?")[0]).lstrip("/")
        if not path:
            body = PAGE.replace("{{HOST}}", html.escape(socket.gethostname())).replace("{{ROWS}}", file_rows()).encode()
            return self.reply(body, "text/html; charset=utf-8")
        if path == "list":
            return self.reply(file_rows().encode(), "text/html; charset=utf-8")
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

    def reply(self, body, ctype):
        self.send_response(200); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", len(body)); self.end_headers(); self.wfile.write(body)

    def is_local(self):
        return self.client_address[0] in LOCAL_IPS

    def do_POST(self):
        """Heartbeat: register this device, return the other devices and any files sent to it."""
        if self.path != "/hello": return self.send_error(404)
        try: me = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 4096)))
        except ValueError: return self.send_error(400)
        now, local = time.time(), self.is_local()
        with LOCK:
            p = PEERS.setdefault(str(me.get("id"))[:64], {"inbox": []})
            p.update(name=str(me.get("name", "?"))[:40], type=str(me.get("type", "?"))[:20], seen=now, local=local)
            for k in [k for k, v in PEERS.items() if now - v["seen"] > 12]: del PEERS[k]
            # The PC's own browser tabs are represented by the single "host" peer.
            peers = [{"id": k, "name": v["name"], "type": v["type"]} for k, v in PEERS.items()
                     if k != me.get("id") and not v["local"]]
            if not local: peers.insert(0, {"id": "host", "name": socket.gethostname(), "type": "PC"})
            inbox = HOST_INBOX if local else p["inbox"]
            out, inbox[:] = list(inbox), []
        self.reply(json.dumps({"peers": peers, "inbox": out, "count": len(list_files())}).encode(), "application/json")

    def do_PUT(self):
        if not self.path.startswith("/upload/"): return self.send_error(404)
        u = urllib.parse.urlsplit(self.path); qs = urllib.parse.parse_qs(u.query)
        to, sender = qs.get("to", ["host"])[0], qs.get("from", ["?"])[0][:40]
        try: fp = safe_path(os.path.basename(urllib.parse.unquote(u.path[8:])))
        except PermissionError: return self.send_error(403)
        left = int(self.headers.get("Content-Length", 0))
        with open(fp + ".part", "wb") as f:
            while left > 0:
                buf = self.rfile.read(min(CHUNK, left))
                if not buf: break
                f.write(buf); left -= len(buf)
        if left: os.remove(fp + ".part"); return self.send_error(400, "Incomplete upload")
        os.replace(fp + ".part", fp)
        offer = {"name": os.path.basename(fp), "size": human(os.path.getsize(fp)), "from": sender}
        with LOCK:
            if to == "host": HOST_INBOX.append(offer); del HOST_INBOX[:-20]
            elif to in PEERS: PEERS[to]["inbox"].append(offer)
        self.send_response(200); self.send_header("Content-Length", 0); self.end_headers()


def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try: s.connect(("10.255.255.255", 1)); return s.getsockname()[0]
    except OSError: return "127.0.0.1"
    finally: s.close()


if __name__ == "__main__":
    ip = lan_ip()
    LOCAL_IPS = {"127.0.0.1", "::1", ip}

    class Server(ThreadingHTTPServer):
        daemon_threads = True
        allow_reuse_address = False  # on Windows reuse lets a 2nd copy silently share the port

    srv = Server(("0.0.0.0", PORT), H)
    print(f"Sharing: {ROOT}\nOpen on iPhone: http://{ip}:{PORT}")
    srv.serve_forever()
