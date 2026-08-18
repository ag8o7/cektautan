#!/usr/bin/env python3
"""CekTautan — server file statis + penghitung pengunjung.

Menjalankan:  python3 app.py 8080

Menyajikan file di folder yang sama dengan server ini, plus tiga endpoint:
  GET  /api/stats   -> {'total': N, 'active': M}
  POST /api/track   -> body {"id": "<visitor-id>"}  (heartbeat / kunjungan baru)
  POST /api/leave   -> body {"id": "<visitor-id>"}  (pengunjung menutup halaman)

total  = jumlah pengunjung unik (per perangkat/browser) yang pernah masuk.
active = pengunjung yang masih terhubung dalam beberapa detik terakhir.
Data disimpan di visitors.json (otomatis dibuat).
"""
import json
import os
import sys
import threading
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

BASE = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(BASE, 'visitors.json')
VERSION_FILE = os.path.join(BASE, 'VERSION')
ACTIVE_TTL = 60          # detik tanpa sinyal = dianggap tidak aktif
HEARTBEAT = 30           # klien mengirim sinyal tiap 30 detik


def read_app_version():
    try:
        with open(VERSION_FILE, encoding='utf-8') as f:
            line = f.readline().strip()
        if line.lower().startswith('v'):
            line = line[1:]
        return line
    except Exception:
        return ''


APP_VERSION = read_app_version()

MIME = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon',
}

_lock = threading.Lock()


def load_data():
    try:
        with open(DATA_FILE, encoding='utf-8') as f:
            data = json.load(f)
        if not isinstance(data.get('active'), dict):
            data['active'] = {}
        if not isinstance(data.get('seen'), list):
            data['seen'] = []
        return data
    except Exception:
        return {'total': 0, 'active': {}, 'seen': []}


def save_data(data):
    tmp = DATA_FILE + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f)
    os.replace(tmp, DATA_FILE)


def cleanup(data):
    now = time.time()
    stale = [k for k, ts in data['active'].items() if now - ts > ACTIVE_TTL]
    for k in stale:
        del data['active'][k]


def stats():
    with _lock:
        data = load_data()
        cleanup(data)
        return {'total': data['total'], 'active': len(data['active'])}


def track(vis_id):
    with _lock:
        data = load_data()
        cleanup(data)
        if vis_id:
            seen = data['seen']
            if vis_id not in seen:
                data['total'] += 1
                seen.append(vis_id)
                if len(seen) > 2000:
                    data['seen'] = seen[-2000:]
            data['active'][vis_id] = time.time()
            save_data(data)
        return {'total': data['total'], 'active': len(data['active'])}


def leave(vis_id):
    with _lock:
        data = load_data()
        cleanup(data)
        if vis_id:
            data['active'].pop(vis_id, None)
            save_data(data)
        return {'total': data['total'], 'active': len(data['active'])}


class Handler(SimpleHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def _send_json(self, obj, status=200):
        body = json.dumps(obj).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _read_json_body(self):
        try:
            n = int(self.headers.get('Content-Length') or 0)
            if n > 8192:
                return {}
            raw = self.rfile.read(n) if n else b''
            return json.loads(raw.decode('utf-8') or '{}')
        except Exception:
            return {}

    def do_GET(self):
        path = urlparse(self.path).path
        if path == '/api/stats':
            self._send_json(stats())
            return
        if path == '/api/version':
            self._send_json({'version': APP_VERSION})
            return
        if path in ('/', ''):
            path = '/index.html'
        target = os.path.normpath(os.path.join(BASE, path.lstrip('/')))
        if not target.startswith(BASE) or not os.path.isfile(target):
            self.send_error(404, 'Not found')
            return
        ext = os.path.splitext(target)[1].lower()
        ctype = MIME.get(ext, 'application/octet-stream')
        try:
            with open(target, 'rb') as f:
                body = f.read()
        except OSError:
            self.send_error(404, 'Not found')
            return
        self.send_response(200)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self):
        path = urlparse(self.path).path
        body = self._read_json_body()
        vis_id = str(body.get('id') or '').strip()[:64]
        if path == '/api/track':
            self._send_json(track(vis_id))
            return
        if path == '/api/leave':
            self._send_json(leave(vis_id))
            return
        self.send_error(404, 'Not found')

    def log_message(self, fmt, *args):
        sys.stderr.write('[%s] %s\n' % (time.strftime('%H:%M:%S'), fmt % args))


if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    httpd = ThreadingHTTPServer(('0.0.0.0', port), Handler)
    print('CekTautan server berjalan: http://localhost:%d' % port)
    print('Data pengunjung disimpan di: %s' % DATA_FILE)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
