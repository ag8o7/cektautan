#!/usr/bin/env python3
"""CekTautan — server file statis + info versi.

Menjalankan:  python3 app.py 8080

Menyajikan file di folder yang sama dengan server ini, plus satu endpoint:
  GET  /api/version  -> {'version': 'X.Y.Z'}  (untuk notifikasi pembaruan)
"""
import json
import os
import sys
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

BASE = os.path.dirname(os.path.abspath(__file__))
VERSION_FILE = os.path.join(BASE, 'VERSION')


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

    def do_GET(self):
        path = urlparse(self.path).path
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

    def log_message(self, fmt, *args):
        sys.stderr.write('[%s] %s\n' % (time.strftime('%H:%M:%S'), fmt % args))


if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    httpd = ThreadingHTTPServer(('0.0.0.0', port), Handler)
    print('CekTautan server berjalan: http://localhost:%d' % port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
