#!/usr/bin/env python3
"""
Simple proxy server that serves the static website files
AND forwards JSON-RPC POST requests to the Zeno node on port 8000.
Run: python3 serve.py
"""
import http.server
import urllib.request
import json
import os
import sys

PORT = 3001
RPC_TARGET = 'http://localhost:8000'
WEBSITE_DIR = os.path.dirname(os.path.abspath(__file__))

class ZenoHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEBSITE_DIR, **kwargs)

    def do_POST(self):
        # Forward all POST requests to the Zeno RPC node
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        try:
            req = urllib.request.Request(
                RPC_TARGET + self.path,
                data=body,
                headers={
                    'Content-Type': 'application/json',
                    'Accept': '*/*',
                }
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = resp.read()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Content-Length', len(result))
                self.end_headers()
                self.wfile.write(result)
        except Exception as e:
            error = json.dumps({'jsonrpc': '2.0', 'id': None, 'error': {'code': -32000, 'message': str(e)}}).encode()
            self.send_response(502)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Content-Length', len(error))
            self.end_headers()
            self.wfile.write(error)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.send_header('Access-Control-Max-Age', '86400')
        self.end_headers()

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        super().end_headers()

    def log_message(self, format, *args):
        # Quiet logging - only show errors
        if '404' in str(args) or '502' in str(args):
            super().log_message(format, *args)

print(f'Zeno website + RPC proxy running on http://localhost:{PORT}')
print(f'Forwarding POST requests to {RPC_TARGET}')
http.server.HTTPServer(('0.0.0.0', PORT), ZenoHandler).serve_forever()
