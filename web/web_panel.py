#!/usr/bin/env python3
"""Paqet Tunnel Plus: loopback-only backend, optionally proxied via HTTPS.
Only explicitly authorized individual service start/stop/restart actions are permitted.
Never edits tunnel YAML, iptables or Paqet core.
"""
import argparse
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

BASE = Path('/etc/paqet-tunnel-plus')
SERVICE = re.compile(r'^paqet-plus-(?:client|server)-[A-Za-z0-9_.-]{1,60}$')
SENSITIVE = re.compile(r'(?im)^([ \t]*(?:key|password|token|secret|authorization)[ \t]*:[ \t]*).*$')
INLINE_SECRET = re.compile(r'(?i)((?:key|password|token|secret)[=:][ \t]*)([^\s,;]+)')
MAX_LOG_LINES = 200
ACTION_LOCK = threading.Lock()
AUDIT_PATH = Path('/opt/paqet-tunnel-plus/web-panel.audit.jsonl')

def run(argv):
    try:
        p = subprocess.run(argv, check=False, capture_output=True, text=True,
                           timeout=5, env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C'})
        return (p.stdout or p.stderr or '')[:24000]
    except (OSError, subprocess.TimeoutExpired):
        return 'اطلاعات در دسترس نیست'

def get_services():
    items = []
    if not BASE.is_dir():
        return items
    for path in sorted(BASE.glob('*.yaml')):
        if path.is_symlink() or not path.is_file() or len(items) >= 100:
            continue
        match = re.fullmatch(r'([A-Za-z0-9_.-]{1,60})-(client|server)\.yaml', path.name)
        if not match:
            continue
        svc = 'paqet-plus-' + match.group(2) + '-' + match.group(1)
        if not SERVICE.fullmatch(svc):
            continue
        try:
            cfg = path.read_text(encoding='utf-8')[:35000]
        except (OSError, UnicodeError):
            continue
        def field(name):
            m = re.search(r'(?m)^[ \t]*'+re.escape(name)+r':[ \t]*(?:\[[ \t]*)?["\x27]?([A-Za-z0-9_.:-]+)', cfg)
            return m.group(1) if m else '—'
        raw = run(['systemctl','show',svc,'--property=ActiveState,SubState,ActiveEnterTimestamp,MainPID','--no-pager'])
        state = dict(line.split('=',1) for line in raw.splitlines() if '=' in line)
        items.append({
            'name':match.group(1), 'role':match.group(2), 'service':svc,
            'state':state.get('ActiveState','unknown'), 'substate':state.get('SubState','unknown'),
            'since':state.get('ActiveEnterTimestamp',''), 'pid':state.get('MainPID',''),
            'kcp_mode':field('mode'), 'mtu':field('mtu'), 'conn':field('conn'),
            'local_flag':field('local_flag'), 'remote_flag':field('remote_flag'),
            'listen_port':field('addr') if match.group(2)=='server' else '—'
        })
    return items

def core_version():
    binary=Path('/usr/local/bin/paqet')
    if not binary.is_file():
        return 'not installed'
    match=re.search(r'(?m)^Version:[ \t]*([^\r\n]+)',run([str(binary),'version']))
    return match.group(1).strip()[:100] if match else 'unknown'

def safe_logs(service,lines):
    if service not in {s['service'] for s in get_services()}:
        raise ValueError('سرویس ناشناخته است')
    count=max(1,min(MAX_LOG_LINES,int(lines)))
    output=run(['journalctl','-u',service,'-n',str(count),'--no-pager','-o','short-iso'])
    output=SENSITIVE.sub(r'\1[REDACTED]',output)
    return INLINE_SECRET.sub(lambda m:m.group(1)+'[REDACTED]',output)

def audit_event(service, action, result):
    """Append-only action journal. If we cannot audit, no action is allowed."""
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(str(AUDIT_PATH), flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        record = {'at': datetime.now(timezone.utc).isoformat(), 'service': service,
                  'action': action, 'result': result}
        with os.fdopen(fd, 'a', encoding='utf-8') as stream:
            stream.write(json.dumps(record, ensure_ascii=False) + '\n')
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise

def service_action(service, action):
    if action not in ('start', 'stop', 'restart'):
        raise ValueError('Unknown action')
    if service not in {s['service'] for s in get_services()}:
        raise ValueError('Unknown Paqet tunnel service')
    # The selected service must be the real Paqet unit, not just a matching YAML filename.
    unit = run(['systemctl', 'show', service, '--property=FragmentPath,ExecStart', '--no-pager'])
    if '/usr/local/bin/paqet' not in unit or '/etc/paqet-tunnel-plus/' not in unit:
        raise ValueError('Service unit was not verified as Paqet Tunnel Plus')
    if not ACTION_LOCK.acquire(blocking=False):
        raise ValueError('Another service operation is in progress')
    try:
        audit_event(service, action, 'requested')
        try:
            result = subprocess.run(
                ['systemctl', action, service], capture_output=True, text=True,
                timeout=25, check=False,
                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'})
            ok = result.returncode == 0
            audit_event(service, action, 'success' if ok else 'failed')
            if not ok:
                raise RuntimeError('systemctl returned a nonzero exit status')
        except (subprocess.TimeoutExpired, OSError):
            audit_event(service, action, 'error')
            raise RuntimeError('Service operation timed out or failed')
        return {'ok': True, 'service': service, 'action': action}
    finally:
        ACTION_LOCK.release()

class Handler(BaseHTTPRequestHandler):
    server_version='PaqetPlusWeb/0.2-preview'
    def log_message(self,fmt,*args):
        sys.stderr.write('['+self.address_string()+'] '+fmt%args+'\n')
    def send(self,status,kind,data):
        if isinstance(data,str):
            data=data.encode('utf-8')
        self.send_response(status)
        for header,value in (
            ('Content-Type',kind),('Content-Length',str(len(data))),
            ('Cache-Control','no-store'),('X-Content-Type-Options','nosniff'),
            ('X-Frame-Options','DENY'),('Referrer-Policy','no-referrer'),
            ('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none")
        ):
            self.send_header(header,value)
        self.end_headers()
        self.wfile.write(data)
    def authorized(self):
        auth=self.headers.get('Authorization','')
        return auth.startswith('Bearer ') and hmac.compare_digest(auth[7:].encode(),self.server.token)
    def do_GET(self):
        u=urlsplit(self.path)
        if u.path in ('/','/index.html'):
            return self.send(200,'text/html; charset=utf-8',self.server.html)
        if u.path=='/app.js':
            return self.send(200,'application/javascript; charset=utf-8',self.server.js)
        if u.path not in ('/api/status','/api/check','/api/logs'):
            return self.send(404,'text/plain; charset=utf-8','Not found')
        if not self.authorized():
            return self.send(401,'application/json; charset=utf-8','{"error":"unauthorized"}')
        try:
            if u.path=='/api/check':
                data={'ok':True,'read_only':True}
            elif u.path=='/api/status':
                data={'read_only':True,'services':get_services(),'core_version':core_version()}
            else:
                q=parse_qs(u.query)
                service=q.get('service',[''])[0]
                data={'service':service,'logs':safe_logs(service,q.get('lines',['80'])[0])}
            return self.send(200,'application/json; charset=utf-8',json.dumps(data,ensure_ascii=False))
        except (ValueError,TypeError):
            return self.send(400,'application/json; charset=utf-8','{"error":"bad request"}')
    def do_POST(self):
        if urlsplit(self.path).path != '/api/service/action':
            return self.send(405, 'application/json; charset=utf-8', '{"error":"method_not_allowed"}')
        if not self.authorized():
            return self.send(401, 'application/json; charset=utf-8', '{"error":"unauthorized"}')
        origin = self.headers.get('Origin')
        if origin and urlsplit(origin).netloc != self.headers.get('Host', ''):
            return self.send(403, 'application/json; charset=utf-8', '{"error":"origin_mismatch"}')
        if self.headers.get('Content-Type', '').split(';')[0].strip() != 'application/json':
            return self.send(415, 'application/json; charset=utf-8', '{"error":"json_only"}')
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 2 <= size <= 2048:
                raise ValueError('Invalid body size')
            body = json.loads(self.rfile.read(size).decode('utf-8'))
            if not isinstance(body, dict) or set(body.keys()) != {'service', 'action'}:
                raise ValueError('Unexpected request fields')
            data = service_action(body['service'], body['action'])
            return self.send(200, 'application/json; charset=utf-8',
                             json.dumps(data, ensure_ascii=False))
        except (ValueError, TypeError, UnicodeError, json.JSONDecodeError):
            return self.send(400, 'application/json; charset=utf-8', '{"error":"invalid_request"}')
        except (RuntimeError, OSError):
            return self.send(500, 'application/json; charset=utf-8', '{"error":"operation_failed"}')

def main():
    ap=argparse.ArgumentParser(description='Read-only Paqet Plus web panel, SSH forwarded')
    ap.add_argument('--port',type=int,default=8792)
    ap.add_argument('--assets',default=str(Path(__file__).resolve().parent))
    ap.add_argument('--token-file',default='/opt/paqet-tunnel-plus/web-panel.token')
    args=ap.parse_args()
    if not 1025<=args.port<=65535:
        ap.error('port must be 1025..65535')
    path=Path(args.token_file)
    if path.exists():
        if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
            ap.error('token file must be regular and chmod 0600')
        token=path.read_text('ascii').strip().encode('ascii')
    else:
        path.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(str(path),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        token=secrets.token_urlsafe(32).encode('ascii')
        with os.fdopen(fd,'wb') as f:
            f.write(token+b'\n')
    if len(token)<32:
        ap.error('token too short')
    assets=Path(args.assets).resolve(strict=True)
    server=ThreadingHTTPServer(('127.0.0.1',args.port),Handler)
    server.token=token
    server.html=(assets/'index.html').read_bytes()
    server.js=(assets/'app.js').read_bytes()
    print('Paqet Plus Web at http://127.0.0.1:'+str(args.port)+' (local, read-only)',flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__=='__main__':
    main()
