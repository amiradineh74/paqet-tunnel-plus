#!/usr/bin/env python3
"""Read-only Paqet web panel regression tests (no privileged commands)."""
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
import urllib.error
import urllib.request

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('web_panel',HERE/'web_panel.py')
w=importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)

class WebTests(unittest.TestCase):
    def test_service_name_validation(self):
        self.assertTrue(w.SERVICE.fullmatch('paqet-plus-client-tunnel'))
        self.assertFalse(w.SERVICE.fullmatch('paqet-plus-server-tunnel;rm -rf /'))

    def test_safe_config_summary(self):
        with tempfile.TemporaryDirectory() as td:
            original_base, original_run = w.BASE, w.run
            w.BASE=Path(td)
            (w.BASE/'tunnel-client.yaml').write_text(
                'role: "client"\nnetwork:\n  tcp:\n    local_flag: ["S"]\n    remote_flag: ["PA"]\n'
                'transport:\n  conn: 1\n  kcp:\n    mode: "fast2"\n    mtu: 1200\n    key: "THIS_IS_A_SECRET"\n',encoding='utf-8'
            )
            w.run=lambda argv:'ActiveState=active\nSubState=running\nMainPID=123\n'
            try:
                found=w.get_services()
                self.assertEqual(found[0]['service'],'paqet-plus-client-tunnel')
                self.assertEqual(found[0]['local_flag'],'S')
                self.assertNotIn('THIS_IS_A_SECRET',json.dumps(found))
            finally:
                w.BASE,w.run=original_base,original_run

    def test_log_redaction_and_whitelist(self):
        with tempfile.TemporaryDirectory() as td:
            original_base,original_run=w.BASE,w.run
            w.BASE=Path(td)
            (w.BASE/'tunnel-client.yaml').write_text('role: "client"',encoding='utf-8')
            w.run=lambda argv:'token=VISIBLE_PASSWORD key: secret_key_here\n'
            try:
                self.assertNotIn('VISIBLE_PASSWORD',w.safe_logs('paqet-plus-client-tunnel',80))
                self.assertNotIn('secret_key_here',w.safe_logs('paqet-plus-client-tunnel',80))
                with self.assertRaises(ValueError):
                    w.safe_logs('ssh.service',80)
            finally:
                w.BASE,w.run=original_base,original_run

    def test_http_rejects_writes_and_requires_token(self):
        server=ThreadingHTTPServer(('127.0.0.1',0),w.Handler)
        server.token=b'this-is-a-test-token-with-at-least-32-bytes'
        server.html=(HERE/'index.html').read_bytes()
        server.js=(HERE/'app.js').read_bytes()
        thread=threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        url='http://127.0.0.1:'+str(server.server_address[1])
        def req(path,auth=None,method='GET'):
            h={} if auth is None else {'Authorization':'Bearer '+auth}
            return urllib.request.urlopen(urllib.request.Request(url+path,headers=h,method=method),timeout=3)
        try:
            with req('/index.html') as r:
                self.assertEqual(r.status,200)
            with self.assertRaises(urllib.error.HTTPError) as e:
                req('/api/status')
            self.assertEqual(e.exception.code,401)
            with req('/api/check',server.token.decode()) as r:
                self.assertTrue(json.load(r)['read_only'])
            with self.assertRaises(urllib.error.HTTPError) as e:
                req('/api/check','bad')
            self.assertEqual(e.exception.code,401)
            with self.assertRaises(urllib.error.HTTPError) as e:
                req('/api/status',server.token.decode(),method='POST')
            self.assertEqual(e.exception.code,405)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

if __name__=='__main__':
    unittest.main()
