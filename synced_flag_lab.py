#!/usr/bin/env python3
"""Synchronized, two-console Paqet flag tests without inter-server SSH.

Each selected role runs independently on the same UTC schedule. The client
temporarily adds a loopback-only forward and tests an actual SSH banner
delivered through Paqet. All scan/stability runs restore their starting YAML.
No changes to kernel, firewall, KCP, routing or unrelated services.
"""
import argparse
import csv
import datetime as dt
import hashlib
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import time

PROFILES = [
    ('historic-s-sa', 'S', 'SA', 'SA', 'PA'),
    ('current-s-pa', 'S', 'PA', 'PA', 'PA'),
    ('standard-pa-pa', 'PA', 'PA', 'PA', 'PA'),
    ('pa-sa', 'PA', 'SA', 'SA', 'PA'),
    ('s-a', 'S', 'A', 'A', 'PA'),
    ('pa-a', 'PA', 'A', 'A', 'PA'),
]
PROFILE_VERSION = '2026-10-22-synced-v2'
WINDOW_SEC = 75
STABILITY_WINDOW_SEC = 360
SERVER_OFFSET = 0
CLIENT_OFFSET = 10
PROBE_OFFSET = 23
PROBE_EVERY = 5
PROBE_COUNT = 8
ALLOWED = {'S', 'SA', 'PA', 'A'}
BASE_DIR = Path('/etc/paqet-tunnel-plus')
REPORT_DIR = Path('/var/log/paqet-tunnel-plus/flag-lab')


def utc(ts=None):
    return dt.datetime.fromtimestamp(ts if ts is not None else time.time(), dt.timezone.utc).isoformat(timespec='seconds')


def timed_wait(t):
    while (left := t - time.time()) > 0:
        time.sleep(min(left, 0.5))


def run(cmd, timeout=25):
    res = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
    if res.returncode:
        raise RuntimeError(f'{cmd[0]} exited {res.returncode}: {res.stderr[-220:]}')
    return res.stdout


def flags_match(text, key):
    found = list(re.finditer(r'(?m)^([ \t]*'+re.escape(key)+r':[ \t]*)\[[ \t]*"([A-Z]+)"[ \t]*\][ \t]*$', text))
    if len(found) != 1:
        raise ValueError('Expected exactly one '+key+' in config')
    return found[0]


def set_flags(text, local, remote):
    if local not in ALLOWED or remote not in ALLOWED:
        raise ValueError('Unsupported flags')
    for field, value in [('local_flag', local), ('remote_flag', remote)]:
        match = flags_match(text, field)
        text = text[:match.start()] + match.group(1) + '["'+value+'"]' + text[match.end():]
    return text


def add_probe(text, local_port, server_ip, ssh_port):
    if not 1025 <= local_port <= 65535 or not 1 <= ssh_port <= 65535:
        raise ValueError('Invalid diagnostic port')
    try:
        socket.inet_aton(server_ip)
        if len(server_ip.split('.')) != 4:
            raise ValueError('Numeric IPv4 required')
    except OSError as exc:
        raise ValueError('Use numeric server IPv4 only') from exc
    entry = ('  - listen: "127.0.0.1:'+str(local_port)+'"\n'
             '    target: "'+server_ip+':'+str(ssh_port)+'"\n'
             '    protocol: "tcp"\n')
    forward = list(re.finditer(r'(?m)^forward:[ \t]*\n', text))
    if len(forward) > 1:
        raise ValueError('Ambiguous forward config')
    if forward:
        end = forward[0].end()
        return text[:end] + entry + text[end:]
    net = re.search(r'(?m)^network:[ \t]*$', text)
    if not net:
        raise ValueError('No network: in config')
    return text[:net.start()] + 'forward:\n' + entry + text[net.start():]


def atomic_write(path, text):
    st = path.stat()
    fd, name = tempfile.mkstemp(prefix='.flag-lab-', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(name, st.st_mode & 0o777)
        os.chown(name, st.st_uid, st.st_gid)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def service_restart(svc):
    run(['systemctl', 'restart', svc], timeout=30)
    run(['systemctl', 'is-active', '--quiet', svc], timeout=6)


def banner_probe(port, timeout=3.5):
    t0 = time.monotonic()
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            got = sock.recv(128)
        return got.startswith(b'SSH-2.0-'), round(1000 * (time.monotonic()-t0), 1)
    except OSError:
        return False, ''


class Runner:
    def __init__(self, args):
        self.args = args
        self.path = Path(args.config)
        self.original = None
        self.backup = None
        self.saved = False
        self.restore_errors = []
        self.results = []

    def preflight(self):
        a = self.args
        if os.geteuid() != 0:
            raise ValueError('Must run as root')
        if not re.fullmatch(r'paqet-plus-'+a.role+r'-[A-Za-z0-9_.-]+', a.service):
            raise ValueError('Invalid service name for role')
        if self.path.parent != BASE_DIR or not self.path.is_file() or self.path.is_symlink():
            raise ValueError('Config must be a real file directly under /etc/paqet-tunnel-plus')
        if (a.role == 'client' and not self.path.name.endswith('-client.yaml')) or (a.role == 'server' and not self.path.name.endswith('-server.yaml')):
            raise ValueError('Wrong config role')
        self.original = self.path.read_text()
        if not re.search(r'(?m)^role:[ \t]*["\x27]?'+a.role+r'\b', self.original):
            raise ValueError('Config role does not match selected role')
        flags_match(self.original, 'local_flag')
        flags_match(self.original, 'remote_flag')
        key = re.search(r'(?m)^[ \t]*key:[ \t]*["\x27]([^"\x27]+)', self.original)
        if not key:
            raise ValueError('Transport key missing')
        hashprefix = hashlib.sha256(key.group(1).encode()).hexdigest()[:16]
        svc_start = run(['systemctl','show','-p','ExecStart','--value', a.service])
        if str(self.path) not in svc_start:
            raise ValueError('Service ExecStart does not reference selected YAML')
        run(['systemctl','is-active','--quiet',a.service])
        if a.role == 'client':
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', a.probe_port))
            if not a.server_ip:
                raise ValueError('Client needs server IPv4 for diagnostic forward')
            add_probe(self.original, a.probe_port, a.server_ip, a.ssh_port)
        else:
            # A real banner is required as the target for the client's test.
            ok, _ = banner_probe(a.ssh_port, timeout=3)
            if not ok:
                raise ValueError('Server local SSH port does not supply a banner; diagnostic probes would be meaningless')
        start = a.start_at
        if start <= time.time() + 15:
            raise ValueError('start-at is <15s ahead; choose shared future Unix epoch')
        if start > time.time() + 3600:
            raise ValueError('start-at is more than an hour ahead')
        print('ROLE:',a.role,'SERVICE:',a.service,'CONFIG:',self.path,flush=True)
        print('TRANSPORT KEY SHA256 PREFIX:',hashprefix,' (MUST match on both servers)',flush=True)
        print('PROFILE VERSION:',PROFILE_VERSION,'START:',start,utc(start),flush=True)
        print('Use SAME timestamp and mode on BOTH consoles.',flush=True)
        print('MODE:',a.mode,'PROFILE:',a.profile_index if a.mode=='stability' else 'all 6',flush=True)
        print('WARNING: selected production Paqet service will restart repeatedly.',flush=True)

    def store_backup(self):
        t = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        self.backup = self.path.with_name(self.path.name + '.synced-flag-lab.' + t + '.bak')
        if self.backup.exists():
            raise ValueError('Backup already exists')
        shutil.copy2(self.path, self.backup)
        os.chmod(self.backup, 0o600)
        self.saved = True
        print('BASELINE BACKUP:', self.backup,flush=True)

    def patch_and_restart(self, profile):
        _, cl, cr, sl, sr = profile
        loc, rem = (cl, cr) if self.args.role == 'client' else (sl, sr)
        text = set_flags(self.original, loc, rem)
        if self.args.role == 'client':
            text = add_probe(text, self.args.probe_port, self.args.server_ip, self.args.ssh_port)
        atomic_write(self.path, text)
        service_restart(self.args.service)

    def record(self, index, profile, result, passed, total, rtt, errors):
        d = {'utc':utc(),'profile_index':index,'profile':profile[0],
             'client_local':profile[1], 'client_remote':profile[2],
             'server_local':profile[3], 'server_remote':profile[4],
             'role':self.args.role,'result':result,'success':passed,'attempts':total,
             'median_ms':rtt,'notes':errors}
        self.results.append(d)
        print(f'[{utc()}] #{index} {profile[0]}: {result} {passed}/{total}' +
              (f' RTT={rtt}ms' if rtt!='' else '') +
              (' '+errors if errors else ''),flush=True)

    def execute(self):
        a = self.args
        self.preflight()
        if not a.yes:
            if input('Type YES to confirm temporary service interruptions: ').strip() != 'YES':
                print('Cancelled; no changes made.')
                return
        self.store_backup()
        try:
            if a.mode == 'stability':
                entries = [(a.profile_index, PROFILES[a.profile_index-1])]
                window = STABILITY_WINDOW_SEC
                probe_count, probe_every = 40, 7
            else:
                entries = list(enumerate(PROFILES,1))
                window = WINDOW_SEC
                probe_count, probe_every = PROBE_COUNT, PROBE_EVERY
            for k, (idx, profile) in enumerate(entries):
                base = a.start_at + k*window
                offset = SERVER_OFFSET if a.role=='server' else CLIENT_OFFSET
                timed_wait(base+offset)
                if time.time() > base+offset+5:
                    raise RuntimeError('Missed synchronized window; not reporting misleading results')
                err=''
                try:
                    self.patch_and_restart(profile)
                except Exception as exc:
                    err=type(exc).__name__+': '+str(exc)[:160]
                    print('[ERROR] apply/restart:',err,flush=True)
                if a.role=='server':
                    self.record(idx,profile,'SERVER_READY' if not err else 'SERVER_ERROR',0,0,'',err)
                else:
                    attempts=[]
                    for j in range(probe_count):
                        timed_wait(base + PROBE_OFFSET + j*probe_every)
                        attempts.append((False,'') if err else banner_probe(a.probe_port))
                    n=sum(1 for ok,_ in attempts if ok)
                    rtts=[ms for ok,ms in attempts if ok]
                    verdict = 'ERROR' if err else 'PROBE_PASS' if n==probe_count else 'UNSTABLE' if n else 'PROBE_FAIL'
                    self.record(idx,profile,verdict,n,probe_count,
                                statistics.median(rtts) if rtts else '',err)
                timed_wait(base+window-3)
            print('Compare BOTH reports. A probe pass is not full production validation.',flush=True)
        finally:
            self.restore()
            self.write_report()

    def restore(self):
        if not self.saved:
            return
        try:
            if self.backup and self.backup.is_file():
                atomic_write(self.path,self.backup.read_text())
                service_restart(self.args.service)
                print('ORIGINAL CONFIG RESTORED; selected service restarted.',flush=True)
            else:
                raise RuntimeError('Backup missing; manual recovery required')
        except Exception as exc:
            self.restore_errors.append(str(exc))
            print('[CRITICAL] RESTORE FAILED:',str(exc),'Backup:',str(self.backup),file=sys.stderr,flush=True)
        self.saved = False

    def write_report(self):
        if not self.results:
            return
        REPORT_DIR.mkdir(parents=True,exist_ok=True)
        os.chmod(REPORT_DIR,0o700)
        filename = REPORT_DIR / ('synced-'+self.args.role+'-'+dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.csv')
        with filename.open('w',newline='') as f:
            writer=csv.DictWriter(f,fieldnames=list(self.results[0]))
            writer.writeheader()
            writer.writerows(self.results)
        os.chmod(filename,0o600)
        print('RESULT REPORT:',filename,flush=True)


def parse():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--role',required=True,choices=['server','client'])
    p.add_argument('--config',required=True)
    p.add_argument('--service',required=True)
    p.add_argument('--start-at',type=int,required=True)
    p.add_argument('--mode',choices=['scan','stability'],default='scan')
    p.add_argument('--profile-index',type=int,choices=list(range(1,len(PROFILES)+1)),default=1)
    p.add_argument('--server-ip',default='')
    p.add_argument('--ssh-port',type=int,default=22)
    p.add_argument('--probe-port',type=int,default=39871)
    p.add_argument('--yes',action='store_true')
    return p.parse_args()


def main():
    a=parse()
    lab=Runner(a)
    def stop(signalnum,frame):
        raise KeyboardInterrupt('Signal '+str(signalnum))
    for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):
        signal.signal(sig,stop)
    try:
        lab.execute()
        if lab.restore_errors:
            return 3
    except KeyboardInterrupt:
        print('[!] Interrupted: restoring original YAML...',flush=True)
        lab.restore()
        lab.write_report()
        return 130
    except Exception as exc:
        print('[ERROR]',type(exc).__name__,str(exc),file=sys.stderr,flush=True)
        lab.restore()
        lab.write_report()
        return 1
    return 0


if __name__=='__main__':
    sys.exit(main())
