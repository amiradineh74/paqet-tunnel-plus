#!/usr/bin/env python3
"""Paqet Tunnel Plus owned-resources uninstaller (no third-party dependencies).

Operates only on units/paths created by the official paqet-tunnel-plus deploy.sh.
Unknown ownership is a hard stop. Preview is the default.
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile

BASE = Path('/etc/paqet-tunnel-plus')
UNITDIR = Path('/etc/systemd/system')
OPT = Path('/opt/paqet-tunnel-plus')
CORE = Path('/usr/local/bin/paqet')
WEB_UNIT = UNITDIR / 'paqet-plus-web.service'
PERSIST = Path('/etc/iptables/rules.v4')
BACKUPS = Path('/root/paqet-tunnel-plus-removal-backups')
UNIT_NAME = re.compile(r'^paqet-plus-(server|client)-([a-zA-Z0-9_.-]+)\.service$')
PORT_RE = re.compile(r'^[0-9]{1,5}$')
CORE_EXEC = re.compile(r'^ExecStart=/usr/local/bin/paqet run -c (/.+)$', re.M)
WEB_EXEC = 'ExecStart=/usr/bin/python3 /opt/paqet-tunnel-plus/web/web_panel.py'


def fail(msg):
    raise RuntimeError(msg)


def command(args, *, check=True, capture=False):
    return subprocess.run(args, check=check, text=True,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.PIPE if capture else None)


def safe_dir(path):
    if path.is_symlink():
        fail(f'Refusing symlink directory: {path}')
    if path.exists() and not path.is_dir():
        fail(f'Expected directory: {path}')


def safe_file(path):
    if path.is_symlink():
        fail(f'Refusing symlink resource: {path}')
    if path.exists() and not path.is_file():
        fail(f'Expected regular file: {path}')


def meta_values(path):
    safe_file(path)
    if not path.is_file():
        fail(f'Missing metadata; cannot prove firewall ownership: {path}')
    values = {}
    for row in path.read_text(errors='replace').splitlines():
        if not row.strip():
            continue
        key, sep, val = row.partition('=')
        if sep and re.fullmatch(r'[A-Z_]+', key):
            if key in values:
                fail(f'Duplicate metadata field {key}: {path}')
            values[key] = val
    return values


def discover():
    safe_dir(BASE); safe_dir(UNITDIR); safe_dir(OPT)
    tunnels = []
    for unit in sorted(UNITDIR.glob('paqet-plus-*.service')):
        if unit.name == WEB_UNIT.name:
            continue
        match = UNIT_NAME.fullmatch(unit.name)
        if not match:
            fail(f'Unknown Paqet Plus unit (manual inspection needed): {unit}')
        safe_file(unit)
        role, name = match.groups()
        svc = unit.name[:-8]
        cfg = BASE / f'{name}-{role}.yaml'
        meta = BASE / f'{svc}.meta'
        safe_file(cfg)
        if not cfg.is_file():
            fail(f'Missing tunnel config: {cfg}')
        text = unit.read_text(errors='replace')
        found = CORE_EXEC.findall(text)
        if len(found) != 1 or found[0] != str(cfg):
            fail(f'Unknown ExecStart; not owned by this installer: {unit}')
        values = meta_values(meta)
        if values.get('ROLE') != role or values.get('TUNNEL_NAME') != name or values.get('CONFIG') != str(cfg):
            fail(f'Metadata mismatch: {meta}')
        port = values.get('PAQET_PORT', '')
        if not PORT_RE.fullmatch(port) or not 1 <= int(port) <= 65535:
            fail(f'Invalid/missing transport port: {meta}')
        ip = values.get('SERVER_IP', '')
        if role == 'client':
            try:
                ipaddress.IPv4Address(ip)
            except ipaddress.AddressValueError:
                fail(f'Invalid/missing client SERVER_IP in {meta}')
        tunnels.append(dict(service=svc, unit=unit, meta=meta, cfg=cfg,
                            role=role, name=name, port=port, ip=ip))
    return tunnels


def firewall_specs(t):
    p = t['port']
    if t['role'] == 'server':
        return [
            ('raw', 'PREROUTING', ('-p', 'tcp', '--dport', p, '-j', 'NOTRACK')),
            ('raw', 'OUTPUT', ('-p', 'tcp', '--sport', p, '-j', 'NOTRACK')),
            ('mangle', 'OUTPUT', ('-p', 'tcp', '--sport', p, '--tcp-flags', 'RST', 'RST', '-j', 'DROP')),
        ]
    ip = t['ip']
    return [
        ('raw', 'PREROUTING', ('-p', 'tcp', '-s', ip, '--sport', p, '-j', 'NOTRACK')),
        ('raw', 'OUTPUT', ('-p', 'tcp', '-d', ip, '--dport', p, '-j', 'NOTRACK')),
        ('mangle', 'OUTPUT', ('-p', 'tcp', '-d', ip, '--dport', p, '--tcp-flags', 'RST', 'RST', '-j', 'DROP')),
    ]


def rules_for(selected):
    out = []
    for t in selected:
        for rule in firewall_specs(t):
            if rule not in out:
                out.append(rule)
    return out


def owned_web():
    safe_file(WEB_UNIT)
    if not WEB_UNIT.exists():
        return False
    if WEB_EXEC not in WEB_UNIT.read_text(errors='replace'):
        fail(f'Web unit collision: {WEB_UNIT}')
    return True


def remaining_core_users(excluded_units):
    users = []
    for location in (Path('/etc/systemd/system'), Path('/lib/systemd/system'), Path('/usr/lib/systemd/system')):
        if not location.is_dir():
            continue
        for f in location.glob('*.service'):
            if f in excluded_units or not f.is_file():
                continue
            try:
                if '/usr/local/bin/paqet' in f.read_text(errors='replace'):
                    users.append(str(f))
            except OSError:
                users.append(f'{f} (unreadable)')
    return sorted(set(users))


def pretty(selected, full, rules, web, core_users):
    print('\n===== PAQET TUNNEL PLUS CLEANUP PREVIEW (NO CHANGES) =====')
    print('Mode:', 'FULL PROJECT CLEANUP' if full else 'SELECTED TUNNEL')
    for t in selected:
        print('TUNNEL:', t['service'], 'port='+t['port'], 'IP='+ (t['ip'] if t['role']=='client' else '(server)'))
        print('  UNIT: ', t['unit']); print('  CONFIG:', t['cfg']); print('  META: ', t['meta'])
    print('EXACT IPTABLES RULES:', len(rules))
    for table, chain, spec in rules:
        print('  iptables -t', table, '-D', chain, *spec)
    if full:
        print('WEB UNIT:', str(WEB_UNIT) if web else '(not installed)')
        print('PROJECT DIRECTORY:', OPT)
        print('CONFIG DIRECTORY:', BASE)
        for folder in (OPT, BASE):
            if folder.is_dir() and not folder.is_symlink():
                entries = sorted(folder.rglob('*'))
                print('  Inventory:', folder, f'({len(entries)} entries)')
                for path in entries[:35]:
                    print('   -', path.relative_to(folder))
                if len(entries) > 35:
                    print('   ...', len(entries)-35, 'additional entries')
        print('CORE:', CORE)
        print('CORE SHARED USERS:', core_users or '(none found in systemd unit files)')
    print('OS PACKAGES: preserved (shared/ownership cannot be proven)')
    print('BACKUP: created outside project, kept for recovery')
    print('WARNING: this DOES NOT touch unrelated services or flush firewall chains.')
    print('WARNING: custom rules and untracked changes require a separate audit.')
    print('===========================================================\n')


def backup(selected, full, web):
    safe_dir(BACKUPS)
    safe_file(PERSIST)
    BACKUPS.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(BACKUPS, 0o700)
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    target = BACKUPS / (('full' if full else selected[0]['service'])+'_'+stamp+'_'+str(os.getpid()))
    target.mkdir(mode=0o700)
    paths = [x[k] for x in selected for k in ('unit', 'cfg', 'meta')]
    if full:
        paths.extend([BASE, OPT])
        if web:
            paths.append(WEB_UNIT)
        if CORE.is_file() and not CORE.is_symlink():
            paths.append(CORE)
    archive = target / 'files.tar.gz'
    with tarfile.open(archive, 'w:gz', dereference=False) as tar:
        for path in dict.fromkeys(paths):
            if path.exists() or path.is_symlink():
                tar.add(path, arcname=str(path).lstrip('/'), recursive=True)
    os.chmod(archive, 0o600)
    if shutil.which('iptables-save'):
        (target/'iptables-before.v4').write_text(command(['iptables-save'], capture=True).stdout)
        os.chmod(target/'iptables-before.v4', 0o600)
    if PERSIST.is_file():
        shutil.copy2(PERSIST, target/'persistent-iptables-before.v4')
        os.chmod(target/'persistent-iptables-before.v4', 0o600)
    return target


def strip_persisted(rules):
    if not PERSIST.is_file():
        return 0
    safe_file(PERSIST)
    original = PERSIST.read_text()
    table = None
    selected = {(t, c, tuple(s)) for t,c,s in rules}
    remaining = []
    removed = 0
    for line in original.splitlines(keepends=True):
        raw = line.strip()
        if raw.startswith('*'):
            table = raw[1:]
        if raw.startswith('-A '):
            try:
                tokens = shlex.split(raw)
            except ValueError:
                fail('Cannot safely parse saved iptables rule; persistence not modified')
            if len(tokens) >= 3 and (table, tokens[1], tuple(tokens[2:])) in selected:
                removed += 1
                continue
        remaining.append(line)
    if removed:
        fd, tmp = tempfile.mkstemp(prefix='.rules.paqet-', dir=str(PERSIST.parent))
        try:
            with os.fdopen(fd,'w') as f:
                f.writelines(remaining)
                f.flush(); os.fsync(f.fileno())
            os.chmod(tmp, PERSIST.stat().st_mode & 0o777)
            os.replace(tmp, PERSIST)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
    return removed


def execute(selected, full, rules, web, core_users):
    if os.geteuid() != 0:
        fail('Removal requires root')
    if not shutil.which('systemctl'):
        fail('systemctl not available')
    if rules and not shutil.which('iptables'):
        fail('iptables not available; cannot ensure cleanup')
    if not selected and not full:
        fail('No tunnel selected')
    phrase = 'PURGE PAQET PLUS' if full else 'REMOVE '+selected[0]['service']
    print('Stopping these services will INTERRUPT active tunnel traffic.')
    typed = input(f'Type exactly {phrase!r} to proceed: ')
    if typed != phrase:
        print('Cancelled without changes.'); return
    target = backup(selected, full, web)
    print('Backup saved:', target)
    print('Backup contains sensitive configuration; protect it.')

    for t in selected:
        command(['systemctl','disable','--now',t['service']+'.service'])

    for table, chain, spec in rules:
        probe = ['iptables','-t',table,'-C',chain,*spec]
        found = command(probe, check=False).returncode == 0
        if found:
            command(['iptables','-t',table,'-D',chain,*spec])
            print('Removed exact firewall rule:', table, chain, ' '.join(spec))
    removed_persistent = strip_persisted(rules)
    print('Removed persisted firewall rule entries:', removed_persistent)

    for t in selected:
        t['unit'].unlink()
        t['cfg'].unlink()
        t['meta'].unlink()
    if full:
        if web:
            command(['systemctl', 'disable', '--now', WEB_UNIT.name])
            WEB_UNIT.unlink()
        safe_dir(BASE); safe_dir(OPT)
        if BASE.is_dir():
            shutil.rmtree(BASE)
        if OPT.is_dir():
            shutil.rmtree(OPT)
        if selected and not core_users and CORE.is_file() and not CORE.is_symlink():
            if not shutil.which('fuser'):
                print('WARNING: fuser unavailable; cannot prove core unused; preserving', CORE)
            elif command(['fuser','-s',str(CORE)],check=False).returncode == 0:
                print('WARNING: core currently in use; preserving',CORE)
            else:
                CORE.unlink()
                print('Removed unshared core:',CORE)
        else:
            print('Core preserved due to detected users or unknown ownership:',CORE)
    command(['systemctl','daemon-reload'])
    pending=[]
    for t in selected:
        for path in (t['unit'],t['cfg'],t['meta']):
            if path.exists() or path.is_symlink():
                pending.append(str(path))
    if full:
        for path in (BASE, OPT, WEB_UNIT):
            if path.exists() or path.is_symlink():
                pending.append(str(path))
    for table, chain, spec in rules:
        if command(['iptables','-t',table,'-C',chain,*spec],check=False).returncode == 0:
            pending.append('iptables -t '+table+' -C '+chain+' '+' '.join(spec))
    if pending:
        print('WARNING: Remaining resources detected:')
        for item in pending: print('  ',item)
    else:
        print('Verified: known selected files/units and exact live firewall rules are absent.')
    print('Cleanup completed; backup retained at:', target)
    print('OS dependencies, unknown/untracked firewall changes and shared binaries are deliberately preserved.')


def main():
    p = argparse.ArgumentParser(description='Paqet Tunnel Plus safe cleanup')
    x = p.add_mutually_exclusive_group()
    x.add_argument('--service', help='select one paqet-plus-(client|server)-NAME service')
    x.add_argument('--all', action='store_true', help='full removal of all Paqet Tunnel Plus resources')
    p.add_argument('--apply', action='store_true', help='require interactive confirmation and apply plan')
    p.add_argument('--list', action='store_true', help='list discovered owned services')
    args = p.parse_args()
    tunnels = discover()
    if args.list:
        for t in tunnels:
            print(t['service'])
        return
    if args.all:
        selected = tunnels
    elif args.service:
        selected = [t for t in tunnels if t['service']==args.service]
        if not selected:
            fail(f'Service not found: {args.service}')
    else:
        if not tunnels:
            print('No owned Paqet Tunnel Plus tunnel services found.')
            print('Use --all to preview full manager/web cleanup if installed.')
            return
        print('Installed tunnel services:')
        for i,t in enumerate(tunnels,1): print(f'  {i}) {t["service"]}')
        print('  A) All tunnels + complete Paqet Tunnel Plus manager cleanup')
        choice = input('Choose: ').strip()
        if choice.upper() == 'A':
            args.all = True; selected = tunnels
        else:
            if not choice.isdigit() or int(choice) not in range(1,len(tunnels)+1):
                fail('Invalid choice')
            selected=[tunnels[int(choice)-1]]
    if not args.all:
        others = [t for t in tunnels if t not in selected]
        intersect = set(rules_for(selected)) & set(rules_for(others))
        if intersect:
            fail('Identical firewall rules shared with remaining Plus tunnels; refusing partial cleanup')
    web = owned_web() if args.all else False
    core_users = remaining_core_users({t['unit'] for t in selected}) if args.all else []
    rules = rules_for(selected)
    pretty(selected,args.all,rules,web,core_users)
    if args.apply:
        execute(selected,args.all,rules,web,core_users)
    else:
        print('DRY RUN ONLY. To apply, run again with --apply and confirm exactly.')

if __name__ == '__main__':
    try:
        main()
    except (RuntimeError,OSError,subprocess.CalledProcessError) as ex:
        print('ERROR:',ex,file=sys.stderr)
        sys.exit(1)
