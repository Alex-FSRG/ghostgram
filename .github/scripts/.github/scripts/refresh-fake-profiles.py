#!/usr/bin/env python3
"""Re-issue the self-signed fake provisioning profiles with a fresh expiration date.

The profiles in build-system/fake-codesigning/profiles expired on 2026-10-30, and rules_apple
refuses an expired profile even for an unsigned build. This keeps every field of each profile
(entitlements, certificate, team) and only moves CreationDate to now and ExpirationDate to just
before the self-signed certificate itself expires, then signs it again with that same
self-signed key (SelfSigned.p12, empty password) — the key the original profiles were signed with.

Usage: refresh-fake-profiles.py <fake-codesigning dir> <openssl binary>
"""
import datetime
import glob
import os
import plistlib
import subprocess
import sys
import tempfile

root, openssl = sys.argv[1], sys.argv[2]
p12 = os.path.join(root, 'certs', 'SelfSigned.p12')


def run(*args, data=None):
    return subprocess.run([openssl, *args], input=data, capture_output=True, check=True).stdout


with tempfile.TemporaryDirectory() as tmp:
    cert = os.path.join(tmp, 'cert.pem')
    key = os.path.join(tmp, 'key.pem')
    # The p12 uses RC2-40 (legacy); OpenSSL 3 needs -legacy, LibreSSL does not know the flag.
    def p12_export(extra, out):
        for legacy in (['-legacy'], []):
            try:
                run('pkcs12', *legacy, '-in', p12, '-passin', 'pass:', *extra, '-out', out)
                return
            except subprocess.CalledProcessError:
                continue
        raise SystemExit('cannot read ' + p12)
    p12_export(['-nokeys', '-clcerts'], cert)
    p12_export(['-nocerts', '-nodes'], key)

    end = run('x509', '-in', cert, '-noout', '-enddate').decode().strip().split('=', 1)[1]
    cert_end = datetime.datetime.strptime(end, '%b %d %H:%M:%S %Y %Z')
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0, tzinfo=None)
    expiry = cert_end - datetime.timedelta(days=1)
    if expiry <= now:
        raise SystemExit('the self-signed certificate itself has expired: ' + end)

    for path in sorted(glob.glob(os.path.join(root, 'profiles', '*.mobileprovision'))):
        content = run('smime', '-inform', 'der', '-verify', '-noverify', '-in', path)
        profile = plistlib.loads(content)
        profile['CreationDate'] = now
        profile['ExpirationDate'] = expiry
        profile['TimeToLive'] = (expiry - now).days
        plist_path = os.path.join(tmp, 'profile.plist')
        with open(plist_path, 'wb') as f:
            plistlib.dump(profile, f)
        signed = run('smime', '-sign', '-binary', '-nodetach', '-outform', 'der', '-md', 'sha256',
                     '-signer', cert, '-inkey', key, '-in', plist_path)
        with open(path, 'wb') as f:
            f.write(signed)
        print(f'{os.path.basename(path)}: {profile["Entitlements"]["application-identifier"]} '
              f'valid until {expiry.isoformat()}Z')
