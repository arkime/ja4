#!/usr/bin/env python3
"""Writes ja4plus.dashboard.json, the dashboard the plugin ships (listed in
Arkime once the plugin's fields exist), with the widget helpers of Arkime's
release/dashboards/generate.py. Run from this directory with the Arkime source
tree beside it, or point ARKIME_DIR at it:
    ARKIME_DIR=../arkime python3 generate-dashboard.py"""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ARKIME = os.environ.get('ARKIME_DIR', os.path.join(HERE, '..', 'arkime'))
sys.path.insert(0, os.path.join(ARKIME, 'release', 'dashboards'))
from generate import plain, nav, metric, table, sankey, sessions, A  # noqa: E402

dash = plain('JA4+', 'JA4+ fingerprints (ja4plus plugin): TLS clients and servers, HTTP clients, certificates, SSH, TCP, DHCP and NTP', [
    nav(),
    metric('TLS clients (JA4)', expression='tls.ja4 == EXISTS!'), metric('TLS servers (JA4S)', expression='tls.ja4s == EXISTS!'),
    metric('HTTP clients (JA4H)', expression='http.ja4h == EXISTS!'), metric('SSH (JA4SSH)', expression='ssh.ja4ssh == EXISTS!'),
    table('tls.ja4', title='TLS client fingerprints (JA4)', metrics=['sessions', 'bytes'], sortMetric='sessions'),
    table('tls.ja4s', title='TLS server fingerprints (JA4S)', metrics=['sessions', 'bytes'], sortMetric='sessions'),
    sankey(['tls.ja4', 'tls.ja4s'], title='TLS client to server fingerprints'),
    table('http.ja4h', title='HTTP client fingerprints (JA4H)'), table('cert.ja4x', title='Certificate fingerprints (JA4X)'),
    table('ssh.ja4ssh', h=2, title='SSH fingerprints (JA4SSH)'), table('tcp.ja4t', h=2, title='TCP client fingerprints (JA4T)'),
    table('tcp.ja4ts', h=2, title='TCP server fingerprints (JA4TS)'), table('dhcp.ja4d', h=2, title='DHCP fingerprints (JA4D)'),
    table('ntp.ja4n', h=2, title='NTP fingerprints (JA4N)'), table('tls.ja4_r', h=2, title='TLS client fingerprints, raw (JA4_r)'),
    sessions(['ip.src', 'ip.dst', 'tls.ja4', 'tls.ja4s', 'http.ja4h', 'cert.ja4x', 'tcp.ja4t']),
], folder=A, requires=['tls.ja4s'])

for i, w in enumerate(dash['data']['widgets']):
    dash['data']['widgets'][i] = {'id': f'w{i}', **w}
out = os.path.join(HERE, 'ja4plus.dashboard.json')
with open(out, 'w') as f:
    f.write(json.dumps(dash, indent=2, ensure_ascii=False) + '\n')
print(f'wrote {out}')
