#!/usr/bin/env python3
"""Run same-binary native compression controls interleaved with each threshold.

Fixture generation is separate and must use the corrected, frozen native base.
This orchestrator never substitutes legacy blocks or regenerates a corpus.
"""
import argparse
import hashlib
import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=pathlib.Path, required=True)
    parser.add_argument('--daemon', type=pathlib.Path)
    parser.add_argument('--fixture', type=pathlib.Path, required=True,
                        help='Completed native fixture output containing fixture/ and relay-block.hex')
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--peers', default='50,100,250,500')
    parser.add_argument('--timeout', type=int, default=600)
    parser.add_argument('--rpcport', type=int, default=19482)
    parser.add_argument('--port', type=int, default=19483)
    parser.add_argument('--plan-only', action='store_true')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    schedule = [{'name': f'{n:02d}-' + ('control' if threshold == 0 else f'threshold-{threshold}'),
                 'threshold_bytes': threshold}
                for n, threshold in enumerate([0, 16384, 0, 65536, 0, 262144, 0])]
    save(args.output / 'schedule.json', schedule)
    if args.plan_only:
        return
    marker = args.fixture / 'fixture' / 'fixture.json'
    fixture = json.loads(marker.read_text())
    if fixture.get('consensus') != 'native_v7' or fixture.get('relay_candidate_verifychain') is not True:
        raise RuntimeError('A completed, consensus-verified native V7 fixture is required')
    if subprocess.check_output(['git', '-C', str(ROOT), 'status', '--porcelain'], text=True).strip():
        raise RuntimeError('Freeze a clean committed source before recording controls')
    daemon = args.daemon or args.build / 'src' / 'lotusd'
    binaries = [daemon, args.build / 'src' / 'bench' / 'p2p-load']
    frozen = {'binaries': {str(path.resolve()): digest(path) for path in binaries},
              'source_commit': subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip(),
              'source_tree': subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD^{tree}'], text=True).strip(),
              'fixture_marker_sha256': digest(marker),
              'relay_bytes_sha256': digest(args.fixture / 'relay-block.hex'),
              'tls_certificate_sha256': digest(args.fixture / 'cert.pem'),
              'tls_key_sha256': digest(args.fixture / 'key.pem')}
    receipt = args.output / 'frozen-inputs.json'
    if receipt.exists() and json.loads(receipt.read_text()) != frozen:
        raise RuntimeError('Resume inputs changed: choose a fresh output, retaining previous evidence')
    save(receipt, frozen)
    for item in schedule:
        current_commit = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
        if current_commit != frozen['source_commit']:
            raise RuntimeError('Source commit changed during interleaved controls')
        for path in binaries:
            if digest(path) != frozen['binaries'][str(path.resolve())]:
                raise RuntimeError('Binary changed during interleaved controls')
        if digest(marker) != frozen['fixture_marker_sha256'] or digest(args.fixture / 'relay-block.hex') != frozen['relay_bytes_sha256']:
            raise RuntimeError('Corpus changed during interleaved controls')
        if digest(args.fixture / 'cert.pem') != frozen['tls_certificate_sha256'] or digest(args.fixture / 'key.pem') != frozen['tls_key_sha256']:
            raise RuntimeError('TLS reference inputs changed during interleaved controls')
        destination = args.output / item['name']
        destination.mkdir(exist_ok=True)
        if not (destination / 'fixture').exists():
            # APFS clones are real independent directories; symlinks would let
            # the per-cell server modify the shared native reference fixture.
            subprocess.run(['cp', '-cR', str(args.fixture / 'fixture'), str(destination / 'fixture')], check=True)
        for filename in ('cert.pem', 'key.pem'):
            target = destination / filename
            if not target.exists():
                subprocess.run(['cp', '-c', str(args.fixture / filename), str(target)], check=True)
            if digest(target) != digest(args.fixture / filename):
                raise RuntimeError('TLS inputs changed between controls')
        relay = destination / 'relay-block.hex'
        if not relay.exists():
            subprocess.run(['cp', '-c', str(args.fixture / 'relay-block.hex'), str(relay)], check=True)
        command = [sys.executable, str(HERE / 'run_matrix.py'), '--build', str(args.build),
                   '--daemon', str(daemon), '--native-fixture', '--output', str(destination),
                   '--independent-threshold', str(item['threshold_bytes']), '--peers', args.peers,
                   '--timeout', str(args.timeout), '--rpcport', str(args.rpcport), '--port', str(args.port),
                   '--max-rss-gib', '24', '--max-swap-growth-gib', '2', '--debug-net']
        save(destination / 'invocation.json', {'command': command, 'threshold_bytes': item['threshold_bytes']})
        subprocess.run(command, check=True)
        matrix = json.loads((destination / 'matrix.json').read_text())
        expected_cells = {(transport, int(peers), scenario) for transport in ('ws', 'wss')
                          for peers in args.peers.split(',') for scenario in ('relay', 'serve')}
        actual_cells = {(record['transport'], record['peers'], record['scenario']) for record in matrix['records']}
        if actual_cells != expected_cells:
            raise RuntimeError(f'Incomplete matrix coverage in {destination}')
        if any(record['status'] not in ('ok', 'resource_blocked') for record in matrix['records']):
            raise RuntimeError(f"Incomplete cells in {destination}; inspect retained receipts before continuing")
    records = []
    for item in schedule:
        destination = args.output / item['name']
        matrix = json.loads((destination / 'matrix.json').read_text())
        for cell in matrix['records']:
            row = dict(cell, run=item['name'], threshold_bytes=item['threshold_bytes'])
            metric_path = destination / cell['name'] / 'metrics.json'
            if metric_path.exists():
                metric = json.loads(metric_path.read_text())
                for key in ('websocket', 'compress_once'):
                    before, after = metric.get(key + '_before'), metric.get(key + '_after')
                    if isinstance(before, dict) and isinstance(after, dict):
                        row[key + '_delta'] = {field: value - before[field] for field, value in after.items()
                                              if isinstance(value, (int, float)) and isinstance(before.get(field), (int, float))}
                wire = row.get('websocket_delta', {})
                payload = wire.get('payload_bytes_sent', 0)
                row['actual_sent_wire_to_payload_ratio'] = wire.get('wire_bytes_sent', 0) / payload if payload else None
            records.append(row)
    save(args.output / 'interleaved.json', {'inputs': frozen, 'schedule': schedule, 'records': records,
         'limitations': ['Loopback shared host; interpret controls and host samples before attribution',
                         '250/500 peer cells are resource-blocked rather than extrapolated',
                         'Native burn-padding load corpus is not a mainnet compression distribution',
                         'No performance conclusion is generated automatically']})


if __name__ == '__main__':
    main()
