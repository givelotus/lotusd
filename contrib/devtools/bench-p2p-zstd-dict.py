#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Interleaved V1/V2 held-out compression microbenchmark (not network TPS).

Fresh connection compression per message is reported separately from a warm
stream. CPU is thread CPU time, not wall clock, and includes context creation
in cold mode. Decode checks are outside the timed region. Output records
versions, source identities, environment and all repetitions.
"""
import argparse
import base64
import collections
import hashlib
import gzip
import json
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import time
import zstandard


def dictionary(path, symbol):
    text = Path(path).read_text()
    body = text.split(symbol + '[', 1)[1].split('{', 1)[1].split('}', 1)[0]
    return bytes(int(x, 16) for x in re.findall(r'0x([0-9a-fA-F]{2})', body))


def run(samples, dictionary, warm):
    # Both pre-training and native transports send bodies under 64 bytes
    # plain. They must not enter or advance the zstd stream in either control.
    if all(len(body) < 64 for body in samples):
        return dict(cpu_ns=0, decode_cpu_ns=0, compressed_bytes=sum(map(len, samples)),
                    messages=len(samples), raw_bytes=sum(map(len, samples)))
    zdict = zstandard.ZstdCompressionDict(dictionary, dict_type=zstandard.DICT_TYPE_RAWCONTENT)
    params = zstandard.ZstdCompressionParameters.from_level(1, window_log=17, write_content_size=0, write_checksum=0)
    # The node shares a prepared CDict, rather than rebuilding it per peer.
    zdict.precompute_compress(level=1)
    zstandard.ZstdDecompressor(dict_data=zdict)  # prepare shared DDict
    encoded = []
    start = time.thread_time_ns()
    if warm:
        encoder = zstandard.ZstdCompressor(compression_params=params, dict_data=zdict).compressobj()
    for body in samples:
        if len(body) < 64:
            encoded.append(body)
            continue
        if not warm:
            encoder = zstandard.ZstdCompressor(compression_params=params, dict_data=zdict).compressobj()
        encoded.append(encoder.compress(body) + encoder.flush(zstandard.COMPRESSOBJ_FLUSH_BLOCK))
    elapsed = time.thread_time_ns() - start
    decoded = []
    decode_start = time.thread_time_ns()
    if warm:
        decoder = zstandard.ZstdDecompressor(dict_data=zdict).decompressobj()
    for body, wire in zip(samples, encoded):
        if len(body) < 64:
            decoded.append(wire)
            continue
        if not warm:
            decoder = zstandard.ZstdDecompressor(dict_data=zdict).decompressobj()
        decoded.append(decoder.decompress(wire))
    decode_elapsed = time.thread_time_ns() - decode_start
    assert decoded == samples
    return dict(cpu_ns=elapsed, decode_cpu_ns=decode_elapsed, compressed_bytes=sum(map(len, encoded)), messages=len(samples), raw_bytes=sum(map(len, samples)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('corpus')
    parser.add_argument('--root', default=str(Path(__file__).resolve().parents[2]))
    parser.add_argument('--output', required=True)
    parser.add_argument('--repetitions', type=int, default=11)
    parser.add_argument('--iterations', type=int, default=25)
    args = parser.parse_args()
    root = Path(args.root)
    data = Path(args.corpus).read_bytes()
    if args.corpus.endswith('.gz'):
        data = gzip.decompress(data)
    rows = [json.loads(line) for line in data.decode().splitlines()]
    groups = collections.defaultdict(list)
    for row in rows:
        if row['group'] == 3:
            groups[row['message']].append(base64.b64decode(row['body']))
            groups['ALL_MIXED'].append(base64.b64decode(row['body']))
    dictionaries = {1: dictionary(root / 'src/net_zstd_dict_data.h', 'P2P_ZSTD_DICT_V1'),
                    2: dictionary(root / 'src/net_zstd_dict_v2_data.h', 'P2P_ZSTD_DICT_V2')}
    records = []
    for name, samples in sorted(groups.items()):
        for warm in (False, True):
            for rep in range(args.repetitions):
                for version in ((1, 2) if rep % 2 == 0 else (2, 1)):
                    trials = [run(samples, dictionaries[version], warm) for _ in range(args.iterations)]
                    measurement = dict(trials[0])
                    measurement['cpu_ns'] = statistics.median(t['cpu_ns'] for t in trials)
                    measurement['decode_cpu_ns'] = statistics.median(t['decode_cpu_ns'] for t in trials)
                    records.append(dict(message=name, warm=warm, repetition=rep, version=version,
                                        **measurement))
    result = dict(schema=1, corpus_sha256=hashlib.sha256(Path(args.corpus).read_bytes()).hexdigest(),
        corpus_uncompressed_sha256=hashlib.sha256(data).hexdigest(),
        benchmark_script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        training_groups=[0,1,2], held_out_group=3, repetitions=args.repetitions, iterations=args.iterations,
        source_commit=subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip(),
        source_diff_sha256=hashlib.sha256(subprocess.check_output(['git','-C',str(root),'diff'])).hexdigest(),
        platform=platform.platform(), machine=platform.machine(), cpu_count=os.cpu_count(),
        load_average=os.getloadavg(), python=platform.python_version(), zstandard=zstandard.__version__,
        zstd_version=zstandard.ZSTD_VERSION,
        dictionaries={v: dict(bytes=len(d),sha256=hashlib.sha256(d).hexdigest()) for v,d in dictionaries.items()},
        records=records)
    Path(args.output).write_text(json.dumps(result,indent=2)+'\n')
    print('message | mode | raw B | V1 B | V2 B | byte delta | V1 CPU ns/msg | V2 CPU ns/msg | V1 decode ns/msg | V2 decode ns/msg')
    print(' | '.join(['---'] * 10))
    for name in sorted(groups):
        for warm in (False,True):
            sets = [[r for r in records if r['message']==name and r['warm']==warm and r['version']==v] for v in (1,2)]
            a,b=sets[0][0],sets[1][0]
            cpu=[statistics.median(r['cpu_ns']/r['messages'] for r in s) for s in sets]
            decode=[statistics.median(r['decode_cpu_ns']/r['messages'] for r in subset) for subset in sets]
            print(f"{name} | {'warm' if warm else 'cold'} | {a['raw_bytes']} | {a['compressed_bytes']} | {b['compressed_bytes']} | {(b['compressed_bytes']/a['compressed_bytes']-1)*100:.1f}% | {cpu[0]:.0f} | {cpu[1]:.0f} | {decode[0]:.0f} | {decode[1]:.0f}")


if __name__ == '__main__':
    main()
