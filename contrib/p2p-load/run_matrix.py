#!/usr/bin/env python3
"""Real-node loopback transport matrix; Python orchestrates, C++ owns all peers.

The fixture has 20 ~8MB and 20 ~32MB blocks of real UTXO-spending transactions.
Transactions use OP_TRUE outputs plus varied OP_RETURN data; this is a load
corpus, not a claim that its compression distribution models mainnet.
"""
import argparse, hashlib, json, math, os, pathlib, platform, resource, shutil, random, re
import subprocess, sys, time, urllib.request
from decimal import Decimal
ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'test'/'functional'))
from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import CBlock, CBlockHeader, CTransaction, CTxIn, CTxOut, COutPoint, FromHex, ser_compact_size
from test_framework.script import CScript, OP_TRUE, OP_RETURN

class RPC:
    def __init__(self, port): self.url=f'http://127.0.0.1:{port}'
    def __getattr__(self, method):
        def call(*params):
            body=json.dumps({'id':1,'method':method,'params':params}).encode()
            req=urllib.request.Request(self.url,body,{'Authorization':'Basic bjJuOm4ybjI='})
            try: response=urllib.request.urlopen(req,timeout=180)
            except urllib.error.HTTPError as e: response=e
            data=json.load(response,parse_float=Decimal)
            if data.get('error'): raise RuntimeError(data['error'])
            return data['result']
        return call

def save(path,value):
    path.write_text(json.dumps(value,indent=2)+'\n')

def start(args,data,tls=False):
    data.mkdir(parents=True,exist_ok=True)
    cmd=[str(args.daemon),f'-datadir={data}','-regtest','-server','-rpcuser=n2n','-rpcpassword=n2n2',f'-rpcport={args.rpcport}',f'-port={args.port}','-bind=127.0.0.1','-connect=0','-dnsseed=0','-discover=0','-maxconnections=600','-whitelist=noban,download@127.0.0.1','-excessiveblocksize=128000000','-blockmaxsize=128000000','-persistmempool=0','-printtoconsole=0']
    if args.independent_threshold is not None: cmd += [f'-p2pcompressoncethreshold={args.independent_threshold}']
    if args.debug_net: cmd += ['-debug=net']
    if tls: cmd += [f'-tlscert={args.output}/cert.pem',f'-tlskey={args.output}/key.pem']
    log=open(data/'process.log','w'); p=subprocess.Popen(cmd,stdout=log,stderr=subprocess.STDOUT)
    rpc=RPC(args.rpcport)
    for _ in range(1200):
        if p.poll() is not None: raise RuntimeError(f'node failed: {data}/process.log')
        try: rpc.getblockcount(); return p,rpc,cmd
        except Exception: time.sleep(.1)
    raise RuntimeError('node RPC timeout')

def stop(p,rpc):
    try: rpc.stop()
    except Exception: p.terminate()
    try: p.wait(timeout=120)
    except subprocess.TimeoutExpired: p.kill(); p.wait()

def fixture(args):
    directory=args.output/'fixture'; marker=directory/'fixture.json'
    if marker.exists(): return json.loads(marker.read_text())
    p,rpc,cmd=start(args,directory)
    try:
        # Mature independent OP_TRUE coinbases, not fake transaction payloads.
        existing=rpc.getblockcount(); prev=int(rpc.getblockhash(0),16); stamps=rpc.getblockheader(rpc.getblockhash(1))['time']-1 if existing else int(time.time())-1000
        random.seed(0)
        coinbases=[]
        for height in range(1,151):
            if height<=existing:
                block=FromHex(CBlock(),rpc.getblock(rpc.getblockhash(height),0)); cb=block.vtx[0]
            else:
                cb=create_coinbase(height); block=create_block(prev,cb,stamps+height); block.solve()
            result=rpc.submitblock(block.serialize().hex()) if height>existing else None
            if result is not None: raise RuntimeError(result)
            coinbases.append(cb); prev=block.hash_int
        receipts=[]
        progress=args.output/'fixture-progress.json'
        previous=json.loads(progress.read_text())['blocks'] if progress.exists() else []
        # ~1000/4000 actual spends per 8/32MB block, with unique 8KB data.
        # One fanout transaction + leaf spends, CTOR ordering handled by blocktools.
        for i in range(41):
            height=151+i
            if i<len(previous) and height<=existing:
                record=previous[i]
                if rpc.getblockhash(height)!=record['hash']: raise RuntimeError('fixture resume hash mismatch')
                receipts.append(record); prev=int(record['hash'],16); continue
            random.seed(height)
            target=8_000_000 if i<20 else 32_000_000
            count=1000 if target==8_000_000 else 4000
            cb_source=coinbases[i]
            fan=CTransaction(); fan.vin=[CTxIn(COutPoint(int(cb_source.txid_hex,16),0),b'')]
            value=cb_source.vout[0].nValue//(count+1)
            fan.vout=[CTxOut(value,CScript([OP_TRUE])) for _ in range(count)]
            txs=[fan]; fan_id=int(fan.txid_hex,16)
            padlen=target//count-85
            for j in range(count):
                tx=CTransaction(); tx.vin=[CTxIn(COutPoint(fan_id,j),b'')]
                # deterministic varied binary corpus, seed/hash explicitly recorded.
                pad=hashlib.shake_256(f'n2-load-v1/{i}/{j}'.encode()).digest(padlen)
                tx.vout=[CTxOut(value-1,CScript([OP_TRUE])),CTxOut(0,CScript([OP_RETURN,pad]))]
                txs.append(tx)
            height=151+i; cb=create_coinbase(height)
            block=create_block(prev,cb,stamps+height,txlist=txs); block.solve()
            raw=CBlockHeader.serialize(block)+ser_compact_size(len(block.vtx))+b''.join(tx.serialize() for tx in block.vtx)
            if i==40:
                (args.output/'relay-block.hex').write_text(raw.hex())
                relay={'hash':block.hash_hex,'bytes':len(raw),'height':height,'transactions':len(block.vtx)}
                break
            result=rpc.submitblock(raw.hex()) if height>existing else None
            if result is not None: raise RuntimeError(f'fixture block {i}: {result}')
            prev=block.hash_int
            receipts.append({'hash':block.hash_hex,'bytes':len(raw),'height':height,'transactions':len(block.vtx),'sha256':hashlib.sha256(raw).hexdigest()})
            save(args.output/'fixture-progress.json',{'blocks':receipts})
        # 40 large + 10 actual preceding small blocks = exactly 50 requested blocks.
        served=[rpc.getblockhash(h) for h in range(141,151)]+[b['hash'] for b in receipts]
        result={'version':1,'generator':'deterministic shake256 OP_RETURN corpus; real OP_TRUE UTXO spends','node_command':cmd,'blocks':receipts,'serve_hashes':served,'relay':relay,'tip':rpc.getbestblockhash()}
    finally: stop(p,rpc)
    save(marker,result)
    return result

def quantile(values,p):
    values=sorted(values)
    return values[min(len(values)-1,math.ceil(p*len(values))-1)] if values else None

def metrics(port):
    try:
        with urllib.request.urlopen(f'http://127.0.0.1:{port}/metrics',timeout=2) as response:
            return {'status':response.status,'body':response.read().decode()}
    except urllib.error.HTTPError as e: return {'status':e.code,'body':e.read().decode(errors='replace')}
    except Exception as e: return {'status':'unavailable','error':str(e)}

def swap_bytes():
    text=subprocess.check_output(['sysctl','-n','vm.swapusage'],text=True)
    return int(float(re.search(r'used = ([0-9.]+)M',text).group(1))*1024**2)

def sample_cpu(pid):
    return subprocess.run(['ps','-M','-p',str(pid),'-o','pid,%cpu,time,comm'],capture_output=True,text=True).stdout

def matrix(args,fx):
    records=[]
    for transport in args.transports.split(','):
        for n in [int(x) for x in args.peers.split(',')]:
            for scenario in args.scenarios.split(','):
                name=f'{transport}-{n}-{scenario}'; folder=args.output/name
                resultpath=folder/'result.json'
                if resultpath.exists() and json.loads(resultpath.read_text()).get('status')=='ok':
                    records.append(json.loads(resultpath.read_text())); continue
                if folder.exists(): folder.rename(args.output/f'{name}-previous-{time.time_ns()}')
                folder.mkdir()
                estimated=n*6*max(b['bytes'] for b in fx['blocks'])
                if estimated>args.max_rss_gib*1024**3:
                    result={'name':name,'status':'resource_blocked','transport':transport,'scenario':scenario,'peers':n,'resource_blocker':'preflight: retained full-frame buffers exceed shared-host memory budget','estimated_peak_bytes':estimated,'last_seconds':None,'first_seconds':None,'p50_seconds':None,'p99_seconds':None,'client_cpu_seconds':None,'received_bytes':0,'peak_combined_rss_bytes':0,'run_count':0}
                    save(resultpath,result); records.append(result); print(name,'resource_blocked (preflight)',flush=True); continue
                data=folder/'data'
                if not data.exists(): subprocess.run(['cp','-cR',str(args.output/'fixture'),str(data)],check=True)
                p,rpc,cmd=start(args,data,transport=='wss')
                client=None
                try:
                    metrics_before=metrics(args.rpcport)
                    network_before=rpc.getnetworkinfo().get('p2p_compress_once')
                    wire_before=rpc.getnettotals().get('websocket')
                    hashes=folder/'hashes.txt'; hashes.write_text('\n'.join(fx['serve_hashes']) if scenario=='serve' else '')
                    ready=folder/'ready'; ready.unlink(missing_ok=True)
                    clientjson=folder/'client.json'
                    clientcmd=[str(args.build/'src/bench/p2p-load'),f'{transport}://127.0.0.1:{args.port}/p2p/ws',str(n),'4',str(args.timeout),str(hashes),str(ready),str(clientjson)]
                    with open(folder/'client.log','w') as output: client=subprocess.Popen(clientcmd,stdout=output,stderr=subprocess.STDOUT)
                    samples=[]; begin=time.monotonic(); submitted=None; resource_blocker=None; swap_start=swap_bytes()
                    while client.poll() is None:
                        rss=subprocess.check_output(['ps','-o','rss=','-p',f'{p.pid},{client.pid}'],text=True)
                        rss_bytes=sum(int(v)*1024 for v in rss.split())
                        samples.append({'at_monotonic':time.monotonic(),'server':sample_cpu(p.pid),'client':sample_cpu(client.pid),'combined_rss_bytes':rss_bytes,'system_swap_bytes':swap_bytes()})
                        if rss_bytes>args.max_rss_gib*1024**3 or samples[-1]['system_swap_bytes']-swap_start>args.max_swap_growth_gib*1024**3:
                            resource_blocker=f'RSS budget ({args.max_rss_gib}GiB) or system swap growth ({args.max_swap_growth_gib}GiB) exceeded on shared host'
                            client.terminate(); client.wait(); break
                        if ready.exists() and scenario=='relay' and submitted is None:
                            submitted=time.monotonic_ns()//1000
                            response=rpc.submitblock((args.output/'relay-block.hex').read_text())
                            if response is not None: raise RuntimeError(response)
                        time.sleep(.25)
                    clientdata=json.loads(clientjson.read_text()) if clientjson.exists() else {}
                    save(folder/'cpu-samples.json',samples)
                    save(folder/'metrics.json',{'before':metrics_before,'after':metrics(args.rpcport),'compress_once_before':network_before,'compress_once_after':rpc.getnetworkinfo().get('p2p_compress_once'),'websocket_before':wire_before,'websocket_after':rpc.getnettotals().get('websocket')})
                    peers=clientdata.get('peers',[])
                    expected=50 if scenario=='serve' else 1
                    status='resource_blocked' if resource_blocker else 'ok' if client.returncode==0 and len(peers)==n and all(row['blocks']==expected for row in peers) else 'failed'
                    durations=[(row['last_us']-(row['request_us'] if scenario=='serve' else submitted))/1e6 for row in peers if row['last_us'] and (scenario=='serve' or submitted)]
                    bytes_total=sum(row['bytes'] for row in peers)
                    transfer_begin=min((row['request_us'] for row in peers if row['request_us']),default=submitted or 0)
                    transfer_end=max((row['last_us'] for row in peers),default=0)
                    transfer_seconds=(transfer_end-transfer_begin)/1e6 if transfer_begin and transfer_end else None
                    result={'name':name,'status':status,'transport':transport,'scenario':scenario,'peers':n,'expected_blocks_per_peer':expected,'completed_peers':sum(row['blocks']==expected for row in peers),'latency_sample_scope':'complete_cell' if status=='ok' else 'partial_only','node_command':cmd,'client_command':clientcmd,'executables':{str(binary):hashlib.sha256(binary.read_bytes()).hexdigest() for binary in [args.daemon,args.build/'src/bench/p2p-load']},'source_commit':subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True).strip(),'elapsed_wall_seconds':time.monotonic()-begin,'client_cpu_seconds':clientdata.get('client_cpu_seconds'),'first_seconds':min(durations) if durations else None,'p50_seconds':quantile(durations,.5),'p99_seconds':quantile(durations,.99),'last_seconds':max(durations) if durations else None,'received_bytes':bytes_total,'submitted_monotonic_us':submitted,'load_average':os.getloadavg(),'run_count':1,'throughput_MBps':bytes_total/1e6/transfer_seconds if status=='ok' and transfer_seconds and transfer_seconds>0 else None,'transfer_seconds':transfer_seconds,'peak_combined_rss_bytes':max((v['combined_rss_bytes'] for v in samples),default=0),'resource_blocker':resource_blocker,'client_detail':'client.json','server_client_cpu_samples':'cpu-samples.json'}
                    save(resultpath,result); records.append(result)
                    print(name,status,flush=True)
                finally:
                    if client and client.poll() is None: client.terminate(); client.wait()
                    stop(p,rpc)
                save(args.output/'matrix.json',{'machine':platform.platform(),'cpu':platform.processor(),'cpu_count':os.cpu_count(),'memory_bytes':int(subprocess.check_output(['sysctl','-n','hw.memsize'])),'source_commit':subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True).strip(),'load_average':os.getloadavg(),'run_count':1,'records':records,'limitations':['loopback CPU/scheduling, not WAN bandwidth','single-run baseline, no speedup inference','OP_RETURN-heavy real-transaction corpus; not mainnet compression distribution','no Linux/Windows/sanitizers']})
                lines=['| Transport | Peers | Scenario | Status | First s | p50 s | p99 s | Last s | Client CPU s |','|---|---:|---|---|---:|---:|---:|---:|---:|']
                for r in records: lines.append('| '+' | '.join(str(r.get(k)) for k in ['transport','peers','scenario','status','first_seconds','p50_seconds','p99_seconds','last_seconds','client_cpu_seconds'])+' |')
                (args.output/'MATRIX.md').write_text('\n'.join(lines)+'\n\nLoopback; one run per cell; baseline only. Server and client per-thread samples are recorded separately.\n')

    write_index(args)

def write_index(args):
    records=[]
    for path in args.output.glob('*/result.json'):
        record=json.loads(path.read_text())
        if path.parent.name != record['name']: continue  # archived attempts stay evidence, not duplicate cells
        records.append(record)
    records.sort(key=lambda r:(r['transport'],r['peers'],r['scenario']))
    machine={'os':platform.platform(),'cpu':subprocess.check_output(['sysctl','-n','machdep.cpu.brand_string'],text=True).strip(),'cpu_count':os.cpu_count(),'memory_bytes':int(subprocess.check_output(['sysctl','-n','hw.memsize']))}
    save(args.output/'matrix.json',{'machine':machine,'run_count_per_executed_cell':1,'records':records,'note':'One-run loopback baseline. Blocked cells have zero runs. Failed/partial latency samples are not complete-cell metrics; see raw receipts. Original failures and diagnostic attempts are retained.'})
    keys=['transport','peers','scenario','status','first_seconds','p50_seconds','p99_seconds','last_seconds','client_cpu_seconds']
    lines=['| Transport | Peers | Scenario | Status | First s | p50 s | p99 s | Last s | Client CPU s |','|---|---:|---|---|---:|---:|---:|---:|---:|']
    for r in records:
        row=[]
        for key in keys:
            value=r.get(key)
            if r['status']!='ok' and key.endswith('_seconds'): value=None
            row.append('—' if value is None else str(round(value,3)) if isinstance(value,float) else str(value))
        lines.append('| '+' | '.join(row)+' |')
    lines+=['','Loopback; one run per executed cell. Server/client per-thread samples are separate. Failed cells have no complete-cell latency result. Resource-blocked cases were not run to completion.','']
    (args.output/'MATRIX.md').write_text('\n'.join(lines))

def main():
    a=argparse.ArgumentParser(); a.add_argument('--build',type=pathlib.Path,required=True); a.add_argument('--daemon',type=pathlib.Path); a.add_argument('--native-fixture',action='store_true'); a.add_argument('--independent-threshold',type=int); a.add_argument('--output',type=pathlib.Path,required=True); a.add_argument('--peers',default='50,100,250,500'); a.add_argument('--transports',default='ws,wss'); a.add_argument('--scenarios',default='relay,serve'); a.add_argument('--timeout',type=int,default=600); a.add_argument('--rpcport',type=int,default=19482); a.add_argument('--port',type=int,default=19483); a.add_argument('--debug-net',action='store_true'); a.add_argument('--max-swap-growth-gib',type=float,default=2); a.add_argument('--max-rss-gib',type=float,default=24); a.add_argument('--fixture-only',action='store_true'); args=a.parse_args()
    args.daemon=args.daemon or (args.build/'src/lotusd' if (args.build/'src/lotusd').exists() else args.build/'src/bitcoind')
    args.output.mkdir(parents=True,exist_ok=True)
    soft,hard=resource.getrlimit(resource.RLIMIT_NOFILE); resource.setrlimit(resource.RLIMIT_NOFILE,(min(4096,hard),hard))
    if not (args.output/'cert.pem').exists(): subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(args.output/'key.pem'),'-out',str(args.output/'cert.pem'),'-subj','/CN=localhost','-days','2'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    save(args.output/'executables.json',{'source_commit':subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True).strip(),'binaries':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [args.daemon,args.build/'src/bench/p2p-load']},'build_type':'Release','chronik':False,'wallet':False})
    if args.native_fixture:
        from make_native_fixture import make_native_fixture
        fx=make_native_fixture(args,start,stop,save)
    else:
        fx=fixture(args)
    if not args.fixture_only: matrix(args,fx)
if __name__=='__main__': main()
