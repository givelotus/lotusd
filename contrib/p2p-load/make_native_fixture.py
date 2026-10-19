#!/usr/bin/env python3
"""Native-V7 counterpart of the legacy networking corpus; not interchangeable.

Use the actual J3 MiniWallet and native miner for all transactions, commitments,
headers, state roots and proof of work. Burn-output padding is explicit corpus
construction, not a claim to represent mainnet compression.
"""
from copy import deepcopy
import hashlib
import json
import subprocess
from test_framework.wallet import MiniWallet
from test_framework.messages import _lotus_v2_encode_output, _lotus_v2_to_output


def make_corpus_transaction(wallet, utxo, block_index, number, template=None):
    """Reuse padding geometry while preserving the original native wire bytes.

    MiniWallet's generic target-size loop serializes the growing transaction on
    every added output. Size it once per funding block, then copy its burn
    outputs. Automatic-success inputs have no output signature to regenerate;
    canonicalize output scripts without computing an unused signing tree.
    """
    tx=wallet.create_self_transfer_multi(
        utxos_to_spend=[utxo],num_outputs=1,fee_per_output=100000,
        target_size=7800 if template is None else 0)['tx']
    if template is None:
        template=(deepcopy(tx.vout[1:]),len(tx.serialize()))
        if not template[0] or not all(output.nFlags & 2 for output in template[0]):
            raise RuntimeError('native padding template contains spendable outputs')
    else:
        tx.vout.extend(deepcopy(template[0]))
    if any(txin.vWitnesses != [(b'\x4e',[],[])] for txin in tx.vin):
        raise RuntimeError('corpus padding fast path requires automatic-success witnesses')
    for output_index,output in enumerate(tx.vout):
        if output.nFlags & 2:
            output.vBranches=[hashlib.sha256(f'n2-native/{block_index}/{number}/{output_index}'.encode()).digest()]
        output.scriptPubKey=_lotus_v2_encode_output(_lotus_v2_to_output(output))
    encoded=tx.serialize()
    if len(encoded)!=template[1] or not encoded.startswith(b'\x07\x00\x00\x00'):
        raise RuntimeError('native padding template changed wire geometry')
    return encoded.hex(),template


def make_native_fixture(args, start, stop, save):
    directory=args.output/'fixture'; marker=directory/'fixture.json'
    if marker.exists():
        data=json.loads(marker.read_text())
        if data.get('consensus')!='native_v7': raise RuntimeError('refusing legacy corpus for native V2')
        if not (args.output/'relay-block.hex').exists(): raise RuntimeError('native fixture missing validated relay candidate')
        return data
    # An incomplete native generation must be resumed deliberately from its
    # recorded exact state, never silently reused with different random values.
    if (directory/'regtest'/'chainstate').exists():
        raise RuntimeError('partial native fixture exists; preserve evidence and choose a fresh output')
    p,rpc,command=start(args,directory)
    try:
        rpc.generatetodescriptor(150,'raw(4e)')
        wallet=MiniWallet(rpc)
        bank=wallet.get_utxos(confirmed_only=True)
        if len(bank)<41: raise RuntimeError(f'not enough mature native coinbases: {len(bank)}')
        large=[]; funding=[]; pending=[]
        for block_index in range(41):
            count=1000 if block_index<20 else 4000
            source=bank[block_index]
            fan=wallet.create_self_transfer_multi(utxos_to_spend=[source],num_outputs=count,fee_per_output=1000)
            if fan['tx'].nVersion!=7: raise RuntimeError('MiniWallet emitted non-native fanout')
            rpc.sendrawtransaction(fan['hex'])
            fund_hash=rpc.generatetodescriptor(1,'raw(4e)')[0]; funding.append(fund_hash)
            transactions=[];padding_template=None
            for number,utxo in enumerate(fan['new_utxos']):
                encoded,padding_template=make_corpus_transaction(
                    wallet,utxo,block_index,number,padding_template)
                transactions.append(encoded)
            for at in range(0,len(transactions),50):
                result=rpc.submitrawtxbatch(transactions[at:at+50])
                if not result.get('accepted'): raise RuntimeError({'native_batch_rejected':result,'block':block_index,'offset':at})
            if rpc.getmempoolinfo()['size']!=count: raise RuntimeError('native mempool count mismatch')
            if block_index==40:
                # Freeze the fixture before mining, preserving exact candidate
                # transactions separately. A clone mines them once to obtain
                # a consensus-valid 134-byte-header relay block, then submits
                # those bytes to untouched fixture clones.
                pending=transactions
                break
            block_hash=rpc.generatetodescriptor(1,'raw(4e)')[0]
            raw=bytes.fromhex(rpc.getblock(block_hash,0)); verbose=rpc.getblock(block_hash,1)
            if rpc.getmempoolinfo()['size']!=0: raise RuntimeError('native miner did not include entire target block')
            if len(verbose['tx'])!=count+1: raise RuntimeError('native block transaction count mismatch')
            large.append({'hash':block_hash,'bytes':len(raw),'transactions':count+1,'height':verbose['height'],'sha256':hashlib.sha256(raw).hexdigest()})
            save(args.output/'native-fixture-progress.json',{'blocks':large,'funding':funding})
        save(args.output/'native-relay-transactions.json',pending)
        fixture={'consensus':'native_v7','generator':'J3 MiniWallet automatic-success spends with varied native burn commitments','node_command':command,'blocks':large,'serve_hashes':funding[:10]+[b['hash'] for b in large],'tip':rpc.getbestblockhash(),'relay_pending_file':'native-relay-transactions.json','relay':{'bytes':32_000_000,'note':'upper-bound sizing until exact candidate mined on disposable clone'}}
    finally: stop(p,rpc)
    save(marker,fixture)
    candidate=args.output/'relay-builder'
    if candidate.exists(): raise RuntimeError('relay-builder exists; preserve and choose fresh native output')
    subprocess.run(['cp','-cR',str(directory),str(candidate)],check=True)
    p,rpc,_=start(args,candidate)
    try:
        for at in range(0,len(pending),50):
            result=rpc.submitrawtxbatch(pending[at:at+50])
            if not result.get('accepted'): raise RuntimeError({'relay_candidate_rejected':result})
        block_hash=rpc.generatetodescriptor(1,'raw(4e)')[0]
        if rpc.getmempoolinfo()['size']!=0: raise RuntimeError('relay candidate incomplete')
        raw=bytes.fromhex(rpc.getblock(block_hash,0))
        (args.output/'relay-block.hex').write_text(raw.hex())
        fixture['relay']={'hash':block_hash,'bytes':len(raw),'transactions':len(pending)+1,'sha256':hashlib.sha256(raw).hexdigest()}
        fixture['relay_candidate_verifychain']=rpc.verifychain(4,1)
        save(marker,fixture)
    finally: stop(p,rpc)
    return fixture
