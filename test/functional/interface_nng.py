#!/usr/bin/env python3
# Copyright (c) 2021 Logos Foundation
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the NNG interface."""

from io import BytesIO
import asyncio

from test_framework.blocktools import create_block, create_coinbase, prepare_block, SUBSIDY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.messages import CTransaction, CTxIn, COutPoint, CTxOut, COIN, CBlockHeader
from test_framework.script import CScript, OP_HASH160, OP_EQUAL
from test_framework.txtools import pad_tx
from test_framework.util import assert_equal


RPC_URL = "tcp://127.0.0.1:52783"
PUB_URL = "tcp://127.0.0.1:52784"


def get_fb_bytes(obj, name):
    get_item = getattr(obj, name)
    get_length = getattr(obj, f'{name}Length')
    return bytes(get_item(i) for i in range(get_length()))


class NngInterfaceTest(BitcoinTestFramework):
    NUM_GENERATED_COINS = 10
    TIMESTAMP = 1630000000

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            f"-nngrpc={RPC_URL}",
            f"-nngpub={PUB_URL}",
            "-nngpubmsg=updateblktip",
            "-nngpubmsg=mempooltxadd",
            "-nngpubmsg=mempooltxrem",
            "-nngpubmsg=blkconnected",
            "-nngpubmsg=blkdisconctd",
            "-nngpubmsg=chainstflush",
            # Always expire after 1h
            "-mempoolexpiry=1",
        ]]
        self.coin_blocks = []

    def skip_test_if_missing_module(self):
        self.skip_if_no_py3_pynng()
        self.skip_if_no_py3_flatbuffers()
        self.skip_if_no_bitcoind_nng_interface()

    def run_test(self):
        self.burn_addr = self.nodes[0].decodescript('00')['p2sh']
        self.anyone_addr = self.nodes[0].decodescript('51')['p2sh']
        self.anyone_script = self.nodes[0].validateaddress(self.anyone_addr)['scriptPubKey']
        self.anyone_addr2 = self.nodes[0].decodescript('52')['p2sh']
        self.anyone_script2 = self.nodes[0].validateaddress(self.anyone_addr2)['scriptPubKey']
        asyncio.get_event_loop().run_until_complete(self._nng_test())

    async def _nng_test(self):
        import pynng, flatbuffers

        node = self.nodes[0]
        node.setmocktime(self.TIMESTAMP)
        with pynng.Req0() as rpc_sock:
            rpc_sock.dial(RPC_URL)
            await self._test_genesis(node, rpc_sock)
            await self._test_get_block_errors(rpc_sock)
            await self._test_get_block_slice_errors(rpc_sock)
            await self._test_send_tx(node, rpc_sock)
            await self._test_get_block_range(node, rpc_sock)
        with pynng.Sub0() as pub_sock:
            pub_sock.dial(PUB_URL)
            await self._test_update_chain_tip(node, pub_sock)
            await self._test_transaction_added_to_mempool(node, pub_sock)
            await self._test_transaction_removed_from_mempool_conflict(node, pub_sock)
            await self._test_transaction_removed_from_mempool_expiry(node, pub_sock)
            await self._test_block_connected(node, pub_sock)
            await self._test_block_disconnected(node, pub_sock)
            await self._test_chain_state_flushed(node, pub_sock)
        self._test_invalid_params(node)

    def _make_get_block_request_fbb(self, *, height=None, blockhash=None):
        from NngInterface import (
            RpcCall,
            RpcRequest,
            GetBlockRequest,
            BlockIdentifier,
            BlockHeight,
            BlockHash,
            Hash,
        )
        import flatbuffers
        fbb = flatbuffers.Builder()
        if height is not None:
            BlockHeight.Start(fbb)
            BlockHeight.AddHeight(fbb, height)
            block_height = BlockHeight.End(fbb)
            GetBlockRequest.Start(fbb)
            GetBlockRequest.AddBlockIdType(fbb, BlockIdentifier.BlockIdentifier.Height)
            GetBlockRequest.AddBlockId(fbb, block_height)
        else:
            BlockHash.Start(fbb)
            BlockHash.AddHash(fbb, Hash.CreateHash(fbb, blockhash))
            block_hash = BlockHash.End(fbb)
            GetBlockRequest.Start(fbb)
            GetBlockRequest.AddBlockIdType(fbb, BlockIdentifier.BlockIdentifier.Hash)
            GetBlockRequest.AddBlockId(fbb, block_hash)
        get_block_request = GetBlockRequest.End(fbb)
        RpcCall.Start(fbb)
        RpcCall.AddRpcType(fbb, RpcRequest.RpcRequest.GetBlockRequest)
        RpcCall.AddRpc(fbb, get_block_request)
        rpc = RpcCall.End(fbb)
        fbb.Finish(rpc)
        return bytes(fbb.Output())

    def _make_get_block_range_request_fbb(self, start_height, num_blocks):
        from NngInterface import (
            RpcCall,
            RpcRequest,
            GetBlockRangeRequest,
            BlockIdentifier,
            BlockHeight,
            BlockHash,
        )
        import flatbuffers
        fbb = flatbuffers.Builder()
        GetBlockRangeRequest.Start(fbb)
        GetBlockRangeRequest.AddStartHeight(fbb, start_height)
        GetBlockRangeRequest.AddNumBlocks(fbb, num_blocks)
        get_block_request = GetBlockRangeRequest.End(fbb)
        RpcCall.Start(fbb)
        RpcCall.AddRpcType(fbb, RpcRequest.RpcRequest.GetBlockRangeRequest)
        RpcCall.AddRpc(fbb, get_block_request)
        rpc = RpcCall.RpcCallEnd(fbb)
        fbb.Finish(rpc)
        return bytes(fbb.Output())

    def _make_get_block_slice_request_fbb(self, file_num, data_pos, num_bytes):
        from NngInterface import (
            RpcCall,
            RpcRequest,
            GetBlockSliceRequest,
        )
        import flatbuffers
        fbb = flatbuffers.Builder()
        GetBlockSliceRequest.Start(fbb)
        GetBlockSliceRequest.AddFileNum(fbb, file_num)
        GetBlockSliceRequest.AddDataPos(fbb, data_pos)
        GetBlockSliceRequest.AddNumBytes(fbb, num_bytes)
        get_block_slice_request = GetBlockSliceRequest.End(fbb)
        RpcCall.Start(fbb)
        RpcCall.AddRpcType(fbb, RpcRequest.RpcRequest.GetBlockSliceRequest)
        RpcCall.AddRpc(fbb, get_block_slice_request)
        rpc = RpcCall.End(fbb)
        fbb.Finish(rpc)
        return bytes(fbb.Output())

    def _make_get_undo_slice_request_fbb(self, file_num, undo_pos, num_bytes):
        from NngInterface import (
            RpcCall,
            RpcRequest,
            GetUndoSliceRequest,
        )
        import flatbuffers
        fbb = flatbuffers.Builder()
        GetUndoSliceRequest.Start(fbb)
        GetUndoSliceRequest.AddFileNum(fbb, file_num)
        GetUndoSliceRequest.AddUndoPos(fbb, undo_pos)
        GetUndoSliceRequest.AddNumBytes(fbb, num_bytes)
        get_undo_slice_request = GetUndoSliceRequest.End(fbb)
        RpcCall.Start(fbb)
        RpcCall.AddRpcType(fbb, RpcRequest.RpcRequest.GetUndoSliceRequest)
        RpcCall.AddRpc(fbb, get_undo_slice_request)
        rpc = RpcCall.End(fbb)
        fbb.Finish(rpc)
        return bytes(fbb.Output())

    def _make_get_mempool_request_fbs(self):
        from NngInterface import (
            RpcCall,
            RpcRequest,
            GetMempoolRequest,
        )
        import flatbuffers
        fbb = flatbuffers.Builder()
        GetMempoolRequest.Start(fbb)
        get_mempool_request = GetMempoolRequest.End(fbb)
        RpcCall.Start(fbb)
        RpcCall.AddRpcType(fbb, RpcRequest.RpcRequest.GetMempoolRequest)
        RpcCall.AddRpc(fbb, get_mempool_request)
        rpc = RpcCall.End(fbb)
        fbb.Finish(rpc)
        return bytes(fbb.Output())

    async def _send_request(self, rpc_sock, request, *, timeout=1):
        await asyncio.wait_for(rpc_sock.asend(request), timeout=timeout)

    async def _recv_response(self, rpc_sock, *, expect_error=None, timeout=1):
        from NngInterface import RpcResult
        response_msg = await asyncio.wait_for(rpc_sock.arecv_msg(), timeout=timeout)
        result = RpcResult.RpcResult.GetRootAs(response_msg.bytes, 0)
        if expect_error is not None:
            assert not result.IsSuccess()
            assert_equal(result.ErrorMsg().decode(), expect_error)
        else:
            assert result.IsSuccess(), f"Unexpected error: {result.ErrorMsg().decode()}"
            return get_fb_bytes(result, 'Data')

    def _get_utxo(self, node):
        blockhash = self.coin_blocks.pop(0)
        coinbase_tx = node.getblock(blockhash, 2)['tx'][0]
        vout = 1
        value = int(coinbase_tx['vout'][vout]['value'] * COIN)
        return COutPoint(int(coinbase_tx['txid'], 16), vout), value

    def _create_block(self, node):
        bestblockhash = node.getbestblockhash()
        bestblock = node.getblock(bestblockhash)
        new_height = bestblock['height'] + 1
        coinbase = create_coinbase(new_height)
        coinbase.vout[1].scriptPubKey = CScript([OP_HASH160, bytes(20), OP_EQUAL])
        return create_block(
            int(bestblock['hash'], 16), coinbase, new_height, bestblock['time'] + 1)

    async def _check_block_slice(self, rpc_sock, block_file_num, tx_data_pos, tx_raw):
        from NngInterface import GetBlockSliceResponse
        await self._send_request(
            rpc_sock, self._make_get_block_slice_request_fbb(block_file_num, tx_data_pos, len(tx_raw)))
        response = await self._recv_response(rpc_sock)
        response = GetBlockSliceResponse.GetBlockSliceResponse.GetRootAs(response, 0)
        assert_equal(get_fb_bytes(response, 'Data').hex(), tx_raw.hex())

    async def _check_undo_slice(self, rpc_sock, block_file_num, tx_undo_pos, coins_raw):
        from NngInterface import GetUndoSliceResponse
        await self._send_request(
            rpc_sock, self._make_get_undo_slice_request_fbb(block_file_num, tx_undo_pos, len(coins_raw)))
        response = await self._recv_response(rpc_sock)
        response = GetUndoSliceResponse.GetUndoSliceResponse.GetRootAs(response, 0)
        assert_equal(get_fb_bytes(response, 'Data').hex(), coins_raw.hex())

    async def _test_genesis(self, node, rpc_sock):
        from NngInterface import GetBlockResponse
        # Assert genesis block matches RPC's
        rpc_genesis_blockhash = node.getblockhash(0)
        rpc_genesis_block = node.getblock(rpc_genesis_blockhash, 2)

        # Test for using both height and blockhash as reference
        for params in [{'height': 0}, {'blockhash': bytes.fromhex(rpc_genesis_blockhash)[::-1]}]:
            # Test GetBlock
            await self._send_request(rpc_sock, self._make_get_block_request_fbb(**params))
            response = await self._recv_response(rpc_sock)
            response = GetBlockResponse.GetBlockResponse.GetRootAs(response, 0)
            block = response.Block()
            block_header = block.Header()
            header = CBlockHeader()
            header.deserialize(BytesIO(get_fb_bytes(block_header, 'Raw')))
            header.rehash()
            assert_equal(header.hash, rpc_genesis_blockhash)
            assert_equal(bytes(block_header.PrevBlockHash().Hash().Data())[::-1].hex(), '0'*64)
            assert_equal(bytes(block_header.BlockHash().Hash().Data())[::-1].hex(), rpc_genesis_blockhash)
            assert_equal(block_header.Timestamp(), rpc_genesis_block['time'])
            assert_equal('%08x' % block_header.NBits(), rpc_genesis_block['bits'])
            assert_equal(block.MetadataLength(), 0)
            assert_equal(block.TxsLength(), 1)
            block_tx = block.Txs(0)
            tx_raw = get_fb_bytes(block_tx.Tx(), 'Raw')
            assert_equal(tx_raw.hex(), rpc_genesis_block['tx'][0]['hex'])
            assert_equal(bytes(block_tx.Tx().Txid().Hash().Data())[::-1].hex(),
                         rpc_genesis_block['tx'][0]['txid'])
            assert_equal(block.FileNum(), 0)
            assert_equal(block.DataPos(), 8)
            assert_equal(block_tx.DataPos(), 170)
            assert_equal(block_tx.UndoPos(), 0)
            assert_equal(block_tx.Tx().SpentCoinsLength(), 0)
            await self._check_block_slice(rpc_sock, block.FileNum(), block_tx.DataPos(), tx_raw)

    async def _test_get_block_errors(self, rpc_sock):
        # Clean chain -> block 1 doesn't exist
        await self._send_request(rpc_sock, self._make_get_block_request_fbb(height=1))
        await self._recv_response(rpc_sock, expect_error='Block not found')
        # blockhash doesn't exist
        await self._send_request(rpc_sock, self._make_get_block_request_fbb(blockhash=bytes(32)))
        await self._recv_response(rpc_sock, expect_error='Block not found')
        # invalid fb
        await self._send_request(rpc_sock, bytes(31))
        await self._recv_response(rpc_sock, expect_error='Invalid flatbuffer encoding')

    async def _test_get_block_slice_errors(self, rpc_sock):
        # file_num doesn't exist
        await self._send_request(rpc_sock, self._make_get_block_slice_request_fbb(1, 0, 10))
        await self._recv_response(rpc_sock, expect_error='Invalid block slice')
        # data_pos out of bounds
        await self._send_request(rpc_sock, self._make_get_block_slice_request_fbb(1, 1000, 10))
        await self._recv_response(rpc_sock, expect_error='Invalid block slice')
        # num_bytes too long
        await self._send_request(rpc_sock, self._make_get_block_slice_request_fbb(1, 0, 1000))
        await self._recv_response(rpc_sock, expect_error='Invalid block slice')

    async def _test_send_tx(self, node, rpc_sock):
        from NngInterface import (
            GetBlockResponse,
            GetMempoolResponse,
        )
        # Generate block and query it
        hashes = node.generatetoaddress(self.NUM_GENERATED_COINS, self.anyone_addr)
        self.coin_blocks = hashes[1:]
        blockhash = bytes.fromhex(hashes[0])[::-1]

        await self._send_request(rpc_sock, self._make_get_block_request_fbb(blockhash=blockhash))
        response = await self._recv_response(rpc_sock)
        response = GetBlockResponse.GetBlockResponse.GetRootAs(response, 0)
        block = response.Block()
        header = CBlockHeader()
        header.deserialize(BytesIO(get_fb_bytes(block.Header(), 'Raw')))
        header.rehash()
        assert_equal(header.hash, blockhash[::-1].hex())
        assert_equal(bytes(block.Header().BlockHash().Hash().Data())[::-1].hex(),
                     blockhash[::-1].hex())
        assert_equal(block.MetadataLength(), 0)
        assert_equal(block.TxsLength(), 1)
        tx_raw = get_fb_bytes(block.Txs(0).Tx(), 'Raw')
        coinbase_tx = CTransaction()
        coinbase_tx.deserialize(BytesIO(tx_raw))
        coinbase_tx.rehash()
        assert_equal(block.FileNum(), 0)
        assert_equal(block.Txs(0).DataPos(), 557)
        assert_equal(block.Txs(0).UndoPos(), 0)
        assert_equal(block.Txs(0).UndoSize(), 0)
        await self._check_block_slice(rpc_sock, block.FileNum(), block.Txs(0).DataPos(), tx_raw)

        # Mature coinbase tx
        node.generatetoaddress(100, self.burn_addr)

        # Create valid tx
        coinbase_value = coinbase_tx.vout[1].nValue
        tx = CTransaction()
        tx.vin.append(
            CTxIn(COutPoint(coinbase_tx.txid, 1), CScript([b'\x51'])))
        tx.vout.append(CTxOut(coinbase_value - 1000, CScript.fromhex(self.anyone_script2)))
        pad_tx(tx)

        # Query mempool -> is empty
        assert_equal(node.getrawmempool(), [])
        await self._send_request(rpc_sock, self._make_get_mempool_request_fbs())
        response = await self._recv_response(rpc_sock)
        response = GetMempoolResponse.GetMempoolResponse.GetRootAs(response, 0)
        assert_equal(response.TxsLength(), 0)

        # Broadcast tx
        node.sendrawtransaction(tx.serialize().hex())
        # Mempool now has tx
        assert_equal(node.getrawmempool(), [tx.txid_hex])
        await self._send_request(rpc_sock, self._make_get_mempool_request_fbs())
        response = await self._recv_response(rpc_sock)
        response = GetMempoolResponse.GetMempoolResponse.GetRootAs(response, 0)
        assert_equal(response.TxsLength(), 1)
        assert_equal(get_fb_bytes(response.Txs(0).Tx(), 'Raw').hex(), tx.serialize().hex())
        assert_equal(response.Txs(0).Tx().SpentCoinsLength(), 1)
        spent_coin = response.Txs(0).Tx().SpentCoins(0)
        assert_equal(spent_coin.TxOut().Amount(), coinbase_value)
        assert_equal(get_fb_bytes(spent_coin.TxOut(), 'Script').hex(), self.anyone_script)
        assert_equal(spent_coin.IsCoinbase(), True)
        assert_equal(spent_coin.Height(), 1)
        assert_equal(response.Txs(0).Time(), self.TIMESTAMP)

        # add 1 more tx for undo data calc
        p2sh_script = CScript([OP_HASH160, bytes(20), OP_EQUAL])
        other_tx = CTransaction()
        other_tx.vin.append(CTxIn(COutPoint(tx.txid, 0), CScript([b'\x52']), 0xffff_ffff))
        other_tx.vout.append(CTxOut(coinbase_value - 2000, p2sh_script))
        pad_tx(other_tx)
        # grind txid to be higher than tx (for CTOR)
        while other_tx.txid < tx.txid:
            other_tx.nLockTime += 1
            other_tx.rehash()
        node.sendrawtransaction(other_tx.serialize().hex())

        await self._send_request(rpc_sock, self._make_get_mempool_request_fbs())
        response = await self._recv_response(rpc_sock)
        response = GetMempoolResponse.GetMempoolResponse.GetRootAs(response, 0)
        assert_equal(response.TxsLength(), 2)
        other_tx_fbb = [
            response.Txs(i)
            for i in range(0, 2)
            if bytes(response.Txs(i).Tx().Txid().Hash().Data()[::-1]).hex() == other_tx.txid_hex
        ][0]
        assert_equal(get_fb_bytes(other_tx_fbb.Tx(), 'Raw').hex(), other_tx.serialize().hex())
        assert_equal(other_tx_fbb.Tx().SpentCoinsLength(), 1)
        spent_coin = other_tx_fbb.Tx().SpentCoins(0)
        assert_equal(spent_coin.TxOut().Amount(), coinbase_value - 1000)
        assert_equal(get_fb_bytes(spent_coin.TxOut(), 'Script').hex(), self.anyone_script2)
        assert_equal(spent_coin.IsCoinbase(), False)
        assert_equal(spent_coin.Height(), -1)
        assert_equal(other_tx_fbb.Time(), self.TIMESTAMP)

        # Mine tx
        hashes = node.generatetoaddress(1, self.burn_addr)
        # Mempool empty again
        assert_equal(node.getrawmempool(), [])
        await self._send_request(rpc_sock, self._make_get_mempool_request_fbs())
        response = await self._recv_response(rpc_sock)
        response = GetMempoolResponse.GetMempoolResponse.GetRootAs(response, 0)
        assert_equal(response.TxsLength(), 0)

        # Block contains tx
        blockhash = bytes.fromhex(hashes[0])[::-1]
        await self._send_request(rpc_sock, self._make_get_block_request_fbb(blockhash=blockhash))
        response = await self._recv_response(rpc_sock)
        response = GetBlockResponse.GetBlockResponse.GetRootAs(response, 0)
        block = response.Block()
        assert_equal(bytes(response.Block().Header().BlockHash().Hash().Data())[::-1].hex(),
                     blockhash[::-1].hex())
        assert_equal(block.MetadataLength(), 0)
        assert_equal(block.TxsLength(), 3)
        assert_equal(block.FileNum(), 0)
        assert_equal(block.UndoPos(), 4518)
        assert_equal(block.Txs(0).DataPos(), 31561)
        assert_equal(block.Txs(0).UndoPos(), 0)
        assert_equal(block.Txs(0).UndoSize(), 0)
        assert_equal(block.Txs(1).DataPos(), 31673)
        assert_equal(block.Txs(1).UndoPos(), 4519)
        assert_equal(block.Txs(1).UndoSize(), 26)
        assert_equal(block.Txs(2).DataPos(), 31774)
        assert_equal(block.Txs(2).UndoPos(), 4519 + 26)
        assert_equal(block.Txs(2).UndoSize(), 29)
        tx0_raw = get_fb_bytes(block.Txs(0).Tx(), 'Raw')
        tx1_raw = get_fb_bytes(block.Txs(1).Tx(), 'Raw')
        tx2_raw = get_fb_bytes(block.Txs(2).Tx(), 'Raw')
        assert_equal(tx1_raw.hex(), tx.serialize().hex())
        assert_equal(bytes(block.Txs(1).Tx().Txid().Hash().Data())[::-1].hex(), tx.txid_hex)
        assert_equal(tx2_raw.hex(), other_tx.serialize().hex())
        assert_equal(bytes(block.Txs(2).Tx().Txid().Hash().Data())[::-1].hex(), other_tx.txid_hex)
        await self._check_block_slice(rpc_sock, block.FileNum(), block.Txs(0).DataPos(), tx0_raw)
        await self._check_block_slice(rpc_sock, block.FileNum(), block.Txs(1).DataPos(), tx1_raw)
        # encoding: CompactSize(numInputs)
        #           | VarInt(heightAndIsCoinbase)
        #           | dummy byte
        #           | VarInt(CompressAmount(50_000_000_00))
        #           | CompressScript(script)
        undo_data = bytes.fromhex('010300806e01da1745e9b549bd0bfa1a569971c77eba30cd5a4b')
        await self._check_undo_slice(rpc_sock, block.FileNum(), block.Txs(1).UndoPos(), undo_data)
        undo_data = bytes.fromhex('01805e00808de81a0169d7ef8f42a25e8791bb37d5fb48456f10')
        await self._check_undo_slice(rpc_sock, block.FileNum(), block.Txs(2).UndoPos(), undo_data)
        
        assert_equal(block.Txs(1).Tx().SpentCoinsLength(), 1)
        spent_coin = block.Txs(1).Tx().SpentCoins(0)
        assert_equal(spent_coin.TxOut().Amount(), int(SUBSIDY * COIN))
        assert_equal(get_fb_bytes(spent_coin.TxOut(), 'Script').hex(), self.anyone_script)
        assert_equal(spent_coin.IsCoinbase(), True)
        assert_equal(spent_coin.Height(), 1)

        assert_equal(block.Txs(2).Tx().SpentCoinsLength(), 1)
        spent_coin = block.Txs(2).Tx().SpentCoins(0)
        assert_equal(spent_coin.TxOut().Amount(), int(SUBSIDY * COIN) - 1000)
        assert_equal(get_fb_bytes(spent_coin.TxOut(), 'Script').hex(), self.anyone_script2)
        assert_equal(spent_coin.IsCoinbase(), False)
        assert_equal(spent_coin.Height(), 111)

    async def _test_get_block_range(self, node, rpc_sock):
        from NngInterface import GetBlockRangeResponse
        for start_height, num_blocks in [(0, 10), (10, 30), (100, 5)]:
            await self._send_request(rpc_sock, self._make_get_block_range_request_fbb(start_height, num_blocks))
            response = await self._recv_response(rpc_sock)
            response = GetBlockRangeResponse.GetBlockRangeResponse.GetRootAs(response, 0)
            assert_equal(response.BlocksLength(), num_blocks)
            for idx in range(num_blocks):
                block_hash = node.getblockhash(start_height + idx)
                block = response.Blocks(idx)
                assert_equal(bytes(block.Header().BlockHash().Hash().Data())[::-1].hex(), block_hash)
        # negative index -> empty list
        await self._send_request(rpc_sock, self._make_get_block_range_request_fbb(-1, 4))
        response = await self._recv_response(rpc_sock)
        response = GetBlockRangeResponse.GetBlockRangeResponse.GetRootAs(response, 0)
        assert_equal(response.BlocksLength(), 0)
        # too many blocks -> rest cut off
        await self._send_request(rpc_sock, self._make_get_block_range_request_fbb(100, 30))
        response = await self._recv_response(rpc_sock)
        response = GetBlockRangeResponse.GetBlockRangeResponse.GetRootAs(response, 0)
        assert_equal(response.BlocksLength(), 12)

    async def _recv_message(self, pub_sock, expected_msg_type, timeout=2):
        received_msg = await asyncio.wait_for(pub_sock.arecv_msg(), timeout=timeout)
        actual_msg_type = received_msg.bytes[:12]
        assert_equal(actual_msg_type.decode(), expected_msg_type)
        return received_msg.bytes[12:]

    async def _check_timeout(self, fut, timeout=0.1):
        try:
            await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            pass
        else:
            raise AssertionError("Future didn't timeout")

    async def _test_update_chain_tip(self, node, pub_sock):
        from NngInterface.UpdatedBlockTip import UpdatedBlockTip
        pub_sock.subscribe('updateblktip')
        hashes = node.generatetoaddress(1, self.burn_addr)
        msg = await self._recv_message(pub_sock, 'updateblktip')
        msg = UpdatedBlockTip.GetRootAs(msg, 0)
        assert_equal(bytes(msg.BlockHash().Hash().Data())[::-1].hex(), hashes[0])
        pub_sock.unsubscribe('updateblktip')

    async def _test_transaction_added_to_mempool(self, node, pub_sock):
        from NngInterface.TransactionAddedToMempool import TransactionAddedToMempool
        pub_sock.subscribe('mempooltxadd')
        tx = CTransaction()
        outpoint, value = self._get_utxo(node)
        tx.vin.append(
            CTxIn(outpoint, CScript([b'\x51'])))
        tx.vout.append(CTxOut(value - 1000, CScript([OP_HASH160, bytes(20), OP_EQUAL])))
        pad_tx(tx)
        node.sendrawtransaction(tx.serialize().hex())
        msg = await self._recv_message(pub_sock, 'mempooltxadd')
        msg = TransactionAddedToMempool.GetRootAs(msg, 0)
        assert_equal(get_fb_bytes(msg.MempoolTx().Tx(), 'Raw').hex(), tx.serialize().hex())
        assert_equal(bytes(msg.MempoolTx().Tx().Txid().Hash().Data())[::-1].hex(), tx.txid_hex)
        assert_equal(msg.MempoolTx().Time(), self.TIMESTAMP)
        assert_equal(msg.MempoolTx().Tx().SpentCoinsLength(), 1)
        spent_coins = msg.MempoolTx().Tx().SpentCoins(0)
        assert_equal(spent_coins.TxOut().Amount(), int(SUBSIDY * COIN))
        assert_equal(get_fb_bytes(spent_coins.TxOut(), 'Script').hex(), self.anyone_script)
        assert_equal(spent_coins.IsCoinbase(), True)
        assert_equal(spent_coins.Height(), 2)
        pub_sock.unsubscribe('mempooltxadd')

    async def _test_transaction_removed_from_mempool_conflict(self, node, pub_sock):
        from NngInterface.TransactionRemovedFromMempool import TransactionRemovedFromMempool
        pub_sock.subscribe('mempooltxrem')
        node.generatetoaddress(1, self.burn_addr)  # empty out mempool from previous test
        await self._check_timeout(pub_sock.arecv_msg(), timeout=0.1) # should not send an eviction message
        assert_equal(node.getrawmempool(), []) # mempool should be empty
        tx = CTransaction()
        outpoint, value = self._get_utxo(node)
        tx.vin.append(CTxIn(outpoint, CScript([b'\x51'])))
        tx.vout.append(CTxOut(value - 1000, CScript([OP_HASH160, bytes(20), OP_EQUAL])))
        pad_tx(tx)
        conflicted_txid = node.sendrawtransaction(tx.serialize().hex())
        tx.vout[0].nValue -= 1 # tweak transaction
        tx.rehash()
        assert conflicted_txid != tx.txid_hex
        block = self._create_block(node)
        block.vtx.append(tx)
        prepare_block(block)
        assert_equal(node.submitblock(block.serialize().hex()), None)
        msg = await self._recv_message(pub_sock, 'mempooltxrem', timeout=5)
        msg = TransactionRemovedFromMempool.GetRootAs(msg, 0)
        txid = bytes(msg.Txid().Hash().Data())[::-1].hex()
        assert_equal(txid, conflicted_txid)
        assert_equal(node.getrawmempool(), [])
        pub_sock.unsubscribe('mempooltxrem')

    async def _test_transaction_removed_from_mempool_expiry(self, node, pub_sock):
        from NngInterface.TransactionRemovedFromMempool import TransactionRemovedFromMempool
        pub_sock.subscribe('mempooltxrem')
        node.generatetoaddress(1, self.burn_addr)  # empty out mempool from previous test
        await self._check_timeout(pub_sock.arecv_msg(), timeout=0.1) # should not send an eviction message
        assert_equal(node.getrawmempool(), []) # mempool should be empty
        tx = CTransaction()
        outpoint, value = self._get_utxo(node)
        tx.vin.append(CTxIn(outpoint, CScript([b'\x51'])))
        tx.vout.append(CTxOut(value - 1000, CScript([OP_HASH160, bytes(20), OP_EQUAL])))
        pad_tx(tx)
        txhash = node.sendrawtransaction(tx.serialize().hex())
        entry_time = node.getmempoolentry(txhash)['time']
        node.setmocktime(entry_time + 3605)
        tx_notify = CTransaction()
        outpoint, value = self._get_utxo(node)
        tx_notify.vin.append(CTxIn(outpoint, CScript([b'\x51'])))
        tx_notify.vout.append(CTxOut(value - 1000, CScript([OP_HASH160, bytes(20), OP_EQUAL])))
        pad_tx(tx_notify)
        node.sendrawtransaction(tx_notify.serialize().hex())
        msg = await self._recv_message(pub_sock, 'mempooltxrem', timeout=5)
        msg = TransactionRemovedFromMempool.GetRootAs(msg, 0)
        assert_equal(bytes(msg.Txid().Hash().Data())[::-1].hex(), tx.txid_hex)
        assert_equal(node.getrawmempool(), [tx_notify.txid_hex])
        pub_sock.unsubscribe('mempooltxrem')

    async def _test_block_connected(self, node, pub_sock):
        from NngInterface.BlockConnected import BlockConnected
        pub_sock.subscribe('blkconnected')
        tx = CTransaction()
        outpoint, value = self._get_utxo(node)
        tx.vin.append(CTxIn(outpoint, CScript([b'\x51'])))
        tx.vout.append(CTxOut(value - 1000, CScript([OP_HASH160, bytes(20), OP_EQUAL])))
        pad_tx(tx)
        txid = node.sendrawtransaction(tx.serialize().hex())
        block = self._create_block(node)
        block.vtx.append(tx)
        prepare_block(block)
        assert_equal(node.submitblock(block.serialize().hex()), None)
        msg = await self._recv_message(pub_sock, 'blkconnected')
        msg = BlockConnected.GetRootAs(msg, 0)
        assert_equal(bytes(msg.Block().Header().BlockHash().Hash().Data())[::-1].hex(), block.hash)
        assert_equal(get_fb_bytes(msg.Block().Header(), 'Raw').hex(),
                     CBlockHeader(block).serialize().hex())
        assert_equal(msg.Block().MetadataLength(), 0)
        assert_equal(msg.Block().TxsLength(), 2)
        assert_equal(get_fb_bytes(msg.Block().Txs(1).Tx(), 'Raw').hex(), tx.serialize().hex())
        assert_equal(msg.Block().Txs(1).Tx().SpentCoinsLength(), 1)
        spent_coin = msg.Block().Txs(1).Tx().SpentCoins(0)
        assert_equal(spent_coin.TxOut().Amount(), int(SUBSIDY * COIN))
        assert_equal(get_fb_bytes(spent_coin.TxOut(), 'Script').hex(), self.anyone_script)
        assert_equal(spent_coin.IsCoinbase(), True)
        assert_equal(spent_coin.Height(), 6)
        assert_equal(msg.TxsConflictedLength(), 0)
        pub_sock.unsubscribe('blkconnected')

    async def _test_block_disconnected(self, node, pub_sock):
        from NngInterface.BlockDisconnected import BlockDisconnected
        pub_sock.subscribe('blkdisconctd')
        tip = node.getbestblockhash()
        tipblock = node.getblock(tip)
        reorged_blockhash = node.generatetoaddress(1, self.burn_addr)[0]
        block1 = create_block(
            int(tip, 16),
            create_coinbase(tipblock['height'] + 1, pubkey=b'\x03'*33),
            tipblock['height'] + 1,
            tipblock['time'] + 1,
        )
        prepare_block(block1)
        assert_equal(node.submitblock(block1.serialize().hex()), 'inconclusive')
        block2 = create_block(
            int(block1.hash, 16),
            create_coinbase(tipblock['height'] + 2, pubkey=b'\x03'*33),
            tipblock['height'] + 2,
            tipblock['time'] + 2,
        )
        prepare_block(block2)
        assert_equal(node.submitblock(block2.serialize().hex()), None)
        msg = await self._recv_message(pub_sock, 'blkdisconctd')
        msg = BlockDisconnected.GetRootAs(msg, 0)
        assert_equal(bytes(msg.Block().Header().BlockHash().Hash().Data())[::-1].hex(),
                     reorged_blockhash)
        assert_equal(msg.Block().TxsLength(), 2)
        spent_coin = msg.Block().Txs(1).Tx().SpentCoins(0)
        assert_equal(spent_coin.TxOut().Amount(), int(SUBSIDY * COIN))
        assert_equal(get_fb_bytes(spent_coin.TxOut(), 'Script').hex(), self.anyone_script)
        assert_equal(spent_coin.IsCoinbase(), True)
        assert_equal(spent_coin.Height(), 5)
        pub_sock.unsubscribe('blkdisconctd')

    async def _test_chain_state_flushed(self, node, pub_sock):
        from NngInterface.ChainStateFlushed import ChainStateFlushed
        pub_sock.subscribe('chainstflush')
        tip = node.getbestblockhash()
        node.gettxoutsetinfo() # forces chain flush
        msg = await self._recv_message(pub_sock, 'chainstflush')
        msg = ChainStateFlushed.GetRootAs(msg, 0)
        assert_equal(bytes(msg.BlockHash().Hash().Data())[::-1].hex(), tip)
        pub_sock.unsubscribe('chainstflush')

    def _test_invalid_params(self, node):
        self.stop_node(0)
        node.assert_start_raises_init_error(
            ["-nngrpc=a"], "Error: Failed listening on -nngrpc=a: Invalid argument")
        node.assert_start_raises_init_error(
            ["-nngpub=a"], "Error: Failed listening on -nngpub=a: Invalid argument")
        node.assert_start_raises_init_error(
            [f"-nngpub={PUB_URL}", "-nngpubmsg=a"], "Error: Invalid message type 'a' in -nngpubmsg.")

if __name__ == '__main__':
    NngInterfaceTest().main()
