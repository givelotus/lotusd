# NNG Indexer Interface

This allows external indexers to be built efficiently using an easy to use NNG interface.

RPC messages are enabled using `-nngrpc=<url>`, where `<url>` should start with tcp:// for a TCP bind, and with ipc:// for a named pipe file.
Available RPC calls currently are:
 - `GetBlockRequest` to get an individual block
 - `GetBlockRangeRequest` to get a range of blocks
 - `GetBlockSliceRequest` to get a slice of a block
 - `GetUndoSliceRequest` to get a slice of the block undo data
 - `GetMempoolRequest` to get the node's mempool

Serialization of the objects transferred and further details are in [nng_interface.fbs](../src/nng_interface/nng_interface.fbs).

Likewise, PubSub messages are enabled using `-nngpub=<url>`, and `-nngpubmsg=<msg>`, where `<msg>` is the message to be enabled (can be supplied more than once) and must be one of:
 - `updateblktip` to notify when the tip moved to a new block hash, after (potentially) a chain of updates. Flatbuffers table is `UpdatedBlockTip`.
 - `mempooltxadd` to notify when a transaction has been added to the mempool. Flatbuffers table is `TransactionAddedToMempool`.
 - `mempooltxrem` to notify when a transaction has been removed from the mempool (e.g. block conflict). Flatbuffers table is `TransactionRemovedFromMempool`.
 - `blkconnected` to notify when a block connected to the chain. Flatbuffers table is `BlockConnected`.
 - `blkdisconctd` to notify when a block disconnected from the chain (e.g. reorg, invalidateblock). Flatbuffers table is `BlockDisconnected`.
 - `chainstflush` to nofity when the block database has been flushed to the disk. Flatbuffers table is `ChainStateFlushed`.

PubSub messages have their message type prepended as the first 12 bytes (0-padded if necessary), after that the message is encoded in the corresponding flatbuffers table (again, see [nng_interface.fbs](../src/nng_interface/nng_interface.fbs)).

## Example

A typical setup for indexers like Chronik would look like, in lotus.conf:

```
nngrpc=ipc://datadir/nngrpc.pipe
nngpub=ipc://datadir/nngpub.pipe
nngpubmsg=blkconnected
nngpubmsg=blkdisconctd
nngpubmsg=mempooltxadd
nngpubmsg=mempooltxrem
```

The same urls would then be specified in the indexer to connect the node to it.
