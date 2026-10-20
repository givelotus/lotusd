# Built-in mining pool

The pool is compiled into the daemon and starts during node initialization when
RPC service is enabled (`-server=1`). It is enabled by default in that mode;
`miningpool=0` in the configuration file or `-miningpool=0` disables it. A
P2P-only node does not create a pool. The existing RPC listener access controls
and public-listener route restrictions also apply to the pool HTTP routes;
this change does not add public access or additional authentication.

Each node owns a separate pool manager. RPC and HTTP handlers retain that node's
manager throughout each request, including long polling. Shutdown rejects new
job/share work, cancels RPC waits, drains handlers and active pool operations,
then releases chainstate. A manager cannot be restarted after interruption;
node startup creates a new one.

The default PPLNS window is **1000 shares**, configurable with
`-poolpplnswindow`. Pool jobs, workers, accepted-share history, and counters are
in memory and reset on restart. Persistent pool state is deferred.

Pool state and configuration are protected by the manager mutex. Share nonce
deduplication, PPLNS accounting and the block-submission claim happen under that
mutex. Block validation runs after releasing it; shutdown waits for validation
to finish before releasing node dependencies. Statistics return copies rather
than references to mutable worker/job state. Startup and final shutdown are
serialized by the node lifecycle; concurrently invoking startup twice is not a
supported API. Test-only Reset requires no active job/share operation.
