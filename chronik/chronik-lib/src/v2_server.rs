//! Explicit V2 HTTP listener lifecycle and coherent nonblocking authority reads.
use chronik_db::v2_branch::{Anchor, V2Db};
use chronik_http::v2::{self, AuthoritativeState, V2HttpState};
use std::{
    net::{SocketAddr, TcpListener},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread::JoinHandle,
};
use tokio::sync::oneshot;

/// Native reconciliation stamp: service binding is immutable; these values must
/// cover every native mutation/recovery boundary, including same-anchor ABA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeContext {
    anchor: Anchor,
    context_generation: u64,
    chain_revision: u64,
}
#[derive(Debug, Default)]
struct Publication {
    context: Option<NativeContext>,
}
enum Update {
    Suspend,
    Invalidate,
    Publish(Anchor),
    Context(NativeContext),
}
/// Authority has independent counters: observation fences every busy/publication
/// boundary; generation versions durable observations and explorer continuations.
/// A complete idle suspend/resume retains generation only with an exact native
/// context stamp. Neither counter wraps, and terminal failure stays unknown.
#[derive(Debug)]
pub struct Authority {
    writer: Mutex<Publication>,
    sequence: AtomicU64,
    generation: AtomicU64,
    height: AtomicU64,
    words: [AtomicU64; 4],
    known: AtomicU64,
}
impl Default for Authority {
    fn default() -> Self {
        Self {
            writer: Mutex::new(Publication::default()),
            sequence: AtomicU64::new(0),
            generation: AtomicU64::new(0),
            height: AtomicU64::new(0),
            words: std::array::from_fn(|_| AtomicU64::new(0)),
            known: AtomicU64::new(0),
        }
    }
}
impl Authority {
    fn terminal(&self) {
        self.known.store(0, Ordering::SeqCst);
        self.generation.store(u64::MAX, Ordering::SeqCst);
        self.sequence.store(u64::MAX, Ordering::SeqCst);
    }
    fn update(&self, update: Update) -> Result<u64, String> {
        let mut publication = match self.writer.lock() {
            Ok(writer) => writer,
            Err(_) => {
                self.terminal();
                return Err("authority lock poisoned".into());
            }
        };
        let previous = self.sequence.load(Ordering::SeqCst);
        let Some(next) = previous.checked_add(2).filter(|n| *n < u64::MAX)
        else {
            self.terminal();
            return Err("authority observation exhausted".into());
        };
        let generation = self.generation.load(Ordering::SeqCst);
        let (anchor, advance) = match &update {
            Update::Suspend => (None, false),
            Update::Invalidate => (None, true),
            Update::Publish(anchor) => (Some(*anchor), true),
            Update::Context(context) => {
                (Some(context.anchor), publication.context != Some(*context))
            }
        };
        let generation = if advance {
            let Some(next) =
                generation.checked_add(1).filter(|n| *n < u64::MAX)
            else {
                self.terminal();
                return Err("authority generation exhausted".into());
            };
            next
        } else {
            generation
        };
        self.sequence.store(previous + 1, Ordering::SeqCst);
        match update {
            Update::Context(context) => publication.context = Some(context),
            Update::Publish(_) => publication.context = None,
            Update::Suspend | Update::Invalidate => {}
        }
        self.known
            .store(u64::from(anchor.is_some()), Ordering::SeqCst);
        if let Some(anchor) = anchor {
            self.height.store(anchor.height, Ordering::SeqCst);
            for (word, bytes) in
                self.words.iter().zip(anchor.block_id.chunks_exact(8))
            {
                word.store(
                    u64::from_le_bytes(bytes.try_into().unwrap()),
                    Ordering::SeqCst,
                );
            }
        }
        self.generation.store(generation, Ordering::SeqCst);
        self.sequence.store(next, Ordering::SeqCst);
        Ok(generation)
    }
    /// Durable invalidation or generic publication; every call consumes a new
    /// generation. Generic publication cannot certify an unchanged native stamp.
    pub fn publish(&self, anchor: Option<Anchor>) -> Result<u64, String> {
        self.update(match anchor {
            Some(a) => Update::Publish(a),
            None => Update::Invalidate,
        })
    }
    /// Hide authority while native work runs. Even an idle tick changes the
    /// observation fence, so an in-flight request cannot span this boundary.
    pub fn suspend(&self) -> Result<u64, String> {
        self.update(Update::Suspend)
    }
    /// Publish only after native reconciliation validated this complete stamp.
    /// An exact unchanged stamp resumes the same durable snapshot generation.
    pub fn publish_context(
        &self,
        anchor: Anchor,
        context_generation: u64,
        chain_revision: u64,
    ) -> Result<u64, String> {
        self.update(Update::Context(NativeContext {
            anchor,
            context_generation,
            chain_revision,
        }))
    }
    /// Observe one coherent stamped authority state without acquiring any lock.
    /// A racing publication returns unknown rather than waiting on its writer.
    pub fn observe(&self) -> AuthoritativeState {
        let first = self.sequence.load(Ordering::SeqCst);
        if first % 2 != 0 {
            return AuthoritativeState {
                observation: first,
                generation: self.generation.load(Ordering::SeqCst),
                anchor: None,
            };
        }
        let generation = self.generation.load(Ordering::SeqCst);
        let known = self.known.load(Ordering::SeqCst) != 0;
        let height = self.height.load(Ordering::SeqCst);
        let mut block_id = [0; 32];
        for (bytes, word) in block_id.chunks_exact_mut(8).zip(&self.words) {
            bytes.copy_from_slice(&word.load(Ordering::SeqCst).to_le_bytes());
        }
        let last = self.sequence.load(Ordering::SeqCst);
        AuthoritativeState {
            observation: last,
            generation,
            anchor: if first == last && known {
                Some(Anchor { block_id, height })
            } else {
                None
            },
        }
    }
}
/// Explicitly started HTTP server. Drop requests shutdown and joins its thread.
#[derive(Debug)]
pub struct V2Server {
    address: String,
    running:
        Mutex<Option<(oneshot::Sender<()>, JoinHandle<Result<(), String>>)>>,
}
impl V2Server {
    /// The actual numeric bound socket address, including an assigned ephemeral port.
    pub fn actual_address(&self) -> String {
        self.address.clone()
    }
    /// Gracefully stop and join the server. Repeated stops are harmless.
    /// The five-second grace deadline is cooperative: it bounds asynchronous
    /// connection draining, not arbitrary blocking work. V2 HTTP handlers use
    /// nonblocking DB acquisition and return 503 while the owner is busy.
    pub fn stop(&self) -> Result<(), String> {
        let mut running =
            self.running.lock().map_err(|_| "server lock poisoned")?;
        if let Some((shutdown, thread)) = running.take() {
            let _ = shutdown.send(());
            thread.join().map_err(|_| "V2 server thread panicked")??;
        }
        Ok(())
    }
}
impl Drop for V2Server {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
/// Start only on an explicit numeric socket address. There is no default port.
/// A dedicated runtime thread owns the listener and shares the service's DB.
pub fn start(
    db: Arc<Mutex<V2Db>>,
    authority: Arc<Authority>,
    service_epoch: [u8; 16],
    index_error: Arc<AtomicBool>,
    bind: &str,
) -> Result<Box<V2Server>, String> {
    if bind.len() > 128 {
        return Err("numeric bind bound".into());
    }
    let address: SocketAddr = bind
        .parse()
        .map_err(|_| "explicit numeric socket required")?;
    let listener = TcpListener::bind(address).map_err(|e| e.to_string())?;
    let address = listener
        .local_addr()
        .map_err(|e| e.to_string())?
        .to_string();
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let (shutdown, receive) = oneshot::channel();
    let thread=std::thread::Builder::new().name("chronik-v2-http".into()).spawn(move||runtime.block_on(async move {
        let listener=tokio::net::TcpListener::from_std(listener).map_err(|e|e.to_string())?;
        let state=V2HttpState {db,service_epoch,index_error,node_anchor:Some(Arc::new(move||authority.observe()))};
        let (graceful,graceful_receive)=oneshot::channel();
        let server=axum::serve(listener,v2::router(state)).with_graceful_shutdown(async {let _=graceful_receive.await;});
        let server=std::future::IntoFuture::into_future(server);
        tokio::pin!(server);
        tokio::select! {
            result=&mut server=>result.map_err(|e|e.to_string()),
            _=receive=>{
                let _=graceful.send(());
                match tokio::time::timeout(std::time::Duration::from_secs(5), &mut server).await {
                    Ok(result)=>result.map_err(|e|e.to_string()),
                    Err(_)=>Err("V2 HTTP graceful shutdown deadline".into()),
                }
            }
        }
    })).map_err(|e|e.to_string())?;
    Ok(Box::new(V2Server {
        address,
        running: Mutex::new(Some((shutdown, thread))),
    }))
}

#[cfg(test)]
#[path = "v2tests/authority.rs"]
mod tests;
