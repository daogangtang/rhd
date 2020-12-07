use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use std::collections::hash_map::{HashMap, Entry};
use log::*;

use futures::{
    Future, Stream, FutureExt,
    future::poll_fn,
    task::{Context as FutureContext, Poll},
    executor::LocalPool,
    channel::mpsc::{self, UnboundedSender, UnboundedReceiver},
};
use futures_timer::Delay;

use codec::{Codec, Decode, Encode};

// dependencies on substrate
use sp_core::{H256, Pair as TTPair};
pub use sp_core::sr25519::{self, Pair, Public as AuthorityId, Signature, LocalizedSignature};
use sp_runtime::traits::{Block as BlockT, NumberFor};
use sp_consensus::{
    Environment, Proposer, SyncOracle, SelectChain, CanAuthorWith,
    import_queue::BoxBlockImport,
};
use sp_blockchain::{HeaderBackend};
use sp_api::{ProvideRuntimeApi};
use sp_inherents::{InherentDataProviders}; 
use sc_network::{NetworkService, ExHashT};
use sc_client_api::{backend::{AuxStore, Backend}, Finalizer};
use sc_consensus_bftml::{BftmlWorker, BftmlChannelMsg, BftmlInnerMsg, BftProposal, gen};
use sc_keystore::KeyStorePtr;

type Hash = H256;

mod rhd;
use rhd::{Agreement, Committed, Communication, Misbehavior, Context as RhdContext, RhdBlockExt};


/// A future that resolves either when canceled (witnessing a block from the network at same height)
/// or when agreement completes.
pub struct RhdWorker {
    // key: Pair,
    // authorities: Vec<AuthorityId>,
    auth_num: u16,
    keystore: KeyStorePtr,
    parent_hash: Hash,

    te_tx: Option<UnboundedSender<Communication>>,     // to engine tx, used in this caller layer
    fe_rx: Option<UnboundedReceiver<Communication>>,   // from engine rx, used in this caller layer

    tc_rx: UnboundedReceiver<BftmlChannelMsg>,
    ts_tx: UnboundedSender<BftmlChannelMsg>,
    cb_tx: UnboundedSender<BftmlChannelMsg>,
    ap_tx: UnboundedSender<BftmlChannelMsg>,
    gp_rx: UnboundedReceiver<BftmlChannelMsg>,
    gpte_tx: Option<UnboundedSender<BftmlChannelMsg>>,

    agreement_poller: Option<Agreement>,

    sleep_fu: Option<Pin<Box<dyn Future<Output=()> + Send>>>,
}

impl RhdWorker {
    pub fn new(
        // key: Pair,
        // authorities: Vec<AuthorityId>,
        auth_num: u16,
        keystore: KeyStorePtr,
        tc_rx: UnboundedReceiver<BftmlChannelMsg>,
        ts_tx: UnboundedSender<BftmlChannelMsg>,
        cb_tx: UnboundedSender<BftmlChannelMsg>,
        ap_tx: UnboundedSender<BftmlChannelMsg>,
        gp_rx: UnboundedReceiver<BftmlChannelMsg>,) -> RhdWorker {

        RhdWorker {
            // key,
            // authorities,
            auth_num,
            keystore,
            parent_hash: Default::default(),

            te_tx: None,
            fe_rx: None,

            tc_rx,
            ts_tx,
            cb_tx,
            ap_tx,
            gp_rx,
            gpte_tx: None,

            agreement_poller: None,
            sleep_fu: None,
        }
    }

    fn create_agreement_poller(&mut self) {
        let (te_tx, te_rx) = mpsc::unbounded::<Communication>();
        let (fe_tx, fe_rx) = mpsc::unbounded::<Communication>();
        let (gpte_tx, gpte_rx) = mpsc::unbounded::<BftmlChannelMsg>();

        // To resolve the ownership problem of which if we use gp_tx/rx directly
        self.gpte_tx = Some(gpte_tx);

        // TODO: Modify this to compile to four different nodes, tmp method
        //let pair_key = generate_sr25519_pair("Alice");
        //let pair_key = generate_sr25519_pair("Bob");
        //let pair_key = generate_sr25519_pair("Charlie");
        //let pair_key = generate_sr25519_pair("Dave");
        let keys = vec![
            generate_sr25519_pair("Alice"),
            generate_sr25519_pair("Bob"),
            generate_sr25519_pair("Charlie"),
            generate_sr25519_pair("Dave"),
        ];
        let auth_num = self.auth_num - 1;
        info!("==> Rhd: auth_num: {}", auth_num);
        let pair_key = if auth_num >= 0 {
            keys[auth_num as usize].clone()
        }
        else {
            keys[0].clone()
        };

        let authorities = vec![
            // sr25519::Public::from(Sr25519Keyring::Alice).into(),
            // sr25519::Public::from(Sr25519Keyring::Bob).into(),
            // sr25519::Public::from(Sr25519Keyring::Charlie).into(),
            // sr25519::Public::from(Sr25519Keyring::Dave).into(),
            generate_sr25519_pair("Alice").public(),
            generate_sr25519_pair("Bob").public(),
            generate_sr25519_pair("Charlie").public(),
            generate_sr25519_pair("Dave").public(),
        ];

        let n = authorities.len();
        let max_faulty = n / 3;

        let rhd_context = RhdContext {
            key: pair_key,
            parent_hash: self.parent_hash.clone(),
            authorities: authorities,
            ap_tx: self.ap_tx.clone(),
            gpte_rx: Some(gpte_rx),
        };

        let mut agreement = rhd::agree(
            rhd_context,
            n,
            max_faulty,
            te_rx, // input
            fe_tx, // output
        );

        self.te_tx = Some(te_tx);
        self.fe_rx = Some(fe_rx);
        self.agreement_poller = Some(agreement);
    }

    fn create_sleep_future(&mut self) -> Pin<Box<Future<Output=()>>> {
        let timeout = Duration::new(5, 0);
        let fut = Delay::new(timeout);

        fut.boxed()
    }
}

// rhd worker main poll
impl Future for RhdWorker {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut FutureContext) -> Poll<Self::Output> {
        info!("===>>> enter RhdWorker poll:");

        // receive protocol msg from bftml, forward it to the rhd engine
        let worker = self.get_mut();

        if worker.sleep_fu.is_none() {
            worker.create_sleep_future();
        }
        if worker.sleep_fu.is_some() {
            let mut sleep_fu = worker.sleep_fu.take().unwrap();
            match Future::poll(Pin::new(&mut sleep_fu), cx) {
                Poll::Ready(_) => {
                    info!("===>>> poll ready RhdWorker sleep_fu");
                }
                _ => {
                    // restore it
                    worker.sleep_fu= Some(sleep_fu);
                    // and return early
                    return Poll::Pending;
                }
            }
        }

        match Stream::poll_next(Pin::new(&mut worker.tc_rx), cx) {
            Poll::Ready(Some(msg)) => {
                info!("===>>> poll ready RhdWorker worker.tc_rx");
                // msg reform
                match msg {
                    BftmlChannelMsg::GossipMsgIncoming(avec) => {
                        if worker.te_tx.is_some() {
                            // [TODO]: decode vec<u8> to type Communication<B>, does this work?
                            //let msg: Communication<B> = avec.decode();
                            let msg: Communication = Decode::decode(&mut &avec[..]).expect("GossipMsgIncoming serialized msg is corrupted.");
                            info!("===>>> poll ready RhdWorker worker. decoded msg");
                            
                            // then forward it
                            // because te_tx here is an Option
                            // self.te_tx.unbounded_send(msg);
                            // [TODO]: check this write style
                            let _ = worker.te_tx.as_ref().map(|c|c.unbounded_send(msg));
                        }
                    }
                    _ => {}
                }

            }
            _ => {}
        }

        // receive rhd engine protocol msg, forward it to bftml
        if worker.fe_rx.is_some() {
            // we think taking action always success
            let mut fe_rx = worker.fe_rx.take().unwrap();
            match Stream::poll_next(Pin::new(&mut fe_rx), cx) {
                Poll::Ready(Some(msg)) => {
                    info!("===>>> poll ready RhdWorker fe_rx");
                    // msg reform
                    // encode it 
                    // [TODO]: make sure this correct?
                    let avec = msg.encode();

                    // and wrap it to BftmlChannelMsg
                    worker.ts_tx.unbounded_send(BftmlChannelMsg::GossipMsgOutgoing(avec));
                }
                _ => {}
            }
            // restore it
            worker.fe_rx = Some(fe_rx);
        }

        // NOTE: try to solve the ownership of gp_rx 
        match Stream::poll_next(Pin::new(&mut worker.gp_rx), cx) {
            Poll::Ready(Some(msg)) => {
                info!("===>>> poll ready RhdWorker worker.gp_rx");
                // msg reform
                match msg {
                    BftmlChannelMsg::GiveProposal(proposal) => {
                        info!("===>>> poll ready RhdWorker proposal msg: {:?}", proposal);
                        if worker.gpte_tx.is_some() {
                            info!("===>>> RhdWorker worker.gpte_tx is some");
                            // forward to inner
                            let _ = worker.gpte_tx.as_ref().map(|c| {
                                c.unbounded_send(BftmlChannelMsg::GiveProposal(proposal));
                                info!("===>>> RhdWorker worker.gpte_tx sent proposal");
                            });
                        }
                        else {
                            info!("===>>> RhdWorker worker.gpte_tx is none");
                        }
                    }
                    _ => {}
                }

            }
            _ => {}
        }

        if worker.agreement_poller.is_none() {
            worker.create_agreement_poller();
        }
        
        if worker.agreement_poller.is_some() {
            info!("===>>> RhdWorker agreement_poller is some.");
            // asure unwrap always works
            let mut agreement_poller = worker.agreement_poller.take().unwrap();
            match Future::poll(Pin::new(&mut agreement_poller), cx) {
                Poll::Ready(Some(commit_msg)) => {
                    info!("===>>> poll ready RhdWorker agreement_poller: {:?}", commit_msg);
                    // the result of poll of agreement is Committed, deal with it
                    // TODO: err handling
                    let candidate = commit_msg.candidate.unwrap();
                    let block_hash = candidate.rhd_hash();
                    let msg = block_hash.as_bytes().to_vec();

                    info!("===>>> poll ready RhdWorker agreement_poller. commit msg: {:?}", msg);
                    worker.cb_tx.unbounded_send(BftmlChannelMsg::CommitBlock(msg));

                    // set back
                    worker.te_tx = None;
                    worker.fe_rx = None;
                    worker.gpte_tx = None;

                    // Repeated: prepare to continue next agreement/consensus
                    worker.create_agreement_poller();
                    // set sleep for seconds
                    worker.create_sleep_future();
                }
                _ => {
                    // restore it
                    worker.agreement_poller = Some(agreement_poller);
                }
            }
        }

        info!("===>>> leave RhdWorker poll:");
        Poll::Pending
    }
}




// We must use some basic types defined in Substrate, imported and use here
// We can specify and wrap all these types in bftml, and import them from bftml module
// to reduce noise on your eye
pub fn make_rhd_worker_pair<B, C, E, SO, S, CAW, H, BD>(
    client: Arc<C>,
    block_import: BoxBlockImport<B, sp_api::TransactionFor<C, B>>,
    proposer_factory: E,
    network: Arc<NetworkService<B, H>>,
    imported_block_rx: UnboundedReceiver<BftmlInnerMsg<B>>,
    sync_oracle: SO,  // sync_oracle is also network
    select_chain: Option<S>,
    inherent_data_providers: InherentDataProviders,
    can_author_with: CAW,
    // key: Pair,   // could be generated by client?
    // authorities: Vec<AuthorityId>,
    auth_num: u16,
    keystore: KeyStorePtr,
    ) -> Result<(impl Future<Output = ()>, impl Future<Output = ()>), sp_consensus::Error> where
    B: BlockT + Clone + Eq,
    B::Hash: std::marker::Unpin,
    NumberFor<B>: Unpin,
	C: HeaderBackend<B> + AuxStore + ProvideRuntimeApi<B> + Finalizer<B, BD> + 'static,
    BD: Backend<B> + std::marker::Unpin,
    E: Environment<B> + Send + Sync + std::marker::Unpin,
    E::Proposer: Proposer<B, Transaction = sp_api::TransactionFor<C, B>>,
    E::Error: std::fmt::Debug,
    sp_api::TransactionFor<C, B>: 'static,
	SO: SyncOracle + Send + Sync + 'static + std::marker::Unpin,
	S: SelectChain<B> + Send + Sync + 'static + std::marker::Unpin,
	CAW: CanAuthorWith<B> + Send + Sync + 'static + std::marker::Unpin,
    H: ExHashT,
{
    // generate channels
    let (tc_tx, tc_rx, ts_tx, ts_rx) = gen::gossip_msg_channels();
    let (cb_tx, cb_rx) = gen::commit_block_channel();
    let (ap_tx, ap_rx) = gen::ask_proposal_channel();
    let (gp_tx, gp_rx) = gen::give_proposal_channel();

    let bftml_worker = BftmlWorker::new(
        client.clone(),
        block_import,
        proposer_factory,
        network,
        imported_block_rx,
        tc_tx,
        ts_rx,
        cb_rx,
        ap_rx,
        gp_tx,
        sync_oracle,
        select_chain,
        inherent_data_providers,
        can_author_with,);

    let mut rhd_worker = RhdWorker::new(
        // key,
        // authorities,
        auth_num,
        keystore,
        tc_rx,
        ts_tx,
        cb_tx,
        ap_tx,
        gp_rx,);

    rhd_worker.create_agreement_poller();

    info!("===>>> make_rhd_worker_pair, two workers");
    Ok((bftml_worker, rhd_worker))
}

// helper
fn generate_sr25519_pair(seed: &str) -> sr25519::Pair {
    sr25519::Pair::from_string(&format!("//{}", seed), None)
        .expect("static values are valid; qed")
}
