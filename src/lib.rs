use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use std::collections::hash_map::{HashMap, Entry};
use log::*;

use futures::{
    Future, Stream,
    future::poll_fn,
    task::{Context as FutureContext, Poll},
    executor::LocalPool,
    channel::mpsc::{self, UnboundedSender, UnboundedReceiver},
};

use codec::{Codec, Decode, Encode};

// dependencies on substrate
use sp_core::{H256, Pair as TTPair};
use sp_core::sr25519::{Pair, Public as AuthorityId, Signature, LocalizedSignature};
use sp_runtime::traits::{Block as BlockT};
use sp_consensus::{
    Environment, Proposer, SyncOracle, SelectChain, CanAuthorWith,
    import_queue::BoxBlockImport,
};
use sp_blockchain::{HeaderBackend};
use sp_api::{ProvideRuntimeApi};
use sp_inherents::{InherentDataProviders}; 
use sc_network::{NetworkService, ExHashT};
use sc_client_api::{backend::{AuxStore}};
use sc_consensus_bftml::{BftmlWorker, BftmlChannelMsg, BftProposal, gen};

type Hash = H256;

mod rhd;
use rhd::{Agreement, Committed, Communication, Misbehavior, Context as RhdContext};

/// A future that resolves either when canceled (witnessing a block from the network at same height)
/// or when agreement completes.
pub struct RhdWorker {
    key: Pair,
    authorities: Vec<AuthorityId>,
    parent_hash: Hash,

    te_tx: Option<UnboundedSender<Communication>>,     // to engine tx, used in this caller layer
    fe_rx: Option<UnboundedReceiver<Communication>>,   // from engine rx, used in this caller layer
//    cm_rx: Option<UnboundedReceiver<Committed>>,

    tc_rx: UnboundedReceiver<BftmlChannelMsg>,
    ts_tx: UnboundedSender<BftmlChannelMsg>,
    cb_tx: UnboundedSender<BftmlChannelMsg>,
    ap_tx: UnboundedSender<BftmlChannelMsg>,
    gp_rx: Option<UnboundedReceiver<BftmlChannelMsg>>,

    agreement_poller: Option<Agreement>,

    proposing: bool,
}

// rhd worker main poll
impl Future for RhdWorker {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut FutureContext) -> Poll<Self::Output> {
        // receive protocol msg from bftml, forward it to the rhd engine
        let worker = self.get_mut();
        match Stream::poll_next(Pin::new(&mut worker.tc_rx), cx) {
            Poll::Ready(Some(msg)) => {
                // msg reform
                match msg {
                    BftmlChannelMsg::GossipMsgIncoming(avec) => {
                        if self.te_tx.is_some() {
                            // [TODO]: decode vec<u8> to type Communication<B>, does this work?
                            //let msg: Communication<B> = avec.decode();
                            let msg: Communication = Decode::decode(&mut &avec[..]).expect("GossipMsgIncoming serialized msg is corrupted.");
                            
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
            let fe_rx = worker.fe_rx.take().unwrap();
            match Stream::poll_next(Pin::new(&mut fe_rx), cx) {
                Poll::Ready(Some(msg)) => {
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

        if worker.agreement_poller.is_none() {
            worker.create_agreement_poller();
        }
        
        if worker.agreement_poller.is_some() {
            // asure unwrap always works
            let agreement_poller = worker.agreement_poller.take().unwrap();
            match Future::poll(Pin::new(&mut agreement_poller), cx) {
                Poll::Ready(Some(commit_msg)) => {
                    // the result of poll of agreement is Committed, deal with it
                    // cm_tx.unbounded_send(commit_msg);
                    // [TODO]: convert Committed to BftProposal
                    // here, we couldn't pass back Commited to lower level Bftml, Bftml doesn't
                    // realize upper structure, and should not realize it.
                    let bp = BftProposal{};
                    worker.cb_tx.unbounded_send(BftmlChannelMsg::CommitBlock(bp));

                    // set back
                    worker.te_tx = None;
                    worker.fe_rx = None;
                    //worker.agreement_poller = None;
                    // continue next agreement/consensus
                    worker.create_agreement_poller();
                }
                _ => {
                    // restore it
                    worker.agreement_poller = Some(agreement_poller);
                }
            }
        }


        Poll::Pending
    }
}

impl RhdWorker {
    pub fn new(
        key: Pair,
        authorities: Vec<AuthorityId>,
        tc_rx: UnboundedReceiver<BftmlChannelMsg>,
        ts_tx: UnboundedSender<BftmlChannelMsg>,
        cb_tx: UnboundedSender<BftmlChannelMsg>,
        ap_tx: UnboundedSender<BftmlChannelMsg>,
        gp_rx: UnboundedReceiver<BftmlChannelMsg>,) -> RhdWorker {

        RhdWorker {
            key,
            authorities,
            parent_hash: Default::default(),

            te_tx: None,
            fe_rx: None,

            tc_rx,
            ts_tx,
            cb_tx,
            ap_tx,
            gp_rx: Some(gp_rx),

            agreement_poller: None,
            proposing: false,
        }
    }

    fn create_agreement_poller(&mut self) {
        // TODO: where authorities come from?
        let rhd_context = RhdContext {
            key: self.key,
            parent_hash: self.parent_hash,
            authorities: self.authorities.clone(),
            ap_tx: self.ap_tx.clone(),
            gp_rx: self.gp_rx.take(),
        };

        let (te_tx, te_rx) = mpsc::unbounded::<Communication>();
        let (fe_tx, fe_rx) = mpsc::unbounded::<Communication>();

        let n = self.authorities.len();
        let max_faulty = n / 3;
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

}



// We must use some basic types defined in Substrate, imported and use here
// We can specify and wrap all these types in bftml, and import them from bftml module
// to reduce noise on your eye
pub fn make_rhd_worker_pair<B, C, E, SO, S, CAW, H>(
    client: Arc<C>,
    block_import: BoxBlockImport<B, sp_api::TransactionFor<C, B>>,
    proposer_factory: E,
    network: Arc<NetworkService<B, H>>,
    imported_block_rx: UnboundedReceiver<BftProposal>,
    sync_oracle: SO,  // sync_oracle is also network
    select_chain: Option<S>,
    inherent_data_providers: InherentDataProviders,
    can_author_with: CAW,
    key: Pair,   // could be generated by client?
    authorities: Vec<AuthorityId>,
    ) -> Result<(impl Future<Output = ()>, impl Future<Output = ()>), sp_consensus::Error> where
    B: BlockT + Clone + Eq,
	C: HeaderBackend<B> + AuxStore + ProvideRuntimeApi<B> + 'static,
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
        key,
        authorities,
        tc_rx,
        ts_tx,
        cb_tx,
        ap_tx,
        gp_rx,);

    rhd_worker.create_agreement_poller();

    Ok((bftml_worker, rhd_worker))
}

