//! Bounded node-local block construction and dispatch queues.

use std::collections::VecDeque;
use std::mem;

use serde::{Deserialize, Serialize};

use crate::admission::NodeAdmission;
use crate::block::{Block, BlockApplicationState, Transaction};
use crate::crypto::{PubKey, SecKey};
use crate::encounter::EncounterRecord;
use crate::error::{BlossomError, Result};
use crate::hash::HashType;
use crate::nonce::Nonce;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LocalBlock {
    pub build_block: Block,
    pub block_deque: VecDeque<Block>,
    pub block_cap: usize,
    pub application_state: BlockApplicationState,
    pub encounter_records: Vec<EncounterRecord>,
    pub node_admissions: Vec<NodeAdmission>,
}

impl LocalBlock {
    pub fn new(block_cap: usize) -> Self {
        Self {
            build_block: Block::default(),
            block_deque: VecDeque::new(),
            block_cap,
            application_state: BlockApplicationState::default(),
            encounter_records: Vec::new(),
            node_admissions: Vec::new(),
        }
    }

    pub fn set_application_state(&mut self, bytes: impl Into<Vec<u8>>) -> Result<()> {
        self.application_state = BlockApplicationState::new(bytes)?;
        Ok(())
    }

    pub fn application_state(&self) -> &BlockApplicationState {
        &self.application_state
    }

    pub fn add_encounter_record(&mut self, record: EncounterRecord) -> Result<HashType> {
        record.verify()?;
        let hash = record.hash();
        self.encounter_records.push(record);
        Ok(hash)
    }

    pub fn encounter_records(&self) -> &[EncounterRecord] {
        &self.encounter_records
    }

    pub fn take_encounter_records(&mut self) -> Vec<EncounterRecord> {
        mem::take(&mut self.encounter_records)
    }

    pub fn add_node_admission(&mut self, admission: NodeAdmission) -> Result<HashType> {
        admission.verify()?;
        let hash = admission.body.hash();
        self.node_admissions.push(admission);
        Ok(hash)
    }

    pub fn node_admissions(&self) -> &[NodeAdmission] {
        &self.node_admissions
    }

    pub fn take_node_admissions(&mut self) -> Vec<NodeAdmission> {
        mem::take(&mut self.node_admissions)
    }

    pub fn add_transaction(&mut self, tx: Transaction) -> HashType {
        let hash = tx.hash;
        self.build_block.body.txs.push(tx);
        hash
    }

    pub fn close_block(
        &mut self,
        secret_key: &SecKey,
        last_epoch: HashType,
        nonce: Nonce,
    ) -> Result<HashType> {
        self.close_block_with(last_epoch, nonce, |block| {
            block.sign(secret_key);
            Ok(())
        })
    }

    /// Seal the open application block with the runtime's execution policy.
    ///
    /// Failed signing or queue admission preserves all pending contents.
    pub(crate) fn close_block_with(
        &mut self,
        last_epoch: HashType,
        nonce: Nonce,
        seal: impl FnOnce(&mut Block) -> Result<()>,
    ) -> Result<HashType> {
        let mut block = self.build_block.clone();
        block.body.last_epoch = last_epoch;
        block.body.nonce = nonce;
        block.body.application_state = self.application_state.clone();
        block.body.encounter_records = self.encounter_records.clone();
        block.body.node_admissions = self.node_admissions.clone();
        seal(&mut block)?;
        self.ensure_enqueueable(&block)?;
        let hash = block.hash;
        self.block_deque.push_back(block);
        self.build_block = Block::default();
        self.encounter_records.clear();
        self.node_admissions.clear();
        Ok(hash)
    }

    pub fn enqueue_block(&mut self, block: Block) -> Result<HashType> {
        block.verify_integrity()?;
        self.enqueue_preverified_block(block)
    }

    /// Enqueue a block after the caller has already applied the appropriate
    /// integrity checks for its trust boundary.
    pub fn enqueue_preverified_block(&mut self, block: Block) -> Result<HashType> {
        self.ensure_enqueueable(&block)?;
        let hash = block.hash;
        self.block_deque.push_back(block);
        Ok(hash)
    }

    pub(crate) fn can_enqueue_preverified_block(&self, block: &Block) -> Result<()> {
        self.ensure_enqueueable(block)
    }

    /// Replaces the volatile trusted queue with the pending block recovered
    /// from the authoritative durable epoch log.
    pub(crate) fn reconcile_durable_pending_block(&mut self, block: Option<Block>) -> Result<()> {
        self.block_deque.clear();
        if let Some(block) = block {
            self.enqueue_preverified_block(block)?;
        }
        Ok(())
    }

    fn ensure_enqueueable(&self, block: &Block) -> Result<()> {
        if self
            .block_deque
            .iter()
            .any(|queued| queued.body.nonce == block.body.nonce)
        {
            return Err(BlossomError::DuplicateBlock);
        }
        if self.block_deque.len() >= self.block_cap {
            return Err(BlossomError::BlockQueueFull);
        }

        Ok(())
    }

    pub fn dequeue_block(
        &mut self,
        validator: Option<PubKey>,
        last_epoch: HashType,
        nonce: Nonce,
        _round: u8,
    ) -> Result<Option<Block>> {
        while let Some(block) = self.block_deque.front() {
            if block.body.nonce.value() < nonce.value() {
                self.block_deque.pop_front();
                continue;
            }
            if block.body.nonce.value() > nonce.value() {
                let actual = block.body.nonce;
                return Err(BlossomError::InvalidBlockNonce {
                    expected: nonce,
                    actual,
                });
            }
            if block.body.last_epoch != last_epoch {
                return Err(BlossomError::InvalidBlockLastEpoch);
            }
            if validator.is_some_and(|validator| block.body.validator != validator) {
                return Err(BlossomError::UnknownSender);
            }
            return Ok(self.block_deque.pop_front());
        }

        Ok(None)
    }

    pub fn contains_nonce(&self, nonce: Nonce) -> bool {
        self.block_deque
            .iter()
            .any(|block| block.body.nonce == nonce)
    }

    pub fn len(&self) -> usize {
        self.block_deque.len()
    }

    /// Counts closed blocks and the open block when it contains transactions.
    ///
    /// A request-driven driver must notice submitted application transactions
    /// before dispatch closes their block. Persistent application-state bytes
    /// alone do not initiate a new epoch.
    pub(crate) fn pending_block_count(&self) -> usize {
        self.block_deque.len() + usize::from(!self.build_block.body.txs.is_empty())
    }

    pub fn is_empty(&self) -> bool {
        self.block_deque.is_empty()
    }
}

impl Default for LocalBlock {
    fn default() -> Self {
        Self::new(100)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::Transaction;
    use crate::crypto::Keypair;

    #[test]
    fn rejects_duplicate_nonces() {
        let keypair = Keypair::generate();
        let mut queue = LocalBlock::new(2);
        let mut block = Block::default();
        block.body.last_epoch = HashType([7; 32]);
        block.body.nonce = Nonce::new(1);
        block.sign(&keypair.secret);

        assert!(queue.enqueue_block(block.clone()).is_ok());
        assert_eq!(
            queue.enqueue_block(block),
            Err(BlossomError::DuplicateBlock)
        );
    }

    #[test]
    fn closes_build_block_into_signed_queue() {
        let keypair = Keypair::generate();
        let mut queue = LocalBlock::new(2);
        queue.set_application_state(b"v1:load=42").unwrap();
        queue.add_transaction(Transaction::new("tx"));

        let hash = queue
            .close_block(&keypair.secret, HashType([1; 32]), Nonce::new(1))
            .unwrap();

        assert_eq!(queue.len(), 1);
        assert_ne!(hash, HashType::default());
        assert_eq!(
            queue.block_deque.front().unwrap().application_state(),
            b"v1:load=42"
        );
        assert_eq!(queue.application_state().as_slice(), b"v1:load=42");
    }

    #[test]
    fn add_transaction_defers_block_hash_work_until_close() {
        let keypair = Keypair::generate();
        let mut queue = LocalBlock::new(2);
        let initial_hash = queue.build_block.hash;
        let tx_hash = queue.add_transaction(Transaction::new("tx"));

        assert_eq!(tx_hash, HashType::hash(b"tx"));
        assert_eq!(queue.build_block.hash, initial_hash);
        assert_eq!(queue.build_block.body.merkle_root, HashType::default());

        let block_hash = queue
            .close_block(&keypair.secret, HashType([1; 32]), Nonce::new(1))
            .unwrap();
        let block = queue.block_deque.front().unwrap();

        assert_eq!(block.hash, block_hash);
        assert_ne!(block.body.merkle_root, HashType::default());
        assert!(block.verify_integrity().is_ok());
    }

    #[test]
    fn close_block_preserves_pending_block_when_queue_full() {
        let keypair = Keypair::generate();
        let mut queue = LocalBlock::new(0);
        queue.add_transaction(Transaction::new("tx"));

        assert_eq!(
            queue.close_block(&keypair.secret, HashType([1; 32]), Nonce::new(1)),
            Err(BlossomError::BlockQueueFull)
        );
        assert_eq!(queue.build_block.body.txs.len(), 1);
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn capacity_is_enforced() {
        let keypair = Keypair::generate();
        let mut queue = LocalBlock::new(1);
        let mut first = Block::default();
        first.body.last_epoch = HashType([1; 32]);
        first.body.nonce = Nonce::new(1);
        first.sign(&keypair.secret);
        let mut second = Block::default();
        second.body.last_epoch = HashType([1; 32]);
        second.body.nonce = Nonce::new(2);
        second.sign(&keypair.secret);

        assert!(queue.enqueue_block(first).is_ok());
        assert_eq!(
            queue.enqueue_block(second),
            Err(BlossomError::BlockQueueFull)
        );
    }

    #[test]
    fn preverified_enqueue_allows_trust_mode_unsigned_blocks() {
        let keypair = Keypair::generate();
        let mut queue = LocalBlock::new(1);
        let mut block = Block::default();
        block.body.last_epoch = HashType([1; 32]);
        block.body.nonce = Nonce::new(1);
        block.seal_unsigned(keypair.public);

        assert_eq!(
            queue.enqueue_block(block.clone()),
            Err(BlossomError::SignatureError)
        );
        let hash = queue.enqueue_preverified_block(block).unwrap();

        assert_ne!(hash, HashType::default());
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn dequeue_drops_stale_blocks() {
        let keypair = Keypair::generate();
        let mut queue = LocalBlock::new(2);
        let mut stale = Block::default();
        stale.body.last_epoch = HashType([1; 32]);
        stale.body.nonce = Nonce::new(1);
        stale.sign(&keypair.secret);
        queue.enqueue_block(stale).unwrap();

        assert!(matches!(
            queue.dequeue_block(None, HashType([1; 32]), Nonce::new(2), 0),
            Ok(None)
        ));
        assert!(queue.is_empty());
    }

    #[test]
    fn dequeue_keeps_future_blocks() {
        let keypair = Keypair::generate();
        let mut queue = LocalBlock::new(2);
        let mut future = Block::default();
        future.body.last_epoch = HashType([1; 32]);
        future.body.nonce = Nonce::new(3);
        future.sign(&keypair.secret);
        queue.enqueue_block(future).unwrap();

        assert!(matches!(
            queue.dequeue_block(None, HashType([1; 32]), Nonce::new(2), 0),
            Err(BlossomError::InvalidBlockNonce { expected, actual })
                if expected == Nonce::new(2) && actual == Nonce::new(3)
        ));
        assert!(queue.contains_nonce(Nonce::new(3)));
    }

    #[test]
    fn dequeue_rejects_wrong_validator() {
        let keypair = Keypair::generate();
        let mut queue = LocalBlock::new(2);
        let mut block = Block::default();
        block.body.last_epoch = HashType([1; 32]);
        block.body.nonce = Nonce::new(1);
        block.sign(&keypair.secret);
        queue.enqueue_block(block).unwrap();

        assert!(matches!(
            queue.dequeue_block(Some(PubKey([99; 32])), HashType([1; 32]), Nonce::new(1), 0),
            Err(BlossomError::UnknownSender)
        ));
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn dequeue_preserves_a_block_when_the_epoch_anchor_changed() {
        let keypair = Keypair::generate();
        let mut queue = LocalBlock::new(2);
        let mut block = Block::default();
        block.body.last_epoch = HashType([1; 32]);
        block.body.nonce = Nonce::new(1);
        block.sign(&keypair.secret);
        queue.enqueue_block(block).unwrap();

        assert!(matches!(
            queue.dequeue_block(None, HashType([2; 32]), Nonce::new(1), 0),
            Err(BlossomError::InvalidBlockLastEpoch)
        ));
        assert_eq!(queue.len(), 1);
    }
}
