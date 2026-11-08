use borsh::{BorshDeserialize, BorshSerialize};
use qubits_crypto::{Domain, PublicKey, SecretKey, Signature};
use qubits_types::Hash;

pub type Round = u64;
pub type ValidatorIndex = u16;

#[derive(BorshSerialize)]
enum Signed<'a> {
    Proposal {
        chain: &'a Hash,
        block: &'a Hash,
        justify: Option<Hash>,
        tc: Option<Hash>,
    },
    Vote {
        chain: &'a Hash,
        block: &'a Hash,
        round: Round,
        kind: VoteKind,
    },
    Timeout {
        chain: &'a Hash,
        round: Round,
        high_qc_round: Round,
    },
}

impl Signed<'_> {
    fn bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("in-memory encoding cannot fail")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ValidatorSet {
    keys: Vec<PublicKey>,
}

impl ValidatorSet {
    pub fn new(keys: Vec<PublicKey>) -> Result<Self, String> {
        if keys.is_empty() || keys.len() > usize::from(ValidatorIndex::MAX) {
            return Err("a validator set needs 1 to 65535 validators".into());
        }
        let distinct: std::collections::BTreeSet<_> = keys.iter().collect();
        if distinct.len() != keys.len() {
            return Err("duplicate validator key".into());
        }
        Ok(ValidatorSet { keys })
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    pub fn max_faulty(&self) -> usize {
        (self.len() - 1) / 3
    }

    pub fn quorum(&self) -> usize {
        self.len() - self.max_faulty()
    }

    pub fn leader(&self, round: Round) -> ValidatorIndex {
        (round % self.len() as u64) as ValidatorIndex
    }

    pub fn key(&self, index: ValidatorIndex) -> Option<&PublicKey> {
        self.keys.get(usize::from(index))
    }

    pub fn index_of(&self, key: &PublicKey) -> Option<ValidatorIndex> {
        self.keys
            .iter()
            .position(|k| k == key)
            .map(|i| i as ValidatorIndex)
    }

    fn verify(&self, index: ValidatorIndex, msg: &[u8], sig: &Signature) -> bool {
        self.key(index)
            .is_some_and(|k| k.verify(Domain::Consensus, msg, sig).is_ok())
    }

    fn verify_quorum<'a>(
        &self,
        signers: impl ExactSizeIterator<Item = (ValidatorIndex, Vec<u8>, &'a Signature)>,
    ) -> bool {
        if signers.len() < self.quorum() {
            return false;
        }
        let mut previous: Option<ValidatorIndex> = None;
        for (index, bytes, sig) in signers {
            if previous.is_some_and(|p| index <= p) || !self.verify(index, &bytes, sig) {
                return false;
            }
            previous = Some(index);
        }
        true
    }
}

/// Which rule a vote was cast under. A certificate holds one kind only: an optimistic quorum
/// proves no timeout certificate exists for the round before, which the safety argument needs.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, BorshSerialize, BorshDeserialize,
)]
pub enum VoteKind {
    Optimistic,
    Normal,
    Fallback,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct QuorumCert {
    pub block: Hash,
    pub round: Round,
    pub kind: VoteKind,
    pub votes: Vec<(ValidatorIndex, Signature)>,
}

impl QuorumCert {
    pub fn genesis(genesis: Hash) -> Self {
        QuorumCert {
            block: genesis,
            round: 0,
            kind: VoteKind::Normal,
            votes: vec![],
        }
    }

    pub fn verify(&self, validators: &ValidatorSet, chain: &Hash) -> bool {
        if self.round == 0 {
            return self.block == *chain && self.votes.is_empty();
        }
        validators.verify_quorum(self.votes.iter().map(|(index, sig)| {
            let bytes = Signed::Vote {
                chain,
                block: &self.block,
                round: self.round,
                kind: self.kind,
            }
            .bytes();
            (*index, bytes, sig)
        }))
    }

    pub fn signers(&self) -> impl Iterator<Item = ValidatorIndex> + '_ {
        self.votes.iter().map(|(index, _)| *index)
    }

    pub(crate) fn digest(&self) -> Hash {
        Hash::digest(
            "qubits.sh 2026-11 qc cache",
            &borsh::to_vec(self).expect("encoding cannot fail"),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TimeoutCert {
    pub round: Round,
    pub entries: Vec<(ValidatorIndex, Round, Signature)>,
    pub high_qc: QuorumCert,
}

impl TimeoutCert {
    pub fn verify(&self, validators: &ValidatorSet, chain: &Hash) -> bool {
        if self.high_qc.round != self.max_high_qc_round() || !self.high_qc.verify(validators, chain)
        {
            return false;
        }
        validators.verify_quorum(self.entries.iter().map(|(index, hqc, sig)| {
            let bytes = Signed::Timeout {
                chain,
                round: self.round,
                high_qc_round: *hqc,
            }
            .bytes();
            (*index, bytes, sig)
        }))
    }

    pub fn max_high_qc_round(&self) -> Round {
        self.entries.iter().map(|(_, r, _)| *r).max().unwrap_or(0)
    }

    fn digest(&self) -> Hash {
        Hash::digest(
            "qubits.sh 2026-11 timeout cert",
            &borsh::to_vec(self).expect("in-memory encoding cannot fail"),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Header {
    pub round: Round,
    pub height: u64,
    pub parent: Hash,
    pub proposer: ValidatorIndex,
    pub voters: Vec<ValidatorIndex>,
    pub payload: Hash,
}

impl Header {
    pub fn id(&self) -> Hash {
        Hash::digest(
            "qubits.sh 2026-11 consensus block",
            &borsh::to_vec(self).expect("in-memory encoding cannot fail"),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Block<P> {
    pub round: Round,
    pub height: u64,
    pub parent: Hash,
    pub proposer: ValidatorIndex,
    /// Validators the proposer last heard a vote from. Only picks leaders: nothing proves it, and
    /// a faulty proposer can add names but not remove the ones honest proposers reported.
    pub voters: Vec<ValidatorIndex>,
    pub payload: P,
}

impl<P: BorshSerialize> Block<P> {
    pub fn header(&self) -> Header {
        Header {
            round: self.round,
            height: self.height,
            parent: self.parent,
            proposer: self.proposer,
            voters: self.voters.clone(),
            payload: Hash::digest(
                "qubits.sh 2026-11 consensus payload",
                &borsh::to_vec(&self.payload).expect("in-memory encoding cannot fail"),
            ),
        }
    }

    pub fn id(&self) -> Hash {
        self.header().id()
    }
}

/// `justify` and `tc` tell the three proposals apart: neither for an optimistic one, sent before
/// the parent has a certificate; `justify` for a normal one; both for a fallback one.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Proposal<P> {
    pub block: Block<P>,
    pub justify: Option<QuorumCert>,
    pub tc: Option<TimeoutCert>,
    pub signature: Signature,
}

impl<P: BorshSerialize> Proposal<P> {
    pub fn optimistic(block: Block<P>, key: &SecretKey, chain: &Hash) -> Self {
        Self::sign(block, None, None, key, chain)
    }

    pub fn sign(
        block: Block<P>,
        justify: Option<QuorumCert>,
        tc: Option<TimeoutCert>,
        key: &SecretKey,
        chain: &Hash,
    ) -> Self {
        let bytes = Signed::Proposal {
            chain,
            block: &block.id(),
            justify: justify.as_ref().map(QuorumCert::digest),
            tc: tc.as_ref().map(TimeoutCert::digest),
        }
        .bytes();
        let signature = key
            .sign(Domain::Consensus, &bytes)
            .expect("signing cannot fail");
        Proposal {
            block,
            justify,
            tc,
            signature,
        }
    }

    pub(crate) fn signature_valid(
        &self,
        id: &Hash,
        validators: &ValidatorSet,
        chain: &Hash,
    ) -> bool {
        let bytes = Signed::Proposal {
            chain,
            block: id,
            justify: self.justify.as_ref().map(QuorumCert::digest),
            tc: self.tc.as_ref().map(TimeoutCert::digest),
        }
        .bytes();
        validators.verify(self.block.proposer, &bytes, &self.signature)
    }
}

/// Proves a block final. Every ancestor of a certified block is certified too, because honest
/// validators vote only after seeing the parent's certificate. So a certificate at the end of
/// `path`, with two rounds in a row anywhere from `tip` on, makes `tip` final.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct FinalityProof {
    pub tip: Hash,
    pub path: Vec<Header>,
    pub qc: QuorumCert,
}

impl FinalityProof {
    pub fn verify(&self, tip_round: Round, validators: &ValidatorSet, chain: &Hash) -> bool {
        let (mut parent, mut round) = (self.tip, tip_round);
        let mut consecutive = false;
        for header in &self.path {
            if header.parent != parent {
                return false;
            }
            consecutive |= header.round == round + 1;
            parent = header.id();
            round = header.round;
        }
        consecutive
            && self.qc.block == parent
            && self.qc.round == round
            && self.qc.verify(validators, chain)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Vote {
    pub block: Hash,
    pub round: Round,
    pub kind: VoteKind,
    pub voter: ValidatorIndex,
    pub signature: Signature,
}

impl Vote {
    /// Signs a vote for `block`.
    pub fn sign(
        block: Hash,
        round: Round,
        kind: VoteKind,
        voter: ValidatorIndex,
        key: &SecretKey,
        chain: &Hash,
    ) -> Self {
        let bytes = Signed::Vote {
            chain,
            block: &block,
            round,
            kind,
        }
        .bytes();
        let signature = key
            .sign(Domain::Consensus, &bytes)
            .expect("signing cannot fail");
        Vote {
            block,
            round,
            kind,
            voter,
            signature,
        }
    }

    pub(crate) fn verify(&self, validators: &ValidatorSet, chain: &Hash) -> bool {
        let bytes = Signed::Vote {
            chain,
            block: &self.block,
            round: self.round,
            kind: self.kind,
        }
        .bytes();
        validators.verify(self.voter, &bytes, &self.signature)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Timeout {
    pub round: Round,
    pub high_qc: QuorumCert,
    pub voter: ValidatorIndex,
    pub signature: Signature,
}

impl Timeout {
    pub fn signed(
        round: Round,
        high_qc: QuorumCert,
        voter: ValidatorIndex,
        key: &SecretKey,
        chain: &Hash,
    ) -> Self {
        let bytes = Signed::Timeout {
            chain,
            round,
            high_qc_round: high_qc.round,
        }
        .bytes();
        let signature = key
            .sign(Domain::Consensus, &bytes)
            .expect("signing cannot fail");
        Timeout {
            round,
            high_qc,
            voter,
            signature,
        }
    }

    pub(crate) fn verify(&self, validators: &ValidatorSet, chain: &Hash) -> bool {
        let bytes = Signed::Timeout {
            chain,
            round: self.round,
            high_qc_round: self.high_qc.round,
        }
        .bytes();
        validators.verify(self.voter, &bytes, &self.signature)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Message<P> {
    Proposal(Proposal<P>),
    /// A normal proposal for a block already sent: the signature is the proposal's
    Certify {
        block: Hash,
        justify: QuorumCert,
        signature: Signature,
    },
    Vote(Vote),
    Timeout(Timeout),
    Sync {
        high_qc: QuorumCert,
        last_tc: Option<TimeoutCert>,
    },
    BlockRequest(Hash),
    BlockResponse(Proposal<P>),
}

#[cfg(test)]
mod tests {
    use qubits_crypto::SchemeId;

    use super::*;

    #[test]
    fn the_proposer_signature_covers_the_certificates() {
        let key = SecretKey::from_seed(SchemeId::MlDsa65, &[1; 32]).unwrap();
        let validators = ValidatorSet::new(vec![key.public_key().clone()]).unwrap();
        let chain = Hash([7; 32]);
        let tc = TimeoutCert {
            round: 4,
            entries: vec![],
            high_qc: QuorumCert::genesis(chain),
        };
        let block = Block {
            round: 5,
            height: 1,
            parent: chain,
            proposer: 0,
            voters: vec![],
            payload: 0u8,
        };
        let id = block.id();
        let justify = QuorumCert::genesis(chain);
        let proposal = Proposal::sign(block, Some(justify), Some(tc.clone()), &key, &chain);
        assert!(proposal.signature_valid(&id, &validators, &chain));

        let mut stripped = proposal.clone();
        stripped.tc = None;
        assert!(!stripped.signature_valid(&id, &validators, &chain));

        let mut no_justify = proposal.clone();
        no_justify.justify = None;
        assert!(!no_justify.signature_valid(&id, &validators, &chain));

        let mut swapped = proposal;
        swapped.tc = Some(TimeoutCert { round: 3, ..tc });
        assert!(!swapped.signature_valid(&id, &validators, &chain));
    }

    #[test]
    fn a_vote_is_bound_to_its_kind() {
        let key = SecretKey::from_seed(SchemeId::MlDsa65, &[1; 32]).unwrap();
        let validators = ValidatorSet::new(vec![key.public_key().clone()]).unwrap();
        let chain = Hash([7; 32]);
        let vote = Vote::sign(Hash([1; 32]), 3, VoteKind::Optimistic, 0, &key, &chain);
        assert!(vote.verify(&validators, &chain));
        let relabelled = Vote {
            kind: VoteKind::Normal,
            ..vote
        };
        assert!(!relabelled.verify(&validators, &chain));
    }

    #[test]
    fn finality_needs_consecutive_rounds_and_a_certificate_at_the_end() {
        let key = SecretKey::from_seed(SchemeId::MlDsa65, &[1; 32]).unwrap();
        let validators = ValidatorSet::new(vec![key.public_key().clone()]).unwrap();
        let chain = Hash([7; 32]);
        let tip = Hash([9; 32]);
        let header = |round, parent| Header {
            round,
            height: round,
            parent,
            proposer: 0,
            voters: vec![],
            payload: Hash::ZERO,
        };
        let certify = |h: &Header| QuorumCert {
            block: h.id(),
            round: h.round,
            kind: VoteKind::Normal,
            votes: vec![(
                0,
                Vote::sign(h.id(), h.round, VoteKind::Normal, 0, &key, &chain).signature,
            )],
        };

        let child = header(6, tip);
        let proof = FinalityProof {
            tip,
            path: vec![child.clone()],
            qc: certify(&child),
        };
        assert!(proof.verify(5, &validators, &chain));
        assert!(!proof.verify(4, &validators, &chain), "a round was skipped");

        let wrong_parent = header(6, Hash([1; 32]));
        let unlinked = FinalityProof {
            tip,
            path: vec![wrong_parent.clone()],
            qc: certify(&wrong_parent),
        };
        assert!(!unlinked.verify(5, &validators, &chain));

        let grandchild = header(9, child.id());
        let longer = FinalityProof {
            tip,
            path: vec![child.clone(), grandchild.clone()],
            qc: certify(&grandchild),
        };
        assert!(longer.verify(5, &validators, &chain));

        let gap = header(7, tip);
        let no_run = FinalityProof {
            tip,
            path: vec![gap.clone()],
            qc: certify(&gap),
        };
        assert!(!no_run.verify(5, &validators, &chain));
    }
}
