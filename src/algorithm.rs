//! Quorum thresholds, deterministic selection, and topology calculations.

use std::collections::BTreeSet;
use std::env;
use std::fmt;
use std::str::FromStr;

use crate::crypto::PubKey;
use crate::error::{BlossomError, Result};
use crate::hash::{HashType, ProtocolHasher};
use borsh::{BorshDeserialize, BorshSerialize};
use indextreemap::IndexTreeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const QUORUM_SIZE: usize = 6;
pub const BLOSSOM_QUORUM_SIZE_ENV: &str = "BLOSSOM_QUORUM_SIZE";
pub const SUPERMAJORITY: f64 = 2.0 / 3.0;
pub const CONSENSUS_PARAMETERS_VERSION: u16 = 1;
const CONSENSUS_PARAMETERS_HASH_DOMAIN: &[u8] = b"blossom/consensus-parameters/v1";

/// The configured branching factor for Blossom's hierarchical quorum overlay.
///
/// This is deliberately not a global finality threshold. Finality continues to
/// use a supermajority of the complete validator set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QuorumSize(usize);

impl QuorumSize {
    pub const DEFAULT: Self = Self(QUORUM_SIZE);

    pub fn new(value: usize) -> Result<Self> {
        if value >= 3 && value.is_multiple_of(3) {
            Ok(Self(value))
        } else {
            Err(BlossomError::InvalidQuorumSize(value))
        }
    }

    pub const fn get(self) -> usize {
        self.0
    }

    pub fn effective(self, validator_count: usize) -> usize {
        self.0.min(validator_count)
    }

    pub fn from_environment() -> Result<Self> {
        match env::var(BLOSSOM_QUORUM_SIZE_ENV) {
            Ok(value) => Self::resolve_startup(None, Some(&value)),
            Err(env::VarError::NotPresent) => Self::resolve_startup(None, None),
            Err(err) => Err(BlossomError::InvalidConfiguration(format!(
                "read {BLOSSOM_QUORUM_SIZE_ENV}: {err}"
            ))),
        }
    }

    /// Resolves the startup-only value using CLI, environment, then the
    /// compatibility default. Callers should persist the result and must not
    /// consult the environment again after joining a cluster.
    pub fn resolve_startup(cli: Option<&str>, environment: Option<&str>) -> Result<Self> {
        cli.or(environment).map_or(Ok(Self::DEFAULT), str::parse)
    }
}

impl Default for QuorumSize {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl fmt::Display for QuorumSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for QuorumSize {
    type Err = BlossomError;

    fn from_str(value: &str) -> Result<Self> {
        let parsed = value.parse::<usize>().map_err(|_| {
            BlossomError::InvalidConfiguration(format!(
                "{BLOSSOM_QUORUM_SIZE_ENV} must be an integer, got {value:?}"
            ))
        })?;
        Self::new(parsed)
    }
}

impl Serialize for QuorumSize {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_u64(self.0 as u64)
    }
}

impl<'de> Deserialize<'de> for QuorumSize {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let value = <u64 as Deserialize>::deserialize(deserializer)?;
        let value = usize::try_from(value).map_err(serde::de::Error::custom)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

impl BorshSerialize for QuorumSize {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&(self.0 as u64), writer)
    }
}

impl BorshDeserialize for QuorumSize {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let value = u64::deserialize_reader(reader)?;
        let value = usize::try_from(value).map_err(std::io::Error::other)?;
        Self::new(value).map_err(std::io::Error::other)
    }
}

/// Versioned parameters committed by genesis and inherited by every epoch.
#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub struct ConsensusParameters {
    pub version: u16,
    pub quorum_size: QuorumSize,
}

impl ConsensusParameters {
    pub const fn new(quorum_size: QuorumSize) -> Self {
        Self {
            version: CONSENSUS_PARAMETERS_VERSION,
            quorum_size,
        }
    }

    pub fn validate(self) -> Result<()> {
        if self.version != CONSENSUS_PARAMETERS_VERSION {
            return Err(BlossomError::InvalidConfiguration(format!(
                "unsupported consensus parameters version {}",
                self.version
            )));
        }
        QuorumSize::new(self.quorum_size.get())?;
        Ok(())
    }

    pub fn hash(self) -> HashType {
        let mut hasher = ProtocolHasher::new();
        hasher.update(CONSENSUS_PARAMETERS_HASH_DOMAIN);
        hasher.update(self.version.to_le_bytes());
        hasher.update((self.quorum_size.get() as u64).to_le_bytes());
        hasher.finalize()
    }
}

impl Default for ConsensusParameters {
    fn default() -> Self {
        Self::new(QuorumSize::DEFAULT)
    }
}

pub fn select_quorums(
    nodes: impl IntoIterator<Item = PubKey>,
    self_key: &PubKey,
    seed: HashType,
    shuffle: bool,
) -> Vec<Vec<PubKey>> {
    select_quorums_with_size(nodes, self_key, seed, shuffle, QuorumSize::DEFAULT)
}

pub fn select_quorums_with_size(
    nodes: impl IntoIterator<Item = PubKey>,
    self_key: &PubKey,
    seed: HashType,
    shuffle: bool,
    quorum_size: QuorumSize,
) -> Vec<Vec<PubKey>> {
    let mut node_map = IndexTreeMap::new();
    for node in nodes {
        node_map.insert(node, ());
    }

    select_quorums_from_index_tree_with_size(&node_map, self_key, seed, shuffle, quorum_size)
}

/// Selects the canonical v2 prefill recipients for one node.
///
/// The prefill set is the union of every quorum the node will meet in the
/// epoch, excluding the node itself. For an ideal network this yields
/// `log_q(n) * (q - 1)` recipients before any optional Byzantine-redundancy
/// widening is applied by a higher-level propagation policy.
pub fn select_prefill_recipients(
    nodes: impl IntoIterator<Item = PubKey>,
    self_key: &PubKey,
    seed: HashType,
    shuffle: bool,
) -> Vec<PubKey> {
    select_prefill_recipients_with_size(nodes, self_key, seed, shuffle, QuorumSize::DEFAULT)
}

pub fn select_prefill_recipients_with_size(
    nodes: impl IntoIterator<Item = PubKey>,
    self_key: &PubKey,
    seed: HashType,
    shuffle: bool,
    quorum_size: QuorumSize,
) -> Vec<PubKey> {
    select_quorums_with_size(nodes, self_key, seed, shuffle, quorum_size)
        .into_iter()
        .flatten()
        .filter(|member| member != self_key)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub fn select_quorums_from_index_tree<N>(
    node_map: &IndexTreeMap<PubKey, N>,
    self_key: &PubKey,
    seed: HashType,
    shuffle: bool,
) -> Vec<Vec<PubKey>>
where
    N: Default + Clone,
{
    select_quorums_from_index_tree_with_size(node_map, self_key, seed, shuffle, QuorumSize::DEFAULT)
}

pub fn select_quorums_from_index_tree_with_size<N>(
    node_map: &IndexTreeMap<PubKey, N>,
    self_key: &PubKey,
    seed: HashType,
    shuffle: bool,
    quorum_size: QuorumSize,
) -> Vec<Vec<PubKey>>
where
    N: Default + Clone,
{
    if node_map.is_empty() {
        return Vec::new();
    }

    let self_index = match node_map.get_index_from_key(self_key) {
        Some(index) => index,
        None => return Vec::new(),
    };

    // A partial first-level group is one complete quorum. Applying the
    // higher-level stride calculation here would select only each node's
    // own position when the membership is smaller than the branching factor.
    if node_map.len() <= quorum_size.get() {
        let mut quorum = node_map.keys().copied().collect::<Vec<_>>();
        quorum.sort_unstable();
        return vec![quorum];
    }

    let (optimal_network_size, rounds) = find_round_number_with_size(node_map.len(), quorum_size);
    if optimal_network_size == 0 || rounds == 0 {
        return Vec::new();
    }

    let mut ordered_indices: Vec<usize> = (0..node_map.len()).collect();
    let self_index = if shuffle {
        deterministic_shuffle(&mut ordered_indices, seed);
        ordered_indices
            .iter()
            .position(|index| *index == self_index)
            .unwrap_or(self_index)
    } else {
        self_index
    };

    algorithm_with_size(
        node_map,
        &ordered_indices,
        self_index,
        optimal_network_size,
        rounds,
        quorum_size,
    )
}

pub fn algorithm<N>(
    node_map: &IndexTreeMap<PubKey, N>,
    ordered_indices: &[usize],
    self_index: usize,
    optimal_network_size: usize,
    rounds: usize,
) -> Vec<Vec<PubKey>>
where
    N: Default + Clone,
{
    algorithm_with_size(
        node_map,
        ordered_indices,
        self_index,
        optimal_network_size,
        rounds,
        QuorumSize::DEFAULT,
    )
}

pub fn algorithm_with_size<N>(
    node_map: &IndexTreeMap<PubKey, N>,
    ordered_indices: &[usize],
    mut self_index: usize,
    optimal_network_size: usize,
    rounds: usize,
    quorum_size: QuorumSize,
) -> Vec<Vec<PubKey>>
where
    N: Default + Clone,
{
    let mut quorum_members_matrix = Vec::new();
    if node_map.is_empty() || optimal_network_size == 0 {
        return quorum_members_matrix;
    }

    self_index = if self_index >= optimal_network_size {
        self_index % optimal_network_size
    } else {
        self_index
    };

    for mut round in 0..rounds {
        let q = quorum_size.get();
        let mut ceiling_network_size = checked_pow(q, round.saturating_add(1))
            .unwrap_or(optimal_network_size.saturating_add(1));
        let mut max_network_size = ceiling_network_size;
        let mut size_multiple = 1;

        if ceiling_network_size > optimal_network_size {
            ceiling_network_size = checked_pow(q, round).unwrap_or(optimal_network_size);
            round = round.saturating_sub(1);
            max_network_size = optimal_network_size;
            size_multiple = (optimal_network_size / ceiling_network_size).max(1);
        }

        let offset = checked_pow(q, round).unwrap_or(optimal_network_size);
        let stride = size_multiple
            .checked_mul(offset)
            .unwrap_or(optimal_network_size);
        let first_quorum_member = (self_index - (self_index % max_network_size))
            .checked_add(self_index % stride)
            .unwrap_or(self_index);

        let mut quorum = Vec::new();
        push_quorum_members(
            &mut quorum,
            node_map,
            ordered_indices,
            first_quorum_member,
            size_multiple,
            offset,
            quorum_size,
        );

        if ordered_indices.len() >= optimal_network_size
            && let Some(second_segment) = optimal_network_size.checked_add(first_quorum_member)
        {
            push_quorum_members(
                &mut quorum,
                node_map,
                ordered_indices,
                second_segment,
                size_multiple,
                offset,
                quorum_size,
            );
        }

        quorum.sort_unstable();
        quorum.dedup();
        quorum_members_matrix.push(quorum);
    }

    quorum_members_matrix
}

fn push_quorum_members<N>(
    quorum: &mut Vec<PubKey>,
    node_map: &IndexTreeMap<PubKey, N>,
    ordered_indices: &[usize],
    first_quorum_member: usize,
    size_multiple: usize,
    offset: usize,
    quorum_size: QuorumSize,
) where
    N: Default + Clone,
{
    for quorum_member in 0..quorum_size.get() {
        let Some(index) = quorum_member
            .checked_mul(size_multiple)
            .and_then(|value| value.checked_mul(offset))
            .and_then(|value| first_quorum_member.checked_add(value))
        else {
            break;
        };
        match member_at(node_map, ordered_indices, index) {
            Some(member) => quorum.push(member),
            None => break,
        }
    }
}

fn member_at<N>(
    node_map: &IndexTreeMap<PubKey, N>,
    ordered_indices: &[usize],
    index: usize,
) -> Option<PubKey>
where
    N: Default + Clone,
{
    let map_index = ordered_indices.get(index).copied()?;
    node_map.get_key_from_index(map_index).copied()
}

pub fn deterministic_shuffle(indices: &mut [usize], seed: HashType) {
    let mut state = u64::from_le_bytes(seed.0[0..8].try_into().unwrap_or([1; 8]));
    if state == 0 {
        state = 0x9e37_79b9_7f4a_7c15;
    }

    for i in (1..indices.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let j = (state as usize) % (i + 1);
        indices.swap(i, j);
    }
}

pub fn find_round_number(network_size: usize) -> (usize, usize) {
    find_round_number_with_size(network_size, QuorumSize::DEFAULT)
}

pub fn find_round_number_with_size(network_size: usize, quorum_size: QuorumSize) -> (usize, usize) {
    if network_size == 0 {
        return (0, 0);
    }
    let q = quorum_size.get();
    if network_size <= q {
        return (network_size, 1);
    }

    let mut base_network_size = q;
    let mut exponent = 1usize;
    while let Some(next) = base_network_size.checked_mul(q) {
        if next > network_size {
            break;
        }
        base_network_size = next;
        exponent = exponent.saturating_add(1);
    }

    let multiple = network_size / base_network_size;
    let optimal_network_size = base_network_size
        .checked_mul(multiple)
        .unwrap_or(base_network_size);
    let rounds = exponent + usize::from(optimal_network_size > base_network_size);
    (optimal_network_size, rounds)
}

fn checked_pow(base: usize, exponent: usize) -> Option<usize> {
    let mut value = 1usize;
    for _ in 0..exponent {
        value = value.checked_mul(base)?;
    }
    Some(value)
}

pub fn supermajority_count(total: usize) -> usize {
    total - (total / 3)
}

/// Returns true when a distinct-voter count reaches the Blossom supermajority.
///
/// Counts larger than `total` are rejected so duplicated or Sybil evidence
/// cannot satisfy a proof by over-counting.
pub fn has_supermajority(total: usize, count: usize) -> bool {
    total > 0 && count <= total && count >= supermajority_count(total)
}

/// Counts distinct voters that belong to the current validator set.
pub fn distinct_current_validator_count<T>(
    voters: impl IntoIterator<Item = T>,
    current_validators: impl IntoIterator<Item = T>,
) -> usize
where
    T: Ord + Copy,
{
    let current_validators = current_validators.into_iter().collect::<BTreeSet<_>>();
    voters
        .into_iter()
        .filter(|voter| current_validators.contains(voter))
        .collect::<BTreeSet<_>>()
        .len()
}

/// Returns true when distinct current-validator evidence reaches supermajority.
pub fn has_distinct_supermajority<T>(
    voters: impl IntoIterator<Item = T>,
    current_validators: impl IntoIterator<Item = T>,
) -> bool
where
    T: Ord + Copy,
{
    let current_validators = current_validators.into_iter().collect::<BTreeSet<_>>();
    let count = voters
        .into_iter()
        .filter(|voter| current_validators.contains(voter))
        .collect::<BTreeSet<_>>()
        .len();
    has_supermajority(current_validators.len(), count)
}

/// Maximum Byzantine population tolerated by the honest-overlap proof.
pub fn byzantine_fault_bound(total: usize) -> usize {
    total.saturating_sub(1) / 3
}

/// Number of slow or absent validators that can be ignored for liveness.
///
/// This is intentionally separate from `byzantine_fault_bound`: a validator can
/// be slow without being Byzantine.
pub fn max_liveness_omissions(total: usize) -> usize {
    total.saturating_sub(supermajority_count(total))
}

/// Minimum overlap between any two accepted supermajority vote sets.
pub fn min_supermajority_intersection(total: usize) -> usize {
    let quorum = supermajority_count(total);
    quorum.saturating_mul(2).saturating_sub(total)
}

/// Returns true when two supermajorities must share at least one honest voter.
pub fn supermajority_has_honest_overlap(total: usize) -> bool {
    total > 0 && min_supermajority_intersection(total) > byzantine_fault_bound(total)
}

/// Returns the slowest sample inside the fastest safe supermajority.
///
/// The caller must pass one sample per distinct current validator that has
/// supplied valid evidence. Fewer than a supermajority, or more samples than
/// eligible validators, means no valid supermajority proof exists.
pub fn supermajority_order_statistic<T, I>(samples: I, total: usize) -> Option<T>
where
    T: Ord + Copy,
    I: IntoIterator<Item = T>,
{
    let quorum = supermajority_count(total);
    if quorum == 0 {
        return None;
    }

    let mut samples = samples.into_iter().collect::<Vec<_>>();
    if samples.len() < quorum || samples.len() > total {
        return None;
    }

    samples.sort_unstable();
    samples.get(quorum - 1).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_first_level_quorum_contains_every_validator() {
        for count in [1, 2, 3, 4, 5, 6, 7] {
            let nodes = (0..count).map(key).collect::<BTreeSet<_>>();
            for self_key in &nodes {
                for shuffle in [false, true] {
                    let quorums = select_quorums(
                        nodes.iter().copied(),
                        self_key,
                        HashType::default(),
                        shuffle,
                    );
                    assert_eq!(quorums.len(), 1);
                    assert_eq!(quorums[0].iter().copied().collect::<BTreeSet<_>>(), nodes);
                }
            }
        }
    }

    fn key(index: u8) -> PubKey {
        PubKey([index; 32])
    }

    #[test]
    fn round_number_matches_quorum_growth() {
        assert_eq!(find_round_number(0), (0, 0));
        assert_eq!(find_round_number(6), (6, 1));
        assert_eq!(find_round_number(36), (36, 2));
        assert_eq!(find_round_number(216), (216, 3));
    }

    #[test]
    fn quorum_size_accepts_only_multiples_of_three_at_least_three() {
        for valid in [3, 6, 9, 12, 99] {
            assert_eq!(QuorumSize::new(valid).unwrap().get(), valid);
        }
        for invalid in [0, 1, 2, 4, 5, 7, 10] {
            assert_eq!(
                QuorumSize::new(invalid),
                Err(BlossomError::InvalidQuorumSize(invalid))
            );
        }
    }

    #[test]
    fn configurable_round_number_uses_checked_integer_growth() {
        let q3 = QuorumSize::new(3).unwrap();
        let q9 = QuorumSize::new(9).unwrap();

        assert_eq!(find_round_number_with_size(0, q3), (0, 0));
        assert_eq!(find_round_number_with_size(3, q3), (3, 1));
        assert_eq!(find_round_number_with_size(9, q3), (9, 2));
        assert_eq!(find_round_number_with_size(27, q3), (27, 3));
        assert_eq!(find_round_number_with_size(54, q3), (54, 4));
        assert_eq!(find_round_number_with_size(8, q9), (8, 1));

        let (optimal, rounds) = find_round_number_with_size(usize::MAX, q3);
        assert!(optimal > 0);
        assert!(optimal > usize::MAX / q3.get());
        assert!(rounds > 1);
    }

    #[test]
    fn configurable_quorums_are_deterministic_and_bounded() {
        let nodes = (0..72).map(key).collect::<Vec<_>>();
        let seed = HashType::hash(b"configurable-quorum");

        for size in [3, 6, 9, 12] {
            let quorum_size = QuorumSize::new(size).unwrap();
            let first =
                select_quorums_with_size(nodes.iter().copied(), &key(7), seed, true, quorum_size);
            let second =
                select_quorums_with_size(nodes.iter().copied(), &key(7), seed, true, quorum_size);
            assert_eq!(first, second);
            assert!(first.iter().all(|quorum| quorum.contains(&key(7))));
            assert!(
                first
                    .iter()
                    .all(|quorum| quorum.len() <= quorum_size.get() * 2)
            );
        }
    }

    #[test]
    fn effective_quorum_size_is_capped_by_validator_count() {
        let q = QuorumSize::new(12).unwrap();
        assert_eq!(q.effective(0), 0);
        assert_eq!(q.effective(5), 5);
        assert_eq!(q.effective(12), 12);
        assert_eq!(q.effective(20), 12);
    }

    #[test]
    fn consensus_parameter_hash_binds_quorum_size() {
        let q3 = ConsensusParameters::new(QuorumSize::new(3).unwrap());
        let q6 = ConsensusParameters::default();
        assert_ne!(q3.hash(), q6.hash());
        assert_eq!(q6.hash(), ConsensusParameters::default().hash());
    }

    #[test]
    fn selects_quorums_containing_self() {
        let nodes = (0..36).map(key).collect::<Vec<_>>();
        let quorums = select_quorums(nodes, &key(7), HashType::default(), false);

        assert_eq!(quorums.len(), 2);
        assert!(quorums.iter().all(|quorum| quorum.contains(&key(7))));
    }

    #[test]
    fn prefill_recipients_union_future_coordinate_lines() {
        let nodes = (0..36).map(key).collect::<Vec<_>>();
        let recipients = select_prefill_recipients(nodes, &key(0), HashType::default(), false);

        assert_eq!(recipients.len(), 10);
        assert!(!recipients.contains(&key(0)));
        for expected in [1, 2, 3, 4, 5, 6, 12, 18, 24, 30] {
            assert!(recipients.contains(&key(expected)));
        }
    }

    #[test]
    fn prefill_recipients_scale_with_tensor_depth() {
        let nodes = (0..216)
            .map(|index| PubKey([index as u8; 32]))
            .collect::<Vec<_>>();
        let recipients = select_prefill_recipients(nodes, &key(0), HashType::default(), false);

        assert_eq!(recipients.len(), 15);
    }

    #[test]
    fn shuffled_quorums_still_contain_self() {
        let nodes = (0..36).map(key).collect::<Vec<_>>();
        let seed = HashType::hash(b"shuffle seed");
        let quorums = select_quorums(nodes, &key(7), seed, true);

        assert_eq!(quorums.len(), 2);
        assert!(quorums.iter().all(|quorum| quorum.contains(&key(7))));
    }

    #[test]
    fn empty_or_missing_self_produces_no_quorums() {
        assert!(
            select_quorums(Vec::<PubKey>::new(), &key(0), HashType::default(), false).is_empty()
        );
        assert!(select_quorums([key(1), key(2)], &key(0), HashType::default(), false).is_empty());
    }

    #[test]
    fn deterministic_shuffle_is_reproducible_and_seed_sensitive() {
        let seed = HashType::hash(b"seed");
        let mut first = (0..12).collect::<Vec<_>>();
        let mut second = (0..12).collect::<Vec<_>>();
        let mut different = (0..12).collect::<Vec<_>>();

        deterministic_shuffle(&mut first, seed);
        deterministic_shuffle(&mut second, seed);
        deterministic_shuffle(&mut different, HashType::hash(b"different"));

        assert_eq!(first, second);
        assert_ne!(first, different);
    }

    #[test]
    fn supermajority_matches_two_thirds_plus_one_boundary() {
        assert_eq!(supermajority_count(0), 0);
        assert_eq!(supermajority_count(1), 1);
        assert_eq!(supermajority_count(3), 2);
        assert_eq!(supermajority_count(6), 4);
        assert_eq!(supermajority_count(7), 5);
    }

    #[test]
    fn supermajority_count_rejects_under_threshold_and_overfull_votes() {
        assert!(!has_supermajority(0, 0));
        assert!(!has_supermajority(6, 3));
        assert!(has_supermajority(6, 4));
        assert!(has_supermajority(6, 6));
        assert!(!has_supermajority(6, 7));
    }

    #[test]
    fn distinct_current_validator_supermajority_ignores_duplicates_and_outsiders() {
        let current_validators = [key(0), key(1), key(2), key(3), key(4), key(5)];
        let voters = [key(0), key(0), key(1), key(2), key(3), key(99)];

        assert_eq!(
            distinct_current_validator_count(voters, current_validators),
            4
        );
        assert!(has_distinct_supermajority(voters, current_validators));
    }

    #[test]
    fn distinct_current_validator_supermajority_rejects_duplicate_shortfall() {
        let current_validators = [key(0), key(1), key(2), key(3), key(4), key(5)];
        let voters = [key(0), key(0), key(1), key(2), key(99)];

        assert_eq!(
            distinct_current_validator_count(voters, current_validators),
            3
        );
        assert!(!has_distinct_supermajority(voters, current_validators));
    }

    #[test]
    fn six_node_quorum_distinguishes_liveness_from_byzantine_safety() {
        assert_eq!(supermajority_count(6), 4);
        assert_eq!(max_liveness_omissions(6), 2);
        assert_eq!(byzantine_fault_bound(6), 1);
        assert_eq!(min_supermajority_intersection(6), 2);
        assert!(supermajority_has_honest_overlap(6));
    }

    #[test]
    fn supermajority_intersection_exceeds_bft_fault_bound() {
        for total in 1..=256 {
            assert!(
                supermajority_has_honest_overlap(total),
                "total={total} quorum={} min_intersection={} max_byzantine={}",
                supermajority_count(total),
                min_supermajority_intersection(total),
                byzantine_fault_bound(total)
            );
        }
    }

    #[test]
    fn one_below_supermajority_loses_honest_overlap_guarantee() {
        for total in 1..=256 {
            let unsafe_quorum = supermajority_count(total).saturating_sub(1);
            let max_byzantine = byzantine_fault_bound(total);
            let min_intersection = unsafe_quorum.saturating_mul(2).saturating_sub(total);

            assert!(
                min_intersection <= max_byzantine,
                "total={total} unsafe_quorum={unsafe_quorum} min_intersection={min_intersection} max_byzantine={max_byzantine}"
            );
        }
    }

    #[test]
    fn supermajority_order_statistic_uses_slowest_safe_supermajority() {
        let samples = [0, 10, 20, 100, 200, 300];

        assert_eq!(supermajority_order_statistic(samples, 6), Some(100));
    }

    #[test]
    fn supermajority_order_statistic_requires_distinct_current_validator_samples() {
        assert_eq!(supermajority_order_statistic([0, 10, 20], 6), None);
        assert_eq!(
            supermajority_order_statistic([0, 10, 20, 100, 200, 300, 1], 6),
            None
        );
    }

    #[test]
    fn quorum_selection_is_deterministic_and_self_consistent_across_sizes() {
        for size in 1..80 {
            let nodes = (0..size).map(|index| key(index as u8)).collect::<Vec<_>>();
            let seed = HashType::hash(&[size as u8]);

            for self_key in &nodes {
                let first = select_quorums(nodes.iter().copied(), self_key, seed, true);
                let second = select_quorums(nodes.iter().copied(), self_key, seed, true);
                assert_eq!(first, second, "size {size} self {self_key}");
                assert!(!first.is_empty(), "size {size} self {self_key}");

                for quorum in &first {
                    assert!(quorum.contains(self_key), "size {size} self {self_key}");
                    let mut sorted = quorum.clone();
                    sorted.sort_unstable();
                    sorted.dedup();
                    assert_eq!(&sorted, quorum, "size {size} self {self_key}");
                    assert!(
                        quorum.len() <= QUORUM_SIZE * 2,
                        "size {size} self {self_key} quorum len {}",
                        quorum.len()
                    );
                }
            }
        }
    }

    #[test]
    fn quorum_members_agree_on_their_round_group() {
        for size in [6usize, 7, 12, 35, 36, 37, 72, 80] {
            let nodes = (0..size).map(|index| key(index as u8)).collect::<Vec<_>>();
            let seed = HashType::hash(&[size as u8, 42]);

            for self_key in &nodes {
                let self_quorums = select_quorums(nodes.iter().copied(), self_key, seed, true);
                for (round, quorum) in self_quorums.iter().enumerate() {
                    for peer in quorum {
                        let peer_quorums = select_quorums(nodes.iter().copied(), peer, seed, true);
                        assert_eq!(
                            peer_quorums.get(round),
                            Some(quorum),
                            "size {size} round {round} self {self_key} peer {peer}"
                        );
                    }
                }
            }
        }
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    const MAX_VALIDATORS: usize = 64;

    #[kani::proof]
    fn supermajority_has_honest_overlap_for_small_validator_sets() {
        let total: usize = kani::any();
        kani::assume(total > 0);
        kani::assume(total <= MAX_VALIDATORS);

        assert!(supermajority_has_honest_overlap(total));
    }

    #[kani::proof]
    fn one_below_supermajority_loses_honest_overlap_for_small_validator_sets() {
        let total: usize = kani::any();
        kani::assume(total > 0);
        kani::assume(total <= MAX_VALIDATORS);

        let unsafe_quorum = supermajority_count(total).saturating_sub(1);
        let max_byzantine = byzantine_fault_bound(total);
        let min_intersection = unsafe_quorum.saturating_mul(2).saturating_sub(total);

        assert!(min_intersection <= max_byzantine);
    }

    #[kani::proof]
    fn supermajority_count_matches_expected_boundary_for_small_validator_sets() {
        let total: usize = kani::any();
        kani::assume(total > 0);
        kani::assume(total <= MAX_VALIDATORS);

        let quorum = supermajority_count(total);

        assert!(has_supermajority(total, quorum));
        assert!(!has_supermajority(total, quorum.saturating_sub(1)));
        assert!(!has_supermajority(total, total + 1));
    }

    #[kani::proof]
    fn configurable_quorum_effective_size_is_bounded() {
        let multiplier: usize = kani::any();
        let validator_count: usize = kani::any();
        kani::assume(multiplier > 0);
        kani::assume(multiplier <= 21);
        kani::assume(validator_count <= MAX_VALIDATORS);

        let configured = multiplier * 3;
        let quorum_size = QuorumSize::new(configured).unwrap();
        let effective = quorum_size.effective(validator_count);
        assert!(effective <= configured);
        assert!(effective <= validator_count);
    }
}
