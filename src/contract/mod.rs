pub(crate) mod fees;
pub(crate) mod outcome;
pub(crate) mod split;

use bitcoin::{transaction::InputWeightPrediction, Amount, FeeRate, TxOut};
use secp::{MaybePoint, Point};
use serde::{Deserialize, Serialize};

use crate::{
    consts::{P2TR_DUST_VALUE, P2TR_SCRIPT_PUBKEY_SIZE},
    errors::Error,
    oracles::EventLockingConditions,
    parties::{MarketMaker, Player},
    spend_info::FundingSpendInfo,
};

use std::collections::{BTreeMap, BTreeSet};

/// A type alias for clarity. Players in the DLC are often referred to by their
/// index in the sorted set of players.
pub type PlayerIndex = usize;

/// A type alias for clarity. DLC outcomes are sometimes referred to by their
/// index in the set of possible outcome messages.
pub type OutcomeIndex = usize;

/// Represents a mapping of player to payout weight for a given outcome.
///
/// A player's payout under an outcome is proportional to the size of their payout weight
/// relative to the sum of payout weights of all other winners for that outcome.
///
/// ```not_rust
/// total_payout = contract_value * weights[player] / sum(weights)
/// ```
///
/// Players who should not receive a payout from an outcome MUST NOT be given an entry
/// in a `PayoutWeights` map.
pub type PayoutWeights = BTreeMap<PlayerIndex, u64>;

/// Represents the parameters which all players and the market maker must agree on
/// to construct a ticketed DLC.
///
/// If all players use the same [`ContractParameters`], they should be able to
/// construct identical sets of outcome and split transactions, and exchange musig2
/// signatures thereupon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractParameters {
    /// The market maker who provides capital for the DLC ticketing process.
    pub market_maker: MarketMaker,

    /// The set of players in the DLC.
    ///
    /// Every player MUST use a public key which is distinct from every other
    /// player's key and from the market maker's key, and MUST have a unique ticket
    /// hash and a unique payout hash. The same person may join a DLC several times,
    /// but must do so with a fresh key and fresh hashes each time. [`validate`][Self::validate]
    /// enforces these rules.
    pub players: Vec<Player>,

    /// The event whose outcome determines the payouts.
    pub event: EventLockingConditions,

    /// A mapping of payout weights under different outcomes. Attestation indexes should
    /// align with [`self.event.locking_points`][EventLockingConditions::locking_points].
    ///
    // The outcome payouts map describes how payouts are allocated based on the Outcome
    // which has been attested to by the oracle. If the oracle doesn't attest to any
    // outcome by the expiry time, then the `Outcome::Expiry` payout will take effect.
    ///
    /// If this map does not contain a key of [`Outcome::Expiry`], then there is no expiry
    /// condition, and the money simply remains locked in the funding outpoint until the
    /// Oracle's attestation is found.
    pub outcome_payouts: BTreeMap<Outcome, PayoutWeights>,

    /// A default mining fee rate to be used for pre-signed transactions.
    pub fee_rate: FeeRate,

    /// The amount of on-chain capital which the market maker will provide when funding
    /// the initial multisig deposit contract (after on-chain mining fees).
    ///
    /// Normally, this would be the expected sum of the players' off-chain payments to
    /// the market maker, minus a fee. Winners will split the funding value among
    /// themselves according to the agreed PayoutWeights for each outcome. Mining fees
    /// are distributed equally among winners.
    pub funding_value: Amount,

    /// A reasonable number of blocks within which a transaction can confirm.
    /// Used for enforcing relative locktime timeout spending conditions.
    ///
    /// Winners can spend after this many blocks; the market maker's reclaim paths
    /// mature after twice this many blocks. Must be between `1` and
    /// [`MAX_RELATIVE_LOCKTIME_BLOCK_DELTA`][Self::MAX_RELATIVE_LOCKTIME_BLOCK_DELTA].
    ///
    /// Reasonable values are:
    ///
    /// - `72`:  ~12 hours
    /// - `144`: ~24 hours
    /// - `432`: ~72 hours
    /// - `1008`: ~1 week
    pub relative_locktime_block_delta: u16,
}

/// Represents one possible outcome branch of the DLC. This includes both
/// outcomes attested-to by the Oracle, and expiry.
#[derive(Clone, Copy, Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum Outcome {
    /// Indicates the oracle attested to a particular outcome of the given index.
    Attestation(OutcomeIndex),

    /// Indicates the oracle failed to attest to any outcome, and the event expiry
    /// timelock was reached.
    Expiry,
}

/// Points to a situation where a player wins a payout from the DLC.
#[derive(Clone, Copy, Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct WinCondition {
    /// Indicates the outcome which would've been attested to by the oracle.
    pub outcome: Outcome,
    /// Indicates the particular player who would be paid out as a winner
    /// in this outcome.
    pub player_index: PlayerIndex,
}

impl ContractParameters {
    /// The largest permitted [`relative_locktime_block_delta`][Self::relative_locktime_block_delta].
    ///
    /// The market maker's reclaim paths are delayed by twice the delta, and that
    /// doubled value must still fit in the 16-bit block-height field of a BIP-68
    /// relative locktime. A larger delta would wrap around and make the reclaim
    /// paths mature *before* the winners' paths.
    pub const MAX_RELATIVE_LOCKTIME_BLOCK_DELTA: u16 = 0x7FFF;

    /// Verifies the parameters are in standardized format and would produce a
    /// contract which is safe to enforce. This is run by
    /// [`TicketedDLC::new`][crate::TicketedDLC::new].
    ///
    /// The following are rejected:
    ///
    /// - no outcomes, an outcome with no winners, or a zero payout weight;
    /// - a player index which does not exist, or an outcome the event cannot produce;
    /// - duplicate ticket hashes, duplicate payout hashes, or a payout hash equal to
    ///   a ticket hash, since revealing one preimage would unlock a path guarded by
    ///   the other;
    /// - a public key shared by two players, or by a player and the market maker,
    ///   since MuSig2 signing sessions identify signers by key;
    /// - an oracle locking point at infinity, which would make an outcome
    ///   transaction spendable without any attestation;
    /// - payout weights so large that payout amounts would overflow;
    /// - a zero fee rate, a zero funding value, or a locktime delta outside
    ///   `1..=MAX_RELATIVE_LOCKTIME_BLOCK_DELTA`;
    /// - an expiry of zero, which would make the expiry transaction spendable
    ///   as soon as the funding transaction confirms.
    ///
    /// Note this cannot check whether a non-zero expiry is still in the future:
    /// the expiry transaction carries a plain (non-adaptor) signature, so once the
    /// expiry height or time has passed, anyone holding the signed contract can
    /// resolve the contract to the [`Outcome::Expiry`] payout map without any
    /// oracle attestation. Integrators must confirm the expiry is far enough in
    /// the future before agreeing to the parameters.
    pub fn validate(&self) -> Result<(), Error> {
        // A contract with no outcomes can never be resolved except cooperatively.
        if self.outcome_payouts.is_empty() {
            return Err(Error::EmptyOutcomePayouts);
        }

        // Ticket and payout hashes must be unique, and the two sets disjoint.
        let mut ticket_hashes = BTreeSet::<&[u8; 32]>::new();
        let mut payout_hashes = BTreeSet::<&[u8; 32]>::new();
        for player in self.players.iter() {
            if !ticket_hashes.insert(&player.ticket_hash) {
                return Err(Error::DuplicateTicketHash);
            }
            if !payout_hashes.insert(&player.payout_hash) {
                return Err(Error::DuplicatePayoutHash);
            }
        }
        if !ticket_hashes.is_disjoint(&payout_hashes) {
            return Err(Error::TicketPayoutHashCollision);
        }

        // Every signer must have a distinct key. Nonces and partial signatures are
        // keyed by pubkey, so a duplicated key can never complete a signing session.
        let mut pubkeys = BTreeSet::from([self.market_maker.pubkey]);
        for player in self.players.iter() {
            if !pubkeys.insert(player.pubkey) {
                return Err(Error::DuplicatePubkey);
            }
        }

        // An adaptor point at infinity turns an adaptor signature into a plain
        // signature, so the outcome could be unlocked without any attestation.
        if self
            .event
            .locking_points
            .iter()
            .any(|point| matches!(point, MaybePoint::Infinity))
        {
            return Err(Error::InvalidLockingPoint);
        }

        for (outcome, payout_map) in self.outcome_payouts.iter() {
            // Check for unknown outcomes.
            if !self.event.is_valid_outcome(outcome) {
                return Err(Error::UnknownOutcome);
            }

            // Check for empty payout map.
            if payout_map.is_empty() {
                return Err(Error::EmptyPayoutMap);
            }

            let mut total_weight: u64 = 0;
            for (&player_index, &weight) in payout_map.iter() {
                // Check for zero payout weights.
                if weight == 0 {
                    return Err(Error::InvalidPayoutWeight);
                }

                // Check for out-of-bounds player indexes.
                if player_index >= self.players.len() {
                    return Err(Error::OutOfBoundsPlayerIndex);
                }

                total_weight = total_weight
                    .checked_add(weight)
                    .ok_or(Error::PayoutWeightOverflow)?;
            }

            // Payouts are computed as `value * weight / total_weight`, so the
            // product of the funding value and the total weight must fit in a u64.
            self.funding_value
                .to_sat()
                .checked_mul(total_weight)
                .ok_or(Error::PayoutWeightOverflow)?;
        }

        // Must use a non-zero fee rate.
        if self.fee_rate == FeeRate::ZERO {
            return Err(Error::InvalidFeeRate);
        }

        // The locktime delta must be non-zero, and twice the delta must still be
        // encodable as a BIP-68 block-height relative locktime.
        if self.relative_locktime_block_delta == 0
            || self.relative_locktime_block_delta > Self::MAX_RELATIVE_LOCKTIME_BLOCK_DELTA
        {
            return Err(Error::InvalidLocktime);
        }

        // An expiry of zero would make the expiry transaction spendable
        // immediately after the funding transaction confirms.
        if self.event.expiry == Some(0) {
            return Err(Error::InvalidExpiry);
        }

        // Must be funded by some fixed non-zero amount.
        if self.funding_value == Amount::ZERO {
            return Err(Error::InvalidFundingValue);
        }

        Ok(())
    }

    /// The relative block delay after which the market maker can reclaim an
    /// outcome transaction output or a split transaction output: twice
    /// [`relative_locktime_block_delta`][Self::relative_locktime_block_delta].
    ///
    /// Saturates at `u16::MAX` so that the reclaim delay can never wrap around to
    /// a value below the winners' delay, even for unvalidated parameters.
    pub fn reclaim_block_delay(&self) -> u16 {
        self.relative_locktime_block_delta.saturating_mul(2)
    }

    /// Returns the transaction output which the funding transaction should pay to.
    ///
    /// Avoid overusing this method, as it recomputes the aggregated key every time
    /// it is invoked. Instead, prefer
    /// [`TicketedDLC::funding_output`][crate::TicketedDLC::funding_output].
    pub fn funding_output(&self) -> Result<TxOut, Error> {
        let spend_info =
            FundingSpendInfo::new(&self.market_maker, &self.players, self.funding_value)?;
        Ok(spend_info.funding_output())
    }

    pub(crate) fn outcome_output_value(&self) -> Result<Amount, Error> {
        let input_weights = [InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH];
        let fee = fees::fee_calc_safe(self.fee_rate, input_weights, [P2TR_SCRIPT_PUBKEY_SIZE])?;
        let outcome_value = fees::fee_subtract_safe(self.funding_value, fee, P2TR_DUST_VALUE)?;
        Ok(outcome_value)
    }

    /// Returns the set of player indexes which this pubkey can sign for.
    ///
    /// For validated parameters this contains at most one index, since every
    /// player must use a distinct key.
    pub fn players_controlled_by_pubkey(&self, pubkey: Point) -> BTreeSet<PlayerIndex> {
        self.players
            .iter()
            .enumerate()
            .filter_map(|(i, player)| {
                if player.pubkey == pubkey {
                    Some(i)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Return the set of all win conditions for which the given pubkey can claim
    /// a split transaction output. In other words, this returns the possible
    /// paths for a given signer to claim winnings.
    ///
    /// If `pubkey` belongs to one or more players, this returns all [`WinCondition`]s
    /// in which the player or players are winners.
    ///
    /// If `pubkey` belongs to the market maker, this returns every [`WinCondition`]
    /// across the entire contract.
    ///
    /// Returns `None` if the pubkey does not belong to any player in the DLC.
    ///
    /// Returns an empty `BTreeSet` if the player is part of the DLC, but isn't due to
    /// receive any payouts on any DLC outcome.
    pub fn win_conditions_claimable_by_pubkey(
        &self,
        pubkey: Point,
    ) -> Option<BTreeSet<WinCondition>> {
        // To sign as the market maker, the caller need only provide the correct secret key.
        let is_market_maker = pubkey == self.market_maker.pubkey;

        let controlling_players = self.players_controlled_by_pubkey(pubkey);

        // Short circuit if this pubkey is not known.
        if controlling_players.is_empty() && !is_market_maker {
            return None;
        }

        let mut relevant_win_conditions = BTreeSet::<WinCondition>::new();
        for (&outcome, payout_map) in self.outcome_payouts.iter() {
            // We can broadcast the split TX for any win-conditions whose player is
            // controlled by `pubkey`. If we're the market maker, we have a claim
            // path on every win condition.
            relevant_win_conditions.extend(payout_map.keys().filter_map(|player_index| {
                if is_market_maker || controlling_players.contains(player_index) {
                    Some(WinCondition {
                        player_index: *player_index,
                        outcome,
                    })
                } else {
                    None
                }
            }));
        }

        Some(relevant_win_conditions)
    }

    /// Return the set of all win conditions which the given pubkey will need to sign
    /// split transactions for.
    ///
    /// If `pubkey` belongs to one or more players, this returns all [`WinCondition`]s
    /// for outcomes in which the player or players are winners.
    ///
    /// If `pubkey` belongs to the market maker, this returns every [`WinCondition`]
    /// across the entire contract.
    ///
    /// Returns `None` if the pubkey does not belong to any player in the DLC.
    ///
    /// Returns an empty `BTreeSet` if the player is part of the DLC, but isn't due to
    /// receive any payouts on any DLC outcome.
    pub fn win_conditions_controlled_by_pubkey(
        &self,
        pubkey: Point,
    ) -> Option<BTreeSet<WinCondition>> {
        // To sign as the market maker, the caller need only provide the correct secret key.
        let is_market_maker = pubkey == self.market_maker.pubkey;

        let controlling_players = self.players_controlled_by_pubkey(pubkey);

        // Short circuit if this pubkey is not known.
        if controlling_players.is_empty() && !is_market_maker {
            return None;
        }

        let mut win_conditions_to_sign = BTreeSet::<WinCondition>::new();
        for (&outcome, payout_map) in self.outcome_payouts.iter() {
            // We want to sign the split TX for any win-conditions under outcomes where the
            // given `pubkey` is one of the winners. If we're the market maker, we sign every
            // win condition.
            if is_market_maker
                || controlling_players
                    .iter()
                    .any(|player_index| payout_map.contains_key(player_index))
            {
                win_conditions_to_sign.extend(payout_map.keys().map(|&player_index| {
                    WinCondition {
                        player_index,
                        outcome,
                    }
                }));
            }
        }

        Some(win_conditions_to_sign)
    }

    /// Return a blank [`SigMap`] illustrating the different outcomes and
    /// win conditions which a given pubkey should sign.
    pub fn sigmap_for_pubkey(&self, pubkey: Point) -> Option<SigMap<()>> {
        let win_conditions = self.win_conditions_controlled_by_pubkey(pubkey)?;
        let sigmap = SigMap {
            by_outcome: self
                .outcome_payouts
                .iter()
                .map(|(&outcome, _)| (outcome, ()))
                .collect(),
            by_win_condition: win_conditions.into_iter().map(|w| (w, ())).collect(),
        };
        Some(sigmap)
    }

    /// Return a full set of all possible win conditions for this DLC.
    pub fn all_win_conditions(&self) -> BTreeSet<WinCondition> {
        let mut all_win_conditions = BTreeSet::new();
        for (&outcome, payout_map) in self.outcome_payouts.iter() {
            all_win_conditions.extend(payout_map.keys().map(|&player_index| WinCondition {
                player_index,
                outcome,
            }));
        }
        all_win_conditions
    }

    /// Returns an empty sigmap covering every outcome and every win condition.
    /// This encompasses every possible message whose signatures are needed
    /// to set up the contract.
    pub fn full_sigmap(&self) -> SigMap<()> {
        SigMap {
            by_outcome: self
                .outcome_payouts
                .iter()
                .map(|(&outcome, _)| (outcome, ()))
                .collect(),
            by_win_condition: self
                .all_win_conditions()
                .into_iter()
                .map(|win_cond| (win_cond, ()))
                .collect(),
        }
    }
}

/// Represents a mapping of different signature requirements to some arbitrary type T.
/// This can be used to efficiently look up signatures, nonces, etc, for each
/// outcome transaction, and for different [`WinCondition`]s within each split transaction.
#[derive(Debug, Clone, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct SigMap<T> {
    /// Corresponds to the set of outcome transactions which the player needs to sign.
    pub by_outcome: BTreeMap<Outcome, T>,
    /// Corresponds to the set of split transaction spending conditions which the
    /// player needs to sign.
    pub by_win_condition: BTreeMap<WinCondition, T>,
}

impl<T> SigMap<T> {
    /// Map each outcome and win condition to values of a specific type using
    /// distinct map functions.
    pub fn map<V, F1, F2>(self, map_outcomes: F1, map_win_conditions: F2) -> SigMap<V>
    where
        F1: Fn(Outcome, T) -> V,
        F2: Fn(WinCondition, T) -> V,
    {
        SigMap {
            by_outcome: self
                .by_outcome
                .into_iter()
                .map(|(o, t)| (o, map_outcomes(o, t)))
                .collect(),
            by_win_condition: self
                .by_win_condition
                .into_iter()
                .map(|(w, t)| (w, map_win_conditions(w, t)))
                .collect(),
        }
    }

    /// Map each outcome and win condition to values of a specific type.
    pub fn map_values<V, F>(self, mut map_fn: F) -> SigMap<V>
    where
        F: FnMut(T) -> V,
    {
        SigMap {
            by_outcome: self
                .by_outcome
                .into_iter()
                .map(|(o, t)| (o, map_fn(t)))
                .collect(),
            by_win_condition: self
                .by_win_condition
                .into_iter()
                .map(|(w, t)| (w, map_fn(t)))
                .collect(),
        }
    }

    /// Return a `SigMap` which contains references to the values held by this `SigMap`.
    pub fn by_ref(&self) -> SigMap<&T> {
        SigMap {
            by_outcome: self.by_outcome.iter().map(|(&k, v)| (k, v)).collect(),
            by_win_condition: self.by_win_condition.iter().map(|(&k, v)| (k, v)).collect(),
        }
    }

    /// Returns true if the given sigmap mirrors the keys of this sigmap exactly.
    /// This means both sigmaps have entries for all the same outcomes and win
    /// conditions, without any extra leftover entries.
    pub fn is_mirror<V>(&self, other: &SigMap<V>) -> bool {
        for outcome in self.by_outcome.keys() {
            if !other.by_outcome.contains_key(outcome) {
                return false;
            }
        }
        for win_cond in self.by_win_condition.keys() {
            if !other.by_win_condition.contains_key(win_cond) {
                return false;
            }
        }

        if self.by_outcome.len() != other.by_outcome.len()
            || self.by_win_condition.len() != other.by_win_condition.len()
        {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oracles::EventLockingConditions;
    use secp::{MaybePoint, Scalar};

    fn key(i: u8) -> Point {
        let mut bytes = [0u8; 32];
        bytes[31] = i;
        Scalar::from_slice(&bytes).unwrap().base_point_mul()
    }

    fn player(i: u8) -> Player {
        Player {
            pubkey: key(i),
            ticket_hash: [i; 32],
            payout_hash: [100 + i; 32],
        }
    }

    fn valid_params() -> ContractParameters {
        ContractParameters {
            market_maker: MarketMaker { pubkey: key(200) },
            players: vec![player(1), player(2)],
            event: EventLockingConditions {
                locking_points: vec![MaybePoint::Valid(key(50)), MaybePoint::Valid(key(51))],
                expiry: Some(1_000),
            },
            outcome_payouts: BTreeMap::from([
                (Outcome::Attestation(0), PayoutWeights::from([(0, 1)])),
                (
                    Outcome::Attestation(1),
                    PayoutWeights::from([(0, 1), (1, 3)]),
                ),
                (Outcome::Expiry, PayoutWeights::from([(1, 1)])),
            ]),
            fee_rate: FeeRate::from_sat_per_vb_u32(10),
            funding_value: Amount::from_sat(100_000),
            relative_locktime_block_delta: 144,
        }
    }

    #[test]
    fn accepts_valid_parameters() {
        valid_params().validate().expect("valid parameters");
    }

    #[test]
    fn rejects_empty_outcome_payouts() {
        let mut p = valid_params();
        p.outcome_payouts.clear();
        assert!(matches!(p.validate(), Err(Error::EmptyOutcomePayouts)));
    }

    #[test]
    fn rejects_duplicate_ticket_hash() {
        let mut p = valid_params();
        p.players[1].ticket_hash = p.players[0].ticket_hash;
        assert!(matches!(p.validate(), Err(Error::DuplicateTicketHash)));
    }

    #[test]
    fn rejects_duplicate_payout_hash() {
        let mut p = valid_params();
        p.players[1].payout_hash = p.players[0].payout_hash;
        assert!(matches!(p.validate(), Err(Error::DuplicatePayoutHash)));
    }

    #[test]
    fn rejects_ticket_payout_hash_collision() {
        // Own ticket hash reused as payout hash.
        let mut p = valid_params();
        p.players[0].payout_hash = p.players[0].ticket_hash;
        assert!(matches!(
            p.validate(),
            Err(Error::TicketPayoutHashCollision)
        ));

        // Another player's ticket hash used as payout hash.
        let mut p = valid_params();
        p.players[0].payout_hash = p.players[1].ticket_hash;
        assert!(matches!(
            p.validate(),
            Err(Error::TicketPayoutHashCollision)
        ));
    }

    #[test]
    fn rejects_shared_pubkeys() {
        let mut p = valid_params();
        p.players[1].pubkey = p.players[0].pubkey;
        assert!(matches!(p.validate(), Err(Error::DuplicatePubkey)));

        let mut p = valid_params();
        p.players[0].pubkey = p.market_maker.pubkey;
        assert!(matches!(p.validate(), Err(Error::DuplicatePubkey)));
    }

    #[test]
    fn rejects_locking_point_at_infinity() {
        let mut p = valid_params();
        p.event.locking_points[1] = MaybePoint::Infinity;
        assert!(matches!(p.validate(), Err(Error::InvalidLockingPoint)));
    }

    #[test]
    fn rejects_unknown_outcome_and_bad_payout_maps() {
        let mut p = valid_params();
        p.outcome_payouts
            .insert(Outcome::Attestation(2), PayoutWeights::from([(0, 1)]));
        assert!(matches!(p.validate(), Err(Error::UnknownOutcome)));

        let mut p = valid_params();
        p.event.expiry = None;
        assert!(matches!(p.validate(), Err(Error::UnknownOutcome)));

        let mut p = valid_params();
        p.outcome_payouts
            .insert(Outcome::Attestation(0), PayoutWeights::new());
        assert!(matches!(p.validate(), Err(Error::EmptyPayoutMap)));

        let mut p = valid_params();
        p.outcome_payouts
            .insert(Outcome::Attestation(0), PayoutWeights::from([(0, 0)]));
        assert!(matches!(p.validate(), Err(Error::InvalidPayoutWeight)));

        let mut p = valid_params();
        p.outcome_payouts
            .insert(Outcome::Attestation(0), PayoutWeights::from([(2, 1)]));
        assert!(matches!(p.validate(), Err(Error::OutOfBoundsPlayerIndex)));
    }

    #[test]
    fn rejects_payout_weight_overflow() {
        // Sum of weights overflows.
        let mut p = valid_params();
        p.outcome_payouts.insert(
            Outcome::Attestation(1),
            PayoutWeights::from([(0, u64::MAX), (1, 1)]),
        );
        assert!(matches!(p.validate(), Err(Error::PayoutWeightOverflow)));

        // Sum fits, but funding_value * total_weight does not.
        let mut p = valid_params();
        p.outcome_payouts.insert(
            Outcome::Attestation(1),
            PayoutWeights::from([(0, u64::MAX / 2), (1, u64::MAX / 2)]),
        );
        assert!(matches!(p.validate(), Err(Error::PayoutWeightOverflow)));

        // Large but safe weights are fine.
        let mut p = valid_params();
        p.outcome_payouts.insert(
            Outcome::Attestation(1),
            PayoutWeights::from([(0, 1 << 40), (1, 1 << 40)]),
        );
        p.validate().expect("2^41 * 100_000 sats fits in a u64");
    }

    #[test]
    fn rejects_bad_fee_rate_funding_value_and_locktime() {
        let mut p = valid_params();
        p.fee_rate = FeeRate::ZERO;
        assert!(matches!(p.validate(), Err(Error::InvalidFeeRate)));

        let mut p = valid_params();
        p.funding_value = Amount::ZERO;
        assert!(matches!(p.validate(), Err(Error::InvalidFundingValue)));

        let mut p = valid_params();
        p.relative_locktime_block_delta = 0;
        assert!(matches!(p.validate(), Err(Error::InvalidLocktime)));

        let mut p = valid_params();
        p.relative_locktime_block_delta = ContractParameters::MAX_RELATIVE_LOCKTIME_BLOCK_DELTA;
        p.validate().expect("maximum delta is allowed");
        assert_eq!(p.reclaim_block_delay(), 0xFFFE);

        p.relative_locktime_block_delta = ContractParameters::MAX_RELATIVE_LOCKTIME_BLOCK_DELTA + 1;
        assert!(matches!(p.validate(), Err(Error::InvalidLocktime)));
    }

    #[test]
    fn rejects_zero_expiry() {
        let mut p = valid_params();
        p.event.expiry = Some(0);
        assert!(matches!(p.validate(), Err(Error::InvalidExpiry)));

        // No expiry at all is fine: there is simply no expiry transaction.
        let mut p = valid_params();
        p.event.expiry = None;
        p.outcome_payouts.remove(&Outcome::Expiry);
        p.validate().expect("missing expiry is allowed");
    }

    #[test]
    fn reclaim_block_delay_never_wraps() {
        let mut p = valid_params();
        assert_eq!(p.reclaim_block_delay(), 288);
        p.relative_locktime_block_delta = 40_000;
        assert_eq!(p.reclaim_block_delay(), u16::MAX);
        assert!(p.reclaim_block_delay() >= p.relative_locktime_block_delta);
    }
}
