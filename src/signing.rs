//! Types for signing DLC transactions with an external signer.
//!
//! [`SigningData`] packages every sighash, adaptor point, signer set and aggregate
//! key needed to produce the MuSig2 signatures for a [`TicketedDLC`][crate::TicketedDLC]
//! without using [`SigningSession`][crate::SigningSession]. It is intended for HSMs,
//! secure enclaves, or MuSig2 implementations written in other languages.
//!
//! For most use cases [`SigningSession`][crate::SigningSession] is preferable: it
//! handles nonce generation, aggregation, and verification automatically.
//!
//! # Workflow
//!
//! 1. Every party builds the same [`TicketedDLC`][crate::TicketedDLC] from the agreed
//!    [`ContractParameters`][crate::ContractParameters] and funding outpoint, and calls
//!    [`TicketedDLC::signing_data`][crate::TicketedDLC::signing_data].
//! 2. Signers exchange public nonces and partial signatures for every sighash in the
//!    [`SigningData`] they are a signer for, using any BIP-327 implementation.
//! 3. Aggregated signatures are assembled into a [`ContractSignatures`][crate::ContractSignatures].
//! 4. Every party verifies them with
//!    [`TicketedDLC::into_signed_contract`][crate::TicketedDLC::into_signed_contract]
//!    (or [`TicketedDLC::verify_signatures`][crate::TicketedDLC::verify_signatures])
//!    **before** the market maker funds the contract and before any player buys a ticket.
//!
//! # Key aggregation
//!
//! All aggregate keys are plain BIP-327 MuSig2 keys built from the ordered signer
//! lists in this struct. Keys are sorted ascending by their 33-byte compressed
//! encoding, which is the BIP-327 key-sorting rule. An external signer should
//! rebuild each aggregate key from the ordered list and check that it equals the
//! corresponding `*_agg_pubkey` field before signing anything.
//!
//! - Outcome transactions (including the expiry transaction) spend the funding output
//!   with a key-path spend. Signers are every player plus the market maker
//!   ([`funding_signers`][SigningData::funding_signers]). The funding output key is the
//!   **untweaked** aggregate key ([`funding_agg_pubkey`][SigningData::funding_agg_pubkey]):
//!   no BIP-341 taproot tweak is applied, because MuSig2 key aggregation coefficients
//!   already prevent any participant from hiding a script path in the aggregate key.
//! - Split transactions spend an outcome output through a tapscript leaf which pushes
//!   the untweaked aggregate key of the market maker plus that outcome's winners
//!   ([`split_signers`][SigningData::split_signers] and
//!   [`split_agg_pubkeys`][SigningData::split_agg_pubkeys]). Each
//!   [`WinCondition`] of an outcome is a distinct leaf and therefore a distinct sighash,
//!   but all leaves of one outcome share the same signer set and aggregate key.
//!
//! # Adaptor signatures
//!
//! Every [`Outcome::Attestation`] sighash MUST be signed with an adaptor signature
//! encrypted under the adaptor point in [`adaptor_points`][SigningData::adaptor_points].
//! Signing it with a plain signature makes that outcome transaction broadcastable by
//! anyone without the oracle's attestation, which lets that party pick the outcome
//! of the contract. [`Outcome::Expiry`] and all split sighashes use plain signatures.
//! Use [`SigningData::requires_adaptor`] and [`SigningData::adaptor_point`] rather than
//! inspecting the maps directly.
//!
//! # Nonce safety
//!
//! MuSig2 secret nonces are one-time secrets. Reusing a secret nonce, or signing two
//! different messages with the same secret nonce, leaks the signing key. An external
//! signer must:
//!
//! - generate a fresh secret nonce for every sighash in this struct, per signing
//!   session, from a CSPRNG following BIP-327 `NonceGen`, ideally binding the sighash
//!   and aggregate key as extra input;
//! - produce exactly one partial signature per secret nonce and then destroy it;
//! - never re-sign a sighash with an existing nonce if the aggregate nonce, the signer
//!   set, or the sighash changed. Start a new session with fresh nonces instead.
//!
//! # Trust
//!
//! `SigningData` is plain data; a signer trusts whoever produced it. A signer that
//! cannot rebuild the transactions from the
//! [`ContractParameters`][crate::ContractParameters] itself should only accept
//! `SigningData` over an authenticated channel from a host it trusts. The host in
//! turn must verify the aggregated result with
//! [`TicketedDLC::verify_signatures`][crate::TicketedDLC::verify_signatures], because
//! an invalid signature set leaves the market maker's capital locked in the funding
//! output until every player cooperates.

use crate::contract::{Outcome, OutcomeIndex, WinCondition};
use crate::errors::Error;
use secp::{MaybePoint, Point};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// All data needed to sign a ticketed DLC using an external signing system.
///
/// See the [module documentation][self] for the key aggregation rules, the adaptor
/// signature requirements, and the nonce-safety requirements a signer must follow.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SigningData {
    /// Sighash of each outcome transaction, spending the funding output by key path.
    /// [`Outcome::Attestation`] entries require adaptor signatures; the
    /// [`Outcome::Expiry`] entry, if present, requires a plain signature.
    pub outcome_sighashes: BTreeMap<Outcome, [u8; 32]>,

    /// Adaptor point for each attestation outcome, taken from the oracle's
    /// [`locking_points`][crate::EventLockingConditions::locking_points]. There is one
    /// entry for every [`Outcome::Attestation`] key in
    /// [`outcome_sighashes`][Self::outcome_sighashes]. [`Outcome::Expiry`] has no entry.
    pub adaptor_points: BTreeMap<OutcomeIndex, MaybePoint>,

    /// Sighash of each split transaction tapscript spending path, keyed by the
    /// [`WinCondition`] whose leaf is being signed. Always plain signatures.
    pub split_sighashes: BTreeMap<WinCondition, [u8; 32]>,

    /// Ordered signer set for the funding output: every player and the market maker,
    /// sorted by compressed encoding. This is the exact input to BIP-327 `KeyAgg`.
    pub funding_signers: Vec<Point>,

    /// The untweaked MuSig2 aggregate key of [`funding_signers`][Self::funding_signers].
    /// It is used directly as the funding output's taproot output key, without a
    /// BIP-341 tweak. Outcome transactions are signed under this key.
    pub funding_agg_pubkey: Point,

    /// Ordered signer set for each outcome's split transaction: the market maker plus
    /// that outcome's winners, sorted by compressed encoding.
    pub split_signers: BTreeMap<Outcome, Vec<Point>>,

    /// The untweaked MuSig2 aggregate key of each entry in
    /// [`split_signers`][Self::split_signers]. Split transactions spend via tapscript
    /// leaves which push this key, so it is used untweaked.
    pub split_agg_pubkeys: BTreeMap<Outcome, Point>,
}

impl SigningData {
    /// Returns the total number of aggregated signatures needed (outcome + split transactions).
    pub fn total_signature_count(&self) -> usize {
        self.outcome_sighashes.len() + self.split_sighashes.len()
    }

    /// Returns true if the given outcome requires an adaptor signature.
    ///
    /// This is true for every [`Outcome::Attestation`], regardless of whether
    /// [`adaptor_points`][Self::adaptor_points] currently contains an entry for it.
    /// A missing adaptor point means the data is incomplete and the outcome must not
    /// be signed at all; it never means a plain signature is acceptable.
    pub fn requires_adaptor(&self, outcome: &Outcome) -> bool {
        matches!(outcome, Outcome::Attestation(_))
    }

    /// Returns the adaptor point to encrypt the signature on `outcome` under.
    ///
    /// Returns `Ok(None)` for [`Outcome::Expiry`], which uses a plain signature.
    /// Returns `Error::UnknownOutcome` if `outcome` is an attestation outcome
    /// without an adaptor point, or is not part of this signing data at all.
    pub fn adaptor_point(&self, outcome: &Outcome) -> Result<Option<MaybePoint>, Error> {
        if !self.outcome_sighashes.contains_key(outcome) {
            return Err(Error::UnknownOutcome);
        }
        match outcome {
            Outcome::Attestation(idx) => self
                .adaptor_points
                .get(idx)
                .copied()
                .map(Some)
                .ok_or(Error::UnknownOutcome),
            Outcome::Expiry => Ok(None),
        }
    }

    /// Returns the adaptor point for an attestation outcome index, or `None` if
    /// there is no entry for that index. Prefer [`SigningData::adaptor_point`].
    pub fn get_adaptor_point(&self, outcome_index: OutcomeIndex) -> Option<&MaybePoint> {
        self.adaptor_points.get(&outcome_index)
    }
}
