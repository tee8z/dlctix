//! Error types returned by this crate.

use std::fmt;

/// Every error which can be returned by this crate.
#[derive(Debug)]
pub enum Error {
    // Fee calculation errors
    /// The available coins do not cover the mining fee.
    InsufficientFunds,
    /// The fee could not be subtracted from the available coins.
    InvalidFeeAmount,
    /// An output value would be below the dust threshold.
    DustAmount,
    /// A transaction weight or fee calculation overflowed.
    WeightOverflow,

    // Contract validation errors
    /// Two players share the same ticket hash.
    DuplicateTicketHash,
    /// Two players share the same payout hash.
    DuplicatePayoutHash,
    /// A payout hash is equal to a ticket hash. Revealing one preimage would
    /// then unlock a spending path guarded by the other.
    TicketPayoutHashCollision,
    /// The same public key is used by more than one signer: two players, or a
    /// player and the market maker.
    DuplicatePubkey,
    /// A payout weight is zero.
    InvalidPayoutWeight,
    /// The payout weights are so large that payout amounts cannot be computed
    /// without integer overflow.
    PayoutWeightOverflow,
    /// A payout map refers to a player index which does not exist.
    OutOfBoundsPlayerIndex,
    /// The fee rate is zero.
    InvalidFeeRate,
    /// The relative locktime delta is zero, or is too large for twice its value
    /// to be encoded in a BIP-68 relative locktime.
    InvalidLocktime,
    /// The funding value is zero.
    InvalidFundingValue,
    /// An oracle locking point is the point at infinity, which would let anyone
    /// unlock the corresponding outcome without an oracle attestation.
    InvalidLockingPoint,
    /// An outcome is not covered by the event's locking points or expiry.
    UnknownOutcome,
    /// The contract has no outcomes at all.
    EmptyOutcomePayouts,
    /// A payout map contains no winners.
    EmptyPayoutMap,

    // Transaction signing errors
    /// A signature, attestation, or set of signature maps is invalid.
    InvalidSignature,
    /// A required signature is missing.
    MissingSignature(String),
    /// A required nonce is missing.
    MissingNonce(String),
    /// A key does not belong to the contract, or does not match the expected key.
    InvalidKey,

    // Dependency errors
    /// MuSig2 key aggregation failed.
    KeyAgg(musig2::errors::KeyAggError),
    /// Tweaking an aggregated key failed.
    Tweak(musig2::errors::TweakError),
    /// MuSig2 signature verification failed.
    Verify(musig2::errors::VerifyError),
    /// MuSig2 partial signing failed.
    Signing(musig2::errors::SigningError),
    /// A curve point encoding is invalid.
    InvalidPoint(secp::errors::InvalidPointBytes),
    /// The provided secret keys do not match the aggregated key.
    InvalidSecretKeys(musig2::errors::InvalidSecretKeysError),
    /// Building a taproot tree failed.
    TaprootBuilder(bitcoin::taproot::TaprootBuilderError),
    /// Finalizing a taproot tree failed.
    IncompleteBuilder(bitcoin::taproot::IncompleteBuilderError),
    /// Computing a taproot sighash failed.
    TaprootSighash(bitcoin::sighash::TaprootError),
    /// Parsing an outcome or player index from a string failed.
    ParseOutcomeIndex(std::num::ParseIntError),

    // General errors
    /// A caller-provided input is invalid.
    InvalidInput(&'static str),
    /// A string could not be parsed.
    Conversion(&'static str),
}

impl std::error::Error for Error {
    // Implement source() to expose inner errors
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;
        match self {
            KeyAgg(e) => Some(e),
            Tweak(e) => Some(e),
            Verify(e) => Some(e),
            Signing(e) => Some(e),
            InvalidPoint(e) => Some(e),
            InvalidSecretKeys(e) => Some(e),
            TaprootBuilder(e) => Some(e),
            IncompleteBuilder(e) => Some(e),
            TaprootSighash(e) => Some(e),
            ParseOutcomeIndex(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match self {
            InsufficientFunds => write!(f, "insufficient funds available"),
            InvalidFeeAmount => write!(f, "invalid fee amount"),
            DustAmount => write!(f, "output amount would be below dust threshold"),
            WeightOverflow => write!(f, "transaction weight calculation overflow"),

            DuplicateTicketHash => write!(f, "duplicate ticket hash found"),
            DuplicatePayoutHash => write!(f, "duplicate payout hash found"),
            TicketPayoutHashCollision => write!(f, "a payout hash is equal to a ticket hash"),
            DuplicatePubkey => write!(f, "the same public key is used by more than one signer"),
            InvalidPayoutWeight => write!(f, "invalid payout weight"),
            PayoutWeightOverflow => write!(f, "payout weights are too large to compute payouts"),
            OutOfBoundsPlayerIndex => write!(f, "player index out of bounds"),
            InvalidFeeRate => write!(f, "invalid fee rate"),
            InvalidLocktime => write!(f, "invalid relative locktime"),
            InvalidFundingValue => write!(f, "invalid funding value"),
            InvalidLockingPoint => write!(f, "oracle locking point is the point at infinity"),
            UnknownOutcome => write!(f, "unknown outcome"),
            EmptyOutcomePayouts => write!(f, "contract has no outcomes"),
            EmptyPayoutMap => write!(f, "empty payout map"),

            InvalidSignature => write!(f, "invalid signature"),
            MissingSignature(msg) => write!(f, "missing required signature: {}", msg),
            MissingNonce(msg) => write!(f, "missing required nonce: {}", msg),
            InvalidKey => write!(f, "invalid key"),

            InvalidInput(msg) => write!(f, "invalid input: {}", msg),
            Conversion(msg) => write!(f, "conversion error: {}", msg),

            KeyAgg(e) => write!(f, "key aggregation error: {}", e),
            Tweak(e) => write!(f, "key tweaking error: {}", e),
            Verify(e) => write!(f, "signature verification error: {}", e),
            Signing(e) => write!(f, "signing error: {}", e),
            InvalidPoint(e) => write!(f, "invalid point error: {}", e),
            InvalidSecretKeys(e) => write!(f, "invalid secret keys: {}", e),
            TaprootBuilder(e) => write!(f, "taproot builder error: {}", e),
            IncompleteBuilder(e) => write!(f, "incomplete taproot builder: {}", e),
            TaprootSighash(e) => write!(f, "taproot sighash error: {}", e),
            ParseOutcomeIndex(e) => write!(f, "invalid outcome index: {}", e),
        }
    }
}

// Implement From for common error types
impl From<musig2::errors::KeyAggError> for Error {
    fn from(e: musig2::errors::KeyAggError) -> Self {
        Error::KeyAgg(e)
    }
}

impl From<musig2::errors::TweakError> for Error {
    fn from(e: musig2::errors::TweakError) -> Self {
        Error::Tweak(e)
    }
}

impl From<musig2::errors::VerifyError> for Error {
    fn from(e: musig2::errors::VerifyError) -> Self {
        Error::Verify(e)
    }
}

impl From<musig2::errors::SigningError> for Error {
    fn from(e: musig2::errors::SigningError) -> Self {
        Error::Signing(e)
    }
}

impl From<secp::errors::InvalidPointBytes> for Error {
    fn from(e: secp::errors::InvalidPointBytes) -> Self {
        Error::InvalidPoint(e)
    }
}

impl From<musig2::errors::InvalidSecretKeysError> for Error {
    fn from(e: musig2::errors::InvalidSecretKeysError) -> Self {
        Error::InvalidSecretKeys(e)
    }
}

impl From<bitcoin::taproot::TaprootBuilderError> for Error {
    fn from(e: bitcoin::taproot::TaprootBuilderError) -> Self {
        Error::TaprootBuilder(e)
    }
}

impl From<bitcoin::taproot::IncompleteBuilderError> for Error {
    fn from(e: bitcoin::taproot::IncompleteBuilderError) -> Self {
        Error::IncompleteBuilder(e)
    }
}

impl From<bitcoin::sighash::TaprootError> for Error {
    fn from(e: bitcoin::sighash::TaprootError) -> Self {
        Error::TaprootSighash(e)
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(e: std::num::ParseIntError) -> Self {
        Error::ParseOutcomeIndex(e)
    }
}
