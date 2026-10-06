//! Pay-to-anchor (P2A) outputs and CPFP fee bumping.
//!
//! When [`ContractParameters::anchor`][crate::ContractParameters::anchor] is set,
//! every outcome transaction, the expiry transaction, and every split transaction
//! carries one extra output as its **last** output: a pay-to-anchor output
//! (`OP_1 <0x4e73>`) worth [`AnchorParams::value`]. Anyone can spend a P2A output
//! with an empty witness, so any party (a player, the market maker, or a third
//! party) can fee-bump a stuck pre-signed transaction with a child-pays-for-parent
//! (CPFP) child that spends the anchor plus some of its own coins.
//!
//! # Design
//!
//! - The anchor carries a small non-zero value, at least [`P2A_DUST_VALUE`]
//!   (240 sats), and the parents stay at transaction version 2 and pay the
//!   contract's [`fee_rate`][crate::ContractParameters::fee_rate]. Spending a P2A
//!   output is standard from Bitcoin Core 28; creating one is standard on every
//!   node that relays segwit v1 outputs. A zero-value (ephemeral) anchor would
//!   need a zero-fee TRUC (version 3) parent, package relay and Bitcoin Core 29
//!   on every hop, and TRUC caps a parent at 10,000 vB, which a split transaction
//!   with a few hundred winners exceeds.
//! - Because the parent still pays its own fee, it propagates on its own through
//!   any node, and a CPFP child is only needed when fees spike. Integrators can
//!   lower [`fee_rate`][crate::ContractParameters::fee_rate] towards a floor once
//!   anchors are on, since a stuck parent can now be bumped.
//! - The anchor value is funded by the contract. On an outcome transaction it is
//!   subtracted from the funding value along with the mining fee. On a split
//!   transaction it is subtracted from the outcome value and shared equally among
//!   the winners, exactly like the split transaction's mining fee.
//! - The anchor is the last output, so the outcome output stays at index `0` and
//!   split outputs keep their per-player indexes.
//!
//! # Pinning
//!
//! A P2A output has no key, so anyone can attach a large, low fee-rate child to it
//! and force an honest bumper to pay that child's absolute fee to replace it
//! (BIP-125 rule 3). Without TRUC this cannot be prevented. Bump early, and bump
//! from more than one party if the market maker is suspected of pinning a split
//! transaction to run down the winners' delay.
//!
//! # Building a CPFP child
//!
//! 1. Broadcast the fully signed parent ([`SignedContract::signed_outcome_tx`][crate::SignedContract::signed_outcome_tx],
//!    [`SignedContract::expiry_tx`][crate::SignedContract::expiry_tx], or
//!    [`SignedContract::signed_split_tx`][crate::SignedContract::signed_split_tx]).
//! 2. Call [`SignedContract::cpfp_child_template`][crate::SignedContract::cpfp_child_template]
//!    (or [`cpfp_child_template`] for a parent whose fee you already know) with
//!    your own confirmed funding UTXOs, a change script, and the target package
//!    fee rate. The anchor is input `0`, followed by the funding inputs in order.
//! 3. Sign the funding inputs with your wallet. The anchor input needs no
//!    signature: leave its witness empty.
//! 4. Broadcast the child after the parent, or submit both together with
//!    `submitpackage` if the parent is below the node's mempool minimum.
//!
//! The child signals replaceability, so it can be replaced with a higher fee
//! child later.

use bitcoin::{
    absolute::LockTime, transaction::InputWeightPrediction, Amount, FeeRate, OutPoint, ScriptBuf,
    Sequence, Transaction, TxIn, TxOut, Weight,
};
use serde::{Deserialize, Serialize};

use crate::errors::Error;

/// The P2A script pubkey: `OP_1 OP_PUSHBYTES_2 4e73`.
pub const P2A_SCRIPT_PUBKEY_BYTES: [u8; 4] = [0x51, 0x02, 0x4e, 0x73];

/// The serialized length of a P2A script pubkey.
pub const P2A_SCRIPT_PUBKEY_SIZE: usize = P2A_SCRIPT_PUBKEY_BYTES.len();

/// The smallest non-dust value of a P2A output under Bitcoin Core's default
/// dust relay fee of 3 sat/vB.
pub const P2A_DUST_VALUE: Amount = Amount::from_sat(240);

/// The weight of one P2A output: 8 bytes of value, a 1-byte script length, and
/// the 4-byte script.
pub const ANCHOR_OUTPUT_WEIGHT: Weight =
    Weight::from_wu(4 * (8 + 1 + P2A_SCRIPT_PUBKEY_SIZE as u64));

/// The weight prediction of an input spending a P2A output: an empty script sig
/// and an empty witness.
pub const ANCHOR_INPUT_WEIGHT: InputWeightPrediction = InputWeightPrediction::from_slice(0, &[]);

/// Parameters of the optional pay-to-anchor output added to every outcome,
/// expiry, and split transaction. See the [module docs][self].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorParams {
    /// The value of each anchor output. Must be at least [`P2A_DUST_VALUE`].
    pub value: Amount,
}

impl Default for AnchorParams {
    fn default() -> Self {
        AnchorParams {
            value: P2A_DUST_VALUE,
        }
    }
}

impl AnchorParams {
    /// Returns the anchor output which is appended to every pre-signed transaction.
    pub fn output(&self) -> TxOut {
        TxOut {
            value: self.value,
            script_pubkey: anchor_script_pubkey(),
        }
    }
}

/// Returns the P2A script pubkey, `OP_1 <0x4e73>`.
pub fn anchor_script_pubkey() -> ScriptBuf {
    ScriptBuf::new_p2a()
}

/// Returns true if the script pubkey is a P2A script.
pub fn is_anchor_script(script_pubkey: &bitcoin::Script) -> bool {
    script_pubkey.as_bytes() == P2A_SCRIPT_PUBKEY_BYTES
}

/// Find the anchor output of a transaction. Returns its outpoint and the output
/// itself, or `None` if the transaction has no P2A output, for example because
/// it was built from parameters without an anchor.
pub fn find_anchor(tx: &Transaction) -> Option<(OutPoint, &TxOut)> {
    let txid = tx.compute_txid();
    tx.output
        .iter()
        .enumerate()
        .rev()
        .find(|(_, output)| is_anchor_script(&output.script_pubkey))
        .map(|(vout, output)| (OutPoint::new(txid, vout as u32), output))
}

/// A confirmed coin which pays for a CPFP child.
#[derive(Debug, Clone)]
pub struct CpfpFundingInput {
    /// The coin to spend.
    pub outpoint: OutPoint,
    /// The output being spent, used for the input value and for signing.
    pub prevout: TxOut,
    /// The expected weight of the input once signed.
    pub weight: InputWeightPrediction,
}

/// Build an unsigned CPFP child which spends the anchor of `parent`.
///
/// `parent` must be the fully signed transaction, since its weight is part of
/// the package fee rate, and `parent_fee` the fee it pays on its own. The child
/// pays enough that the parent and child together reach `package_fee_rate`, and
/// never less than `package_fee_rate` on its own weight. Everything else,
/// including the anchor value, goes to a single output paying
/// `change_script_pubkey`.
///
/// The anchor is input `0` with an empty witness; the funding inputs follow in
/// the given order and must be signed by the caller.
///
/// Returns [`Error::MissingAnchor`] if `parent` has no anchor output,
/// [`Error::InsufficientFunds`] if the coins do not cover the fee, and
/// [`Error::DustAmount`] if the change would be dust.
pub fn cpfp_child_template(
    parent: &Transaction,
    parent_fee: Amount,
    funding_inputs: &[CpfpFundingInput],
    change_script_pubkey: ScriptBuf,
    package_fee_rate: FeeRate,
) -> Result<Transaction, Error> {
    let (anchor_outpoint, anchor_output) = find_anchor(parent).ok_or(Error::MissingAnchor)?;

    let input_weights = std::iter::once(ANCHOR_INPUT_WEIGHT)
        .chain(funding_inputs.iter().map(|input| input.weight))
        .collect::<Vec<_>>();
    let child_weight =
        bitcoin::transaction::predict_weight(input_weights, [change_script_pubkey.len()]);

    let parent_vsize = parent.weight().to_vbytes_ceil();
    let child_vsize = child_weight.to_vbytes_ceil();
    let package_fee = package_fee_rate
        .fee_vb(parent_vsize + child_vsize)
        .ok_or(Error::WeightOverflow)?;
    let child_min_fee = package_fee_rate
        .fee_vb(child_vsize)
        .ok_or(Error::WeightOverflow)?;
    let child_fee = package_fee
        .checked_sub(parent_fee)
        .unwrap_or(Amount::ZERO)
        .max(child_min_fee);

    let available = funding_inputs
        .iter()
        .try_fold(anchor_output.value, |acc, input| {
            acc.checked_add(input.prevout.value)
        })
        .ok_or(Error::InvalidFeeAmount)?;
    let change_value = crate::contract::fees::fee_subtract_safe(
        available,
        child_fee,
        change_script_pubkey.minimal_non_dust() - Amount::ONE_SAT,
    )?;

    let input = std::iter::once(anchor_outpoint)
        .chain(funding_inputs.iter().map(|input| input.outpoint))
        .map(|previous_output| TxIn {
            previous_output,
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            ..TxIn::default()
        })
        .collect();

    Ok(Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input,
        output: vec![TxOut {
            value: change_value,
            script_pubkey: change_script_pubkey,
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash as _;

    #[test]
    fn p2a_constants() {
        let script = anchor_script_pubkey();
        assert_eq!(script.as_bytes(), &P2A_SCRIPT_PUBKEY_BYTES);
        assert!(is_anchor_script(&script));
        assert_eq!(script.len(), P2A_SCRIPT_PUBKEY_SIZE);
        assert_eq!(script.minimal_non_dust(), P2A_DUST_VALUE);
        assert_eq!(
            ANCHOR_OUTPUT_WEIGHT,
            AnchorParams::default().output().weight()
        );
        // Only the empty script sig's length byte; `predict_weight` adds the outpoint, the
        // sequence and the empty witness's item count.
        assert_eq!(ANCHOR_INPUT_WEIGHT.weight(), Weight::from_wu(4));
    }

    fn parent_with_anchor() -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![
                TxOut {
                    value: Amount::from_sat(10_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                },
                AnchorParams::default().output(),
            ],
        }
    }

    fn funding(value: u64) -> CpfpFundingInput {
        CpfpFundingInput {
            outpoint: OutPoint::new(bitcoin::Txid::from_byte_array([7; 32]), 1),
            prevout: TxOut {
                value: Amount::from_sat(value),
                script_pubkey: ScriptBuf::new_p2a(),
            },
            weight: InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH,
        }
    }

    #[test]
    fn find_anchor_returns_last_p2a_output() {
        let parent = parent_with_anchor();
        let (outpoint, output) = find_anchor(&parent).unwrap();
        assert_eq!(outpoint, OutPoint::new(parent.compute_txid(), 1));
        assert_eq!(output.value, P2A_DUST_VALUE);

        let mut no_anchor = parent.clone();
        no_anchor.output.pop();
        assert!(find_anchor(&no_anchor).is_none());
    }

    #[test]
    fn cpfp_child_reaches_package_fee_rate() {
        let parent = parent_with_anchor();
        let parent_fee = Amount::from_sat(100);
        let change = ScriptBuf::new_p2a();
        let rate = FeeRate::from_sat_per_vb_u32(20);

        let child = cpfp_child_template(
            &parent,
            parent_fee,
            &[funding(50_000)],
            change.clone(),
            rate,
        )
        .unwrap();

        assert_eq!(child.input.len(), 2);
        assert_eq!(child.input[0].previous_output.txid, parent.compute_txid());
        assert_eq!(child.input[0].previous_output.vout, 1);
        assert!(child.input[0].witness.is_empty());
        assert_eq!(child.output.len(), 1);

        let child_weight = bitcoin::transaction::predict_weight(
            [
                ANCHOR_INPUT_WEIGHT,
                InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH,
            ],
            [change.len()],
        );
        let child_fee = Amount::from_sat(50_000) + P2A_DUST_VALUE - child.output[0].value;
        let package_vsize = parent.weight().to_vbytes_ceil() + child_weight.to_vbytes_ceil();
        assert_eq!(
            parent_fee + child_fee,
            rate.fee_vb(package_vsize).unwrap(),
            "package pays exactly the target rate"
        );

        // A parent which already overpays still needs a child paying its own way.
        let child = cpfp_child_template(
            &parent,
            Amount::from_sat(1_000_000),
            &[funding(50_000)],
            change.clone(),
            rate,
        )
        .unwrap();
        let child_fee = Amount::from_sat(50_000) + P2A_DUST_VALUE - child.output[0].value;
        assert_eq!(
            child_fee,
            rate.fee_vb(child_weight.to_vbytes_ceil()).unwrap()
        );
    }

    #[test]
    fn cpfp_child_errors() {
        let parent = parent_with_anchor();
        let rate = FeeRate::from_sat_per_vb_u32(20);

        let mut no_anchor = parent.clone();
        no_anchor.output.pop();
        assert!(matches!(
            cpfp_child_template(
                &no_anchor,
                Amount::ZERO,
                &[funding(50_000)],
                ScriptBuf::new_p2a(),
                rate
            ),
            Err(Error::MissingAnchor)
        ));

        assert!(matches!(
            cpfp_child_template(&parent, Amount::ZERO, &[], ScriptBuf::new_p2a(), rate),
            Err(Error::InsufficientFunds)
        ));
    }
}
