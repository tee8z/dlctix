use bitcoin::{
    key::constants::SCHNORR_SIGNATURE_SIZE,
    opcodes::all::*,
    taproot::{LeafVersion, TaprootSpendInfo},
    transaction::InputWeightPrediction,
    Amount, ScriptBuf,
};
use musig2::KeyAggContext;
use secp::Point;

use crate::{
    errors::Error,
    hashlock::PREIMAGE_SIZE,
    parties::{MarketMaker, Player},
};

/// Represents a taproot contract for a specific player's split TX payout output.
/// This tree has three nodes:
///
/// 1. A relative-timelocked hash-lock which pays to the player if they know their ticket
///    preimage after one round of block delay.
///
/// 2. A relative-timelock which pays to the market maker after two rounds of block delay.
///
/// 3. A hash-lock which pays to the market maker immediately if they learn the
//     payout preimage from the player.
#[derive(Debug, Clone)]
pub(crate) struct SplitSpendInfo {
    untweaked_ctx: KeyAggContext,
    tweaked_ctx: KeyAggContext,
    payout_value: Amount,
    spend_info: TaprootSpendInfo,
    winner: Player,
    win_script: ScriptBuf,
    reclaim_script: ScriptBuf,
    sellback_script: ScriptBuf,
}

impl SplitSpendInfo {
    pub(crate) fn new(
        winner: Player,
        market_maker: &MarketMaker,
        payout_value: Amount,
        block_delta: u16,
    ) -> Result<SplitSpendInfo, Error> {
        let mut pubkeys = vec![market_maker.pubkey, winner.pubkey];
        pubkeys.sort();
        let untweaked_ctx = KeyAggContext::new(pubkeys)?;
        let joint_payout_pubkey: Point = untweaked_ctx.aggregated_pubkey();

        // The win script, used by a ticketholding winner to claim their
        // payout on-chain if the market maker doesn't cooperate.
        //
        // Inputs: <player_sig> <preimage>
        let win_script = bitcoin::script::Builder::new()
            // Check relative locktime: <delta> OP_CSV OP_DROP
            .push_int(block_delta as i64)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            // Check ticket preimage: OP_SHA256 <ticket_hash> OP_EQUALVERIFY
            .push_opcode(OP_SHA256)
            .push_slice(winner.ticket_hash)
            .push_opcode(OP_EQUALVERIFY)
            // Check signature: <winner_pk> OP_CHECKSIG
            .push_slice(winner.pubkey.serialize_xonly())
            .push_opcode(OP_CHECKSIG)
            .into_script();

        // The reclaim script, used by the market maker to reclaim their capital
        // if the player never paid for their ticket preimage.
        //
        // Inputs: <mm_sig>
        let reclaim_script = bitcoin::script::Builder::new()
            // Check relative locktime: <2*delta> OP_CSV OP_DROP
            .push_int(2 * block_delta as i64)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            // Check signature: <mm_pubkey> OP_CHECKSIG
            .push_slice(market_maker.pubkey.serialize_xonly())
            .push_opcode(OP_CHECKSIG)
            .into_script();

        // The sellback script, used by the market maker to reclaim their capital
        // if the player agrees to sell their payout output from the split TX back
        // to the market maker.
        //
        // Inputs: <mm_sig> <payout_preimage>
        let sellback_script = bitcoin::script::Builder::new()
            // Check payout preimage: OP_SHA256 <payout_hash> OP_EQUALVERIFY
            .push_opcode(OP_SHA256)
            .push_slice(winner.payout_hash)
            .push_opcode(OP_EQUALVERIFY)
            // Check signature: <mm_pubkey> OP_CHECKSIG
            .push_slice(market_maker.pubkey.serialize_xonly())
            .push_opcode(OP_CHECKSIG)
            .into_script();

        let weighted_script_leaves = [
            (2, sellback_script.clone()),
            (1, win_script.clone()),
            (1, reclaim_script.clone()),
        ];
        let tr_spend_info = TaprootSpendInfo::with_huffman_tree(
            secp256k1::SECP256K1,
            joint_payout_pubkey.into(),
            weighted_script_leaves,
        )?;

        let tweaked_ctx = untweaked_ctx.clone().with_taproot_tweak(
            tr_spend_info
                .merkle_root()
                .expect("should always have merkle root")
                .as_ref(),
        )?;

        let split_spend_info = SplitSpendInfo {
            untweaked_ctx,
            tweaked_ctx,
            payout_value,
            spend_info: tr_spend_info,
            winner,
            win_script,
            reclaim_script,
            sellback_script,
        };
        Ok(split_spend_info)
    }

    pub(crate) fn key_agg_ctx_untweaked(&self) -> &KeyAggContext {
        &self.untweaked_ctx
    }

    pub(crate) fn key_agg_ctx_tweaked(&self) -> &KeyAggContext {
        &self.tweaked_ctx
    }

    /// Returns the TX locking script for this player's split TX output contract.
    pub(crate) fn script_pubkey(&self) -> ScriptBuf {
        ScriptBuf::new_p2tr_tweaked(self.spend_info.output_key())
    }

    pub(crate) fn payout_value(&self) -> Amount {
        self.payout_value
    }

    /// Computes the input weight when spending an output of the split TX
    /// as an input of the player's win TX. This assumes the player's win script
    /// leaf is being used to unlock the taproot tree.
    pub(crate) fn input_weight_for_win_tx(&self) -> InputWeightPrediction {
        let win_control_block = self
            .spend_info
            .control_block(&(self.win_script.clone(), LeafVersion::TapScript))
            .expect("win script cannot be missing");

        // The witness stack for the win TX which spends a split TX output is:
        // <player_sig> <preimage> <script> <ctrl_block>
        InputWeightPrediction::new(
            0,
            [
                SCHNORR_SIGNATURE_SIZE,   // BIP340 schnorr signature
                PREIMAGE_SIZE,            // Ticket preimage
                self.win_script.len(),    // Script
                win_control_block.size(), // Control block
            ],
        )
    }

    /// Computes the input weight when spending an output of the split TX
    /// as an input of the market maker's reclaim TX. This assumes the market
    /// maker's reclaim script leaf is being used to unlock the taproot tree.
    pub(crate) fn input_weight_for_reclaim_tx(&self) -> InputWeightPrediction {
        let reclaim_control_block = self
            .spend_info
            .control_block(&(self.reclaim_script.clone(), LeafVersion::TapScript))
            .expect("reclaim script cannot be missing");

        // The witness stack for the reclaim TX which spends a split TX output is:
        // <player_sig> <script> <ctrl_block>
        InputWeightPrediction::new(
            0,
            [
                SCHNORR_SIGNATURE_SIZE,       // BIP340 schnorr signature
                self.reclaim_script.len(),    // Script
                reclaim_control_block.size(), // Control block
            ],
        )
    }

    /// Computes the input weight when spending an output of the split TX
    /// as an input of the sellback TX. This assumes the market maker's sellback
    /// script leaf is being used to unlock the taproot tree.
    pub(crate) fn input_weight_for_sellback_tx(&self) -> InputWeightPrediction {
        let sellback_control_block = self
            .spend_info
            .control_block(&(self.sellback_script.clone(), LeafVersion::TapScript))
            .expect("sellback script cannot be missing");

        // The witness stack for the sellback TX which spends a split TX output is:
        // <mm_sig> <payout_preimage> <script> <ctrl_block>
        InputWeightPrediction::new(
            0,
            [
                SCHNORR_SIGNATURE_SIZE,        // BIP340 schnorr signature
                PREIMAGE_SIZE,                 // Payout preimage
                self.sellback_script.len(),    // Script
                sellback_control_block.size(), // Control block
            ],
        )
    }

    // pub(crate) fn sighash_tx_win(&self)
}
