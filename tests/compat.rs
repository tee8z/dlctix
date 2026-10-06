//! Compatibility with contracts built and signed by dlctix 0.1.0.
//!
//! Integrators store serialized `ContractParameters` and `SignedContract` values.
//! Those must keep deserializing, re-serialize to the same bytes, and rebuild
//! byte-identical transactions and sighashes, so the stored signatures stay
//! valid. These tests run the same fixture through the published 0.1.0 crate
//! and through this version and compare the results, and pin a digest of the
//! 0.1.0 transactions and sighashes.

use dlctix::bitcoin::hashes::{sha256, Hash as _, HashEngine as _};
use dlctix::bitcoin::{consensus, OutPoint, Transaction, Txid};
use dlctix::secp::{Point, Scalar};
use dlctix::{ContractParameters, Outcome, SignedContract, TicketedDLC, WinCondition};
use dlctix_v010 as v010;

use std::collections::BTreeMap;

/// Parameters as serialized by dlctix 0.1.0. The market maker key is `12 * G`,
/// the players' keys are `10 * G`, `11 * G` and `13 * G`, and the oracle locking
/// points are `14 * G` and `15 * G`, so the attestations are `14` and `15`.
/// Ticket hashes are the SHA-256 of `[1; 32]`, `[2; 32]` and `[3; 32]`.
const PARAMS_V010_JSON: &str = r#"{"market_maker":{"pubkey":"03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a"},"players":[{"pubkey":"03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7","ticket_hash":"72cd6e8422c407fb6d098690f1130b7ded7ec2f7f5e1d30bd9d521f015363793","payout_hash":"1414141414141414141414141414141414141414141414141414141414141414"},{"pubkey":"03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb","ticket_hash":"75877bb41d393b5fb8455ce60ecd8dda001d06316496b14dfa7f895656eeca4a","payout_hash":"2828282828282828282828282828282828282828282828282828282828282828"},{"pubkey":"03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8","ticket_hash":"648aa5c579fb30f38af744d97d6ec840c7a91277a499a0d780f3e7314eca090b","payout_hash":"3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c"}],"event":{"locking_points":["03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4","02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e"],"expiry":800000},"outcome_payouts":{"att0":{"0":1},"att1":{"1":1,"2":2},"exp":{"0":1,"1":1,"2":1}},"fee_rate":2500,"funding_value":300000,"relative_locktime_block_delta":432}"#;

/// SHA-256 over every outcome and split txid, then every outcome and split
/// sighash, which dlctix 0.1.0 builds for the fixture, each in map order.
const PINNED_V010_DIGEST: &str = "11852c4e334f5b432fd612fe391c03981b4223684698990f9e1187ad49f371ee";

const MARKET_MAKER_SECKEY: u128 = 12;
const PLAYER_SECKEYS: [u128; 3] = [10, 11, 13];

fn scalar(n: u128) -> Scalar {
    Scalar::try_from(n).unwrap()
}

fn funding_outpoint() -> OutPoint {
    OutPoint::new(Txid::from_byte_array([0x5a; 32]), 1)
}

fn txs_by_name<K: ToString>(txs: &BTreeMap<K, Transaction>) -> Vec<(String, Vec<u8>)> {
    txs.iter()
        .map(|(k, tx)| (k.to_string(), consensus::serialize(tx)))
        .collect()
}

fn sighashes_by_name<K: ToString>(sighashes: &BTreeMap<K, [u8; 32]>) -> Vec<(String, [u8; 32])> {
    sighashes
        .iter()
        .map(|(k, sighash)| (k.to_string(), *sighash))
        .collect()
}

/// SHA-256 over the given txids, then the given sighashes.
fn digest<'a>(
    txs: impl IntoIterator<Item = &'a Transaction>,
    sighashes: impl IntoIterator<Item = &'a [u8; 32]>,
) -> String {
    let mut engine = sha256::Hash::engine();
    for tx in txs {
        engine.input(tx.compute_txid().as_byte_array());
    }
    for sighash in sighashes {
        engine.input(sighash);
    }
    sha256::Hash::from_engine(engine).to_string()
}

#[test]
fn v010_parameters_deserialize_and_reserialize_identically() {
    let params: ContractParameters = serde_json::from_str(PARAMS_V010_JSON).unwrap();
    assert_eq!(params.anchor, None);
    assert_eq!(serde_json::to_string(&params).unwrap(), PARAMS_V010_JSON);

    // Binary formats too: CBOR written by 0.1.0 reads back and re-encodes the same.
    let old: v010::ContractParameters = serde_json::from_str(PARAMS_V010_JSON).unwrap();
    let mut old_cbor = Vec::new();
    ciborium::into_writer(&old, &mut old_cbor).unwrap();
    let decoded: ContractParameters = ciborium::from_reader(old_cbor.as_slice()).unwrap();
    assert_eq!(decoded, params);
    let mut new_cbor = Vec::new();
    ciborium::into_writer(&decoded, &mut new_cbor).unwrap();
    assert_eq!(new_cbor, old_cbor);
}

#[test]
fn v010_transactions_and_sighashes_are_unchanged() {
    let old_params: v010::ContractParameters = serde_json::from_str(PARAMS_V010_JSON).unwrap();
    let new_params: ContractParameters = serde_json::from_str(PARAMS_V010_JSON).unwrap();

    let old = v010::TicketedDLC::new(old_params, funding_outpoint()).unwrap();
    let new = TicketedDLC::new(new_params, funding_outpoint()).unwrap();

    assert_eq!(old.funding_output(), new.funding_output());
    assert_eq!(
        txs_by_name(old.unsigned_outcome_txs()),
        txs_by_name(new.unsigned_outcome_txs())
    );
    assert_eq!(
        txs_by_name(old.unsigned_split_txs()),
        txs_by_name(new.unsigned_split_txs())
    );

    let old_sd = old.signing_data().unwrap();
    let new_sd = new.signing_data().unwrap();
    assert_eq!(
        sighashes_by_name(&old_sd.outcome_sighashes),
        sighashes_by_name(&new_sd.outcome_sighashes)
    );
    assert_eq!(
        sighashes_by_name(&old_sd.split_sighashes),
        sighashes_by_name(&new_sd.split_sighashes)
    );
    assert_eq!(old_sd.funding_agg_pubkey, new_sd.funding_agg_pubkey);

    // No anchors anywhere.
    for tx in new
        .unsigned_outcome_txs()
        .values()
        .chain(new.unsigned_split_txs().values())
    {
        assert!(dlctix::anchor::find_anchor(tx).is_none());
    }
}

#[test]
fn v010_digest_is_pinned() {
    // Guards the 0.1.0 transaction layout once the 0.1.0 dev-dependency is gone.
    let old_params: v010::ContractParameters = serde_json::from_str(PARAMS_V010_JSON).unwrap();
    let old = v010::TicketedDLC::new(old_params, funding_outpoint()).unwrap();
    let old_sd = old.signing_data().unwrap();
    let old_digest = digest(
        old.unsigned_outcome_txs()
            .values()
            .chain(old.unsigned_split_txs().values()),
        old_sd
            .outcome_sighashes
            .values()
            .chain(old_sd.split_sighashes.values()),
    );
    assert_eq!(old_digest, PINNED_V010_DIGEST, "dlctix 0.1.0 digest");

    let new_params: ContractParameters = serde_json::from_str(PARAMS_V010_JSON).unwrap();
    let new = TicketedDLC::new(new_params, funding_outpoint()).unwrap();
    let new_sd = new.signing_data().unwrap();
    let new_digest = digest(
        new.unsigned_outcome_txs()
            .values()
            .chain(new.unsigned_split_txs().values()),
        new_sd
            .outcome_sighashes
            .values()
            .chain(new_sd.split_sighashes.values()),
    );
    assert_eq!(new_digest, PINNED_V010_DIGEST);
}

/// Sign the fixture with the 0.1.0 in-process signing sessions.
fn sign_with_v010() -> v010::SignedContract {
    use v010::{NonceSharingRound, SigningSession};

    let mut rng = rand::rng();
    let params: v010::ContractParameters = serde_json::from_str(PARAMS_V010_JSON).unwrap();
    let dlc = v010::TicketedDLC::new(params, funding_outpoint()).unwrap();

    let mm_seckey = scalar(MARKET_MAKER_SECKEY);
    let mm_session = SigningSession::<NonceSharingRound>::new(dlc.clone(), &mut rng, mm_seckey)
        .expect("market maker session");
    let player_sessions: Vec<SigningSession<NonceSharingRound>> = PLAYER_SECKEYS
        .iter()
        .map(|&sk| SigningSession::new(dlc.clone(), &mut rng, scalar(sk)).expect("player session"))
        .collect();

    let mut pubnonces = BTreeMap::from([(
        mm_session.our_public_key(),
        mm_session.our_public_nonces().clone(),
    )]);
    for session in &player_sessions {
        pubnonces.insert(
            session.our_public_key(),
            session.our_public_nonces().clone(),
        );
    }

    let mm_session = mm_session
        .aggregate_nonces_and_compute_partial_signatures(pubnonces)
        .expect("aggregate nonces");

    let mut partial_sigs = BTreeMap::new();
    for session in player_sessions {
        let pubkey: Point = session.our_public_key();
        let session = session
            .compute_partial_signatures(mm_session.aggregated_nonces().clone())
            .expect("player partial signatures");
        partial_sigs.insert(pubkey, session.our_partial_signatures().clone());
    }
    mm_session
        .aggregate_all_signatures(partial_sigs)
        .expect("aggregate signatures")
}

#[test]
fn v010_signed_contract_still_verifies_and_resolves() {
    let old = sign_with_v010();
    let stored = serde_json::to_string(&old).unwrap();

    let new: SignedContract = serde_json::from_str(&stored).expect("0.1.0 SignedContract");
    assert_eq!(serde_json::to_string(&new).unwrap(), stored);
    assert_eq!(new.params().anchor, None);

    // The stored signatures verify against the rebuilt transactions.
    let mm_pubkey = scalar(MARKET_MAKER_SECKEY).base_point_mul();
    new.dlc()
        .verify_signatures(mm_pubkey, new.all_signatures())
        .expect("0.1.0 signatures verify");

    // Every signed transaction is byte-identical.
    for (outcome_index, attestation) in [(0usize, 14u128), (1, 15)] {
        assert_eq!(
            consensus::serialize(
                &old.signed_outcome_tx(outcome_index, scalar(attestation))
                    .unwrap()
            ),
            consensus::serialize(
                &new.signed_outcome_tx(outcome_index, scalar(attestation))
                    .unwrap()
            ),
        );
    }
    assert_eq!(
        consensus::serialize(&old.expiry_tx().unwrap()),
        consensus::serialize(&new.expiry_tx().unwrap()),
    );

    for (player_index, ticket_preimage) in [(0usize, [1u8; 32]), (1, [2; 32]), (2, [3; 32])] {
        for outcome in [
            Outcome::Attestation(0),
            Outcome::Attestation(1),
            Outcome::Expiry,
        ] {
            let win_cond = WinCondition {
                outcome,
                player_index,
            };
            let old_win_cond: v010::WinCondition = win_cond.to_string().parse().unwrap();
            let old_split = old.signed_split_tx(&old_win_cond, ticket_preimage);
            let new_split = new.signed_split_tx(&win_cond, ticket_preimage);
            assert_eq!(old_split.is_ok(), new_split.is_ok(), "{win_cond}");
            if let (Ok(old_split), Ok(new_split)) = (old_split, new_split) {
                assert_eq!(
                    consensus::serialize(&old_split),
                    consensus::serialize(&new_split)
                );
            }
        }
    }
}
