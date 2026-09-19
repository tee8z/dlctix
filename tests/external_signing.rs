//! End-to-end test of the external signing API using only the public API.
//!
//! An "HSM" here is just the `musig2` functional API driven by hand: it receives
//! the `SigningData` extracted from the `TicketedDLC`, rebuilds every aggregate
//! key from the ordered signer sets, signs every sighash with fresh nonces, and
//! hands back aggregated signatures. The host then verifies them with
//! `TicketedDLC::into_signed_contract` and resolves the contract.

use dlctix::bitcoin::{Amount, FeeRate, OutPoint, Txid};
use dlctix::musig2::{
    self, AdaptorSignature, AggNonce, CompactSignature, KeyAggContext, PartialSignature, PubNonce,
    SecNonce,
};
use dlctix::secp::{MaybePoint, Point, Scalar};
use dlctix::{
    attestation_locking_point, attestation_secret, hashlock, ContractParameters,
    ContractSignatures, EventLockingConditions, MarketMaker, Outcome, PayoutWeights, Player,
    SigningData, TicketedDLC, WinCondition,
};

use dlctix::bitcoin::hashes::Hash as _;
use rand::{CryptoRng, RngCore};
use std::collections::BTreeMap;

const ALICE: usize = 0;
const BOB: usize = 1;
const CAROL: usize = 2;

struct Fixture {
    dlc: TicketedDLC,
    mm_pubkey: Point,
    /// Secret key of every signer (players and market maker), by pubkey.
    seckeys: BTreeMap<Point, Scalar>,
    ticket_preimages: Vec<hashlock::Preimage>,
    oracle_seckey: Scalar,
    oracle_secnonce: Scalar,
    outcome_messages: Vec<Vec<u8>>,
}

fn fixture() -> Fixture {
    let mut rng = rand::rng();

    let oracle_seckey = Scalar::random(&mut rng);
    let oracle_secnonce = Scalar::random(&mut rng);
    let outcome_messages: Vec<Vec<u8>> = ["alice wins", "bob and carol win", "carol wins"]
        .into_iter()
        .map(|m| m.as_bytes().to_vec())
        .collect();
    let locking_points: Vec<MaybePoint> = outcome_messages
        .iter()
        .map(|msg| {
            attestation_locking_point(
                oracle_seckey.base_point_mul(),
                oracle_secnonce.base_point_mul(),
                msg,
            )
        })
        .collect();

    let market_maker_seckey = Scalar::random(&mut rng);
    let mm_pubkey = market_maker_seckey.base_point_mul();
    let mut seckeys = BTreeMap::from([(mm_pubkey, market_maker_seckey)]);

    let mut players = Vec::new();
    let mut ticket_preimages = Vec::new();
    for _ in 0..3 {
        let seckey = Scalar::random(&mut rng);
        let ticket_preimage = hashlock::preimage_random(&mut rng);
        players.push(Player {
            pubkey: seckey.base_point_mul(),
            ticket_hash: hashlock::sha256(&ticket_preimage),
            payout_hash: hashlock::sha256(&hashlock::preimage_random(&mut rng)),
        });
        ticket_preimages.push(ticket_preimage);
        seckeys.insert(seckey.base_point_mul(), seckey);
    }

    let outcome_payouts = BTreeMap::from([
        (Outcome::Attestation(0), PayoutWeights::from([(ALICE, 1)])),
        (
            Outcome::Attestation(1),
            PayoutWeights::from([(BOB, 2), (CAROL, 1)]),
        ),
        (Outcome::Attestation(2), PayoutWeights::from([(CAROL, 1)])),
        (Outcome::Expiry, PayoutWeights::from([(ALICE, 1), (BOB, 1)])),
    ]);

    let params = ContractParameters {
        market_maker: MarketMaker { pubkey: mm_pubkey },
        players,
        event: EventLockingConditions {
            locking_points,
            expiry: Some(500_000),
        },
        outcome_payouts,
        fee_rate: FeeRate::from_sat_per_vb_unchecked(50),
        funding_value: Amount::from_sat(400_000),
        relative_locktime_block_delta: 72,
    };

    let funding_outpoint = OutPoint {
        txid: Txid::from_byte_array([0xAB; 32]),
        vout: 0,
    };
    let dlc = TicketedDLC::new(params, funding_outpoint).expect("valid contract");

    Fixture {
        dlc,
        mm_pubkey,
        seckeys,
        ticket_preimages,
        oracle_seckey,
        oracle_secnonce,
        outcome_messages,
    }
}

/// Simulates every signer of `ctx` running one MuSig2 signing session on `message`
/// with fresh nonces, returning their partial signatures and the aggregated nonce.
fn external_sign<R: RngCore + CryptoRng>(
    ctx: &KeyAggContext,
    seckeys: &BTreeMap<Point, Scalar>,
    message: &[u8; 32],
    adaptor_point: Option<MaybePoint>,
    rng: &mut R,
) -> (Vec<PartialSignature>, AggNonce) {
    let agg_pubkey: Point = ctx.aggregated_pubkey();
    let signers: Vec<Scalar> = ctx
        .pubkeys()
        .iter()
        .map(|pk| *seckeys.get(pk).expect("signer key available"))
        .collect();

    // Round 1: one fresh nonce per signer, bound to the message and aggregate key.
    let secnonces: Vec<SecNonce> = signers
        .iter()
        .map(|sk| SecNonce::generate(&mut *rng, *sk, agg_pubkey, message, &[]))
        .collect();
    let pubnonces: Vec<PubNonce> = secnonces.iter().map(|n| n.public_nonce()).collect();
    let aggnonce = AggNonce::sum(&pubnonces);

    // Round 2: partial signatures. Each secret nonce is consumed exactly once.
    let partials = signers
        .iter()
        .zip(secnonces)
        .map(|(sk, secnonce)| match adaptor_point {
            Some(t) => musig2::adaptor::sign_partial(ctx, *sk, secnonce, &aggnonce, t, message)
                .expect("adaptor partial signature"),
            None => musig2::sign_partial(ctx, *sk, secnonce, &aggnonce, message)
                .expect("partial signature"),
        })
        .collect();

    (partials, aggnonce)
}

/// Produce a complete, externally-signed `ContractSignatures` for the fixture.
fn sign_externally(fx: &Fixture, sd: &SigningData) -> ContractSignatures {
    let mut rng = rand::rng();
    let funding_ctx = KeyAggContext::new(sd.funding_signers.clone()).expect("funding key agg");
    assert_eq!(
        funding_ctx.aggregated_pubkey::<Point>(),
        sd.funding_agg_pubkey,
        "signer must be able to rebuild the funding key from the ordered signer list"
    );

    let mut outcome_tx_signatures = BTreeMap::new();
    let mut expiry_tx_signature = None;
    for (outcome, sighash) in &sd.outcome_sighashes {
        let adaptor_point = sd.adaptor_point(outcome).expect("adaptor point lookup");
        let (partials, aggnonce) =
            external_sign(&funding_ctx, &fx.seckeys, sighash, adaptor_point, &mut rng);

        match (outcome, adaptor_point) {
            (Outcome::Attestation(idx), Some(point)) => {
                let sig: AdaptorSignature = musig2::adaptor::aggregate_partial_signatures(
                    &funding_ctx,
                    &aggnonce,
                    point,
                    partials,
                    sighash,
                )
                .expect("aggregate adaptor signature");
                musig2::adaptor::verify_single(sd.funding_agg_pubkey, &sig, sighash, point)
                    .expect("aggregated adaptor signature must verify");
                outcome_tx_signatures.insert(*idx, sig);
            }
            (Outcome::Expiry, None) => {
                let sig: CompactSignature = musig2::aggregate_partial_signatures(
                    &funding_ctx,
                    &aggnonce,
                    partials,
                    sighash,
                )
                .expect("aggregate expiry signature");
                musig2::verify_single(sd.funding_agg_pubkey, sig, sighash)
                    .expect("aggregated expiry signature must verify");
                expiry_tx_signature = Some(sig);
            }
            other => panic!("inconsistent signing data: {:?}", other),
        }
    }

    let mut split_tx_signatures = BTreeMap::new();
    for (win_cond, sighash) in &sd.split_sighashes {
        let signers = &sd.split_signers[&win_cond.outcome];
        let ctx = KeyAggContext::new(signers.clone()).expect("split key agg");
        assert_eq!(
            ctx.aggregated_pubkey::<Point>(),
            sd.split_agg_pubkeys[&win_cond.outcome],
            "signer must be able to rebuild the split key from the ordered signer list"
        );
        let (partials, aggnonce) = external_sign(&ctx, &fx.seckeys, sighash, None, &mut rng);
        let sig: CompactSignature =
            musig2::aggregate_partial_signatures(&ctx, &aggnonce, partials, sighash)
                .expect("aggregate split signature");
        musig2::verify_single(sd.split_agg_pubkeys[&win_cond.outcome], sig, sighash)
            .expect("aggregated split signature must verify");
        split_tx_signatures.insert(*win_cond, sig);
    }

    ContractSignatures {
        expiry_tx_signature,
        outcome_tx_signatures,
        split_tx_signatures,
    }
}

fn sorted(mut keys: Vec<Point>) -> Vec<Point> {
    keys.sort();
    keys
}

#[test]
fn signing_data_describes_every_signature_and_signer_set() {
    let fx = fixture();
    let params = fx.dlc.params();
    let sd = fx.dlc.signing_data().expect("signing data");

    // Three attestation outcomes plus expiry; one adaptor point per attestation.
    assert_eq!(sd.outcome_sighashes.len(), 4);
    assert_eq!(sd.adaptor_points.len(), 3);
    // 1 + 2 + 1 + 2 win conditions.
    assert_eq!(sd.split_sighashes.len(), 6);
    assert_eq!(sd.split_signers.len(), 4);
    assert_eq!(sd.split_agg_pubkeys.len(), 4);
    assert_eq!(sd.total_signature_count(), 10);

    // Funding signers: every player plus the market maker, BIP-327 sorted.
    let expected_funding: Vec<Point> = sorted(
        params
            .players
            .iter()
            .map(|p| p.pubkey)
            .chain([fx.mm_pubkey])
            .collect(),
    );
    assert_eq!(sd.funding_signers, expected_funding);
    assert_eq!(
        KeyAggContext::new(sd.funding_signers.clone())
            .unwrap()
            .aggregated_pubkey::<Point>(),
        sd.funding_agg_pubkey
    );
    // The funding output key is the untweaked aggregate key, used directly.
    let spk = fx.dlc.funding_output().script_pubkey;
    assert_eq!(
        &spk.as_bytes()[2..],
        &sd.funding_agg_pubkey.serialize_xonly()
    );

    // Split signers: market maker plus that outcome's winners, BIP-327 sorted.
    for (outcome, payout_map) in &params.outcome_payouts {
        let expected: Vec<Point> = sorted(
            payout_map
                .keys()
                .map(|&i| params.players[i].pubkey)
                .chain([fx.mm_pubkey])
                .collect(),
        );
        assert_eq!(
            sd.split_signers[outcome], expected,
            "signers for {}",
            outcome
        );
        assert_eq!(
            KeyAggContext::new(expected)
                .unwrap()
                .aggregated_pubkey::<Point>(),
            sd.split_agg_pubkeys[outcome]
        );
        for &player_index in payout_map.keys() {
            let win_cond = WinCondition {
                outcome: *outcome,
                player_index,
            };
            assert!(
                sd.split_sighashes.contains_key(&win_cond),
                "missing {}",
                win_cond
            );
        }
    }

    // Adaptor points match the oracle's locking points exactly.
    for (idx, point) in params.event.locking_points.iter().enumerate() {
        assert_eq!(sd.adaptor_points[&idx], *point);
        assert_eq!(
            sd.adaptor_point(&Outcome::Attestation(idx)).unwrap(),
            Some(*point)
        );
        assert!(sd.requires_adaptor(&Outcome::Attestation(idx)));
    }
    assert!(!sd.requires_adaptor(&Outcome::Expiry));
    assert_eq!(sd.adaptor_point(&Outcome::Expiry).unwrap(), None);
    assert!(sd.adaptor_point(&Outcome::Attestation(99)).is_err());

    // A signer must never fall back to a plain signature when an adaptor point is
    // missing: `requires_adaptor` stays true and `adaptor_point` errors.
    let mut truncated = sd.clone();
    truncated.adaptor_points.remove(&0);
    assert!(truncated.requires_adaptor(&Outcome::Attestation(0)));
    assert!(truncated.adaptor_point(&Outcome::Attestation(0)).is_err());

    // Every sighash is distinct.
    let mut all: Vec<[u8; 32]> = sd
        .outcome_sighashes
        .values()
        .chain(sd.split_sighashes.values())
        .copied()
        .collect();
    all.sort();
    all.dedup();
    assert_eq!(all.len(), sd.total_signature_count());

    // SigningData round-trips through serde.
    let json = serde_json::to_string(&sd).expect("serialize");
    let decoded: SigningData = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded, sd);
}

#[test]
fn externally_signed_contract_verifies_and_resolves() {
    let fx = fixture();
    let params = fx.dlc.params().clone();
    let sd = fx.dlc.signing_data().expect("signing data");
    let signatures = sign_externally(&fx, &sd);

    // The market maker verifies everything; each player verifies what concerns them.
    fx.dlc
        .verify_signatures(fx.mm_pubkey, &signatures)
        .expect("market maker verification");
    for player in &params.players {
        fx.dlc
            .verify_signatures(player.pubkey, &signatures)
            .expect("player verification");
    }
    // A key that is not part of the contract cannot verify anything.
    let stranger = Scalar::random(&mut rand::rng()).base_point_mul();
    assert!(fx.dlc.verify_signatures(stranger, &signatures).is_err());

    // Conversion into a SignedContract verifies first...
    let signed = fx
        .dlc
        .clone()
        .into_signed_contract(fx.mm_pubkey, signatures.clone())
        .expect("verified signed contract");
    assert_eq!(signed.all_signatures(), &signatures);

    // ...and the resulting contract is enforceable on-chain.
    let outcome_index = 1; // bob and carol win
    let attestation = attestation_secret(
        fx.oracle_seckey,
        fx.oracle_secnonce,
        &fx.outcome_messages[outcome_index],
    );
    let outcome_tx = signed
        .signed_outcome_tx(outcome_index, attestation)
        .expect("signed outcome tx");
    assert_eq!(outcome_tx.input[0].witness.len(), 1);
    assert_eq!(outcome_tx.input[0].witness.nth(0).unwrap().len(), 64);

    let wrong_attestation = attestation_secret(
        fx.oracle_seckey,
        fx.oracle_secnonce,
        &fx.outcome_messages[0],
    );
    assert!(signed
        .signed_outcome_tx(outcome_index, wrong_attestation)
        .is_err());

    let bob_win_cond = WinCondition {
        outcome: Outcome::Attestation(outcome_index),
        player_index: BOB,
    };
    let split_tx = signed
        .signed_split_tx(&bob_win_cond, fx.ticket_preimages[BOB])
        .expect("signed split tx");
    assert_eq!(split_tx.input[0].witness.len(), 4);
    assert_eq!(split_tx.output.len(), 2);

    assert!(signed.expiry_tx().is_some());
}

#[test]
fn into_signed_contract_rejects_bad_signatures() {
    let fx = fixture();
    let sd = fx.dlc.signing_data().expect("signing data");
    let good = sign_externally(&fx, &sd);

    // 1. A missing split signature is caught by the market maker and by the affected
    //    player, but is irrelevant to a player who cannot claim that path.
    let carol_wins = WinCondition {
        outcome: Outcome::Attestation(2),
        player_index: CAROL,
    };
    let mut missing = good.clone();
    missing.split_tx_signatures.remove(&carol_wins);
    let alice = fx.dlc.params().players[ALICE].pubkey;
    let carol = fx.dlc.params().players[CAROL].pubkey;
    assert!(fx.dlc.verify_signatures(fx.mm_pubkey, &missing).is_err());
    assert!(fx.dlc.verify_signatures(carol, &missing).is_err());
    fx.dlc
        .verify_signatures(alice, &missing)
        .expect("alice is not a winner of outcome 2");
    assert!(fx
        .dlc
        .clone()
        .into_signed_contract(fx.mm_pubkey, missing)
        .is_err());

    // 2. An adaptor signature encrypted under the wrong oracle point is rejected,
    //    so a signer cannot be tricked into unlocking outcome 0 with outcome 1's
    //    attestation.
    let mut swapped = good.clone();
    let sig0 = swapped.outcome_tx_signatures[&0];
    let sig1 = swapped.outcome_tx_signatures[&1];
    swapped.outcome_tx_signatures.insert(0, sig1);
    swapped.outcome_tx_signatures.insert(1, sig0);
    assert!(fx.dlc.verify_signatures(fx.mm_pubkey, &swapped).is_err());
    assert!(fx.dlc.verify_signatures(alice, &swapped).is_err());

    // 3. A missing expiry signature is rejected for anyone who wins on expiry.
    let mut no_expiry = good.clone();
    no_expiry.expiry_tx_signature = None;
    assert!(fx.dlc.verify_signatures(fx.mm_pubkey, &no_expiry).is_err());
    assert!(fx.dlc.verify_signatures(alice, &no_expiry).is_err());
    fx.dlc
        .verify_signatures(carol, &no_expiry)
        .expect("carol does not win on expiry");

    // 4. The unchecked constructor exists for callers who verified already.
    fx.dlc
        .verify_signatures(fx.mm_pubkey, &good)
        .expect("good signatures");
    let _ = fx.dlc.clone().into_signed_contract_unchecked(good);
}
