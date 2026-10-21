//! Reloads every contract fixture from disk and verifies it with the upstream crate.
//!
//! Nothing here reuses the generator's scenario code: each check starts from the bytes in
//! `contracts/test/fixtures/` and the values in `manifest.json`. Contract-facing primitives
//! (SHA-256, ed25519, EIP-2537 point encodings) are additionally checked with implementations
//! independent of the commonware wrappers that produced them.

use bajillion_fixtures::{
    hex,
    storage::genesis_replica,
    trace::{Hashed, TracingSha256, record},
    unhex,
};
use blst::{
    BLST_ERROR, blst_p1_affine, blst_p1_affine_compress, blst_p1_affine_generator,
    blst_p1_affine_in_g1, blst_p1_deserialize, blst_p2_affine, blst_p2_affine_compress,
    blst_p2_affine_generator, blst_p2_affine_in_g2, blst_p2_deserialize,
};
use bytes::Bytes;
use commonware_clearing::bajillion::{
    admission::{COMMITTEE_HASH_NAMESPACE, Committee, HEADER_NAMESPACE, Vote, bls12381},
    boundary::{DepositBatch, SignedWithdrawal, WithdrawalBatch},
    challenge::{Challenge, Verdict, adjudicate},
    payment::VectorAck,
    posted,
    qmdb::{StateRoot, account_key},
    settlement::{
        Bounds, ClaimedRange, EpochDeadlinePolicy, Genesis, SettlementChain, SettlementConfig,
    },
    transition::{
        BatchId, CloseContext, EpochContext, HEADER_ROOT_HASH_NAMESPACE, Header, RootBundle,
        WithdrawalClaim, validate_close_with_strategy,
    },
};
use commonware_codec::{Copying, Decode, DecodeExt, Encode, RangeCfg};
use commonware_cryptography::{
    Hasher, Sha256,
    bls12381::primitives::{
        group::{G1, G2},
        ops::{aggregate, hash_with_namespace, verify_proof_of_possession},
        variant::{MinSig, Variant},
    },
    sha256::Digest,
};
use commonware_cryptography_curve25519::signing::{BatchVerifier, StrictVerifyingKey as Key};
use commonware_parallel::Sequential;
use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
use commonware_utils::{TestRng, iter::NonEmpty, sequence::FixedBytes, union_unique};
use serde_json::Value;
use sha2::Digest as _;
use std::{
    collections::BTreeSet,
    num::{NonZeroU64, NonZeroUsize},
    path::PathBuf,
};

type Chain = SettlementChain<TracingSha256, Key>;

const COMMITTEE_SIZE: usize = 4;
const MAX_ITEMS: usize = 1_024;

struct Fixtures {
    dir: PathBuf,
    manifest: Value,
}

impl Fixtures {
    fn load() -> Self {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/test/fixtures");
        let text = std::fs::read_to_string(dir.join("manifest.json")).expect("manifest exists");
        Self {
            dir,
            manifest: serde_json::from_str(&text).expect("manifest is JSON"),
        }
    }

    /// Bytes of `<name>.hex`, checked against the manifest's recorded length.
    fn file(&self, name: &str) -> Vec<u8> {
        let entry = &self.manifest["fixtures"][name];
        assert_eq!(entry["file"], format!("{name}.hex"), "{name} is listed");
        let bytes = self.read(&format!("{name}.hex"));
        assert_eq!(
            bytes.len() as u64,
            entry["bytes"].as_u64().unwrap(),
            "{name} length"
        );
        bytes
    }

    fn read(&self, file: &str) -> Vec<u8> {
        let text = std::fs::read_to_string(self.dir.join(file)).expect("fixture file exists");
        assert!(!text.ends_with('\n'), "{file} has no trailing newline");
        assert_eq!(text, text.to_lowercase(), "{file} is lowercase");
        unhex(&text)
    }

    fn u64(&self, pointer: &str) -> u64 {
        self.manifest
            .pointer(pointer)
            .and_then(Value::as_u64)
            .unwrap_or_else(|| panic!("manifest {pointer} is an integer"))
    }

    fn bytes(&self, pointer: &str) -> Vec<u8> {
        hex_value(
            self.manifest
                .pointer(pointer)
                .unwrap_or_else(|| panic!("manifest has {pointer}")),
        )
    }

    fn close_context(&self) -> CloseContext<Key, Digest> {
        decode(&self.file("close_context"))
    }

    fn roots(&self) -> RootBundle<Digest> {
        decode(&self.file("root_bundle"))
    }

    fn header(&self) -> Header<Digest> {
        decode(&self.file("header"))
    }

    fn committee(&self) -> Committee {
        let bytes = self.file("committee");
        let committee = Committee::decode_cfg(Copying(&bytes), &COMMITTEE_SIZE).unwrap();
        assert_eq!(committee.encode().as_ref(), bytes.as_slice());
        committee
    }

    fn certificate(&self) -> bls12381::Certificate {
        let bytes = self.file("certificate");
        let certificate =
            bls12381::Certificate::decode_cfg(Copying(&bytes), &COMMITTEE_SIZE).unwrap();
        assert_eq!(certificate.encode().as_ref(), bytes.as_slice());
        certificate
    }

    fn deposits(&self) -> DepositBatch<Key> {
        let bytes = self.file("deposit_batch");
        let deposits =
            DepositBatch::decode_cfg(Copying(&bytes), &RangeCfg::new(..=MAX_ITEMS)).unwrap();
        assert_eq!(deposits.encode().as_ref(), bytes.as_slice());
        deposits
    }

    fn withdrawals(&self) -> WithdrawalBatch<Key, Digest> {
        let bytes = self.file("withdrawal_batch");
        let cfg = (
            RangeCfg::new(..=MAX_ITEMS),
            RangeCfg::new(..=self.max_destination()),
        );
        let withdrawals = WithdrawalBatch::decode_cfg(Copying(&bytes), &cfg).unwrap();
        assert_eq!(withdrawals.encode().as_ref(), bytes.as_slice());
        withdrawals
    }

    fn claim(&self) -> WithdrawalClaim<Digest> {
        let bytes = self.file("payout_claim");
        let cfg = RangeCfg::new(..=self.max_destination());
        let claim = WithdrawalClaim::decode_cfg(Copying(&bytes), &cfg).unwrap();
        assert_eq!(claim.encode().as_ref(), bytes.as_slice());
        claim
    }

    fn max_destination(&self) -> usize {
        self.u64("/scenario/settlement_config/max_destination_bytes") as usize
    }

    fn bounds(&self) -> Bounds {
        Bounds {
            committee: COMMITTEE_SIZE,
            items: MAX_ITEMS,
            destination: self.max_destination(),
        }
    }

    fn accounts(&self) -> Vec<(String, Key, u64, u64)> {
        self.manifest["scenario"]["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|account| {
                (
                    account["name"].as_str().unwrap().to_string(),
                    decode(&hex_value(&account["public_key"])),
                    account["opening_balance"].as_u64().unwrap(),
                    account["final_balance"].as_u64().unwrap(),
                )
            })
            .collect()
    }

    fn trace(&self, name: &str) -> &Value {
        &self.manifest["traces"][name]["calls"]
    }
}

fn hex_value(value: &Value) -> Vec<u8> {
    unhex(value.as_str().expect("hex string"))
}

/// Decodes a configless crate value and requires the encoding to be canonical.
fn decode<T: DecodeExt<()> + Encode>(bytes: &[u8]) -> T {
    let value = T::decode(Copying(bytes)).expect("fixture decodes");
    assert_eq!(
        value.encode().as_ref(),
        bytes,
        "fixture encoding is canonical"
    );
    value
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(bytes).into()
}

/// The manifest's JSON form of a recorded trace, for byte-exact comparison.
fn trace_json(trace: &[Hashed]) -> Value {
    Value::Array(
        trace
            .iter()
            .map(|hashed| {
                serde_json::json!({
                    "parts": hashed.parts.iter().map(hex).collect::<Vec<_>>(),
                    "preimage": hex(hashed.preimage()),
                    "digest": hex(hashed.digest),
                })
            })
            .collect(),
    )
}

/// The verdict naming the manifest uses for adjudication outcomes.
fn outcome<E: core::fmt::Debug>(result: &Result<Verdict, E>) -> String {
    match result {
        Ok(Verdict::Proven(kind)) => format!("Proven({kind:?})"),
        Ok(Verdict::NoContradiction) => "NoContradiction".to_string(),
        Err(error) => format!("Err({error:?})"),
    }
}

// EIP-2537 decoding, written against the EIP text rather than the generator: each base field
// element is 64 big-endian bytes with 16 leading zeros, and an Fp2 element is c0 then c1.

fn fp_limbs(eip: &[u8]) -> Vec<&[u8]> {
    eip.chunks(64)
        .map(|element| {
            assert!(
                element[..16].iter().all(|byte| *byte == 0),
                "Fp padding is zero"
            );
            &element[16..]
        })
        .collect()
}

fn recompress_g1(eip: &[u8]) -> [u8; 48] {
    assert_eq!(eip.len(), 128, "EIP-2537 G1 length");
    let limbs = fp_limbs(eip);
    // ZCash uncompressed G1 is x || y.
    let serialized = [limbs[0], limbs[1]].concat();
    let mut affine = blst_p1_affine::default();
    let mut out = [0u8; 48];
    // SAFETY: `serialized` holds the 96 bytes blst reads and `out` the 48 it writes.
    unsafe {
        assert_eq!(
            blst_p1_deserialize(&mut affine, serialized.as_ptr()),
            BLST_ERROR::BLST_SUCCESS,
            "EIP-2537 G1 point is on the curve"
        );
        assert!(blst_p1_affine_in_g1(&affine), "G1 point is in the subgroup");
        blst_p1_affine_compress(out.as_mut_ptr(), &affine);
    }
    out
}

fn recompress_g2(eip: &[u8]) -> [u8; 96] {
    assert_eq!(eip.len(), 256, "EIP-2537 G2 length");
    let limbs = fp_limbs(eip);
    // EIP-2537 order is x.c0, x.c1, y.c0, y.c1; ZCash uncompressed is x.c1, x.c0, y.c1, y.c0.
    let serialized = [limbs[1], limbs[0], limbs[3], limbs[2]].concat();
    let mut affine = blst_p2_affine::default();
    let mut out = [0u8; 96];
    // SAFETY: `serialized` holds the 192 bytes blst reads and `out` the 96 it writes.
    unsafe {
        assert_eq!(
            blst_p2_deserialize(&mut affine, serialized.as_ptr()),
            BLST_ERROR::BLST_SUCCESS,
            "EIP-2537 G2 point is on the curve"
        );
        assert!(blst_p2_affine_in_g2(&affine), "G2 point is in the subgroup");
        blst_p2_affine_compress(out.as_mut_ptr(), &affine);
    }
    out
}

fn pad(limb: &str) -> Vec<u8> {
    let mut out = vec![0u8; 16];
    out.extend(unhex(limb));
    out
}

const P: &str = "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";
// Generator coordinates copied from the EIP-2537 specification.
const H1_X: &str = "0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
const H1_Y: &str = "0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";
const H2_X_C0: &str = "0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";
const H2_X_C1: &str = "0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e";
const H2_Y_C0: &str = "0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801";
const H2_Y_C1: &str = "0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";

/// p - value for a 48-byte big-endian field element.
fn negate_fp(value: &str) -> String {
    let (p, value) = (unhex(P), unhex(value));
    let mut out = vec![0u8; 48];
    let mut borrow = 0i16;
    for i in (0..48).rev() {
        let mut digit = i16::from(p[i]) - i16::from(value[i]) - borrow;
        borrow = i16::from(digit < 0);
        if digit < 0 {
            digit += 256;
        }
        out[i] = digit as u8;
    }
    assert_eq!(borrow, 0);
    hex(out)
}

/// Every `{compressed, eip2537}` hint object anywhere in the manifest.
fn hints(value: &Value, found: &mut Vec<(Vec<u8>, Vec<u8>)>) {
    match value {
        Value::Object(map) => {
            if let (Some(compressed), Some(eip)) = (map.get("compressed"), map.get("eip2537")) {
                found.push((hex_value(compressed), hex_value(eip)));
            }
            map.values().for_each(|child| hints(child, found));
        }
        Value::Array(items) => items.iter().for_each(|child| hints(child, found)),
        _ => {}
    }
}

#[test]
fn manifest_indexes_exactly_the_fixture_files() {
    let fixtures = Fixtures::load();
    let mut listed = BTreeSet::new();
    for (name, entry) in fixtures.manifest["fixtures"].as_object().unwrap() {
        fixtures.file(name);
        listed.insert(entry["file"].as_str().unwrap().to_string());
    }
    for entry in fixtures.manifest["hashes"].as_object().unwrap().values() {
        listed.insert(entry["preimage_file"].as_str().unwrap().to_string());
    }
    for record in fixtures.manifest["challenges"].as_array().unwrap() {
        assert!(listed.contains(record["file"].as_str().unwrap()));
    }
    let on_disk = std::fs::read_dir(&fixtures.dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.ends_with(".hex"))
        .collect::<BTreeSet<_>>();
    assert_eq!(on_disk, listed);
    assert_eq!(
        fixtures.manifest["upstream"]["rev"],
        "dd6d60cb44fb3dc05cee1efa06d957ce30df1340"
    );
}

#[test]
fn header_preimage_and_named_hashes_match_the_crate() {
    let fixtures = Fixtures::load();
    let context = fixtures.close_context();
    let roots = fixtures.roots();
    let header = fixtures.header();
    let total = fixtures.u64("/close/withdrawal_total");
    let epoch_context: EpochContext<Key, Digest> = decode(&fixtures.file("epoch_context"));
    assert_eq!(context.epoch_context(), &epoch_context);
    assert!(epoch_context.verify_anchor::<Sha256>());
    assert!(header.verify::<Sha256, Key>(&context, &roots, total));

    let preimage = fixtures.read("header_preimage.hex");
    let expected = [
        HEADER_ROOT_HASH_NAMESPACE,
        &fixtures.file("close_context"),
        &fixtures.file("root_bundle"),
        &total.to_be_bytes(),
    ]
    .concat();
    assert_eq!(preimage, expected);
    assert_eq!(sha256(&preimage).as_slice(), header.digest().as_ref());

    let batch_id: BatchId<Digest> = decode(&fixtures.file("batch_id"));
    assert_eq!(batch_id, header.batch_id::<Sha256>());
    assert_eq!(fixtures.bytes("/close/header"), header.encode().as_ref());
    assert_eq!(
        fixtures.bytes("/close/batch_id"),
        batch_id.encode().as_ref()
    );

    // Every named hash: parts concatenate to the preimage file, which hashes to the digest.
    for (name, entry) in fixtures.manifest["hashes"].as_object().unwrap() {
        let preimage = fixtures.read(entry["preimage_file"].as_str().unwrap());
        let parts = entry["parts"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|part| hex_value(&part["hex"]))
            .collect::<Vec<_>>();
        assert_eq!(parts, preimage, "{name} parts");
        assert_eq!(
            sha256(&preimage).to_vec(),
            hex_value(&entry["digest"]),
            "{name}"
        );
    }
    let digest = |name: &str| fixtures.bytes(&format!("/hashes/{name}/digest"));
    assert_eq!(digest("header"), header.digest().as_ref());
    assert_eq!(digest("batch_id"), batch_id.digest().as_ref());
    assert_eq!(digest("epoch_anchor"), context.payment().anchor().as_ref());
    assert_eq!(digest("proposal_id"), roots.proposal.digest().as_ref());
    let committee = fixtures.committee();
    assert_eq!(digest("committee_commitment"), context.committee().as_ref());
    assert_eq!(committee.commitment::<Sha256>(), *context.committee());
    assert_eq!(
        fixtures.read("committee_commitment_preimage.hex"),
        [COMMITTEE_HASH_NAMESPACE, &fixtures.file("committee")].concat()
    );
    let withdrawals = fixtures.withdrawals();
    assert_eq!(
        digest("withdrawal_id"),
        withdrawals.requests()[0].id::<Sha256>().digest().as_ref()
    );
    assert_eq!(
        fixtures.read("proposal_id_preimage.hex"),
        [
            b"_COMMONWARE_CLEARING_PROPOSAL_ID".as_slice(),
            &fixtures.file("epoch_context"),
            &fixtures.file("dealing")
        ]
        .concat()
    );
}

#[test]
fn every_traced_preimage_hashes_to_its_digest() {
    let fixtures = Fixtures::load();
    let traces = fixtures.manifest["traces"].as_object().unwrap();
    assert!(!traces.is_empty());
    for (name, trace) in traces {
        for call in trace["calls"].as_array().unwrap() {
            let parts = call["parts"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(hex_value)
                .collect::<Vec<_>>();
            let preimage = hex_value(&call["preimage"]);
            assert_eq!(parts, preimage, "{name} parts");
            assert_eq!(
                sha256(&preimage).to_vec(),
                hex_value(&call["digest"]),
                "{name}"
            );
        }
    }
}

#[test]
fn ed25519_signatures_verify_over_their_exact_signed_bytes() {
    let fixtures = Fixtures::load();
    let records = fixtures.manifest["ed25519"].as_array().unwrap();
    assert!(!records.is_empty());
    for record in records {
        let label = record["label"].as_str().unwrap();
        let namespace = hex_value(&record["namespace"]);
        let message = hex_value(&record["message"]);
        let signed = hex_value(&record["signed_bytes"]);
        assert_eq!(signed, union_unique(&namespace, &message), "{label}");
        let public = hex_value(&record["public_key"]);
        let signature = hex_value(&record["signature"]);

        let key: Key = decode(&public);
        let crate_signature = decode(&signature);
        assert!(
            key.verify(&namespace, &message, &crate_signature),
            "{label}"
        );

        // An RFC 8032 verifier over the signed bytes is what a contract runs.
        let independent = ed25519_consensus::VerificationKey::try_from(
            <[u8; 32]>::try_from(public.as_slice()).unwrap(),
        )
        .unwrap();
        let independent_signature =
            ed25519_consensus::Signature::from(<[u8; 64]>::try_from(signature.as_slice()).unwrap());
        independent
            .verify(&independent_signature, &signed)
            .unwrap_or_else(|_| panic!("{label} verifies independently"));
    }

    // Every acknowledgment fixture authenticates under the registered payment context.
    let context = fixtures.close_context();
    for payment in fixtures.manifest["scenario"]["payments"]
        .as_array()
        .unwrap()
    {
        let ack: VectorAck<Key, Digest> = decode(&fixtures.file(payment["ack"].as_str().unwrap()));
        ack.verify(context.payment()).unwrap();
        assert_eq!(ack.body().seq(), payment["seq"].as_u64().unwrap());
        assert_eq!(
            ack.body().cumulative_debit(),
            payment["cumulative_debit"].as_u64().unwrap()
        );
    }
    let withdrawals = fixtures.withdrawals();
    let withdrawal = &withdrawals.requests()[0];
    withdrawal.verify_deployment(context.deployment()).unwrap();
    let signed = SignedWithdrawal::<Key, Digest>::decode_cfg(
        Copying(&fixtures.bytes("/scenario/withdrawal/signed")),
        &RangeCfg::new(..=fixtures.max_destination()),
    )
    .unwrap();
    assert_eq!(&signed, withdrawal);
}

#[test]
fn eip2537_hints_recompress_to_the_crate_bytes() {
    // Pin the coordinate order against the generators printed in the EIP itself.
    let h1 = [pad(H1_X), pad(H1_Y)].concat();
    let h2 = [pad(H2_X_C0), pad(H2_X_C1), pad(H2_Y_C0), pad(H2_Y_C1)].concat();
    let (mut g1, mut g2) = ([0u8; 48], [0u8; 96]);
    // SAFETY: blst returns valid static generators; the outputs match blst's sizes.
    unsafe {
        blst_p1_affine_compress(g1.as_mut_ptr(), blst_p1_affine_generator());
        blst_p2_affine_compress(g2.as_mut_ptr(), blst_p2_affine_generator());
    }
    assert_eq!(recompress_g1(&h1), g1);
    assert_eq!(recompress_g2(&h2), g2);

    let fixtures = Fixtures::load();
    let mut found = Vec::new();
    hints(&fixtures.manifest, &mut found);
    // 4 keys, 4 proofs, 4 proof message hashes, 3 votes, the header message hash, the aggregate
    // signature and key, and the negated generator.
    assert_eq!(found.len(), 19);
    for (compressed, eip) in &found {
        match compressed.len() {
            48 => {
                assert_eq!(recompress_g1(eip).as_slice(), compressed.as_slice());
                G1::decode(Copying(compressed)).expect("crate G1 decodes");
            }
            96 => {
                assert_eq!(recompress_g2(eip).as_slice(), compressed.as_slice());
                G2::decode(Copying(compressed)).expect("crate G2 decodes");
            }
            length => panic!("unexpected point length {length}"),
        }
    }

    let negated = [
        pad(H2_X_C0),
        pad(H2_X_C1),
        pad(&negate_fp(H2_Y_C0)),
        pad(&negate_fp(H2_Y_C1)),
    ]
    .concat();
    assert_eq!(fixtures.bytes("/bls/negated_g2_generator/eip2537"), negated);
}

#[test]
fn committee_proofs_votes_and_certificate_verify() {
    let fixtures = Fixtures::load();
    let bls = &fixtures.manifest["bls"];
    let committee = fixtures.committee();
    let header = fixtures.header();
    let pop_namespace = hex_value(&bls["pop_namespace"]);
    assert_eq!(
        bls["message_dst"],
        "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_"
    );
    assert_eq!(
        bls["pop_dst"],
        "BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_"
    );
    assert_eq!(
        bls["message_dst"].as_str().unwrap().as_bytes(),
        MinSig::MESSAGE
    );
    assert_eq!(
        bls["pop_dst"].as_str().unwrap().as_bytes(),
        MinSig::PROOF_OF_POSSESSION
    );

    let members = bls["committee"].as_array().unwrap();
    assert_eq!(members.len(), COMMITTEE_SIZE);
    for (index, member) in members.iter().enumerate() {
        assert_eq!(member["index"].as_u64().unwrap() as usize, index);
        let public_bytes = hex_value(&member["public_key"]["compressed"]);
        let public: G2 = decode(&public_bytes);
        assert_eq!(&public, &committee.members()[index]);
        let pop: G1 = decode(&hex_value(&member["proof_of_possession"]["compressed"]));
        verify_proof_of_possession::<MinSig>(&public, &pop_namespace, &pop).unwrap();
        assert_eq!(
            hex_value(&member["pop_signed_bytes"]),
            union_unique(&pop_namespace, &public_bytes)
        );
        let pop_hash = hash_with_namespace::<MinSig>(
            MinSig::PROOF_OF_POSSESSION,
            &pop_namespace,
            &public_bytes,
        );
        assert_eq!(
            hex_value(&member["pop_message_hash"]["compressed"]),
            pop_hash.encode().as_ref()
        );
    }

    let header_bytes = header.encode();
    assert_eq!(
        hex_value(&bls["header_message"]),
        union_unique(HEADER_NAMESPACE, &header_bytes)
    );
    let header_hash =
        hash_with_namespace::<MinSig>(MinSig::MESSAGE, HEADER_NAMESPACE, &header_bytes);
    assert_eq!(
        hex_value(&bls["header_message_hash"]["compressed"]),
        header_hash.encode().as_ref()
    );

    let verifier = bls12381::Scheme::verifier(committee.clone());
    for vote in bls["votes"].as_array().unwrap() {
        let vote = Vote {
            signer: commonware_utils::Participant::from_usize(
                vote["signer"].as_u64().unwrap() as usize
            ),
            signature: decode::<G1>(&hex_value(&vote["signature"]["compressed"])).into(),
        };
        assert!(verifier.verify_vote(&header, &vote));
    }

    let certificate = fixtures.certificate();
    assert!(verifier.verify(&header, &certificate));
    let signers = certificate
        .signers
        .iter()
        .map(usize::from)
        .collect::<Vec<_>>();
    let listed = bls["certificate"]["signers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|index| index.as_u64().unwrap() as usize)
        .collect::<Vec<_>>();
    assert_eq!(signers, listed);
    assert!(signers.len() >= committee.quorum());
    let certificate_bytes = fixtures.file("certificate");
    let aggregate_signature = hex_value(&bls["certificate"]["aggregate_signature"]["compressed"]);
    assert_eq!(
        &certificate_bytes[certificate_bytes.len() - 48..],
        aggregate_signature
    );
    let aggregate_public = aggregate::combine_public_keys::<MinSig, _>(
        NonEmpty::try_new(signers.iter().map(|index| &committee.members()[*index])).unwrap(),
    );
    assert_eq!(
        hex_value(&bls["certificate"]["aggregate_public_key"]["compressed"]),
        aggregate_public.encode().as_ref()
    );

    let pairing = [
        hex_value(&bls["header_message_hash"]["eip2537"]),
        hex_value(&bls["certificate"]["aggregate_public_key"]["eip2537"]),
        hex_value(&bls["certificate"]["aggregate_signature"]["eip2537"]),
        hex_value(&bls["negated_g2_generator"]["eip2537"]),
    ]
    .concat();
    assert_eq!(hex_value(&bls["pairing_check_input"]), pairing);
}

#[test]
fn dealing_revalidates_to_the_certified_close() {
    let fixtures = Fixtures::load();
    let context = fixtures.close_context();
    let deposits = fixtures.deposits();
    let withdrawals = fixtures.withdrawals();
    let roots = fixtures.roots();
    let header = fixtures.header();
    let dealing = Bytes::from(fixtures.file("dealing"));
    let accounts = fixtures.accounts();
    deterministic::Runner::default().start(|runtime| async move {
        let balances = accounts
            .iter()
            .map(|(_, key, opening, _)| (key.clone(), *opening))
            .collect::<Vec<_>>();
        let replica =
            genesis_replica::<Sha256>(runtime.child("replica"), "replica", &balances).await;
        assert_eq!(
            replica.state().root().encode().as_ref(),
            fixtures.file("genesis_state_root").as_slice()
        );
        let decoded = posted::decode::<Key, Digest>(dealing, &context).unwrap();
        let prepared = validate_close_with_strategy::<Sha256, _, _, _, _, BatchVerifier, _>(
            &replica,
            &context,
            &deposits,
            &withdrawals,
            decoded,
            &mut TestRng::new(1),
            &Sequential,
        )
        .await
        .expect("the dealing validates against genesis");
        assert_eq!(prepared.close().header, header);
        assert_eq!(prepared.close().roots, roots);
        assert_eq!(
            prepared.close().withdrawal_total,
            fixtures.u64("/close/withdrawal_total")
        );
        let (replica, _) = Box::pin(prepared.apply::<_, Sha256>(replica))
            .await
            .unwrap();
        for (name, key, _, expected) in &accounts {
            let balance = replica
                .state()
                .get(&account_key(key).unwrap())
                .await
                .unwrap()
                .map_or(0, NonZeroU64::get);
            assert_eq!(balance, *expected, "final balance of {name}");
        }
    });
}

#[test]
fn settlement_replays_admission_challenges_finalization_and_claim() {
    let fixtures = Fixtures::load();
    let config = &fixtures.manifest["scenario"]["settlement_config"];
    let field = |name: &str| config[name].as_u64().unwrap();
    let settlement_config = SettlementConfig::new(
        EpochDeadlinePolicy::new(
            NonZeroU64::new(field("admission_delay")).unwrap(),
            NonZeroU64::new(field("challenge_duration")).unwrap(),
        ),
        NonZeroU64::new(field("deposit_inclusion_timeout")).unwrap(),
        NonZeroU64::new(field("minimum_withdrawal_notice")).unwrap(),
        NonZeroU64::new(field("maximum_withdrawal_notice")).unwrap(),
        field("max_destination_bytes") as usize,
        NonZeroUsize::new(field("max_deposit_ids") as usize).unwrap(),
    );
    let mut accounts = fixtures
        .accounts()
        .iter()
        .map(|(_, key, opening, _)| {
            (
                FixedBytes::new(<[u8; 32]>::try_from(account_key(key).unwrap().as_ref()).unwrap()),
                NonZeroU64::new(*opening).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    accounts.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    let root: StateRoot<Digest> = decode(&fixtures.file("genesis_state_root"));
    let genesis = Genesis::new(
        root,
        fixtures.u64("/scenario/genesis/operations"),
        &accounts,
    )
    .unwrap();
    assert_eq!(
        genesis.liability(),
        fixtures.u64("/scenario/genesis/liability")
    );
    let deployment: Digest = decode(&fixtures.bytes("/scenario/deployment"));
    let operator: Key = decode(&fixtures.bytes("/scenario/operator"));
    let epoch = fixtures.u64("/scenario/epoch");
    let timing = |name: &str| fixtures.u64(&format!("/scenario/timing/{name}"));

    let (chain, trace) = record(|| {
        Chain::new(
            deployment,
            operator,
            fixtures.committee(),
            &genesis,
            epoch,
            settlement_config,
        )
    });
    let mut chain = chain.unwrap();
    assert_eq!(trace_json(&trace), *fixtures.trace("settlement_new"));

    let epoch_context: EpochContext<Key, Digest> = decode(&fixtures.file("epoch_context"));
    let (registered, trace) = record(|| {
        chain.register_epoch(
            timing("register_at"),
            epoch_context,
            0,
            fixtures.deposits(),
            fixtures.withdrawals(),
            |_| true,
        )
    });
    registered.unwrap();
    assert_eq!(trace_json(&trace), *fixtures.trace("register_epoch"));
    let context = fixtures.close_context();
    assert_eq!(chain.registered().unwrap().context, &context);
    assert_eq!(context.admission_deadline(), timing("admission_deadline"));
    assert_eq!(context.challenge_deadline(), timing("challenge_deadline"));

    let header = fixtures.header();
    let roots = fixtures.roots();
    let total = fixtures.u64("/close/withdrawal_total");
    let certificate = fixtures.certificate();
    // A certificate over a different header must not admit.
    let other = Header::new::<Sha256, Key>(&context, &roots, total + 1);
    assert!(!bls12381::Scheme::verifier(fixtures.committee()).verify(&other, &certificate));
    let (batch_id, trace) =
        record(|| chain.admit(timing("admit_at"), header, roots, total, certificate));
    let batch_id = batch_id.unwrap();
    assert_eq!(trace_json(&trace), *fixtures.trace("admit"));
    assert_eq!(batch_id, decode(&fixtures.file("batch_id")));
    assert_eq!(
        chain.pending().unwrap().successor_liability,
        fixtures.u64("/close/successor_liability")
    );
    let admitted = chain.encode();
    assert_eq!(
        admitted.as_ref(),
        fixtures.file("settlement_chain_admitted").as_slice()
    );

    // Each challenge runs on its own copy of the admitted chain.
    let maximum = fixtures.u64("/scenario/settlement_config/max_challenge_bytes") as usize;
    let mut proven = BTreeSet::new();
    for record_json in fixtures.manifest["challenges"].as_array().unwrap() {
        let name = record_json["name"].as_str().unwrap();
        let bytes = fixtures.file(name);
        let challenge: Challenge<Key, Digest> = decode(&bytes);
        let direct =
            adjudicate::<Sha256, Key, Digest>(&context, &header, &roots, total, &challenge);
        let mut copy = Chain::decode_cfg(admitted.clone(), &fixtures.bounds()).unwrap();
        let (settled, trace) =
            record(|| copy.challenge_encoded(timing("admit_at"), batch_id, &bytes, maximum));
        assert_eq!(outcome(&direct), record_json["expected"], "{name}");
        assert_eq!(direct.is_ok(), settled.is_ok(), "{name}");
        if let (Ok(direct), Ok(settled)) = (&direct, &settled) {
            assert_eq!(direct, settled, "{name}");
        }
        assert_eq!(trace_json(&trace), *fixtures.trace(name), "{name}");

        // The kind and outcome named by the fixture are fixed independently of the manifest.
        let kind = record_json["kind"].as_str().unwrap();
        let expected_variant = matches!(
            (&challenge, kind),
            (Challenge::AckFork { .. }, "AckFork")
                | (Challenge::HigherAckDebit { .. }, "HigherAckDebit")
        );
        assert!(expected_variant, "{name} encodes a {kind}");
        if name.ends_with("_proven") {
            assert_eq!(outcome(&direct), format!("Proven({kind})"), "{name}");
            proven.insert(kind.to_string());
        } else if name.ends_with("_no_contradiction") {
            assert!(matches!(direct, Ok(Verdict::NoContradiction)), "{name}");
        } else {
            assert!(direct.is_err(), "{name} is rejected");
        }
        // A proven challenge faults the copy; any other outcome leaves it untouched.
        assert_eq!(
            copy.encode() != admitted,
            matches!(settled, Ok(Verdict::Proven(_))),
            "{name}"
        );
    }
    assert_eq!(
        proven,
        BTreeSet::from(["AckFork".to_string(), "HigherAckDebit".to_string()])
    );

    let (finalized, trace) = record(|| chain.finalize(timing("finalize_at")));
    let (finalized, commit_index) = finalized.unwrap();
    assert_eq!(trace_json(&trace), *fixtures.trace("finalize"));
    assert_eq!(finalized.batch_id, batch_id);
    assert_eq!(
        commit_index,
        fixtures.u64("/payout_claim/finalized_commit_index")
    );

    let claim = fixtures.claim();
    let payouts = chain.finalized_payouts();
    assert_eq!(payouts, roots.withdrawal_outputs);
    assert_eq!(
        payouts.root.as_ref(),
        fixtures.bytes("/payout_claim/payout_head/root")
    );
    assert_eq!(
        payouts.operations,
        fixtures.u64("/payout_claim/payout_head/operations")
    );
    assert_eq!(
        payouts.floor,
        fixtures.u64("/payout_claim/payout_head/floor")
    );
    let output = claim.verify::<Sha256>(&payouts).unwrap();
    assert_eq!(output.amount(), fixtures.u64("/payout_claim/amount"));
    assert_eq!(
        output.destination().as_ref(),
        fixtures.bytes("/payout_claim/destination")
    );
    assert_eq!(claim.position(), fixtures.u64("/payout_claim/position"));
    let opening = fixtures.file("payout_opening");
    assert!(fixtures.file("payout_claim").ends_with(&opening));

    let neighbors = [
        None,
        Some(ClaimedRange {
            start: commit_index,
            end: commit_index + 1,
        }),
    ];
    let (effect, trace) = record(|| chain.claim_withdrawal(&neighbors, &claim));
    let effect = effect.unwrap();
    assert_eq!(trace_json(&trace), *fixtures.trace("claim_withdrawal"));
    assert_eq!(effect.output, output);
    assert_eq!(
        effect.claimed.start,
        fixtures.u64("/payout_claim/claimed_range_after/start")
    );
    assert_eq!(
        effect.claimed.end,
        fixtures.u64("/payout_claim/claimed_range_after/end")
    );
    // The same location cannot be claimed twice.
    let after = [Some(effect.claimed), None];
    assert!(chain.claim_withdrawal(&after, &claim).is_err());
}

#[test]
fn prepare_dealing_trace_covers_the_signed_terminal_batch() {
    let fixtures = Fixtures::load();
    let entry = &fixtures.manifest["hashes"]["terminal_batch_digest"];
    let digest = hex_value(&entry["digest"]);
    let dealing_trace = fixtures.trace("prepare_dealing").as_array().unwrap();
    assert!(
        dealing_trace
            .iter()
            .any(|call| hex_value(&call["digest"]) == digest),
        "the terminal batch digest comes from the dealing trace"
    );
    let signature = fixtures.manifest["ed25519"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["label"] == "terminal_batch_operator")
        .unwrap();
    assert_eq!(hex_value(&signature["message"]), digest);
    let dealing = fixtures.file("dealing");
    let signature = hex_value(&signature["signature"]);
    assert!(
        dealing
            .windows(signature.len())
            .any(|window| window == signature)
    );
    // The batch preimage begins with the namespace and the registered epoch context.
    let preimage = fixtures.read("terminal_batch_digest_preimage.hex");
    let prefix = [
        commonware_clearing::bajillion::transition::TERMINAL_BATCH_HASH_NAMESPACE,
        &fixtures.file("epoch_context"),
    ]
    .concat();
    assert!(preimage.starts_with(&prefix));
    assert_eq!(Sha256::hash(&[&preimage]).as_ref(), digest.as_slice());
}
