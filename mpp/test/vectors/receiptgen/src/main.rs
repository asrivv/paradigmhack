//! Builds one `EntryReceipt` per credited recipient of every fixture acknowledgment.
//!
//! Each out-vector is rebuilt from the fixture scenario, its root must equal the signed
//! `send_root`, and every receipt must pass `EntryReceipt::verify` under the fixture epoch
//! context and survive a decode round trip before it is written.

use commonware_clearing::bajillion::{
    payment::{EntryReceipt, VectorAck},
    transition::EpochContext,
    vector::{OutEntry, OutVector},
};
use commonware_codec::{Copying, DecodeExt as _, Encode as _};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_cryptography_curve25519::signing::StrictVerifyingKey as Key;
use std::fs;

const FIXTURES: &str = "../../../../contracts/test/fixtures";

/// Fixture acknowledgments with the payer's cumulative out-vector after each one
/// (manifest.json `scenario.payments` and `scenario.terminals`).
const CASES: [(&str, &str, &[(&str, u64, u64)]); 6] = [
    ("ack_a_seq0", "a", &[("b", 20, 1)]),
    ("ack_b_seq0", "b", &[("c", 12, 1)]),
    ("ack_c_seq0", "c", &[("d", 7, 1)]),
    ("ack_d_seq0", "d", &[("a", 5, 1)]),
    ("ack_c_seq1", "c", &[("b", 4, 1), ("d", 7, 1)]),
    ("ack_d_seq1", "d", &[("b", 6, 1), ("a", 5, 1)]),
];

fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim().trim_start_matches("0x");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::from("0x");
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn fixture(name: &str) -> Vec<u8> {
    unhex(&fs::read_to_string(format!("{FIXTURES}/{name}.hex")).unwrap())
}

fn key(name: &str) -> Key {
    let encoded = match name {
        "a" => "eee7bdf2d67def50cfc175f738b9072e36b45c30f11c9c9bad009b252fc767ca",
        "b" => "d86cb3490abdc8d49a141b140ddcf91976dc5ab9d4c0a5a1a9901d1686619f30",
        "c" => "fbe881214313271d9393c954ffbb7f17f494ee9e8d1918eb89c47e38d9da5e89",
        "d" => "f4218e0a231d995b7f3edde2168be1c19da77aef26e63e87265a5a782ffe2b7b",
        _ => unreachable!(),
    };
    Key::decode(Copying(&unhex(encoded))).unwrap()
}

fn main() {
    let context = EpochContext::<Key, Digest>::decode(Copying(&fixture("epoch_context"))).unwrap();
    let payment = context.payment();
    let mut rows = Vec::new();
    for (label, payer, entries) in CASES {
        let ack = VectorAck::<Key, Digest>::decode(Copying(&fixture(label))).unwrap();
        ack.verify(payment).unwrap();
        let mut entries: Vec<(&str, OutEntry<Key>)> = entries
            .iter()
            .map(|(name, cumulative, count)| {
                let entry = OutEntry { recipient: key(name), cumulative: *cumulative, count: *count };
                (*name, entry)
            })
            .collect();
        entries.sort_by(|left, right| left.1.recipient.cmp(&right.1.recipient));
        let vector = OutVector::new(
            payment.epoch(),
            key(payer),
            entries.iter().map(|(_, entry)| entry.clone()).collect(),
        )
        .unwrap();
        let tree = vector.commitment::<Sha256, Digest>().unwrap();
        assert_eq!(tree.root(), ack.body().send_root(), "{label}: rebuilt root differs");
        for (position, (name, entry)) in entries.iter().enumerate() {
            let receipt = EntryReceipt {
                ack: ack.clone(),
                recipient: entry.recipient.clone(),
                cumulative: entry.cumulative,
                count: entry.count,
                opening: tree.opening(position as u32).unwrap(),
            };
            receipt.verify::<Sha256>(payment).unwrap();
            let encoded = receipt.encode();
            assert_eq!(EntryReceipt::<Key, Digest>::decode(Copying(encoded.as_ref())).unwrap(), receipt);
            rows.push(format!(
                "    {{ \"ack\": \"{label}\", \"payer\": \"{payer}\", \"recipient\": \"{name}\", \
                 \"position\": {position}, \"cumulative\": {}, \"count\": {}, \"receipt\": \"{}\" }}",
                entry.cumulative,
                entry.count,
                hex(encoded.as_ref())
            ));
        }
    }
    println!(
        "{{\n  \"source\": \"commonware-clearing EntryReceipt encodings from test/vectors/receiptgen at \
         commonwarexyz/monorepo dd6d60cb44fb3dc05cee1efa06d957ce30df1340\",\n  \"receipts\": [\n{}\n  ]\n}}",
        rows.join(",\n")
    );
}
