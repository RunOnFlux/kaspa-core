//! Differential oracle for @runonflux/kaspa-core.
//!
//! Reads a JSON array of requests on stdin, writes a JSON array of responses on stdout.
//! Every answer is produced by rusty-kaspa's own crates, so agreement with the
//! TypeScript library is agreement with consensus.
//!
//! Wire format for transactions (all byte fields hex, all u64 fields decimal strings):
//!   tx      = { version, inputs: [input], outputs: [output], lockTime, subnetworkId, gas, payload }
//!   input   = { txid, index, sigScript, sequence, sigOpCount? , computeBudget? }
//!   output  = { value, spkVersion, spk, covenant?: { authorizingInput, covenantId } }
//!   entry   = { amount, spkVersion, spk, blockDaaScore, isCoinbase, covenantId? }

use std::io::Read;
use std::panic;

use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::{
    constants::STORAGE_MASS_PARAMETER,
    hashing::{
        sighash::{calc_ecdsa_signature_hash, calc_schnorr_signature_hash, SigHashReusedValuesUnsync},
        sighash_type::SigHashType,
        tx as txhashing,
    },
    mass::{transaction_estimated_serialized_size, Gram, MassCalculator},
    subnets::SubnetworkId,
    tx::{
        ComputeCommit, CovenantBinding, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint,
        TransactionOutput, UtxoEntry, VerifiableTransaction,
    },
};
use kaspa_hashes::{Hash, PersonalMessageSigningHash};
use kaspa_txscript::{
    caches::Cache, pay_to_script_hash_script, script_builder::ScriptBuilder, standard::multisig_redeem_script, EngineCtx, EngineFlags,
    TxScriptEngine,
};
use serde_json::{json, Value};

type R<T> = Result<T, String>;

fn s<'a>(v: &'a Value, k: &str) -> R<&'a str> {
    v.get(k).and_then(|x| x.as_str()).ok_or_else(|| format!("missing string field `{k}`"))
}
fn u(v: &Value, k: &str) -> R<u64> {
    match v.get(k) {
        Some(Value::String(x)) => x.parse::<u64>().map_err(|e| format!("bad u64 `{k}`: {e}")),
        Some(Value::Number(n)) => n.as_u64().ok_or_else(|| format!("bad number `{k}`")),
        _ => Err(format!("missing integer field `{k}`")),
    }
}
fn bytes(v: &Value, k: &str) -> R<Vec<u8>> {
    hex::decode(s(v, k)?).map_err(|e| format!("bad hex `{k}`: {e}"))
}
fn hash32(v: &Value, k: &str) -> R<Hash> {
    let b = bytes(v, k)?;
    let a: [u8; 32] = b.try_into().map_err(|_| format!("`{k}` must be 32 bytes"))?;
    Ok(Hash::from_bytes(a))
}

fn parse_tx(v: &Value) -> R<Transaction> {
    let version = u(v, "version")? as u16;
    let mut inputs = Vec::new();
    for i in v.get("inputs").and_then(|x| x.as_array()).ok_or("missing inputs")? {
        let compute_commit = if version >= 1 {
            ComputeCommit::ComputeBudget((u(i, "computeBudget").unwrap_or(0) as u16).into())
        } else {
            ComputeCommit::SigopCount((u(i, "sigOpCount")? as u8).into())
        };
        inputs.push(TransactionInput {
            previous_outpoint: TransactionOutpoint { transaction_id: hash32(i, "txid")?, index: u(i, "index")? as u32 },
            signature_script: bytes(i, "sigScript")?,
            sequence: u(i, "sequence")?,
            compute_commit,
        });
    }
    let mut outputs = Vec::new();
    for o in v.get("outputs").and_then(|x| x.as_array()).ok_or("missing outputs")? {
        let covenant = match o.get("covenant") {
            Some(c) if !c.is_null() => {
                Some(CovenantBinding { authorizing_input: u(c, "authorizingInput")? as u16, covenant_id: hash32(c, "covenantId")? })
            }
            _ => None,
        };
        outputs.push(TransactionOutput {
            value: u(o, "value")?,
            script_public_key: ScriptPublicKey::from_vec(u(o, "spkVersion")? as u16, bytes(o, "spk")?),
            covenant,
        });
    }
    let sub: [u8; 20] = bytes(v, "subnetworkId")?.try_into().map_err(|_| "subnetworkId must be 20 bytes")?;
    Ok(Transaction::new(
        version,
        inputs,
        outputs,
        u(v, "lockTime")?,
        SubnetworkId::from_bytes(sub),
        u(v, "gas")?,
        bytes(v, "payload")?,
    ))
}

fn parse_entries(v: &Value) -> R<Vec<UtxoEntry>> {
    let mut out = Vec::new();
    for e in v.as_array().ok_or("entries must be an array")? {
        let covenant_id = match e.get("covenantId") {
            Some(c) if !c.is_null() => Some(hash32(e, "covenantId")?),
            _ => None,
        };
        out.push(UtxoEntry {
            amount: u(e, "amount")?,
            script_public_key: ScriptPublicKey::from_vec(u(e, "spkVersion")? as u16, bytes(e, "spk")?),
            block_daa_score: u(e, "blockDaaScore")?,
            is_coinbase: e.get("isCoinbase").and_then(|x| x.as_bool()).unwrap_or(false),
            covenant_id,
        });
    }
    Ok(out)
}

fn prefix(p: &str) -> R<Prefix> {
    Prefix::try_from(p).map_err(|e| e.to_string())
}

fn handle(req: &Value) -> R<Value> {
    match s(req, "op")? {
        "encodeAddress" => {
            let version = match u(req, "version")? {
                0 => Version::PubKey,
                1 => Version::PubKeyECDSA,
                8 => Version::ScriptHash,
                x => return Err(format!("bad version {x}")),
            };
            let a = Address::new(prefix(s(req, "prefix")?)?, version, &bytes(req, "payload")?);
            Ok(json!({ "address": a.to_string() }))
        }
        "decodeAddress" => {
            let a = Address::try_from(s(req, "address")?).map_err(|e| e.to_string())?;
            Ok(json!({ "prefix": a.prefix.to_string(), "version": a.version as u8, "payload": hex::encode(a.payload.as_slice()) }))
        }
        "pushData" => {
            let mut b = ScriptBuilder::new();
            b.add_data(&bytes(req, "data")?).map_err(|e| e.to_string())?;
            Ok(json!({ "script": hex::encode(b.drain()) }))
        }
        "pushI64" => {
            let v: i64 = s(req, "value")?.parse().map_err(|e| format!("{e}"))?;
            let mut b = ScriptBuilder::new();
            b.add_i64(v).map_err(|e| e.to_string())?;
            Ok(json!({ "script": hex::encode(b.drain()) }))
        }
        "multisigRedeem" => {
            let keys: Vec<[u8; 32]> = req
                .get("keys")
                .and_then(|x| x.as_array())
                .ok_or("missing keys")?
                .iter()
                .map(|k| {
                    let b = hex::decode(k.as_str().unwrap_or_default()).map_err(|e| e.to_string())?;
                    b.try_into().map_err(|_| "key must be 32 bytes".to_string())
                })
                .collect::<R<_>>()?;
            let script = multisig_redeem_script(keys.iter(), u(req, "m")? as usize).map_err(|e| e.to_string())?;
            let spk = pay_to_script_hash_script(&script);
            Ok(json!({ "redeem": hex::encode(&script), "spk": hex::encode(spk.script()), "spkVersion": spk.version() }))
        }
        "p2sh" => {
            let spk = pay_to_script_hash_script(&bytes(req, "redeem")?);
            Ok(json!({ "spk": hex::encode(spk.script()), "spkVersion": spk.version() }))
        }
        "txid" => {
            let tx = parse_tx(req.get("tx").ok_or("missing tx")?)?;
            Ok(json!({ "id": tx.id().to_string(), "hash": txhashing::hash(&tx).to_string() }))
        }
        "sighash" => {
            let tx = parse_tx(req.get("tx").ok_or("missing tx")?)?;
            let entries = parse_entries(req.get("entries").ok_or("missing entries")?)?;
            let idx = u(req, "index")? as usize;
            let ht = SigHashType::from_u8(u(req, "hashType")? as u8).map_err(|e| e.to_string())?;
            let populated = PopulatedTransaction::new(&tx, entries);
            let r1 = SigHashReusedValuesUnsync::new();
            let r2 = SigHashReusedValuesUnsync::new();
            let schnorr = calc_schnorr_signature_hash(&populated, idx, ht, &r1);
            let ecdsa = calc_ecdsa_signature_hash(&populated, idx, ht, &r2);
            Ok(json!({ "schnorr": schnorr.to_string(), "ecdsa": ecdsa.to_string() }))
        }
        "mass" => {
            let tx = parse_tx(req.get("tx").ok_or("missing tx")?)?;
            let entries = parse_entries(req.get("entries").ok_or("missing entries")?)?;
            let mc = MassCalculator::new(1, 10, STORAGE_MASS_PARAMETER);
            let nc = mc.calc_non_contextual_masses(&tx);
            let populated = PopulatedTransaction::new(&tx, entries);
            let storage = mc.calc_contextual_masses(&populated).map(|c| c.storage_mass);
            Ok(json!({
                "size": transaction_estimated_serialized_size(&tx),
                "compute": nc.compute_mass,
                "transient": nc.transient_mass,
                "storage": storage,
            }))
        }
        "verify" => {
            let tx = parse_tx(req.get("tx").ok_or("missing tx")?)?;
            let entries = parse_entries(req.get("entries").ok_or("missing entries")?)?;
            let populated = PopulatedTransaction::new(&tx, entries);
            let cache = Cache::new(10_000);
            let reused = SigHashReusedValuesUnsync::new();
            let flags = EngineFlags { sigop_script_units: Gram(1000).into() };
            let mut results = Vec::new();
            for (i, (input, entry)) in populated.populated_inputs().enumerate() {
                let ctx = EngineCtx::new(&cache).with_reused(&reused);
                let limit = input.compute_commit.allowed_script_units();
                let mut vm =
                    TxScriptEngine::from_transaction_input_with_script_units_limit(&populated, input, i, entry, ctx, flags, limit);
                let r = vm.execute();
                let p2sh_sigops = kaspa_txscript::p2sh_sig_scanner(&input.signature_script, &entry.script_public_key);
                results.push(json!({
                    "ok": r.is_ok(),
                    "error": r.err().map(|e| e.to_string()),
                    "p2shSigOps": p2sh_sigops,
                }));
            }
            Ok(json!({ "inputs": results }))
        }
        "p2shSigScanner" => {
            let spk = ScriptPublicKey::from_vec(0, bytes(req, "spk")?);
            Ok(json!({ "sigops": kaspa_txscript::p2sh_sig_scanner(&bytes(req, "sigScript")?, &spk) }))
        }
        "personalMessageHash" => {
            let mut h = PersonalMessageSigningHash::new();
            h.write(bytes(req, "message")?);
            Ok(json!({ "hash": h.finalize().to_string() }))
        }
        "schnorrSignNoAux" => {
            let sk = bytes(req, "secret")?;
            let kp = secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, &sk).map_err(|e| e.to_string())?;
            let digest: [u8; 32] = bytes(req, "digest")?.try_into().map_err(|_| "digest must be 32 bytes")?;
            let msg = secp256k1::Message::from_digest(digest);
            let sig = secp256k1::SECP256K1.sign_schnorr_no_aux_rand(&msg, &kp);
            Ok(json!({ "signature": hex::encode(sig.as_ref()), "xonly": hex::encode(kp.x_only_public_key().0.serialize()) }))
        }
        other => Err(format!("unknown op `{other}`")),
    }
}

fn main() {
    // Batch from a file path argument if given (robust inside test runners), else stdin.
    let input = match std::env::args().nth(1) {
        Some(path) => std::fs::read_to_string(path).expect("read request file"),
        None => {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s).expect("read stdin");
            s
        }
    };
    let reqs: Vec<Value> = serde_json::from_str(&input).expect("stdin must be a JSON array");
    panic::set_hook(Box::new(|_| {}));
    let out: Vec<Value> = reqs
        .iter()
        .map(|req| {
            let id = req.get("id").cloned().unwrap_or(Value::Null);
            match panic::catch_unwind(|| handle(req)) {
                Ok(Ok(result)) => json!({ "id": id, "ok": true, "result": result }),
                Ok(Err(e)) => json!({ "id": id, "ok": false, "error": e }),
                Err(_) => json!({ "id": id, "ok": false, "error": "panic" }),
            }
        })
        .collect();
    println!("{}", serde_json::to_string(&out).expect("serialize"));
}
