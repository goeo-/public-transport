use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::ops::Add;
use std::str::FromStr;
use serde::{Deserialize, Serialize};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};
use web_sys::js_sys::Uint8Array;
use sha2::Digest;
use futures_util::stream::StreamExt;
use k256::ecdsa::signature::Verifier as k256Verifier;
use libipld::Cid;

#[derive(Serialize, Deserialize, Debug)]
pub struct DNSJsonAnswer {
    name: String,
    r#type: u16,
    #[serde(rename="TTL")]
    ttl: u16,
    data: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DNSJsonResponse {
    pub error: Option<String>,
    #[serde(rename="Answer")]
    pub answer: Option<Vec<DNSJsonAnswer>>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DidVerificationMethod {
    pub id: String,
    #[serde(rename="publicKeyMultibase")]
    pub public_key_multibase: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DidDocument {
    #[serde(rename="verificationMethod")]
    pub verification_method: Option<Vec<DidVerificationMethod>>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignedCommitObject<'a> {
    did: String,
    version: u16,
    data: Cid,
    rev: String,
    prev: Option<Cid>,
    sig: &'a [u8]
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UnsignedCommitObject {
    did: String,
    rev: String,
    data: Cid,
    prev: Option<Cid>,
    version: u16
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IPLDEntry {
    p: u32,
    k: String,
    v: Cid,
    t: Option<Cid>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IPLDNode {
    l: Option<Cid>,
    e: Vec<IPLDEntry>
}

struct DFSState {
    found: bool,
    min: Option<String>,
    max: Option<String>,
    depth: Option<u32>
}

fn dfs(tree: &HashMap<Cid, Vec<u8>>, visited: &mut HashSet<Cid>, start: Option<Cid>, target: Cid) -> Result<DFSState, JsValue> {
    let start = match start {
        Some(cid) => cid,
        None => {
            return Ok(DFSState {
                found: false,
                min: None,
                max: None,
                depth: None
            });
        }
    };
    if visited.contains(&start) {
        panic!("this tree is not a tree?");
    }
    visited.insert(start.clone());
    let block = match tree.get(&start) {
        Some(block) => block,
        None => {
            return Ok(DFSState {
                found: false,
                min: None,
                max: None,
                depth: None
            });
        }
    };
    let node: IPLDNode = serde_ipld_dagcbor::from_slice(block).unwrap();
    let left_state = dfs(tree, visited, node.l, target)?;

    let mut key = String::new();
    let mut found = left_state.found;
    let mut depth: Option<u32> = None;
    let mut first_key: Option<String> = None;
    let mut last_key: Option<String> = None;

    for entry in node.e {
        if entry.v == target {
            found = true;
        }
        key.truncate(entry.p as usize);
        key = key.add(&entry.k);

        let key_digest = sha2::Sha256::digest(&key);
        let mut zero_count = 0u32;
        'count: for byte in key_digest {
            for bit in (0..8u32).rev() {
                if (byte >> bit & 1) != 0 {
                    break 'count;
                }
                zero_count += 1;
            }
        }

        let this_depth = zero_count / 2;
        match depth {
            None => {
                depth = Some(this_depth);
            }
            Some(depth) => {
                if depth != this_depth {
                    return Err("node has entries with different depths".into());
                }
            }
        }

        if let None = last_key {
            first_key = Some(key.clone());
            last_key = Some(key.clone());
        }

        let last_key_ = last_key.unwrap();
        if last_key_ > key {
            return Err("entries are out of order".into());
        }

        let right_state = dfs(tree, visited, entry.t, target)?;

        if let Some(min) = right_state.min {
            if min < last_key_ {
                return Err("entries are out of order".into());
            }
        }
        found = found || right_state.found;

        if let Some(left_depth) = left_state.depth {
            if left_depth >= this_depth {
                return Err("depths are out of order".into());
            }
        }
        if let Some(right_depth) = right_state.depth {
            if right_depth >= this_depth {
                return Err("depths are out of order".into());
            }
        }

        last_key = match right_state.max {
            Some(key) => Some(key),
            None => Some(key.clone())
        };
    }

    if let Some(left_max) = left_state.max {
        if let Some(ref first_key) = first_key {
            if &left_max > first_key {
                return Err("entries are out of order".into());
            }
        }
    }

    Ok(DFSState {
        found,
        min: first_key,
        max: last_key,
        depth
    })
}

#[wasm_bindgen]
pub async fn authenticate_post(uri: &str, cid: &str, record: JsValue) -> Result<(), JsValue> {
    let cid = Cid::from_str(cid).unwrap();
    let (hash_type, hash_digest, hash_len) = cid.hash().into_inner();

    if hash_type != 0x12 || hash_len != 0x20 {
        return Err("unexpected cid type".into());
    }

    /* disabled until i can get serde_ipld_dagcbor (or something else) to serialize into real dag-cbor
    let deserializer = serde_wasm_bindgen::Deserializer::from(record);
    let writer = serde_ipld_dagcbor::ser::BufWriter::new(Vec::new());
    let mut serializer = serde_ipld_dagcbor::ser::Serializer::new(writer);
    serde_transcode::transcode(deserializer, &mut serializer).unwrap();

    let cbor_writer = serializer.into_inner();
    let cbor = cbor_writer.buffer();

    let record_hash = sha2::Sha256::digest(cbor);

    if &hash_digest[..32] != record_hash.as_slice() {
        return Err(format!("given cid doesn't match given record, {:?}", cbor).into());
    }
     */

    if &uri[..5] != "at://" {
        return Err("invalid record uri".into());
    }

    let parts: Vec<&str> = uri[5..].split('/').collect();
    if parts.len() != 3 {
        return Err("invalid record uri".into());
    }

    let mut opts = RequestInit::new();
    opts.method("GET");
    opts.mode(RequestMode::Cors);

    let window = web_sys::window().unwrap();

    let url = format!(
        "https://bsky.network/xrpc/com.atproto.sync.getRecord?did={}&collection={}&rkey={}",
        parts[0], parts[1], parts[2]
    );
    let request = Request::new_with_str_and_init(&url, &opts)?;

    let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
    if !resp_value.is_instance_of::<Response>() {
        return Err("could not get response".into());
    }
    let resp: Response = resp_value.dyn_into().unwrap();

    let array_buffer = JsFuture::from(resp.array_buffer()?).await?;
    let array = Uint8Array::new(AsRef::<JsValue>::as_ref(&array_buffer));
    let bytes = array.to_vec();

    let car_reader = iroh_car::CarReader::new(bytes.as_slice()).await;
    if let Err(_) = car_reader {
        return Err("Failed to decode CAR".into());
    }

    let car_reader = car_reader.unwrap();
    let header = car_reader.header().clone();
    let mut stream = Box::pin(car_reader.stream());

    let mut blocks: HashMap<Cid, Vec<u8>> = HashMap::new();

    while let Some(block) = stream.next().await {
        let (cid, cbor) = block.unwrap();
        let (hash_type, hash_digest, hash_len) = cid.hash().into_inner();
        if hash_type != 0x12 || hash_len != 0x20 {
            return Err("unexpected cid type".into());
        }

        let record_hash = sha2::Sha256::digest(&cbor);

        if &hash_digest[..32] != record_hash.as_slice() {
            return Err("a cid in the car doesn't match its record".into());
        }
        blocks.insert(cid, cbor);
    }

    let signing_key = get_signing_key(parts[0]).await?;
    let (_, signing_key) = libipld::multibase::decode(signing_key).unwrap();

    let mut visited: HashSet<Cid> = HashSet::new();

    let mut car_found = false;

    for root in header.roots() {
        let block_data = blocks.get(root).unwrap();
        let root_object: SignedCommitObject = serde_ipld_dagcbor::from_slice(block_data).unwrap();
        if root_object.did != parts[0] {
            return Err("did from car doesn't match did from uri".into());
        }
        let unsigned_object = UnsignedCommitObject{
            did: root_object.did,
            version: root_object.version,
            data: root_object.data,
            rev: root_object.rev,
            prev: root_object.prev
        };
        let data_signed = serde_ipld_dagcbor::to_vec(&unsigned_object).unwrap();

        if root_object.sig.len() != 64 {
            return Err("unexpected signature length".into());
        }
        let sc_r: [u8; 32] = root_object.sig[..32].try_into().unwrap();
        let sc_s: [u8; 32] = root_object.sig[32..].try_into().unwrap();

        let result = match signing_key[..2] {
            [0xe7, 0x01] => {
                let pub_key = k256::ecdsa::VerifyingKey::from_sec1_bytes(&signing_key[2..]).unwrap();
                let signature = k256::ecdsa::Signature::from_scalars(sc_r, sc_s).unwrap();
                pub_key.verify(&data_signed, &signature)
            },
            [0x80, 0x24] => {
                let pub_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&signing_key[2..]).unwrap();
                let signature = p256::ecdsa::Signature::from_scalars(sc_r, sc_s).unwrap();
                pub_key.verify(&data_signed, &signature)
            },
            _ => {return Err("unknown signing key format".into());}
        };
        if let Err(_) = result {
            return Err("signature not verified".into());
        }

        let res = dfs(&blocks, &mut visited, Some(root_object.data), cid)?;
        car_found = car_found || res.found;
    }

    if !car_found{
        return Err("could not find cid in signed roots".into());
    }
    return Ok(())
}

#[wasm_bindgen]
pub async fn resolve_handle(handle: &str) -> Result<String, JsValue> {
    let mut opts = RequestInit::new();
    opts.method("GET");
    opts.mode(RequestMode::Cors);

    let window = web_sys::window().unwrap();

    let url = format!("https://1.1.1.1/dns-query?name=_atproto.{handle}&type=TXT");
    let request = Request::new_with_str_and_init(&url, &opts)?;
    request
        .headers()
        .set("Accept", "application/dns-json")?;

    let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
    if !resp_value.is_instance_of::<Response>() {
        return Err("could not get response".into());
    }
    let resp: Response = resp_value.dyn_into().unwrap();

    let json = JsFuture::from(resp.json()?).await?;
    let parsed: DNSJsonResponse = serde_wasm_bindgen::from_value(json)?;

    if let Some(error) = parsed.error {
        panic!("dns failed with error: {}", error);
    }
    else if let Some(answer) = parsed.answer {
        if answer.len() >= 1 {
            let data_len = &answer[0].data.len();
            if &answer[0].data[..9] != "\"did=did:" {
                return Err("got invalid data from dns while resolving did".into());
            }
            return Ok(String::from(&answer[0].data[5..data_len-1]));
        }
    }

    let mut opts = RequestInit::new();
    opts.method("GET");
    opts.mode(RequestMode::Cors);

    let url = format!("https://{handle}/.well-known/atproto-did");
    let request = Request::new_with_str_and_init(&url, &opts)?;
    let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;


    if !resp_value.is_instance_of::<Response>() {
        return Err("could not get response".into());
    }
    let resp: Response = resp_value.dyn_into().unwrap();
    let resp_text = JsFuture::from(resp.text()?).await?;

    let out = resp_text.as_string().unwrap();
    if &out[..4] != "did:" {
        return Err("can't resolve user".into())
    }
    Ok(out)
}

#[wasm_bindgen]
pub async fn get_signing_key(did: &str) -> Result<String, JsValue> {
    let url = match &did[..8] {
        "did:plc:" => format!("https://plc.directory/{did}"),
        "did:web:" => format!("https://{}/.well-known/did.json", &did[8..]),
        _ => {
            return Err("invalid did".into())
        }
    };

    let mut opts = RequestInit::new();
    opts.method("GET");
    opts.mode(RequestMode::Cors);

    let window = web_sys::window().unwrap();

    let request = Request::new_with_str_and_init(&url, &opts)?;

    let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
    if !resp_value.is_instance_of::<Response>() {
        return Err("could not get response".into());
    }
    let resp: Response = resp_value.dyn_into().unwrap();

    let json = JsFuture::from(resp.json()?).await?;
    let parsed: DidDocument = serde_wasm_bindgen::from_value(json)?;

    if let Some(verification_methods) = parsed.verification_method {
        for method in verification_methods {
            if method.id == format!("{did}#atproto") {
                return Ok(method.public_key_multibase);
            }
        }
    }
    else {
        return Err("no verification method in did document".into())
    }

    Err("couldn't find signing key".into())
}