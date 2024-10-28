use pyo3::prelude::*;
use pyo3::types::PyList;
use rabe::schemes::bsw::*;
use rabe::utils::policy::pest::PolicyLanguage;
use serde_json::{ser, de};
use std::vec::Vec;

#[pyfunction]
/** 
 * Setup adapter for rabe.
 *
 * Initialize a new cp-abe environment by creating a public key(pk) and master key pair(mk).
 * These are encoded as opaque json strings (which can be managed in python and passed back to the
 * rest of the functions below.
 */
fn cpabe_setup() -> (String, String) {
    let (pk, mk) = setup();
    let spk = pk_to_json(pk);
    let smk = mk_to_json(mk);
    (spk, smk)
}

#[pyfunction]
/** 
 * Keygen adapter for rabe.
 *
 * From a master key (mk), a public key (pk), and a collection of attributes (attributes), produce
 * a json-encoded secret key (sk) object.
 */
fn cpabe_keygen<'py>(pk: String, mk: String, attributes: &Bound<'py, PyList>) -> String {
    let _mk = json_to_mk(mk.clone());
    let _pk = json_to_pk(pk.clone());
    let mut attr_vec: Vec<String> = Vec::new();
    for value in attributes.iter() {
        attr_vec.push(value.to_string());
    }
    
    let pos: Vec<&str> = attr_vec.iter().map(AsRef::as_ref).collect();
    let sk = keygen(&_pk, &_mk, pos.as_slice()).unwrap();
    sk_to_json(sk)
}


#[pyfunction]
/** 
 * Encrypt adapter for rabe. Given a json-formatted public key (pk), a policy (policy), and a
 * plaintext message (plaintext), produce a ciphertext-json object.
 */
fn cpabe_encrypt<'py>(pk: String, policy: &str, plaintext: &[u8]) -> String {
    let _pk = json_to_pk(pk.clone());
    let ct = encrypt(&_pk, policy, PolicyLanguage::HumanPolicy, plaintext).unwrap();
    ct_to_json(ct)
}

#[pyfunction]
/** 
 * Decrypt adapter for rabe. Given a json-formatted secret key (sk) and a ciphertext (ct),
 *  decrypt the ciphertext to produce a plaintext (as a vector of bytes) or produce an error.
 */
fn cpabe_decrypt(sk: String, ct: String) -> Vec<u8> {
    let _sk = json_to_sk(sk.clone());
    let _ct = json_to_ct(ct.clone());

    let pt = decrypt(&_sk, &_ct).unwrap();
    pt

}

#[pyfunction]
/** 
 * Delegate adapter for rabe. Given a json-formatted public key, secret key, and a subset of
 * attributes (assigned to the secret key), produce a second secret-key (in json form) that can be
 * used to decrypt ciphertext with such attributes.
 */
fn cpabe_delegate<'py>(pk: String, sk: String, subset: &Bound<'py, PyList>) -> String {

    let _sk = json_to_sk(sk.clone());
    let _pk = json_to_pk(pk.clone());
    let mut attr_vec: Vec<String> = Vec::new();
    for value in subset.iter() {
        attr_vec.push(value.to_string());
    }
    
    let pos: Vec<&str> = attr_vec.iter().map(AsRef::as_ref).collect();
    let sk = delegate(&_pk, &_sk, pos.as_slice()).unwrap();
    sk_to_json(sk)
}

/**
 * encodes public-key object in rust into a json representation Keep in mind this json
 * object is an opaque key object from rabe, and not a standard key representation format such as
 * PEM/DER/PKCSvX variants.  
 */
fn pk_to_json(a: CpAbePublicKey) -> String {
    ser::to_string(&a).unwrap()
}

/**
 * encodes master-key object in rust into a json representation Keep in mind this json
 * object is an opaque key object from rabe, and not a standard key representation format such as
 * PEM/DER/PKCSvX variants.  
 */
fn mk_to_json(a: CpAbeMasterKey) -> String {
    ser::to_string(&a).unwrap()
}

/**
 * encodes secret-key object in rust into a json representation Keep in mind this json
 * object is an opaque key object from rabe, and not a standard key representation format such as
 * PEM/DER/PKCSvX variants.  
 */
fn sk_to_json(a: CpAbeSecretKey) -> String {
    ser::to_string(&a).unwrap()
}


/**
 * encodes cphertext object in rust into a json representation Keep in mind this json
 * object is an opaque key object from rabe, and not a standard key representation format such as
 * PEM/DER/PKCSvX variants.  
 */
fn ct_to_json(a: CpAbeCiphertext) -> String {
    ser::to_string(&a).unwrap()
}

fn json_to_pk(a: String) -> CpAbePublicKey {
    de::from_str(&a).unwrap()
}

fn json_to_mk(a: String) -> CpAbeMasterKey {
    de::from_str(&a).unwrap()
}

fn json_to_ct(a: String) -> CpAbeCiphertext {
    de::from_str(&a).unwrap()
}

fn json_to_sk(a: String) -> CpAbeSecretKey {
    de::from_str(&a).unwrap()
}






/// A Python module implemented in Rust.
#[pymodule]
fn cpabe(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(cpabe_setup, m)?)?;
    m.add_function(wrap_pyfunction!(cpabe_keygen, m)?)?;
    m.add_function(wrap_pyfunction!(cpabe_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(cpabe_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(cpabe_delegate, m)?)?;
    Ok(())
}
