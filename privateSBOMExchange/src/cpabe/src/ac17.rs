use pyo3::prelude::*;
use pyo3::types::PyList;
use rabe::schemes::ac17::*;
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
pub fn ac17_cpabe_setup() -> (String, String) {
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
pub fn ac17_cpabe_keygen<'py>(mk: String, attributes: &Bound<'py, PyList>) -> String {
    let _mk = json_to_mk(mk.clone());
    let mut attr_vec: Vec<String> = Vec::new();
    for value in attributes.iter() {
        attr_vec.push(value.to_string());
    }
    
    let pos: Vec<&str> = attr_vec.iter().map(AsRef::as_ref).collect();
    let sk = cp_keygen(&_mk, pos.as_slice()).unwrap();
    sk_to_json(sk)
}


#[pyfunction]
/** 
 * Encrypt adapter for rabe. Given a json-formatted public key (pk), a policy (policy), and a
 * plaintext message (plaintext), produce a ciphertext-json object.
 */
pub fn ac17_cpabe_encrypt<'py>(pk: String, policy: &str, plaintext: &[u8]) -> String {
    let _pk = json_to_pk(pk.clone());
    let ct = cp_encrypt(&_pk, policy, plaintext, PolicyLanguage::HumanPolicy).unwrap();
    ct_to_json(ct)
}

#[pyfunction]
/** 
 * Decrypt adapter for rabe. Given a json-formatted secret key (sk) and a ciphertext (ct),
 *  decrypt the ciphertext to produce a plaintext (as a vector of bytes) or produce an error.
 */
pub fn ac17_cpabe_decrypt(sk: String, ct: String) -> Vec<u8> {
    let _sk = json_to_sk(sk.clone());
    let _ct = json_to_ct(ct.clone());

    let pt = cp_decrypt(&_sk, &_ct).unwrap();
    pt

}

/**
 * encodes public-key object in rust into a json representation Keep in mind this json
 * object is an opaque key object from rabe, and not a standard key representation format such as
 * PEM/DER/PKCSvX variants.  
 */
fn pk_to_json(a: Ac17PublicKey) -> String {
    ser::to_string(&a).unwrap()
}

/**
 * encodes master-key object in rust into a json representation Keep in mind this json
 * object is an opaque key object from rabe, and not a standard key representation format such as
 * PEM/DER/PKCSvX variants.  
 */
fn mk_to_json(a: Ac17MasterKey) -> String {
    ser::to_string(&a).unwrap()
}

/**
 * encodes secret-key object in rust into a json representation Keep in mind this json
 * object is an opaque key object from rabe, and not a standard key representation format such as
 * PEM/DER/PKCSvX variants.  
 */
fn sk_to_json(a: Ac17CpSecretKey) -> String {
    ser::to_string(&a).unwrap()
}


/**
 * encodes cphertext object in rust into a json representation Keep in mind this json
 * object is an opaque key object from rabe, and not a standard key representation format such as
 * PEM/DER/PKCSvX variants.  
 */
fn ct_to_json(a: Ac17CpCiphertext) -> String {
    ser::to_string(&a).unwrap()
}

fn json_to_pk(a: String) -> Ac17PublicKey {
    de::from_str(&a).unwrap()
}

fn json_to_mk(a: String) -> Ac17MasterKey {
    de::from_str(&a).unwrap()
}

fn json_to_ct(a: String) -> Ac17CpCiphertext {
    de::from_str(&a).unwrap()
}

fn json_to_sk(a: String) -> Ac17CpSecretKey {
    de::from_str(&a).unwrap()
}
