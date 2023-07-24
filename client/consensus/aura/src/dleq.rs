/// DLEQ Proof 

use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_std::{UniformRand, ops::Mul};
use rand_chacha::{
	ChaCha20Rng,
	rand_core::SeedableRng,
};
use ark_ff::{PrimeField, fields::models::fp::Fp};
use ark_ec::AffineRepr;
use sha2::Digest;
use sha3::{ Shake128, digest::{Update, ExtendableOutput, XofReader}, };
use ark_ff::BigInteger;
use ark_bls12_381::{Fr, G2Projective};

/// the type of the G1 group
type K = ark_bls12_381::G1Affine;

// TODO: serialization??
/// a struct to hold a DLEQ proof
pub struct DLEQProof {
	/// the first commitment point rG
    pub commitment_1: K,
	///  the second commitment point rH
    pub commitment_2: K,
	/// the witness s = r + c*x
    pub witness: Fr,
	/// secret * G (can probably remove...)
    pub out: K,
}

/// implementation of dleq proof
impl DLEQProof {
    /// construct a new DLEQ Proof for the given id and secret
    ///
    /// * `id`: The identity from which we will derive a public key
    /// * `x`: The secret in the scalar field S (over which K is defined).
    /// * `g`: A group generator of K
    ///
    pub fn new(id: &[u8], x: Fr, g: K) -> (Self, K) {
        let pk = hash_to_g1(&id);
        let d: K = pk.mul(x).into();
        (prepare_proof(x, d, pk, g), d)
    }

    /// verify a DLEQ Proof with a given id and slot secret
    pub fn verify(id: &[u8], d: K, proof: DLEQProof) -> bool {
        let pk = hash_to_g1(&id);
        verify_proof(pk, d, proof)
    }
}

/// Prepare a DLEQ proof of knowledge of the value 'x'
/// 
/// * `x`: The secret (scalar)
///
fn prepare_proof(x: Fr, d: K, q: K, g: K) -> DLEQProof {
    let mut rng = ChaCha20Rng::from_seed([2;32]);
    let r: Fr = Fr::rand(&mut rng);
    let commitment_1: K = g.mul(r).into();
    let commitment_2: K = q.mul(r).into();
    let pk: K = g.mul(x).into();
    let c: Fr = prepare_witness(vec![commitment_1, commitment_2, pk, d]);
    let s = r + x * c;
    DLEQProof {
        commitment_1, 
        commitment_2, 
        witness: s, 
        out: pk
    }
}

/// verify the proof was generated on the given input
/// 
/// * `q`: The group element such that d = xq for the secret q
/// * `d`: The 'secret'
/// * `proof`: The DLEQ proof to verify 
/// 
fn verify_proof(q: K , d: K, proof: DLEQProof) -> bool {
    let c = prepare_witness(vec![proof.commitment_1, proof.commitment_2, proof.out, d]);
    let check_x: K = (proof.out.mul(c) - K::generator().mul(proof.witness)).into();
    let check_y: K = (d.mul(c) - q.mul(proof.witness)).into();

    check_x.x.eq(&proof.commitment_1.x) &&
        check_y.x.eq(&proof.commitment_2.x)
}

/// Prepare a witness for the proof using Shake128
/// 
/// `p`: A point in the group G1 
/// 
fn prepare_witness(points: Vec<K>) -> Fr {
    let mut h = sha3::Shake128::default();

    for p in points.iter() {
        let mut bytes = Vec::with_capacity(p.compressed_size());
        p.serialize_compressed(&mut bytes).unwrap();
        h.update(bytes.as_slice());
    }
    
    let mut o = [0u8; 32];
    // get challenge from hasher
    h.finalize_xof().read(&mut o);
    Fr::from_be_bytes_mod_order(&o)
}

/// hash the input to the G1 curve
pub fn hash_to_g1(b: &[u8]) -> K {
    let mut nonce = 0u32;
    loop {
        let c = [b, &nonce.to_be_bytes()].concat();
        match K::from_random_bytes(&sha256(&c)) {
            Some(v) => {
                // if v.is_in_correct_subgroup_assuming_on_curve() { return v.into(); }
                return v.mul_by_cofactor_to_group().into();
            }
            None => nonce += 1,
        }
    }
}

/// sha256 hash the input slice
fn sha256(b: &[u8]) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
	sha2::Digest::update(&mut hasher, b);
    // hasher.update(b);
    hasher.finalize().to_vec()
}