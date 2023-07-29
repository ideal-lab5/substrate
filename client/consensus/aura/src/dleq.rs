/// DLEQ Proofs
use ark_serialize::CanonicalSerialize;
use ark_std::{UniformRand, ops::Mul};
use rand_chacha::{
	ChaCha20Rng,
	rand_core::SeedableRng,
};
use ark_ff::PrimeField;
use ark_ec::AffineRepr;
use sha2::Digest;
use sha3::digest::{Update, ExtendableOutput, XofReader};
use ark_bls12_381::Fr;

/// the type of the G1 group
type K = ark_bls12_381::G1Affine;

// TODO: serialization??
/// a struct to hold a DLEQ proof
#[derive(Default, Clone)]
pub struct DLEQProof {
	/// the first commitment point rG
    pub commitment_1: K,
	///  the second commitment point rH
    pub commitment_2: K,
	/// the witness s = r + c*x
    pub witness: Fr,
	/// secret * G
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
    pub fn verify(id: &[u8], d: K, g: K, proof: DLEQProof) -> bool {
        let pk = hash_to_g1(&id);
        verify_proof(pk, d, g, proof)
    }
}

/// Prepare a DLEQ proof of knowledge of the value 'x'
/// 
/// * `x`: The secret (scalar)
///
fn prepare_proof(x: Fr, d: K, q: K, g: K) -> DLEQProof {
    // DRIEMWORKS::TODO determine a seed
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
/// * `g`: A publicly known generator used to generate the proof
/// * `proof`: The DLEQ proof to verify 
/// 
fn verify_proof(q: K , d: K, g: K, proof: DLEQProof) -> bool {
    let c = prepare_witness(vec![proof.commitment_1, proof.commitment_2, proof.out, d]);
    let check_x: K = (proof.out.mul(c) - g.mul(proof.witness)).into();
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

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::{
        ChaCha20Rng,
        rand_core::SeedableRng,
    };

    use ark_serialize::CanonicalDeserialize;

    #[test]
    fn dleq_prepare_and_verify_works() {
        let id = b"test_id_1".to_vec();
        let mut rng = ChaCha20Rng::seed_from_u64(0u64);
        let x = Fr::rand(&mut rng);
        let g = K::generator();
        let mut test = Vec::new();
        g.serialize_compressed(&mut test).unwrap();
        let (proof, d) = DLEQProof::new(&id, x, g);
        // valid proof
        let validity = DLEQProof::verify(&id, d, g, proof.clone());
        assert!(validity == true);
        // valid proof but wrong id
        let bad_id = b"test_id_2".to_vec();
        let validity = DLEQProof::verify(&bad_id, d, g, proof.clone());
        assert!(validity == false);
        // valid proof but wrong slot secret
        let bad_slot_secret = K::rand(&mut rng);
        let validity = DLEQProof::verify(&id, bad_slot_secret, g, proof);
        assert!(validity == false);
        // invalid proof but correct id and slot secret
        let (new_proof, _) = DLEQProof::new(&id, x, bad_slot_secret);
        let validity = DLEQProof::verify(&id, d, g, new_proof);
        assert!(validity == false);
    } 

    #[test]
    fn prove_secret_correctness_manual_testing_tool() {
        // deserialize slot secret bytes to G1
        let slot_secret_str = "0xaf7ea1cea2f862cda855ba7b7e338325cafdf264d0ad0b6190ce9593960934297d156d6ced5ad6cd8dd495faa94d6ac9";
        let d_bytes = array_bytes::hex2bytes_unchecked(slot_secret_str);
        let d = K::deserialize_compressed(&d_bytes[..]).unwrap();

        // get the expected id and encode as point in G1
        // subkey inspect 5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY
        // or check https://ss58.org/
        let author = "0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d".to_string();
        let id = "281774282";
        let mut hex = array_bytes::hex2bytes_unchecked(author);
        hex.append(&mut id.as_bytes().to_vec());
        let pk = hash_to_g1(&hex);

        // just hardcoded for testing purposes
        let x_bytes = [2;32];
        let x: Fr = Fr::from_be_bytes_mod_order(&x_bytes);

        let d_actual: K = pk.mul(x).into();
        assert!(d == d_actual);

    }
}