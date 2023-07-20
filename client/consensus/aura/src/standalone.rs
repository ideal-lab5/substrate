// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd. & Ideal Labs (USA) <--- how does that work?
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Standalone functions used within the implementation of Aura.

use std::fmt::Debug;

use log::trace;

use codec::Codec;

use codec::{Encode, Decode};

use sc_client_api::{backend::AuxStore, UsageProvider};
use sp_api::{Core, ProvideRuntimeApi};
use sp_application_crypto::{AppCrypto, AppPublic};
use sp_blockchain::Result as CResult;
use sp_consensus::Error as ConsensusError;
use sp_consensus_slots::Slot;
use sp_core::crypto::{ByteArray, Pair};
use sp_keystore::KeystorePtr;
use sp_runtime::{
	traits::{Block as BlockT, Header, NumberFor, Zero, TrailingZeroInput},
	DigestItem,
};
use sp_consensus_aura::digests::PreDigest;
use dleq_vrf::{
	Transcript, vrf, 
	Signature, 
	PublicKey,
	SecretKey as SK, 
	ThinVrf as Vrf, 
};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_std::{UniformRand, ops::Mul};
use rand_chacha::{
	ChaCha20Rng,
	rand_core::SeedableRng,
};
use ark_ff::{PrimeField, fields::models::fp::Fp};
use ark_ec::AffineRepr;

pub use sc_consensus_slots::check_equivocation;

use super::{
	AuraApi, 
	AuthorityId, 
	CompatibilityMode, 
	CompatibleDigestItem, 
	SlotDuration, 
	LOG_TARGET,
};
use sha2::Digest;
use sha3::{ Shake128, digest::{Update, ExtendableOutput, XofReader}, };
use ark_ff::BigInteger;
use ark_bls12_381::{Fr, G2Projective};

type K = ark_bls12_381::G1Affine;

type SecretKey = SK<K>;

type ThinVrf = Vrf<K>;

type H2C = ark_ec::hashing::map_to_curve_hasher::MapToCurveBasedHasher::<
    <K as ark_ec::AffineRepr>::Group,
    ark_ff::fields::field_hashers::DefaultFieldHasher<sha2::Sha256>,
    ark_ec::hashing::curve_maps::wb::WBMap<ark_bls12_381::g1::Config>,
>;

/// Get the slot duration for Aura by reading from a runtime API at the best block's state.
pub fn slot_duration<A, B, C>(client: &C) -> CResult<SlotDuration>
where
	A: Codec,
	B: BlockT,
	C: AuxStore + ProvideRuntimeApi<B> + UsageProvider<B>,
	C::Api: AuraApi<B, A>,
{
	slot_duration_at(client, client.usage_info().chain.best_hash)
}

/// Get the slot duration for Aura by reading from a runtime API at a given block's state.
pub fn slot_duration_at<A, B, C>(client: &C, block_hash: B::Hash) -> CResult<SlotDuration>
where
	A: Codec,
	B: BlockT,
	C: AuxStore + ProvideRuntimeApi<B>,
	C::Api: AuraApi<B, A>,
{
	client.runtime_api().slot_duration(block_hash).map_err(|err| err.into())
}

/// Get the slot author for given block along with authorities.
pub fn slot_author<P: Pair>(slot: Slot, authorities: &[AuthorityId<P>]) -> Option<&AuthorityId<P>> {
	if authorities.is_empty() {
		return None
	}

	let idx = *slot % (authorities.len() as u64);
	assert!(
		idx <= usize::MAX as u64,
		"It is impossible to have a vector with length beyond the address space; qed",
	);

	let current_author = authorities.get(idx as usize).expect(
		"authorities not empty; index constrained to list length;this is a valid index; qed",
	);

	Some(current_author)
}

/// Attempt to claim a slot using a keystore.
///
/// This returns `None` if the slot author is not locally controlled, and `Some` if it is,
/// with the public key of the slot author.
pub async fn claim_slot<B, P: Pair>(
	slot: Slot,
	block_hash: B::Hash,
	authorities: &[AuthorityId<P>],
	secret: &[u8;32],
	pk_bytes: &[u8;48], // H-to-g1(ID)
	keystore: &KeystorePtr,
) -> Option<(PreDigest, P::Public)> 
	where B: BlockT {
	let expected_author = slot_author::<P>(slot, authorities);
	let public = expected_author.and_then(|p| {
		if keystore.has_keys(&[(p.to_raw_vec(), sp_application_crypto::key_types::AURA)]) {
			// TODO should probably be passed as a param
			let mut id = p.to_raw_vec();
			let s = u64::from(slot);
			id.append(&mut s.to_string().as_bytes().to_vec());
			let pk = hash_to_g1(&id);
			let seed = <[u8; 32]>::decode(&mut TrailingZeroInput::new(b"test"))
				.expect("input is padded with zeroes; qed");
			let mut rng = ChaCha20Rng::from_seed(seed);
			let x: Fr = Fr::from_be_bytes_mod_order(secret);
			// the (to be exposed) slot secret
			let d: K = pk.mul(x).into();
			let proof = prepare_proof(x, d, pk);
			let pre_digest = PreDigest {
				slot: slot, 
				secret: convert_to_bytes::<K, 48>(d).try_into().unwrap(),
				proof: (
					convert_to_bytes::<K, 48>(
						proof.commitment_1).try_into().unwrap(),
					convert_to_bytes::<K, 48>(
						proof.commitment_2).try_into().unwrap(),
					convert_to_bytes::<Fr, 32>(
						proof.witness).try_into().unwrap(),
					convert_to_bytes::<K, 48>(
						proof.out).try_into().unwrap(),
				),
			};
			Some((pre_digest.clone(), p.clone()))
		} else {
			None
		}
	});
	
	public
}

// TODO: proper error handling
fn convert_from_bytes<E: CanonicalDeserialize, const N: usize>(bytes: &[u8; N]) -> Option<E> {
	let k: E = E::deserialize_compressed(&bytes[..]).unwrap();
	Some(k)
}

// should it be an error instead?
fn convert_to_bytes<E: CanonicalSerialize, const N: usize>(k: E) -> [u8;N] {
	let mut out = Vec::with_capacity(k.compressed_size());
	k.serialize_compressed(&mut out).unwrap_or(());
	let o: [u8; N] = out.try_into().unwrap_or([0;N]);
	o
}

fn hash_to_g1(b: &[u8]) -> K {
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

fn sha256(b: &[u8]) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
	sha2::Digest::update(&mut hasher, b);
    // hasher.update(b);
    hasher.finalize().to_vec()
}

// TODO: serialization??
/// a struct to hold a DLEQ proof
pub struct Proof<K, S> {
	/// the first commitment point rG
    pub commitment_1: K,
	///  the second commitment point rH
    pub commitment_2: K,
	/// the witness s = r + c*x
    pub witness: S,
	/// secret * G (can probably remove...)
    pub out: K,
}

/// Prepare a DLEQ proof of knowledge of the value 'x'
/// 
/// * `x`: The secret (scalar)
///
pub fn prepare_proof(x: Fr, d: K, q: K) -> Proof<K, Fr> {
    let mut rng = ChaCha20Rng::from_seed([2;32]);
    let r: Fr = Fr::rand(&mut rng);
    let commitment_1: K = K::generator().mul(r).into();
    let commitment_2: K = q.mul(r).into();
    let pk: K = K::generator().mul(x).into();
    let c: Fr = prepare_witness(vec![commitment_1, commitment_2, pk, d]);
    let s = r + x * c;
    Proof {
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
fn verify_proof(q: K , d: K, proof: Proof<K, Fr>) -> bool {
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


/// Produce the pre-runtime digest containing the slot info and slot secret.
///
/// This is intended to be put into the block header prior to runtime execution,
/// so the runtime can read the slot in this way.
pub fn pre_digest<P: Pair>(digest: PreDigest) -> sp_runtime::DigestItem
where
	P::Signature: Codec,
{
	<DigestItem as CompatibleDigestItem<P::Signature>>::aura_pre_digest(digest)
}

/// Produce the seal digest item by signing the hash of a block.
///
/// Note that after this is added to a block header, the hash of the block will change.
pub fn seal<Hash, P>(
	header_hash: &Hash,
	public: &P::Public,
	keystore: &KeystorePtr,
) -> Result<sp_runtime::DigestItem, ConsensusError>
where
	Hash: AsRef<[u8]>,
	P: Pair,
	P::Signature: Codec + TryFrom<Vec<u8>>,
	P::Public: AppPublic,
{
	let signature = keystore
		.sign_with(
			<AuthorityId<P> as AppCrypto>::ID,
			<AuthorityId<P> as AppCrypto>::CRYPTO_ID,
			public.as_slice(),
			header_hash.as_ref(),
		)
		.map_err(|e| ConsensusError::CannotSign(format!("{}. Key: {:?}", e, public)))?
		.ok_or_else(|| {
			ConsensusError::CannotSign(format!("Could not find key in keystore. Key: {:?}", public))
		})?;
	
	let signature = signature
		.clone()
		.try_into()
		.map_err(|_| ConsensusError::InvalidSignature(signature, public.to_raw_vec()))?;

	let signature_digest_item =
		<DigestItem as CompatibleDigestItem<P::Signature>>::aura_seal(signature);

	Ok(signature_digest_item)
}

/// Errors in pre-digest lookup.
#[derive(Debug, thiserror::Error)]
pub enum PreDigestLookupError {
	/// Multiple Aura pre-runtime headers
	#[error("Multiple Aura pre-runtime headers")]
	MultipleHeaders,
	/// No Aura pre-runtime digest found
	#[error("No Aura pre-runtime digest found")]
	NoDigestFound,
}

/// Extract a pre-digest from a block header.
///
/// This fails if there is no pre-digest or there are multiple.
///
/// Returns the `slot` stored in the pre-digest or an error if no pre-digest was found.
pub fn find_pre_digest<B: BlockT, Signature: Codec>(
	header: &B::Header,
) -> Result<PreDigest, PreDigestLookupError> {
	if header.number().is_zero() {
		return Ok(PreDigest{ 
			slot: 0.into(), 
			secret: [0;48], 
			proof: ([0;48], [0;48], [0;32], [0;48]),
			// vrf_signature: [0;80], 
			// vrf_public: [0;48],
			// ios: [0;32],
		});
	}

	let mut pre_digest: Option<PreDigest> = None;
	for log in header.digest().logs() {
		trace!(target: LOG_TARGET, "Checking log {:?}", log);
		match (CompatibleDigestItem::<Signature>::as_aura_pre_digest(log), pre_digest.is_some()) {
			(Some(_), true) => return Err(PreDigestLookupError::MultipleHeaders),
			(None, _) => trace!(target: LOG_TARGET, "Ignoring digest not meant for us"),
			(s, false) => pre_digest = s,
		}
	}
	pre_digest.ok_or_else(|| PreDigestLookupError::NoDigestFound)
}

/// Fetch the current set of authorities from the runtime at a specific block.
///
/// The compatibility mode and context block number informs this function whether
/// to initialize the hypothetical block created by the runtime API as backwards compatibility
/// for older chains.
pub fn fetch_authorities_with_compatibility_mode<A, B, C>(
	client: &C,
	parent_hash: B::Hash,
	context_block_number: NumberFor<B>,
	compatibility_mode: &CompatibilityMode<NumberFor<B>>,
) -> Result<Vec<A>, ConsensusError>
where
	A: Codec + Debug,
	B: BlockT,
	C: ProvideRuntimeApi<B>,
	C::Api: AuraApi<B, A>,
{
	let runtime_api = client.runtime_api();

	match compatibility_mode {
		CompatibilityMode::None => {},
		// Use `initialize_block` until we hit the block that should disable the mode.
		CompatibilityMode::UseInitializeBlock { until } =>
			if *until > context_block_number {
				runtime_api
					.initialize_block(
						parent_hash,
						&B::Header::new(
							context_block_number,
							Default::default(),
							Default::default(),
							parent_hash,
							Default::default(),
						),
					)
					.map_err(|_| ConsensusError::InvalidAuthoritiesSet)?;
			},
	}

	runtime_api
		.authorities(parent_hash)
		.ok()
		.ok_or(ConsensusError::InvalidAuthoritiesSet)
}

/// Load the current set of authorities from a runtime at a specific block.
pub fn fetch_authorities<A, B, C>(
	client: &C,
	parent_hash: B::Hash,
) -> Result<Vec<A>, ConsensusError>
where
	A: Codec + Debug,
	B: BlockT,
	C: ProvideRuntimeApi<B>,
	C::Api: AuraApi<B, A>,
{
	client
		.runtime_api()
		.authorities(parent_hash)
		.ok()
		.ok_or(ConsensusError::InvalidAuthoritiesSet)
}

/// Errors in slot and seal verification.
#[derive(Debug, thiserror::Error)]
pub enum SealVerificationError<Header> { 
	/// Header is deferred to the future.
	#[error("Header slot is in the future")]
	Deferred(Header, Slot),

	/// The header has no seal digest.
	#[error("Header is unsealed.")]
	Unsealed,

	/// The header has a malformed seal.
	#[error("Header has a malformed seal")]
	BadSeal,

	/// The header has a bad signature.
	#[error("Header has a bad signature")]
	BadSignature,

	/// No slot author found.
	#[error("No slot author for provided slot")]
	SlotAuthorNotFound,

	/// Header has no valid slot pre-digest.
	#[error("Header has no valid slot pre-digest")]
	InvalidPreDigest(PreDigestLookupError),
}

// DRIEMWORKS::TODO
/// Check a header has been signed by the right key. If the slot is too far in the future, an error
/// will be returned. If it's successful, returns the pre-header (i.e. without the seal),
/// the slot, and the digest item containing the seal.
///
/// Note that this does not check for equivocations, and [`check_equivocation`] is recommended
/// for that purpose.
///
/// This digest item will always return `Some` when used with `as_aura_seal`.
pub fn check_header_slot_and_seal<B: BlockT, P: Pair>(
	slot_now: Slot,
	mut header: B::Header,
	authorities: &[AuthorityId<P>],
) -> Result<(B::Header, PreDigest, DigestItem), SealVerificationError<B::Header>>
where
	P::Signature: Codec,
	P::Public: Codec + PartialEq + Clone,
{
	let seal = header.digest_mut().pop().ok_or(SealVerificationError::Unsealed)?;

	let sig = seal.as_aura_seal().ok_or(SealVerificationError::BadSeal)?;

	let claim = find_pre_digest::<B, P::Signature>(&header)
		.map_err(SealVerificationError::InvalidPreDigest)?;

	let slot = claim.slot;

	// the slot cannot be in the future
	if slot > slot_now {
		header.digest_mut().push(seal);
		return Err(SealVerificationError::Deferred(header, slot))
	} else {
		let expected_author =
			slot_author::<P>(slot, authorities).ok_or(SealVerificationError::SlotAuthorNotFound)?;
		let mut id = expected_author.to_raw_vec();
		let s = u64::from(slot);
		id.append(&mut s.to_string().as_bytes().to_vec());
		// the expected public key associated with the slot
		let pk = hash_to_g1(&id);
		let secret_bytes = claim.secret;
		// TODO: error handling
		let d: K = K::deserialize_compressed(&secret_bytes[..]).unwrap();
		let p = claim.proof;
		let proof = Proof {
			commitment_1: 
				convert_from_bytes::<K, 48>(&p.0).unwrap(),
			commitment_2: 
				convert_from_bytes::<K, 48>(&p.1).unwrap(),
			witness: 
				convert_from_bytes::<Fr, 32>(&p.2).unwrap(),
			out: 
				convert_from_bytes::<K, 48>(&p.3).unwrap(),
		};
		let is_valid = verify_proof(pk, d, proof);
		// TODO: create error type
		assert!(is_valid);
		// check the signature is valid under the expected authority and
		// chain state.
		let pre_hash = header.hash();

		if P::verify(&sig, pre_hash.as_ref(), expected_author) {
			Ok((header, claim, seal))
		} else {
			Err(SealVerificationError::BadSignature)
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use sp_keyring::sr25519::Keyring;

	use sha3::{ Shake128, digest::{Update, ExtendableOutput, XofReader}, };
	use ark_ff::BigInteger;
	use ark_ec::{pairing::Pairing, CurveConfig, Group};

	#[test]
	fn tony() {
		// PROVER
		let seed = <[u8; 32]>::decode(&mut TrailingZeroInput::new(b"test"))
			.expect("input is padded with zeroes; qed");
		let mut rng = ChaCha20Rng::from_seed(seed);
		// the 'secret'
		let x: Fr = Fr::rand(&mut rng);
		// choose a random generator P
		let G: K = K::generator();
		// sample random point in the scalar field
		let r: Fr = Fr::rand(&mut rng);
		// create a commitment
		let R: K = G.mul(r).into();
		// convert commitment to bytes
        let mut  R_Bytes= Vec::with_capacity(R.compressed_size());
        R.serialize_compressed(&mut R_Bytes).unwrap();
		// write commitment bytes to hasher
        let mut h = sha3::Shake128::default();
        h.update(R_Bytes.as_slice());
		let mut o = [0u8; 32];
		// get challenge from hashers
        h.finalize_xof().read(&mut o);
		let c: Fr = Fr::from_be_bytes_mod_order(&o);
		// calculate s 
		let s = r + &(x * c);
		// POK = (R, s)

		// VERIFIER
		let R_v: K = G.mul(x).into();
		let P: K = (G.mul(s) - R_v.mul(c)).into();
		assert!(P == R);
	}

	#[test]
	fn authorities_call_works() {
		let client = substrate_test_runtime_client::new();

		assert_eq!(client.chain_info().best_number, 0);
		assert_eq!(
			fetch_authorities_with_compatibility_mode(
				&client,
				client.chain_info().best_hash,
				1,
				&CompatibilityMode::None
			)
			.unwrap(),
			vec![
				Keyring::Alice.public().into(),
				Keyring::Bob.public().into(),
				Keyring::Charlie.public().into()
			]
		);

		assert_eq!(
			fetch_authorities(&client, client.chain_info().best_hash).unwrap(),
			vec![
				Keyring::Alice.public().into(),
				Keyring::Bob.public().into(),
				Keyring::Charlie.public().into()
			]
		);
	}
}
