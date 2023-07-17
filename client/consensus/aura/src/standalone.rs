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
use sha2::digest::Update;

pub use sc_consensus_slots::check_equivocation;

use super::{
	AuraApi, 
	AuthorityId, 
	CompatibilityMode, 
	CompatibleDigestItem, 
	SlotDuration, 
	LOG_TARGET,
};
use ark_bls12_381::Fr;

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
	secret: &[u8;32],
	authorities: &[AuthorityId<P>],
	keystore: &KeystorePtr,
) -> Option<(PreDigest, P::Public)> 
	where B: BlockT {
	// DRIEMWORKS::TODO should I replace this with expected_identity?
	// let expected_author = Hash-to-G1(identity::<P>(slot, authorities));
	// what if, when claiming the slot they decrypt
	let expected_author = slot_author::<P>(slot, authorities);
	let public = expected_author.and_then(|p| {
		if keystore.has_keys(&[(p.to_raw_vec(), sp_application_crypto::key_types::AURA)]) {
			let seed = <[u8; 32]>::decode(&mut TrailingZeroInput::new(secret.as_ref()))
				.expect("input is padded with zeroes; qed");
			let mut rng = ChaCha20Rng::from_seed(seed);
			let mut transcript = Transcript::new_labeled(b"etf");
			// both in G1
			let b = K::rand(&mut rng);
			let h = K::rand(&mut rng);

			let mut b_out = Vec::new();
			b.serialize_compressed(&mut b_out);
			let mut p_out = Vec::new();
			h.serialize_compressed(&mut p_out);

			let mut t = Transcript::new_labeled(b"etf");
			t.append(&b);
			t.append(&h);

			let mut reader = t.fork(b"secret").chain(secret.clone()).witness(&mut rng);
			let r: Fr = reader.read_uniform::<Fr>();
			let commitment: K = (b * r).into();
			t.append(&commitment);
			let c_bytes: [u8; 32] = t.challenge(b"challenge").read_byte_array();
			let c: Fr = Fr::from_be_bytes_mod_order(&c_bytes);
			let x: Fr = Fr::from_be_bytes_mod_order(secret);
			let s = r + c * x; 
			let mut commitment_out = Vec::new();
			commitment.serialize_compressed(&mut commitment_out).unwrap();

			let mut s_out = Vec::new();
			s.serialize_compressed(&mut s_out).unwrap();

			let pre_digest = PreDigest {
				slot: slot, 
				secret: *secret,
				challenge: commitment_out.try_into().unwrap(),
				witness: s_out.try_into().unwrap(), // I don't think the name is correct.. but w/e
				pps: (b_out.try_into().unwrap(), p_out.try_into().unwrap()),
			};
			Some((pre_digest.clone(), p.clone()))
		} else {
			None
		}
	});
	
	public
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
			secret: [0;32], 
			challenge: [0;48],
			witness: [0;32],
			pps: ([0;48], [0;48]),
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
		// DRIEMWORKS::TODO
		let secret = claim.secret;
		if !secret.eq(&[0;32]) {
			// "B"
			let r1_bytes = claim.pps.0;
			let r1: K = K::deserialize_compressed(&r1_bytes[..]).unwrap();
			// "P"
			let r2_bytes = claim.pps.1;
			let r2: K = K::deserialize_compressed(&r2_bytes[..]).unwrap();
			// "R"
			let challenge_bytes = claim.challenge;
			let challenge: K = K::deserialize_compressed(&challenge_bytes[..]).unwrap();
			// "s"
			let witness_bytes = claim.witness;
			let w: Fr = Fr::deserialize_compressed(&witness_bytes[..]).unwrap();
			
			let mut t = Transcript::new_labeled(b"etf");
			t.append(&r1);
			t.append(&r2);
			t.append(&challenge);
			let c_bytes: [u8; 32] = t.challenge(b"challenge").read_byte_array();
			let c: Fr = Fr::from_be_bytes_mod_order(&c_bytes);

			// calc: R' = sB- cP = w*r1 - c_bytes * r2
			// check: R = R'?
			let check: K = ((r1 * w) - (r2 * c)).into();
			assert!(check.eq(&challenge));
		} else {
			log::info!("The secret is empty");
		}
		// transcript.append()
		// TODO: should we also verify this secret?
		// since it's generated with PSS, we can do that
		// by checking that f(i) = j where j is my secret share
		// for that slot and f(x) would be exposed (instead of just the secret)
		// but does that cause problems in terms of storage space/costs
		// in the future?

		// let vrf_pk_buf = claim.vrf_public;
		// let mut vrf_pk = PublicKey::deserialize_compressed(
		// 	vrf_pk_buf.as_ref()).unwrap();
		// // let pk = vrf_sk.as_publickey();

		// let vrf_sig_buf = claim.vrf_signature;
		// let sig_thin = Signature::deserialize_compressed(
		// 	vrf_sig_buf.as_ref()).unwrap();

		// let mut t_0 = Transcript::new_labeled(b"EtFNetwork");
		// let mut reader = t_0.challenge(b"Keying&Blinding");
		// let vrf = ThinVrf { keying_base: reader.read_uniform() };
		// let mut sk = SecretKey::ephemeral(vrf.clone());

		// rebuild vrf ios?
		// let mk_io = |n: Vec<u8>| {
		// 	let input = vrf::ark_hash_to_curve::<K,H2C>(b"VrfIO", &n).unwrap();
		// 	sk.vrf_inout(input)
		// };
		// let ios: [vrf::VrfInOut<K>; 3] = [
		// 	mk_io(slot.to_le_bytes()[..].into()), 
		// 	mk_io(secret.into()),
		// 	mk_io([2;32].into()),
		// ];

		// this is basically just a schnorr signature..
		// let t = Transcript::new_labeled(b"etf");
		// match vrf.verify_thin_vrf(t, &[], &vrf_pk, &sig_thin) {
		// 	Ok(_) => { /* all good */ },
		// 	Err(e) => panic!("{:?}", e),
		// } 

		// check the signature is valid under the expected authority and
		// chain state.
		let expected_author =
			slot_author::<P>(slot, authorities).ok_or(SealVerificationError::SlotAuthorNotFound)?;

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

	#[test]
	fn tony() {
		// prover
		let secret = [3;32];
		let seed = <[u8; 32]>::decode(&mut TrailingZeroInput::new(secret.as_ref()))
			.expect("input is padded with zeroes; qed");
		let mut rng = ChaCha20Rng::from_seed(seed);
		// both in G1
		let b = K::rand(&mut rng);
		let h = K::rand(&mut rng);

		// let mut b_out = Vec::new();
		// b.serialize_compressed(&mut b_out);
		// let mut p_out = Vec::new();
		// h.serialize_compressed(&mut p_out);

		let mut t = Transcript::new_labeled(b"etf");
		t.append(&b);
		t.append(&h);

		let mut reader = t.fork(b"secret").chain(secret.clone()).witness(&mut rng);
		let r: Fr = reader.read_uniform::<Fr>();
		let commitment: K = (b * r).into();
		t.append(&commitment);
		let c_bytes: [u8; 32] = t.challenge(b"challenge").read_byte_array();
		let c: Fr = Fr::from_be_bytes_mod_order(&c_bytes);
		let x: Fr = Fr::from_be_bytes_mod_order(secret);
		let s = r + c * x; 
		let pi = (commitment, s);



		// "B"
		// let r1_bytes = claim.pps.0;
		// let r1: K = K::deserialize_compressed(&r1_bytes[..]).unwrap();
		// // "P"
		// let r2_bytes = claim.pps.1;
		// let r2: K = K::deserialize_compressed(&r2_bytes[..]).unwrap();
		// // "R"
		// let challenge_bytes = claim.challenge;
		// let challenge: K = K::deserialize_compressed(&challenge_bytes[..]).unwrap();
		// // "s"
		// let witness_bytes = claim.witness;
		// let w: Fr = Fr::deserialize_compressed(&witness_bytes[..]).unwrap();
		
		let mut t = Transcript::new_labeled(b"etf");
		t.append(&b);
		t.append(&h);
		t.append(&commitment);
		let c_bytes: [u8; 32] = t.challenge(b"challenge").read_byte_array();
		let c: Fr = Fr::from_be_bytes_mod_order(&c_bytes);

		// calc: R' = sB- cP = w*r1 - c_bytes * r2
		// check: R = R'?
		let check: K = ((s * b) - (c * h)).into();
		assert!(check.eq(&challenge));
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
