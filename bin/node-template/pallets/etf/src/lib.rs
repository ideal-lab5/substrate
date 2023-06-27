#![cfg_attr(not(feature = "std"), no_std)]

/// Edit this file to define custom logic or remove it if it is not needed.
/// Learn more about FRAME and the core library of Substrate FRAME pallets:
/// <https://docs.substrate.io/reference/frame-pallets/>
pub use pallet::*;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;
pub(crate) mod bls12_381;

pub(crate) use ark_scale::hazmat::ArkScaleProjective;
const HOST_CALL: ark_scale::Usage = ark_scale::HOST_CALL;
pub(crate) type ArkScale<T> = ark_scale::ArkScale<T, HOST_CALL>;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
pub mod weights;
pub use weights::*;
use sp_staking::SessionIndex;
use codec::{Encode, Decode};
use frame_system::offchain::{SendSignedTransaction};
use frame_support::{
	dispatch::Vec, BoundedSlice,
	traits::{
		Randomness,
		ValidatorRegistration, ValidatorSet, ValidatorSetWithIdentification,
	},
};
use sp_runtime::{
	KeyTypeId,
	traits::{Convert, TrailingZeroInput},
};
use rand_chacha::{
	rand_core::{RngCore, SeedableRng},
	ChaCha20Rng,
};
use ark_poly::{
    polynomial::univariate::DensePolynomial,
    DenseUVPolynomial, Polynomial,
};
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::{fields::Field, One, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_std::{rand::Rng, ops::Mul, test_rng, vec, string::ToString, UniformRand};
use sp_ark_bls12_381::{
	fq::Fq, fq2::Fq2, fr::Fr, Bls12_381 as Bls12_381Host, G1Affine as G1AffineHost,
	G1Projective as G1ProjectiveHost, G2Affine as G2AffineHost,
	G2Projective as G2ProjectiveHost, HostFunctions,
};

use ark_bls12_381::G1Projective;

pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"aura");

pub mod crypto {
	use super::KEY_TYPE;
	use sp_core::sr25519::Signature as Sr25519Signature;
	use sp_runtime::app_crypto::{app_crypto, sr25519};
	use sp_runtime::{traits::Verify, MultiSignature, MultiSigner};
	use sp_std::convert::TryFrom;

	app_crypto!(sr25519, KEY_TYPE);

	pub struct TestAuthId;
	// implemented for runtime
	impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for TestAuthId {
		type RuntimeAppPublic = Public;
		type GenericSignature = sp_core::sr25519::Signature;
		type GenericPublic = sp_core::sr25519::Public;
	}

	// implemented for mock runtime in test
	impl frame_system::offchain::AppCrypto<<Sr25519Signature as Verify>::Signer, Sr25519Signature>
		for TestAuthId
	{
		type RuntimeAppPublic = Public;
		type GenericSignature = sp_core::sr25519::Signature;
		type GenericPublic = sp_core::sr25519::Public;
	}
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*; 	
	use primitive_types::H256;
	use crate::{bls12_381, ArkScale, ArkScaleProjective};
	use frame_system::{
		pallet_prelude::*,
		offchain::{
			Signer,
			AppCrypto,
			CreateSignedTransaction,
		}
	};

	#[pallet::pallet]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(_);

	/// Configure the pallet by specifying the parameters and types on which it depends.
	#[pallet::config]
	pub trait Config: frame_system::Config + pallet_session::Config  + CreateSignedTransaction<Call<Self>> {
		/// Because this pallet emits events, it depends on the runtime's definition of an event.
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		/// Type representing the weight of this pallet
		type WeightInfo: WeightInfo;
		/// the maximum number of validators
		type MaxAuthorities: Get<u32>;
		/// Something that provides randomness in the runtime.
		type Randomness: Randomness<Self::Hash, Self::BlockNumber>;
		/// The identifier type for an authority.
		type AuthorityId: AppCrypto<Self::Public, Self::Signature>;
	}

	#[pallet::storage]
	#[pallet::getter(fn validators)]
	pub type Validators<T: Config> = StorageValue<
		_, BoundedVec<T::AccountId, T::MaxAuthorities>, ValueQuery,
	>;

	#[pallet::storage]
	pub type SessionPublicKey<T: Config> = StorageMap<
		_,
		Blake2_128,
		SessionIndex,
		Vec<u8>,
		ValueQuery,
	>;

	#[pallet::storage]
	#[pallet::getter(fn session_secret_keys)]
	pub type SessionSecretKeys<T: Config> = StorageMap<
		_,
		Blake2_128,
		SessionIndex,
		Vec<(u32, Vec<u8>)>,
		ValueQuery,
	>;

	/// map block num to secret
	#[pallet::storage]
	#[pallet::getter(fn slot_secrets)]
	pub type SlotSecrets<T: Config> = StorageMap<
		_,
		Blake2_128,
		Slot,
		Vec<u8>,
		ValueQuery,
	>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
	}

	// Errors inform users that something went wrong.
	#[pallet::error]
	pub enum Error<T> {
	}

	#[pallet::genesis_config]
	#[derive(frame_support::DefaultNoBound)]
	pub struct GenesisConfig<T: Config> {
		pub initial_validators: Vec<T::AccountId>,
	}

	// #[cfg(feature = "std")]
	// impl<T: Config> Default for GenesisConfig<T> {
	// 	fn default() -> Self {
	// 		Self { initial_validators: Default::default() }
	// 	}
	// }

	#[pallet::genesis_build]
	impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
		fn build(&self) {
			Pallet::<T>::initialize_validators(&self.initial_validators);
		}
	}

	 /// The identifier for the parachain consensus update inherent.
	 pub const INHERENT_IDENTIFIER: InherentIdentifier = *b"etfslots";

	 #[pallet::inherent]
	 impl<T: Config> ProvideInherent for Pallet<T>
	 where
		 <T as frame_system::Config>::Hash: From<H256>,
	 {
		 type Call = Call<T>;
		 type Error = sp_inherents::MakeFatalError<()>;
		 const INHERENT_IDENTIFIER: InherentIdentifier = INHERENT_IDENTIFIER;
 
		 fn create_inherent(data: &InherentData) -> Option<Self::Call> {
			let secret: Vec<u8> =
				data.get_data(&Self::INHERENT_IDENTIFIER).ok().flatten()?;
			
			Some(Call::reveal_slot_secret { secret })
		 }
 
		 fn is_inherent(call: &Self::Call) -> bool {
			matches!(call, Call::reveal_slot_secret { .. })
		 }

		 fn check_inherent(
			call: &Self::Call,
			data: &InherentData,
		) -> Result<(), Self::Error> {
			// todo
			Ok(())
		}
	 }
 
	#[pallet::call]
	impl<T: Config> Pallet<T> {
		
		/// called via an *inherent only*
		/// reveals a validator's slot secret by publishing it in a block
		///
		/// * `origin`: should be none, but must provide valid claim of slot authorship
		/// * `secret`: the secret to publish in the block
		/// TODO: require valid slot claim + verify
		#[pallet::call_index(0)]
		#[pallet::weight(0)]
		pub fn reveal_slot_secret(
			origin: OriginFor<T>,
			slot: Slot,
		) -> DispatchResult {
			ensure_none(origin)?;
			let current_block = frame_system::Pallet::<T>::block_number();
			SlotSecrets::<T>::insert(current_block, secret);
			Ok(())
		}

		/// called by root before each session
		/// submits session secret shares for each authority and the session public key
		///
		#[pallet::call_index(1)]
		#[pallet::weight(0)]
		pub fn submit_session_artifacts(
			origin: OriginFor<T>,
			session_index: SessionIndex,
			// session_pubkey: Vec<u8>,
			session_secrets: Vec<(u32, Vec<u8>)>,
		) -> DispatchResult {
			ensure_root(origin)?;
			// SessionPublicKey::<T>::insert(session_index.clone(), session_pubkey);
			SessionSecretKeys::<T>::insert(session_index.clone(), session_secrets);
			Ok(())
		}

		
		// #[pallet::call_index(2)]
		// #[pallet::weight(0)]
		// pub fn submit_session_pk(
		// 	origin: OriginFor<T>,
		// 	session_index: SessionIndex,
		// 	pk: [u8;32],
		// ) -> DispatchResult {
		// 	ensure_root(origin)?;
		// 	// let current_block = frame_system::Pallet::<T>::block_number();
		// 	// SlotSecrets::<T>::insert(current_block, secret);
		// 	Ok(())
		// }
	}
}

impl<T: Config> Pallet<T> {

	fn initialize_validators(validators: &[T::AccountId]) {
		log::info!("Initializing validators defined in the chain spec.");
		assert!(validators.len() > 0, "At least 1 validator should be initialized");
		assert!(<Validators<T>>::get().is_empty(), "Validators are already initialized!");
		let bounded = <BoundedSlice<'_, _, T::MaxAuthorities>>::try_from(validators)
				.expect("Initial authority set must be less than T::MaxAuthorities");
		<Validators<T>>::put(bounded);
	}

	/// generate a new random polynomial over the scalar field
	pub fn keygen<R: Rng + Sized>(
		t: usize,
		mut rng: R
	) -> DensePolynomial<Fr> {
		DensePolynomial::<Fr>::rand(t as usize, &mut rng)
	}

	/// calculate 'n' shares from the polynomial
	/// poly(1), ..., poly(n)
	pub fn calculate_shares(
		n: u8,
		poly: DensePolynomial<Fr>,
	) -> Vec<Fr> {
		(1..n).map(|k| poly.clone().evaluate(&<Fr>::from(k))).collect::<Vec<_>>()
	}
}

impl<T: Config> pallet_session::SessionManager<T::AccountId> for Pallet<T> {
	// Plan a new session and provide new validator set.
	// TODO: deal with randomness freshness
	// https://github.com/paritytech/substrate/issues/8312
	fn new_session(new_index: u32) -> Option<Vec<T::AccountId>> {
		log::info!("Starting new session with index: {:?}", new_index);
		let binding = Self::validators();
		let authorities = binding.as_slice();

		let (seed, _) = T::Randomness::random(new_index.to_string().as_bytes());
		// seed needs to be guaranteed to be 32 bytes.
		let seed = <[u8; 32]>::decode(&mut TrailingZeroInput::new(seed.as_ref()))
			.expect("input is padded with zeroes; qed");
		let mut rng = ChaCha20Rng::from_seed(seed);
		// // add timestamp to seed?
		
		// this is not the correct number of secrets but w/e for now
		let n = binding.len();
		// super simple scheme: produce a secret for each authority and put onchain
		let t = n;

		let f = Self::keygen(t, &mut rng);
		let master_secret = f.clone().evaluate(&<Fr>::from(0));
		let session_secrets = Self::calculate_shares(t as u8, f);		
		let encoded_secrets = session_secrets.iter().enumerate().map(|(i, s)| {
			let mut bytes: Vec<u8> = Vec::new();
			s.serialize_compressed(&mut bytes).unwrap();
			(i as u32, bytes)
		}).collect::<Vec<(u32, Vec<u8>)>>();

		// still having problems with group operations
		let generator = G1Projective::rand(&mut rng).into_affine();
		let p_pub = generator.mul(master_secret);
		let mut mpk_bytes = Vec::new();
		p_pub.serialize_compressed(&mut mpk_bytes.clone()).unwrap();

		SessionPublicKey::<T>::insert(new_index, mpk_bytes);
		SessionSecretKeys::<T>::insert(new_index, encoded_secrets);

		// let signer = frame_system::offchain::Signer::<T, <T as pallet::Config>::AuthorityId>::all_accounts();
		// if !signer.can_sign() {
		// 	log::error!(
		// 		"No local accounts available. Consider adding one via `author_insertKey` RPC.",
		// 	);
		// }
		// let results = signer.send_signed_transaction(|_account| { 
		// 	Call::submit_session_artifacts{
		// 		session_index: new_index,
		// 		// session_pubkey: mpk_bytes.clone(),
		// 		session_secrets: encoded_secrets.clone(),
		// 	}
		// });

		// for (_, res) in &results {
		// 	match res {
		// 		Ok(()) => log::info!("Submitted results successfully"),
		// 		Err(e) => log::error!("Failed to submit transaction: {:?}",  e),
		// 	}
		// }

		Some(authorities.into())
	}

	fn start_session(start_index: u32) {
		log::info!("Starting session with index: {:?}", start_index);
		// ActiveEra::<T>::mutate(|s| *s = Some(start_index));
	}

	fn end_session(end_index: u32) {
		log::info!("Ending session with index: {:?}", end_index);
	}
}

// Implementation of Convert trait for mapping ValidatorId with AccountId.
pub struct ValidatorOf<T>(sp_std::marker::PhantomData<T>);

impl<T: Config> Convert<T::ValidatorId, Option<T::ValidatorId>> for ValidatorOf<T> {
	fn convert(account: T::ValidatorId) -> Option<T::ValidatorId> {
		Some(account)
	}
}

impl<T: Config> ValidatorSet<T::AccountId> for Pallet<T> {
	type ValidatorId = T::ValidatorId;
	type ValidatorIdOf = T::ValidatorIdOf;

	fn session_index() -> sp_staking::SessionIndex {
		pallet_session::Pallet::<T>::current_index()
	}

	fn validators() -> Vec<Self::ValidatorId> {
		pallet_session::Pallet::<T>::validators()
	}
}

impl<T: Config> ValidatorSetWithIdentification<T::AccountId> for Pallet<T> {
	type Identification = T::ValidatorId;
	type IdentificationOf = ValidatorOf<T>;
}
