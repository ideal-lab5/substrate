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
use frame_system::offchain::{SendSignedTransaction, Signer, SubmitTransaction};
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
	transaction_validity::{InvalidTransaction, TransactionValidity, ValidTransaction},
	offchain::storage::StorageRetrievalError,
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

type Slot = u64;

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
	use sp_runtime::offchain::storage::StorageValueRef;
	// use sp_consensus_slots::Slot;

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
	pub type SessionSecretKeys<T: Config> = StorageDoubleMap<
		_,
		Blake2_128,
		Slot,
		Blake2_128,
		SessionIndex,
		Vec<Vec<u8>>, // TODO: update this: Slot -> Vec<EncryptedSecret>? 
		ValueQuery,
	>;

	#[pallet::storage]
	pub type Test<T: Config> = 
		StorageValue<_, u32, ValueQuery>;


	#[pallet::storage]
	pub type CurrentSessionIndex<T: Config> = 
		StorageValue<_, SessionIndex, ValueQuery>;

	#[pallet::storage]
	pub type ActiveSessionIndex<T: Config> = 
		StorageValue<_, SessionIndex, ValueQuery>;

	#[pallet::storage]
	pub type NextSessionIndex<T: Config> = 
		StorageValue<_, SessionIndex, ValueQuery>;

	/// TODO map block num to secret
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
		InvalidSigner,
	}

	#[pallet::genesis_config]
	#[derive(frame_support::DefaultNoBound)]
	pub struct GenesisConfig<T: Config> {
		pub initial_validators: Vec<T::AccountId>,
	}

	#[pallet::genesis_build]
	impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
		fn build(&self) {
			Pallet::<T>::initialize_validators(&self.initial_validators);
		}
	}


	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn offchain_worker(block_number: T::BlockNumber) {
			// if the CurrentSessionIndex changed... then it should be ahead of the active by one
			let next = CurrentSessionIndex::<T>::get();
			let current = CurrentSessionIndex::<T>::get();
			let active = ActiveSessionIndex::<T>::get();

			// if ending a session => submit new keys
			if next == active + 1 {
				Self::refresh_keys(next, Self::validators().into());
			}
			// // if planning an upcoming session, then calculate new key shares
			// if current == active + 1 {
			// 	// TODO
			// 	// Self::update_keys(current, Self::validators().into());
			// }

			// // stage0: keygen
			// let mut stage_0 = StorageValueRef::persistent(b"STAGE0");
			// // stage1: secret derivation and storage
			// let mut stage_1 = StorageValueRef::persistent(b"STAGE1");
			// // won't trigger the first session..
			// if let Some(s0) = stage_0.get::<u32>().unwrap_or(Some(0)) {
			// 	// genesis or between session end and planning
			// 	if s0 == (next as u32) - 1  && next > active {
			// 		log::info!("CALLING REFRESH KEYS");
			// 		// the session has ended, setup keys for next session
			// 		Self::refresh_keys(next, Self::validators().into());
			// 		stage_0.set(&next);
			// 	} else if let Some(s1) = stage_1.get::<u32>().unwrap_or(Some(0)) { 
			// 		// this should be triggered when start_session is called
			// 		// i.e. when the active session has incremented
			// 		if s1 == active - 1 {
			// 			// this should represent the encrypted secret
			// 			let mut test = 
			// 					StorageValueRef::persistent(b"test");
			// 				test.set(&[3;32]);
			// 			// we know there are 10 slots in the session obviously we need
			// 			// to actually caluclate this, not just hard code ;)
						
			// 			let start = TryInto::<u64>::try_into(block_number).ok().unwrap();
			// 			let end_block_number: u64 = start + 10u64;
			// 			log::info!("Writing secret for slots from block {:?} to {:?}",
			// 				block_number, end_block_number);
			// 			let session_slots = (start..end_block_number);
			// 			session_slots.map(|i: u64| {
			// 				let ssk = &SessionSecretKeys::<T>::get(s1)[i as usize];
			// 				let key = i.to_string();
			// 				let mut secret = 
			// 					StorageValueRef::persistent(key.as_bytes());
			// 				secret.set(ssk);
			// 			});
			// 			stage_1.set(&current);
			// 		}
			// 	} else {
			// 		stage_1.set(&0);
			// 	}
			// } else {
			// 	// do nothing for now?
			// 	stage_0.set(&0);
			// }

			// TODO [#3398] Generate offence report for all authorities that skipped their
			// slots.
		}
	}

	 #[pallet::inherent]
	 impl<T: Config> ProvideInherent for Pallet<T>
	 where
		 <T as frame_system::Config>::Hash: From<H256>,
	 {
		 type Call = Call<T>;
		 type Error = sp_inherents::MakeFatalError<()>;
		 const INHERENT_IDENTIFIER: InherentIdentifier = *b"etfslots";
 
		 fn create_inherent(data: &InherentData) -> Option<Self::Call> {
			log::info!("Calling the inherent");
			match data.get_data(&Self::INHERENT_IDENTIFIER) {
				Ok(secret) => {
					let s = secret.unwrap_or(Vec::new());
					log::info!("found secret: {:?}", s.clone());
					let slot: Slot = data.get_data(b"auraslot").ok().flatten()?;
					log::info!("Found slot: {:?}", slot);
					Some(Call::reveal_slot_secret { slot, secret: s })
				},
				Err(e) => {
					panic!("{:?}", e);
				}
			}
			
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
		
		// DRIEMWORKS::TODO REMOVE THIS?
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
			secret: Vec<u8>,
		) -> DispatchResult {
			// ensure_none(origin)?;
			SlotSecrets::<T>::insert(slot, secret);
			Ok(())
		}

		/// submits session secret shares for each authority and the session public key
		///
		#[pallet::call_index(1)]
		#[pallet::weight(0)]
		pub fn submit_session_artifacts(
			origin: OriginFor<T>,
			session_index: SessionIndex,
			session_secrets: Vec<(u64, Vec<u8>)>,
		) -> DispatchResult {
			log::info!("submitting session artifacts");
			let who = ensure_signed(origin)?;
			// this seems overly expensive..
			for (idx, sk) in session_secrets.iter() {
				SessionSecretKeys::<T>::mutate(idx, session_index.clone(), |secrets| {
					secrets.push(sk.clone());
				});
			}
			Ok(())
		}
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

	pub fn refresh_keys(
		new_index: SessionIndex, 
		authorities: Vec<T::AccountId>
	) -> Result<(), Error<T>> {
		let (seed, _) = T::Randomness::random(new_index.to_string().as_bytes());
		// seed needs to be guaranteed to be 32 bytes.
		let seed = <[u8; 32]>::decode(&mut TrailingZeroInput::new(seed.as_ref()))
			.expect("input is padded with zeroes; qed");
		let mut rng = ChaCha20Rng::from_seed(seed);
		// add timestamp to seed?
		// we actually need the number of slots/session, not number of authorities
		// defined in aura config
		// let n = authorities.len();
		// DRIEMWORKS::TODO CALC SLOTS/SESSION (it's 10 right now)
		let n = 10;
		// (n,n) TSS
		let t = n;
		let f = Self::keygen(t, &mut rng);
		let master_secret = f.clone().evaluate(&<Fr>::from(0));
		// Q: can i store this locally? offchain storage?
		let secret_shares = Self::calculate_shares(n as u8, f);		
		let encoded_secrets = secret_shares.iter().enumerate().map(|(i, s)| {
			let mut bytes: Vec<u8> = Vec::new();
			s.serialize_compressed(&mut bytes).unwrap();
			(i as u64, bytes)
		}).collect::<Vec<(u64, Vec<u8>)>>();

		let signer = Signer::<T, T::AuthorityId>::all_accounts();
		if !signer.can_sign() {
			return Err(Error::<T>::InvalidSigner);
		}
		let results = signer.send_signed_transaction(|_account| 
			Call::submit_session_artifacts { 
				session_index: new_index.clone(), 
				session_secrets: encoded_secrets.clone(),
			});

		for (acc, res) in &results {
			match res {
				Ok(()) => log::info!("Submitted session secrets"),
				Err(e) => log::error!("Failed to submit session secrets"),
			}
		}
		Ok(())
	}
}

impl<T: Config> pallet_session::SessionManager<T::AccountId> for Pallet<T> {
	// Plan a new session and provide new validator set.
	// TODO: deal with randomness freshness
	// https://github.com/paritytech/substrate/issues/8312
	fn new_session(new_index: u32) -> Option<Vec<T::AccountId>> {
		log::info!("Starting new session with index: {:?}", new_index);
		CurrentSessionIndex::<T>::put(new_index);
		Some(Self::validators().into())
	}

	fn new_session_genesis(new_index: SessionIndex)  -> Option<Vec<T::AccountId>> {
		CurrentSessionIndex::<T>::put(new_index);
		Some(Self::validators().into())
	}

	fn start_session(start_index: u32) {
		log::info!("Starting session with index: {:?}", start_index);
		ActiveSessionIndex::<T>::put(start_index);
	}

	fn end_session(end_index: u32) {
		log::info!("Ending session with index: {:?}", end_index);
		let active = ActiveSessionIndex::<T>::get();
		NextSessionIndex::<T>::put(active + 1);
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
