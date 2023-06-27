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
use frame_system::offchain::{SendSignedTransaction, SubmitTransaction};
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
	pub type SessionSecretKeys<T: Config> = StorageMap<
		_,
		Blake2_128,
		SessionIndex,
		Vec<(u32, Vec<u8>)>, // TODO: update this: Slot -> Vec<EncryptedSecret>? 
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
			let current = CurrentSessionIndex::<T>::get();
			let active = ActiveSessionIndex::<T>::get();
			if current > active {
				// we're planning a new session
				Self::refresh_keys(current, Self::validators().into());
			} else if current == active {
				// we have started or are in a session
				// reveal 'next block secret'
			}
		}
	}
	
	#[pallet::validate_unsigned]
	impl<T: Config> ValidateUnsigned for Pallet<T> {
		type Call = Call<T>;

		/// Validate unsigned call to this module.
		///
		/// By default unsigned transactions are disallowed, but implementing the validator
		/// here we make sure that some particular calls (the ones produced by offchain worker)
		/// are being whitelisted and marked as valid.
		fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
			ValidTransaction::with_tag_prefix("etfnetwork")
				.priority(2 << 20)
				.longevity(5)
				.propagate(true)
				.build()
			// // Firstly let's check that we call the right function.
			// if let Call::submit_session_artifacts { .. } = call {
			// 	// Self::validate_transaction_parameters(session_index, session_secrets)
			// 	ValidTransaction::with_tag_prefix("etfnetwork")
			// 		.priority(2 << 20)
			// 		.longevity(5)
			// 		.propagate(true)
			// 		.build()
			// } else {
			// 	InvalidTransaction::Call.into()
			// }
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
			let slot: Slot = data.get_data(b"auraslot").ok().flatten()?;
			
			// can we read from local storage? No
			let storage = StorageValueRef::persistent(b"TEST");

			if let Ok(Some(res)) = storage.get::<u64>() {
				// log::info!("cached result: {:?}", res);
				assert!(false);
			} else {
				assert!(true);
				// log::info!("As expected.");
			}
			let secret: Vec<u8> =
				data.get_data(&Self::INHERENT_IDENTIFIER).ok().flatten()?;
			Some(Call::reveal_slot_secret { slot, secret })
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
			secret: Vec<u8>,
		) -> DispatchResult {
			ensure_none(origin)?;
			// let current_block = frame_system::Pallet::<T>::block_number();
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
			session_secrets: Vec<(u32, Vec<u8>)>,
		) -> DispatchResult {
			ensure_none(origin)?;
			SessionSecretKeys::<T>::insert(
				session_index.clone(), session_secrets
			);
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

	// fn validate_transaction_parameters(
	// 	index: &SessionIndex,
	// 	encoded_secrets: &Vec<(u32, Vec<u8>)>
	// ) -> TransactionValidity {
	// 	// DRIEMWORKS::TODO logic to validate unsigned
	// 	// 1. make sure the index is the expected one
	// 	// 2. make sure 

	// 	// // Now let's check if the transaction has any chance to succeed.
	// 	// let next_unsigned_at = <NextUnsignedAt<T>>::get();
	// 	// if &next_unsigned_at > block_number {
	// 	// 	return InvalidTransaction::Stale.into()
	// 	// }
	// 	// // Let's make sure to reject transactions from the future.
	// 	// let current_block = <system::Pallet<T>>::block_number();
	// 	// if &current_block < block_number {
	// 	// 	return InvalidTransaction::Future.into()
	// 	// }

	// 	// We prioritize transactions that are more far away from current average.
	// 	//
	// 	// Note this doesn't make much sense when building an actual oracle, but this example
	// 	// is here mostly to show off offchain workers capabilities, not about building an
	// 	// oracle.
	// 	// let avg_price = Self::average_price()
	// 	// 	.map(|price| if &price > new_price { price - new_price } else { new_price - price })
	// 	// 	.unwrap_or(0);

	// 	ValidTransaction::with_tag_prefix("etfnetwork")
	// 		// We set base priority to 2**20 and hope it's included before any other
	// 		// transactions in the pool. Next we tweak the priority depending on how much
	// 		// it differs from the current average. (the more it differs the more priority it
	// 		// has).
	// 		// .priority(T::UnsignedPriority::get().saturating_add(avg_price as _))
	// 		// This transaction does not require anything else to go before into the pool.
	// 		// In theory we could require `previous_unsigned_at` transaction to go first,
	// 		// but it's not necessary in our case.
	// 		//.and_requires()
	// 		// We set the `provides` tag to be the same as `next_unsigned_at`. This makes
	// 		// sure only one transaction produced after `next_unsigned_at` will ever
	// 		// get to the transaction pool and will end up in the block.
	// 		// We can still have multiple transactions compete for the same "spot",
	// 		// and the one with higher priority will replace other one in the pool.
	// 		.and_provides(index)
	// 		// The transaction is only valid for next 5 blocks. After that it's
	// 		// going to be revalidated by the pool.
	// 		.longevity(5)
	// 		// It's fine to propagate that transaction to other peers, which means it can be
	// 		// created even by nodes that don't produce blocks.
	// 		// Note that sometimes it's better to keep it for yourself (if you are the block
	// 		// producer), since for instance in some schemes others may copy your solution and
	// 		// claim a reward.
	// 		.propagate(true)
	// 		.build()
	// }

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

	pub fn refresh_keys(new_index: SessionIndex, authorities: Vec<T::AccountId>) {
		let (seed, _) = T::Randomness::random(new_index.to_string().as_bytes());
		// seed needs to be guaranteed to be 32 bytes.
		let seed = <[u8; 32]>::decode(&mut TrailingZeroInput::new(seed.as_ref()))
			.expect("input is padded with zeroes; qed");
		let mut rng = ChaCha20Rng::from_seed(seed);
		// add timestamp to seed?
		// we actually need the number of slots/session, not number of authorities
		// defined in aura config
		let n = authorities.len();
		// (n,n) TSS
		let t = n;
		let f = Self::keygen(t, &mut rng);
		let master_secret = f.clone().evaluate(&<Fr>::from(0));
		// Q: can i store this locally? offchain storage?
		let secret_shares = Self::calculate_shares(n as u8, f);		
		let encoded_secrets = secret_shares.iter().enumerate().map(|(i, s)| {
			let mut bytes: Vec<u8> = Vec::new();
			s.serialize_compressed(&mut bytes).unwrap();
			(i as u32, bytes)
		}).collect::<Vec<(u32, Vec<u8>)>>();

		// still having problems with group operations
		// let generator = G1Projective::rand(&mut rng).into_affine();
		// let p_pub = generator.mul(master_secret);
		// let mut mpk_bytes = Vec::new();
		// p_pub.serialize_compressed(&mut mpk_bytes.clone()).unwrap();

		// DRIEMWORKS::TODO: Require some type of proof that we verify when checking unsigned tx
		let call = Call::submit_session_artifacts { 
			session_index: new_index.clone(), 
			session_secrets: encoded_secrets.clone(),
		};
		// TODO: use signed tx
		SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into())
			.map_err(|()| "Unable to submit unsigned transaction.");
	}
}

impl<T: Config> pallet_session::SessionManager<T::AccountId> for Pallet<T> {
	// Plan a new session and provide new validator set.
	// TODO: deal with randomness freshness
	// https://github.com/paritytech/substrate/issues/8312
	fn new_session(new_index: u32) -> Option<Vec<T::AccountId>> {
		log::info!("Starting new session with index: {:?}", new_index);
		// check who gave keys
		CurrentSessionIndex::<T>::put(new_index);
		Some(Self::validators().into())
	}

	fn start_session(start_index: u32) {
		log::info!("Starting session with index: {:?}", start_index);
		ActiveSessionIndex::<T>::put(start_index);
	}

	fn end_session(end_index: u32) {
		log::info!("Ending session with index: {:?}", end_index);
		// trigger new keygen
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
