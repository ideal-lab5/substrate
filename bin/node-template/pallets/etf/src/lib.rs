#![cfg_attr(not(feature = "std"), no_std)]

/// Edit this file to define custom logic or remove it if it is not needed.
/// Learn more about FRAME and the core library of Substrate FRAME pallets:
/// <https://docs.substrate.io/reference/frame-pallets/>
pub use pallet::*;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
pub mod weights;
pub use weights::*;
use sp_staking::SessionIndex;
use codec::{Encode, Decode};
use frame_support::{
	dispatch::Vec, BoundedSlice,
	traits::{
		Randomness,
		ValidatorRegistration, ValidatorSet, ValidatorSetWithIdentification,
	},
};
use sp_runtime::traits::{Convert, TrailingZeroInput};
use rand_chacha::{
	rand_core::{RngCore, SeedableRng},
	ChaCha20Rng,
};
use ark_ec::{
    AffineRepr, CurveGroup,
    pairing::Pairing,
};
use ark_ff::UniformRand;
use ark_poly::{
    polynomial::univariate::DensePolynomial,
    DenseUVPolynomial, Polynomial,
};
use ark_std::{
	vec,
	string::ToString,
    ops::Mul,
    rand::Rng,
    Zero,
};
use sp_ark_ec_utils::{

};
// use sp_ark_models::Group;
use sp_ark_bls12_381::{
	ArkScale,
    Bls12_381, 
	Fr,
    G1Projective as G1, G2Affine, 
    G2Projective as G2
};

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*; 	
	use primitive_types::H256;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	/// Configure the pallet by specifying the parameters and types on which it depends.
	#[pallet::config]
	pub trait Config: frame_system::Config + pallet_session::Config {
		/// Because this pallet emits events, it depends on the runtime's definition of an event.
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		/// Type representing the weight of this pallet
		type WeightInfo: WeightInfo;
		/// the maximum number of validators
		type MaxAuthorities: Get<u32>;
		/// Something that provides randomness in the runtime.
		type Randomness: Randomness<Self::Hash, Self::BlockNumber>;
	}

	#[pallet::storage]
	#[pallet::getter(fn validators)]
	pub type Validators<T: Config> = StorageValue<
		_, BoundedVec<T::AccountId, T::MaxAuthorities>, ValueQuery,
	>;

	/// map block num to secret
	#[pallet::storage]
	pub type SlotSecrets<T: Config> = StorageMap<
		_,
		Blake2_128,
		T::BlockNumber,
		u32,
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
			let secret: u32 =
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
 

	// Dispatchable functions allows users to interact with the pallet and invoke state changes.
	// These functions materialize as "extrinsics", which are often compared to transactions.
	// Dispatchable functions must be annotated with a weight and must return a DispatchResult.
	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// An example dispatchable that takes a singles value as a parameter, writes the value to
		/// storage and emits an event. This function must be dispatched by a signed extrinsic.
		#[pallet::call_index(0)]
		#[pallet::weight(0)]
		pub fn reveal_slot_secret(
			origin: OriginFor<T>,
			secret: u32,
		) -> DispatchResult {
			ensure_none(origin)?;
			let current_block = frame_system::Pallet::<T>::block_number();
			SlotSecrets::<T>::insert(current_block, secret);
			Ok(())
		}

		#[pallet::call_index(1)]
		#[pallet::weight(0)]
		pub fn submit_session_artifacts(
			origin: OriginFor<T>,
			session_index: SessionIndex,
			session_pubkey: Vec<u8>,
			secrets: Vec<(u32, Vec<u8>)>,
		) -> DispatchResult {
			ensure_root(origin)?;
			// let current_block = frame_system::Pallet::<T>::block_number();
			// SlotSecrets::<T>::insert(current_block, secret);
			Ok(())
		}

		#[pallet::call_index(2)]
		#[pallet::weight(0)]
		pub fn submit_session_pk(
			origin: OriginFor<T>,
			session_index: SessionIndex,
			pk: [u8;32],
		) -> DispatchResult {
			ensure_root(origin)?;
			// let current_block = frame_system::Pallet::<T>::block_number();
			// SlotSecrets::<T>::insert(current_block, secret);
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

	/// generate a new random polynomial over the field Fr
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

	pub fn generate_msm_args<Group: ark_ec::VariableBaseMSM>(
		size: u32,
	) -> (ArkScale<Vec<Group>>, ArkScale<Vec<Group::ScalarField>>) {
		let (seed, _) = T::Randomness::random(b"test");
		// seed needs to be guaranteed to be 32 bytes.
		let seed = <[u8; 32]>::decode(&mut TrailingZeroInput::new(seed.as_ref()))
			.expect("input is padded with zeroes; qed");
		let rng = &mut ChaCha20Rng::from_seed(seed);
		let scalars = (0..size).map(|_| Group::ScalarField::rand(rng)).collect::<Vec<_>>();
		let bases = (0..size).map(|_| Group::rand(rng)).collect::<Vec<_>>();
		let bases: ArkScale<Vec<Group>> = bases.into();
		let scalars: ArkScale<Vec<Group::ScalarField>> = scalars.into();
		(bases, scalars)
	}
}

impl<T: Config> pallet_session::SessionManager<T::AccountId> for Pallet<T> {
	// Plan a new session and provide new validator set.
	fn new_session(new_index: u32) -> Option<Vec<T::AccountId>> {
		log::info!("Starting new session with index: {:?}", new_index);
		let binding = Self::validators();
		// calculate a secret polynomial f(x)
		// for now, requires 100% participation for decryption
		// make this a configurable parameter later on
		let t = binding.len();
				// we'll need a random seed here.
		// TODO: deal with randomness freshness
		// https://github.com/paritytech/substrate/issues/8312
		let (seed, _) = T::Randomness::random(new_index.to_string().as_bytes());
		// seed needs to be guaranteed to be 32 bytes.
		let seed = <[u8; 32]>::decode(&mut TrailingZeroInput::new(seed.as_ref()))
			.expect("input is padded with zeroes; qed");
		let mut rng = ChaCha20Rng::from_seed(seed);
		let f = Self::keygen(t, rng);
		// calculate shares f(1), ..., f(n) and session pubkey P_pub
		let msk = f.clone().evaluate(&<Fr>::from(0));
		// let mpk: G2 = G2::generator().mul(msk);

		// let scalars = <ArkScale<
		// 	Vec<<ark_bls12_381::Bls12_381 as Pairing>::ScalarField>,
		// > as Decode>::decode(&mut scalars.as_slice())
		// .unwrap().0;
		// let _ = crate::bls12_381::do_msm_g2_optimized(&bases[..], &scalars[..]);

		// let _base: ArkScale<sp_ark_models::short_weierstrass::Projective<sp_bls12_381::g2::Config>> = G2<T>::generator().into();
		// let _base: ArkScale<G2<T>> = G2<T>::generator().into();
		// let _scalar: ArkScale<Group::ScalarField> = msk.into();

		let session_secrets = Self::calculate_shares(t as u8, f);
		let scalar_msk: ArkScale<Vec<
		ark_ec::short_weierstrass::Projective<sp_ark_bls12_381::g2::Config>
		>> = session_secrets.into();
		// encode (mpk, {i -> secret_i}; i = 1,...,n)

		// call extrinsic with (spk, secret_shares)

		let authorities = binding.as_slice();
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
