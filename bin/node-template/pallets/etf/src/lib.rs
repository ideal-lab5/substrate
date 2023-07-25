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
use codec::{Encode, Decode};
use frame_system::offchain::{SendSignedTransaction, Signer, SubmitTransaction};
use frame_support::{
	pallet_prelude::*,
	sp_std::prelude::ToOwned,
	dispatch::Vec, BoundedSlice,
	traits::{
		Randomness,
		ValidatorRegistration, ValidatorSet, ValidatorSetWithIdentification,
	},
};
use sp_runtime::{
	KeyTypeId, DispatchResult,
	traits::{Convert, TrailingZeroInput},
	transaction_validity::{InvalidTransaction, TransactionValidity, ValidTransaction},
	offchain::storage::StorageRetrievalError,
};

pub(crate) use ark_scale::hazmat::ArkScaleProjective;
const HOST_CALL: ark_scale::Usage = ark_scale::HOST_CALL;
pub(crate) type ArkScale<T> = ark_scale::ArkScale<T, HOST_CALL>;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use sp_runtime::DispatchResult;
	use frame_system::pallet_prelude::*; 	
	use primitive_types::H256;
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
	pub trait Config: frame_system::Config {
		/// Because this pallet emits events, it depends on the runtime's definition of an event.
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		/// Type representing the weight of this pallet
		type WeightInfo: WeightInfo;
		/// the maximum number of validators
		type MaxAuthorities: Get<u32>;
		/// Something that provides randomness in the runtime.
		type Randomness: Randomness<Self::Hash, Self::BlockNumber>;
	}

	/// The validator set
	/// currently static as defined on genesis but can be made dynamic
	#[pallet::storage]
	#[pallet::getter(fn validators)]
	pub type Validators<T: Config> = StorageValue<
		_, BoundedVec<T::AccountId, T::MaxAuthorities>, ValueQuery,
	>;

	/// public params for ibe
	#[pallet::storage]
	pub type IBEParams<T: Config> = StorageValue<
		_, Vec<u8>, ValueQuery,
	>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// the public ibe params were updated successfully
		IBEParamsUpdated,
	}

	// Errors inform users that something went wrong.
	#[pallet::error]
	pub enum Error<T> {
		/// the vector could not be decoded to an element of G1
		G1DecodingFailure,
	}

	#[pallet::genesis_config]
	#[derive(frame_support::DefaultNoBound)]
	pub struct GenesisConfig<T: Config> {
		pub initial_validators: Vec<T::AccountId>,
		pub initial_ibe_params: Vec<u8>,
	}

	#[pallet::genesis_build]
	impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
		fn build(&self) {
			Pallet::<T>::initialize_validators(&self.initial_validators);
			Pallet::<T>::set_ibe_params(&self.initial_ibe_params)
				.expect("The input should be a valid generator of G1; qed");
		}
	}
 
	#[pallet::call]
	impl<T: Config> Pallet<T> {

		/// update the public parameters needed for the IBE scheme
		///
		/// * `g`: A hex-encoded generator of G1
		///
		#[pallet::weight(0)]
		pub fn update_ibe_params(
			origin: OriginFor<T>,
			g: Vec<u8>,
		) -> DispatchResult {
			ensure_root(origin)?;
			Self::set_ibe_params(&g)?;
			Self::deposit_event(Event::IBEParamsUpdated);
			Ok(())
		}
	}
}

impl<T: Config> Pallet<T> {

	/// initialize the validator set
	fn initialize_validators(validators: &[T::AccountId]) {
		log::info!("Initializing validators defined in the chain spec.");
		assert!(validators.len() > 0, "At least 1 validator should be initialized");
		assert!(<Validators<T>>::get().is_empty(), "Validators are already initialized!");
		let bounded = <BoundedSlice<'_, _, T::MaxAuthorities>>::try_from(validators)
				.expect("Initial authority set must be less than T::MaxAuthorities");
		<Validators<T>>::put(bounded);
	}

	/// attempt to deserialize the slice to an element of G1 
	/// and add it to storage if valid
	///
	/// `g`: A compressed and serialized point in G1
	///
	fn set_ibe_params(g: &Vec<u8>) -> DispatchResult {
		// check if the input can be decoded as G1
		log::info!("g is {:?} long", g.len());
		let _ = <ArkScale<Vec<ark_bls12_381::G1Affine>> as Decode>::
			decode(&mut g.as_slice())
			.map_err(|e| {
				log::info!("This is the error that we see: {:?}", e);
				return Error::<T>::G1DecodingFailure;
			})?;
		IBEParams::<T>::set(g.to_owned());
		Ok(())
	}

	/// fetch the current ibe params
	pub fn ibe_params() -> Vec<u8> {
		IBEParams::<T>::get()
	}
}