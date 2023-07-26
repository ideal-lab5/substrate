#![cfg_attr(not(feature = "std"), no_std)]

/// # EtF Pallet
///
/// The EtF pallet stores public parameters needed for the identity based encryption scheme
///
pub use pallet::*;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
pub mod weights;
pub use weights::*;
use frame_support::{
	pallet_prelude::*,
	sp_std::prelude::ToOwned,
	dispatch::Vec,
	traits::Randomness,
};
use sp_runtime::DispatchResult;

use ark_serialize::CanonicalDeserialize;

// pub(crate) use ark_scale::hazmat::ArkScaleProjective;
// const HOST_CALL: ark_scale::Usage = ark_scale::HOST_CALL;
// pub(crate) type ArkScale<T> = ark_scale::ArkScale<T, HOST_CALL>;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use sp_runtime::DispatchResult;
	use frame_system::pallet_prelude::*;

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
		/// Something that provides randomness in the runtime.
		type Randomness: Randomness<Self::Hash, Self::BlockNumber>;
	}

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
	pub struct GenesisConfig {
		// SCALE encoded?
		pub initial_ibe_params: Vec<u8>,
	}

	#[pallet::genesis_build]
	impl<T: Config> GenesisBuild<T> for GenesisConfig {
		fn build(&self) {
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
		#[pallet::weight(100_00)]
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

	/// attempt to deserialize the slice to an element of G1 
	/// and add it to storage if valid
	///
	/// `g`: A compressed and serialized element of G1
	///
	fn set_ibe_params(g: &Vec<u8>) -> DispatchResult {
		let _ = 
			ark_bls12_381::G1Affine::deserialize_compressed(&g[..])
			.map_err(|_| Error::<T>::G1DecodingFailure)?;
		// let _ = <ArkScale<Vec<ark_bls12_381::G1Affine>> as Decode>::
		// 	decode(&mut g.as_slice())
		// 	.map_err(|_| Error::<T>::G1DecodingFailure)?;
		IBEParams::<T>::set(g.to_owned());
		Ok(())
	}

	/// fetch the current ibe params
	pub fn ibe_params() -> Vec<u8> {
		IBEParams::<T>::get()
	}
}