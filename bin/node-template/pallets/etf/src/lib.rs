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
pub use weights::WeightInfo;
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

	/// dleq param (generator) (G1), p (G2), p_pub (G2)
	#[pallet::storage]
	pub type IBEParams<T: Config> = StorageValue<
		_, (Vec<u8>, Vec<u8>, Vec<u8>), ValueQuery,
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
		G2DecodingFailure,
	}

	#[pallet::genesis_config]
	#[derive(frame_support::DefaultNoBound)]
	pub struct GenesisConfig {
		// SCALE encoded?
		pub initial_ibe_params: Vec<u8>,
		pub initial_ibe_pp: Vec<u8>,
		pub initial_ibe_commitment: Vec<u8>, 
	}

	#[pallet::genesis_build]
	impl<T: Config> GenesisBuild<T> for GenesisConfig {
		fn build(&self) {
			Pallet::<T>::set_ibe_params(
				&self.initial_ibe_params, &self.initial_ibe_pp, &self.initial_ibe_commitment)
				.expect("The input should be a valid generator of G1; qed");
		}
	}
 
	#[pallet::call]
	impl<T: Config> Pallet<T> {

		/// update the public parameters needed for the IBE scheme
		///
		/// * `g`: A generator of G1
		///
		#[pallet::weight(T::WeightInfo::update_ibe_params())]
		#[pallet::call_index(1)]
		pub fn update_ibe_params(
			origin: OriginFor<T>,
			g: Vec<u8>,
			ibe_pp_bytes: Vec<u8>,
			ibe_commitment_bytes: Vec<u8>,
		) -> DispatchResult {
			ensure_root(origin)?;
			Self::set_ibe_params(&g, &ibe_pp_bytes, &ibe_commitment_bytes)?;
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
	/// TODO: should also provide a DLEQ proof and verify it here
	fn set_ibe_params(g: &Vec<u8>, ibe_pp_bytes: &Vec<u8>, ibe_commitment_bytes: &Vec<u8>) -> DispatchResult {
		let _ = 
			ark_bls12_381::G1Affine::deserialize_compressed(&g[..])
			.map_err(|_| Error::<T>::G1DecodingFailure)?;
		let _ = 
			ark_bls12_381::G2Affine::deserialize_compressed(&ibe_pp_bytes[..])
			.map_err(|_| Error::<T>::G2DecodingFailure)?;
		let _ = 
			ark_bls12_381::G2Affine::deserialize_compressed(&ibe_commitment_bytes[..])
			.map_err(|_| Error::<T>::G2DecodingFailure)?;
		// let _ = <ArkScale<Vec<ark_bls12_381::G1Affine>> as Decode>::
		// 	decode(&mut g.as_slice())
		// 	.map_err(|_| Error::<T>::G1DecodingFailure)?;
		IBEParams::<T>::set((g.to_owned(), ibe_pp_bytes.to_owned(), ibe_commitment_bytes.to_owned()));
		Ok(())
	}

	/// fetch the current ibe params
	pub fn ibe_params() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
		IBEParams::<T>::get()
	}
}