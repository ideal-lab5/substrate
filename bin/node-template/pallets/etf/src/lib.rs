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
	pub trait Config: frame_system::Config {
		/// Because this pallet emits events, it depends on the runtime's definition of an event.
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		/// Type representing the weight of this pallet
		type WeightInfo: WeightInfo;
	}

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
		) -> result::Result<(), Self::Error> {
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
	}
}
