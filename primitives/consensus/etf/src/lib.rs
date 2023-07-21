#![cfg_attr(not(feature = "std"), no_std)]

sp_api::decl_runtime_apis! {
	/// API necessary for block authorship with aura.
	pub trait EtfApi {
		/// return the identity for the slot
		fn identity(slot: sp_consensus_slots::Slot) -> sp_std::vec::Vec<u8>;
	}
}
