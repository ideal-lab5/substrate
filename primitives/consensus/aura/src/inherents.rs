// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/// Contains the inherents for the AURA module
use sp_inherents::{Error, InherentData, InherentIdentifier};

/// The Aura inherent identifier.
pub const INHERENT_IDENTIFIER: InherentIdentifier = *b"auraslot";

/// The type of the Aura inherent.
pub type InherentType = sp_consensus_slots::Slot;
pub type SInherentType = u32;

pub type InherentTypeWrapper = (InherentType, SInherentType);

/// Auxiliary trait to extract Aura inherent data.
pub trait AuraInherentData {
	/// Get aura inherent data.
	fn aura_inherent_data(&self) -> Result<Option<InherentTypeWrapper>, Error>;
	/// Replace aura inherent data.
	fn aura_replace_inherent_data(&mut self, new: InherentTypeWrapper);
}

impl AuraInherentData for InherentData {
	fn aura_inherent_data(&self) -> Result<Option<InherentTypeWrapper>, Error> {
		self.get_data(&INHERENT_IDENTIFIER)
	}

	fn aura_replace_inherent_data(&mut self, new: InherentTypeWrapper) {
		self.replace_data(INHERENT_IDENTIFIER, &new);
	}
}

/// Provides the slot duration inherent data for `Aura`.
// TODO: Remove in the future. https://github.com/paritytech/substrate/issues/8029
#[cfg(feature = "std")]
pub struct InherentDataProvider {
	slot: InherentType,
	secret: SInherentType,
}

#[cfg(feature = "std")]
impl InherentDataProvider {
	/// Create a new instance with the given slot.
	pub fn new(slot: InherentType, secret: SInherentType) -> Self {
		Self { slot, secret }
	}

	/// Creates the inherent data provider by calculating the slot from the given
	/// `timestamp` and `duration`.
	pub fn from_timestamp_and_slot_duration(
		timestamp: sp_timestamp::Timestamp,
		slot_duration: sp_consensus_slots::SlotDuration,
	) -> Self {
		let slot = InherentType::from_timestamp(timestamp, slot_duration);

		Self { slot, secret: 1u32 }
	}

	/// returns the `secret` of this InherentDataProvider
	pub fn secret(&self) -> SInherentType {
		self.secret
	}
}

#[cfg(feature = "std")]
impl sp_std::ops::Deref for InherentDataProvider {
	type Target = InherentType;

	fn deref(&self) -> &Self::Target {
		&self.slot
	}
}

#[cfg(feature = "std")]
#[async_trait::async_trait]
impl sp_inherents::InherentDataProvider for InherentDataProvider {
	async fn provide_inherent_data(&self, inherent_data: &mut InherentData) -> Result<(), Error> {
		inherent_data.put_data(INHERENT_IDENTIFIER, &self.slot)
	}

	async fn try_handle_error(
		&self,
		_: &InherentIdentifier,
		_: &[u8],
	) -> Option<Result<(), Error>> {
		// There is no error anymore
		None
	}
}
