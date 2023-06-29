// This file is part of TBD.

// Copyright (C) Ideal Labs, Ltd.
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
use codec::Encode;
/// The Aura inherent identifier.
pub const INHERENT_IDENTIFIER: InherentIdentifier = *b"etfslots";

/// the type of the inherent
pub type InherentType = [u8;32];

/// Provides the slot secret inherent data for `EtF`.
/// implements [`InherentDataProvider`]
#[cfg(feature = "std")]
pub struct InherentDataProvider(Option<InherentType>);

#[cfg(feature = "std")]
impl InherentDataProvider {
	/// Create a new instance with the given slot.
	// pub fn create(secret: InherentType) -> Result<InherentDataProvider, anyhow::Error> {
	pub fn create(secret: InherentType) -> InherentDataProvider {
		// Self { secret }
		// Ok(InherentDataProvider(Some(secret)))
		InherentDataProvider(Some(secret))
	}
}

#[cfg(feature = "std")]
#[async_trait::async_trait]
impl sp_inherents::InherentDataProvider for InherentDataProvider {
	async fn provide_inherent_data(
        &self, 
        inherent_data: &mut InherentData
    ) -> Result<(), Error> {
        if let Some(x) = &self.0 {
		    inherent_data.put_data(INHERENT_IDENTIFIER, &x)?;
        };
        Ok(())
	}

	async fn try_handle_error(
		&self,
		_: &InherentIdentifier,
		_: &[u8],
	) -> Option<Result<(), Error>> {
		None
	}
}

