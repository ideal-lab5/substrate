use jsonrpsee::{
	core::{async_trait, RpcResult},
	proc_macros::rpc,
	types::error::{CallError, ErrorObject},
};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_runtime::{
	generic::BlockId,
	traits::{Block as BlockT, MaybeDisplay},
};
use std::sync::Arc;
use codec::Codec;
use sp_core::Bytes;
pub use sp_consensus_etf::EtfApi as EtfRuntimeApi;

type ResponseType = Vec<u8>;

#[rpc(client, server)]
pub trait EtfApi<BlockHash> {

	#[method(name = "etf_slot_identity")]
	fn identity(
		&self,
		slot: sp_consensus_slots::Slot,
		at: Option<BlockHash>,
	) -> RpcResult<ResponseType>;
}

/// A struct that implements EtfApi
pub struct Etf<C, P> {
	client: Arc<C>,
	_marker: std::marker::PhantomData<P>,
}

impl<C, P> Etf<C, P> {
	/// create new 'Encrypt' instance with the given reference to the client
	pub fn new(client: Arc<C>) -> Self {
		Self { client, _marker: Default::default() }
	}
}

/// Errors encountered by the RPC
pub enum Error {
	/// the call to runtime failed
	RuntimeError,
}

impl From<Error> for i32 {
	fn from(e: Error) -> i32 {
		match e {
			Error::RuntimeError => 1,
		}
	}
}

#[async_trait]
impl<C, Block> 
	EtfApiServer<<Block as BlockT>::Hash> for Etf<C, Block>
where 
	Block: BlockT,
	C: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
	C::Api: EtfRuntimeApi<Block>,
{

	fn identity(
		&self,
		slot: sp_consensus_slots::Slot,
		at: Option<<Block as BlockT>::Hash>
	) -> RpcResult<ResponseType> {
		let api = self.client.runtime_api();
		// let at = BlockId::hash(at.unwrap_or_else(||
		// 	self.client.info().best_hash
		// ));
        let at_hash = at.unwrap_or_else(|| self.client.info().best_hash);

		api.identity(at_hash, slot)
			.map_err(|e| {
				CallError::Custom(ErrorObject::owned(
					Error::RuntimeError.into(),
					"Unable to calculate a slot identity.",
					Some(e.to_string())
				)
			).into()
		})
	}
}