//! Benchmarking setup for pallet-etf
#![cfg(feature = "runtime-benchmarks")]
use super::*;

#[allow(unused)]
use crate::Pallet as Etf;
use frame_benchmarking::v2::*;
use frame_system::RawOrigin;

#[benchmarks]
mod benchmarks {
	use super::*;

	#[benchmark]
	fn update_ibe_params() {
		let bytes = array_bytes::hex2bytes_unchecked("a191b705ef18a6e4e5bd4cc56de0b8f94b1f3c908f3e3fcbd4d1dc12eb85059be7e7d801edc1856c8cfbe6d63a681c1f");
		#[extrinsic_call]
		update_ibe_params(RawOrigin::Root, bytes.clone());
		assert_eq!(IBEParams::<T>::get(), bytes);
	}

	impl_benchmark_test_suite!(
        Etf, crate::mock::new_test_ext(&"a191b705ef18a6e4e5bd4cc56de0b8f94b1f3c908f3e3fcbd4d1dc12eb85059be7e7d801edc1856c8cfbe6d63a681c1f"), 
        crate::mock::Test);
}
