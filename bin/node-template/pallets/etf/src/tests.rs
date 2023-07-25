use crate::{mock::*, Error, Event};
use ark_std::{rand::Rng, test_rng, UniformRand};
use ark_serialize::CanonicalSerialize;
use frame_support::{assert_noop, assert_ok};

#[test]
fn it_sets_the_genesis_state() {

	let mut rng = test_rng();
	let g = ark_bls12_381::G1Affine::rand(&mut rng);
	let mut g_bytes = Vec::new();
	g.serialize_compressed(&mut g_bytes).unwrap();
	let hex = hex::encode(&g_bytes);

	new_test_ext(&hex.clone()).execute_with(|| {
		let ibe_params = Etf::ibe_params();
        assert!(ibe_params.len() == 48);
	});
}

#[test]
fn it_allows_root_to_update_generator() {
	let mut rng = test_rng();
	
	let g = ark_bls12_381::G1Affine::rand(&mut rng);
	let mut g_bytes = Vec::new();
	g.serialize_compressed(&mut g_bytes).unwrap();
	let hex = hex::encode(&g_bytes);

	new_test_ext(&hex.clone()).execute_with(|| {
		
		let h = ark_bls12_381::G1Affine::rand(&mut rng);
		let mut h_bytes = Vec::new();
		h.serialize_compressed(&mut h_bytes).unwrap();

		assert_ok!(
			Etf::update_ibe_params(
				RuntimeOrigin::root(),
				h_bytes,
			)
		);

	});
}

#[test]
fn it_fails_to_update_generator_when_not_decodable() {
	let mut rng = test_rng();
	
	let g = ark_bls12_381::G1Affine::rand(&mut rng);
	let mut g_bytes = Vec::new();
	g.serialize_compressed(&mut g_bytes).unwrap();
	let hex = hex::encode(&g_bytes);

	new_test_ext(&hex.clone()).execute_with(|| {
		
		let mut h_bytes = Vec::new();
		h_bytes.push(1);

		assert_noop!(
			Etf::update_ibe_params(
				RuntimeOrigin::root(),
				h_bytes,
			),
			Error::<Test>::G1DecodingFailure,
		);

	});
}
