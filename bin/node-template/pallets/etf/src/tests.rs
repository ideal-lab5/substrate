use crate::{mock::*, Error, Event};
use ark_std::{rand::Rng, test_rng, UniformRand};
use ark_serialize::CanonicalSerialize;
use frame_support::{assert_noop, assert_ok};

#[test]
fn it_sets_the_genesis_state() {
    let validators = vec![1, 2, 3];

	let mut rng = test_rng();
	let g = ark_bls12_381::G1Affine::rand(&mut rng);
	let mut g_bytes = Vec::new();
	g.serialize_compressed(&mut g_bytes).unwrap();
	let hex = hex::encode(&g_bytes);

	new_test_ext(validators.clone(), &hex.clone()).execute_with(|| {
        assert!(Etf::validators() == validators);
		let ibe_params = Etf::ibe_params();
        assert!(ibe_params.len() == 48);
	});
}

// #[test]
// fn correct_error_for_none_value() {
// 	new_test_ext().execute_with(|| {
// 		// Ensure the expected error is thrown when no value is present.
// 		assert_noop!(
// 			TemplateModule::cause_error(RuntimeOrigin::signed(1)),
// 			Error::<Test>::NoneValue
// 		);
// 	});
// }
