use crate as pallet_etf;
use frame_support::traits::{
    ConstU16, ConstU64,
    GenesisBuild,
};
use sp_core::H256;
use sp_runtime::{
	testing::Header,
	traits::{BlakeTwo256, IdentityLookup},
};
use frame_support_test::TestRandomness;

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;

// Configure a mock runtime to test the pallet.
frame_support::construct_runtime!(
	pub enum Test where
		Block = Block,
		NodeBlock = Block,
		UncheckedExtrinsic = UncheckedExtrinsic,
	{
		System: frame_system,
		Etf: pallet_etf,
	}
);

impl frame_system::Config for Test {
	type BaseCallFilter = frame_support::traits::Everything;
	type BlockWeights = ();
	type BlockLength = ();
	type DbWeight = ();
	type RuntimeOrigin = RuntimeOrigin;
	type RuntimeCall = RuntimeCall;
	type Index = u64;
	type BlockNumber = u64;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountId = u64;
	type Lookup = IdentityLookup<Self::AccountId>;
	type Header = Header;
	type RuntimeEvent = RuntimeEvent;
	type BlockHashCount = ConstU64<250>;
	type Version = ();
	type PalletInfo = PalletInfo;
	type AccountData = ();
	type OnNewAccount = ();
	type OnKilledAccount = ();
	type SystemWeightInfo = ();
	type SS58Prefix = ConstU16<42>;
	type OnSetCode = ();
	type MaxConsumers = frame_support::traits::ConstU32<16>;
}

impl pallet_etf::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type WeightInfo = pallet_etf::weights::SubstrateWeightInfo<Test>;
    type Randomness = TestRandomness<Self>;
}

// Build genesis storage according to the mock runtime.
pub fn new_test_ext(
    g1_hex: &str,
	g2_hex: &str,
) -> sp_io::TestExternalities {

	let mut t = frame_system::GenesisConfig::default().build_storage::<Test>().unwrap();
    let ibe_g1: Vec<u8> = array_bytes::hex2bytes_unchecked(g1_hex);
	let ibe_g2: Vec<u8> = array_bytes::hex2bytes_unchecked(g2_hex);

    GenesisBuild::<Test>::assimilate_storage(
        &pallet_etf::GenesisConfig {
            initial_ibe_params: ibe_g1.clone(),
			initial_ibe_pp: ibe_g2.clone(),
			initial_ibe_commitment: ibe_g2.clone(),
        },
        &mut t,
    ).unwrap();
    

    t.into()
}
