#include <boost/test/unit_test.hpp>

#include "vbk/genesis.hpp"
#include "vbk/init.hpp"
#include <chainparams.h>
#include <consensus/validation.h>
#include <validation.h>

BOOST_AUTO_TEST_SUITE(VBK_GenesisBlock)

struct GenesisBlockFixture {
    GenesisBlockFixture()
    {
        VeriBlock::InitConfig();
        VeriBlock::InitUtilService();
    }

    static void init(const std::string& name)
    {
        SelectParams(name);
    }

    static void check(const std::string& name)
    {
        init(name);
        auto& params = Params();
        const CBlock& block = params.GenesisBlock();
        BlockValidationState state;
        bool result = CheckBlock(block, state, params.GetConsensus(), true);
        BOOST_CHECK(result);
        if (!result) {
            printf("State: %s\n", state.GetDebugMessage().c_str());
        }
    }
    std::string initialPubkey = "047c62bbf7f5aa4dd5c16bad99ac621b857fac4e93de86e45f5ada73404eeb44dedcf377b03c14a24e9d51605d9dd2d8ddaef58760d9c4bb82d9c8f06d96e79488";
    std::string pszTimestamp = "VeriBlock";
};

BOOST_FIXTURE_TEST_CASE(main, GenesisBlockFixture)
{
//        // Do the actual block mining
//        {
//            init("main");
//
//            CBlock block = VeriBlock::MineGenesisBlock(
//                1337,
//                pszTimestamp,
//                initialPubkey,
//                0x1d00ffff,
//                1,
//                0,
//                50 * COIN);
//
//            printf("%s\n", block.ToString().c_str());
//        }

    check("main");
}

BOOST_FIXTURE_TEST_CASE(test, GenesisBlockFixture)
{
    //    // Do the actual block mining
    //    {
    //        init("test");
    //
    //        CBlock block = VeriBlock::MineGenesisBlock(
    //            1337,
    //            pszTimestamp,
    //            initialPubkey,
    //            0x1d0fffff, // 30 sec on macbook pro 2013
    //            1,
    //            0,
    //            50 * COIN);
    //
    //        printf("%s\n", block.ToString().c_str());
    //    }

    check("test");
}

BOOST_FIXTURE_TEST_CASE(regtest, GenesisBlockFixture)
{
    //    // Do the actual block mining
    //    {
    //        init("regtest");
    //
    //        CBlock block = VeriBlock::MineGenesisBlock(
    //            1337,
    //            pszTimestamp,
    //            initialPubkey,
    //            0x207fffff,
    //            1, // version
    //            0, // starting nonce
    //            50 * COIN);
    //
    //        printf("BLOCK:\n%s\n", block.ToString().c_str());
    //    }

    check("regtest");
}


BOOST_AUTO_TEST_SUITE_END()
