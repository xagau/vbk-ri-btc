#include <boost/test/unit_test.hpp>

#include <chainparams.h>
#include <consensus/merkle.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <validation.h>
#include <wallet/wallet.h>

#include <vbk/init.hpp>

struct IntegrationTextFixture : public TestChain100Setup {

    IntegrationTextFixture() : TestChain100Setup()
    {
        VeriBlock::Config& config = VeriBlock::getService<VeriBlock::Config>();
        config.bootstrap_bitcoin_blocks = {"000212B90002500640D2DCFDD047AF3F197C2BB743C05C2619919657462191847838E067A540836ABBE2C5AB1AA8DA98602D68C05DFB5C010405F5E1584D4024", "000212BA0002539544FC18F77FD997B080D52BB743C05C2619919657462191847838E067FF19E383F41F4B8A586142E47DB3B6225DFB5C080405F5E15876C544", "000212BB0002304FB9683DAFC9396A7F36492BB743C05C2619919657462191847838E067A87CF5F304B4E102B104320C5CBA33B85DFB5C500405F5E15A2670DE", "000212BC00025870BF9AD09BF0137D74551A2BB743C05C2619919657462191847838E06718A87B5E2923426270A6554112B0A7945DFB5C930405F5E1265B82D7", "000212BD000221C1F97385FB4F50D012571E2BB743C05C2619919657462191847838E067AAE01CA8E166338760880FC2C68466645DFB5CE60405F5E15DA9ACE9", "000212BE00025DB805D6B59D588982F60CF92BB743C05C2619919657462191847838E06703925057C5DC7A36080403CD446EF1B95DFB5E2F0405F5E1656929E3", "000212BF00024B0D40593576A382CD58DA5E2BB743C05C2619919657462191847838E0673C67D352F821E84195F9393C70A37BA15DFB5E7F0405F5E13425A20A", "000212C000022E28E85F3B565A9CE3A6D36F2BB743C05C2619919657462191847838E067B9321B6449970FB663B56210261D2AE75DFB5E800405F5E16742DE63", "000212C100022EABFB8FAF228721BA705F282BB743C05C2619919657462191847838E067C1D55AED879E3C2A39AD3DA4C72AA32C5DFB5EA10405F5E1351804AE", "000212C20002D918744D237CB620F05C04CB2BB743C05C2619919657462191847838E0673EFCD8817DD5C7DC3F71BCC71C992C1D5DFB5F0F0405F5E1382F2CCB", "000212C30002083EB27D9F62BE9FC7E178472BB743C05C2619919657462191847838E067AC554CC2C3E2942460A742093FA20F8D5DFB5F100405F5E138362725", "000212C4000282B9C1AF739155679954D27D2BB743C05C2619919657462191847838E067CEC2574589471F8635D3C85BC56803245DFB5F120405F5E13843B8A3", "000212C500028BD2113E1525CF7B7176DF782BB743C05C2619919657462191847838E0671B597D4BAE12B2A71CF670D6910608DF5DFB5F3C0405F5E139720FCD", "000212C600022E6EB382CD9D47641B43314C2BB743C05C2619919657462191847838E067073821D2D8891A8610B8C18897ED065A5DFB5F570405F5E16A8BEC2E", "000212C70002C1B622B7A4AB48CA23EAB9242BB743C05C2619919657462191847838E06731D8269A8DF296193B158E7059DA3E3C5DFB5FBF0405F5E16EC2628B"};
        config.bitcoin_first_block_height = 1610826;
        config.bootstrap_veriblock_blocks = {"000000204E2FE8861AF5135B650512F2197DA6F57EA4AE495959E2A3E5850000000000005C1C10A2A023B0375ABF924E0F04D36F1F645E5B906DEBCD59D1E9AAADA9029A0E56FB5DFFFF001B75696A5B", "000000208A55C72B18AF0884EBE94F035E3EF3F581C9BF2915F54EDBB3530000000000005BEF944BBC852CA367D9B771DC7060DBE373E78095758C03E0822B9EC0257579C056FB5DFFFF001B9E787E4A", "00000020615F9BFDF41FADEEC01BB69ED6A3B4751A1E6A3B3901554356E800000000000004E28DC3633A798A42113304FB3E23F2C34FB64BF16F85C96387D4336D1524A5FE57FB5DFFFF001BB06B5D3D", "00000020313C38FDA19B2DC29CD0B0C3A5D402B29DD99019573F7D03E049000000000000A27BB8E349594A307997AE3E27BB4B767E4FB61D5E6053DDDD12F41E67DA39E46058FB5DFFFF001BA234951F", "00000020AB142C1020A85F5F94A64FAF1073E10631BBA606F6895568C179000000000000B6DDC3FF20EF1AFD4070521270CCD9E9606CCCE4A21C1F4189F18A55A2496DB59258FB5DFFFF001B5114DFFD", "00000020F74C38CBF19627902641C66BEB42934DB826EEDDBE538D2B0AAF00000000000070551E97C33CE1B1E357984683606F0FBAAE1E79D350CFFA489A34CF0C8FA1DAF658FB5DFFFF001BD5A959BC", "00000020FDF387285B7C1444B37F5F4C68AEAE3C50D1B4E5989C123F2B2E000000000000026EBDB6D235AAC2E31EC757FFBF5A1B99CB7FFE9B8334EA618AA0BDA74806E43759FB5DFFFF001BACF5113C", "00000020862AA943B501E24F122BA508D444FDA9E6ED720D01C9C5FC254900000000000090BDE5548BEB2AAA1809A4CF667F72E6A1F82A221E58C7BF6E463E338BC64C74A959FB5DFFFF001B0957D25B", "000000207CE1E81B69DC90653C8652D7E897F66D7CF49C7D17AAF087A21E00000000000016D70855883C41BA77CA41BE3A30D3EC902132E317C29F2BFB298531DD54C09D6C5AFB5DFFFF001B36E17BC4", "0000002076FBC13AFFEABF306C9F00B7F046B3FC3257F6F4D9D96BE45E5600000000000011B793687891A9E218046C5A9DC5552F2DE86B4B6CFA6E70CC5F4F15F66FEEC6B25AFB5DFFFF001B1825B521", "00000020AA5B1689B9B745A265EF864C18E74E0615FD0ED4F919D2725A8E000000000000C5F543263E5D3A794FE3D4BE20CE131B134B32336FC2FBABDBE7E62F02A3F5A17A5BFB5DFFFF001BEDC8CF53", "000000200AD01BDE5BD4221A3CEF8A5DECB199B4B999D5157A48F20E9F1D000000000000E73841C91619662B365D690BD054F8A005C8DB2E22063872F91F3FD5E305AF05EB5BFB5DFFFF001B6BAA1754", "00000020BFA07C30A017FCEB97F0B738E4CCFB937809AFC370CDB93EECDC000000000000C0C55F28309FDB0F0EF745F9BA3118462529DFAE84B280578EBBF9F31E40DBC0C15EFB5DFFFF001BC597988F", "000000208791BB6E32BD11121C3BF13EBEF976C555CDC1D20C5CD60DCE56000000000000A4A861D7B9813C8BACB6C0C79BD6568C81DB4FEA90460375127BDDF2C425722BCD5EFB5DFFFF001B91F6168A", "000000206AB5E7E62B060B31171533EDFC60D473B2C4381768BAA5AD1D97000000000000EB6CCCE2E6FB36E7E75E0A0941691BF36053BD676A510C35CFFFB2A16A8621B56F5FFB5DFFFF001BB14CAEAD"};

        VeriBlock::InitPopService();
    }
};

BOOST_FIXTURE_TEST_SUITE(rpc_tests, IntegrationTextFixture)

BOOST_AUTO_TEST_CASE(getpopdata_test)
{
    NodeContext node;
    node.chain = interfaces::MakeChain(node);
    node.connman = std::unique_ptr<CConnman>(new CConnman(GetRand(std::numeric_limits<uint64_t>::max()), GetRand(std::numeric_limits<uint64_t>::max())));
    auto& chain = node.chain;
    VeriBlock::InitRpcService(node.connman.get());
    std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(chain.get(), WalletLocation(), WalletDatabase::CreateDummy());
    AddWallet(wallet);

    int blockHeight = 10;
    CBlockIndex* blockIndex = ChainActive()[blockHeight];
    CBlock block;

    BOOST_CHECK(ReadBlockFromDisk(block, blockIndex, Params().GetConsensus()));

    CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
    ssBlock << blockIndex->GetBlockHeader();

    uint256 txRoot = BlockMerkleRoot(block);
    auto keystones = VeriBlock::getService<VeriBlock::UtilService>().getKeystoneHashesForTheNextBlock(blockIndex->pprev);
    auto contextInfo = VeriBlock::ContextInfoContainer(blockIndex->nHeight, keystones, txRoot);
    auto authedContext = contextInfo.getAuthenticated();

    JSONRPCRequest request;
    request.strMethod = "getpopdata";
    request.params = UniValue(UniValue::VARR);
    request.fHelp = false;

    request.params.push_back(blockHeight);

    if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();

    UniValue result;
    BOOST_CHECK_NO_THROW(result = tableRPC.execute(request));

    BOOST_CHECK(find_value(result.get_obj(), "raw_contextinfocontainer").get_str() == HexStr(authedContext.begin(), authedContext.end()));
    BOOST_CHECK(find_value(result.get_obj(), "block_header").get_str() == HexStr(ssBlock));
    BOOST_CHECK(find_value(result.get_obj(), "last_known_veriblock_blocks").get_array().size() == 15); // number of bootsrap blocks that have been set up in .properties file
    BOOST_CHECK(find_value(result.get_obj(), "last_known_bitcoin_blocks").get_array().size() == 15); // number of bootsrap blocks that have been set up in .properties file
}

BOOST_AUTO_TEST_CASE(submitpop_test)
{   
    JSONRPCRequest request;
    request.strMethod = "submitpop";
    request.params = UniValue(UniValue::VARR);
    request.fHelp = false;
    
    std::vector<uint8_t> atv(100, 1);
    std::vector<uint8_t> vtb(100, 2);
    std::string vtb_str = "02046002011667FF0A897E5D512A0B6DA2F41C479867FE6B3A4CAE2640000013350002A793C872D6F6460E90BED62342BB968195F8C515D3EED7277A09EFAC4BE99F95F0A15628B06BA3B44C0190B5C0495C9B8ACD0701C5235EBBBE9C02011B01000000010CE74F1FB694A001EEBB1D7D08CE6208033F5BF7263EBAD2DE07BBF518672732000000006A47304402200CF4998ABA1682ABEB777E762807A9DD2635A0B77773F66491B83EE3C87099BA022033B7CA24DC520915B8B0200CBDCF95BA6AE866354585AF9C53EE86F27362EBEC012103E5BAF0709C395A82EF0BD63BC8847564AC201D69A8E6BF448D87AA53A1C431AAFFFFFFFF02B7270D00000000001976A9148B9EA8545059F3A922457AFD14DDF3855D8B109988AC0000000000000000536A4C50000013350002A793C872D6F6460E90BED62342BB968195F8C515D3EED7277A09EFAC4BE99F95F0A15628B06BA3B44C0190B5C0495C9B8ACD0701C5235EBBBE9CD4E943EFE1864DF04216615CF92083F40000000002019F040000067B040000000C040000000400000020204D66077FDF24246FFD6B6979DFEDEF5D46588654ADDEB35EDB11E993C131F61220023D1ABE8758C6F917EC0C65674BBD43D66EE14DC667B3117DFC44690C6F5AF120096DDBA03CA952AF133FB06307C24171E53BF50AB76F1EDEABDE5E99F78D4EAD202F32CF1BEE50349D56FC1943AF84F2D2ABDA520F64DC4DB37B2F3DB20B0ECB572093E70120F1B539D0C1495B368061129F30D35F9E436F32D69967AE86031A275620F554378A116E2142F9F6315A38B19BD8A1B2E6DC31201F2D37A058F03C39C06C200824705685CECA003C95140434EE9D8BBBF4474B83FD4ECC2766137DB9A44D7420B7B9E52F3EE8CE4FBB8BE7D6CF66D33A20293F806C69385136662A74453FB162201732C9A35E80D4796BABEA76AACE50B49F6079EA3E349F026B4491CFE720AD17202D9B57E92AB51FE28A587050FD82ABB30ABD699A5CE8B54E7CD49B2A827BCB9920DCBA229ACDC6B7F028BA756FD5ABBFEBD31B4227CD4137D728EC5EA56C457618202CF1439A6DBCC1A35E96574BDDBF2C5DB9174AF5AD0D278FE92E06E4AC349A42500000C020134F09D43659EB53982D9AFB444B96FA4BB58C037D2914000000000000000000CE0B1A9A77DD0DB127B5DF4BC368CD6AC299A9747D991EC2DACBC0B699A2E4A5B3919B5C6C1F2C1773703BC001035000008020FC61CC9D4EAC4B2D14761A4D06AF8A9EF073DCD7FB5E0D000000000000000000A31508D4B101D0AD11E43EF9419C23FC277F67EDAE83C598EE70866DBCEF5E25268B9B5C6C1F2C17E11874AF50000040203F8E3980304439D853C302F6E496285E110E251251531300000000000000000039A72C22268381BD8D9DCFE002F472634A24CF0454DE8B50F89E10891E5FFB1DE08D9B5C6C1F2C1744290A925000000020BAA42E40345A7F826A31D37DB1A5D64B67B72732477422000000000000000000A33AD6BE0634647B26633AB85FA8DE258480BBB25E59C68E48BB0B608B12362B10919B5C6C1F2C1749C4D1F0473045022100F4DCE45EDCC6BFC4A1F44EF04E47E90A348EFD471F742F18B882AC77A8D0E89E0220617CF7C4A22211991687B17126C1BB007A3B2A25C550F75D66B857A8FD9D75E7583056301006072A8648CE3D020106052B8104000A03420004B3C10470C8E8E426F1937758D9FB5E97A1891176CB37D4C12D4AF4107B1AA3E8A8A754C06A22760E44C60642FBA883967C19740D5231336326F7962750C8DF990400000000040000000D202A014E88ED7AB65CDFAA85DAEAB07EEA6CBA5E147F736EDD8D02C2F9DDF0DEC60400000006205B977EA09A554AD56957F662284044E7D37450DDADF7DB3647712F59693997872020D0A3D873EEEEE6A222A75316DCE60B53CA43EAEA09D27F0ECE897303A53AE920C06FE913DCA5DC2736563B80834D69E6DFDF1B1E92383EA62791E410421B6C1120049F68D350EEB8B3DF630C8308B5C8C2BA4CD6210868395B084AF84D19FF0E902000000000000000000000000000000000000000000000000000000000000000002036252DFC621DE420FB083AD9D8767CBA627EDDEEC64E421E9576CEE21297DD0A40000013700002449C60619294546AD825AF03B0935637860679DDD55EE4FD21082E18686EB53C1F4E259E6A0DF23721A0B3B4B7AB5C9B9211070211CAF01C3F010100";
    std::string atv_str = "01580101166772F51AB208D32771AB1506970EEB664462730B838E0203E800010701370100010C6865616465722062797465730112636F6E7465787420696E666F20627974657301117061796F757420696E666F2062797465734630440220398B74708DC8F8AEE68FCE0C47B8959E6FCE6354665DA3ED87A83F708E62AA6B02202E6C00C00487763C55E92C7B8E1DD538B7375D8DF2B2117E75ACBB9DB7DEB3C7583056301006072A8648CE3D020106052B8104000A03420004DE4EE8300C3CD99E913536CF53C4ADD179F048F8FE90E5ADF3ED19668DD1DBF6C2D8E692B1D36EAC7187950620A28838DA60A8C9DD60190C14C59B82CB90319E04000000010400000000201FEC8AA4983D69395010E4D18CD8B943749D5B4F575E88A375DEBDC5ED22531C040000000220000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000040000013880002449C60619294546AD825AF03B0935637860679DDD55EE4FD21082E18686E26BBFDA7D5E4462EF24AE02D67E47D785C9B90F301010000000000010100";

    UniValue vtbs_params(UniValue::VARR);
    vtbs_params.push_back(vtb_str);

    request.params.push_back(atv_str);
    request.params.push_back(vtbs_params);

    if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();

    UniValue result;
    BOOST_CHECK_NO_THROW(result = tableRPC.execute(request));

    uint256 popTxHash;
    popTxHash.SetHex(result.get_str());

    BOOST_CHECK(mempool.exists(popTxHash));
}

BOOST_AUTO_TEST_CASE(updatecontext_test)
{
    // This test have to be ran with the clear alt-integration service`s databases
    NodeContext node;
    node.chain = interfaces::MakeChain(node);
    node.connman = std::unique_ptr<CConnman>(new CConnman(GetRand(std::numeric_limits<uint64_t>::max()), GetRand(std::numeric_limits<uint64_t>::max())));
    auto& chain = node.chain;
    VeriBlock::InitRpcService(node.connman.get());
    std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(chain.get(), WalletLocation(), WalletDatabase::CreateDummy());
    AddWallet(wallet);

    int blockHeight = 10;

    JSONRPCRequest request;
    request.strMethod = "getpopdata";
    request.params = UniValue(UniValue::VARR);
    request.fHelp = false;

    request.params.push_back(blockHeight);

    if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();

    UniValue result;
    BOOST_CHECK_NO_THROW(result = tableRPC.execute(request));

    BOOST_CHECK(find_value(result.get_obj(), "last_known_veriblock_blocks").get_array().size() == 15); // number of bootsrap blocks that have been set up in .properties file
    BOOST_CHECK(find_value(result.get_obj(), "last_known_bitcoin_blocks").get_array().size() == 15); // number of bootsrap blocks that have been set up in .properties file


    request.strMethod = "updatecontext";
    request.params = UniValue(UniValue::VARR);
    request.fHelp = false;

    // These values was taken from the alt-integration service default properties file and also was removed from that file
    UniValue veriblock_blocks(UniValue::VARR);
    veriblock_blocks.push_back("000212C80002129B6280D651E9FC3D46799D2BB743C05C2619919657462191847838E067718CC361844278EAB1BD9E1FB387D0F45DFB5FC70405F5E16DAF3C66");

    UniValue bitcoin_blocks(UniValue::VARR);
    bitcoin_blocks.push_back("00000020E2EEC323DA41F7F3387E8E4F1BF313EDFD2247788CBA378900040000000000002878DE94F86A20B384C0B0FC6BAAD61EBB0DCDC7126684072CCAD3EE624905060F60FB5DFFFF001B2CBAA52B");

    request.params.push_back(bitcoin_blocks);
    request.params.push_back(veriblock_blocks);

    if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();

    BOOST_CHECK_NO_THROW(result = tableRPC.execute(request));

    BOOST_CHECK(result.get_str() == "Bitcoin and VeriBlock bloks were added");

    request.strMethod = "getpopdata";
    request.params = UniValue(UniValue::VARR);
    request.fHelp = false;

    request.params.push_back(blockHeight);

    if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();

    BOOST_CHECK_NO_THROW(result = tableRPC.execute(request));

    BOOST_CHECK(find_value(result.get_obj(), "last_known_veriblock_blocks").get_array().size() == 16); // number of bustrap blocks that have been set up in .properties file
    BOOST_CHECK(find_value(result.get_obj(), "last_known_bitcoin_blocks").get_array().size() == 16); // number of bustrap blocks that have been set up in .properties file
}
BOOST_AUTO_TEST_SUITE_END()