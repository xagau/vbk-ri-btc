#ifndef BITCOIN_SRC_VBK_POP_SERVICE_POP_SERVICE_IMPL_HPP
#define BITCOIN_SRC_VBK_POP_SERVICE_POP_SERVICE_IMPL_HPP

#include <vbk/entity/pop.hpp>
#include <vbk/pop_service.hpp>
#include <vbk/pop_service/pop_service_exception.hpp>
#include <veriblock/popmanager.hpp>
#include <veriblock/state_manager.hpp>
#include <veriblock/storage/endorsement_repository_inmem.hpp>
#include <veriblock/storage/repository_rocks_manager.hpp>

#include <memory>
#include <vector>

#include <chainparams.h>

#include <sync.h>

namespace VeriBlock {

class PopServiceImpl : public PopService
{
private:
    std::mutex mutex;
    std::shared_ptr<AltChainParams> alt_param = std::make_shared<VeriBlock::AltChainParams>();
    std::shared_ptr<VeriBlock::BtcChainParams> btc_param = std::make_shared<VeriBlock::BtcChainParamsTest>();
    std::shared_ptr<VeriBlock::VbkChainParams> vbk_param = std::make_shared<VeriBlock::VbkChainParamsTest>();
    std::shared_ptr<VeriBlock::EndorsementRepository<BtcEndorsement>> btc_e_repo = std::make_shared<VeriBlock::EndorsementRepositoryInmem<BtcEndorsement>>();
    std::shared_ptr<VeriBlock::EndorsementRepository<VbkEndorsement>> vbk_e_repo = std::make_shared<VeriBlock::EndorsementRepositoryInmem<VbkEndorsement>>();
    VeriBlock::PopManager pop;
    VeriBlock::StateManager<RepositoryRocksManager> stateManager;

public:
    VeriBlock::PopManager& getPopManager()
    {
        return pop;
    }

    VeriBlock::StateManager<RepositoryRocksManager>& getStateManager()
    {
        return stateManager;
    }

    // FIXME: have to make it public so that it could be accessed in mocks
    // the index of the last temporary payloads applied to the alt-integration blockchain view
    uint32_t temporaryPayloadsIndex;

    PopServiceImpl(bool doinit = true);

    ~PopServiceImpl() override = default;

    bool addTemporaryPayloads(const CTransactionRef& tx, const CBlockIndex& pindexPrev, const Consensus::Params& params, TxValidationState& state) override;
    void clearTemporaryPayloads() override;

    std::vector<BlockBytes> getLastKnownVBKBlocks(size_t blocks) override;
    std::vector<BlockBytes> getLastKnownBTCBlocks(size_t blocks) override;

    bool checkVTBinternally(const std::vector<uint8_t>& bytes) override;
    bool checkATVinternally(const std::vector<uint8_t>& bytes) override;

    int compareTwoBranches(const CBlockIndex* commonKeystone, const CBlockIndex* leftForkTip, const CBlockIndex* rightForkTip) override;

    void rewardsCalculateOutputs(const int& blockHeight, const CBlockIndex& endorsedBlock, const CBlockIndex& contaningBlocksTip, const CBlockIndex* difficulty_start_interval, const CBlockIndex* difficulty_end_interval, std::map<CScript, int64_t>& outputs) override;

    bool blockPopValidation(const CBlock& block, const CBlockIndex& pindexPrev, const Consensus::Params& params, BlockValidationState& state) override;

    bool doUpdateContext(const std::vector<std::vector<uint8_t>>& veriBlockBlocks, const std::vector<std::vector<uint8_t>>& bitcoinBlocks, TxValidationState& state) override;
    void doRemoveContext(const std::vector<std::vector<uint8_t>>& veriBlockBlocks, const std::vector<std::vector<uint8_t>>& bitcoinBlocks) override;

    bool parsePopTx(const CTransactionRef& tx, ScriptError* serror, Publications* publications, Context* ctx, PopTxType* type) override;

    bool determineATVPlausibilityWithBTCRules(AltchainId altChainIdentifier, const CBlockHeader& popEndorsementHeader, const Consensus::Params& params, TxValidationState& state) override;

    bool commitPayloads(const CBlockIndex& prev, const CBlock& connecting, TxValidationState& state) override;

    bool removePayloads(const CBlockIndex& block, TxValidationState& state) override;

    virtual void getPublicationsData(const Publications& tx, PublicationData& publicationData);
};

bool blockPopValidationImpl(PopServiceImpl& pop, const CBlock& block, const CBlockIndex& pindexPrev, const Consensus::Params& params, BlockValidationState& state);

bool txPopValidation(PopServiceImpl& pop, const CTransactionRef& tx, const CBlockIndex& pindexPrev, const Consensus::Params& params, TxValidationState& state, uint32_t heightIndex);

// FIXME: an ugly crutch for tests
bool addTemporaryPayloadsImpl(PopServiceImpl& pop, const CTransactionRef& tx, const CBlockIndex& pindexPrev, const Consensus::Params& params, TxValidationState& state);
void clearTemporaryPayloadsImpl(PopServiceImpl& pop);
void initTemporaryPayloadsMock(PopServiceImpl& pop);

} // namespace VeriBlock
#endif //BITCOIN_SRC_VBK_POP_SERVICE_POP_SERVICE_IMPL_HPP
