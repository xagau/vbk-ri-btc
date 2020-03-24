#ifndef BITCOIN_SRC_VBK_POP_SERVICE_POP_SERVICE_IMPL_HPP
#define BITCOIN_SRC_VBK_POP_SERVICE_POP_SERVICE_IMPL_HPP

#include <vbk/entity/pop.hpp>
#include <vbk/pop_service.hpp>
#include <vbk/pop_service/pop_service_exception.hpp>
#include <veriblock/blockchain/alt_block_tree.hpp>
#include <veriblock/storage/repository_rocks_manager.hpp>
#include <veriblock/state_manager.hpp>

#include <memory>
#include <vector>

#include <chainparams.h>

#include <sync.h>

namespace VeriBlock {

class PopServiceImpl : public PopService
{
private:
    std::mutex mutex;

    std::shared_ptr<altintegration::AltTree> altTree;
    std::shared_ptr<altintegration::StateManager<altintegration::RepositoryRocksManager>> stateManager;

public:
    altintegration::AltTree& getAltTree()
    {
        return *altTree;
    }

    altintegration::StateManager<altintegration::RepositoryRocksManager>& getStateManager()
    {
        return *stateManager;
    }

    PopServiceImpl();

    ~PopServiceImpl() override = default;

    std::vector<BlockBytes> getLastKnownVBKBlocks(size_t blocks) override;
    std::vector<BlockBytes> getLastKnownBTCBlocks(size_t blocks) override;

    bool checkVTBinternally(const std::vector<uint8_t>& bytes) override;
    bool checkATVinternally(const std::vector<uint8_t>& bytes) override;

    int compareTwoBranches(const CBlockIndex* commonKeystone, const CBlockIndex* leftForkTip, const CBlockIndex* rightForkTip) override;

    void rewardsCalculateOutputs(const int& blockHeight, const CBlockIndex& endorsedBlock, const CBlockIndex& contaningBlocksTip, const CBlockIndex* difficulty_start_interval, const CBlockIndex* difficulty_end_interval, std::map<CScript, int64_t>& outputs) override;

    bool blockPopValidation(const CBlock& block, const CBlockIndex& pindexPrev, const Consensus::Params& params, BlockValidationState& state) override;

    bool determineATVPlausibilityWithBTCRules(AltchainId altChainIdentifier, const CBlockHeader& popEndorsementHeader, const Consensus::Params& params, TxValidationState& state) override;

    bool commitPayloads(const CBlockIndex& prev, const CBlock& connecting, TxValidationState& state) override;

    bool removePayloads(const CBlockIndex& block) override;
};

bool blockPopValidationImpl(PopServiceImpl& pop, const CBlock& block, const CBlockIndex& pindexPrev, const Consensus::Params& params, BlockValidationState& state);

bool txPopValidation(PopServiceImpl& pop, const CBlock& block, const CTransactionRef& tx, const CBlockIndex& pindexPrev, const Consensus::Params& params, TxValidationState& state, altintegration::Payloads& payloads);

} // namespace VeriBlock
#endif //BITCOIN_SRC_VBK_POP_SERVICE_POP_SERVICE_IMPL_HPP
