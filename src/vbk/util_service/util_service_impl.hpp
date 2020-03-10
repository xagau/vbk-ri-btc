#ifndef BITCOIN_SRC_VBK_UTIL_SERVICE_UTIL_SERVICE_IMPL_HPP
#define BITCOIN_SRC_VBK_UTIL_SERVICE_UTIL_SERVICE_IMPL_HPP

#include "vbk/config.hpp"
#include "vbk/util_service.hpp"

#include <consensus/validation.h>
#include <vbk/interpreter.hpp>
#include <vector>

namespace VeriBlock {

struct UtilServiceImpl : public UtilService {
    ~UtilServiceImpl() override = default;

    bool CheckPopInputs(const CTransaction& tx, TxValidationState& state, unsigned int flags, bool cacheSigStore, PrecomputedTransactionData& txdata) override;

    bool isKeystone(const CBlockIndex& block) override;

    const CBlockIndex* getPreviousKeystone(const CBlockIndex& block) override;

    KeystoneArray getKeystoneHashesForTheNextBlock(const CBlockIndex* pindexPrev) override;

    uint256 makeTopLevelRoot(int height, const KeystoneArray& keystones, const uint256& txRoot) override;

    int compareForks(const CBlockIndex& left, const CBlockIndex& right) override;

    // Pop rewards methods
    PoPRewards getPopRewards(const CBlockIndex& pindexPrev, const Consensus::Params& consensusParams) override;
    void addPopPayoutsIntoCoinbaseTx(CMutableTransaction& coinbaseTx, const CBlockIndex& pindexPrev, const Consensus::Params& consensusParams) override;
    bool checkCoinbaseTxWithPopRewards(const CTransaction& tx, const CAmount& PoWBlockReward, const CBlockIndex& pindexPrev, const Consensus::Params& consensusParams, BlockValidationState& state) override;

    bool EvalScript(const CScript& script, std::vector<std::vector<unsigned char>>& stack, ScriptError* serror, Publications* publications, Context* context, PopTxType* type, bool with_checks) override;

    bool validatePopTx(const CTransaction& tx, TxValidationState& state) override;
    bool validatePopTxInput(const CTxIn& in, TxValidationState& state);
    bool validatePopTxOutput(const CTxOut& in, TxValidationState& state);

    bool shouldDownloadChain(const CBlockIndex& tip) override;

protected:
    const CBlockIndex* FindCommonKeystone(const CBlockIndex* leftFork, const CBlockIndex* rightFork);

    bool IsCrossedKeystoneBoundary(const CBlockIndex& bottom, const CBlockIndex& tip);
};
} // namespace VeriBlock


#endif //BITCOIN_SRC_VBK_UTIL_SERVICE_UTIL_SERVICE_IMPL_HPP
