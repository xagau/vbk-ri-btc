#include "pop_service_impl.hpp"

#include <chrono>
#include <memory>
#include <thread>

#include <amount.h>
#include <chain.h>
#include <consensus/validation.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/sigcache.h>
#include <shutdown.h>
#include <streams.h>
#include <util/strencodings.h>
#include <validation.h>

#include <vbk/merkle.hpp>
#include <vbk/service_locator.hpp>
#include <vbk/util.hpp>
#include <vbk/util_service.hpp>

#include <veriblock/alt-util.hpp>
#include <veriblock/finalizer.hpp>
#include <veriblock/storage/repository_rocks_manager.hpp>

namespace {

altintegration::AltBlock cast(int nHeight, const CBlockHeader& block)
{
    altintegration::AltBlock alt;
    alt.height = nHeight;
    alt.timestamp = block.nTime;
    auto hash = block.GetHash();
    alt.hash = std::vector<uint8_t>{hash.begin(), hash.end()};
    return alt;
}

CBlockHeader headerFromBytes(const std::vector<uint8_t>& v)
{
    CDataStream stream(v, SER_NETWORK, PROTOCOL_VERSION);
    CBlockHeader header;
    stream >> header;
    return header;
}

} // namespace


namespace VeriBlock {

const static std::string DATABASE_NAME = "alt-integration-db";

PopServiceImpl::PopServiceImpl()
{
     // TODO use new interface of the alt-integration-lib
    /*
    stateManager = std::make_shared<altintegration::StateManager<altintegration::RepositoryRocksManager>>(DATABASE_NAME);

    auto alt = altintegration::AltTree::init<altintegration::RepositoryRocksManager>(
        stateManager,
        Params().getAltParams(),
        Params().getBtcParams(),
        Params().getVbkParams());

    altTree = std::make_shared<altintegration::AltTree>(std::move(alt));
    */
}

bool PopServiceImpl::commitPayloads(const CBlockIndex& prev, const CBlock& connecting, TxValidationState& state)
{
    std::lock_guard<std::mutex> lock(mutex);
    // TODO use new interface of the alt-integration-lib
    /*
    auto change = getStateManager().newChange();
    auto block = cast(prev.nHeight, connecting.GetBlockHeader());

    for(const auto& tx : connecting.vtx) {
        altintegration::Payloads payloads;
        if(!txPopValidation(*this, connecting, *tx, prev, Params().GetConsensus(), state, payloads)) {
            return false;
        }
    }

    getAltTree().currentPopManager().commit();
    change->commit();
    */

    return true;
}

bool PopServiceImpl::removePayloads(const CBlockIndex& connecting)
{
    std::lock_guard<std::mutex> lock(mutex);
    // TODO use new interface of the alt-integration-lib
    /*
    altintegration::ValidationState instate;
    auto block = cast(connecting.nHeight, connecting.GetBlockHeader());
    return getAltTree().setState(block.previousBlock, instate);
    */

    return true;
}


std::vector<BlockBytes> PopServiceImpl::getLastKnownVBKBlocks(size_t blocks)
{
    std::lock_guard<std::mutex> lock(mutex);
    // TODO use new interface of the alt-integration-lib
    /*
    return altintegration::getLastKnownBlocks(getAltTree().currentPopManager().vbk(), blocks);
    */

    return std::vector<BlockBytes>();
}

std::vector<BlockBytes> PopServiceImpl::getLastKnownBTCBlocks(size_t blocks)
{
    std::lock_guard<std::mutex> lock(mutex);
    // TODO use new interface of the alt-integration-lib
    /*
    return altintegration::getLastKnownBlocks(getAltTree().currentPopManager().btc(), blocks);
    */

    return std::vector<BlockBytes>();
}

bool PopServiceImpl::checkVTBinternally(const std::vector<uint8_t>& bytes)
{
    try {
        auto vtb = altintegration::VTB::fromVbkEncoding(bytes);
        altintegration::ValidationState state;
        return altintegration::checkVTB(vtb, state, Params().getVbkParams(), Params().getBtcParams());
    } catch (...) {
        return false;
    }
}

bool PopServiceImpl::checkATVinternally(const std::vector<uint8_t>& bytes)
{
    try {
        auto atv = altintegration::ATV::fromVbkEncoding(bytes);
        altintegration::ValidationState state;
        return altintegration::checkATV(atv, state, Params().getVbkParams());
    } catch (...) {
        return false;
    }
}

// Forkresolution
int PopServiceImpl::compareTwoBranches(const CBlockIndex* commonKeystone, const CBlockIndex* leftForkTip, const CBlockIndex* rightForkTip)
{
    std::lock_guard<std::mutex> lock(mutex);
    //    TwoBranchesRequest request;
    //    CompareTwoBranchesReply reply;
    //    ClientContext context;
    //
    //    const CBlockIndex* workingLeft = leftForkTip;
    //    const CBlockIndex* workingRight = rightForkTip;
    //
    //    while (true) {
    //        AltChainBlock* b = request.add_leftfork();
    //        ::BlockToProtoAltChainBlock(*workingLeft, *b);
    //
    //        if (workingLeft == commonKeystone)
    //            break;
    //        workingLeft = workingLeft->pprev;
    //    }
    //
    //    while (true) {
    //        AltChainBlock* b = request.add_rightfork();
    //        ::BlockToProtoAltChainBlock(*workingRight, *b);
    //
    //        if (workingRight == commonKeystone)
    //            break;
    //        workingRight = workingRight->pprev;
    //    }
    //
    //    Status status = grpcPopService->CompareTwoBranches(&context, request, &reply);
    //    if (!status.ok()) {
    //        throw PopServiceException(status);
    //    }
    //
    //    return reply.compareresult();

    return 0;
}

// Pop rewards
void PopServiceImpl::rewardsCalculateOutputs(const int& blockHeight, const CBlockIndex& endorsedBlock, const CBlockIndex& contaningBlocksTip, const CBlockIndex* difficulty_start_interval, const CBlockIndex* difficulty_end_interval, std::map<CScript, int64_t>& outputs)
{
    std::lock_guard<std::mutex> lock(mutex);
    // TODO: implement
}

bool PopServiceImpl::determineATVPlausibilityWithBTCRules(AltchainId altChainIdentifier, const CBlockHeader& popEndorsementHeader, const Consensus::Params& params, TxValidationState& state)
{
    // Some additional checks could be done here to ensure that the context info container
    // is more apparently initially valid (such as checking both included block hashes
    // against the minimum PoW difficulty on the network).
    // However, the ATV will fail to validate upon attempted inclusion into a block anyway
    // if the context info container contains a bad block height, or nonexistent previous keystones
    auto expected = getService<Config>().index.unwrap();
    if (altChainIdentifier.unwrap() != expected) {
        return state.Invalid(TxValidationResult::TX_BAD_POP_DATA, "pop-tx-altchain-id", "wrong altchain ID. Expected " + std::to_string(expected) + ", got " + std::to_string(altChainIdentifier.unwrap()));
    }

    if (!CheckProofOfWork(popEndorsementHeader.GetHash(), popEndorsementHeader.nBits, params)) {
        return state.Invalid(TxValidationResult::TX_BAD_POP_DATA, "pop-tx-endorsed-block-pow", "endorsed block has invalid PoW: " + popEndorsementHeader.GetHash().GetHex());
    }

    return true;
}

bool txPopValidation(PopServiceImpl& pop, const CBlock& block, const CTransaction& tx, const CBlockIndex& pindexPrev, const Consensus::Params& params, TxValidationState& state, altintegration::Payloads& payloads) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    altintegration::ValidationState instate;
    VeriBlock::Publications publications;
    VeriBlock::Context context;
    VeriBlock::PopTxType type = VeriBlock::PopTxType::UNKNOWN;
    ScriptError serror = ScriptError::SCRIPT_ERR_UNKNOWN_ERROR;
    std::vector<std::vector<uint8_t>> stack;

    payloads.alt.containing = cast(pindexPrev.nHeight + 1, block.GetBlockHeader());

    // parse transaction
    if (!VeriBlock::getService<VeriBlock::UtilService>().EvalScript(tx.vin[0].scriptSig, stack, &serror, &publications, &context, &type, false)) {
        return state.Invalid(
            TxValidationResult::TX_BAD_POP_DATA,
            "pop-tx-invalid-script",
            "[" + tx.GetHash().ToString() + "] scriptSig of POP tx is invalid: " + ScriptErrorString(serror));
    }

    switch (type) {
    case VeriBlock::PopTxType::CONTEXT: {
        // TODO use new interface of the alt-integration-lib
        /*
        payloads.alt.hasAtv = false;
        payloads.vtbs.clear();

        auto& c = context;

        // parse BTC context
        try {
            payloads.btccontext.clear();
            payloads.btccontext.reserve(c.btc.size());
            std::transform(c.btc.begin(), c.btc.end(), std::back_inserter(payloads.btccontext), [](const std::vector<uint8_t>& v) {
                return altintegration::BtcBlock::fromRaw(v);
            });
        } catch (const std::exception& e) {
            return state.Invalid(TxValidationResult::TX_BAD_POP_DATA,
                "pop-tx-invalid-btc-context",
                "[" + tx.GetHash().ToString() + "] BTC context is invalid: " + e.what());
        }

        // parse VBK context
        try {
            payloads.vbkcontext.clear();
            payloads.vbkcontext.reserve(c.vbk.size());
            std::transform(c.vbk.begin(), c.vbk.end(), std::back_inserter(payloads.vbkcontext), [](const std::vector<uint8_t>& v) {
                return altintegration::VbkBlock::fromRaw(v);
            });
        } catch (const std::exception& e) {
            return state.Invalid(TxValidationResult::TX_BAD_POP_DATA,
                "pop-tx-invalid-vbk-context",
                "[" + tx.GetHash().ToString() + "] VBK context is invalid: " + e.what());
        }

        */
        break;
    }
    case VeriBlock::PopTxType::PUBLICATIONS: {
        // TODO use new interface of the alt-integration-lib
        /*
        payloads.alt.atv = altintegration::ATV::fromVbkEncoding(publications.atv);
        payloads.alt.hasAtv = true;
        const altintegration::PublicationData& publicationData = payloads.alt.atv.transaction.publicationData;

        CBlockHeader endorsedHeader;

        // parse endorsed header
        try {
            endorsedHeader = headerFromBytes(publicationData.header);
        } catch (const std::exception& e) {
            return state.Invalid(TxValidationResult::TX_BAD_POP_DATA, "pop-tx-alt-block-invalid", "[" + tx.GetHash().ToString() + "] can't deserialize endorsed block header: " + e.what());
        }

        TxValidationState txState;
        if (!pop.determineATVPlausibilityWithBTCRules(AltchainId(publicationData.identifier), endorsedHeader, params, txState)) {
            return state.Invalid(TxValidationResult::TX_BAD_POP_DATA, "pop-tx-alt-block-wrong-chain", "[" + tx.GetHash().ToString() + "]: " + txState.GetRejectReason() + ", " + txState.GetDebugMessage());
        }

        // verify endorsed header exists
        AssertLockHeld(cs_main);
        const CBlockIndex* endorsedIndex = LookupBlockIndex(endorsedHeader.GetHash());
        if (endorsedIndex == nullptr) {
            return state.Invalid(TxValidationResult::TX_BAD_POP_DATA, "pop-tx-endorsed-block-not-known-orphan-block", "[" + tx.GetHash().ToString() + "] can not find endorsed block index: " + endorsedHeader.GetHash().ToString());
        }

        // verify endorsed header is ancestor of currently validated block
        const CBlockIndex* ancestor = pindexPrev.GetAncestor(endorsedIndex->nHeight);
        if (ancestor == nullptr || ancestor->GetBlockHash() != endorsedIndex->GetBlockHash()) {
            return state.Invalid(TxValidationResult::TX_BAD_POP_DATA, "pop-tx-endorsed-block-not-from-this-chain", "[" + tx.GetHash().ToString() + "] can not find endorsed block in the chain: " + endorsedHeader.GetHash().ToString());
        }

        // verify endorsed header is within settlement interval
        auto config = VeriBlock::getService<VeriBlock::Config>();
        if (pindexPrev.nHeight + 1 - endorsedIndex->nHeight > config.POP_REWARD_SETTLEMENT_INTERVAL) {
            return state.Invalid(TxValidationResult::TX_BAD_POP_DATA, "pop-tx-endorsed-block-too-old",
                "[" + tx.GetHash().ToString() + "] endorsed block is too old for this chain: " + endorsedIndex->GetBlockHash().GetHex() +
                    ". (last block height: " + std::to_string(pindexPrev.nHeight + 1) + ", endorsed block height: " + std::to_string(endorsedIndex->nHeight) + ", settlement interval: " + std::to_string(config.POP_REWARD_SETTLEMENT_INTERVAL) + ")");
        }

        // set endorsed header
        payloads.alt.endorsed = cast(endorsedIndex->nHeight, endorsedHeader);

        // parse VTBs
        auto& p = publications;
        try {
            payloads.vtbs.clear();
            payloads.vtbs.reserve(p.vtbs.size());
            std::transform(p.vtbs.begin(), p.vtbs.end(), std::back_inserter(payloads.vtbs), [](const std::vector<uint8_t>& v) {
                return altintegration::VTB::fromVbkEncoding(v);
            });
        } catch (const std::exception& e) {
            return state.Invalid(TxValidationResult::TX_BAD_POP_DATA,
                "pop-tx-invalid-vtbs",
                "[" + tx.GetHash().ToString() + "] parsing of VTB is invalid: " + e.what());
        }
        */
        break;
    }
    default: {
        return state.Invalid(
            TxValidationResult::TX_BAD_POP_DATA,
            "pop-tx-eval-script-failed",
            "[" + tx.GetHash().ToString() + "] EvalScript returned unexpected type");
    }
    }

    return true;
}


bool blockPopValidationImpl(PopServiceImpl& pop, const CBlock& block, const CBlockIndex& pindexPrev, const Consensus::Params& params, BlockValidationState& state) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    LOCK(mempool.cs);
    AssertLockHeld(mempool.cs);
    AssertLockHeld(cs_main);

    // TODO use new interface of the alt-integration-lib
    /*
    return altintegration::tryValidateWithResources(
        [&]() -> bool {
            const auto& config = getService<Config>();
            size_t numOfPopTxes = 0;

            for (const auto& tx : block.vtx) {
                if (!isPopTx(*tx)) {
                    // do not even consider regular txes here
                    continue;
                }

                if (++numOfPopTxes > config.max_pop_tx_amount) {
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "pop-block-num-pop-tx", "too many pop transactions in a block");
                }

                TxValidationState txstate;
                altintegration::Payloads payloads;
                if (!txPopValidation(pop, block, *tx, pindexPrev, params, txstate, payloads)) {
                    mempool.removeRecursive(*tx, MemPoolRemovalReason::BLOCK);
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, txstate.GetRejectReason(), txstate.GetDebugMessage());
                }
            }

            // after validation, clear last applied payloads
            pop.getAltTree().currentPopManager().rollback();

            return true;
        },
        [&pop] { pop.getAltTree().currentPopManager().rollback(); });
        */
    return true;
}

bool PopServiceImpl::blockPopValidation(const CBlock& block, const CBlockIndex& pindexPrev, const Consensus::Params& params, BlockValidationState& state) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    return blockPopValidationImpl(*this, block, pindexPrev, params, state);
}

} // namespace VeriBlock
