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

namespace {

VeriBlock::AltBlock cast(int nHeight, const CBlockHeader& block)
{
    VeriBlock::AltBlock alt;
    alt.height = nHeight;
    alt.timestamp = block.nTime;
    auto hash = block.GetBlockHash();
    alt.hash = std::vector<uint8_t>{hash.begin(), hash.end()};
    return alt;
}

CBlock headerFromBytes(const std::vector<uint8_t>& v)
{
    CDataStream stream(v, SER_NETWORK, PROTOCOL_VERSION);
    CBlockHeader header;
    stream >> header;
    return header;
}

VeriBlock::Payloads cast(const Publications& publications)
{
    VeriBlock::AltProof altproof;
    altproof.atv = VeriBlock::ATV::fromVbkEncoding(publications.atv);
    altproof.containing = cast(prev.nHeight + 1, connecting);

    CBlock endorsed = headerFromBytes(altproof.atv.transaction.publicationData.header);
    auto* index = LookupBlockIndex(endorsed.GetHash());
    assert(index != nullptr);
    altproof.endorsed = cast(index->nHeight, index->GetBlockHeader());

    VeriBlock::Payloads payloads;
    payloads.alt = altproof;

    std::transform(publications.vtbs.begin(), publications.vtbs.end(), std::back_inserter(payloads.vtbs), [](const std::vector<uint8_t>& v) {
        return VeriBlock::VTB::fromVbkEncoding(v);
    });
}


inline uint32_t getReservedBlockIndexBegin(const VeriBlock::Config& config)
{
    return std::numeric_limits<uint32_t>::max() - config.max_pop_tx_amount;
}

inline uint32_t getReservedBlockIndexEnd(const VeriBlock::Config& config)
{
    return std::numeric_limits<uint32_t>::max();
}

inline std::string heightToHash(uint32_t height)
{
    return arith_uint256(height).GetHex();
}

} // namespace


namespace VeriBlock {

PopServiceImpl::PopServiceImpl(bool doinit) : pop(btc_param, vbk_param, btc_e_repo, vbk_e_repo, alt_param)
{
    // for mocking purposes
    if (!doinit) return;

    auto& config = VeriBlock::getService<VeriBlock::Config>();

    assert(getReservedBlockIndexBegin(config) <= getReservedBlockIndexEnd(config) && "oh no, programming error");
    temporaryPayloadsIndex = getReservedBlockIndexEnd(config);
    clearTemporaryPayloads();
}

void initTemporaryPayloadsMock(PopServiceImpl& pop)
{
    auto& config = VeriBlock::getService<VeriBlock::Config>();

    pop.temporaryPayloadsIndex = getReservedBlockIndexBegin(config);
}

void PopServiceImpl::connectPayloads(const CBlockIndex& prev, const CBlock& connecting)
{
    std::lock_guard<std::mutex> lock(mutex);

    VeriBlock::ValidationState state;
    for (const auto& tx : connecting.vtx) {
        if (!isPopTx(*tx)) {
            continue;
        }

        Publications publications;
        Context context;
        PopTxType type;
        ScriptError serror;
        bool ret = parsePopTx(tx, &serror, &publications, &context, &type);
        assert(ret && "scriptSig of pop tx is invalid in addPayloads");

        switch (type) {
        case PopTxType::CONTEXT: {
            bool ret = this->updateContext(context.vbk, context.btc, state);
            assert(ret); // we expect that payloads are correct here
            assert(state.IsValid());
            break;
        }
        case PopTxType::PUBLICATIONS: {
            VeriBlock::Payloads payloads = cast(publications);
            bool ret = pop.addPayloads(payloads, state);
            assert(ret); // we expect that payloads are correct here
            assert(state.IsValid());
            break;
        }

        default: {
            break;
        }
        }
    }
}

void PopServiceImpl::removePayloads(const CBlockIndex& block)
{
    //
}


std::vector<BlockBytes> PopServiceImpl::getLastKnownVBKBlocks(size_t blocks)
{
    std::lock_guard<std::mutex> lock(mutex);
    return getLastKnownBlocks(pop.vbk(), blocks);
}

std::vector<BlockBytes> PopServiceImpl::getLastKnownBTCBlocks(size_t blocks)
{
    std::lock_guard<std::mutex> lock(mutex);
    return getLastKnownBlocks(pop.btc(), blocks);
}

bool PopServiceImpl::checkVTBinternally(const std::vector<uint8_t>& bytes)
{
    try {
        auto vtb = VeriBlock::VTB::fromVbkEncoding(bytes);
        VeriBlock::ValidationState state;

        return VeriBlock::checkVTB(vtb, state, *vbk_param, *btc_param);
    } catch (...) {
        return false;
    }
}

bool PopServiceImpl::checkATVinternally(const std::vector<uint8_t>& bytes)
{
    try {
        auto atv = VeriBlock::ATV::fromVbkEncoding(bytes);
        VeriBlock::ValidationState state;
        return VeriBlock::checkATV(atv, state, *vbk_param);
    } catch (...) {
        return false;
    }
}

bool PopServiceImpl::updateContext(const std::vector<std::vector<uint8_t>>& veriBlockBlocks, const std::vector<std::vector<uint8_t>>& bitcoinBlocks, TxValidationState& state)
{
    VeriBlock::ValidationState instate;
    // apply BTC blocks
    if (!VeriBlock::addBlocks(pop.getPopManager().btc(), bitcoinBlocks, instate)) {
        return state.Invalid(
            TxValidationResult::TX_BAD_POP_DATA,
            instate.GetRejectReason(),
            strprintf("BTC context is invalid: %s",
                instate.GetDebugMessage()));
    }

    // apply VBK blocks
    if (!VeriBlock::addBlocks(pop.getPopManager().vbk(), veriBlockBlocks, instate)) {
        return state.Invalid(
            TxValidationResult::TX_BAD_POP_DATA,
            instate.GetRejectReason(),
            strprintf("VBK context is invalid: %s",
                instate.GetDebugMessage()));
    }

    return true;
}

// Forkresolution
int PopServiceImpl::compareTwoBranches(const CBlockIndex* commonKeystone, const CBlockIndex* leftForkTip, const CBlockIndex* rightForkTip)
{
    std::lock_guard<std::mutex> lock(mutex);
    TwoBranchesRequest request;
    CompareTwoBranchesReply reply;
    ClientContext context;

    const CBlockIndex* workingLeft = leftForkTip;
    const CBlockIndex* workingRight = rightForkTip;

    while (true) {
        AltChainBlock* b = request.add_leftfork();
        ::BlockToProtoAltChainBlock(*workingLeft, *b);

        if (workingLeft == commonKeystone)
            break;
        workingLeft = workingLeft->pprev;
    }

    while (true) {
        AltChainBlock* b = request.add_rightfork();
        ::BlockToProtoAltChainBlock(*workingRight, *b);

        if (workingRight == commonKeystone)
            break;
        workingRight = workingRight->pprev;
    }

    Status status = grpcPopService->CompareTwoBranches(&context, request, &reply);
    if (!status.ok()) {
        throw PopServiceException(status);
    }

    return reply.compareresult();
}

// Pop rewards
void PopServiceImpl::rewardsCalculateOutputs(const int& blockHeight, const CBlockIndex& endorsedBlock, const CBlockIndex& contaningBlocksTip, const CBlockIndex* difficulty_start_interval, const CBlockIndex* difficulty_end_interval, std::map<CScript, int64_t>& outputs)
{
    std::lock_guard<std::mutex> lock(mutex);
    // TODO: implement
}

bool PopServiceImpl::parsePopTx(const CTransactionRef& tx, ScriptError* serror, Publications* pub, Context* ctx, PopTxType* type)
{
    std::vector<std::vector<uint8_t>> stack;
    return getService<UtilService>().EvalScript(tx->vin[0].scriptSig, stack, serror, pub, ctx, type, false);
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
        return state.Invalid(TxValidationResult::TX_BAD_POP_DATA, "pop-tx-altchain-id", strprintf("wrong altchain ID. Expected %d, got %d.", expected, altChainIdentifier.unwrap()));
    }

    if (!CheckProofOfWork(popEndorsementHeader.GetHash(), popEndorsementHeader.nBits, params)) {
        return state.Invalid(TxValidationResult::TX_BAD_POP_DATA, "pop-tx-endorsed-block-pow", strprintf("endorsed block has invalid PoW: %s"));
    }

    return true;
}

bool PopServiceImpl::addTemporaryPayloads(const CTransactionRef& tx, const CBlockIndex& pindexPrev, const Consensus::Params& params, TxValidationState& state)
{
    return addTemporaryPayloadsImpl(*this, tx, pindexPrev, params, state);
}

bool addTemporaryPayloadsImpl(PopServiceImpl& pop, const CTransactionRef& tx, const CBlockIndex& pindexPrev, const Consensus::Params& params, TxValidationState& state)
{
    auto& config = VeriBlock::getService<VeriBlock::Config>();
    if (pop.temporaryPayloadsIndex >= getReservedBlockIndexEnd(config)) {
        return state.Invalid(TxValidationResult::TX_BAD_POP_DATA, "pop-block-num-pop-tx", "too many pop transactions in a block");
    }

    //TODO: need locking

    bool isValid = txPopValidation(pop, tx, pindexPrev, params, state, pop.temporaryPayloadsIndex);
    if (isValid) {
        pop.temporaryPayloadsIndex++;
    }

    return isValid;
}

void PopServiceImpl::clearTemporaryPayloads()
{
    clearTemporaryPayloadsImpl(*this);
}

void clearTemporaryPayloadsImpl(PopServiceImpl& pop)
{
    // since we have no transactional interface (yet), we agreed to do the following instead:
    // 1. during block pop validation, execute addPayloads with heights from reserved block heights - this changes the state of alt-service and does all validations.
    // 2. since it changes state, after validation we want to rollback. execute removePayloads on all reserved heights to do that
    // 3. if node was shutdown during block pop validation, also clear all payloads within given height range
    // range is [uint32_t::max() - pop_tx_amount_per_block...uint32_t::max); total size is config.pop_tx_amount

    const auto begin = getReservedBlockIndexBegin(getService<Config>());
    const auto end = pop.temporaryPayloadsIndex;

    for (uint32_t height = end - 1; height >= begin; --height) {
        try {
            pop.removePayloads(heightToHash(height), height);
        } catch (const std::exception& /*ignore*/) {
        }
    }

    pop.temporaryPayloadsIndex = begin;
}

bool txPopValidation(PopServiceImpl& pop, const CTransactionRef& tx, const CBlockIndex& pindexPrev, const Consensus::Params& params, TxValidationState& state, uint32_t heightIndex) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    auto& config = VeriBlock::getService<VeriBlock::Config>();
    Publications publications;
    ScriptError serror = ScriptError::SCRIPT_ERR_UNKNOWN_ERROR;
    Context context;
    VeriBlock::ValidationState instate;
    PopTxType type = PopTxType::UNKNOWN;
    if (!pop.parsePopTx(tx, &serror, &publications, &context, &type)) {
        return state.Invalid(TxValidationResult::TX_BAD_POP_DATA, "pop-tx-invalid-script", strprintf("[%s] scriptSig of POP tx is invalid: %s", tx->GetHash().ToString(), ScriptErrorString(serror)));
    }

    switch (type) {
    case PopTxType::CONTEXT: {
        try {
            if (!this->updateContext(context.vbk, context.btc, state)) {
                return state.Invalid(
                    TxValidationResult::TX_BAD_POP_DATA,
                    "pop-tx-updatecontext-failed",
                    strprintf("[%s] updatecontext failed: %s", tx->GetHash().ToString(), state.GetDebugMessage()));
            }
        } catch (const std::exception& e) {
            return state.Invalid(TxValidationResult::TX_BAD_POP_DATA, "pop-tx-updatecontext-failed", strprintf("[%s] updatecontext failed: %s", tx->GetHash().ToString(), e.what()));
        }
        break;
    }

    case PopTxType::PUBLICATIONS: {
        PublicationData popEndorsement;
        pop.getPublicationsData(publications, popEndorsement);

        CBlockHeader popEndorsementHeader;

        try {
            popEndorsementHeader = headerFromBytes(popEndorsement.header);
        } catch (const std::exception& e) {
            return state.Invalid(TxValidationResult::TX_BAD_POP_DATA, "pop-tx-alt-block-invalid", strprintf("[%s] can't deserialize endorsed block header: %s", tx->GetHash().ToString(), e.what()));
        }

        if (!pop.determineATVPlausibilityWithBTCRules(AltchainId(popEndorsement.identifier()), popEndorsementHeader, params, state)) {
            return false; // TxValidationState already set
        }

        AssertLockHeld(cs_main);
        const CBlockIndex* popEndorsementIdnex = LookupBlockIndex(popEndorsementHeader.GetHash());
        if (popEndorsementIdnex == nullptr) {
            return state.Invalid(TxValidationResult::TX_BAD_POP_DATA, "pop-tx-endorsed-block-not-known-orphan-block", strprintf("[%s] can not find endorsed block index: %s", tx->GetHash().ToString(), popEndorsementHeader.GetHash().ToString()));
        }
        const CBlockIndex* ancestor = pindexPrev.GetAncestor(popEndorsementIdnex->nHeight);
        if (ancestor == nullptr || ancestor->GetBlockHash() != popEndorsementIdnex->GetBlockHash()) {
            return state.Invalid(TxValidationResult::TX_BAD_POP_DATA, "pop-tx-endorsed-block-not-from-this-chain", strprintf("[%s] can not find endorsed block in the chain: %s", tx->GetHash().ToString(), popEndorsementHeader.GetHash().ToString()));
        }

        if (pindexPrev.nHeight + 1 - popEndorsementIdnex->nHeight > config.POP_REWARD_SETTLEMENT_INTERVAL) {
            return state.Invalid(TxValidationResult::TX_BAD_POP_DATA,
                "pop-tx-endorsed-block-too-old",
                strprintf("[%s] endorsed block is too old for this chain: %s. (last block height: %d, endorsed block height: %d, settlement interval: %d)",
                    tx->GetHash().ToString(),
                    popEndorsementIdnex->GetBlockHash().GetHex(),
                    pindexPrev.nHeight + 1,
                    popEndorsementIdnex->nHeight,
                    config.POP_REWARD_SETTLEMENT_INTERVAL));
        }

        try {
            VeriBlock::Payloads payloads = cast(publications);
            if (!pop.getPopManager().addPayloads(payloads, state)) {
                return state.Invalid(
                    TxValidationResult::TX_BAD_POP_DATA,
                    "pop-tx-add-payloads-failed",
                    strprintf(
                        "[%s] addPayloads failed: %s, %s",
                        tx->GetHash().ToString(),
                        state.GetRejectReason(),
                        state.GetDebugMessage()));
            }
        } catch (const PopServiceException& e) {
            return state.Invalid(
                TxValidationResult::TX_BAD_POP_DATA,
                "pop-tx-add-payloads-failed",
                strprintf(
                    "[%s] addPayloads failed: %s",
                    tx->GetHash().ToString(),
                    e.what()));
        }
        break;
    }
    default:
        return state.Invalid(TxValidationResult::TX_BAD_POP_DATA, "pop-tx-eval-script-failed", strprintf("[%s] EvalScript returned unexpected type", tx->GetHash().ToString()));
    }

    return true;
}


bool blockPopValidationImpl(PopServiceImpl& pop, const CBlock& block, const CBlockIndex& pindexPrev, const Consensus::Params& params, BlockValidationState& state) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    const auto& config = getService<Config>();
    size_t numOfPopTxes = 0;

    LOCK(mempool.cs);
    AssertLockHeld(mempool.cs);
    AssertLockHeld(cs_main);
    for (const auto& tx : block.vtx) {
        if (!isPopTx(*tx)) {
            // do not even consider regular txes here
            continue;
        }

        if (++numOfPopTxes > config.max_pop_tx_amount) {
            clearTemporaryPayloadsImpl(pop);
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "pop-block-num-pop-tx", "too many pop transactions in a block");
        }

        TxValidationState txstate;

        if (!addTemporaryPayloadsImpl(pop, tx, pindexPrev, params, txstate)) {
            clearTemporaryPayloadsImpl(pop);
            mempool.removeRecursive(*tx, MemPoolRemovalReason::BLOCK);
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, txstate.GetRejectReason(), txstate.GetDebugMessage());
        }
    }

    // because this is validation, we need to clear current temporary payloads
    // actual addPayloads call is performed in ConnectTip
    clearTemporaryPayloadsImpl(pop);

    return true;
}

bool PopServiceImpl::blockPopValidation(const CBlock& block, const CBlockIndex& pindexPrev, const Consensus::Params& params, BlockValidationState& state) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    return blockPopValidationImpl(*this, block, pindexPrev, params, state);
}

void PopServiceImpl::getPublicationsData(const Publications& tx, PublicationData& publicationData)
{
    auto atv = VeriBlock::ATV::fromVbkEncoding(tx.atv);
    publicationData = atv.transaction.publicationData;
}
} // namespace VeriBlock
