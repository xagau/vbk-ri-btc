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
    auto hash = block.GetHash();
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

VeriBlock::Payloads cast(const VeriBlock::Publications& publications, const CBlockIndex& blockIndexPrev)
{
    VeriBlock::AltProof altproof;
    altproof.atv = VeriBlock::ATV::fromVbkEncoding(publications.atv);
    altproof.containing = cast(blockIndexPrev.nHeight + 1, blockIndexPrev.GetBlockHeader());

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

bool forEachPopTx(
    CBlock& block,
    std::function<bool(const VeriBlock::Publications&, VeriBlock::ValidationState&)> onPublications,
    std::function<bool(const VeriBlock::Context&, TxValidationState&)> onContext,
    BlockValidationState& state)
{
    TxValidationState stx;
    bool ret = forEachPopTx(block, std::move(onPublications), std::move(onContext), stx);
    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, stx.GetRejectReason(),
        "[" + block.GetHash().GetHex() + "] pop block invalid: " + stx.GetDebugMessage());
}

bool onPopTx(
    const CTransaction& tx,
    std::function<bool(const VeriBlock::Publications&, VeriBlock::ValidationState&)> onPublications,
    std::function<bool(const VeriBlock::Context&, TxValidationState&)> onContext,
    TxValidationState& state)
{
    VeriBlock::ValidationState instate;
    TxValidationState txInstate;
    VeriBlock::Publications publications;
    VeriBlock::Context context;
    VeriBlock::PopTxType type = VeriBlock::PopTxType::UNKNOWN;
    ScriptError serror = ScriptError::SCRIPT_ERR_UNKNOWN_ERROR;
    if (!VeriBlock::getService<VeriBlock::PopService>().parsePopTx(MakeTransactionRef(tx), &serror, &publications, &context, &type)) {
        return state.Invalid(
            TxValidationResult::TX_BAD_POP_DATA,
            "pop-tx-invalid-script",
            "[" + tx.GetHash().ToString() + "] scriptSig of POP tx is invalid: " + ScriptErrorString(serror));
    }


    switch (type) {
    case VeriBlock::PopTxType::CONTEXT: {
        if (!onContext(context, txInstate)) {
            return state.Invalid(
                TxValidationResult::TX_BAD_POP_DATA,
                "pop-tx-updatecontext-failed",
                "[" + tx.GetHash().ToString() + "] updatecontext failed: " + txInstate.GetRejectReason() + ", " + txInstate.GetDebugMessage());
        }
        break;
    }
    case VeriBlock::PopTxType::PUBLICATIONS: {
        if (!onPublications(publications, instate)) {
            return state.Invalid(
                TxValidationResult::TX_BAD_POP_DATA,
                "pop-tx-publications-failed",
                "[" + tx.GetHash().ToString() + "] publications failed: " + instate.GetRejectReason() + ", " + instate.GetDebugMessage());
        }
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

bool forEachPopTx(
    const CBlock& block,
    std::function<bool(const VeriBlock::Publications&, VeriBlock::ValidationState&)> onPublications,
    std::function<bool(const VeriBlock::Context&, TxValidationState&)> onContext,
    TxValidationState& state)
{
    for (const auto& tx : block.vtx) {
        if (!VeriBlock::isPopTx(*tx)) {
            continue;
        }

        if (!onPopTx(*tx, onPublications, onContext, state)) {
            return false;
        }
    }

    return true;
}

} // namespace


namespace VeriBlock {

const static std::string DATABASE_NAME = "alt-integration-db";

PopServiceImpl::PopServiceImpl(bool doinit) : pop(btc_param, vbk_param, btc_e_repo, vbk_e_repo, alt_param), stateManager(DATABASE_NAME)
{
    // for mocking purposes
    if (!doinit) return;
}

bool PopServiceImpl::commitPayloads(const CBlockIndex& prev, const CBlock& connecting, TxValidationState& state)
{
    std::lock_guard<std::mutex> lock(mutex);

    // TODO commit StateChange changes
    std::shared_ptr<StateChange> change = stateManager.newChange();

    bool ret = forEachPopTx(
        connecting,
        [this, &change, &prev](const Publications& publications, VeriBlock::ValidationState& state) -> bool {
            // handle publications changes
            VeriBlock::Payloads payloads = cast(publications, prev);
            return pop.addPayloads(payloads, *change, state);
        },
        [this](const Context& context, TxValidationState& state) -> bool {
            // handle context changes
            return this->doUpdateContext(context.vbk, context.btc, state);
        },
        state);

    if (ret) {
        // block is valid
        pop.commit();
        stateManager.commit(change);
    } else {
        pop.rollback(*change);
    }


    return ret;
}

bool PopServiceImpl::removePayloads(const CBlockIndex& connecting, TxValidationState& state)
{
    std::lock_guard<std::mutex> lock(mutex);

    // TODO commit StateChange changes
    auto change = stateManager.newChange();

    pop.rollback(*change);

    return forEachPopTx(
        connecting.GetBlockHeader(),
        [this, &change, &connecting](const Publications& publications, VeriBlock::ValidationState&) -> bool {
            // remove publications
            VeriBlock::Payloads payloads = cast(publications, *connecting.pprev);
            this->pop.removePayloads(payloads, *change);
            return true;
        },
        [this, &state](const Context& context, TxValidationState&) -> bool {
            // remove context
            this->doRemoveContext(context.vbk, context.btc);
            return true;
        },
        state);
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

void PopServiceImpl::doRemoveContext(const std::vector<std::vector<uint8_t>>& veriBlockBlocks, const std::vector<std::vector<uint8_t>>& bitcoinBlocks)
{
    VeriBlock::ValidationState instate;
    // remove BTC blocks
    VeriBlock::removeBlocks(pop.btc(), bitcoinBlocks);
    // remove VBK blocks
    VeriBlock::removeBlocks(pop.vbk(), veriBlockBlocks);
}

bool PopServiceImpl::doUpdateContext(const std::vector<std::vector<uint8_t>>& veriBlockBlocks, const std::vector<std::vector<uint8_t>>& bitcoinBlocks, TxValidationState& state)
{
    VeriBlock::ValidationState instate;
    // apply BTC blocks
    if (!VeriBlock::addBlocks(pop.btc(), bitcoinBlocks, instate)) {
        return state.Invalid(
            TxValidationResult::TX_BAD_POP_DATA,
            instate.GetRejectReason(),
            "BTC context is invalid: " + instate.GetDebugMessage());
    }

    // apply VBK blocks
    if (!VeriBlock::addBlocks(pop.vbk(), veriBlockBlocks, instate)) {
        return state.Invalid(
            TxValidationResult::TX_BAD_POP_DATA,
            instate.GetRejectReason(),
            "VBK context is invalid: " + instate.GetDebugMessage());
    }

    return true;
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
        return state.Invalid(TxValidationResult::TX_BAD_POP_DATA, "pop-tx-altchain-id", "wrong altchain ID. Expected " + std::to_string(expected) + ", got " + std::to_string(altChainIdentifier.unwrap()));
    }

    if (!CheckProofOfWork(popEndorsementHeader.GetHash(), popEndorsementHeader.nBits, params)) {
        return state.Invalid(TxValidationResult::TX_BAD_POP_DATA, "pop-tx-endorsed-block-pow", "endorsed block has invalid PoW: " + popEndorsementHeader.GetHash().GetHex());
    }

    return true;
}

bool PopServiceImpl::addTemporaryPayloads(const CTransactionRef& tx, const CBlockIndex& pindexPrev, const Consensus::Params& params, TxValidationState& state)
{
    return addTemporaryPayloadsImpl(*this, tx, pindexPrev, params, state);
}

bool addTemporaryPayloadsImpl(PopServiceImpl& pop, const CTransactionRef& tx, const CBlockIndex& pindexPrev, const Consensus::Params& params, TxValidationState& state)
{
    //TODO: need locking

    bool isValid = txPopValidation(pop, tx, pindexPrev, params, state, pop.temporaryPayloadsIndex);
    if (isValid) {
        pop.temporaryPayloadsIndex++;
    }

    return isValid;
}

void PopServiceImpl::clearTemporaryPayloads()
{
    // TODO commit StateChange changes
    auto change = stateManager.newChange();
    this->pop.rollback(*change);
}

bool txPopValidation(PopServiceImpl& pop, const CTransactionRef& tx, const CBlockIndex& pindexPrev, const Consensus::Params& params, TxValidationState& state, uint32_t heightIndex) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    onPopTx(
        *tx, [&pop, &tx, &params, &pindexPrev](const Publications& publications, VeriBlock::ValidationState& state) {
              // handle publications changes
              PublicationData popEndorsement;
              pop.getPublicationsData(publications, popEndorsement);

              CBlockHeader popEndorsementHeader;

              try {
                  popEndorsementHeader = headerFromBytes(popEndorsement.header);
              } catch (const std::exception& e) {
                  return state.Invalid("pop-tx-alt-block-invalid", "[" + tx->GetHash().ToString() + "] can't deserialize endorsed block header: " + e.what());
              }

              TxValidationState txState;
              if (!pop.determineATVPlausibilityWithBTCRules(AltchainId(popEndorsement.identifier), popEndorsementHeader, params, txState)) {
                  return state.Invalid("pop-tx-alt-block-invalid", "[" + tx->GetHash().ToString() + "]: " + txState.GetRejectReason() + ", " + txState.GetDebugMessage());
              }

              AssertLockHeld(cs_main);
              const CBlockIndex* popEndorsementIdnex = LookupBlockIndex(popEndorsementHeader.GetHash());
              if (popEndorsementIdnex == nullptr) {
                  return state.Invalid("pop-tx-endorsed-block-not-known-orphan-block", "[" + tx->GetHash().ToString() + "] can not find endorsed block index: " + popEndorsementHeader.GetHash().ToString());
              }
              const CBlockIndex* ancestor = pindexPrev.GetAncestor(popEndorsementIdnex->nHeight);
              if (ancestor == nullptr || ancestor->GetBlockHash() != popEndorsementIdnex->GetBlockHash()) {
                  return state.Invalid("pop-tx-endorsed-block-not-from-this-chain", "[" + tx->GetHash().ToString() + "] can not find endorsed block in the chain: " + popEndorsementHeader.GetHash().ToString());
              }
              auto config = VeriBlock::getService<VeriBlock::Config>();

              if (pindexPrev.nHeight + 1 - popEndorsementIdnex->nHeight > config.POP_REWARD_SETTLEMENT_INTERVAL) {
                  return state.Invalid("pop-tx-endorsed-block-too-old",
                                       "[" + tx->GetHash().ToString() +  "] endorsed block is too old for this chain: " + popEndorsementIdnex->GetBlockHash().GetHex() +
                      ". (last block height: " + std::to_string(pindexPrev.nHeight + 1) + ", endorsed block height: " 
                      + std::to_string(popEndorsementIdnex->nHeight) + ", settlement interval: " +std::to_string(config.POP_REWARD_SETTLEMENT_INTERVAL)+")");
              }

              try {
                  VeriBlock::Payloads payloads = cast(publications, pindexPrev);

                  //TODO commit StateChange changes
                  auto change = pop.getStateManager().newChange();
                  
                  if (!pop.getPopManager().addPayloads(payloads, *change, state)) {
                      return state.Invalid(
                          "pop-tx-add-payloads-failed",
                              "[" + tx->GetHash().ToString() + "] addPayloads failed: " + state.GetRejectReason() + ", " + state.GetDebugMessage());
                  }
              } catch (const PopServiceException& e) {
                  return state.Invalid(
                      "pop-tx-add-payloads-failed",
                          "[" + tx->GetHash().ToString() + "] addPayloads failed: " + e.what());
              } },
        [&pop](const Context& context, TxValidationState& state) {
            // handle context changes
            return pop.doUpdateContext(context.vbk, context.btc, state);

            //            ) {
            //                return state.Invalid(
            //                    TxValidationResult::TX_BAD_POP_DATA,
            //                    "pop-tx-updatecontext-failed",
            //                    strprintf("[%s] updatecontext failed: %s", tx->GetHash().ToString(), state.GetDebugMessage()));
            //            }
        },
        state);
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
