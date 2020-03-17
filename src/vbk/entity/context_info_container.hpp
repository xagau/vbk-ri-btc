#ifndef BITCOIN_SRC_VBK_ENTITY_CONTEXT_INFO_CONTAINER_HPP
#define BITCOIN_SRC_VBK_ENTITY_CONTEXT_INFO_CONTAINER_HPP

#include "vbk/config.hpp"
#include "vbk/service_locator.hpp"
#include <hash.h>
#include <uint256.h>

namespace VeriBlock {

struct ContextInfoContainer {
    int32_t height = 0;
    KeystoneArray keystones{};
    uint256 txMerkleRoot{};

    explicit ContextInfoContainer() = default;

    explicit ContextInfoContainer(int height, const KeystoneArray& keystones, const uint256& txMerkleRoot)
    {
        this->height = height;
        this->keystones = keystones;
        this->txMerkleRoot = txMerkleRoot;
    }

    uint256 getUnauthenticatedHash() const
    {
        auto unauth = getUnauthenticated();
        return Hash(unauth.begin(), unauth.end());
    }

    std::vector<uint8_t> getUnauthenticated() const
    {
        std::vector<uint8_t> ret(4, 0);

        /// put height
        int i = 0;
        ret[i++] = (height & 0xff000000u) >> 24u;
        ret[i++] = (height & 0x00ff0000u) >> 16u;
        ret[i++] = (height & 0x0000ff00u) >> 8u;
        ret[i++] = (height & 0x000000ffu) >> 0u;

        /// put keystones
        ret.reserve(keystones.size() * 32);
        for (const uint256& keystone : keystones) {
            ret.insert(ret.end(), keystone.begin(), keystone.end());
        }

        return ret;
    }

    std::vector<uint8_t> getAuthenticated() const
    {
        auto v = this->getUnauthenticated();
        v.insert(v.end(), txMerkleRoot.begin(), txMerkleRoot.end());
        return v;
    }
};

} // namespace VeriBlock

#endif //BITCOIN_SRC_VBK_ENTITY_CONTEXT_INFO_CONTAINER_HPP
