/*
 * Copyright (c) 2026 ns-3 RPL module contributors
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Processing of the RFC 6554 source routing header, registered on the node's
 * Ipv6ExtensionRoutingDemux the way Ipv6ExtensionLooseRouting registers RH0.
 */

#ifndef RPL_SOURCE_ROUTING_EXTENSION_H
#define RPL_SOURCE_ROUTING_EXTENSION_H

#include "ns3/ipv6-extension.h"

namespace ns3
{
namespace rpl
{

/**
 * @ingroup rpl
 *
 * @brief IPv6 Extension Routing: RFC 6554, Type 3 (Source Routing Header).
 *
 * Registered on a node's Ipv6ExtensionRoutingDemux, this is invoked by the
 * core's Ipv6ExtensionRouting dispatcher whenever a packet addressed to this
 * node carries a Routing Header of type 3: RPL_RH_TYPE_SRH. The algorithm is
 * RFC 6554 section 4.1's, the one Ipv6ExtensionLooseRouting already runs for
 * RH0 in this same ns-3 core, since with CmprI, CmprE and Pad fixed at zero
 * the two headers are processed identically; only the routing type and the
 * meaning of the four bytes after Segments Left differ, and both are zero on
 * the wire in this implementation.
 *
 * Processing swaps the current destination into the address list and reads
 * the next one out, so the address a router is visited under is always its
 * own; the packet is then re-injected through RouteOutput() and sent on its
 * way, exactly as if it had just originated. This runs only at nodes the
 * packet is currently addressed to, which is every hop of the path in turn,
 * so RplRoutingProtocol never needs to inspect this header itself.
 */
class RplIpv6ExtensionSourceRouting : public Ipv6ExtensionRouting
{
  public:
    /**
     * @brief Routing type, RFC 6554 section 3.
     */
    static const uint8_t TYPE_ROUTING = 3;

    /**
     * @brief Get the type ID.
     * @return the object TypeId
     */
    static TypeId GetTypeId();

    RplIpv6ExtensionSourceRouting();
    ~RplIpv6ExtensionSourceRouting() override;

    uint8_t GetTypeRouting() const override;
    Ipv6ExtensionRoutingHeader* GetExtensionRoutingHeaderPtr() override;

    uint8_t Process(Ptr<Packet>& packet,
                    uint8_t offset,
                    const Ipv6Header& ipv6Header,
                    Ipv6Address dst,
                    uint8_t* nextHeader,
                    bool& stopProcessing,
                    bool& isDropped,
                    Ipv6L3Protocol::DropReason& dropReason) override;
};

} // namespace rpl
} // namespace ns3

#endif /* RPL_SOURCE_ROUTING_EXTENSION_H */
