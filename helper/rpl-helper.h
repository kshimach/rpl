/*
 * Copyright (c) 2026 ns-3 RPL module contributors
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef RPL_HELPER_H
#define RPL_HELPER_H

#include "ns3/ipv6-address.h"
#include "ns3/ipv6-routing-helper.h"
#include "ns3/node-container.h"
#include "ns3/object-factory.h"

namespace ns3
{

/**
 * @ingroup rpl
 *
 * @brief Helper installing rpl::RplRoutingProtocol on nodes.
 *
 * Pass it to InternetStackHelper::SetRoutingHelper() before installing the
 * stack, then mark the border router with SetRoot(), giving it the GUA or
 * ULA prefix it owns and disseminates over the DODAG (RFC 6550 section
 * 6.7.10's Prefix Information option) for every other node's SLAAC (RFC
 * 4862) address. The root builds its own DODAGID from that same prefix; no
 * node's global address is assigned ahead of time by the simulation script.
 */
class RplHelper : public Ipv6RoutingHelper
{
  public:
    RplHelper();

    /**
     * @brief Copy constructor, used by the Ipv6RoutingHelper machinery.
     * @param o object to copy
     */
    RplHelper(const RplHelper& o);

    // Deleted: assignment is not supported by the Ipv6RoutingHelper contract.
    RplHelper& operator=(const RplHelper&) = delete;

    RplHelper* Copy() const override;
    Ptr<Ipv6RoutingProtocol> Create(Ptr<Node> node) const override;

    /**
     * @brief Set an attribute on the RPL routing protocols created afterwards.
     * @param name attribute name
     * @param value attribute value
     */
    void Set(std::string name, const AttributeValue& value);

    /**
     * @brief Make a node the DODAG root, owning the given prefix.
     *
     * The node builds its own DODAGID from prefix the same way SLAAC would
     * (RootPrefix/RootPrefixLength attributes on RplRoutingProtocol), and
     * Duplicate Address Detection runs on it exactly as it would on any
     * other autoconfigured address -- the DODAG only actually starts once
     * that finishes, asynchronously, not when this call returns.
     *
     * @param node the node to promote
     * @param prefix the GUA or ULA prefix this DODAG runs on
     * @param prefixLength the prefix length, in bits
     */
    void SetRoot(Ptr<Node> node, Ipv6Address prefix, uint8_t prefixLength = 64) const;

    /**
     * @brief Assign fixed streams to the random variables used by RPL.
     * @param c the nodes to act on
     * @param stream first stream index to use
     * @return the number of stream indices assigned
     */
    int64_t AssignStreams(NodeContainer c, int64_t stream);

  private:
    ObjectFactory m_agentFactory; //!< creates the routing protocol instances
};

} // namespace ns3

#endif /* RPL_HELPER_H */
