/*
 * Copyright (c) 2026 ns-3 RPL module contributors
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef RPL_HELPER_H
#define RPL_HELPER_H

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
 * stack, then mark the border router with SetRoot() once its global address
 * exists (the DODAGID is taken from that address).
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
     * @brief Make a node the DODAG root.
     *
     * Call this after global addresses have been assigned, since the DODAGID is
     * the node's first global address.
     *
     * @param node the node to promote
     */
    void SetRoot(Ptr<Node> node) const;

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
