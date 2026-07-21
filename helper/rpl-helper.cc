/*
 * Copyright (c) 2026 ns-3 RPL module contributors
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "rpl-helper.h"

#include "ns3/ipv6-l3-protocol.h"
#include "ns3/log.h"
#include "ns3/node.h"
#include "ns3/rpl-routing-protocol.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("RplHelper");

RplHelper::RplHelper()
{
    m_agentFactory.SetTypeId("ns3::rpl::RplRoutingProtocol");
}

RplHelper::RplHelper(const RplHelper& o)
    : m_agentFactory(o.m_agentFactory)
{
}

RplHelper*
RplHelper::Copy() const
{
    return new RplHelper(*this);
}

Ptr<Ipv6RoutingProtocol>
RplHelper::Create(Ptr<Node> node) const
{
    Ptr<rpl::RplRoutingProtocol> agent = m_agentFactory.Create<rpl::RplRoutingProtocol>();
    node->AggregateObject(agent);
    return agent;
}

void
RplHelper::Set(std::string name, const AttributeValue& value)
{
    m_agentFactory.Set(name, value);
}

void
RplHelper::SetRoot(Ptr<Node> node) const
{
    Ptr<rpl::RplRoutingProtocol> rpl = node->GetObject<rpl::RplRoutingProtocol>();
    NS_ASSERT_MSG(rpl, "RPL is not installed on node " << node->GetId());
    rpl->SetAsRoot();
}

int64_t
RplHelper::AssignStreams(NodeContainer c, int64_t stream)
{
    int64_t currentStream = stream;
    for (auto i = c.Begin(); i != c.End(); i++)
    {
        Ptr<rpl::RplRoutingProtocol> rpl = (*i)->GetObject<rpl::RplRoutingProtocol>();
        if (rpl)
        {
            currentStream += rpl->AssignStreams(currentStream);
        }
    }
    return currentStream - stream;
}

} // namespace ns3
