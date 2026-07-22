/*
 * Copyright (c) 2026 ns-3 RPL module contributors
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "rpl-packet-info-option.h"

#include "rpl-header.h"
#include "rpl-routing-protocol.h"

#include "ns3/log.h"
#include "ns3/node.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("RplIpv6OptionRpl");

namespace rpl
{

NS_OBJECT_ENSURE_REGISTERED(RplIpv6OptionRpl);

TypeId
RplIpv6OptionRpl::GetTypeId()
{
    static TypeId tid = TypeId("ns3::rpl::RplIpv6OptionRpl")
                            .SetParent<Ipv6Option>()
                            .SetGroupName("Rpl")
                            .AddConstructor<RplIpv6OptionRpl>();
    return tid;
}

RplIpv6OptionRpl::RplIpv6OptionRpl()
    : m_lastProcessedUid(0),
      m_rankErrorSignaled(false)
{
}

RplIpv6OptionRpl::~RplIpv6OptionRpl()
{
}

void
RplIpv6OptionRpl::SetNode(Ptr<Node> node)
{
    m_node = node;
    Ipv6Option::SetNode(node);
}

uint8_t
RplIpv6OptionRpl::GetOptionNumber() const
{
    return RPL_HBH_OPTION_TYPE;
}

uint8_t
RplIpv6OptionRpl::Process(Ptr<Packet> packet,
                          uint8_t offset,
                          const Ipv6Header& ipv6Header,
                          bool& isDropped)
{
    NS_LOG_FUNCTION(this << packet << +offset << ipv6Header << isDropped);

    // Ipv6L3Protocol::Receive() walks the Hop-by-Hop chain once itself and,
    // for a packet addressed to this node, a second time inside
    // LocalDeliver(); a packet tag would not reliably tell the two calls
    // apart, since nothing guarantees it survives this node handing the
    // packet onward if it turns out to need forwarding instead. The packet's
    // own Uid, compared against the last one this node actually acted on,
    // does: it is stable across both calls of the same Receive(), and this
    // object is per node, so a Uid that happens to reappear at another node
    // (or a later, unrelated packet at this one) never collides with what
    // this node itself last handled.
    if (packet->GetUid() == m_lastProcessedUid)
    {
        return RplPacketInfoHeader().GetSerializedSize();
    }
    m_lastProcessedUid = packet->GetUid();

    Ptr<RplRoutingProtocol> rpl = m_node->GetObject<RplRoutingProtocol>();
    if (!rpl)
    {
        return RplPacketInfoHeader().GetSerializedSize();
    }

    // Packet has no way to patch bytes in place, so the option is read out
    // through a fragment covering everything from here to the end of the
    // packet, updated, and spliced back onto the untouched prefix.
    Ptr<Packet> tail = packet->CreateFragment(offset, packet->GetSize() - offset);
    RplPacketInfoHeader rpi;
    tail->RemoveHeader(rpi);

    bool down = rpi.GetDown();
    uint16_t senderRank = rpi.GetSenderRank();
    uint16_t ownRank = rpl->GetRank();

    // RFC 6550 section 11.2: moving up, the previous hop should be further
    // from the root, i.e. of higher rank, than this one; moving down, the
    // opposite. Anything else is a rank inconsistency, e.g. a stale route or
    // a loop.
    bool inconsistent = down ? (senderRank >= ownRank) : (senderRank <= ownRank);

    if (inconsistent)
    {
        if (m_rankErrorSignaled)
        {
            // RFC 6550 section 11.2: a second inconsistency in a row is
            // treated as a confirmed loop rather than a transient one, and
            // ns3::Ipv6Extension::Process() would drop the packet outright
            // here. ns3::Ipv6Option::Process() has no equivalent of that
            // stopProcessing output, only isDropped, which
            // Ipv6Extension::ProcessOptions() never turns into one either:
            // setting it below only traces the packet as dropped, and does
            // not stop it from still being delivered or forwarded. See
            // design-constraints.md for the full account; the rank error is
            // still flagged, and Trickle still reset, which is what gets a
            // corrected DIO out to whoever is on the stale route sooner.
            NS_LOG_WARN("Rank inconsistency confirmed for the second packet in a row ("
                        << (down ? "down" : "up") << ", sender rank " << senderRank
                        << ", own rank " << ownRank << ")");
            isDropped = true;
        }
        else
        {
            NS_LOG_LOGIC("Rank inconsistency flagged (" << (down ? "down" : "up")
                                                         << ", sender rank " << senderRank
                                                         << ", own rank " << ownRank << ")");
            m_rankErrorSignaled = true;
            rpl->NotifyRankInconsistency();
        }
        rpi.SetRankError(true);
    }
    else
    {
        m_rankErrorSignaled = false;
    }

    rpi.SetSenderRank(ownRank);
    tail->AddHeader(rpi);

    packet->RemoveAtEnd(packet->GetSize() - offset);
    packet->AddAtEnd(tail);

    return rpi.GetSerializedSize();
}

} // namespace rpl
} // namespace ns3
