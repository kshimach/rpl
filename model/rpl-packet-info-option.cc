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
#include "ns3/simulator.h"

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
      m_lastProcessedTime(Time::Min())
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

    // Packet has no way to patch bytes in place, so the option is read out
    // through a fragment covering everything from here to the end of the
    // packet, updated, and spliced back onto the untouched prefix.
    Ptr<Packet> tail = packet->CreateFragment(offset, packet->GetSize() - offset);
    RplPacketInfoHeader rpi;
    tail->RemoveHeader(rpi);

    // How far the caller's option walk advances past this option. Parsed
    // before any of the early returns below rather than assumed to be the
    // bare six octets: an option carrying sub-TLVs (RFC 6553 section 3) is
    // longer than that, and reporting six for one of those would have the
    // caller read the first sub-TLV as if it were the next option.
    uint8_t optionSize = static_cast<uint8_t>(rpi.GetSerializedSize());

    if (rpi.IsMalformed())
    {
        // The Opt Data Len this option arrived with is unusable, so nothing
        // in it can be checked or rewritten (@see
        // RplPacketInfoHeader::Deserialize() for what makes one unusable).
        // RFC 6553 section 3 has the two high order bits of the Option Type
        // set to '01', which per RFC 8200 section 4.2 means a receiver that
        // cannot process the option discards the packet; the same is the
        // only safe answer for one it can recognise but not parse. Only the
        // Option Type and Opt Data Len octets were really read, so that is
        // what the caller is told it may skip -- and it stops walking the
        // option list at all once isDropped is set.
        NS_LOG_WARN("Dropping a packet whose RPL Option could not be parsed");
        isDropped = true;
        return 2;
    }

    // Ipv6L3Protocol::Receive() walks the Hop-by-Hop chain once itself and,
    // for a packet addressed to this node, a second time inside
    // LocalDeliver(); a packet tag would not reliably tell the two calls
    // apart, since nothing guarantees it survives this node handing the
    // packet onward if it turns out to need forwarding instead. The packet's
    // own Uid, compared against the last one this node actually acted on,
    // does -- except a Uid alone cannot tell that pair apart from a packet
    // that genuinely loops back to this node later: RPL's own forwarding
    // (RplIpv6ExtensionSourceRouting::Process()'s CreateFragment()-based
    // rebuild) keeps the original Uid across every hop, so a looped-back
    // packet reintroduces a Uid this node already saw. The Receive()/
    // LocalDeliver() pair for one packet always falls in the same simulation
    // event, so requiring the time to match too, not just the Uid, still
    // catches that pair while letting a same-Uid packet arriving at a later
    // time (a loop) through -- which is exactly the case RFC 6550 section
    // 11.2's rank-inconsistency check exists to catch.
    Time now = Simulator::Now();
    if (packet->GetUid() == m_lastProcessedUid && now == m_lastProcessedTime)
    {
        return optionSize;
    }
    m_lastProcessedUid = packet->GetUid();
    m_lastProcessedTime = now;

    Ptr<RplRoutingProtocol> rpl = m_node->GetObject<RplRoutingProtocol>();
    if (!rpl)
    {
        return optionSize;
    }

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
        // RFC 6550 section 11.2.2.2, verbatim: "One inconsistency along the
        // path is not considered a critical error and the packet may
        // continue. However, a second detection along the path of the same
        // packet should not occur and the packet MUST be dropped. This
        // process is controlled by the Rank-Error bit associated with the
        // packet. When an inconsistency is detected on a packet, if the
        // Rank-Error bit was not set, then the Rank-Error bit is set. If it
        // was set the packet MUST be discarded and the Trickle timer MUST be
        // reset." The state that decides "confirmed" is carried on the
        // packet itself (its Rank-Error bit as received, RFC 6550 section
        // 11.2's "A host or RPL leaf node MUST set the 'R' bit to 0" is what
        // guarantees every packet starts at 0), not anything this node
        // remembers between packets.
        if (rpi.GetRankError())
        {
            // ns3::Ipv6Extension::Process() would drop the packet outright
            // here. ns3::Ipv6Option::Process() has no equivalent of that
            // stopProcessing output, only isDropped, which
            // Ipv6Extension::ProcessOptions() never turns into one either:
            // setting it below only traces the packet as dropped, and does
            // not stop it from still being delivered or forwarded. See
            // design-constraints.md for the full account; the Trickle reset
            // this confirmed case triggers is what gets a corrected DIO out
            // to whoever is on the stale route sooner.
            NS_LOG_WARN("Rank inconsistency confirmed (Rank-Error bit already set on arrival) ("
                        << (down ? "down" : "up") << ", sender rank " << senderRank
                        << ", own rank " << ownRank << ")");
            isDropped = true;
            rpl->NotifyRankInconsistency();
        }
        else
        {
            NS_LOG_LOGIC("Rank inconsistency flagged (" << (down ? "down" : "up")
                                                         << ", sender rank " << senderRank
                                                         << ", own rank " << ownRank << ")");
            rpi.SetRankError(true);
        }
    }

    rpi.SetSenderRank(ownRank);
    tail->AddHeader(rpi);

    packet->RemoveAtEnd(packet->GetSize() - offset);
    packet->AddAtEnd(tail);

    return optionSize;
}

} // namespace rpl
} // namespace ns3
