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

    // A Hop-by-hop Route (AODV-RPL RFC 9854 sections 6.2.3/6.4.3, P2P-RPL
    // RFC 6997 sections 9.6/9.7) is its own, separate routing decision,
    // kept alive by its own Default Lifetime rather than by the RREQ-
    // Instance's/temporary DAG's own membership -- RFC 6997 section 7 has
    // a Target unconditionally leave the temporary DAG at its 'L'
    // deadline, typically well before the (often much longer) route it
    // discovered is meant to expire, so this node's own membership under
    // rpi.GetInstanceId() may already be gone by the time data actually
    // flows over the route it found. The rank-consistency check below has
    // no meaning for that state at all -- it exists to catch a route to
    // the wrong root, something a Hop-by-hop Route's own, independently
    // maintained next-hop table cannot suffer from -- so it is skipped
    // entirely here, the same way it never runs at all for an H=0 source-
    // routed packet (@see RplRoutingProtocol::PrepareOutgoingPacket()'s
    // own "no RPL Option" branch). SenderRank is deliberately left
    // untouched rather than refreshed to this node's own rank: nothing
    // downstream ever reads it once Hop-by-hop routing has taken over for
    // this Instance, since every hop takes this same early return.
    //
    // What this actually guards against, concretely: this module's own
    // isDropped, below, only traces a confirmed rank inconsistency rather
    // than enforcing it (@see design-constraints.md), so an expired
    // membership's GetRankForInstance() answering RPL_INFINITE_RANK does
    // not by itself cause a Hop-by-hop Route's packets to be dropped --
    // confirmed by temporarily removing this early return and finding
    // RplP2pHopByHopRouteOutlivesTemporaryDagTestCase still passed. What
    // it does prevent is a downstream router that still holds a live,
    // ordinary membership under the same reused-looking instanceId
    // reading the rewritten (and, once one hop's own membership is gone,
    // permanently RPL_INFINITE_RANK) SenderRank as a genuine
    // inconsistency and resetting that unrelated DODAG's Trickle timer
    // over it (@see NotifyRankInconsistency()) -- noise this module has
    // no reason to accept just because a Hop-by-hop Route happens to be
    // using the same Instance space.
    // rpi.GetInstanceId() carries RFC 6550 section 5.1's Local RPLInstanceID
    // 'D' flag as received (set for AODV-RPL's upward route, RFC 9854
    // section 6.2.3), but a stored Hop-by-hop Route's own instanceId is
    // always kept D=0 (@see RplRoutingProtocol::RouteInput()'s matching
    // comment); masked off here so a D=1 packet still matches it.
    uint8_t hopByHopInstanceId = rpi.GetInstanceId();
    if (hopByHopInstanceId & RPL_LOCAL_INSTANCE_FLAG)
    {
        hopByHopInstanceId &= static_cast<uint8_t>(~RPL_LOCAL_INSTANCE_D_FLAG);
    }
    if (rpl->HasHopByHopRoute(hopByHopInstanceId, ipv6Header.GetDestination()))
    {
        tail->AddHeader(rpi);
        packet->RemoveAtEnd(packet->GetSize() - offset);
        packet->AddAtEnd(tail);
        return optionSize;
    }

    // RFC 6550 section 11.2.2.3: a Forwarding-Error bounce leaves the 'O'
    // (down) bit untouched even though the packet is, for this one hop,
    // physically moving back up towards the root -- so the ordinary rank-
    // consistency check just below, which assumes 'O' truthfully describes
    // the packet's direction, would misread this hop's own sender (a child,
    // necessarily of higher rank) as a down-direction inconsistency and
    // flag or drop a packet that is behaving exactly as designed. Handled
    // and returned before that check runs, the same way the Hop-by-hop
    // Route case above it is: "the node MUST remove the routing states that
    // caused forwarding to that neighbour, clear the Forwarding-Error bit,
    // and attempt to send the packet again" -- RouteInput()'s own Storing
    // mode block does the "attempt again" half, immediately after this
    // option processing step returns, off the same downwardRoutes state
    // NotifyForwardingError() just updated.
    if (rpi.GetForwardingError())
    {
        rpl->NotifyForwardingError(rpi.GetInstanceId(), ipv6Header.GetDestination());
        rpi.SetForwardingError(false);
        tail->AddHeader(rpi);
        packet->RemoveAtEnd(packet->GetSize() - offset);
        packet->AddAtEnd(tail);
        return optionSize;
    }

    bool down = rpi.GetDown();
    uint16_t senderRank = rpi.GetSenderRank();
    // Scoped to the DODAG this packet's own RPLInstanceID names, not
    // whichever one is this node's base: a node holding more than one
    // concurrent membership (contrib/rpl's own extension beyond a single
    // DODAG) still owns a distinct rank in each, and this packet only ever
    // belongs to one of them. The RPI carries no DODAGID, so this is
    // resolved by RPLInstanceID alone (@see
    // RplRoutingProtocol::FindDodagByInstance()); a node with only the base
    // DODAG sees no behaviour change (GetRankForInstance(RPL_DEFAULT_INSTANCE)
    // is GetRank()).
    uint16_t ownRank = rpl->GetRankForInstance(rpi.GetInstanceId());

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
            rpl->NotifyRankInconsistency(rpi.GetInstanceId());
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
