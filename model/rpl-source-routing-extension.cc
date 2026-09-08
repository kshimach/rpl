/*
 * Copyright (c) 2026 kawashy
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "rpl-source-routing-extension.h"

#include "rpl-conf.h"
#include "rpl-header.h"
#include "rpl-routing-protocol.h"

#include "ns3/icmpv6-header.h"
#include "ns3/icmpv6-l4-protocol.h"
#include "ns3/ipv6-l3-protocol.h"
#include "ns3/ipv6-route.h"
#include "ns3/ipv6-routing-protocol.h"
#include "ns3/log.h"
#include "ns3/node.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("RplIpv6ExtensionSourceRouting");

namespace rpl
{

NS_OBJECT_ENSURE_REGISTERED(RplIpv6ExtensionSourceRouting);

TypeId
RplIpv6ExtensionSourceRouting::GetTypeId()
{
    static TypeId tid = TypeId("ns3::rpl::RplIpv6ExtensionSourceRouting")
                            .SetParent<Ipv6ExtensionRouting>()
                            .SetGroupName("Rpl")
                            .AddConstructor<RplIpv6ExtensionSourceRouting>();
    return tid;
}

RplIpv6ExtensionSourceRouting::RplIpv6ExtensionSourceRouting()
{
}

RplIpv6ExtensionSourceRouting::~RplIpv6ExtensionSourceRouting()
{
}

uint8_t
RplIpv6ExtensionSourceRouting::GetTypeRouting() const
{
    return TYPE_ROUTING;
}

Ipv6ExtensionRoutingHeader*
RplIpv6ExtensionSourceRouting::GetExtensionRoutingHeaderPtr()
{
    return new RplSourceRoutingHeader();
}

uint8_t
RplIpv6ExtensionSourceRouting::Process(Ptr<Packet>& packet,
                                       uint8_t offset,
                                       const Ipv6Header& ipv6Header,
                                       Ipv6Address dst,
                                       uint8_t* nextHeader,
                                       bool& stopProcessing,
                                       bool& isDropped,
                                       Ipv6L3Protocol::DropReason& dropReason)
{
    NS_LOG_FUNCTION(this << packet << offset << ipv6Header << dst << nextHeader << isDropped);

    // For ICMPv6 Error packets.
    Ptr<Packet> malformedPacket = packet->Copy();
    malformedPacket->AddHeader(ipv6Header);

    // Whatever precedes the Routing Header, e.g. an RPL Option in a
    // Hop-by-Hop header, is not this function's to touch, but it does have
    // to survive onto the packet this hop resends: RFC 6553's Hop-by-Hop
    // option is meant to be examined and updated at every hop of the path,
    // not just the first, and it already was, by its own Process(), earlier
    // in this same dispatch chain. header's next header field still says so
    // regardless of what happens below, so silently dropping it here would
    // leave that claim false on the wire.
    Ptr<Packet> prefix = packet->CreateFragment(0, offset);

    Ptr<Packet> p = packet->Copy();
    p->RemoveAtStart(offset);

    // Copy IPv6 Header: ipv6Header -> ipv6header, so it can be mutated below.
    Buffer tmp;
    tmp.AddAtStart(ipv6Header.GetSerializedSize());
    Buffer::Iterator it = tmp.Begin();
    Ipv6Header ipv6header;
    ipv6Header.Serialize(it);
    ipv6header.Deserialize(it);

    RplSourceRoutingHeader routingHeader;
    p->RemoveHeader(routingHeader);

    if (nextHeader)
    {
        *nextHeader = routingHeader.GetNextHeader();
    }

    Ptr<Ipv6L3Protocol> ipv6 = GetNode()->GetObject<Ipv6L3Protocol>();
    Ptr<Icmpv6L4Protocol> icmpv6 = ipv6->GetIcmpv6();

    Ipv6Address srcAddress = ipv6header.GetSource();
    Ipv6Address destAddress = ipv6header.GetDestination();
    uint8_t hopLimit = ipv6header.GetHopLimit();
    uint8_t segmentsLeft = routingHeader.GetSegmentsLeft();
    uint8_t nbAddress = static_cast<uint8_t>(routingHeader.GetAddresses().size());

    if (segmentsLeft == 0)
    {
        // This node is the packet's real final destination: nothing more to
        // do, let the rest of the extension chain, or the upper layer, run.
        isDropped = false;
        return routingHeader.GetSerializedSize();
    }

    if (segmentsLeft > nbAddress)
    {
        NS_LOG_LOGIC("Malformed header. Drop!");
        // RFC 4443 section 3.4: Pointer is the octet offset within the
        // invoking packet, i.e. malformedPacket -- IPv6 header included --
        // not within packet/offset, which are relative to the start of the
        // extension header chain that follows it. offset + 3 alone (the
        // Segments Left field, 3 bytes into this Routing Header) would point
        // 40 bytes too early, into the IPv6 header itself.
        icmpv6->SendErrorParameterError(malformedPacket,
                                        srcAddress,
                                        Icmpv6Header::ICMPV6_MALFORMED_HEADER,
                                        ipv6Header.GetSerializedSize() + offset + 3);
        dropReason = Ipv6L3Protocol::DROP_MALFORMED_HEADER;
        isDropped = true;
        stopProcessing = true;
        return routingHeader.GetSerializedSize();
    }

    uint8_t nextAddressIndex = nbAddress - segmentsLeft;
    Ipv6Address nextAddress = routingHeader.GetAddress(nextAddressIndex);

    if (nextAddress.IsMulticast() || destAddress.IsMulticast())
    {
        // RFC 6554 section 4.1: neither the destination nor a listed address
        // may be multicast.
        dropReason = Ipv6L3Protocol::DROP_MALFORMED_HEADER;
        isDropped = true;
        stopProcessing = true;
        return routingHeader.GetSerializedSize();
    }

    // RFC 6554 section 4.2: a routing loop is present if the Routing Header
    // names an address assigned to this router twice -- other than the
    // entry Segments Left currently points at, which is not yet meaningful
    // to check here, since it only becomes this router's own address as
    // part of the swap below -- with at least one different address between
    // the two. Ordinary forwarding along the DODAG never produces this: the
    // root computes the whole path in one shot from the DAOs it collected,
    // so it can only happen if that path is stale (a parent changed after
    // the root built it) or was tampered with.
    {
        bool sawLocalAddress = false;
        bool sawOtherSinceLocalAddress = false;
        for (uint8_t i = 0; i < nbAddress; i++)
        {
            if (i == nextAddressIndex)
            {
                continue;
            }

            bool isLocal = false;
            for (uint32_t j = 0; j < ipv6->GetNInterfaces() && !isLocal; j++)
            {
                for (uint32_t k = 0; k < ipv6->GetNAddresses(j); k++)
                {
                    if (ipv6->GetAddress(j, k).GetAddress() == routingHeader.GetAddress(i))
                    {
                        isLocal = true;
                        break;
                    }
                }
            }

            if (isLocal)
            {
                if (sawLocalAddress && sawOtherSinceLocalAddress)
                {
                    NS_LOG_LOGIC("Routing loop: this router's address appears twice. Drop!");
                    // Same Pointer adjustment as the Segments Left check
                    // above: offset is relative to malformedPacket's IPv6
                    // payload, not its start.
                    icmpv6->SendErrorParameterError(malformedPacket,
                                                    srcAddress,
                                                    Icmpv6Header::ICMPV6_MALFORMED_HEADER,
                                                    ipv6Header.GetSerializedSize() + offset + 2);
                    dropReason = Ipv6L3Protocol::DROP_ROUTE_ERROR;
                    isDropped = true;
                    stopProcessing = true;
                    return routingHeader.GetSerializedSize();
                }
                sawLocalAddress = true;
                sawOtherSinceLocalAddress = false;
            }
            else if (sawLocalAddress)
            {
                sawOtherSinceLocalAddress = true;
            }
        }
    }

    if (hopLimit <= 1)
    {
        NS_LOG_LOGIC("Time Exceeded: Hop Limit <= 1. Drop!");
        icmpv6->SendErrorTimeExceeded(malformedPacket, srcAddress, Icmpv6Header::ICMPV6_HOPLIMIT);
        dropReason = Ipv6L3Protocol::DROP_MALFORMED_HEADER;
        isDropped = true;
        stopProcessing = true;
        return routingHeader.GetSerializedSize();
    }

    // RFC 6554 section 4.1: this node was addressed under destAddress, so
    // that is what the current slot is for from now on; the packet moves on
    // addressed to whatever was listed there.
    routingHeader.SetSegmentsLeft(segmentsLeft - 1);
    routingHeader.SetAddress(nextAddressIndex, destAddress);
    ipv6header.SetDestination(nextAddress);
    ipv6header.SetHopLimit(hopLimit - 1);
    p->AddHeader(routingHeader);
    prefix->AddAtEnd(p);
    // The header just rewritten does not necessarily reserialize to the same
    // size: Cmpri()/Cmpre() (RplSourceRoutingHeader's RFC 6554 CmprI/CmprE
    // compression) is recomputed from the address list's current contents
    // every time, so writing destAddress into this slot can change how much
    // of it compresses away. prefix now holds everything that follows the
    // IPv6 header (whatever preceded the Routing Header, unchanged, plus the
    // just-rebuilt Routing Header and the payload behind it), so its size is
    // the new Payload Length.
    ipv6header.SetPayloadLength(prefix->GetSize());

    // Short-circuit: the packet was addressed to us, so it is re-sent to the
    // new destination rather than handed further up the receive path.
    Ptr<Ipv6RoutingProtocol> ipv6rp = ipv6->GetRoutingProtocol();
    NS_ASSERT(ipv6rp);

    // nextAddress is a next hop the root already confirmed is one radio hop
    // away when it built this header (see PrepareOutgoingPacket()'s comment
    // on why the final entry is a global address rather than link-local).
    // RouteOutput() would refuse a global destination as "not on-link"
    // (RplRoutingProtocol::RouteOutput()'s own comment explains why that is
    // the right call for traffic in general), so this goes straight to
    // RouteToNeighbour() instead of through the ordinary routing lookup.
    // Fetch RPL as an aggregate on the node rather than casting
    // GetRoutingProtocol(): when RPL is composed with other protocols the
    // node's routing protocol is an Ipv6ListRouting, and casting that to
    // RplRoutingProtocol would fail, skipping RouteToNeighbour() and letting
    // the fallback RouteOutput() send the final, globally addressed hop up
    // toward the root as "not on-link" instead of to the on-link neighbour.
    Ptr<Ipv6Route> rtentry;
    if (Ptr<rpl::RplRoutingProtocol> rpl = GetNode()->GetObject<rpl::RplRoutingProtocol>())
    {
        // Scoped to the DODAG this source-routed packet's own RPI names,
        // not always the base one: a relay forwarding a downward packet
        // for a non-base DODAG (one CreateLocalDodag() formed) needs that
        // membership's own Parent set, which may sit on a different
        // interface than the base's (RouteToNeighbour()'s own comment on
        // InterfaceForNeighbour()'s single-interface fallback). Falls back
        // to the base-scoped overload when nothing is found, which is
        // this node's own base DODAG in the ordinary, single-DODAG case.
        uint8_t instanceId;
        if (rpl->ReadRpiInstanceId(packet, ipv6header, instanceId))
        {
            rtentry = rpl->RouteToNeighbour(instanceId, nextAddress, ipv6header.GetDestination());
        }
        if (!rtentry)
        {
            rtentry = rpl->RouteToNeighbour(nextAddress, ipv6header.GetDestination());
        }
    }
    if (!rtentry)
    {
        Socket::SocketErrno err;
        rtentry = ipv6rp->RouteOutput(prefix, ipv6header, nullptr, err);
    }
    if (rtentry)
    {
        ipv6->SendRealOut(rtentry, prefix, ipv6header);
    }
    else
    {
        // RFC 6554 section 4.2: "if the IPv6 Destination Address is not
        // on-link, a router MUST drop the datagram and SHOULD send an
        // ICMPv6 Destination Unreachable message with Code 7". Both
        // RouteToNeighbour() and the routing lookup above failed. On a node
        // with at least one started RPL interface this cannot actually
        // happen from nextAddress alone: RouteToNeighbour()'s
        // InterfaceForNeighbour() deliberately treats any address as
        // reachable through that sole interface (see its own comment) since
        // the root, not this hop, is the one that decided nextAddress is one
        // radio hop away -- verifying that again here would just be
        // re-litigating a call this node has no better information to make
        // than the root already did. This is what actually running out of
        // RPL interfaces to send on looks like instead.
        NS_LOG_LOGIC("No route for the next router of the source route. Drop!");
        icmpv6->SendErrorDestinationUnreachable(malformedPacket, srcAddress, RPL_ICMPV6_SRH_ERROR);
        dropReason = Ipv6L3Protocol::DROP_NO_ROUTE;
    }

    // The packet was fully handled by the resend above: stopProcessing must
    // be set, not just isDropped, or Ipv6L3Protocol::LocalDeliver()'s caller
    // loop, which only inspects stopProcessing, keeps walking the untouched
    // copy of the packet it holds and ends up delivering the inner payload to
    // this node's own upper layers too, as if this node, and not the one
    // named in the Routing Header, were the real destination.
    isDropped = true;
    stopProcessing = true;
    return routingHeader.GetSerializedSize();
}

} // namespace rpl
} // namespace ns3
