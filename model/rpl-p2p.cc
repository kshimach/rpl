/*
 * Copyright (c) 2026 ns-3 RPL module contributors
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * P2P-RPL (RFC 6997) route discovery, layered on the core RPL machinery in
 * rpl-routing-protocol.cc the same way rpl-aodv.cc layers AODV-RPL on it --
 * these are methods of RplRoutingProtocol like any other, kept in a
 * translation unit of their own only because rpl-routing-protocol.cc is
 * already some three thousand lines. @see design-constraints.md.
 *
 * Scope: source-routed (H=0) discovery for a single Target, a single Source
 * Route. Hop-by-hop routes (H=1) need storing mode, which this module does
 * not have at all -- the same reason AODV-RPL stays out of H=1 too.
 * @see design-constraints.md.
 */

#include "rpl-conf.h"
#include "rpl-header.h"
#include "rpl-routing-protocol.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("RplP2p");

namespace rpl
{

RplRoutingProtocol::DodagKey
RplRoutingProtocol::DiscoverP2pRoute(Ipv6Address target)
{
    NS_LOG_FUNCTION(this << target);

    DodagKey empty{0, Ipv6Address::GetAny()};

    if (target.IsAny() || IsOwnAddress(target))
    {
        NS_LOG_WARN("Not discovering a P2P-RPL route to " << target << ": not a usable target");
        return empty;
    }

    // The DODAGID of the temporary DAG is one of the Origin's own addresses
    // (RFC 6997 section 6.1), and it has to be routable across the whole
    // discovery, so a link-local will not do -- CreateLocalDodag() uses
    // GetGlobalAddress() for exactly that reason and fails if there is none
    // yet.
    if (GetGlobalAddress().IsAny())
    {
        NS_LOG_WARN("Not discovering a P2P-RPL route to "
                    << target << ": no global address to root the temporary DAG at");
        return empty;
    }

    // A Local RPLInstanceID, unique per DODAGID (RFC 6550 section 5.1) --
    // shared with AODV-RPL's own DiscoverRoute() search, since both root
    // their local instances at this same node's global address and
    // IsJoinedTo() already resolves by the (instanceId, dodagId) pair
    // regardless of which protocol owns the membership.
    uint8_t instanceId = 0;
    bool found = false;
    for (uint8_t candidate = 0; candidate <= RPL_AODV_PREFIX_LENGTH_MASK; candidate++)
    {
        uint8_t local = static_cast<uint8_t>(RPL_LOCAL_INSTANCE_FLAG | candidate);
        if ((local & RPL_LOCAL_INSTANCE_D_FLAG) != 0)
        {
            continue;
        }
        if (!IsJoinedTo(local, GetGlobalAddress()))
        {
            instanceId = local;
            found = true;
            break;
        }
    }
    if (!found)
    {
        NS_LOG_WARN("Not discovering a P2P-RPL route to " << target
                                                           << ": no free Local RPLInstanceID");
        return empty;
    }

    DodagKey key = CreateLocalDodag(instanceId, RPL_MOP_P2P_ROUTE_DISCOVERY);
    if (key.dodagId.IsAny())
    {
        return empty;
    }

    auto it = m_dodags.find(key);
    NS_ASSERT_MSG(it != m_dodags.end(), "CreateLocalDodag() did not leave a membership behind");
    DodagMembership& dodag = it->second;

    // RFC 6997 section 6.1: "the Origin MUST set the MaxRankIncrease
    // parameter to zero to disable local repair of the temporary DAG."
    // CreateDodagMembership() leaves the generic (nonzero) default in place,
    // since it has no way to know this membership is about to become a
    // temporary DAG rather than an ordinary DODAG.
    dodag.maxRankIncrease = 0;

    dodag.p2p.target = target;
    dodag.p2p.isOrigin = true;
    dodag.p2p.isTarget = false;
    dodag.p2p.maxRank = m_p2pMaxRank;
    dodag.p2p.lifetimeField = m_p2pLifetime;
    dodag.p2p.reply = true;
    dodag.p2p.hopByHop = false;
    // Empty at the Origin: "The Origin and Target addresses MUST NOT be
    // included in the Address vector" (RFC 6997 section 7), and only
    // Intermediate Routers append to it (section 9.4).
    dodag.p2p.addressVector.clear();

    // A discovery has to complete within its own 'L' field, so it is paced
    // far faster than the base DODAG's steady-state upkeep -- the same
    // reason AODV-RPL's own local instances use a dedicated Trickle
    // configuration rather than the base DODAG's.
    dodag.dioIntervalMin = m_p2pDioIntervalMin;
    dodag.dioIntervalDoublings = m_p2pDioIntervalDoublings;
    dodag.dioRedundancy = m_p2pDioRedundancy;
    dodag.dioTrickle.SetParameters(dodag.dioIntervalMin,
                                   dodag.dioIntervalDoublings,
                                   dodag.dioRedundancy);
    dodag.dioTrickle.Reset();

    ArmP2pExpiry(dodag, key);

    NS_LOG_INFO("Discovering a P2P-RPL route to " << target << " as Origin of temporary DAG "
                                                   << +instanceId << " at " << key.dodagId);
    return key;
}

void
RplRoutingProtocol::ArmP2pExpiry(DodagMembership& dodag, DodagKey key)
{
    uint32_t seconds = RplP2pLifetimeSeconds(dodag.p2p.lifetimeField);

    dodag.p2p.expiry.SetFunction(&RplRoutingProtocol::P2pInstanceExpired, this);
    dodag.p2p.expiry.SetArguments(key);
    dodag.p2p.expiry.Cancel();
    dodag.p2p.expiry.Schedule(Seconds(seconds));
}

void
RplRoutingProtocol::P2pInstanceExpired(DodagKey key)
{
    NS_LOG_FUNCTION(this << +key.instanceId << key.dodagId);

    if (m_dodags.find(key) == m_dodags.end())
    {
        return;
    }

    NS_LOG_INFO("Temporary DAG " << +key.instanceId << " at " << key.dodagId
                                 << " reached its 'L' deadline, leaving it");
    // RFC 6997 section 7: "A router MUST detach from the temporary DAG...
    // once the duration of its membership in the DAG has reached the value
    // indicated by the L field." poison = false: a temporary DAG never
    // carries routing state to begin with ("MUST NOT be used to route data
    // packets", section 9.1), so there is nothing downstream to withdraw,
    // the same reasoning AodvInstanceExpired() uses for its own instances.
    LeaveDodag(key, false);
}

bool
RplRoutingProtocol::ShouldRefuseP2pRdo(const RplDioHeader& dio, Ipv6Address from) const
{
    DodagKey key{dio.GetInstanceId(), dio.GetDodagId()};

    // The structural counterpart of ShouldRefuseAodvInstance()'s own
    // self-DODAGID check, without the REJOIN_REENABLE bar: RFC 6997 does
    // not mention rejoining a temporary DAG, but once this node's own
    // membership has been erased at its 'L' deadline (P2pInstanceExpired()),
    // nothing else stops a straggling DIO pulling it back in as an
    // ordinary member of a DODAG rooted at its own address -- the isRoot
    // check in HandleDio() only covers the window while the membership
    // still exists.
    if (IsOwnAddress(key.dodagId))
    {
        NS_LOG_LOGIC("Refusing this node's own temporary DAG, heard back from " << from);
        return true;
    }

    // RFC 6997 section 6.1: "A received P2P mode DIO MUST be discarded if
    // the MaxRankIncrease parameter inside the DODAG Configuration Option
    // is not zero." No option present at all falls back to the "default
    // DODAG Configuration Option" section 6.1 itself defines, whose own
    // MaxRankIncrease is 0 -- so only an explicit nonzero value refuses.
    if (dio.HasDagConfiguration() && dio.GetMaxRankIncrease() != 0)
    {
        NS_LOG_LOGIC("Refusing a P2P mode DIO with a nonzero MaxRankIncrease from " << from);
        return true;
    }

    const P2pRdoOption& rdo = dio.GetP2pRdo();

    // RFC 6997 section 9.4: "if adding its IPv6 address to the route in the
    // Address vector inside the P2P-RDO would result in the route
    // containing multiple addresses belonging to this router" -- a loop.
    // Checked here, before the join below, for the same reason
    // ShouldRefuseAodvRrep()'s own Address Vector loop check is: the
    // generic join HandleDio() performs happens regardless of what a
    // post-join handler decides, so anything meant to prevent it has to run
    // first.
    for (const auto& hop : rdo.addressVector)
    {
        if (IsOwnAddress(hop))
        {
            NS_LOG_LOGIC("Refusing a P2P mode DIO whose Address Vector already holds " << hop);
            return true;
        }
    }

    // RFC 6997 section 7: "An Intermediate Router MUST NOT join a temporary
    // DAG...if the integer portion of its rank would be equal to or
    // higher...than the MaxRank limit. A Target can join the temporary DAG
    // at a rank whose integer portion is equal to the MaxRank." The same
    // relaxation-for-the-far-end shape as AODV-RPL's own RankLimit (@see
    // ShouldRefuseAodvRreq()), with "is this node the Target" standing in
    // for "is this node the TargNode/OrigNode" there -- this router is the
    // Target if one of its own addresses is the TargetAddr the P2P-RDO
    // names (multiple Targets via RPL Target options are out of scope,
    // @see design-constraints.md).
    if (rdo.maxRankOrNh != RPL_P2P_MAX_RANK_INFINITE)
    {
        uint16_t minHopRankIncrease =
            dio.HasDagConfiguration() ? dio.GetMinHopRankIncrease() : m_minHopRankIncrease;
        NS_ASSERT_MSG(minHopRankIncrease > 0, "MinHopRankIncrease of zero would divide by zero");

        uint16_t advertisedDagRank = dio.GetRank() / minHopRankIncrease;
        if (advertisedDagRank >= rdo.maxRankOrNh)
        {
            NS_LOG_LOGIC("Refusing a P2P mode DIO advertising DAGRank "
                        << advertisedDagRank << ", at or past the MaxRank " << +rdo.maxRankOrNh);
            return true;
        }

        uint16_t ownDagRank = static_cast<uint16_t>(advertisedDagRank + 1);
        bool isTarget = IsOwnAddress(rdo.target);
        if (isTarget ? (ownDagRank > rdo.maxRankOrNh) : (ownDagRank >= rdo.maxRankOrNh))
        {
            NS_LOG_LOGIC("Refusing a P2P mode DIO that would put this node at DAGRank "
                        << ownDagRank << ", past the MaxRank " << +rdo.maxRankOrNh);
            return true;
        }
    }

    NS_LOG_LOGIC("Accepting a P2P mode DIO from " << from);
    return false;
}

void
RplRoutingProtocol::HandleP2pRdo(const RplDioHeader& dio, Ipv6Address from, uint32_t interface)
{
    NS_LOG_FUNCTION(this << from << interface);

    DodagKey key{dio.GetInstanceId(), dio.GetDodagId()};

    auto it = m_dodags.find(key);
    if (it == m_dodags.end())
    {
        return;
    }
    DodagMembership& dodag = it->second;

    // The Origin hearing its own P2P mode DIO come back around, re-flooded
    // by a router that appended itself: nothing to do. Its own Address
    // Vector is the authoritative empty one.
    if (dodag.p2p.isOrigin)
    {
        return;
    }

    const P2pRdoOption& rdo = dio.GetP2pRdo();

    // A Target that already recognised itself has nothing further to learn
    // from a later copy -- an unconditional repeat check, the same as
    // HandleAodvRreq()'s own dodag.aodv.isTarget one.
    if (dodag.p2p.isTarget)
    {
        NS_LOG_LOGIC("Already the Target of temporary DAG " << +key.instanceId
                                                             << ", ignoring a repeat");
        return;
    }

    // An intermediate router's Address Vector must track its preferred
    // parent, not just whichever copy of the DIO arrived first -- the same
    // reasoning and the same recipe as HandleAodvRreq()'s own.
    if (!dodag.p2p.addressVector.empty() && from != dodag.preferredParent)
    {
        NS_LOG_LOGIC("Already part of temporary DAG " << +key.instanceId
                                                       << " via a better parent than " << from
                                                       << ", ignoring this copy");
        return;
    }

    dodag.p2p.target = rdo.target;
    dodag.p2p.maxRank = rdo.maxRankOrNh;
    dodag.p2p.lifetimeField = rdo.lifetime;
    dodag.p2p.reply = rdo.reply;
    dodag.p2p.hopByHop = rdo.hopByHop;
    dodag.p2p.isTarget = IsOwnAddress(rdo.target);

    // RFC 6997 section 9.4: "the intermediate router MUST add a unicast
    // IPv6 address of the receiving interface...to the route in the Address
    // vector." A global address, since the vector becomes a Source Route
    // later.
    Ipv6Address ownAddress = GetGlobalAddressIn(dodag);
    if (ownAddress.IsAny())
    {
        NS_LOG_LOGIC("No global address to put in the Address Vector yet");
        return;
    }

    dodag.p2p.addressVector = rdo.addressVector;
    if (dodag.p2p.addressVector.size() >= RPL_P2P_ADDRESS_VECTOR_MAX_ENTRIES)
    {
        NS_LOG_WARN("The Address Vector is full at "
                    << dodag.p2p.addressVector.size() << " entries; leaving temporary DAG "
                    << +key.instanceId);
        LeaveDodag(key, false);
        return;
    }
    dodag.p2p.addressVector.push_back(ownAddress);

    ArmP2pExpiry(dodag, key);

    NS_LOG_INFO("Joined temporary DAG " << +key.instanceId << " at " << key.dodagId
                                        << " looking for " << dodag.p2p.target << ", "
                                        << dodag.p2p.addressVector.size()
                                        << " hop(s) from the Origin"
                                        << (dodag.p2p.isTarget ? ", and this node is it" : ""));

    // RFC 6997 section 9.5: "A Target MUST NOT forward a P2P mode DIO any
    // further if no other Targets are to be discovered" -- true here
    // unconditionally, since multiple Targets via RPL Target options are
    // out of scope (@see design-constraints.md). Replying with a P2P-DRO is
    // a later increment's job; for now this just stops the propagation an
    // Intermediate Router gets below, rather than leaving the Target's own
    // Trickle timer (already reset by HandleDio() when the preferred parent
    // was chosen) to re-flood the DIO exactly like an ordinary relay would.
    if (dodag.p2p.isTarget)
    {
        return;
    }

    // Nothing sends the DIO onward here: DioTrickleFire() already
    // multicasts this membership's DIO on its own schedule, and SendDio()
    // fills in the P2P-RDO from the state just recorded.
}

bool
RplRoutingProtocol::GetP2pAddressVector(uint8_t instanceId,
                                        Ipv6Address dodagId,
                                        std::vector<Ipv6Address>& addressVector) const
{
    addressVector.clear();
    auto it = m_dodags.find(DodagKey{instanceId, dodagId});
    if (it == m_dodags.end())
    {
        return false;
    }
    addressVector = it->second.p2p.addressVector;
    return true;
}

bool
RplRoutingProtocol::IsP2pTarget(uint8_t instanceId, Ipv6Address dodagId) const
{
    auto it = m_dodags.find(DodagKey{instanceId, dodagId});
    return it != m_dodags.end() && it->second.p2p.isTarget;
}

} // namespace rpl
} // namespace ns3
