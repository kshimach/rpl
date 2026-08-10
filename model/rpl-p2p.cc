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

} // namespace rpl
} // namespace ns3
