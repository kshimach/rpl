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
    // out of scope (@see design-constraints.md). This stops the propagation
    // an Intermediate Router gets below, rather than leaving the Target's
    // own Trickle timer (already reset by HandleDio() when the preferred
    // parent was chosen) to re-flood the DIO exactly like an ordinary relay
    // would.
    if (dodag.p2p.isTarget)
    {
        // "If the Reply flag inside the P2P-RDO in the received DIO is set
        // to one, the Target MUST select one or more discovered routes and
        // send one or more P2P-DRO messages" (section 9.5). Exactly one
        // here: N > 0 (several Source Routes) is out of scope.
        if (dodag.p2p.reply)
        {
            // A fresh transmission cycle, distinct from P2pDroRetry()'s own
            // resend of the same content on timeout -- RFC 6997 section 10's
            // 'Seq' is what lets the Origin's P2P-DRO-ACK be matched back to
            // the P2P-DRO it acknowledges, so a P2P-DRO whose Address Vector
            // just changed (this DIO may have arrived with a different one
            // than the last) needs a Seq of its own. Resets the retry budget
            // for the same reason: this supersedes whatever cycle (if any)
            // was already in flight for the old Seq.
            dodag.p2p.droSequence++;
            dodag.p2p.droAckPending = m_p2pDroAckRequested;
            dodag.p2p.droRetriesLeft = m_p2pDroMaxRetransmissions;
            SendP2pDro(dodag, key);
        }
        return;
    }

    // Nothing sends the DIO onward here: DioTrickleFire() already
    // multicasts this membership's DIO on its own schedule, and SendDio()
    // fills in the P2P-RDO from the state just recorded.
}

void
RplRoutingProtocol::SendP2pDro(DodagMembership& dodag, DodagKey key)
{
    NS_LOG_FUNCTION(this << +key.instanceId << key.dodagId);

    NS_ASSERT_MSG(!dodag.p2p.addressVector.empty(), "The Target is not in its own Address Vector");
    Ipv6Address ownAddress = dodag.p2p.addressVector.back();

    RplP2pDroHeader dro;
    dro.SetInstanceId(dodag.instanceId);
    // RFC 6997 section 9.5: a Target MAY set 'S' when "this router is the
    // only Target specified in the corresponding DIO...and the Target has
    // already selected the desired number of routes" -- both are always
    // true in this implementation's scope (a single Target, N=0 meaning
    // exactly one route), so this is unconditional rather than a policy
    // choice the way the 'A' flag below is.
    dro.SetStop(true);
    dro.SetAckRequested(m_p2pDroAckRequested);
    dro.SetSequence(dodag.p2p.droSequence);
    // "the router recognizes itself as the Origin" by matching the P2P-DRO's
    // own DODAGID field (RFC 6997 section 9.7) -- the temporary DAG's own
    // DODAGID already is the Origin's address.
    dro.SetDodagId(key.dodagId);

    P2pRdoOption rdo;
    rdo.reply = false; // section 8.2: "MUST be set to zero on transmission"
    rdo.hopByHop = dodag.p2p.hopByHop; // "MUST have the same value as the H bit...in the...DIO"
    rdo.numRoutes = 0;                 // section 8.2: "MUST be set to zero on transmission"
    rdo.lifetime = 0;                  // section 8.2: "MUST be set to zero on transmission"
    // Section 8.2: "the Address vector MUST contain a complete route...such
    // that...the last element contains the IPv6 address of the router next
    // to the Target" -- this node's own trailing entry (the Target itself)
    // is excluded here, unlike the DIO's own accumulated Address Vector,
    // which keeps it (@see HandleP2pRdo() and design-constraints.md).
    rdo.addressVector.assign(dodag.p2p.addressVector.begin(), dodag.p2p.addressVector.end() - 1);
    // "the NH field is set to n = (Option Length - 2 - (16 - Compr)) /
    // (16 - Compr)", which is exactly this vector's own entry count.
    rdo.maxRankOrNh = static_cast<uint8_t>(rdo.addressVector.size());
    rdo.target = ownAddress;
    dro.SetP2pRdo(rdo);

    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(dro);
    // "A P2P-DRO message MUST travel from the Target to the Origin via
    // link-local multicast...transmitted on all interfaces" (section 8) --
    // unlike AODV-RPL's symmetric RREP, which SendAodvRrepTo() unicasts to
    // one specific next hop.
    SendRplMessageMulticast(packet, RPL_CODE_P2P_DRO, Ipv6Address(RPL_ALL_NODES_MULTICAST));

    NS_LOG_INFO("Answering the P2P mode DIO for " << dodag.p2p.target << " with a P2P-DRO over "
                                                   << rdo.addressVector.size() << " hop(s)"
                                                   << (m_p2pDroAckRequested ? ", ack requested" : ""));

    // Only arms the wait timer, never resets droAckPending/droRetriesLeft:
    // this function is also what P2pDroRetry() calls to resend the exact
    // same P2P-DRO on timeout, and doing either here would make every retry
    // renew its own retry budget, so MAX_P2P_DRO_RETRANSMISSIONS would never
    // actually bind. The two callers -- HandleP2pRdo() for a fresh cycle,
    // P2pDroRetry() for a resend -- own that state themselves instead.
    if (m_p2pDroAckRequested)
    {
        // Bound here rather than in CreateDodagMembership() (@see
        // DodagMembership::P2pState::droRetryEvent's own comment): harmless
        // to redo on every call, SetFunction()/SetArguments() just overwrite
        // the same binding.
        dodag.p2p.droRetryEvent.SetFunction(&RplRoutingProtocol::P2pDroRetry, this);
        dodag.p2p.droRetryEvent.SetArguments(key);
        dodag.p2p.droRetryEvent.Cancel();
        dodag.p2p.droRetryEvent.Schedule(m_p2pDroAckWaitTime);
    }
}

void
RplRoutingProtocol::P2pDroRetry(DodagKey key)
{
    auto it = m_dodags.find(key);
    if (it == m_dodags.end())
    {
        return;
    }
    DodagMembership& dodag = it->second;

    NS_LOG_FUNCTION(this << +dodag.p2p.droRetriesLeft);

    if (!dodag.p2p.droAckPending)
    {
        return;
    }

    if (dodag.p2p.droRetriesLeft == 0)
    {
        // RFC 6997 section 9.5 caps retransmissions at
        // MAX_P2P_DRO_RETRANSMISSIONS and says nothing beyond that -- unlike
        // a DAO, which the next periodic refresh tries again, a P2P-DRO has
        // no periodic refresh of its own to fall back on (the temporary DAG
        // just expires at its own 'L' deadline, @see P2pInstanceExpired()).
        NS_LOG_WARN("No P2P-DRO-ACK for sequence " << +dodag.p2p.droSequence
                                                    << ", giving up until the temporary DAG "
                                                       "expires");
        dodag.p2p.droAckPending = false;
        return;
    }

    dodag.p2p.droRetriesLeft--;
    // Rebuilds and resends the same content: droSequence is untouched here,
    // only HandleP2pRdo() bumps it for a genuinely new cycle.
    SendP2pDro(dodag, key);
}

void
RplRoutingProtocol::HandleP2pDro(const RplP2pDroHeader& dro, Ipv6Address from, uint32_t interface)
{
    NS_LOG_FUNCTION(this << from << interface);

    if (!dro.HasP2pRdo())
    {
        NS_LOG_WARN("Dropping a P2P-DRO with no P2P-RDO option");
        return;
    }

    DodagKey key{dro.GetInstanceId(), dro.GetDodagId()};
    auto it = m_dodags.find(key);
    if (it == m_dodags.end())
    {
        // RFC 6997 sections 9.6/9.7: "MUST discard the received P2P-DRO...
        // if it...no longer belongs to the temporary DAG identified by the
        // RPLInstanceID and the DODAGID fields."
        NS_LOG_LOGIC("Dropping a P2P-DRO for a temporary DAG this node is not part of");
        return;
    }
    DodagMembership& dodag = it->second;
    const P2pRdoOption& rdo = dro.GetP2pRdo();

    if (dodag.p2p.isOrigin)
    {
        // RFC 6997 section 9.7. rdo.addressVector is the fixed snapshot the
        // Target built once (SendP2pDro()), already running Origin-outward
        // -- unlike AODV-RPL's asymmetric RREP-Instance, whose own vector
        // accumulates hop by hop during the flood back and so needs
        // reversing at the OrigNode, this needs none (@see
        // design-constraints.md).
        P2pRoute route;
        route.hops = rdo.addressVector;
        route.hops.push_back(rdo.target);
        route.instanceId = dodag.instanceId;
        // "The lifetime is set according to DODAG configuration (i.e., not
        // the L field)" -- RFC 9854 section 6.4.3's wording for the AODV-RPL
        // analogue, and the same PathLifetime/lifetime unit a DAO-derived
        // route gets; RFC 6997 has no equivalent sentence of its own but
        // the same reasoning applies (the temporary DAG's own 'L' bounds
        // discovery, not the route it finds).
        route.expire = Simulator::Now() + Seconds(m_pathLifetime * m_lifetimeUnit);
        m_p2pRoutes[rdo.target] = route;

        NS_LOG_INFO("P2P-RPL route discovery to " << rdo.target << " completed over "
                                                   << route.hops.size() << " hop(s)");
        return;
    }

    // An Intermediate Router: only the one router named at the Address
    // Vector's current NH position acts (RFC 6997 section 9.6); every other
    // one that also happens to hear the multicast has nothing to do here.
    // NH is 1-indexed ("Address[NH]"); out-of-range values (including 0,
    // which never names a valid entry) are simply not this node's turn.
    if (rdo.maxRankOrNh == 0 || rdo.maxRankOrNh > rdo.addressVector.size() ||
        !IsOwnAddress(rdo.addressVector[rdo.maxRankOrNh - 1]))
    {
        NS_LOG_LOGIC("Not named at the current NH position, ignoring this P2P-DRO");
        return;
    }

    // RFC 6997 section 9.6: "To prevent loops, the router MUST discard the
    // P2P-DRO message with no further processing if the Address vector in
    // the P2P-RDO includes multiple IPv6 addresses assigned to the
    // router's interfaces."
    uint32_t ownCount = 0;
    for (const auto& hop : rdo.addressVector)
    {
        if (IsOwnAddress(hop))
        {
            ownCount++;
        }
    }
    if (ownCount > 1)
    {
        NS_LOG_LOGIC("Dropping a P2P-DRO whose Address Vector names this router more than once");
        return;
    }

    // "The router MUST decrement the NH field inside the P2P-RDO and send
    // the P2P-DRO message further via link-local multicast" -- unchanged
    // otherwise; H=1's Hop-by-hop routing state (the bullets in between,
    // in section 9.6's own text) is out of scope.
    P2pRdoOption relayedRdo = rdo;
    relayedRdo.maxRankOrNh = static_cast<uint8_t>(rdo.maxRankOrNh - 1);

    RplP2pDroHeader relayed;
    relayed.SetInstanceId(dro.GetInstanceId());
    relayed.SetStop(dro.GetStop());
    relayed.SetAckRequested(dro.GetAckRequested());
    relayed.SetSequence(dro.GetSequence());
    relayed.SetDodagId(dro.GetDodagId());
    relayed.SetP2pRdo(relayedRdo);

    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(relayed);
    SendRplMessageMulticast(packet, RPL_CODE_P2P_DRO, Ipv6Address(RPL_ALL_NODES_MULTICAST));

    NS_LOG_INFO("Relaying a P2P-DRO for " << rdo.target << " onward, NH now "
                                          << +relayedRdo.maxRankOrNh);
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

bool
RplRoutingProtocol::GetP2pRoute(Ipv6Address target, std::vector<Ipv6Address>& hops) const
{
    hops.clear();
    auto it = m_p2pRoutes.find(target);
    if (it == m_p2pRoutes.end() || it->second.expire <= Simulator::Now())
    {
        return false;
    }
    hops = it->second.hops;
    return true;
}

uint32_t
RplRoutingProtocol::GetP2pRouteCount() const
{
    uint32_t count = 0;
    Time now = Simulator::Now();
    for (const auto& [target, route] : m_p2pRoutes)
    {
        if (route.expire > now)
        {
            count++;
        }
    }
    return count;
}

bool
RplRoutingProtocol::FindP2pRoute(Ipv6Address dst,
                                 std::vector<Ipv6Address>& hops,
                                 uint8_t& instanceId) const
{
    hops.clear();
    auto it = m_p2pRoutes.find(dst);
    if (it == m_p2pRoutes.end() || it->second.expire <= Simulator::Now())
    {
        return false;
    }

    // Converted to link-local, the same form ComputeSourceRoute() returns,
    // so that PrepareOutgoingPacket()'s existing hops-to-Routing-Header
    // recipe applies unchanged -- it is that function that puts the global
    // destination back into the last entry.
    for (const auto& hop : it->second.hops)
    {
        hops.push_back(LinkLocalOf(hop));
    }
    instanceId = it->second.instanceId;
    return true;
}

} // namespace rpl
} // namespace ns3
