/*
 * Copyright (c) 2026 ns-3 RPL module contributors
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * AODV-RPL (RFC 9854) route discovery, layered on the core RPL machinery in
 * rpl-routing-protocol.cc. These are methods of RplRoutingProtocol like any
 * other -- the discovery leans on m_dodags, SendDio(), CreateLocalDodag(),
 * SelectPreferredParent() and the per-membership Trickle timers, all of them
 * private -- kept in a translation unit of their own only because
 * rpl-routing-protocol.cc is already some three thousand lines. @see
 * design-constraints.md.
 *
 * Scope: source-routed (H=0) discovery for a single target, symmetric (S=1)
 * or asymmetric (S=0). Hop-by-hop routes (H=1) need storing mode, which
 * this module does not have at all. @see design-constraints.md.
 */

#include "rpl-conf.h"
#include "rpl-header.h"
#include "rpl-routing-protocol.h"

#include "ns3/ipv6-l3-protocol.h"
#include "ns3/log.h"
#include "ns3/simulator.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("RplAodv");

namespace rpl
{

bool
RplRoutingProtocol::IsOwnAddress(Ipv6Address address) const
{
    if (address.IsAny())
    {
        return false;
    }
    for (uint32_t i = 0; i < m_ipv6->GetNInterfaces(); i++)
    {
        for (uint32_t j = 0; j < m_ipv6->GetNAddresses(i); j++)
        {
            if (m_ipv6->GetAddress(i, j).GetAddress() == address)
            {
                return true;
            }
        }
    }
    return false;
}

RplRoutingProtocol::DodagKey
RplRoutingProtocol::DiscoverRoute(Ipv6Address target)
{
    NS_LOG_FUNCTION(this << target);

    DodagKey empty{0, Ipv6Address::GetAny()};

    if (target.IsAny() || IsOwnAddress(target))
    {
        NS_LOG_WARN("Not discovering a route to " << target << ": not a usable target");
        return empty;
    }

    // The DODAGID of the RREQ-Instance is one of the OrigNode's own
    // addresses (RFC 9854 section 6.1), and it has to be routable across the
    // whole discovery, so a link-local will not do -- CreateLocalDodag()
    // uses GetGlobalAddress() for exactly that reason and fails if there is
    // none yet.
    if (GetGlobalAddress().IsAny())
    {
        NS_LOG_WARN("Not discovering a route to " << target << ": no global address to root the "
                                                              "RREQ-Instance at");
        return empty;
    }

    // A Local RPLInstanceID, which is only unique per DODAGID (RFC 6550
    // section 5.1) -- and every RREQ-Instance this node originates shares
    // one DODAGID, this node's own address, so the ID has to be unique
    // among them. Scanning for the first free one rather than counting up
    // and wrapping: a discovery that has already ended has freed its ID, and
    // reusing the lowest free one keeps the numbers small and predictable.
    // The 'D' flag stays clear throughout; CreateLocalDodag() enforces that
    // for control messages regardless.
    uint8_t instanceId = 0;
    bool found = false;
    for (uint8_t candidate = 0; candidate <= RPL_AODV_PREFIX_LENGTH_MASK; candidate++)
    {
        uint8_t local = static_cast<uint8_t>(RPL_LOCAL_INSTANCE_FLAG | candidate);
        if ((local & RPL_LOCAL_INSTANCE_D_FLAG) != 0)
        {
            // Would collide with the 'D' flag's bit; not a usable Local ID.
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
        NS_LOG_WARN("Not discovering a route to " << target << ": no free Local RPLInstanceID");
        return empty;
    }

    // RFC 9854 section 6.1: "it MUST increase its own Sequence Number to
    // avoid conflicts with previously established routes".
    m_aodvSeqNo++;

    DodagKey key = CreateLocalDodag(instanceId, RPL_MOP_P2P_ROUTE_DISCOVERY);
    if (key.dodagId.IsAny())
    {
        return empty;
    }

    auto it = m_dodags.find(key);
    NS_ASSERT_MSG(it != m_dodags.end(), "CreateLocalDodag() did not leave a membership behind");
    DodagMembership& dodag = it->second;

    dodag.aodv.symmetric = true; // RFC 9854 section 6.1: the OrigNode sets S to 1
    dodag.aodv.origSeqNo = m_aodvSeqNo;
    dodag.aodv.rankLimit = m_aodvRankLimit;
    dodag.aodv.lifetimeField = m_aodvLifetime;
    dodag.aodv.target = target;
    dodag.aodv.isOrigin = true;
    dodag.aodv.isTarget = false;
    // Empty at the OrigNode: "The Origin and Target addresses MUST NOT be
    // included in the Address vector" is P2P-RPL's wording, and RFC 9854
    // section 6.2.5 has only intermediate routers append to it.
    dodag.aodv.addressVector.clear();

    // A discovery has to complete within its own 'L' field, so it is paced
    // far faster than the base DODAG's steady-state upkeep.
    dodag.dioIntervalMin = m_aodvDioIntervalMin;
    dodag.dioIntervalDoublings = m_aodvDioIntervalDoublings;
    dodag.dioTrickle.SetParameters(dodag.dioIntervalMin,
                                   dodag.dioIntervalDoublings,
                                   dodag.dioRedundancy);
    dodag.dioTrickle.Reset();

    ArmAodvExpiry(dodag, key);

    NS_LOG_INFO("Discovering a route to " << target << " as OrigNode of RREQ-Instance "
                                          << +instanceId << " at " << key.dodagId
                                          << ", Orig SeqNo " << +m_aodvSeqNo);
    return key;
}

void
RplRoutingProtocol::ArmAodvExpiry(DodagMembership& dodag, DodagKey key)
{
    uint32_t seconds = RplAodvLifetimeSeconds(dodag.aodv.lifetimeField);
    if (seconds == 0)
    {
        // RFC 9854 section 4.1's 0x00, "No time limit imposed": the
        // membership then lives until something else takes it down.
        return;
    }

    dodag.aodv.expiry.SetFunction(&RplRoutingProtocol::AodvInstanceExpired, this);
    dodag.aodv.expiry.SetArguments(key);
    dodag.aodv.expiry.Cancel();
    dodag.aodv.expiry.Schedule(Seconds(seconds));
}

void
RplRoutingProtocol::AodvInstanceExpired(DodagKey key)
{
    NS_LOG_FUNCTION(this << +key.instanceId << key.dodagId);

    if (m_dodags.find(key) == m_dodags.end())
    {
        return;
    }

    NS_LOG_INFO("RREQ-Instance " << +key.instanceId << " at " << key.dodagId
                                 << " reached its 'L' deadline, leaving it");
    // RFC 9854 section 4.1: "Once a node leaves an RREQ-Instance, it MUST
    // NOT rejoin the same RREQ-Instance for at least the time interval
    // specified by the configuration variable REJOIN_REENABLE."
    m_aodvRejoinBlocked[key] = Simulator::Now() + m_aodvRejoinReenable;
    // poison = false. AODV-RPL has no notion of poisoning: RFC 9854 section
    // 4.1 says only that a node "SHOULD leave the RREQ-Instance and stop
    // sending or receiving any more DIOs" for it. The poisoning path would
    // multicast an infinite-rank DIO -- core RPL's way of telling a
    // sub-DODAG to detach, which means nothing here -- and would also start
    // LeaveDodag()'s base-DODAG promotion, which must never consider a
    // route-discovery instance.
    LeaveDodag(key, false);
}

bool
RplRoutingProtocol::ShouldRefuseAodvRreq(const RplDioHeader& dio, Ipv6Address from) const
{
    const RplDioHeader::RreqOption& rreq = dio.GetRreq();
    DodagKey key{dio.GetInstanceId(), dio.GetDodagId()};

    // RFC 9854 section 4.1's REJOIN_REENABLE. This is what actually ends a
    // discovery: a node that has served out its 'L' field is still
    // surrounded by neighbours Trickle-pacing the same RREQ-DIO, and
    // without this it rejoins at once and the instance never dies. The
    // OrigNode is the worst case -- it would rejoin its own discovery as an
    // ordinary member, take a preferred parent in a DODAG rooted at itself,
    // and route its own DODAGID away from itself.
    // Expired entries are swept in HandleAodvRreq(), which is not const;
    // this only reads.
    auto blocked = m_aodvRejoinBlocked.find(key);
    if (blocked != m_aodvRejoinBlocked.end() && Simulator::Now() < blocked->second)
    {
        NS_LOG_LOGIC("Refusing an RREQ for instance " << +key.instanceId << " at " << key.dodagId
                                                      << ", left too recently to rejoin");
        return true;
    }

    // An RREQ-DIO naming this node as the OrigNode, heard back from a
    // neighbour propagating it. Refused even before the instance expires:
    // joining a DODAG rooted at this node's own address would make it a
    // member of its own discovery.
    if (IsOwnAddress(dio.GetDodagId()))
    {
        NS_LOG_LOGIC("Refusing this node's own RREQ, heard back from " << from);
        return true;
    }

    // Out of scope, and refused rather than half-honoured: a hop-by-hop
    // route needs the per-destination next-hop state of storing mode, which
    // this module does not have at all. @see design-constraints.md.
    if (rreq.hopByHop)
    {
        NS_LOG_LOGIC("Refusing an RREQ asking for a hop-by-hop route (H=1), which needs storing "
                     "mode");
        return true;
    }

    // No Compr check here: RplDioHeader::Deserialize() already reconstructs
    // full addresses from whatever Compr the sender used (RFC 9854 section
    // 4.1's "elided octets are shared with the IPv6 address in the
    // DODAGID"), so rreq.addressVector below is always full addresses
    // regardless of what was actually on the wire.

    // RFC 9854 section 6.2.1: "When H=0 in the incoming RREQ, the router
    // MUST drop the RREQ-DIO if one of its addresses is present in the
    // Address Vector." The route would otherwise loop back through here.
    for (const auto& hop : rreq.addressVector)
    {
        if (IsOwnAddress(hop))
        {
            NS_LOG_LOGIC("Refusing an RREQ whose Address Vector already holds " << hop);
            return true;
        }
    }

    // RFC 9854 section 4.1: "A router MUST discard a received RREQ if the
    // integer part of the advertised Rank equals or exceeds the RankLimit",
    // and a router other than the TargNode must not join at a rank that
    // would reach it either. The rank this node would take is the sender's
    // plus one hop, so both are decided here, before the join.
    if (rreq.rankLimit != RPL_AODV_RANK_LIMIT_INFINITE)
    {
        uint16_t minHopRankIncrease =
            dio.HasDagConfiguration() ? dio.GetMinHopRankIncrease() : m_minHopRankIncrease;
        NS_ASSERT_MSG(minHopRankIncrease > 0, "MinHopRankIncrease of zero would divide by zero");

        uint16_t advertisedDagRank = dio.GetRank() / minHopRankIncrease;
        if (advertisedDagRank >= rreq.rankLimit)
        {
            NS_LOG_LOGIC("Refusing an RREQ advertising DAGRank " << advertisedDagRank
                                                                 << ", at or past the RankLimit "
                                                                 << +rreq.rankLimit);
            return true;
        }

        // What this node's own rank would become. The TargNode is allowed to
        // sit exactly at the RankLimit ("TargNode can join the RREQ-Instance
        // at a Rank whose integer portion is less than or equal to the
        // RankLimit"), every other router strictly below it, so the check is
        // relaxed by one step when the ART option names this node.
        uint16_t ownDagRank = static_cast<uint16_t>(advertisedDagRank + 1);
        bool isTarget = dio.HasArt() && IsOwnAddress(dio.GetArt().target);
        if (isTarget ? (ownDagRank > rreq.rankLimit) : (ownDagRank >= rreq.rankLimit))
        {
            NS_LOG_LOGIC("Refusing an RREQ that would put this node at DAGRank "
                         << ownDagRank << ", past the RankLimit " << +rreq.rankLimit);
            return true;
        }
    }

    NS_LOG_LOGIC("Accepting an RREQ from " << from);
    return false;
}

void
RplRoutingProtocol::HandleAodvRreq(const RplDioHeader& dio, Ipv6Address from, uint32_t interface)
{
    NS_LOG_FUNCTION(this << from << interface);

    DodagKey key{dio.GetInstanceId(), dio.GetDodagId()};

    // The rejoin bar for this key has run out, or it would not have got
    // past ShouldRefuseAodvRreq(). Dropping it here keeps the map from
    // growing without bound across many discoveries.
    m_aodvRejoinBlocked.erase(key);

    auto it = m_dodags.find(key);
    if (it == m_dodags.end())
    {
        return;
    }
    DodagMembership& dodag = it->second;

    // The OrigNode hearing its own RREQ come back around: nothing to do.
    // Its own Address Vector is the authoritative empty one.
    if (dodag.aodv.isOrigin)
    {
        return;
    }

    const RplDioHeader::RreqOption& rreq = dio.GetRreq();

    // RFC 9854 section 4.3: "An RREQ-DIO message MUST carry at least one ART
    // option ... Otherwise, the message MUST be dropped." Enforced here
    // rather than in ShouldRefuseAodvRreq() because the membership is
    // already formed by now -- the DIO was a valid DIO, it is only its
    // AODV-RPL content that is unusable, so the DODAG side of it stands.
    if (!dio.HasArt())
    {
        NS_LOG_WARN("Ignoring the AODV-RPL content of an RREQ-DIO with no ART option");
        return;
    }

    // RFC 9854 section 6.2.6: a TargNode "already associated with the
    // RREQ-Instance ... takes no further action" -- unconditional, unlike
    // the intermediate-router case just below, so this stays a plain repeat
    // check.
    if (dodag.aodv.isTarget)
    {
        NS_LOG_LOGIC("Already the TargNode of RREQ-Instance " << +key.instanceId
                                                              << ", ignoring a repeat");
        return;
    }

    // An intermediate router's Address Vector must track its preferred
    // parent, not just whichever copy of the RREQ arrived first. HandleDio()
    // already ran SelectPreferredParent() before calling here (it is the
    // very last thing it does before handing off to this function), so
    // dodag.preferredParent already reflects this DIO if it was good enough
    // to win -- a link-local, comparable to from directly, both being the
    // sender's own address. Found the hard way: a probe
    // (scratch/rpl-aodv-av-stale-probe.cc, deleted once this was confirmed
    // and fixed) sent a worse RREQ first and a better one second and found
    // the Rank had switched to the better parent while the Address Vector
    // -- and so the route eventually propagated onward, and the source
    // route an OrigNode would end up with -- still named the worse one.
    // RFC 9854 section 6.2.1's own MaxUsefulRank language backs this: a
    // router already in the instance re-evaluates a later RREQ against the
    // best Rank it has seen, it does not simply keep the first one.
    if (!dodag.aodv.addressVector.empty() && from != dodag.preferredParent)
    {
        NS_LOG_LOGIC("Already part of RREQ-Instance "
                    << +key.instanceId << " via a better parent than " << from
                    << ", ignoring this copy");
        return;
    }

    dodag.aodv.origSeqNo = rreq.origSeqNo;
    dodag.aodv.rankLimit = rreq.rankLimit;
    dodag.aodv.lifetimeField = rreq.lifetime;
    dodag.aodv.target = dio.GetArt().target;
    dodag.aodv.isOrigin = false;
    dodag.aodv.isTarget = IsOwnAddress(dio.GetArt().target);

    // RFC 9854 section 6.2.4. The incoming 'S' having been cleared anywhere
    // upstream is final -- "If the S bit arrives already set to be 0, then
    // it is set to be 0 when the RREQ-DIO is propagated". Otherwise the
    // router decides whether the downward direction of the link it just
    // heard this on also satisfies the Objective Function.
    //
    // Deciding that for real is explicitly out of the RFC's own scope ("It
    // is beyond the scope of this document to specify the criteria used when
    // determining whether or not each link is symmetric"), and it is not
    // implementable here in any case: both metrics this module keeps are
    // measured on received frames (ETX from the LQI tag, LQL from the RSSI
    // tag), so they describe the same direction as each other and comparing
    // them -- which is what RFC 9854 Appendix A's example method does, using
    // a transmit-side ETX this module has no equivalent of -- says nothing
    // about asymmetry. Links are therefore symmetric unless the
    // AodvForceAsymmetric attribute says otherwise, which is also the RFC's
    // own opening position: "Links are considered symmetric until indication
    // to the contrary is received" (section 5). @see design-constraints.md.
    dodag.aodv.symmetric = rreq.symmetric && !m_aodvForceAsymmetric;

    // RFC 9854 section 6.2.5: "the intermediate router MUST append the
    // address of its interface receiving the RREQ-DIO into the Address
    // Vector". A global address, not the link-local the DIO arrived from:
    // the vector becomes a source route later, and every entry has to be
    // reachable from more than one hop away.
    Ipv6Address ownAddress = GetGlobalAddressIn(dodag);
    if (ownAddress.IsAny())
    {
        NS_LOG_LOGIC("No global address to put in the Address Vector yet");
        return;
    }

    dodag.aodv.addressVector = rreq.addressVector;
    if (dodag.aodv.addressVector.size() >= RplDioHeader::AODV_ADDRESS_VECTOR_MAX_ENTRIES)
    {
        // The option's own 8-bit Opt Data Len cannot describe another entry.
        // The RankLimit normally stops a discovery long before this, so
        // reaching it means the limit was configured away (0, "no limit").
        NS_LOG_WARN("The Address Vector is full at "
                    << dodag.aodv.addressVector.size()
                    << " entries; leaving RREQ-Instance " << +key.instanceId);
        LeaveDodag(key, false);
        return;
    }
    dodag.aodv.addressVector.push_back(ownAddress);

    ArmAodvExpiry(dodag, key);

    NS_LOG_INFO("Joined RREQ-Instance " << +key.instanceId << " at " << key.dodagId
                                        << " looking for " << dodag.aodv.target << ", "
                                        << dodag.aodv.addressVector.size()
                                        << " hop(s) from the OrigNode"
                                        << (dodag.aodv.isTarget ? ", and this node is it" : ""));

    // RFC 9854 section 6.2.6: a TargNode that was not already in the
    // RREQ-Instance "prepares and transmits an RREP-DIO". Answered once --
    // a repeat copy of the same RREQ is turned away by the check above, so
    // this cannot fire twice for one discovery.
    if (dodag.aodv.isTarget)
    {
        SendAodvRrep(dodag, key);
    }

    // Nothing sends the RREQ onward here: DioTrickleFire() already
    // multicasts this membership's DIO on its own schedule, and SendDio()
    // fills in the RREQ and ART options from the state just recorded. The
    // Trickle timer was reset by HandleDio() when the preferred parent was
    // chosen, so the propagation is already imminent.
}

void
RplRoutingProtocol::SendAodvRrepTo(const DodagMembership& dodag,
                                   const RplDioHeader& dio,
                                   Ipv6Address nextHop)
{
    // One radio hop, so the message goes to the neighbour's link-local
    // address: RouteOutput() never treats a global address as on-link, and
    // sending an RREP to a global one would hand it to this node's preferred
    // parent instead of to the neighbour the Address Vector names.
    Ipv6Address linkLocal = LinkLocalOf(nextHop);
    uint32_t interface = InterfaceForNeighbour(dodag, linkLocal);
    if (interface == 0)
    {
        interface = m_ifcToSocket.empty() ? 0 : m_ifcToSocket.begin()->first;
        if (interface == 0)
        {
            NS_LOG_WARN("No interface to send an RREP to " << nextHop << " on");
            return;
        }
    }

    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(dio);
    SendRplMessageOn(interface, packet, RPL_CODE_DIO, linkLocal);
    NS_LOG_INFO("Sent an RREP towards the OrigNode via " << nextHop);
}

void
RplRoutingProtocol::StartAodvRrepInstance(const DodagMembership& rreqDodag, DodagKey rreqKey)
{
    NS_LOG_FUNCTION(this << +rreqKey.instanceId << rreqKey.dodagId);

    Ipv6Address ownAddress = GetGlobalAddressIn(rreqDodag);
    if (ownAddress.IsAny())
    {
        NS_LOG_LOGIC("No global address to root an RREP-Instance at yet");
        return;
    }

    // Everything carried over from the RREQ-Instance, read out up front so
    // the rest of this function does not interleave reads of one membership
    // with writes to another. (m_dodags is a std::map, so the insertion
    // below does not invalidate rreqDodag -- this is for legibility, not
    // safety.) The RREQ-Instance's own DODAGID is the OrigNode, which is
    // what the RREP has to be aimed back at.
    Ipv6Address origNode = rreqKey.dodagId;
    uint8_t rankLimit = rreqDodag.aodv.rankLimit;
    uint8_t lifetimeField = rreqDodag.aodv.lifetimeField;

    // RFC 9854 section 6.3.3: the RREP-InstanceID is the RREQ-InstanceID
    // plus Delta, and "the RPLInstanceID of an already active RREP-Instance
    // MUST NOT be used again for assigning RPLInstanceID for the later
    // RREP-Instance" -- two OrigNodes that happened to pick the same
    // RREQ-InstanceID for routes to this same TargNode would otherwise
    // produce two DODAGs an intermediate router could not tell apart, since
    // both would carry this node's address as the DODAGID.
    //
    // Delta is six bits, so the search runs 0..63. A candidate that would
    // set the Local RPLInstanceID's 'D' flag is skipped rather than used:
    // CreateLocalDodag() clears that bit unconditionally (RFC 6550 section
    // 5.1 requires it clear in control messages), which would leave the
    // instance running under an ID one bit off from the one Delta describes,
    // and every receiver's own instanceId - delta would then miss.
    uint8_t rrepInstanceId = 0;
    bool found = false;
    for (uint8_t delta = 0; delta <= (RPL_AODV_DELTA_MASK >> RPL_AODV_DELTA_SHIFT); delta++)
    {
        uint8_t candidate = static_cast<uint8_t>(rreqKey.instanceId + delta);
        if ((candidate & RPL_LOCAL_INSTANCE_D_FLAG) != 0)
        {
            continue;
        }
        if (!IsJoinedTo(candidate, ownAddress))
        {
            rrepInstanceId = candidate;
            found = true;
            break;
        }
    }
    if (!found)
    {
        NS_LOG_WARN("No free RPLInstanceID left to pair an RREP-Instance with RREQ-Instance "
                    << +rreqKey.instanceId);
        return;
    }

    // "the TargNode MUST build a DODAG in the RREP-Instance corresponding to
    // the RREQ-DIO rooted at itself, in order to provide OrigNode with a
    // downstream route to the TargNode" (section 6.3.2).
    DodagKey rrepKey = CreateLocalDodag(rrepInstanceId, RPL_MOP_P2P_ROUTE_DISCOVERY);
    if (rrepKey.dodagId.IsAny())
    {
        return;
    }

    auto it = m_dodags.find(rrepKey);
    NS_ASSERT_MSG(it != m_dodags.end(), "CreateLocalDodag() did not leave a membership behind");
    DodagMembership& rrepDodag = it->second;

    // RFC 9854 section 6.1's rule for the OrigNode's own Sequence Number,
    // applied to the TargNode originating this instance: it is what the ART
    // option carries as Dest SeqNo, and what tells a stale route from this
    // one at the far end.
    m_aodvSeqNo++;

    rrepDodag.aodv.isRrepInstance = true;
    rrepDodag.aodv.pairedInstanceId = rreqKey.instanceId;
    rrepDodag.aodv.origNode = origNode;
    rrepDodag.aodv.origSeqNo = m_aodvSeqNo;
    rrepDodag.aodv.rankLimit = rankLimit;
    rrepDodag.aodv.lifetimeField = lifetimeField;
    rrepDodag.aodv.target = ownAddress; // the TargNode is this node
    rrepDodag.aodv.isOrigin = false;
    rrepDodag.aodv.isTarget = true;
    // Empty at the root: section 6.4.4 has only the routers the RREP passes
    // through append to it, the mirror of the RREQ's own rule.
    rrepDodag.aodv.addressVector.clear();

    // Paced like the RREQ-Instance rather than like the base DODAG: the
    // RREP has to reach the OrigNode inside the same 'L' lifetime.
    rrepDodag.dioIntervalMin = m_aodvDioIntervalMin;
    rrepDodag.dioIntervalDoublings = m_aodvDioIntervalDoublings;
    rrepDodag.dioTrickle.SetParameters(rrepDodag.dioIntervalMin,
                                       rrepDodag.dioIntervalDoublings,
                                       rrepDodag.dioRedundancy);
    rrepDodag.dioTrickle.Reset();

    ArmAodvExpiry(rrepDodag, rrepKey);

    NS_LOG_INFO("Answering the RREQ for " << ownAddress << " with an asymmetric RREP-Instance "
                                          << +rrepInstanceId << " (Delta "
                                          << +static_cast<uint8_t>(rrepInstanceId -
                                                                   rreqKey.instanceId)
                                          << ") rooted here, towards OrigNode " << origNode);
    // Nothing is transmitted here: the Trickle timer just reset above
    // multicasts the RREP-DIO, with SendDio() filling in the RREP and ART
    // options from the state recorded above -- the same division of labour
    // the RREQ side uses.
}

void
RplRoutingProtocol::SendAodvRrep(DodagMembership& dodag, DodagKey key)
{
    NS_LOG_FUNCTION(this << +key.instanceId << key.dodagId);

    // RFC 9854 section 6.3.2: an asymmetric route cannot be answered by
    // unicasting back the way the RREQ came, because that is exactly the
    // direction some hop on it failed to satisfy. The TargNode floods a
    // DODAG of its own instead.
    if (!dodag.aodv.symmetric)
    {
        StartAodvRrepInstance(dodag, key);
        return;
    }

    Ipv6Address ownAddress = GetGlobalAddressIn(dodag);
    if (ownAddress.IsAny())
    {
        NS_LOG_LOGIC("No global address to answer an RREQ from yet");
        return;
    }

    RplDioHeader rrep;
    // RFC 9854 section 6.3.3: the RREP-InstanceID is the RREQ-InstanceID
    // plus Delta. Delta stays 0 here -- it exists to break a collision with
    // another discovery's RREP-Instance already active at this TargNode, and
    // no RREP-Instance DODAG is ever built on a symmetric route for one to
    // collide with.
    rrep.SetInstanceId(key.instanceId);
    rrep.SetVersionNumber(0);
    rrep.SetRank(m_minHopRankIncrease);
    rrep.SetMop(RPL_MOP_P2P_ROUTE_DISCOVERY);
    rrep.SetGrounded(true);
    rrep.SetDtsn(0);
    // "TargNode sets one of its IPv6 addresses in the DODAGID field of the
    // RREP-DIO message" (RFC 9854 section 4.2).
    rrep.SetDodagId(ownAddress);

    RplDioHeader::RrepOption option;
    option.gratuitous = false; // section 7's Gratuitous RREP is out of scope
    option.hopByHop = false;   // "MUST be set to be the same as the H bit in the RREQ option"
    // compr left at its default: RplDioHeader::Serialize() computes its own
    // from the addresses below and m_dodagId, ignoring this field.
    option.lifetime = dodag.aodv.lifetimeField;
    option.rankLimit = dodag.aodv.rankLimit;
    option.delta = 0;
    // "for a symmetric route, it is the Address Vector when the RREQ-DIO
    // arrives at the TargNode, unchanged during the transmission to the
    // OrigNode" (RFC 9854 section 4.2). That vector already ends with this
    // node, appended when the RREQ arrived.
    option.addressVector = dodag.aodv.addressVector;
    rrep.SetRrep(option);

    // The ART option of an RREP names the OrigNode, not the target: it is
    // what tells each router on the way back whether it is the OrigNode
    // (RFC 9854 section 6.4.2), and it carries this node's own Sequence
    // Number as the route's Dest SeqNo (section 6.3).
    RplDioHeader::ArtOption art;
    art.destSeqNo = m_aodvSeqNo;
    art.prefixLength = 0;
    art.target = key.dodagId; // the RREQ-Instance's DODAGID is the OrigNode
    rrep.SetArt(art);

    // The next hop back is the entry before this node's own in the Address
    // Vector, or the OrigNode itself when this node is the only entry.
    const std::vector<Ipv6Address>& hops = dodag.aodv.addressVector;
    NS_ASSERT_MSG(!hops.empty(), "The TargNode is not in its own Address Vector");
    Ipv6Address nextHop = hops.size() >= 2 ? hops[hops.size() - 2] : key.dodagId;

    NS_LOG_INFO("Answering the RREQ for " << dodag.aodv.target << " with an RREP over "
                                          << hops.size() << " hop(s)");
    SendAodvRrepTo(dodag, rrep, nextHop);
}

void
RplRoutingProtocol::HandleAodvRrep(const RplDioHeader& dio, Ipv6Address from, uint32_t interface)
{
    NS_LOG_FUNCTION(this << from << interface);

    const RplDioHeader::RrepOption& rrep = dio.GetRrep();

    // RFC 9854 section 4.2: "Exactly one RREP option MUST be present in an
    // RREP-DIO message, otherwise, the message MUST be dropped", and section
    // 4.3 the same for the one ART option an RREP carries.
    if (!dio.HasArt())
    {
        NS_LOG_WARN("Dropping an RREP-DIO with no ART option");
        return;
    }
    if (rrep.hopByHop)
    {
        NS_LOG_LOGIC("Dropping an RREP asking for hop-by-hop routing");
        return;
    }
    // No Compr check here, matching ShouldRefuseAodvRreq(): rrep.addressVector
    // is already full addresses regardless of what Compr the wire used (@see
    // RplDioHeader::Deserialize()).

    // Section 6.3.3 in reverse: the RREQ-InstanceID is the RREP's own
    // RPLInstanceID less Delta, wrapping the way the addition did.
    uint8_t rreqInstanceId = static_cast<uint8_t>(dio.GetInstanceId() - rrep.delta);
    Ipv6Address origNode = dio.GetArt().target;
    DodagKey rreqKey{rreqInstanceId, origNode};

    auto it = m_dodags.find(rreqKey);
    if (it == m_dodags.end())
    {
        // Nothing here asked for this route. Not an error worth warning
        // about: an RREP can outrace its own RREQ-Instance's 'L' deadline on
        // a node that has already left.
        NS_LOG_LOGIC("Dropping an RREP for RREQ-Instance " << +rreqInstanceId << " at " << origNode
                                                           << ", which this node is not part of");
        return;
    }
    DodagMembership& dodag = it->second;

    // RFC 9854 section 6.4: "a router that already belongs to the
    // RREP-Instance SHOULD drop the RREP-DIO". This module never forms an
    // RREP-Instance DODAG for a symmetric route (section 6.3.1), so there is
    // no membership to check; dodag.aodv.rrepHandled stands in for it.
    // Without this, a duplicate physical delivery of the same RREP-DIO
    // (link-layer retransmission, for example) got relayed again at every
    // intermediate hop -- harmless on its own since the Address Vector is
    // fixed-length so it does not amplify, but pure waste, and at the
    // OrigNode it just overwrote m_aodvRoutes[target] with identical data.
    if (dodag.aodv.rrepHandled)
    {
        NS_LOG_LOGIC("Already handled an RREP for RREQ-Instance "
                    << +rreqInstanceId << " at " << origNode << ", dropping a repeat");
        return;
    }
    dodag.aodv.rrepHandled = true;

    // RFC 9854 section 6.4.2: "The router next checks if one of its
    // addresses is included in the ART option. If it is included, this
    // router is the OrigNode of the route discovery."
    if (IsOwnAddress(origNode))
    {
        if (rrep.addressVector.empty())
        {
            NS_LOG_WARN("Dropping an RREP that carries no route at all");
            return;
        }

        AodvRoute route;
        route.hops = rrep.addressVector;
        route.rreqInstanceId = rreqInstanceId;
        route.destSeqNo = dio.GetArt().destSeqNo;
        // "The lifetime is set according to DODAG configuration (i.e., not
        // the L field)" (RFC 9854 section 6.4.3) -- the same PathLifetime
        // and lifetime unit a DAO-derived route gets.
        route.expire = Simulator::Now() + Seconds(m_pathLifetime * m_lifetimeUnit);

        // The TargNode is the last entry of the Address Vector, which is
        // what the route is keyed by.
        Ipv6Address target = route.hops.back();
        m_aodvRoutes[target] = route;

        NS_LOG_INFO("Route discovery to " << target << " completed over " << route.hops.size()
                                          << " hop(s), Dest SeqNo " << +route.destSeqNo);
        return;
    }

    // An intermediate router: pass it on, unchanged, one hop further back.
    // Nothing is recorded here -- RFC 9854 section 6.4.3 builds a route
    // entry only when H=1, which is exactly what source routing exists to
    // avoid.
    //
    // Section 6.4.1's "An intermediate router MUST discard an RREP if one of
    // its addresses is present in the Address Vector" is deliberately NOT
    // applied. On a symmetric route the Address Vector is the one the RREQ
    // accumulated on the way out (section 4.2), so by construction it holds
    // every intermediate router: read literally that rule would discard the
    // RREP at the first hop back and no symmetric discovery could ever
    // complete. It is a loop check for the asymmetric case, where the RREP
    // floods and accumulates a vector of its own. @see design-constraints.md.
    const std::vector<Ipv6Address>& hops = rrep.addressVector;
    size_t ownIndex = hops.size();
    for (size_t i = 0; i < hops.size(); i++)
    {
        if (IsOwnAddress(hops[i]))
        {
            ownIndex = i;
            break;
        }
    }
    if (ownIndex == hops.size())
    {
        NS_LOG_LOGIC("Dropping an RREP whose Address Vector does not run through this node");
        return;
    }

    Ipv6Address nextHop = ownIndex >= 1 ? hops[ownIndex - 1] : origNode;
    NS_LOG_INFO("Relaying an RREP for " << origNode << " onward via " << nextHop);
    SendAodvRrepTo(dodag, dio, nextHop);
}

void
RplRoutingProtocol::HandleAodvRrepInstance(const RplDioHeader& dio,
                                           Ipv6Address from,
                                           uint32_t interface)
{
    NS_LOG_FUNCTION(this << from << interface);

    DodagKey key{dio.GetInstanceId(), dio.GetDodagId()};

    auto it = m_dodags.find(key);
    if (it == m_dodags.end())
    {
        return;
    }
    DodagMembership& dodag = it->second;

    const RplDioHeader::RrepOption& rrep = dio.GetRrep();

    // RFC 9854 section 4.3: an RREP-DIO carries exactly one ART option, and
    // it is what names the OrigNode this RREP-Instance is aimed at. Checked
    // here rather than before the join for the same reason HandleAodvRreq()
    // checks its own: the DIO was a valid DIO, so the DODAG side of it
    // stands even when its AODV-RPL content is unusable.
    if (!dio.HasArt())
    {
        NS_LOG_WARN("Ignoring the AODV-RPL content of an RREP-DIO with no ART option");
        return;
    }
    if (rrep.hopByHop)
    {
        NS_LOG_LOGIC("Ignoring an RREP asking for hop-by-hop routing");
        return;
    }

    // The TargNode rooting this instance has nothing to learn from its own
    // flood coming back around.
    if (dodag.aodv.isRrepInstance && dodag.aodv.isTarget)
    {
        return;
    }

    // RFC 9854 section 6.4.1: "An intermediate router MUST discard an RREP
    // if one of its addresses is present in the Address Vector". This is
    // where that rule finally means something -- on an asymmetric route the
    // Address Vector is the RREP's own, accumulated as it floods, so a
    // repeat that already ran through here is a loop. (On a symmetric route
    // the vector is the RREQ's, which by construction holds every
    // intermediate router, so the same rule is deliberately not applied
    // there. @see HandleAodvRrep() and design-constraints.md.)
    for (const auto& hop : rrep.addressVector)
    {
        if (IsOwnAddress(hop))
        {
            NS_LOG_LOGIC("Dropping an RREP whose Address Vector already holds " << hop);
            return;
        }
    }

    // First arrival: record what this instance is. Re-recorded on a later,
    // better copy the same way HandleAodvRreq() does, which is what keeps
    // the Address Vector in step with the preferred parent.
    if (!dodag.aodv.addressVector.empty() && from != dodag.preferredParent)
    {
        NS_LOG_LOGIC("Already in RREP-Instance " << +key.instanceId
                                                  << " via a better parent than " << from
                                                  << ", ignoring this copy");
        return;
    }

    dodag.aodv.isRrepInstance = true;
    dodag.aodv.pairedInstanceId = static_cast<uint8_t>(dio.GetInstanceId() - rrep.delta);
    dodag.aodv.origNode = dio.GetArt().target;
    dodag.aodv.origSeqNo = dio.GetArt().destSeqNo;
    dodag.aodv.rankLimit = rrep.rankLimit;
    dodag.aodv.lifetimeField = rrep.lifetime;
    dodag.aodv.target = key.dodagId; // an RREP-Instance is rooted at the TargNode
    dodag.aodv.isTarget = false;
    dodag.aodv.isOrigin = IsOwnAddress(dodag.aodv.origNode);

    // Section 6.4.4: "If H=0, the intermediate router MUST include the
    // address of the interface receiving the RREP-DIO into the Address
    // Vector" -- the mirror of the RREQ's own rule, and the same recipe:
    // a global address, since the vector becomes a source route later.
    Ipv6Address ownAddress = GetGlobalAddressIn(dodag);
    if (ownAddress.IsAny())
    {
        NS_LOG_LOGIC("No global address to put in the Address Vector yet");
        return;
    }

    dodag.aodv.addressVector = rrep.addressVector;
    if (dodag.aodv.addressVector.size() >= RplDioHeader::AODV_ADDRESS_VECTOR_MAX_ENTRIES)
    {
        NS_LOG_WARN("The Address Vector is full at "
                    << dodag.aodv.addressVector.size() << " entries; leaving RREP-Instance "
                    << +key.instanceId);
        LeaveDodag(key, false);
        return;
    }

    if (dodag.aodv.isOrigin)
    {
        // The OrigNode consumes the RREP rather than propagating it: this is
        // the end of the flood's useful reach. Its own address is appended
        // first anyway, so the vector this node holds describes the whole
        // path the way every other member's does.
        dodag.aodv.addressVector.push_back(ownAddress);
        ArmAodvExpiry(dodag, key);

        // And the route falls out of it -- reversed. The RREP flooded from
        // the TargNode outward, each router appending itself, so this vector
        // runs TargNode-side first and ends at this node: [R2, R1, self] on
        // a line self--R1--R2--TargNode. AodvRoute::hops is the other way
        // round by construction, "every hop from the OrigNode outward, the
        // TargNode last", so it is this vector minus its own last entry,
        // reversed, with the TargNode appended: [R1, R2, TargNode].
        //
        // The symmetric case does no reversing: there the vector is the
        // RREQ's, already accumulated in the OrigNode-outward direction and
        // carried back unchanged (RFC 9854 section 4.2). Getting these two
        // the same way round is the single easiest thing to get wrong here,
        // which is why each direction has its own end-to-end test.
        //
        // Reversing is sound precisely because this is the RREP-Instance:
        // every router joined it over a link that satisfied the Objective
        // Function towards the TargNode (section 6.4.1), which is the
        // direction this route will carry data.
        AodvRoute route;
        NS_ASSERT_MSG(!dodag.aodv.addressVector.empty(), "The OrigNode is not in its own vector");
        for (size_t i = dodag.aodv.addressVector.size() - 1; i > 0; i--)
        {
            route.hops.push_back(dodag.aodv.addressVector[i - 1]);
        }
        route.hops.push_back(dodag.aodv.target);
        route.rreqInstanceId = dodag.aodv.pairedInstanceId;
        route.destSeqNo = dodag.aodv.origSeqNo;
        // "The lifetime is set according to DODAG configuration (i.e., not
        // the L field)" (section 6.4.3), same as the symmetric path.
        route.expire = Simulator::Now() + Seconds(m_pathLifetime * m_lifetimeUnit);
        m_aodvRoutes[dodag.aodv.target] = route;

        NS_LOG_INFO("Asymmetric route discovery to " << dodag.aodv.target << " completed over "
                                                     << route.hops.size() << " hop(s), Dest SeqNo "
                                                     << +route.destSeqNo);
        return;
    }

    dodag.aodv.addressVector.push_back(ownAddress);
    ArmAodvExpiry(dodag, key);

    NS_LOG_INFO("Joined RREP-Instance " << +key.instanceId << " at " << key.dodagId
                                        << " heading for OrigNode " << dodag.aodv.origNode << ", "
                                        << dodag.aodv.addressVector.size()
                                        << " hop(s) from the TargNode");
    // Nothing transmits here: this membership's own Trickle timer, reset by
    // HandleDio() when the preferred parent was chosen, multicasts the
    // RREP-DIO onward with SendDio() filling in the options.
}

bool
RplRoutingProtocol::GetAodvRoute(Ipv6Address target, std::vector<Ipv6Address>& hops) const
{
    hops.clear();
    auto it = m_aodvRoutes.find(target);
    if (it == m_aodvRoutes.end() || it->second.expire <= Simulator::Now())
    {
        return false;
    }
    hops = it->second.hops;
    return true;
}

uint32_t
RplRoutingProtocol::GetAodvRouteCount() const
{
    uint32_t count = 0;
    Time now = Simulator::Now();
    for (const auto& [target, route] : m_aodvRoutes)
    {
        if (route.expire > now)
        {
            count++;
        }
    }
    return count;
}

bool
RplRoutingProtocol::FindAodvRoute(Ipv6Address dst,
                                  std::vector<Ipv6Address>& hops,
                                  uint8_t& instanceId) const
{
    hops.clear();
    auto it = m_aodvRoutes.find(dst);
    if (it == m_aodvRoutes.end() || it->second.expire <= Simulator::Now())
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
    instanceId = it->second.rreqInstanceId;
    return true;
}

bool
RplRoutingProtocol::GetAodvAddressVector(uint8_t instanceId,
                                         Ipv6Address dodagId,
                                         std::vector<Ipv6Address>& addressVector) const
{
    addressVector.clear();
    auto it = m_dodags.find(DodagKey{instanceId, dodagId});
    if (it == m_dodags.end())
    {
        return false;
    }
    addressVector = it->second.aodv.addressVector;
    return true;
}

bool
RplRoutingProtocol::IsAodvTarget(uint8_t instanceId, Ipv6Address dodagId) const
{
    auto it = m_dodags.find(DodagKey{instanceId, dodagId});
    return it != m_dodags.end() && it->second.aodv.isTarget;
}

bool
RplRoutingProtocol::IsAodvSymmetric(uint8_t instanceId, Ipv6Address dodagId) const
{
    auto it = m_dodags.find(DodagKey{instanceId, dodagId});
    return it != m_dodags.end() && it->second.aodv.symmetric;
}

bool
RplRoutingProtocol::FindAodvRrepInstance(Ipv6Address origNode, DodagKey& key) const
{
    for (const auto& [candidate, dodag] : m_dodags)
    {
        if (dodag.aodv.isRrepInstance && dodag.aodv.origNode == origNode)
        {
            key = candidate;
            return true;
        }
    }
    return false;
}

} // namespace rpl
} // namespace ns3
