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
 * Scope: source-routed (H=0), symmetric (S=1) discovery for a single target.
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

    // Compr is only ever sent as 0 here, and a nonzero one would mean the
    // Address Vector's entries have had prefix octets elided that this
    // implementation never puts back.
    if (rreq.compr != 0)
    {
        NS_LOG_LOGIC("Refusing an RREQ with Compr " << +rreq.compr
                                                    << ": address elision is not implemented");
        return true;
    }

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

    // Already in this instance, from an earlier copy of the same RREQ. RFC
    // 9854 section 6.2.6: a TargNode "already associated with the
    // RREQ-Instance ... takes no further action". For an intermediate router
    // the Address Vector already recorded is the one it propagates, and
    // replacing it with a later copy's would swap a settled route for
    // another with no reason to prefer it.
    if (!dodag.aodv.addressVector.empty() || dodag.aodv.isTarget)
    {
        NS_LOG_LOGIC("Already part of RREQ-Instance " << +key.instanceId << ", ignoring a repeat");
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
    // Deciding that is explicitly out of the RFC's own scope ("It is beyond
    // the scope of this document to specify the criteria used when
    // determining whether or not each link is symmetric"), and this module
    // has no reverse-direction link metric to consult: the ETX it keeps is
    // measured on received frames only. Every link is therefore treated as
    // symmetric, which is also the RFC's own opening position -- "Links are
    // considered symmetric until indication to the contrary is received"
    // (section 5). @see design-constraints.md.
    dodag.aodv.symmetric = rreq.symmetric;

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

    // Nothing sends the RREQ onward here: DioTrickleFire() already
    // multicasts this membership's DIO on its own schedule, and SendDio()
    // fills in the RREQ and ART options from the state just recorded. The
    // Trickle timer was reset by HandleDio() when the preferred parent was
    // chosen, so the propagation is already imminent.
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

} // namespace rpl
} // namespace ns3
