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
 * Scope: source-routed (H=0) and Hop-by-hop (H=1) discovery for a single
 * target, both symmetric (S=1) and asymmetric (S=0). H=1 shares
 * RplRoutingProtocol::m_hopByHopRoutes with P2P-RPL's own (RFC 6997, @see
 * rpl-p2p.cc, which needs none of core RPL's own storing mode either).
 * Unlike P2P-RPL's unidirectional, single-DODAG H=1, AODV-RPL's is
 * bidirectional (RFC 6550 section 5.1's Local RPLInstanceID 'D' flag: set
 * for the upward route, clear for the downward one). The upward route entry
 * (RFC 9854 section 6.2.3) is built the same way regardless of S --
 * HandleAodvRreq() -- since the RFC's own upward-route step has no S bit
 * qualifier at all, only section 6.2.4's choice of which reply mechanism to
 * use does. The downward route entry (section 6.4.3) differs by S: a
 * symmetric route's RREP-DIO is unicast hop-by-hop, so the sender is
 * already the next hop by construction (HandleAodvRrep()); an asymmetric
 * one floods a separate RREP-Instance DODAG rooted at TargNode, so the next
 * hop instead has to be that DODAG's own preferred parent
 * (HandleAodvRrepInstance()) -- both keep the entry's own RPLInstanceID as
 * the RREQ-InstanceID regardless of which DODAG built it, which is what
 * lets HasHopByHopRoute()'s rank-check bypass work for both without ever
 * comparing the RREQ-Instance's and RREP-Instance's unrelated Rank
 * hierarchies.
 *
 * Also implements the Gratuitous RREP (G-RREP) shortcut of RFC 9854 section
 * 7: an intermediate router relaying an RREQ that already caches a fresh
 * enough Hop-by-hop Route to the target (from some earlier, unrelated
 * discovery) answers OrigNode directly, without waiting for the discovery
 * to reach TargNode and a real RREP to come all the way back
 * (SendAodvGratuitousRrep(), triggered from HandleAodvRreq()). Only
 * meaningful for H=1: an H=0 relay never caches anything to answer from.
 * Deliberately NOT implemented: section 7's own further optimization of
 * unicast-relaying the RREQ itself along the cached route hop by hop
 * (rather than continuing to rely on the ordinary multicast Trickle flood
 * that still, independently, reaches TargNode either way) -- correctness
 * does not depend on it, and it would risk confusing the preferred-parent
 * tracking downstream nodes already do for the multicast copy, by having
 * the same RREQ-Instance arrive over two different paths. @see
 * design-constraints.md.
 */

#include "rpl-conf.h"
#include "rpl-header.h"
#include "rpl-routing-protocol.h"

#include "ns3/ipv6-l3-protocol.h"
#include "ns3/log.h"
#include "ns3/simulator.h"

#include <algorithm>

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
RplRoutingProtocol::DiscoverRoute(Ipv6Address target, bool hopByHop)
{
    NS_LOG_FUNCTION(this << target << hopByHop);

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
    dodag.aodv.hopByHop = hopByHop;
    dodag.aodv.target = target;
    // A single-entry record: this module's own DiscoverRoute() only ever
    // starts a discovery for one target at a time (RFC 9854 section 6.1's
    // OrigNode-initiated multi-target discovery, via more than one ART
    // option from the very start, is not exposed here -- the same scope
    // boundary P2P-RPL's own DiscoverP2pRoute() keeps, @see
    // design-constraints.md). SendDio() rebuilds the outgoing ART list from
    // this rather than from target directly, so it has to be seeded here
    // too, not just at a relay that learns it from an incoming RREQ-DIO.
    dodag.aodv.targets = {target};
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
RplRoutingProtocol::ShouldRefuseAodvInstance(DodagKey key, Ipv6Address from) const
{
    // RFC 9854 section 4.1's REJOIN_REENABLE. This is what actually ends a
    // discovery: a node that has served out its 'L' field is still
    // surrounded by neighbours Trickle-pacing the same DIO, and without this
    // it rejoins at once and the instance never dies. The node that rooted
    // the instance is the worst case -- it would rejoin its own discovery as
    // an ordinary member, take a preferred parent in a DODAG rooted at
    // itself, and route its own DODAGID away from itself.
    // Expired entries are swept by the callers' non-const counterparts;
    // this only reads.
    auto blocked = m_aodvRejoinBlocked.find(key);
    if (blocked != m_aodvRejoinBlocked.end() && Simulator::Now() < blocked->second)
    {
        NS_LOG_LOGIC("Refusing instance " << +key.instanceId << " at " << key.dodagId
                                          << ", left too recently to rejoin");
        return true;
    }

    // A DIO naming this node as the instance's own root, heard back from a
    // neighbour propagating it. Refused even before the instance expires:
    // joining a DODAG rooted at this node's own address would make it a
    // member of its own discovery. (While the membership still exists
    // HandleDio()'s isRoot check catches this first; this is what covers
    // the window after it has been erased.)
    if (IsOwnAddress(key.dodagId))
    {
        NS_LOG_LOGIC("Refusing this node's own instance, heard back from " << from);
        return true;
    }

    return false;
}

bool
RplRoutingProtocol::ShouldRefuseAodvRreq(const RplDioHeader& dio, Ipv6Address from) const
{
    const RplDioHeader::RreqOption& rreq = dio.GetRreq();
    DodagKey key{dio.GetInstanceId(), dio.GetDodagId()};

    // The two checks an RREQ-Instance and an RREP-Instance need alike: the
    // rejoin bar, and this node's own instance heard back.
    if (ShouldRefuseAodvInstance(key, from))
    {
        return true;
    }

    // No Compr check here: RplDioHeader::Deserialize() already reconstructs
    // full addresses from whatever Compr the sender used (RFC 9854 section
    // 4.1's "elided octets are shared with the IPv6 address in the
    // DODAGID"), so rreq.addressVector below is always full addresses
    // regardless of what was actually on the wire.

    if (rreq.hopByHop)
    {
        // RFC 9854 section 6.2.1: "When H=1 in the incoming RREQ, the
        // router MUST drop the RREQ message if the Orig SeqNo field of the
        // RREQ is older than the SeqNo value that X has stored for a route
        // to OrigNode." No route stored for this OrigNode yet is not stale
        // by definition. Read directly off m_hopByHopRoutes rather than
        // through FindHopByHopRoute()/HasHopByHopRoute(), neither of which
        // exposes the stored seqNo a caller would need to compare against.
        auto stored = m_hopByHopRoutes.find(dio.GetDodagId());
        if (stored != m_hopByHopRoutes.end() && stored->second.expire > Simulator::Now() &&
            RplSequenceNewer(stored->second.seqNo, rreq.origSeqNo))
        {
            NS_LOG_LOGIC("Refusing an RREQ with a stale Orig SeqNo "
                        << +rreq.origSeqNo << " for OrigNode " << dio.GetDodagId()
                        << ", already holding " << +stored->second.seqNo);
            return true;
        }
    }
    else
    {
        // RFC 9854 section 6.2.1: "When H=0 in the incoming RREQ, the
        // router MUST drop the RREQ-DIO if one of its addresses is present
        // in the Address Vector." The route would otherwise loop back
        // through here. Not meaningful for H=1, whose Address Vector stays
        // empty throughout (RFC 9854 section 4.1: "In hop-by-hop mode
        // (H=1), this field MUST be set to zero and ignored").
        for (const auto& hop : rreq.addressVector)
        {
            if (IsOwnAddress(hop))
            {
                NS_LOG_LOGIC("Refusing an RREQ whose Address Vector already holds " << hop);
                return true;
            }
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
        // relaxed by one step when an ART option names this node -- checked
        // against every ART option the RREQ-DIO carries (section 6.1: "the
        // OrigNode can include multiple TargNode addresses via multiple ART
        // options"), not just the first, since this router can be any one of
        // several TargNodes this discovery is looking for.
        uint16_t ownDagRank = static_cast<uint16_t>(advertisedDagRank + 1);
        bool isTarget = std::any_of(dio.GetArts().begin(),
                                    dio.GetArts().end(),
                                    [this](const RplDioHeader::ArtOption& art) {
                                        return IsOwnAddress(art.target);
                                    });
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

bool
RplRoutingProtocol::ShouldRefuseAodvRrep(const RplDioHeader& dio, Ipv6Address from) const
{
    DodagKey key{dio.GetInstanceId(), dio.GetDodagId()};

    // The two checks an RREQ-Instance and an RREP-Instance need alike: the
    // rejoin bar, and this node's own instance heard back.
    if (ShouldRefuseAodvInstance(key, from))
    {
        return true;
    }

    // RFC 9854 section 4.3: an RREP-DIO carries exactly one ART option, and
    // it is what names the OrigNode this RREP-Instance is aimed at.
    if (!dio.HasArt())
    {
        NS_LOG_WARN("Refusing an RREP-DIO with no ART option");
        return true;
    }

    const RplDioHeader::RrepOption& rrep = dio.GetRrep();

    // RFC 9854 section 6.4.1: "An intermediate router MUST discard an RREP
    // if one of its addresses is present in the Address Vector". On an
    // asymmetric route the Address Vector is the RREP's own, accumulated as
    // it floods, so a repeat that already ran through here is a loop. (On a
    // symmetric route the vector is the RREQ's, which by construction holds
    // every intermediate router, so the same rule is deliberately not
    // applied there. @see HandleAodvRrep() and design-constraints.md.)
    for (const auto& hop : rrep.addressVector)
    {
        if (IsOwnAddress(hop))
        {
            NS_LOG_LOGIC("Refusing an RREP whose Address Vector already holds " << hop);
            return true;
        }
    }

    // RFC 9854 section 6.4.1: "If the S bit of the RREQ-Instance is set to
    // 0, the router MUST determine whether the downward direction of the
    // link ... satisfies the OF and whether the router's Rank would not
    // exceed the RankLimit. If these are true, the router joins the DODAG
    // of the RREP-Instance." This module is always in that S=0 branch here
    // -- a symmetric route's RREP never reaches this function at all
    // (HandleDio() calls HandleAodvRrep() for it instead). The computation
    // mirrors ShouldRefuseAodvRreq()'s exactly (section 4.2 defines the RREP
    // option's own RankLimit "similarly to RankLimit in the RREQ message"),
    // with isOrigin standing in for isTarget: it is the OrigNode that
    // section 4.1's text relaxes the bound for ("TargNode can join ... at a
    // Rank ... less than or equal to the RankLimit"), the RREP-Instance's
    // equivalent of the RREQ-Instance's TargNode.
    //
    // Checked here rather than in HandleAodvRrepInstance(), even though the
    // RFC discusses it in the same breath as the Address Vector check just
    // above: unlike that one, this has to run before HandleDio()'s own
    // join, the same reason ShouldRefuseAodvRreq()'s own RankLimit check
    // does. HandleDio() calls JoinDodag() unconditionally for a DodagKey it
    // has no membership for yet, before HandleAodvRrepInstance() ever runs
    // -- refusing there would stop this function's caller from populating
    // dodag.aodv, but the ordinary DODAG membership JoinDodag() already
    // created would stay behind regardless, leaving the node joined in
    // every way IsJoinedTo() can see, just without the SendDio() branch
    // (@see the isRrepInstance check there) that would ever advertise
    // anything useful into it.
    if (rrep.rankLimit != RPL_AODV_RANK_LIMIT_INFINITE)
    {
        uint16_t minHopRankIncrease =
            dio.HasDagConfiguration() ? dio.GetMinHopRankIncrease() : m_minHopRankIncrease;
        NS_ASSERT_MSG(minHopRankIncrease > 0, "MinHopRankIncrease of zero would divide by zero");

        uint16_t advertisedDagRank = dio.GetRank() / minHopRankIncrease;
        if (advertisedDagRank >= rrep.rankLimit)
        {
            NS_LOG_LOGIC("Refusing an RREP-Instance DIO advertising DAGRank "
                        << advertisedDagRank << ", at or past the RankLimit "
                        << +rrep.rankLimit);
            return true;
        }

        uint16_t ownDagRank = static_cast<uint16_t>(advertisedDagRank + 1);
        bool isOrigin = IsOwnAddress(dio.GetArt().target);
        if (isOrigin ? (ownDagRank > rrep.rankLimit) : (ownDagRank >= rrep.rankLimit))
        {
            NS_LOG_LOGIC("Refusing an RREP-Instance DIO that would put this node at DAGRank "
                         << ownDagRank << ", past the RankLimit " << +rrep.rankLimit);
            return true;
        }
    }

    NS_LOG_LOGIC("Accepting an RREP-Instance DIO from " << from);
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
    // RREQ-Instance ... takes no further action" -- relaxed the same way
    // MatchesP2pTarget()'s caller relaxes P2P-RPL's own repeat guard
    // (@see design-constraints.md): section 6.2.2 lets "one of the
    // TargNodes ... be an intermediate router to other TargNodes" when a
    // discovery names more than one, so a TargNode only truly has nothing
    // further to do once targets (the ones still left to relay onward) is
    // also empty.
    if (dodag.aodv.isTarget && dodag.aodv.targets.empty())
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
    // H=1 keeps no Address Vector to read this from (@see below), so the
    // equivalent "already processed at least one copy" signal is instead
    // whether this router has already recorded an upward Hop-by-hop Route
    // for this exact RREQ-Instance.
    bool aodvAlreadyProcessed = rreq.hopByHop ? HasHopByHopRoute(key.instanceId, key.dodagId)
                                              : !dodag.aodv.addressVector.empty();
    if (aodvAlreadyProcessed && from != dodag.preferredParent)
    {
        NS_LOG_LOGIC("Already part of RREQ-Instance "
                    << +key.instanceId << " via a better parent than " << from
                    << ", ignoring this copy");
        return;
    }

    dodag.aodv.origSeqNo = rreq.origSeqNo;
    dodag.aodv.rankLimit = rreq.rankLimit;
    dodag.aodv.lifetimeField = rreq.lifetime;
    dodag.aodv.hopByHop = rreq.hopByHop; // SendDio() re-emits this, propagating H onward
    dodag.aodv.target = dio.GetArt().target;
    dodag.aodv.isOrigin = false;

    // RFC 9854 section 6.2.2: "the intermediate router maintains a record
    // of the targets that have been requested for a given RREQ-Instance"
    // and, once a later RREQ-DIO's own list differs from what came before,
    // propagates only "the intersection of all received lists". targets
    // holds that record; dodag.aodv.addressVector is still the previous
    // RREQ-DIO's own at this point (overwritten further down), so its
    // emptiness is what tells the very first RREQ-DIO this instance ever
    // processes apart from a later one -- nothing has been recorded yet
    // for the first, so it seeds the record outright instead of
    // intersecting against nothing.
    //
    // The RFC also asks a router to ignore "an incoming RREQ-DIO message
    // having multiple ART options coming from a router with higher Rank
    // than the Rank of the stored targets". A separate check for that is
    // not needed on top of this: the guard just above already refuses any
    // RREQ-DIO whose sender is not (still) dodag.preferredParent once this
    // router has joined, and SelectPreferredParent() -- run by HandleDio()
    // immediately before this function, on every DIO -- only ever moves
    // that to a neighbour whose Rank is at least as good as the best seen
    // so far, so a worse-Rank sender's copy never reaches this point to
    // begin with. @see design-constraints.md for the fuller comparison
    // against the RFC's own, per-target-record wording.
    std::vector<Ipv6Address> incomingTargets;
    for (const auto& art : dio.GetArts())
    {
        incomingTargets.push_back(art.target);
    }
    if (dodag.aodv.addressVector.empty())
    {
        dodag.aodv.targets = incomingTargets;
    }
    else
    {
        std::vector<Ipv6Address> intersected;
        for (const auto& storedTarget : dodag.aodv.targets)
        {
            if (std::find(incomingTargets.begin(), incomingTargets.end(), storedTarget) !=
                incomingTargets.end())
            {
                intersected.push_back(storedTarget);
            }
        }
        dodag.aodv.targets = intersected;
    }

    // "The router is a TargNode if it finds one of its own addresses in a
    // Target option in the RREQ" -- checked against every entry left in
    // targets after the intersection above, not just the first. If the
    // OrigNode is looking for more than one TargNode, "before transmitting
    // the RREQ-DIO ... a TargNode MUST delete the Target option
    // encapsulating its own address, so that downstream routers with
    // higher Rank values do not try to create a route to this TargNode" --
    // done here rather than at SendDio() time so that targets already
    // holds exactly what this router still needs to relay onward. Once
    // true, isTarget stays true even though the very entry that matched is
    // erased in the same step: RFC 9854 gives a router no way to
    // un-become a TargNode, the same "no way to un-become a Target"
    // reasoning MatchesP2pTarget()'s own caller documents for P2P-RPL.
    bool wasTarget = dodag.aodv.isTarget;
    bool matchedThisTime = false;
    for (auto entry = dodag.aodv.targets.begin(); entry != dodag.aodv.targets.end();)
    {
        if (IsOwnAddress(*entry))
        {
            matchedThisTime = true;
            entry = dodag.aodv.targets.erase(entry);
        }
        else
        {
            ++entry;
        }
    }
    dodag.aodv.isTarget = wasTarget || matchedThisTime;

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

    if (rreq.hopByHop)
    {
        // RFC 9854 sections 4.1/6.2.5: "In hop-by-hop mode (H=1), this
        // field MUST be set to zero and ignored" -- no Address Vector
        // maintenance at all. Instead, record this node's own next hop
        // toward OrigNode (section 6.2.3): from, the neighbour this RREQ-
        // DIO copy was accepted from (the guard above already refused any
        // copy not from dodag.preferredParent). Passed through as received
        // rather than resolved to a global address first: RouteToNeighbour()
        // accepts either form (its own neighbour.IsLinkLocal() check), and
        // InterfaceForNeighbour() matches on the interface identifier
        // shared by both forms regardless.
        if (!StoreHopByHopRoute(key.instanceId,
                               key.dodagId,
                               key.dodagId,
                               from,
                               Seconds(m_pathLifetime * m_lifetimeUnit),
                               true,
                               rreq.origSeqNo))
        {
            NS_LOG_LOGIC("Discarding an RREQ-DIO establishing a Hop-by-hop Route that conflicts "
                        "with or is staler than one already held for OrigNode "
                        << key.dodagId);
            return;
        }

        // RFC 9854 section 7: this router MAY short-circuit with a
        // Gratuitous RREP (G-RREP) if it already holds a downward
        // Hop-by-hop Route to the target -- from some earlier, unrelated
        // discovery -- at least as fresh as what OrigNode already knows.
        // "At least as fresh" is read off the RREQ-DIO's own ART option
        // destSeqNo (0 meaning "no known information", section 4.3), not
        // the RREQ option's own Orig SeqNo just stored above -- that is
        // OrigNode's freshness, a different node's entirely. Only
        // meaningful for H=1: an H=0 relay never caches a route at all, so
        // it can never be "already holding one" here (@see
        // design-constraints.md). Not attempted for the TargNode itself
        // (isTarget): it answers for real, via SendAodvRrep() below, once
        // matchedThisTime is known.
        auto cachedRoute = m_hopByHopRoutes.find(dodag.aodv.target);
        if (!dodag.aodv.isTarget && cachedRoute != m_hopByHopRoutes.end() &&
            cachedRoute->second.expire > Simulator::Now() &&
            !RplSequenceNewer(dio.GetArt().destSeqNo, cachedRoute->second.seqNo))
        {
            SendAodvGratuitousRrep(dodag,
                                   key,
                                   dodag.aodv.target,
                                   cachedRoute->second.seqNo,
                                   from);
        }
    }
    else
    {
        // RFC 9854 section 6.2.5: "the intermediate router MUST append the
        // address of its interface receiving the RREQ-DIO into the Address
        // Vector". A global address, not the link-local the DIO arrived
        // from: the vector becomes a source route later, and every entry
        // has to be reachable from more than one hop away.
        Ipv6Address ownAddress = GetGlobalAddressIn(dodag);
        if (ownAddress.IsAny())
        {
            NS_LOG_LOGIC("No global address to put in the Address Vector yet");
            return;
        }

        dodag.aodv.addressVector = rreq.addressVector;
        if (dodag.aodv.addressVector.size() >= RplDioHeader::AODV_ADDRESS_VECTOR_MAX_ENTRIES)
        {
            // The option's own 8-bit Opt Data Len cannot describe another
            // entry. The RankLimit normally stops a discovery long before
            // this, so reaching it means the limit was configured away (0,
            // "no limit").
            NS_LOG_WARN("The Address Vector is full at "
                        << dodag.aodv.addressVector.size()
                        << " entries; leaving RREQ-Instance " << +key.instanceId);
            LeaveDodag(key, false);
            return;
        }
        dodag.aodv.addressVector.push_back(ownAddress);
    }

    ArmAodvExpiry(dodag, key);

    NS_LOG_INFO("Joined RREQ-Instance " << +key.instanceId << " at " << key.dodagId
                                        << " looking for " << dodag.aodv.target << ", "
                                        << dodag.aodv.addressVector.size()
                                        << " hop(s) from the OrigNode"
                                        << (dodag.aodv.isTarget ? ", and this node is it" : "")
                                        << ", " << dodag.aodv.targets.size()
                                        << " target(s) left to relay onward");

    // RFC 9854 section 6.2.6: a TargNode that was not already in the
    // RREQ-Instance "prepares and transmits an RREP-DIO". Answered once --
    // matchedThisTime can only be true when wasTarget was still false: the
    // repeat guard above already returns early whenever isTarget is true
    // and nothing is left in targets, and a TargNode with other targets
    // still outstanding cannot match its own address a second time, since
    // the very entry that matched it the first time was erased out of
    // targets in that same step above.
    if (matchedThisTime)
    {
        SendAodvRrep(dodag, key);
    }

    // Nothing sends the RREQ onward here: DioTrickleFire() already
    // multicasts this membership's DIO on its own schedule, and SendDio()
    // fills in the RREQ and ART options from the state just recorded -- or,
    // if targets came out empty, suppresses the RREQ-DIO outright (section
    // 6.2.2's "If the intersection is empty ... the router MUST NOT
    // transmit any RREQ-DIO"). The Trickle timer was reset by HandleDio()
    // when the preferred parent was chosen, so the propagation is already
    // imminent either way.
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
RplRoutingProtocol::SendAodvGratuitousRrep(DodagMembership& dodag,
                                           DodagKey key,
                                           Ipv6Address target,
                                           uint8_t targetSeqNo,
                                           Ipv6Address upwardNextHop)
{
    NS_LOG_FUNCTION(this << +key.instanceId << key.dodagId << target << upwardNextHop);

    RplDioHeader rrep;
    // RFC 9854 section 6.3.3: Delta stays 0 here for the same reason
    // SendAodvRrep()'s own symmetric branch does -- no RREP-Instance DODAG
    // is ever built for a Gratuitous RREP to collide with either.
    rrep.SetInstanceId(key.instanceId);
    rrep.SetVersionNumber(0);
    rrep.SetRank(m_minHopRankIncrease);
    rrep.SetMop(RPL_MOP_P2P_ROUTE_DISCOVERY);
    rrep.SetGrounded(true);
    rrep.SetDtsn(0);
    // RFC 9854 section 4.2: "TargNode sets one of its IPv6 addresses in the
    // DODAGID field of the RREP-DIO message" -- this router is speaking on
    // TargNode's own behalf (section 7), not answering for itself, so this
    // is target rather than this node's own address (@see SendAodvRrep(),
    // whose ordinary RREP-DIO uses its own).
    rrep.SetDodagId(target);

    RplDioHeader::RrepOption option;
    option.gratuitous = true;        // RFC 9854 section 7's 'G' bit
    option.hopByHop = dodag.aodv.hopByHop; // always true in practice, @see the caller
    option.lifetime = dodag.aodv.lifetimeField;
    option.rankLimit = dodag.aodv.rankLimit;
    option.delta = 0;
    // Empty: a Gratuitous RREP for H=1 carries no Address Vector, the same
    // reason an ordinary H=1 RREP does not (RFC 9854 section 4.1). Source-
    // routed (H=0) Gratuitous RREPs are out of scope here; @see
    // design-constraints.md for why H=1 is this feature's only realistic
    // trigger in this module regardless.
    rrep.SetRrep(option);

    RplDioHeader::ArtOption art;
    // "Sequence Number for the last route that OrigNode stored to the
    // Destination" (section 4.3) is what an ordinary RREP's own ART option
    // carries too -- read from the cached route this router already held
    // rather than from this node's own m_aodvSeqNo, since this router is
    // not TargNode and has no Sequence Number of TargNode's to increment;
    // it can only vouch for the freshness of the route it is offering.
    art.destSeqNo = targetSeqNo;
    art.prefixLength = 0;
    art.target = key.dodagId; // the RREQ-Instance's DODAGID is OrigNode
    rrep.SetArt(art);

    NS_LOG_INFO("Answering the RREQ for " << target << " with a Gratuitous RREP over a cached "
                                          "route, sent upward via "
                                          << upwardNextHop);
    SendAodvRrepTo(dodag, rrep, upwardNextHop);
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
    // Carried over from the RREQ-Instance: SendDio() re-emits this on every
    // RREP-DIO transmission the same way it does for the RREQ side, and
    // HandleAodvRrepInstance() reads it to decide whether to build an H=0
    // AodvRoute (from the flooded Address Vector) or an H=1 downward
    // HopByHopRoute (from the preferred parent) once the flood completes.
    rrepDodag.aodv.hopByHop = rreqDodag.aodv.hopByHop;
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
    option.hopByHop = dodag.aodv.hopByHop; // "MUST be set to be the same as the H bit in the RREQ option"
    // compr left at its default: RplDioHeader::Serialize() computes its own
    // from the addresses below and m_dodagId, ignoring this field.
    option.lifetime = dodag.aodv.lifetimeField;
    option.rankLimit = dodag.aodv.rankLimit;
    option.delta = 0;
    // "for a symmetric route, it is the Address Vector when the RREQ-DIO
    // arrives at the TargNode, unchanged during the transmission to the
    // OrigNode" (RFC 9854 section 4.2). That vector already ends with this
    // node, appended when the RREQ arrived -- empty throughout for H=1
    // (section 4.1: "In hop-by-hop mode (H=1), this field MUST be set to
    // zero and ignored"), since HandleAodvRreq() never populates it then.
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

    // The next hop back: for a Source Route (H=0), the entry before this
    // node's own in the Address Vector, or the OrigNode itself when this
    // node is the only entry; for a Hop-by-hop Route (H=1), the upward
    // route HandleAodvRreq() already recorded when this RREQ-DIO was
    // accepted (RFC 9854 section 6.3.1: "the RREP-DIO message is unicast to
    // the Next Hop according to the Address Vector (H=0) or the route entry
    // (H=1)").
    Ipv6Address nextHop;
    if (dodag.aodv.hopByHop)
    {
        bool found = FindHopByHopRoute(key.instanceId, key.dodagId, key.dodagId, nextHop);
        NS_ASSERT_MSG(found, "HandleAodvRreq() must have stored the upward route by now");
    }
    else
    {
        const std::vector<Ipv6Address>& hops = dodag.aodv.addressVector;
        NS_ASSERT_MSG(!hops.empty(), "The TargNode is not in its own Address Vector");
        nextHop = hops.size() >= 2 ? hops[hops.size() - 2] : key.dodagId;
    }

    NS_LOG_INFO("Answering the RREQ for " << dodag.aodv.target << " with an RREP, next hop "
                                          << nextHop);
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
    // No Compr check here, matching ShouldRefuseAodvRreq(): rrep.addressVector
    // is already full addresses regardless of what Compr the wire used (@see
    // RplDioHeader::Deserialize()). Asymmetric H=1 stays out of scope (@see
    // ShouldRefuseAodvRreq()'s matching guard); this function only ever
    // handles the symmetric case (HandleDio() dispatches here for a unicast
    // RREP-DIO specifically), so no further check is needed here for that.

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

    // RFC 9854 sections 6.2.3/6.4.3: an H=1 route entry records only each
    // router's own next hop, unlike H=0's whole path, so every router the
    // RREP passes through -- OrigNode included -- stores its own downward
    // entry toward TargNode here, pointing at from: one hop closer to
    // TargNode than this router is, since the RREP travels that direction
    // back from wherever it originated. dodag.aodv.target already names
    // TargNode, set from the RREQ-Instance's own ART option this same
    // membership recorded (DiscoverRoute() at the OrigNode,
    // HandleAodvRreq() everywhere else). destSeqNo is TargNode's own
    // Sequence Number, the freshness this specific (downward) direction is
    // judged by, the same way Orig SeqNo judges the upward one.
    if (rrep.hopByHop)
    {
        if (!StoreHopByHopRoute(rreqInstanceId,
                               origNode,
                               dodag.aodv.target,
                               from,
                               Seconds(m_pathLifetime * m_lifetimeUnit),
                               true,
                               dio.GetArt().destSeqNo))
        {
            NS_LOG_LOGIC("Discarding an RREP establishing a Hop-by-hop Route that conflicts "
                        "with or is staler than one already held for "
                        << dodag.aodv.target);
            return;
        }
    }

    // RFC 9854 section 6.4.2: "The router next checks if one of its
    // addresses is included in the ART option. If it is included, this
    // router is the OrigNode of the route discovery."
    if (IsOwnAddress(origNode))
    {
        if (rrep.hopByHop)
        {
            NS_LOG_INFO("Hop-by-hop Route discovery to " << dodag.aodv.target
                                                          << " completed, next hop " << from);
            return;
        }

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
    Ipv6Address nextHop;
    if (rrep.hopByHop)
    {
        // RFC 9854 section 6.4.4: "the local route entry" -- this node's
        // own upward Hop-by-hop Route toward OrigNode, recorded by
        // HandleAodvRreq() when the original RREQ-DIO passed through here.
        if (!FindHopByHopRoute(rreqInstanceId, origNode, origNode, nextHop))
        {
            NS_LOG_LOGIC("Dropping an RREP for " << origNode
                        << ": no upward Hop-by-hop Route recorded for it");
            return;
        }
    }
    else
    {
        // Section 6.4.1's "An intermediate router MUST discard an RREP if one
        // of its addresses is present in the Address Vector" is deliberately
        // NOT applied. On a symmetric route the Address Vector is the one the
        // RREQ accumulated on the way out (section 4.2), so by construction
        // it holds every intermediate router: read literally that rule would
        // discard the RREP at the first hop back and no symmetric discovery
        // could ever complete. It is a loop check for the asymmetric case,
        // where the RREP floods and accumulates a vector of its own. @see
        // design-constraints.md.
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
        nextHop = ownIndex >= 1 ? hops[ownIndex - 1] : origNode;
    }

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

    // The rejoin bar for this key has run out, or HandleDio() would not have
    // let the join through. Dropping it here keeps the map from growing
    // without bound, the same way HandleAodvRreq() does for its own.
    m_aodvRejoinBlocked.erase(key);

    auto it = m_dodags.find(key);
    if (it == m_dodags.end())
    {
        return;
    }
    DodagMembership& dodag = it->second;

    const RplDioHeader::RrepOption& rrep = dio.GetRrep();

    // Every check that has to run before HandleDio()'s own join --
    // structural validity, the loop check, and the RankLimit -- is in
    // ShouldRefuseAodvRrep() instead, called from there. This function only
    // ever runs once that join has already happened.

    // The TargNode rooting this instance has nothing to learn from its own
    // flood coming back around.
    if (dodag.aodv.isRrepInstance && dodag.aodv.isTarget)
    {
        return;
    }

    uint8_t pairedInstanceId = static_cast<uint8_t>(dio.GetInstanceId() - rrep.delta);

    // First arrival: record what this instance is. Re-recorded on a later,
    // better copy the same way HandleAodvRreq() does, which is what keeps
    // the Address Vector in step with the preferred parent. H=1 keeps no
    // Address Vector to read this from (@see below), so the equivalent
    // "already processed at least one copy" signal is instead whether this
    // router has already recorded a downward Hop-by-hop Route for this
    // exact RREP-Instance's own TargNode.
    bool alreadyProcessed = rrep.hopByHop ? HasHopByHopRoute(pairedInstanceId, key.dodagId)
                                          : !dodag.aodv.addressVector.empty();
    if (alreadyProcessed && from != dodag.preferredParent)
    {
        NS_LOG_LOGIC("Already in RREP-Instance " << +key.instanceId
                                                  << " via a better parent than " << from
                                                  << ", ignoring this copy");
        return;
    }

    dodag.aodv.isRrepInstance = true;
    dodag.aodv.pairedInstanceId = pairedInstanceId;
    dodag.aodv.origNode = dio.GetArt().target;
    dodag.aodv.origSeqNo = dio.GetArt().destSeqNo;
    dodag.aodv.rankLimit = rrep.rankLimit;
    dodag.aodv.lifetimeField = rrep.lifetime;
    dodag.aodv.hopByHop = rrep.hopByHop; // SendDio() re-emits this, propagating H onward
    dodag.aodv.target = key.dodagId; // an RREP-Instance is rooted at the TargNode
    dodag.aodv.isTarget = false;
    dodag.aodv.isOrigin = IsOwnAddress(dodag.aodv.origNode);

    if (rrep.hopByHop)
    {
        // RFC 9854 section 6.4.3: "For an asymmetric route, the Next Hop is
        // the preferred parent in the DODAG of RREP-Instance" -- read as
        // dodag.preferredParent rather than from, unlike the symmetric
        // case's HandleAodvRrep(): the RREP-Instance is flooded rather than
        // unicast hop-by-hop, so from is merely whichever copy is being
        // processed right now, while dodag.preferredParent is the one
        // SelectPreferredParent() (run by HandleDio() immediately before
        // this function, on every DIO) has already resolved to the best
        // Rank seen so far. The alreadyProcessed guard above already keeps
        // the two equal at this specific point (a worse-Rank copy is
        // refused before reaching here, so from always matches whatever
        // dodag.preferredParent already was), which is why
        // RplAodvAsymmetricHopByHopRouteFollowsParentTestCase cannot
        // independently observe this choice over from -- dodag.preferredParent
        // is still the right one to read: correct by construction rather
        // than by coincidence with a guard that could change independently
        // of this line. The RPLInstanceID is the RREQ-InstanceID
        // (pairedInstanceId) regardless of which
        // DODAG -- RREQ-Instance or RREP-Instance -- established the entry
        // (sections 6.2.3 and 6.4.3 agree on this), which is exactly what
        // lets HasHopByHopRoute()'s bypass work here despite the
        // RREP-Instance's own Rank hierarchy being unrelated to the
        // RREQ-Instance's (@see design-constraints.md for why the Rank
        // mismatch this was once thought to block on does not matter to a
        // bypass that never compares Ranks at all).
        if (!StoreHopByHopRoute(pairedInstanceId,
                               dodag.aodv.origNode,
                               key.dodagId,
                               dodag.preferredParent,
                               Seconds(m_pathLifetime * m_lifetimeUnit),
                               true,
                               dodag.aodv.origSeqNo))
        {
            NS_LOG_LOGIC("Discarding an RREP-Instance DIO establishing a Hop-by-hop Route that "
                        "conflicts with or is staler than one already held for "
                        << key.dodagId);
            return;
        }

        ArmAodvExpiry(dodag, key);

        if (dodag.aodv.isOrigin)
        {
            NS_LOG_INFO("Asymmetric Hop-by-hop Route discovery to "
                        << key.dodagId << " completed, next hop " << dodag.preferredParent);
        }
        else
        {
            NS_LOG_INFO("Joined RREP-Instance " << +key.instanceId << " at " << key.dodagId
                                                << " heading for OrigNode " << dodag.aodv.origNode);
        }
        // Nothing else transmits here: this membership's own Trickle timer,
        // reset by HandleDio() when the preferred parent was chosen,
        // multicasts the RREP-DIO onward with SendDio() filling in the
        // options -- the same division of labour the H=0 branch below uses.
        return;
    }

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
RplRoutingProtocol::GetAodvTargets(uint8_t instanceId,
                                   Ipv6Address dodagId,
                                   std::vector<Ipv6Address>& targets) const
{
    targets.clear();
    auto it = m_dodags.find(DodagKey{instanceId, dodagId});
    if (it == m_dodags.end())
    {
        return false;
    }
    targets = it->second.aodv.targets;
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
