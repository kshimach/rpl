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
 * Scope: a single Target, a single Source Route (H=0) or Hop-by-hop Route
 * (H=1). Neither needs core RPL's own storing mode (MOP 2, DAO-driven) at
 * all -- every field H=1 support needs comes from the P2P-RDO/P2P-DRO
 * messages this module already exchanges; @see design-constraints.md.
 */

#include "rpl-conf.h"
#include "rpl-header.h"
#include "rpl-routing-protocol.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

#include <algorithm>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("RplP2p");

namespace rpl
{

RplRoutingProtocol::DodagKey
RplRoutingProtocol::DiscoverP2pRoute(Ipv6Address target, bool hopByHop)
{
    NS_LOG_FUNCTION(this << target << hopByHop);

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
    // RFC 6997 section 7, the 'N' field: "This field is valid only if the R
    // flag is set to one and the H flag is set to zero... When Hop-by-hop
    // Routes are being discovered, the N field MUST be set to zero on
    // transmission and ignored on reception." Section 9.5 says the same
    // thing from the Target's side: "If the H flag inside the P2P-RDO is
    // set to one, the Target needs to select one route". So P2pNumRoutes
    // only ever reaches the wire on a Source Route discovery.
    dodag.p2p.numRoutes = hopByHop ? 0 : m_p2pNumRoutes;
    dodag.p2p.reply = true;
    dodag.p2p.hopByHop = hopByHop;
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
RplRoutingProtocol::MatchesP2pTarget(const RplDioHeader& dio) const
{
    if (IsOwnAddress(dio.GetP2pRdo().target))
    {
        return true;
    }
    for (const auto& targetOption : dio.GetTargets())
    {
        if (IsOwnAddress(targetOption.target))
        {
            return true;
        }
    }
    return false;
}

bool
RplRoutingProtocol::HasOtherP2pTargets(const DodagMembership& dodag) const
{
    for (const auto& target : dodag.p2p.additionalTargets)
    {
        if (!IsOwnAddress(target))
        {
            return true;
        }
    }
    return false;
}

bool
RplRoutingProtocol::ShouldRefuseP2pRdo(const RplDioHeader& dio, Ipv6Address from) const
{
    DodagKey key{dio.GetInstanceId(), dio.GetDodagId()};

    // RFC 6997 sections 8/9.6/9.7: once a P2P-DRO with 'S' = 1 has been seen
    // for this temporary DAG, "SHOULD NOT...process any more DIOs" for it --
    // @see DodagMembership::P2pState::stopped's own comment for the other
    // half (not generating any more).
    auto existing = m_dodags.find(key);
    if (existing != m_dodags.end() && existing->second.p2p.stopped)
    {
        NS_LOG_LOGIC("Refusing a P2P mode DIO for a temporary DAG that has already stopped");
        return true;
    }

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
    // for "is this node the TargNode/OrigNode" there -- this router is a
    // Target if one of its own addresses is the P2P-RDO's own primary
    // TargetAddr or names one of any additional RPL Target options
    // (@see MatchesP2pTarget(), RFC 6997 section 9.3).
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
        bool isTarget = MatchesP2pTarget(dio);
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
    // from a later copy -- unless other Targets (RPL Target options,
    // @see MatchesP2pTarget()) remain undiscovered, in which case RFC 6997
    // section 9.5 has it continue "as an Intermediate Router would": still
    // accumulating and re-advertising the Address Vector below, for
    // whichever other Target(s) are further along. HasOtherP2pTargets()
    // reads additionalTargets as last known from whenever this node most
    // recently processed a DIO for this temporary DAG (rebuilt fresh below,
    // the same "state from the last DIO" contract addressVector already
    // has), so false here means either this is the single-Target case
    // HandleAodvRreq()'s own isTarget repeat check mirrors, or every other
    // Target this node once knew about is gone from the DIOs it has heard
    // since -- either way, nothing left to relay onward for.
    // RFC 6997 section 9.4's route diversity, kept ahead of every guard
    // below for the same reason the alternate collection is: the copies
    // those guards discard are exactly the ones carrying a different route.
    RecordP2pCandidateRoute(dodag, rdo, from);

    // RFC 6997 section 7's 'N': the Origin asked for more than one route, so
    // a copy of the DIO this node would otherwise drop below -- as a repeat,
    // or as having come from something other than the preferred parent -- is
    // exactly what carries the alternate. Recorded before both of those
    // guards for that reason, and only at a Target that has already
    // recognised itself: the copy that made this node a Target is the one
    // addressVector holds, and everything after it is a candidate alternate.
    // rdo.numRoutes, not dodag.p2p.numRoutes: this runs ahead of the guards
    // below, and so ahead of the assignment that adopts this DIO's 'N', so
    // reading the membership here would cap the collection by the PREVIOUS
    // DIO's value. 'H' = 1 forces zero for the same reason it does there
    // (RFC 6997 section 7's "ignored on reception").
    uint8_t asked = rdo.hopByHop ? 0 : rdo.numRoutes;
    if (dodag.p2p.isTarget && asked > 0)
    {
        RecordP2pAlternateRoute(dodag, rdo, asked);
    }

    if (dodag.p2p.isTarget && !HasOtherP2pTargets(dodag))
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
    // "...and ignored on reception" (section 7). Zeroed rather than merely
    // skipped at the branch below, so that this node also re-emits zero
    // when it relays the DIO onward (@see SendDio()) -- a peer that sets
    // both bits does not get its 'N' laundered through this router.
    dodag.p2p.numRoutes = rdo.hopByHop ? 0 : rdo.numRoutes;
    dodag.p2p.reply = rdo.reply;
    dodag.p2p.hopByHop = rdo.hopByHop;
    // Once true, stays true even if a later DIO's P2P-RDO TargetAddr
    // happens to differ (RFC 6997 gives routers no way to un-become a
    // Target); MatchesP2pTarget() also catches an RPL Target option match,
    // which the old IsOwnAddress(rdo.target) alone missed entirely.
    dodag.p2p.isTarget = dodag.p2p.isTarget || MatchesP2pTarget(dio);

    // Raw copy of this DIO's own RPL Target options, unfiltered: RFC 6997
    // has no rule removing a Target option once it matches this router
    // (unlike AODV-RPL's ART, which a TargNode MUST delete its own copy of
    // before relaying, @see design-constraints.md), so section 9.5's "no
    // other Targets...specified via RPL Target options" is checked as
    // written -- an empty list, not an empty list-minus-self.
    dodag.p2p.additionalTargets.clear();
    for (const auto& targetOption : dio.GetTargets())
    {
        dodag.p2p.additionalTargets.push_back(targetOption.target);
    }

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

    // Whether this DIO named this node as (one of) the Target(s), whatever
    // the node's own broader isTarget history -- this specific reply is
    // triggered by this specific DIO having matched, not by isTarget
    // already being true from a previous one (the repeat guard above
    // already filtered out DIOs that would not otherwise have reached
    // here).
    if (dodag.p2p.isTarget)
    {
        // RFC 6997 section 9.5: "A Target MUST NOT forward a P2P mode DIO
        // any further if no other Targets are to be discovered... the
        // Target MUST generate DIOs for this route discovery as an
        // Intermediate Router would" otherwise. The latter needs nothing
        // extra here: falling through to the function's end does not
        // itself send anything (DioTrickleFire() -- already reset above,
        // via SelectPreferredParent() in HandleDio() -- is what re-floods
        // this membership's DIO on its own schedule, exactly like an
        // ordinary relay's), so the only decision left to make here is the
        // reply below, gated on additionalTargets being irrelevant to it:
        // RFC 6997 does not condition sending a P2P-DRO on whether other
        // Targets remain, only on the 'R' flag.
        // "If the Reply flag inside the P2P-RDO in the received DIO is set
        // to one, the Target MUST select one or more discovered routes and
        // send one or more P2P-DRO messages" (section 9.5). How many is
        // the 'N' field's business: one when it is zero, sent from here,
        // and otherwise a batch assembled by P2pDroCollectExpire() once
        // the collection window closes.
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
            //
            // Wrapped at the wire field's own 2-bit width rather than left
            // to grow (distinct from RplSequenceIncrement(), this module's
            // RFC 6550 section 7.2 wraparound for its 8-bit lollipop
            // counters like dodag.version in GlobalRepairFire() -- this
            // 'Seq' is a P2P-RPL/RFC 6997 field of its own, unrelated
            // width and rule):
            // a Target with a temporary DAG membership that outlives its
            // own 'L' deadline by little enough, or one that keeps
            // re-matching a Target named only via an RPL Target option
            // (@see DodagMembership::P2pState::additionalTargets, never
            // filtered down to exclude this node's own already-matched
            // entry), can run this every time a fresh-looking DIO arrives
            // for as long as the membership exists -- found by
            // /protocol-test-matrix's own multi-Target relay test, an
            // NS_ASSERT in RplP2pDroHeader::SetSequence() ("Seq does not
            // fit its 2-bit field") past four cycles without this.
            dodag.p2p.droSequence =
                (dodag.p2p.droSequence + 1) & (RPL_P2P_DRO_SEQ_MASK >> RPL_P2P_DRO_SEQ_SHIFT);
            dodag.p2p.droAckPending = m_p2pDroAckRequested;
            dodag.p2p.droRetriesLeft = m_p2pDroMaxRetransmissions;
            if (dodag.p2p.numRoutes == 0)
            {
                // The single-route case, untouched: reply now, from the one
                // route this DIO just delivered.
                //
                // A window may still be open from an earlier DIO that
                // carried a nonzero 'N' (only reachable on the multi-Target
                // path, where the repeat guard above lets later DIOs
                // through). Cancelling it is what keeps this reply the only
                // one: left running, it would fire with extra == 0 and send
                // this same P2P-DRO a second time, re-arming droRetryEvent
                // for a Seq the Origin has already acknowledged.
                dodag.p2p.droCollectEvent.Cancel();
                dodag.p2p.droCollecting = false;
                SendP2pDro(dodag, key);
            }
            else if (!dodag.p2p.droCollecting)
            {
                // 'N' > 0. Replying from here would send the only route this
                // node has heard so far, N+1 times over -- the copy that made
                // it a Target is by construction the first copy to arrive.
                // Hold off instead and let RecordP2pAlternateRoute() collect
                // whatever else the flood brings, @see P2pDroCollectExpire().
                //
                // Never re-armed while a window is already open: a
                // multi-Target discovery can reach this branch again (the
                // repeat guard above lets DIOs through while other Targets
                // are still outstanding), and restarting the window on each
                // one would let a steady DIO stream defer the reply past the
                // temporary DAG's own 'L' deadline entirely.
                // Clamped to close before the temporary DAG's own 'L'
                // deadline. RFC 6997 section 9.5: "all P2P-DRO
                // transmissions and retransmissions MUST take place while
                // the Target is still a part of the temporary DAG... A
                // Target MUST NOT transmit a P2P-DRO if it no longer
                // belongs to this DAG." LeaveDodag() cancels this event, so
                // an over-long window can never violate that MUST -- it
                // just means the Target silently never answers at all,
                // which is worse than answering early with whatever it has.
                //
                // ArmP2pExpiry() ran earlier in this same call, so what
                // GetDelayLeft() reports here is always the full 'L' rather
                // than any partially elapsed remainder -- the comparison is
                // effectively "is the configured window at least as long as
                // 'L' itself". NOT reachable at the defaults: 256 ms is
                // below even the shortest 'L' of 1 s. It takes a caller
                // configuring a window of a second or more, which this
                // module's own tests do. (An earlier version of this
                // comment, and of design-constraints.md section 73.4,
                // claimed the default reached it; that was arithmetically
                // wrong and the /protocol-test-matrix audit caught it.)
                Time window = m_p2pDroCollectWindow;
                Time remaining = dodag.p2p.expiry.GetDelayLeft();
                if (window >= remaining)
                {
                    window = remaining / 2;
                    NS_LOG_WARN("P2pDroCollectWindow ("
                                << m_p2pDroCollectWindow.As(Time::MS)
                                << ") outlasts this temporary DAG; collecting for "
                                << window.As(Time::MS) << " instead");
                }
                // The previous cycle's retry timer belongs to a Seq this
                // cycle has just superseded, and nothing will be on the
                // wire for the new one until the window closes. Left armed,
                // it fires mid-window and pushes slot 0 out early under the
                // new Seq -- a send the window exists to prevent, and one
                // that spends a retry on something that is not a retry.
                // (The 'N' = 0 branch above gets this for free: its
                // SendP2pDro() re-arms the timer immediately.)
                dodag.p2p.droRetryEvent.Cancel();
                dodag.p2p.droCollecting = true;
                dodag.p2p.droCollectEvent.SetFunction(&RplRoutingProtocol::P2pDroCollectExpire,
                                                      this);
                dodag.p2p.droCollectEvent.SetArguments(key);
                dodag.p2p.droCollectEvent.Cancel();
                dodag.p2p.droCollectEvent.Schedule(window);
                NS_LOG_INFO("Holding the P2P-DRO reply for "
                            << window.As(Time::MS) << " to collect up to "
                            << +dodag.p2p.numRoutes << " alternate route(s)");
            }
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

    // The single tracked route: 'S' as it has always been computed, and the
    // one P2P-DRO droSequence/droAckPending/droRetriesLeft belong to.
    SendP2pDroRoute(dodag,
                    key,
                    dodag.p2p.addressVector,
                    dodag.p2p.droSequence,
                    !HasOtherP2pTargets(dodag),
                    m_p2pDroAckRequested);
}

void
RplRoutingProtocol::SendP2pDroRoute(DodagMembership& dodag,
                                    DodagKey key,
                                    const std::vector<Ipv6Address>& route,
                                    uint8_t sequence,
                                    bool stop,
                                    bool trackAck)
{
    NS_LOG_FUNCTION(this << +key.instanceId << key.dodagId << route.size() << +sequence << stop
                         << trackAck);

    NS_ASSERT_MSG(!route.empty(), "The Target is not in its own Address Vector");
    Ipv6Address ownAddress = route.back();

    RplP2pDroHeader dro;
    dro.SetInstanceId(dodag.instanceId);
    // 'S' is decided by the caller, @see the stop parameter. Both of RFC
    // 6997 section 9.5's conditions for it are evaluated there: "this
    // router is the only Target specified in the corresponding DIO" is
    // HasOtherP2pTargets() being false -- the more permissive reading of
    // section 9.3's own condition, @see its doc comment and
    // design-constraints.md for why a plain additionalTargets.empty()
    // check is not enough -- and "the Target has already selected the
    // desired number of routes" is true of every route in a batch, since
    // P2pDroCollectExpire() has the whole batch in hand before it sends
    // any of it.
    dro.SetStop(stop);
    dro.SetAckRequested(trackAck);
    dro.SetSequence(sequence);
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
    rdo.addressVector.assign(route.begin(), route.end() - 1);
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
                                                   << (trackAck ? ", ack requested" : ""));

    // Only arms the wait timer, never resets droAckPending/droRetriesLeft:
    // this function is also what P2pDroRetry() calls to resend the exact
    // same P2P-DRO on timeout, and doing either here would make every retry
    // renew its own retry budget, so MAX_P2P_DRO_RETRANSMISSIONS would never
    // actually bind. The callers that start a cycle -- HandleP2pRdo() for
    // 'N' = 0, P2pDroCollectExpire() for 'N' > 0 -- own that state
    // themselves instead, and P2pDroRetry() deliberately leaves it alone.
    if (trackAck)
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
RplRoutingProtocol::PruneP2pCandidateRoutes(DodagMembership& dodag)
{
    uint16_t best = RPL_INFINITE_RANK;
    std::vector<DodagMembership::P2pState::P2pCandidate> live;
    live.reserve(dodag.p2p.candidateRoutes.size());

    for (auto& candidate : dodag.p2p.candidateRoutes)
    {
        auto parent = dodag.parents.find(candidate.from);
        if (parent == dodag.parents.end())
        {
            // The neighbour this route runs through is no longer a usable
            // parent -- SelectPreferredParent()'s staleness sweep erased it.
            // Advertising a path into it would send the eventual P2P-DRO
            // through a node this router cannot reach itself.
            NS_LOG_LOGIC("Dropping a candidate route through " << candidate.from
                                                                << ", no longer a parent");
            continue;
        }
        uint16_t rank = RankViaParent(dodag, parent->second);
        if (rank == RPL_INFINITE_RANK)
        {
            continue;
        }
        best = std::min(best, rank);
        live.push_back(std::move(candidate));
    }

    // "As long as all these routes are the best seen so far" (RFC 6997
    // section 9.4) is a constraint on the set being internally consistent,
    // so only the survivors that still tie the best rank stay. best is
    // recomputed from the live parent set rather than remembered, which is
    // what lets candidateRank rise again when this router's own best rank
    // legitimately worsens.
    dodag.p2p.candidateRoutes.clear();
    for (auto& candidate : live)
    {
        auto parent = dodag.parents.find(candidate.from);
        if (RankViaParent(dodag, parent->second) == best)
        {
            dodag.p2p.candidateRoutes.push_back(std::move(candidate));
        }
    }
    dodag.p2p.candidateRank = best;
}

void
RplRoutingProtocol::RecordP2pCandidateRoute(DodagMembership& dodag,
                                            const P2pRdoOption& rdo,
                                            Ipv6Address from)
{
    NS_LOG_FUNCTION(this << from << rdo.addressVector.size());

    // The rank this node would advertise if it took this neighbour as its
    // parent -- RFC 6997 section 9.4: "the route comparison in a P2P-RPL
    // route discovery is performed using the parent selection rules of the
    // OF in use as specified in Section 14 of RPL". HandleDio() has already
    // folded this DIO into dodag.parents by the time it calls into here
    // (@see its own comment at the call site), so the entry is current.
    auto parent = dodag.parents.find(from);
    if (parent == dodag.parents.end())
    {
        return;
    }
    uint16_t rank = RankViaParent(dodag, parent->second);
    if (rank == RPL_INFINITE_RANK)
    {
        return;
    }

    // Against the live set, not against a high-water mark: a route whose
    // neighbour has since gone, or whose rank has since moved, must not go
    // on defining what "best" means here.
    PruneP2pCandidateRoutes(dodag);

    // Worse than what is already held: nothing to keep. "As long as all
    // these routes are the best seen so far" is the whole constraint on the
    // set, and it is what keeps this from degenerating into "remember every
    // route anyone ever advertised".
    if (rank > dodag.p2p.candidateRank)
    {
        return;
    }

    Ipv6Address ownAddress = GetGlobalAddressIn(dodag);
    if (ownAddress.IsAny())
    {
        return;
    }
    // The same full-vector rule HandleP2pRdo() applies to addressVector
    // (section 9.4), applied before this node appends itself. Over-full is
    // a reason to drop the candidate, not to leave the DAG: the membership
    // decision belongs to HandleP2pRdo() and is made on the copy that
    // actually becomes addressVector.
    if (rdo.addressVector.size() >= RPL_P2P_ADDRESS_VECTOR_MAX_ENTRIES)
    {
        return;
    }
    std::vector<Ipv6Address> route = rdo.addressVector;
    route.push_back(ownAddress);

    if (rank < dodag.p2p.candidateRank)
    {
        // A strictly better route supersedes the whole set rather than
        // joining it, so the invariant "every entry ties candidateRank"
        // holds without a sweep.
        NS_LOG_INFO("A rank " << rank << " route supersedes " << dodag.p2p.candidateRoutes.size()
                              << " candidate(s) at rank " << dodag.p2p.candidateRank);
        dodag.p2p.candidateRoutes.clear();
        dodag.p2p.candidateRank = rank;
    }

    for (const auto& known : dodag.p2p.candidateRoutes)
    {
        if (route == known.route)
        {
            return;
        }
    }

    // Bounded by the same limit the Address Vector itself has. Without a cap
    // this grows with the number of neighbours advertising a tied rank, and
    // it is filled straight from received DIOs -- RFC 6997 puts no bound on
    // it at all, so this one is this module's own.
    if (dodag.p2p.candidateRoutes.size() >= RPL_P2P_ADDRESS_VECTOR_MAX_ENTRIES)
    {
        NS_LOG_LOGIC("Not keeping a further tied-rank route; the candidate set is full");
        return;
    }

    NS_LOG_INFO("Keeping a rank " << rank << " route over " << route.size() - 1
                                  << " hop(s) as candidate " << dodag.p2p.candidateRoutes.size());
    dodag.p2p.candidateRoutes.push_back({from, std::move(route)});
}

void
RplRoutingProtocol::RecordP2pAlternateRoute(DodagMembership& dodag,
                                            const P2pRdoOption& rdo,
                                            uint8_t asked)
{
    NS_LOG_FUNCTION(this << rdo.addressVector.size());

    Ipv6Address ownAddress = GetGlobalAddressIn(dodag);
    if (ownAddress.IsAny())
    {
        return;
    }

    // Completed the same way HandleP2pRdo() completes addressVector: this
    // node's own address appended, the full-vector check applied first
    // (RFC 6997 section 9.4). Unlike there, an over-full vector is only a
    // reason to drop this candidate, not to leave the temporary DAG --
    // this node is a Target, and the route it is actually replying with is
    // addressVector's, which is nowhere near the limit or it would have
    // left already.
    if (rdo.addressVector.size() >= RPL_P2P_ADDRESS_VECTOR_MAX_ENTRIES)
    {
        return;
    }
    std::vector<Ipv6Address> route = rdo.addressVector;
    route.push_back(ownAddress);

    // Exact-duplicate rejection only. RFC 6997 section 9.5 says "the Target
    // SHOULD avoid selecting routes that have large segments in common",
    // and this does not meet that in full: a partial-overlap metric would
    // have to invent both a threshold and a tie-break this module has no
    // basis to pick. (The "This document does not prescribe a particular
    // method" sentence nearby is not cover for it -- that one is about how
    // the Target discovers candidates, and the SHOULD is a separate
    // constraint on whichever method it picks.) What this does catch is
    // the limiting case, identical routes, which arrive routinely because
    // a neighbour re-floods the same DIO on every Trickle interval.
    // Overlap short of identity is a known gap, @see design-constraints.md.
    if (route == dodag.p2p.addressVector)
    {
        return;
    }
    for (const auto& known : dodag.p2p.alternateRoutes)
    {
        if (route == known)
        {
            return;
        }
    }

    // Capped at exactly what was asked for: 'N' is 2 bits, so at most three
    // alternates on top of the one addressVector already holds. Once full,
    // a new candidate displaces the longest held route if it beats it,
    // rather than being dropped for arriving second -- RFC 6997 section
    // 9.5 offers "selecting the best routes discovered over a certain time
    // period" as an example method, and a window that keeps the first
    // arrivals regardless of quality is not that. Hop count is the only
    // comparison available: OF0 is the objective function in use here, and
    // the Address Vector carries no metric of its own.
    if (dodag.p2p.alternateRoutes.size() >= asked)
    {
        auto worst = std::max_element(dodag.p2p.alternateRoutes.begin(),
                                      dodag.p2p.alternateRoutes.end(),
                                      [](const auto& a, const auto& b) {
                                          return a.size() < b.size();
                                      });
        if (worst == dodag.p2p.alternateRoutes.end() || worst->size() <= route.size())
        {
            return;
        }
        NS_LOG_INFO("A " << route.size() - 1 << "-hop alternate route displaces a "
                         << worst->size() - 1 << "-hop one");
        *worst = std::move(route);
        return;
    }

    NS_LOG_INFO("Recorded an alternate route to this Target over " << route.size() - 1
                                                                    << " hop(s)");
    dodag.p2p.alternateRoutes.push_back(std::move(route));
}

void
RplRoutingProtocol::P2pDroCollectExpire(DodagKey key)
{
    auto it = m_dodags.find(key);
    if (it == m_dodags.end())
    {
        return;
    }
    DodagMembership& dodag = it->second;

    NS_LOG_FUNCTION(this << +key.instanceId << key.dodagId
                         << dodag.p2p.alternateRoutes.size());

    dodag.p2p.droCollecting = false;

    // Guards the pre-window code got for free by running inline with the
    // DIO that triggered it, and which the state can have left behind
    // during the window: a later DIO can clear 'R'.
    //
    // stopped is deliberately NOT among them, though an earlier version of
    // this check included it. RFC 6997 section 5 says a router seeing 'S'
    // "SHOULD NOT process any more DIOs", "SHOULD NOT generate any more
    // DIOs" and "SHOULD cancel any pending DIO transmissions" -- all about
    // DIOs, none about a P2P-DRO this Target has already committed to
    // sending. Section 9.5's "the Target MUST select one or more discovered
    // routes and send one or more P2P-DRO messages" is what it owes, and
    // the window is a deferral of that reply, not a reconsideration of it.
    // Including stopped here meant another Target's own batch -- which
    // travels back through this node and sets stopped on it -- could land
    // inside this Target's window and silence it outright, leaving the
    // Origin with no route to it and no retry to recover with.
    if (!dodag.p2p.isTarget || !dodag.p2p.reply)
    {
        NS_LOG_LOGIC("The collection window closed on a Target with nothing left to answer");
        dodag.p2p.alternateRoutes.clear();
        return;
    }

    if (dodag.p2p.addressVector.empty())
    {
        // Nothing to reply with. Only reachable if the membership lost its
        // Address Vector between arming the window and now; the
        // single-route path asserts instead, because it runs inline with
        // the DIO that just filled it in.
        NS_LOG_WARN("The collection window closed with no route to reply with");
        return;
    }

    // 'S' goes on every P2P-DRO of the batch, not just the last. RFC 6997
    // section 9.5's second condition is that "the Target has already
    // selected the desired number of routes", and by the time anything is
    // sent from here the whole batch has been selected -- the window has
    // closed and nothing more will be added. Putting it only on the last
    // one would be legal too, but strictly worse in this implementation:
    // section 5 has every router that hears a P2P-DRO with 'S' stop
    // processing DIOs for the temporary DAG, HandleP2pDro() only ever acts
    // on the router named at the current NH position, and each route in
    // the batch travels a different path -- so "last only" would deliver
    // the stop signal along one path and leave every other path running to
    // its own 'L' deadline. It also keeps a P2pDroRetry() resend identical
    // to what it resends: SendP2pDro() recomputes 'S' from
    // HasOtherP2pTargets() alone, which would otherwise flip a slot-0
    // retry from 'S' = 0 to 'S' = 1.
    const bool stop = !HasOtherP2pTargets(dodag);

    // Slot 0, the tracked one: identical in every respect to what the
    // single-route path sends, including its 'A' flag and retry budget,
    // which HandleP2pRdo() has already set up.
    SendP2pDroRoute(dodag, key, dodag.p2p.addressVector, dodag.p2p.droSequence, stop,
                    m_p2pDroAckRequested);

    uint32_t sent = 1;
    for (const auto& route : dodag.p2p.alternateRoutes)
    {
        // The set's own cap was applied per arrival, against whatever 'N'
        // that DIO carried; a later DIO can have lowered it. Bounding the
        // loop here as well is what makes "one plus 'N'" hold on the wire
        // whatever order the values arrived in.
        if (sent > dodag.p2p.numRoutes)
        {
            break;
        }
        // Only genuinely distinct routes go out; a short batch is not
        // padded up to 'N' + 1 with copies of a route already sent. RFC
        // 6997 section 9.5's "one plus the value of the N field" describes
        // how many routes the Target selects, while the SHOULD two
        // sentences later -- "the Target SHOULD avoid selecting routes that
        // have large segments in common" -- constrains which ones qualify,
        // and two identical routes are that prohibition's limiting case.
        // Spending a network-wide multicast flood per duplicate to satisfy
        // a count, at the cost of the SHOULD, is the wrong trade.
        // @see design-constraints.md.
        //
        // The window's own dedup ran against the addressVector as it stood
        // when each alternate arrived, and a preferred-parent switch
        // mid-window can have replaced it since, so the comparison is
        // repeated here against what slot 0 actually sent.
        if (route == dodag.p2p.addressVector)
        {
            continue;
        }
        // Every route in the batch carries the same 'Seq'. Seq exists only
        // to match a P2P-DRO-ACK back to the P2P-DRO it acknowledges (RFC
        // 6997 section 10), these carry 'A' = 0 and so are never
        // acknowledged, and giving them Seqs of their own would burn
        // through the field's 2 bits and start colliding with the Seq of
        // the *next* cycle, which is tracked.
        SendP2pDroRoute(dodag, key, route, dodag.p2p.droSequence, stop, false);
        sent++;
    }

    NS_LOG_INFO("Replied with " << sent << " P2P-DRO(s) over distinct routes, of the "
                                << +dodag.p2p.numRoutes + 1 << " asked for");

    // Cleared so that a genuinely new reply cycle (a multi-Target discovery
    // reaching HandleP2pRdo()'s reply branch again) collects afresh rather
    // than re-sending what it already sent.
    dodag.p2p.alternateRoutes.clear();
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
        // The Origin asked about one Target; a P2P-DRO naming a different
        // one is answering a question it never posed. Nothing in the
        // message is authenticated (RFC 6997 section 14: "a rogue router
        // could...generate bogus P2P-DRO messages carrying bad routes"),
        // and without this a neighbour of the Origin could plant an entry
        // in m_p2pRoutes for any destination at all by forging a P2P-DRO
        // for a discovery it merely overheard. Matching the Target is the
        // one thing about a P2P-DRO the Origin does independently know.
        if (rdo.target != dodag.p2p.target)
        {
            NS_LOG_LOGIC("Dropping a P2P-DRO for " << rdo.target << ", not this discovery's "
                                                   << dodag.p2p.target);
            return;
        }

        if (rdo.hopByHop)
        {
            // RFC 6997 section 9.7: "the Origin MUST store in its memory
            // the state for this Hop-by-hop Route in the manner described
            // in Section 9.6" -- the same next-hop rule an intermediate
            // router's own uses below, with the Origin standing in for
            // "NH=0": the next hop is Address[1] (addressVector.front()),
            // unless the vector is empty, i.e. the Target is a direct
            // neighbour, in which case the Target itself is the next hop.
            Ipv6Address nextHop =
                rdo.addressVector.empty() ? rdo.target : rdo.addressVector.front();
            if (!StoreHopByHopRoute(dodag.instanceId,
                                    dodag.dodagId,
                                    rdo.target,
                                    nextHop,
                                    Seconds(m_pathLifetime * m_lifetimeUnit)))
            {
                NS_LOG_LOGIC("Discarding a P2P-DRO establishing a Hop-by-hop Route that "
                            "conflicts with one already held for "
                            << rdo.target);
                return;
            }
            NS_LOG_INFO("P2P-RPL Hop-by-hop Route discovery to "
                        << rdo.target << " completed, next hop " << nextHop);
        }
        else
        {
            // RFC 6997 section 9.7. rdo.addressVector is the fixed
            // snapshot the Target built once (SendP2pDro()), already
            // running Origin-outward -- unlike AODV-RPL's asymmetric
            // RREP-Instance, whose own vector accumulates hop by hop
            // during the flood back and so needs reversing at the
            // OrigNode, this needs none (@see design-constraints.md).
            P2pRoute route;
            route.hops = rdo.addressVector;
            route.hops.push_back(rdo.target);
            route.instanceId = dodag.instanceId;
            // "The lifetime is set according to DODAG configuration (i.e.,
            // not the L field)" -- RFC 9854 section 6.4.3's wording for
            // the AODV-RPL analogue, and the same PathLifetime/lifetime
            // unit a DAO-derived route gets; RFC 6997 has no equivalent
            // sentence of its own but the same reasoning applies (the
            // temporary DAG's own 'L' bounds discovery, not the route it
            // finds).
            route.expire = Simulator::Now() + Seconds(m_pathLifetime * m_lifetimeUnit);

            // Shortest wins within one discovery, rather than last wins.
            // With 'N' = 0 this is a distinction without a difference (the
            // only repeats are P2pDroRetry()'s own resends of an identical
            // route, which are not strictly shorter), but 'N' > 0 has the
            // Target answer with several genuinely different routes, and
            // taking whichever happened to arrive last would make the
            // alternates it went to the trouble of collecting worth nothing.
            // m_p2pRoutes still holds exactly one route per Target: RFC 6997
            // gives no rule for keeping several, and choosing between them
            // afterwards (failover? load sharing?) is a policy this module
            // has no basis to invent.
            auto existing = m_p2pRoutes.find(rdo.target);
            if (dodag.p2p.routeStored && existing != m_p2pRoutes.end() &&
                existing->second.hops.size() < route.hops.size())
            {
                NS_LOG_INFO("Keeping the " << existing->second.hops.size()
                                            << "-hop route to " << rdo.target
                                            << " over this discovery's " << route.hops.size()
                                            << "-hop one");
            }
            else
            {
                m_p2pRoutes[rdo.target] = route;
                NS_LOG_INFO("P2P-RPL route discovery to " << rdo.target << " completed over "
                                                           << route.hops.size() << " hop(s)");
            }
            dodag.p2p.routeStored = true;
        }

        // RFC 6997 section 9.7: "If the A flag is set to one...the Origin
        // MUST generate a P2P-DRO-ACK message...and unicast the message to
        // the Target." Fields are copied straight from the P2P-DRO, per
        // section 10's "MUST have the same values as the corresponding
        // fields in the P2P-DRO message". The route just recorded above
        // resolves the unicast: RouteOutput()'s own P2P route lookup (@see
        // GetP2pRoute()) finds it by rdo.target, the same way ordinary
        // application traffic to a freshly discovered P2P-RPL target does.
        if (dro.GetAckRequested())
        {
            RplP2pDroAckHeader ack;
            ack.SetInstanceId(dro.GetInstanceId());
            ack.SetSequence(dro.GetSequence());
            ack.SetDodagId(dro.GetDodagId());

            Ptr<Packet> ackPacket = Create<Packet>();
            ackPacket->AddHeader(ack);
            SendRplMessageUnicast(ackPacket, RPL_CODE_P2P_DRO_ACK, rdo.target);

            NS_LOG_INFO("Acknowledging the P2P-DRO from " << rdo.target << " (Seq "
                                                           << +dro.GetSequence() << ")");
        }

        // RFC 6997 section 9.7: "If the Stop flag...is set to one, the
        // Origin SHOULD NOT generate any more DIOs for this temporary DAG
        // and SHOULD cancel any pending DIO transmissions." Only the
        // "SHOULD NOT...generate" half is implemented, via
        // ShouldRefuseP2pRdo()'s own stopped check refusing this node's own
        // rejoin/reprocessing path -- not dioTrickle.Stop() itself. Calling
        // that here was tried and reverted: it silences this node's DIOs
        // for the temporary DAG immediately, but a downstream router whose
        // preferredParent is this node is still an ordinary DodagMembership
        // as far as the generic staleness sweep in SelectPreferredParent()
        // is concerned, and going silent reads to it as "parent died", not
        // "discovery is over" -- it loses its last parent and poisons
        // itself out within a few Trickle intervals, well before its own
        // 'L' deadline. @see design-constraints.md.
        dodag.p2p.stopped = dodag.p2p.stopped || dro.GetStop();
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

    if (rdo.hopByHop)
    {
        // RFC 6997 section 9.6: "the router MUST store the state for the
        // Forward Hop-by-hop Route carried inside the P2P-RDO... the IPv6
        // address of the next hop, Address[NH+1] (unless the NH value
        // equals the number of elements in the Address vector, in which
        // case the Target itself is the next hop)". NH is still
        // rdo.maxRankOrNh here (this node's own position, Address[NH]),
        // not yet decremented -- Address[NH+1] is addressVector[NH] in
        // the Address vector's own 0-indexed storage.
        Ipv6Address nextHop = (rdo.maxRankOrNh == rdo.addressVector.size())
                                  ? rdo.target
                                  : rdo.addressVector[rdo.maxRankOrNh];
        if (!StoreHopByHopRoute(dro.GetInstanceId(),
                                dro.GetDodagId(),
                                rdo.target,
                                nextHop,
                                Seconds(m_pathLifetime * m_lifetimeUnit)))
        {
            NS_LOG_LOGIC("Discarding a P2P-DRO establishing a Hop-by-hop Route that conflicts "
                        "with one already held for "
                        << rdo.target);
            return;
        }
    }

    // "The router MUST decrement the NH field inside the P2P-RDO and send
    // the P2P-DRO message further via link-local multicast."
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

    // RFC 6997 section 9.6: same Stop handling as the Origin branch above
    // (@see its own comment for why dioTrickle.Stop() is deliberately not
    // called here), after relaying rather than before -- relaying this
    // P2P-DRO is unaffected by its own Stop flag, the same "P2P-DRO
    // processing continues regardless" rule.
    dodag.p2p.stopped = dodag.p2p.stopped || dro.GetStop();
}

void
RplRoutingProtocol::HandleP2pDroAck(const RplP2pDroAckHeader& ack, Ipv6Address from)
{
    NS_LOG_FUNCTION(this << from);

    // Resolved by the DODAG the P2P-DRO-ACK itself names, the same reason
    // HandleDaoAck() does: with more than one temporary DAG's own P2P-DRO
    // pending an ack at once, a P2P-DRO-ACK naming one must not be applied
    // to a different membership's droAckPending/droRetryEvent.
    auto it = m_dodags.find(DodagKey{ack.GetInstanceId(), ack.GetDodagId()});
    if (it == m_dodags.end())
    {
        NS_LOG_LOGIC("Dropping a P2P-DRO-ACK for a temporary DAG this node is not part of");
        return;
    }
    DodagMembership& dodag = it->second;

    if (!dodag.p2p.isTarget || !dodag.p2p.droAckPending)
    {
        NS_LOG_LOGIC("Not waiting on a P2P-DRO-ACK for this temporary DAG, dropping");
        return;
    }

    if (ack.GetSequence() != dodag.p2p.droSequence)
    {
        // A stale ack for a P2P-DRO this node has since superseded (a newer
        // DIO arrived and HandleP2pRdo() started a fresh cycle with its own
        // Seq), or a misdirected one.
        NS_LOG_LOGIC("Ignoring a P2P-DRO-ACK for sequence "
                    << +ack.GetSequence() << ", waiting for " << +dodag.p2p.droSequence);
        return;
    }

    dodag.p2p.droRetryEvent.Cancel();
    dodag.p2p.droAckPending = false;

    NS_LOG_INFO("P2P-DRO-ACK received for sequence " << +ack.GetSequence() << " from " << from);
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
