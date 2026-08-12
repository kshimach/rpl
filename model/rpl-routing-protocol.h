/*
 * Copyright (c) 2026 ns-3 RPL module contributors
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * RPL (RFC 6550) in non-storing mode, ported from Contiki-NG rpl-lite
 * (Copyright (c) 2010, Swedish Institute of Computer Science, 3-clause BSD).
 */

#ifndef RPL_ROUTING_PROTOCOL_H
#define RPL_ROUTING_PROTOCOL_H

#include "rpl-conf.h"
#include "rpl-trickle-timer.h"

#include "ns3/callback.h"
#include "ns3/ipv6-address.h"
#include "ns3/ipv6-interface.h"
#include "ns3/ipv6-l3-protocol.h"
#include "ns3/ipv6-routing-protocol.h"
#include "ns3/nstime.h"
#include "ns3/random-variable-stream.h"
#include "ns3/socket.h"
#include "ns3/timer.h"

#include <map>
#include <tuple>

namespace ns3
{
namespace rpl
{

/// @defgroup rpl RPL Routing

class RplDioHeader;
class RplDaoHeader;
class RplDaoAckHeader;
class RplP2pDroHeader;
class RplP2pDroAckHeader;

/**
 * @ingroup rpl
 *
 * @brief RPL, the IPv6 Routing Protocol for Low-Power and Lossy Networks.
 *
 * The protocol is designed to run over the 6LoWPAN adaptation layer in
 * route-over mode, i.e. it must be installed on the IPv6 interfaces backed by
 * a SixLowPanNetDevice rather than on the underlying LrWpanNetDevice.
 *
 * RPL control messages are ICMPv6 type 155. ns-3's Icmpv6L4Protocol silently
 * discards unknown ICMPv6 types, so instead of subclassing it this protocol
 * opens an Ipv6RawSocket per interface: Ipv6L3Protocol::LocalDeliver() hands a
 * copy of every locally-destined packet to the raw sockets before running the
 * layer-4 demux. No modification of the ns-3 core is required.
 *
 * The upward routes of the DODAG are built from DIOs paced by a Trickle timer,
 * with ranks computed by OF0 (RFC 6552). The downward routes are those of the
 * non-storing mode: every node tells the root, with a DAO, which parent it
 * sits under, so only the root holds a picture of the topology and it puts the
 * whole path into every packet it sends down, as a real RFC 6554 Routing
 * Header. @see RplSourceRoutingHeader for the wire format and
 * RplIpv6ExtensionSourceRouting for how it is processed hop by hop.
 */
class RplRoutingProtocol : public Ipv6RoutingProtocol
{
  public:
    /**
     * @brief Identifies one RPL Instance this node is currently part of.
     *
     * RFC 6550 section 5.1: a Local RPLInstanceID (the high bit set) is only
     * meaningful together with the DODAGID of the node that assigned it --
     * two different origins may reuse the same raw ID byte for two entirely
     * unrelated instances. Keying on the pair rather than the ID alone
     * covers that case for free, which is also the pairing RFC 6997 section
     * 12 requires to identify a P2P-RPL Hop-by-hop Route. A Global
     * RPLInstanceID (the only kind this module forms today) just always
     * pairs with the one DODAG this node picked within it.
     *
     * Public because CreateLocalDodag() hands one back to its caller, and
     * IsJoinedTo()/GetRankIn() take one to identify a non-base membership.
     */
    struct DodagKey
    {
        uint8_t instanceId; //!< RPLInstanceID
        Ipv6Address dodagId; //!< DODAGID

        /**
         * @brief Order two keys, so this type can be a std::map key.
         * @param other the key to compare against
         * @return true if this key sorts before @p other
         */
        bool operator<(const DodagKey& other) const
        {
            return std::tie(instanceId, dodagId) < std::tie(other.instanceId, other.dodagId);
        }

        /**
         * @brief Compare two keys for equality.
         *
         * Needed because a DodagKey travels as a bound argument on the
         * Callback DioTrickleFire() is invoked through (MakeCallback(...,
         * this, key) in JoinDodag()/HandleDadSuccess()): ns-3's
         * CallbackComponent<T> requires operator== on any bound argument
         * type, to support comparing two Callback objects for equality.
         *
         * @param other the key to compare against
         * @return true if the two keys are equal
         */
        bool operator==(const DodagKey& other) const
        {
            return instanceId == other.instanceId && dodagId == other.dodagId;
        }

        /**
         * @brief Compare two keys for inequality.
         * @param other the key to compare against
         * @return true if the two keys are not equal
         */
        bool operator!=(const DodagKey& other) const
        {
            return !(*this == other);
        }
    };

    /**
     * @brief Get the type ID.
     * @return the object TypeId
     */
    static TypeId GetTypeId();

    RplRoutingProtocol();
    ~RplRoutingProtocol() override;

    // Inherited from Ipv6RoutingProtocol
    Ptr<Ipv6Route> RouteOutput(Ptr<Packet> p,
                               const Ipv6Header& header,
                               Ptr<NetDevice> oif,
                               Socket::SocketErrno& sockerr) override;
    bool RouteInput(Ptr<const Packet> p,
                    const Ipv6Header& header,
                    Ptr<const NetDevice> idev,
                    const UnicastForwardCallback& ucb,
                    const MulticastForwardCallback& mcb,
                    const LocalDeliverCallback& lcb,
                    const ErrorCallback& ecb) override;
    void NotifyInterfaceUp(uint32_t interface) override;
    void NotifyInterfaceDown(uint32_t interface) override;
    void NotifyAddAddress(uint32_t interface, Ipv6InterfaceAddress address) override;
    void NotifyRemoveAddress(uint32_t interface, Ipv6InterfaceAddress address) override;
    void NotifyAddRoute(Ipv6Address dst,
                        Ipv6Prefix mask,
                        Ipv6Address nextHop,
                        uint32_t interface,
                        Ipv6Address prefixToUse = Ipv6Address::GetZero()) override;
    void NotifyRemoveRoute(Ipv6Address dst,
                           Ipv6Prefix mask,
                           Ipv6Address nextHop,
                           uint32_t interface,
                           Ipv6Address prefixToUse = Ipv6Address::GetZero()) override;
    void SetIpv6(Ptr<Ipv6> ipv6) override;
    void PrintRoutingTable(Ptr<OutputStreamWrapper> stream,
                           Time::Unit unit = Time::S) const override;
    void PrepareOutgoingPacket(Ptr<Packet> packet,
                               Ipv6Header& header,
                               Ptr<Ipv6Route> route) override;

    /**
     * @brief Write the same state PrintRoutingTable() does, as one line of
     *        JSON, for a reader that is a program rather than a person.
     *
     * PrintRoutingTable()'s output is prose -- it drops the MRHOF columns
     * when the objective function is OF0, and the LQL one unless LQL is
     * enabled -- which makes it pleasant to read and unpleasant to parse
     * against. This emits every key on every call instead, using a JSON null
     * for the ones that do not apply to the current configuration, so that a
     * consumer can index into the result without first working out which
     * shape it got. One line per call, newline-terminated and flushed, so a
     * consumer reading the simulation's stdout can act on each node's
     * snapshot as it arrives.
     *
     * @param stream the output stream to write to
     */
    void PrintRoutingTableJson(Ptr<OutputStreamWrapper> stream) const;

    /**
     * @brief Make this node the root of the DODAG.
     *
     * The DODAGID is the node's first global address, so this must be called
     * after the global addresses have been assigned.
     */
    void SetAsRoot();

    /**
     * @brief Become the root of a new, self-originated local DODAG.
     *
     * For a node that wants to initiate its own DODAG at runtime rather than
     * (or in addition to) joining one via RplHelper::SetRoot() -- e.g. an
     * AODV-RPL (RFC 9854) OrigNode forming its RREQ-Instance, or a P2P-RPL
     * (RFC 6997) Origin forming a temporary DAG. DODAGID is this node's own
     * current global address (both RFCs root their local instance at the
     * initiating node itself), so this must be called after the node has
     * one. Carries no Prefix Information Option -- neither RFC uses one for
     * the local instance, since every participant already has whatever
     * address the base DODAG gave it -- so joiners of this DODAG never
     * attempt SLAAC on it.
     *
     * @param instanceId the local RPLInstanceID (high bit set, RFC 6550
     *        section 5.1) to form the new DODAG under; must not already
     *        identify a DODAG this node is part of
     * @param mop the Mode of Operation to advertise
     * @return the key of the new membership, an empty key (dodagId ::) if
     *         this node has no global address yet to root the DODAG at
     */
    DodagKey CreateLocalDodag(uint8_t instanceId, uint8_t mop = RPL_MOP_NON_STORING);

    /**
     * @brief Whether this node is the DODAG root.
     * @return true if this node is the root
     */
    bool IsRoot() const;

    /**
     * @brief Whether this node has joined a DODAG.
     * @return true if this node is part of a DODAG
     */
    bool IsJoined() const;

    /**
     * @brief Get the rank of this node within its DODAG.
     * @return the rank, RPL_INFINITE_RANK if this node has not joined one
     */
    uint16_t GetRank() const;

    /**
     * @brief Get this node's own path ETX under MRHOF (RFC 6719).
     * @return the path ETX, fixed-point (*128), 0 if not running MRHOF or not
     *         yet computed
     */
    uint16_t GetPathEtx() const;

    /**
     * @brief Set the function that turns an RSSI reading into a Link Quality
     *        Level (RFC 6551 section 4.6).
     *
     * The RFC deliberately leaves LQL "implementation specific": how a raw
     * signal reading should map to the 0 (undetermined) - 7 (worst
     * determined) scale depends on the radio and the deployment, so this is
     * a plain callback rather than a fixed table. Defaults to a coarse
     * built-in mapping; call this to replace it with one calibrated for a
     * particular radio or scenario.
     *
     * @param mapping RSSI in dBm -> LQL (0-7)
     */
    void SetRssiToLqlMapping(Callback<uint8_t, double> mapping);

    /**
     * @brief Map an RSSI reading to a Link Quality Level using whatever
     *        mapping is currently configured (SetRssiToLqlMapping(), or the
     *        built-in default).
     * @param rssiDbm the received signal strength, in dBm
     * @return the LQL, 0 (undetermined) to 7 (worst determined)
     */
    uint8_t RssiToLql(double rssiDbm) const;

    /**
     * @brief Get the DODAGID of the DODAG this node belongs to.
     * @return the DODAGID, :: if this node has not joined one
     */
    Ipv6Address GetDodagId() const;

    /**
     * @brief Get the link-local address of the preferred parent.
     * @return the preferred parent, :: if there is none
     */
    Ipv6Address GetPreferredParent() const;

    /**
     * @brief Whether this node is currently part of a specific DODAG.
     *
     * Unlike IsJoined(), which only ever answers for the base DODAG, this
     * checks any membership -- base or not -- by its own key.
     *
     * @param instanceId the RPLInstanceID of the DODAG
     * @param dodagId the DODAGID of the DODAG
     * @return true if this node is part of that DODAG
     */
    bool IsJoinedTo(uint8_t instanceId, Ipv6Address dodagId) const;

    /**
     * @brief Get the rank of this node within a specific DODAG.
     * @param instanceId the RPLInstanceID of the DODAG
     * @param dodagId the DODAGID of the DODAG
     * @return the rank, RPL_INFINITE_RANK if this node is not part of it
     */
    uint16_t GetRankIn(uint8_t instanceId, Ipv6Address dodagId) const;

    /**
     * @brief Get the rank of this node within whichever DODAG it holds under
     *        a given RPLInstanceID.
     *
     * Unlike GetRankIn(), which needs the full (instanceId, dodagId) key,
     * this is what a receive-side check driven only by a packet's own RPL
     * Option (RFC 6553's RPI, which carries no DODAGID -- @see RouteInput())
     * can resolve with. If more than one membership shares instanceId, an
     * arbitrary but deterministic one of them answers (@see
     * FindDodagByInstance()).
     *
     * @param instanceId the RPLInstanceID of the DODAG
     * @return the rank, RPL_INFINITE_RANK if this node holds no membership
     *         under that RPLInstanceID
     */
    uint16_t GetRankForInstance(uint8_t instanceId) const;

    /**
     * @brief Whether this node is still waiting on a DAO-ACK for a specific
     *        DODAG's most recently sent DAO.
     * @param instanceId the RPLInstanceID of the DODAG
     * @param dodagId the DODAGID of the DODAG
     * @return true if a DAO-ACK is outstanding, false if it has been
     *         acknowledged or this node is not part of that DODAG
     */
    bool IsDaoAckPendingIn(uint8_t instanceId, Ipv6Address dodagId) const;

    /**
     * @brief Get how many DODAGs this node currently belongs to at once.
     * @return the number of concurrent DODAG memberships
     */
    uint32_t GetDodagCount() const;

    /**
     * @brief Act on a rank inconsistency reported by the RPL Option (RFC 6553,
     *        RFC 6550 section 11.2), the way a multicast DIS does: reset the
     *        Trickle timer so an up to date DIO goes out sooner than it
     *        otherwise would, in case this node's own view of the DODAG is
     *        what is stale.
     *
     * Called by RplIpv6OptionRpl, not by anything in this class. Resolved by
     * RPLInstanceID alone (@see FindDodagByInstance()), the same limit
     * GetRankForInstance() documents: the RPI carries no DODAGID.
     *
     * @param instanceId the RPLInstanceID the inconsistent packet belongs to
     */
    void NotifyRankInconsistency(uint8_t instanceId);

    /**
     * @brief Get how many nodes the root has heard a DAO from.
     *
     * Only meaningful on the root, which is the only node that keeps the
     * topology in non-storing mode.
     *
     * @return the number of nodes in the topology this node knows about
     */
    uint32_t GetTopologySize() const;

    /**
     * @brief Get the path the root would put in a Routing Header for a
     *        destination.
     *
     * Per RFC 6554 section 3, the IPv6 header's own destination field becomes
     * the first hop and the Routing Header's address list holds every hop
     * after that, the final destination included as its own last entry: that
     * is what lets each router along the way find the address it was just
     * addressed under by reading the current destination field, without
     * knowing anything about the rest of the path. Since a DODAG's downward
     * routes only ever cross one radio hop at a time between consecutive
     * entries, every address returned here is link-local, resolved the same
     * way the address of a one-hop neighbour is elsewhere in this class.
     *
     * @param destination the address to reach, root excluded
     * @param [out] hops every hop after the root, in order, as link-local
     *              addresses, destination included as the last entry; a
     *              single entry means destination is a direct child of the
     *              root and needs no Routing Header at all
     * @return true if a path was found
     */
    bool ComputeSourceRoute(Ipv6Address destination, std::vector<Ipv6Address>& hops) const;

    /**
     * @brief ComputeSourceRoute(), for a DODAG other than the base one.
     *
     * The two-argument overload only ever answers for the base DODAG (the
     * root's own downward topology). A node that additionally roots a
     * CreateLocalDodag()-formed DODAG needs the same computation scoped to
     * that membership's own topology instead.
     *
     * @param instanceId the RPLInstanceID of the DODAG to compute over
     * @param dodagId the DODAGID of the DODAG to compute over
     * @param destination the address to reach, root excluded
     * @param [out] hops as the two-argument overload
     * @return true if a path was found; false if this node does not root
     *         that DODAG at all
     */
    bool ComputeSourceRoute(uint8_t instanceId,
                            Ipv6Address dodagId,
                            Ipv6Address destination,
                            std::vector<Ipv6Address>& hops) const;

    /**
     * @brief Assign a fixed stream number to the random variables used here.
     * @param stream first stream index to use
     * @return the number of stream indices assigned
     */
    int64_t AssignStreams(int64_t stream);

    /**
     * @brief Build a route handing a packet straight to a one-hop neighbour.
     *
     * Public so RplIpv6ExtensionSourceRouting::Process() can use it to relay
     * a source-routed packet to the next hop the Routing Header names,
     * without going through RouteOutput(): RouteOutput() deliberately never
     * treats a global address as on-link (a DODAG shares one prefix across
     * many hops, see RouteOutput()'s own comment), which is the right call
     * for traffic in general but wrong here, since the root already
     * confirmed this exact hop is one radio hop away when it built the
     * header. The neighbour is identified by its interface identifier alone
     * (the low 64 bits), so this works whether the caller names it by its
     * link-local or global address -- both resolve to the same interface.
     *
     * @param neighbour the address of the neighbour to send to
     * @param dst the destination to put in the route
     * @return the route, nullptr if the neighbour is on no known interface
     */
    Ptr<Ipv6Route> RouteToNeighbour(Ipv6Address neighbour, Ipv6Address dst) const;

    /**
     * @brief RouteToNeighbour(), scoped to a specific DODAG's own parent set.
     *
     * The two-argument overload only ever looks the neighbour up in the base
     * DODAG's own Parent set (InterfaceForNeighbour()'s default), which is
     * indistinguishable from "unknown" on a genuinely multi-interface node
     * if the neighbour was only ever heard advertising a different
     * RPLInstanceID. Threaded through by RplIpv6ExtensionSourceRouting::
     * Process() once it has read the source-routed packet's own RPI.
     *
     * @param instanceId the RPLInstanceID whose Parent set to search
     * @param neighbour the address of the neighbour to send to
     * @param dst the destination to put in the route
     * @return the route, nullptr if the neighbour is on no known interface
     */
    Ptr<Ipv6Route> RouteToNeighbour(uint8_t instanceId,
                                    Ipv6Address neighbour,
                                    Ipv6Address dst) const;

    /**
     * @brief Read the RPLInstanceID out of a packet's own RPL Option.
     *
     * A relaying/forwarding node needs to know which DODAG a packet
     * belongs to, and the only place that is recorded is the RPI (RFC
     * 6553) PrepareOutgoingPacket() attached when the packet was
     * originated. Public so both RouteInput() and
     * RplIpv6ExtensionSourceRouting::Process() (a different class,
     * resolving the instanceId to pass to the instance-aware
     * RouteToNeighbour() above) can use it. Safe to read directly here
     * rather than needing it stashed somewhere by RplIpv6OptionRpl::
     * Process(): that Hop-by-Hop option processing (Ipv6L3Protocol::
     * Receive() -> Ipv6ExtensionHopByHop::Process() -> Ipv6Extension::
     * ProcessOptions()) only ever rewrites the RPI in place at its
     * original offset, and Receive() never trims the bytes it reports
     * consumed off the packet before a forwarding decision is made -- so
     * the RPI is still exactly where PrepareOutgoingPacket() put it by the
     * time either caller runs.
     *
     * @param p the packet being routed
     * @param header the packet's own IPv6 header
     * @param [out] instanceId the RPLInstanceID found
     * @return true if a well-formed RPI was found and @p instanceId was set
     */
    bool ReadRpiInstanceId(Ptr<const Packet> p,
                           const Ipv6Header& header,
                           uint8_t& instanceId) const;

    /**
     * @brief Get the first global address of this node.
     * @return the global address, :: if the node has none (including while
     * SLAAC has not yet completed Duplicate Address Detection on it)
     */
    Ipv6Address GetGlobalAddress() const;

    // AODV-RPL (RFC 9854). Implemented in model/rpl-aodv.cc, not
    // model/rpl-routing-protocol.cc. Scoped to source-routed discovery
    // (H=0) for a single target, symmetric or asymmetric; @see
    // design-constraints.md for what that leaves out and why.

    /**
     * @brief Start an AODV-RPL route discovery towards a target.
     *
     * Forms a new RREQ-Instance -- a local RPL Instance rooted at this node,
     * RFC 9854 section 6.1 -- and starts Trickle-pacing RREQ-DIOs into it.
     * The discovery runs on its own from there; its result, once the RREP
     * comes back, is read with GetAodvRoute().
     *
     * This node's own Sequence Number is incremented first, per section 6.1,
     * so that routes left over from an earlier discovery are recognised as
     * stale.
     *
     * @param target the address to find a route to
     * @return the key of the RREQ-Instance, or a key whose dodagId is any()
     *         if the discovery could not be started (no global address to
     *         root it at, or no Local RPLInstanceID left to allocate)
     */
    DodagKey DiscoverRoute(Ipv6Address target);

    /**
     * @brief Get the Address Vector an RREQ-Instance has accumulated.
     *
     * The route the RREQ-DIO took to reach this node, as this node would
     * propagate it onward -- its own address included (RFC 9854 section
     * 6.2.5). Exposed for tests and for inspecting a discovery in progress.
     *
     * @param instanceId the RPLInstanceID of the RREQ-Instance
     * @param dodagId the DODAGID of the RREQ-Instance, i.e. the OrigNode
     * @param [out] addressVector the accumulated route, OrigNode side first
     * @return true if this node is part of that RREQ-Instance
     */
    bool GetAodvAddressVector(uint8_t instanceId,
                              Ipv6Address dodagId,
                              std::vector<Ipv6Address>& addressVector) const;

    /**
     * @brief Get the ART targets an RREQ-Instance still has left to relay.
     *
     * RFC 9854 section 6.2.2's own record of "the targets that have been
     * requested for a given RREQ-Instance", after every intersection with a
     * later RREQ-DIO's own list and every self-ART deletion this node has
     * made. Exposed for tests and for inspecting a discovery in progress,
     * the AODV-RPL counterpart of GetAodvAddressVector().
     *
     * @param instanceId the RPLInstanceID of the RREQ-Instance
     * @param dodagId the DODAGID of the RREQ-Instance, i.e. the OrigNode
     * @param [out] targets the targets still left to relay onward
     * @return true if this node is part of that RREQ-Instance
     */
    bool GetAodvTargets(uint8_t instanceId,
                        Ipv6Address dodagId,
                        std::vector<Ipv6Address>& targets) const;

    /**
     * @brief Get the source route an AODV-RPL discovery found to a target.
     *
     * The Address Vector the RREP brought back: every hop from the OrigNode
     * outward, the TargNode itself last, as global addresses. Only the
     * OrigNode of a discovery ever holds one -- an intermediate router on a
     * source-routed (H=0) route keeps no per-destination state at all, which
     * is the whole point of source routing.
     *
     * @param target the TargNode the route leads to
     * @param [out] hops the route, first hop first and the target last
     * @return true if a live route is held; expired ones are dropped and
     *         reported as absent
     */
    bool GetAodvRoute(Ipv6Address target, std::vector<Ipv6Address>& hops) const;

    /**
     * @brief How many live AODV-RPL routes this node holds.
     * @return the number of routes, expired ones excluded
     */
    uint32_t GetAodvRouteCount() const;

    /**
     * @brief Whether this node is the TargNode of an RREQ-Instance it holds.
     * @param instanceId the RPLInstanceID of the RREQ-Instance
     * @param dodagId the DODAGID of the RREQ-Instance
     * @return true if one of this node's addresses is the instance's target
     */
    bool IsAodvTarget(uint8_t instanceId, Ipv6Address dodagId) const;

    /**
     * @brief The 'S' bit this node would put on an RREQ-DIO it propagates
     *        for an RREQ-Instance it holds (RFC 9854 section 6.2.4).
     * @param instanceId the RPLInstanceID of the RREQ-Instance
     * @param dodagId the DODAGID of the RREQ-Instance
     * @return true if the route so far is symmetric, false if it is not or
     *         if this node holds no such membership
     */
    bool IsAodvSymmetric(uint8_t instanceId, Ipv6Address dodagId) const;

    /**
     * @brief Find the RREP-Instance this node holds for a given OrigNode.
     *
     * An asymmetric discovery's RREP-Instance is keyed by the TargNode's
     * address, not the OrigNode's, and its RPLInstanceID is the
     * RREQ-InstanceID plus a Delta chosen at the TargNode (RFC 9854 section
     * 6.3.3) -- so neither half of its key can be predicted from the
     * RREQ-Instance alone. This looks it up by the one thing a caller does
     * know.
     *
     * @param origNode the OrigNode the discovery is for
     * @param [out] key the RREP-Instance's key, untouched if none is found
     * @return true if this node holds such an RREP-Instance
     */
    bool FindAodvRrepInstance(Ipv6Address origNode, DodagKey& key) const;

    // P2P-RPL (RFC 6997). Implemented in model/rpl-p2p.cc, not
    // model/rpl-routing-protocol.cc, the same split rpl-aodv.cc keeps for
    // AODV-RPL. Scoped to source-routed discovery (H=0) for a single Target
    // and a single Source Route; @see design-constraints.md for what that
    // leaves out and why.

    /**
     * @brief Start a P2P-RPL route discovery towards a target.
     *
     * Forms a temporary DAG -- a local RPL Instance rooted at this node, RFC
     * 6997 section 6.1 -- and starts Trickle-pacing P2P mode DIOs into it.
     * The discovery runs on its own from there; its result, once a P2P-DRO
     * comes back, will be read with GetP2pRoute() (@see later increments;
     * not implemented yet).
     *
     * @param target the address to find a route to
     * @return the key of the temporary DAG, or a key whose dodagId is any()
     *         if the discovery could not be started (no global address to
     *         root it at, or no Local RPLInstanceID left to allocate)
     */
    DodagKey DiscoverP2pRoute(Ipv6Address target);

    /**
     * @brief Get the Address Vector a P2P-RPL temporary DAG has accumulated.
     *
     * The route the P2P mode DIO took to reach this node, as this node
     * would propagate it onward -- its own address included (RFC 6997
     * section 9.4). Exposed for tests and for inspecting a discovery in
     * progress, the P2P-RPL counterpart of GetAodvAddressVector().
     *
     * @param instanceId the RPLInstanceID of the temporary DAG
     * @param dodagId the DODAGID of the temporary DAG, i.e. the Origin
     * @param [out] addressVector the accumulated route, Origin side first
     * @return true if this node is part of that temporary DAG
     */
    bool GetP2pAddressVector(uint8_t instanceId,
                             Ipv6Address dodagId,
                             std::vector<Ipv6Address>& addressVector) const;

    /**
     * @brief Whether this node is the Target of a temporary DAG it holds.
     * @param instanceId the RPLInstanceID of the temporary DAG
     * @param dodagId the DODAGID of the temporary DAG
     * @return true if one of this node's addresses is the instance's Target
     */
    bool IsP2pTarget(uint8_t instanceId, Ipv6Address dodagId) const;

    /**
     * @brief Get the source route a P2P-RPL discovery found to a target.
     *
     * The P2P-RPL counterpart of GetAodvRoute(): every hop from the Origin
     * outward, the Target itself last, as global addresses. Only the
     * Origin of a discovery ever holds one.
     *
     * @param target the Target the route leads to
     * @param [out] hops the route, first hop first and the target last
     * @return true if a live route is held; expired ones are dropped and
     *         reported as absent
     */
    bool GetP2pRoute(Ipv6Address target, std::vector<Ipv6Address>& hops) const;

    /**
     * @brief How many live P2P-RPL routes this node holds.
     * @return the number of routes, expired ones excluded
     */
    uint32_t GetP2pRouteCount() const;

  protected:
    void DoInitialize() override;
    void DoDispose() override;

  private:
    /// A neighbour that advertises a DIO, and so is a candidate parent.
    struct Parent
    {
        Ipv6Address address;                //!< link-local address of the neighbour
        uint32_t interface{0};              //!< interface the neighbour was heard on
        uint16_t rank{RPL_INFINITE_RANK};   //!< rank the neighbour advertises
        uint8_t dtsn{0};    //!< the neighbour's DTSN, used by DAO in non-storing mode
        Time lastHeard;     //!< when the last DIO from this neighbour arrived
        uint8_t freshness{0}; //!< how many DIOs this neighbour has been heard with
        uint16_t etx{RPL_ETX_FIXED_POINT}; //!< EWMA link ETX to this neighbour (MRHOF, *128)
        uint16_t pathEtx{0}; //!< the neighbour's own advertised path ETX (MRHOF, *128)
        uint8_t lql{RPL_LQL_UNDETERMINED}; //!< Link Quality Level to this neighbour (RFC 6551 4.6)
    };

    /// What the root remembers about one node of the DODAG, learnt from DAOs.
    struct TopologyEntry
    {
        Ipv6Address parent;     //!< the parent the node reports sitting under
        uint8_t pathSequence{0}; //!< path sequence of the DAO this came from
        Time expire;            //!< when the entry goes stale
    };

    /**
     * @brief Everything this node knows about its membership in one DODAG.
     *
     * One of these exists per RPL Instance this node is currently part of,
     * keyed by DodagKey in m_dodags -- instanceId and dodagId below are
     * carried again here, redundant with that key, purely so the many
     * methods that take a DodagMembership& do not also have to be handed
     * the key just to log or compare it.
     *
     * Holds live Timer state (dioTrickle's own two timers, daoEvent,
     * daoRetryEvent). ns3::Timer owns a raw TimerImpl* it deletes in its own
     * destructor and declares no copy or move of its own, so the compiler-
     * generated copy constructor/assignment it falls back on would copy
     * that pointer, not the object it points to -- two Timers left sharing
     * one TimerImpl, and a double free the moment either is destroyed or
     * reassigned. RplTrickleTimer holds two such Timers directly and
     * inherits the same hazard. Deleting DodagMembership's own copy and
     * move members below is what turns a future accidental copy of one of
     * these into a compile error instead of that runtime corruption: every
     * entry in m_dodags is built in place (std::map::operator[] on first
     * access, or try_emplace()) and mutated only through a reference to
     * that one instance, never assigned as a whole struct.
     */
    struct DodagMembership
    {
        DodagMembership() = default;
        DodagMembership(const DodagMembership&) = delete;
        DodagMembership& operator=(const DodagMembership&) = delete;
        DodagMembership(DodagMembership&&) = delete;
        DodagMembership& operator=(DodagMembership&&) = delete;

        uint8_t instanceId{RPL_DEFAULT_INSTANCE}; //!< RPLInstanceID of the DODAG
        Ipv6Address dodagId;    //!< DODAGID, i.e. the global address of the root
        bool isRoot{false};     //!< true if this node is the root of this DODAG
        uint8_t version{0};     //!< DODAG version number
        uint16_t rank{RPL_INFINITE_RANK}; //!< rank of this node in the DODAG
        uint8_t mop{RPL_MOP_NON_STORING}; //!< Mode of Operation of the DODAG
        uint8_t dtsn{0};        //!< Destination Advertisement Trigger Sequence Number
        bool grounded{false};   //!< Grounded flag of the DODAG
        uint8_t preference{0};  //!< preference of the DODAG

        uint16_t ocp{RPL_OCP_OF0}; //!< objective code point in use
        uint16_t pathEtx{0}; //!< this node's own path ETX under MRHOF, fixed-point (*128)
        uint16_t minHopRankIncrease{RPL_MIN_HOPRANKINC}; //!< MinHopRankIncrease, also the rank of the root
        uint16_t maxRankIncrease{RPL_MAX_RANKINC};       //!< MaxRankIncrease

        /**
         * @brief L of RFC 6550 section 8.2.2.4 rule 3: the lowest rank this
         *        node has advertised within the current DODAG Version.
         *
         * Reset to RPL_INFINITE_RANK by JoinDodag() (no rank advertised in
         * this Version yet) and lowered by SelectPreferredParent() whenever
         * the new rank stays within the bound the rule imposes; a rank that
         * does not is never folded in, since INFINITE_RANK -- what the node
         * advertises instead -- "is an exception to this rule".
         */
        uint16_t lowestRankThisVersion{RPL_INFINITE_RANK};
        Time dioIntervalMin;              //!< Trickle Imin for DIOs
        uint8_t dioIntervalDoublings{RPL_DIO_INTERVAL_DOUBLINGS}; //!< Trickle doublings for DIOs
        uint8_t dioRedundancy{RPL_DIO_REDUNDANCY}; //!< Trickle redundancy constant for DIOs

        /// Whether a Prefix Information option (RFC 6550 section 6.7.10) is
        /// being carried: always true on the root once RootPrefix takes
        /// effect, copied from the DIO joined on by every other node
        /// (JoinDodag()) and re-advertised unchanged on this node's own
        /// DIOs (SendDio()), the same "root decides, everyone forwards"
        /// pattern as the DODAG Configuration option.
        bool hasPrefixInfo{false};
        Ipv6Address prefix;           //!< the prefix this DODAG's addresses are built on
        uint8_t prefixLength{0};      //!< prefix length of prefix, in bits
        bool prefixOnLink{false};     //!< 'L' flag
        bool prefixAutonomous{false}; //!< 'A' flag
        uint32_t prefixValidLifetime{0};     //!< Valid Lifetime, in seconds
        uint32_t prefixPreferredLifetime{0}; //!< Preferred Lifetime, in seconds

        RplTrickleTimer dioTrickle;            //!< paces the multicast DIOs
        std::map<Ipv6Address, Parent> parents; //!< candidate parents, by link-local address
        Ipv6Address preferredParent;           //!< link-local address of the preferred parent

        uint8_t daoSequence{0};   //!< sequence of the last DAO this node sent
        uint8_t pathSequence{0};  //!< path sequence of the route this node advertises
        uint8_t daoRetriesLeft{0}; //!< retries left for the DAO awaiting an acknowledgement
        bool daoAckPending{false}; //!< true while a DAO-ACK is being waited for
        Timer daoEvent{Timer::CANCEL_ON_DESTROY};      //!< schedules the periodic DAO
        Timer daoRetryEvent{Timer::CANCEL_ON_DESTROY}; //!< schedules the retry of an unacknowledged DAO

        /**
         * @brief Paces this node's own periodic Global Repair, root only.
         *
         * RFC 6550 section 3.2.2: "A DODAG root institutes a global repair
         * operation by incrementing the DODAGVersionNumber." Section 8.2.2.1
         * leaves the trigger to root policy, and section 18.2.5 lists
         * "periodic or event triggered" as the two configurable choices --
         * GlobalRepairFire() is the periodic one. Bound in
         * CreateDodagMembership() only for a DODAG this node roots that is
         * not a route-discovery instance (mop != RPL_MOP_P2P_ROUTE_DISCOVERY):
         * an AODV-RPL/P2P-RPL temporary DAG already self-terminates on its
         * own 'L' deadline and RFC 6997/9854 have no global repair concept of
         * their own. Left unarmed (never scheduled) when
         * m_globalRepairInterval is Time::Max(), the default -- see
         * design-constraints.md section 37 for the count-to-infinity bug
         * this exists to recover from.
         */
        Timer globalRepairEvent{Timer::CANCEL_ON_DESTROY};

        /// The root only: which parent each node reports sitting under.
        std::map<Ipv6Address, TopologyEntry> topology;

        /**
         * @brief AODV-RPL (RFC 9854) state, meaningful only while
         *        mop == RPL_MOP_P2P_ROUTE_DISCOVERY.
         *
         * Kept inside DodagMembership rather than in a map of its own
         * alongside m_dodags: an RREQ-Instance is created and destroyed
         * through exactly the same CreateDodagMembership()/JoinDodag() and
         * LeaveDodag() path as any other membership, and a parallel
         * container would add an erase discipline to keep in step with it
         * for no gain. This struct is already a union of concerns -- the six
         * DAO fields and topology above mean nothing to AODV-RPL either.
         */
        struct AodvRreqState
        {
            /// The 'S' bit this node would put on an RREQ-DIO it propagates,
            /// i.e. whether every hop back to the OrigNode has met the
            /// Objective Function so far (RFC 9854 section 6.2.4's "S bit of
            /// the RREQ-Instance").
            bool symmetric{true};
            /// The Sequence Number of whichever node originated this
            /// instance: the OrigNode's, off the RREQ that formed an
            /// RREQ-Instance, or the TargNode's own for an RREP-Instance
            /// (@see isRrepInstance), where it is what the RREP's ART
            /// option carries as its Dest SeqNo.
            uint8_t origSeqNo{0};
            uint8_t rankLimit{0}; //!< RankLimit, 0 meaning no limit
            uint8_t lifetimeField{0}; //!< the 'L' field this instance was opened with
            Ipv6Address target;   //!< the first ART target ever seen for this instance; logging/RREP-Instance use only, @see targets below

            /// Every ART target this router still has to relay onward for
            /// this RREQ-Instance (RFC 9854 section 6.1 lets an RREQ-DIO
            /// carry more than one ART option: "OrigNode can initiate the
            /// route discovery process for multiple targets
            /// simultaneously"). Seeded from the first RREQ-DIO
            /// HandleAodvRreq() processes for this instance, then on every
            /// later one intersected against that DIO's own ART list
            /// (section 6.2.2's "the intersection of all received lists"),
            /// then has this router's own matched address(es) deleted from
            /// it ("a TargNode MUST delete the Target option encapsulating
            /// its own address") -- unlike P2P-RPL's additionalTargets,
            /// which RFC 6997 never asks to be filtered this way, @see
            /// design-constraints.md. Re-emitted as SendDio()'s outgoing
            /// ART list; empty means every target reached so far has been
            /// accounted for, which is also this router's cue to stop
            /// transmitting an RREQ-DIO at all (section 6.2.2's "If the
            /// intersection is empty ... the router MUST NOT transmit any
            /// RREQ-DIO") unless it is still the OrigNode. Meaningless for
            /// an RREP-Instance (@see isRrepInstance), which always carries
            /// exactly one ART (section 4.3) built straight from origNode
            /// instead.
            std::vector<Ipv6Address> targets;
            /// The route the RREQ-DIO took to get here, OrigNode-side first,
            /// as this node would propagate it: its own address is already
            /// appended (RFC 9854 section 6.2.5).
            std::vector<Ipv6Address> addressVector;
            bool isOrigin{false}; //!< this node started the discovery
            bool isTarget{false}; //!< this node is the TargNode being looked for
            /// This membership is the RREP-Instance of an asymmetric (S=0)
            /// discovery rather than its RREQ-Instance: a second DODAG the
            /// TargNode roots at itself and floods, so that the OrigNode
            /// learns a downstream route whose links were each checked in
            /// the direction data will actually take (RFC 9854 section
            /// 6.3.2). Every field above keeps its meaning, read against
            /// this DODAG instead -- target is the TargNode either way,
            /// addressVector is the RREP's own accumulated path (section
            /// 6.4.4), and isOrigin/isTarget still say which end this node
            /// is. A symmetric discovery never sets this: its RREP is a
            /// unicast that builds no DODAG at all (section 6.3.1).
            bool isRrepInstance{false};
            /// The RREQ-InstanceID this RREP-Instance is paired with (RFC
            /// 9854 section 6.3.3). The RREP-Instance's own RPLInstanceID
            /// is this plus the RREP option's Delta; both ends need the
            /// pair to tell one discovery's RREP-Instance from another's.
            uint8_t pairedInstanceId{0};
            /// The OrigNode, i.e. the RREQ-Instance's DODAGID. Named in the
            /// RREP's ART option, which is how a router receiving an
            /// RREP-DIO recognises whether it is the OrigNode (section
            /// 6.4.2) -- for an RREP-Instance the DODAGID is the TargNode,
            /// so the OrigNode has to be carried separately.
            Ipv6Address origNode;
            /// RFC 9854 section 6.4: "a router that already belongs to the
            /// RREP-Instance SHOULD drop the RREP-DIO". A symmetric route
            /// never forms an RREP-Instance DODAG to check membership
            /// against (section 6.3.1), so this stands in for it -- set the
            /// first time this RREQ-Instance's RREP is handled here, either
            /// consumed (OrigNode) or relayed onward (intermediate router).
            bool rrepHandled{false};
            /// When the 'L' field's deadline takes this node out of the
            /// instance (RFC 9854 section 4.1). Never armed for the
            /// unlimited encoding.
            Timer expiry{Timer::CANCEL_ON_DESTROY};
        };

        AodvRreqState aodv; //!< AODV-RPL state; untouched unless mop is 4

        /**
         * @brief P2P-RPL (RFC 6997) state, meaningful only while this
         *        membership is a temporary DAG rather than an AODV-RPL one
         *        (mop == RPL_MOP_P2P_ROUTE_DISCOVERY and target is set).
         *
         * A separate struct from AodvRreqState rather than a shared one:
         * unlike AODV-RPL's RREQ- and RREP-Instance, which really are the
         * same shape playing two roles within one protocol, AODV-RPL and
         * P2P-RPL are two independent protocols that only happen to share
         * the "P2P Route Discovery" Mode of Operation value (RFC 9854's own
         * introduction: "there is no conflict with P2P-RPL, a previous
         * document using the same MOP"; @see design-constraints.md). A
         * DodagMembership formed for one never populates the other.
         */
        struct P2pState
        {
            bool isOrigin{false}; //!< this node started the discovery
            bool isTarget{false}; //!< this node is (one of) the Target(s) being looked for
            Ipv6Address target;   //!< the Target being looked for (RFC 6997 section 7's TargetAddr)
            /// Any additional Targets this temporary DAG's DIOs name via
            /// RPL Target options (RFC 6550 section 6.7.7, reused by RFC
            /// 6997 section 9.3), beyond the primary one above. Rebuilt
            /// from scratch on every DIO HandleP2pRdo() processes, the
            /// same "state from the last DIO" contract addressVector
            /// already has -- RFC 6997 has no rule removing an entry once
            /// it matches this router (unlike AODV-RPL's ART, @see
            /// design-constraints.md), so this is always this DIO's raw
            /// list, this node's own matched entry included whenever it
            /// was matched via a Target option rather than the primary
            /// TargetAddr above. @see HasOtherP2pTargets() for what
            /// "nothing else outstanding" actually checks against this.
            std::vector<Ipv6Address> additionalTargets;
            uint8_t maxRank{0};   //!< MaxRank, 0 meaning no limit
            uint8_t lifetimeField{0}; //!< the 'L' field this temporary DAG was opened with
            bool reply{true};         //!< 'R': whether the Target should send a P2P-DRO back
            bool hopByHop{false};     //!< 'H': always false; H=1 is out of scope
            /// RFC 6997 sections 8/9.6/9.7: set once a P2P-DRO with 'S' = 1
            /// has been seen for this temporary DAG. ShouldRefuseP2pRdo()
            /// refuses every further P2P mode DIO once this is true -- the
            /// "SHOULD NOT...process any more DIOs" half only.
            /// dioTrickle.Stop() (the "SHOULD NOT generate any more
            /// DIOs...cancel any pending transmissions" half) is
            /// deliberately not called: it was tried and reverted, because
            /// it silences this node immediately, and a downstream router
            /// whose preferredParent is this node is still an ordinary
            /// DodagMembership as far as the generic staleness sweep in
            /// SelectPreferredParent() is concerned -- going silent reads
            /// to it as "parent died", not "discovery is over", so it loses
            /// its last parent and poisons itself out well before its own
            /// 'L' deadline. This node's own Trickle is instead left to
            /// wind down naturally and the temporary DAG to retire on 'L'
            /// like any other, the same as every other P2P-RPL membership.
            /// P2P-DRO processing itself is unaffected either way, per the
            /// RFC's own "MUST continue to process the P2P-DRO messages"
            /// even after Stop.
            bool stopped{false};
            /// The route accumulated so far in the Forward direction
            /// (Origin-side first), as this node would propagate it: its own
            /// address is already appended (RFC 6997 section 9.4).
            std::vector<Ipv6Address> addressVector;
            /// When the 'L' field's deadline takes this node out of the
            /// temporary DAG (RFC 6997 section 7).
            Timer expiry{Timer::CANCEL_ON_DESTROY};

            /// Target only, RFC 6997 sections 9.5/10: state for the P2P-DRO
            /// this node is waiting on a P2P-DRO-ACK for. droSequence is the
            /// 'Seq' the outstanding (or most recently sent) P2P-DRO carried,
            /// what an arriving P2P-DRO-ACK is checked against.
            uint8_t droSequence{0};
            bool droAckPending{false};   //!< true while waiting on a P2P-DRO-ACK
            uint8_t droRetriesLeft{0};   //!< retries left for the P2P-DRO awaiting one
            /// Schedules the retransmission of an unacknowledged P2P-DRO
            /// (P2P_DRO_ACK_WAIT_TIME). Bound on first use, in SendP2pDro()
            /// itself, rather than in CreateDodagMembership() alongside
            /// daoRetryEvent's own binding: unlike a DAO, whether a P2P-DRO
            /// (and hence this Timer) is ever needed is not known until this
            /// node turns out to be a Target and actually sends one.
            Timer droRetryEvent{Timer::CANCEL_ON_DESTROY};
        };

        P2pState p2p; //!< P2P-RPL state; untouched unless this membership is a temporary DAG
    };

    /**
     * @brief Open the RPL raw socket on an interface and join ff02::1a.
     * @param interface the IPv6 interface index
     */
    void StartInterface(uint32_t interface);

    /**
     * @brief Close the RPL socket on an interface and leave ff02::1a.
     * @param interface the IPv6 interface index
     */
    void StopInterface(uint32_t interface);

    /**
     * @brief Receive and dispatch an ICMPv6 type 155 message.
     * @param socket the socket the message arrived on
     */
    void RecvRpl(Ptr<Socket> socket);

    /**
     * @brief Send a DIS, soliciting DIOs from neighbours.
     * @param dst destination, ff02::1a for the multicast case
     */
    void SendDis(Ipv6Address dst);

    /**
     * @brief Periodic multicast DIS while this node has not joined a DODAG.
     */
    void DisTimerExpire();

    /**
     * @brief Send a DIO describing the DODAG this node belongs to.
     * @param dodag the DODAG membership to describe
     * @param dst destination, ff02::1a for the multicast case
     * @param interface the interface to send on, 0 for all RPL interfaces
     */
    void SendDio(DodagMembership& dodag, Ipv6Address dst, uint32_t interface = 0);

    /**
     * @brief Send a multicast DIO because the Trickle timer said so.
     * @param key identifies which DODAG membership's Trickle timer fired
     */
    void DioTrickleFire(DodagKey key);

    /**
     * @brief Act on a received DIS, RFC 6550 section 8.3.
     *
     * A multicast DIS resets the Trickle timer of every node that hears it; a
     * unicast DIS is answered with a unicast DIO.
     *
     * @param from the sender
     * @param interface the interface the DIS arrived on
     * @param toMulticast true if the DIS was sent to ff02::1a
     */
    void HandleDis(Ipv6Address from, uint32_t interface, bool toMulticast);

    /**
     * @brief Act on a received DIO: join or update the DODAG.
     * @param dio the DIO
     * @param from the sender's link-local address
     * @param interface the interface the DIO arrived on
     * @param linkEtx the instantaneous link ETX to the sender, RPL_ETX_FIXED_POINT
     *                (neutral, i.e. 1.0) if it could not be estimated
     * @param lql the Link Quality Level to the sender, RPL_LQL_UNDETERMINED (0)
     *            if it could not be estimated
     * @param toMulticast whether it was addressed to all-RPL-nodes rather
     *                    than to this node. Only AODV-RPL looks at it, to
     *                    tell an RREP-DIO unicast back along a symmetric
     *                    route (RFC 9854 section 6.3.1) from one flooded
     *                    into an asymmetric route's RREP-Instance (section
     *                    6.3.2) -- the RREP option carries nothing that
     *                    distinguishes them.
     */
    void HandleDio(const RplDioHeader& dio,
                   Ipv6Address from,
                   uint32_t interface,
                   uint16_t linkEtx,
                   uint8_t lql,
                   bool toMulticast);

    /**
     * @brief Act on the AODV-RPL options of a DIO that carries them.
     *
     * Called from HandleDio() once the ordinary DODAG machinery has run, so
     * the membership this DIO belongs to already exists and this node's rank
     * and preferred parent in it are already settled. Implemented in
     * model/rpl-aodv.cc.
     *
     * @param dio the DIO, carrying an RREQ option and an ART option
     * @param from the link-local address of the neighbour that sent it
     * @param interface the interface it arrived on
     */
    void HandleAodvRreq(const RplDioHeader& dio, Ipv6Address from, uint32_t interface);

    /**
     * @brief Whether an AODV-RPL DIO should be refused before it is joined.
     *
     * The checks RFC 9854 section 6.2.1 puts ahead of joining the
     * RREQ-Instance, which therefore have to run before HandleDio()'s own
     * join: this node's address already in the Address Vector (the route
     * would loop), and a rank that would reach or exceed the RankLimit.
     * Implemented in model/rpl-aodv.cc.
     *
     * @param dio the DIO to judge
     * @param from the link-local address of the neighbour that sent it
     * @return true if the DIO must be dropped without joining
     */
    bool ShouldRefuseAodvRreq(const RplDioHeader& dio, Ipv6Address from) const;

    /**
     * @brief The refusals an RREQ-Instance and an RREP-Instance share.
     *
     * RFC 9854 section 4.1's REJOIN_REENABLE bar, plus a DIO for an instance
     * this node itself rooted heard back from a neighbour. Both matter to
     * either kind of instance, and both cover the same window: after the
     * membership has been erased at its 'L' deadline, when HandleDio()'s own
     * isRoot check no longer has anything to look at.
     *
     * @param key the instance's key
     * @param from the link-local address of the neighbour that sent the DIO
     * @return true if the DIO must be dropped without joining
     */
    bool ShouldRefuseAodvInstance(DodagKey key, Ipv6Address from) const;

    /**
     * @brief Whether an RREP-Instance DIO should be refused before it is
     *        joined.
     *
     * The RREP-Instance counterpart of ShouldRefuseAodvRreq(): the checks
     * RFC 9854 section 6.4.1 puts ahead of joining the RREP-Instance DODAG,
     * which therefore have to run before HandleDio()'s own join exactly as
     * the RREQ side's do -- this node's address already in the Address
     * Vector (the route would loop), and a rank that would reach or exceed
     * the RankLimit, relaxed by one step for the OrigNode the way the RREQ
     * side relaxes it for the TargNode.
     *
     * @param dio the RREP-DIO to judge
     * @param from the link-local address of the neighbour that sent it
     * @return true if the DIO must be dropped without joining
     */
    bool ShouldRefuseAodvRrep(const RplDioHeader& dio, Ipv6Address from) const;

    /**
     * @brief Whether a P2P mode DIO should be refused before it is joined.
     *
     * RFC 6997's own set of pre-join checks, gathered in one place for the
     * same reason ShouldRefuseAodvRrep() gathers AODV-RPL's: this node's
     * address already in the Address Vector (section 9.4, a loop), a rank
     * that would reach or exceed the MaxRank (section 7, relaxed by one
     * step for the Target the way AODV-RPL's RankLimit relaxes for the
     * TargNode/OrigNode), a nonzero MaxRankIncrease (section 6.1: "A
     * received P2P mode DIO MUST be discarded if the MaxRankIncrease
     * parameter...is not zero"), and this node's own address as the
     * DODAGID -- P2P-RPL has no REJOIN_REENABLE of its own (RFC 6997 does
     * not mention rejoining at all), but the underlying hazard
     * ShouldRefuseAodvInstance() guards against is structural, not a policy
     * choice from that RFC: after this node's own temporary DAG membership
     * has been erased at its 'L' deadline, nothing else stops a straggling
     * DIO pulling it back in as an ordinary member of a DODAG rooted at its
     * own address.
     *
     * @param dio the P2P mode DIO to judge
     * @param from the link-local address of the neighbour that sent it
     * @return true if the DIO must be dropped without joining
     */
    bool ShouldRefuseP2pRdo(const RplDioHeader& dio, Ipv6Address from) const;

    /**
     * @brief Whether this node is (one of) the Target(s) a P2P mode DIO
     *        names.
     *
     * RFC 6997 section 9.3: "The router MUST check the Target addresses
     * listed in the P2P-RDO and any RPL Target options included in the
     * received DIO. If one of its IPv6 addresses is listed as a Target
     * address...the router considers itself a Target." Checked against
     * the P2P-RDO's own primary TargetAddr and every RPL Target option
     * (@see RplDioHeader::GetTargets()) -- a small helper rather than
     * inlining the loop twice, since ShouldRefuseP2pRdo()'s MaxRank
     * relaxation and HandleP2pRdo()'s own isTarget assignment both need
     * exactly this same check.
     *
     * @param dio the P2P mode DIO to check
     * @return true if one of this node's own addresses is named
     */
    bool MatchesP2pTarget(const RplDioHeader& dio) const;

    /**
     * @brief Whether a temporary DAG's own additionalTargets record still
     *        names a Target other than this node.
     *
     * RFC 6997 section 9.5's Stop-eligibility condition ("this router is
     * the only Target specified...i.e., the corresponding DIO specified a
     * unicast address of the router as the TargetAddr inside the P2P-RDO
     * with no additional Targets specified via RPL Target options") and
     * its "MUST NOT forward a P2P mode DIO any further" condition are both
     * worded around the primary-TargetAddr case, and read literally would
     * never be satisfiable for a Target matched only through an RPL Target
     * option: additionalTargets carries every RPL Target option this DIO
     * named, including this node's own matched entry (never filtered out,
     * @see DodagMembership::P2pState::additionalTargets), so a plain
     * emptiness check can never be true once this node has matched itself
     * that way. This is the more permissive reading design-constraints.md
     * settles on: "is there a Target other than me still outstanding",
     * which reduces to the literal reading whenever this node's own
     * address is not among the entries at all (the original, common case
     * of a single Target named via the primary TargetAddr, where
     * additionalTargets is simply empty either way).
     *
     * @param dodag the temporary DAG membership to check
     * @return true if additionalTargets names a Target other than this node
     */
    bool HasOtherP2pTargets(const DodagMembership& dodag) const;

    /**
     * @brief Act on an RREP-DIO travelling back towards the OrigNode.
     *
     * Never joined as a DODAG: on a symmetric route "the DODAG in
     * RREP-Instance does not need to be built" (RFC 9854 section 6.3.1), so
     * an RREP-DIO is a unicast carrying a finished route rather than an
     * advertisement to join. HandleDio() therefore hands it here and returns
     * without running any of its ordinary machinery. Implemented in
     * model/rpl-aodv.cc.
     *
     * @param dio the DIO, carrying an RREP option and an ART option
     * @param from the link-local address of the neighbour that sent it
     * @param interface the interface it arrived on
     */
    void HandleAodvRrep(const RplDioHeader& dio, Ipv6Address from, uint32_t interface);

    /**
     * @brief Send the RREP that answers an RREQ this node is the target of.
     *
     * Branches on the RREQ-Instance's own 'S' bit: a symmetric route is
     * answered by unicasting straight back along the Address Vector (RFC
     * 9854 section 6.3.1), an asymmetric one by handing off to
     * StartAodvRrepInstance().
     *
     * @param dodag the RREQ-Instance being answered
     * @param key its key
     */
    void SendAodvRrep(DodagMembership& dodag, DodagKey key);

    /**
     * @brief Root and start flooding an RREP-Instance for an asymmetric
     *        (S=0) discovery this node is the target of.
     *
     * RFC 9854 section 6.3.2: the reverse of the path the RREQ took is by
     * definition not usable when 'S' was cleared, so instead of unicasting
     * an answer the TargNode builds a second DODAG rooted at itself and
     * floods it. Routers join it only over links that satisfy the Objective
     * Function in the direction of the TargNode -- which is the direction
     * the OrigNode's data will travel.
     *
     * Nothing is transmitted before this returns: the membership's own
     * Trickle timer multicasts the RREP-DIO, built by SendDio() from the
     * state recorded here, exactly as an RREQ-Instance's is.
     *
     * @param rreqDodag the RREQ-Instance being answered
     * @param rreqKey its key, whose dodagId is the OrigNode
     */
    void StartAodvRrepInstance(const DodagMembership& rreqDodag, DodagKey rreqKey);

    /**
     * @brief Take an RREP-DIO of an asymmetric discovery's RREP-Instance,
     *        once the DODAG machinery has already joined it.
     *
     * The RREP-Instance counterpart of HandleAodvRreq(), called from the
     * same place in HandleDio() and for the same reason: RFC 9854 section
     * 6.4.4 has the router append the address of the interface it heard the
     * RREP-DIO on, which is only meaningful once this membership's preferred
     * parent has been settled.
     *
     * @param dio the RREP-DIO just processed
     * @param from the neighbour it came from, a link-local address
     * @param interface the interface it arrived on
     */
    void HandleAodvRrepInstance(const RplDioHeader& dio, Ipv6Address from, uint32_t interface);

    /**
     * @brief Take a P2P mode DIO, once the DODAG machinery has already
     *        joined it.
     *
     * The P2P-RPL counterpart of HandleAodvRreq(), called from the same
     * position in HandleDio() and for the same reason: RFC 6997 section 9.4
     * has the router append the address of the interface it heard the DIO
     * on, which is only meaningful once this membership's preferred parent
     * has been settled. Recognising this node as the Target (section 9.3)
     * happens here too, triggering SendP2pDro() the first time.
     *
     * @param dio the P2P mode DIO just processed
     * @param from the neighbour it came from, a link-local address
     * @param interface the interface it arrived on
     */
    void HandleP2pRdo(const RplDioHeader& dio, Ipv6Address from, uint32_t interface);

    /**
     * @brief Answer a P2P mode DIO with a P2P-DRO, as its Target.
     *
     * RFC 6997 section 9.5: sent once this router has recognised itself as
     * the Target and the P2P-RDO's Reply flag asked for one. The Address
     * Vector accumulated so far (dodag.p2p.addressVector) already ends with
     * this node's own address, appended by HandleP2pRdo() the same way an
     * ordinary Intermediate Router's is; the outgoing P2P-RDO drops that
     * trailing entry, since section 8.2 has the vector's last element be
     * "the router next to the Target" rather than the Target itself (a
     * narrower exclusion than the RREP option's own Address Vector, which
     * AODV-RPL's SendAodvRrep() sends unchanged, TargNode's own trailing
     * entry included -- @see design-constraints.md).
     *
     * Transmitted via link-local multicast on every interface (section 8),
     * unlike AODV-RPL's symmetric RREP, which unicasts to a specific next
     * hop.
     *
     * @param dodag the temporary DAG membership, at this Target
     * @param key its key
     */
    void SendP2pDro(DodagMembership& dodag, DodagKey key);

    /**
     * @brief Act on a received P2P-DRO: relay it onward, or store the route
     *        it carries if this node is the Origin it names.
     *
     * RFC 6997 sections 9.6 (Intermediate Router) and 9.7 (Origin). Unlike a
     * DIO, a P2P-DRO is never joined as a DODAG -- it is looked up by
     * (RPLInstanceID, DODAGID) against a temporary DAG membership this node
     * already holds, and discarded if there is none (the node is not part
     * of the discovery this P2P-DRO belongs to).
     *
     * For an Intermediate Router: only the router named at the Address
     * Vector's current NH position acts (every other one that also happens
     * to hear the multicast has nothing to do); it decrements NH and
     * re-multicasts, unchanged otherwise. H=1's Hop-by-hop routing state is
     * out of scope (@see design-constraints.md).
     *
     * For the Origin: the Address Vector is a fixed snapshot the Target
     * built once (SendP2pDro()), already Origin-outward -- unlike AODV-RPL's
     * asymmetric RREP-Instance, whose own vector accumulates hop by hop
     * during the flood back and so needs reversing at the OrigNode, this
     * needs none.
     *
     * @param dro the P2P-DRO just received
     * @param from the neighbour it came from, a link-local address
     * @param interface the interface it arrived on
     */
    void HandleP2pDro(const RplP2pDroHeader& dro, Ipv6Address from, uint32_t interface);

    /**
     * @brief Re-send an unacknowledged P2P-DRO, or give up.
     *
     * RFC 6997 section 9.5: a Target that set the P2P-DRO's 'A' flag
     * retransmits the same P2P-DRO (same 'Seq') if
     * P2P_DRO_ACK_WAIT_TIME elapses with no P2P-DRO-ACK, up to
     * MAX_P2P_DRO_RETRANSMISSIONS times. Modelled on DaoRetry().
     *
     * @param key identifies which DODAG membership's retry timer fired
     */
    void P2pDroRetry(DodagKey key);

    /**
     * @brief Act on a received P2P-DRO-ACK: cancel the retry it acknowledges.
     *
     * RFC 6997 section 10. Only meaningful at the Target that requested it;
     * silently dropped if this node is not currently waiting on one, or if
     * the instanceId/dodagId/sequence do not match what is outstanding (a
     * stale or misdirected ACK).
     *
     * @param ack the P2P-DRO-ACK just received
     * @param from the neighbour it arrived from (unicast, but not
     *        necessarily one radio hop -- forwarded like any other unicast)
     */
    void HandleP2pDroAck(const RplP2pDroAckHeader& ack, Ipv6Address from);

    /**
     * @brief Unicast an RREP-DIO one hop towards the OrigNode.
     *
     * The next hop is named by a global address out of the Address Vector,
     * but the message goes to its link-local: it crosses exactly one radio
     * hop, and RouteOutput() deliberately never treats a global address as
     * on-link (@see its own comment on why that is right in general).
     *
     * @param dodag the RREQ-Instance the route belongs to, for its parent set
     * @param dio the RREP-DIO to send
     * @param nextHop the global address of the neighbour to send it to
     */
    void SendAodvRrepTo(const DodagMembership& dodag,
                        const RplDioHeader& dio,
                        Ipv6Address nextHop);

    /**
     * @brief Find the AODV-RPL source route to a destination, if one is held.
     * @param dst the destination
     * @param [out] hops the route as link-local addresses, the form
     *              ComputeSourceRoute() also returns
     * @param [out] instanceId the RREQ-InstanceID the route was found under
     * @return true if a live route was found
     */
    bool FindAodvRoute(Ipv6Address dst,
                       std::vector<Ipv6Address>& hops,
                       uint8_t& instanceId) const;

    /**
     * @brief Find the P2P-RPL source route to a destination, if one is held.
     * @param dst the destination
     * @param [out] hops the route as link-local addresses, the form
     *              ComputeSourceRoute() also returns
     * @param [out] instanceId the temporary DAG's RPLInstanceID the route
     *              was found under
     * @return true if a live route was found
     */
    bool FindP2pRoute(Ipv6Address dst,
                      std::vector<Ipv6Address>& hops,
                      uint8_t& instanceId) const;

    /**
     * @brief Arm the 'L' field's deadline for an RREQ-Instance.
     *
     * A no-op for RFC 9854 section 4.1's "no time limit imposed" encoding.
     * Re-armed rather than left alone when a later copy of the same RREQ
     * arrives, so the deadline is measured from when this node last had
     * reason to believe the discovery was still live.
     *
     * @param dodag the membership to arm
     * @param key its key, which the expiry callback needs to find it again
     */
    void ArmAodvExpiry(DodagMembership& dodag, DodagKey key);

    /**
     * @brief Leave an RREQ-Instance whose 'L' field has run out.
     * @param key the RREQ-Instance to leave
     */
    void AodvInstanceExpired(DodagKey key);

    /**
     * @brief Arm the 'L' field's deadline for a P2P-RPL temporary DAG.
     *
     * Unlike ArmAodvExpiry(), never a no-op: RFC 6997 section 7's 'L' field
     * has no "unlimited" encoding, every value names a real duration.
     *
     * @param dodag the membership to arm
     * @param key its key, which the expiry callback needs to find it again
     */
    void ArmP2pExpiry(DodagMembership& dodag, DodagKey key);

    /**
     * @brief Leave a P2P-RPL temporary DAG whose 'L' field has run out.
     * @param key the temporary DAG to leave
     */
    void P2pInstanceExpired(DodagKey key);

    /**
     * @brief Whether an address is one of this node's own.
     * @param address the address to look for
     * @return true if some interface of this node holds it
     */
    bool IsOwnAddress(Ipv6Address address) const;

    /**
     * @brief Join the DODAG advertised by a DIO, adopting its configuration.
     *
     * If the DIO carries a Prefix Information option, this is also what
     * triggers SLAAC (RFC 4862) on it: Ipv6L3Protocol::
     * AddAutoconfiguredAddress() builds the address and starts Duplicate
     * Address Detection, asynchronously -- HandleDadSuccess() is what learns
     * it finished.
     *
     * @param dio the DIO
     * @param interface the interface the DIO arrived on, i.e. the one to
     *                  SLAAC an address onto
     */
    void JoinDodag(const RplDioHeader& dio, uint32_t interface);

    /**
     * @brief Leave a DODAG and erase its membership.
     *
     * @param key identifies the membership to leave; must currently exist
     *        in m_dodags
     * @param poison whether to advertise INFINITE_RANK on the way out (RFC
     *        6550 section 8.2.2.5). True when the node is detaching because
     *        it can no longer hold a parent, which is what tells its
     *        sub-DODAG to stop treating it as a way to the root; false when
     *        it is only stepping between DODAG Versions (section 8.2.2.4
     *        rule 5), where it rejoins in the same event and its next DIO
     *        already carries the new version.
     */
    void LeaveDodag(DodagKey key, bool poison);

    /**
     * @brief Compute the rank this node would have through a given parent.
     *
     * Under OF0 (RFC 6552, rank factor 1, stretch 0, step of rank 1): with no
     * link metric available every neighbour is one MinHopRankIncrease away.
     * Under MRHOF (RFC 6719 section 3.3): the rank is the path cost through
     * the parent, unless that is less than the parent's own rank plus
     * MinHopRankIncrease, in which case the latter is used instead, so a
     * rank never implies a shorter path than the hop count actually taken.
     *
     * @param dodag the DODAG membership the parent belongs to
     * @param parent the candidate parent
     * @param pathCost if not null, filled with the MRHOF path cost computed
     *                 along the way (PathCostViaParent(parent)), so a caller
     *                 that needs both values does not have to compute the
     *                 path cost a second time. Left untouched under OF0.
     * @return the resulting rank, RPL_INFINITE_RANK if the parent is unusable
     */
    uint16_t RankViaParent(const DodagMembership& dodag,
                           const Parent& parent,
                           uint32_t* pathCost = nullptr) const;

    /**
     * @brief Compute the path cost this node would advertise through a given
     *        parent, MRHOF (RFC 6719) only.
     *
     * RFC 6551 section 4.3 defines ETX as an additive metric: the path cost
     * is the parent's own advertised path ETX plus the ETX of the link to
     * it.
     *
     * @param parent the candidate parent
     * @return the path cost, fixed-point (*128)
     */
    uint32_t PathCostViaParent(const Parent& parent) const;

    /**
     * @brief Fold a new link ETX sample into a parent's EWMA estimate.
     *
     * The first ever sample seeds the estimate outright rather than being
     * blended in from the neutral default, so a newly heard neighbour is not
     * biased towards looking like a perfect link for several DIOs. Every
     * later sample uses an EWMA with alpha = 1/8, the same smoothing TCP's
     * RTO estimator uses for the same reason: react to real change, not to
     * one noisy reading.
     *
     * @param parent the parent to update, its freshness already accounts for
     *               this sample
     * @param sample the instantaneous link ETX just observed, fixed-point (*128)
     */
    void UpdateLinkEtx(Parent& parent, uint16_t sample) const;

    /**
     * @brief Estimate the instantaneous link ETX to whoever sent a packet.
     *
     * Wi-SUN FAN 1.1 derives its mandatory ETX metric from the bidirectional
     * link quality Neighbor Discovery measures on the radio. This module
     * approximates that with lr-wpan's own per-frame LQI
     * (ns3::lrwpan::LrWpanLqiTag), read by its registered TypeId name
     * through the generic PacketTagIterator rather than a direct #include of
     * lr-wpan: librpl keeps building and running over any link layer that
     * way, matching how sixlowpan itself does not hard-depend on the link
     * layer it is almost always paired with, and it simply falls back to a
     * neutral ETX if the link layer does not attach the tag.
     *
     * @param packet the received packet, tags intact
     * @return the instantaneous link ETX, fixed-point (*128), RPL_ETX_FIXED_POINT
     *         (neutral, i.e. 1.0) if no LQI tag is present
     */
    uint16_t LinkEtxFromPacket(Ptr<const Packet> packet) const;

    /**
     * @brief Estimate the Link Quality Level to whoever sent a packet.
     *
     * Reads lr-wpan's per-frame RSSI (ns3::lrwpan::LrWpanRssiTag), located
     * the same decoupled way LinkEtxFromPacket() reads the LQI tag, and runs
     * it through RssiToLql().
     *
     * @param packet the received packet, tags intact
     * @return the LQL, RPL_LQL_UNDETERMINED (0) if no RSSI tag is present
     */
    uint8_t LinkLqlFromPacket(Ptr<const Packet> packet) const;

    /**
     * @brief Re-run parent selection and update the rank.
     *
     * Candidates that have not been heard from for two maximum DIO intervals
     * are dropped, since that is two missed DIOs in a row. Under MRHOF (RFC
     * 6719 section 3.3), the current preferred parent is kept over a
     * candidate of lower path cost unless the difference exceeds
     * RPL_MRHOF_PARENT_SWITCH_THRESHOLD, so the node does not flap between
     * parents of near-identical quality.
     *
     * @param dodag the DODAG membership to reselect a preferred parent within
     * @return true if the preferred parent or the rank changed
     */
    bool SelectPreferredParent(DodagMembership& dodag);

    /**
     * @brief Advertise this node to the root, RFC 6550 section 6.4.
     *
     * The DAO travels to the DODAGID like any other upward traffic, so every
     * node on the way just forwards it and only the root ever reads it.
     *
     * @param dodag the DODAG membership to advertise
     */
    void SendDao(DodagMembership& dodag);

    /**
     * @brief Withdraw this node's own advertisement, RFC 6550 section 6.4.3.
     *
     * A No-Path DAO -- a DAO whose Transit Information carries a Path
     * Lifetime of 0 -- tells the root this node's target is no longer
     * reachable via @p viaParent. Sent as a one-shot, best-effort message:
     * unlike SendDao(), no DAO-ACK is requested and there is no retry, since
     * by the time this is worth sending the path it would retry over is
     * usually the one just found unusable in the first place, and the
     * periodic refresh (or PurgeTopology() on the root, once the
     * advertised PathLifetime elapses) is what a lost No-Path ultimately
     * falls back on.
     *
     * @param dodag the DODAG membership to withdraw from
     * @param viaParent the link-local address of the parent this node was
     *        last advertised as reachable through, i.e. the caller's own
     *        preferredParent read before clearing it
     */
    void SendNoPathDao(DodagMembership& dodag, Ipv6Address viaParent);

    /**
     * @brief Send a DAO now and schedule the next refresh.
     * @param key identifies which DODAG membership's DAO timer fired
     */
    void DaoTimerExpire(DodagKey key);

    /**
     * @brief Re-send the DAO that was not acknowledged, or give up.
     * @param key identifies which DODAG membership's retry timer fired
     */
    void DaoRetry(DodagKey key);

    /**
     * @brief Institute a Global Repair (RFC 6550 section 3.2.2): move this
     *        node's own DODAG to a new Version and reschedule the next one.
     *
     * Root only, and only for a DODAG this node roots -- globalRepairEvent
     * is never bound otherwise. @see DodagMembership::globalRepairEvent for
     * why this is periodic rather than event-triggered, and
     * design-constraints.md section 37 for the bug this recovers from.
     *
     * @param key identifies which DODAG membership's repair timer fired
     */
    void GlobalRepairFire(DodagKey key);

    /**
     * @brief Act on a received DAO. Only the root ever gets one.
     * @param dao the DAO
     * @param from the address of the node that advertised itself
     */
    void HandleDao(const RplDaoHeader& dao, Ipv6Address from);

    /**
     * @brief Act on a received DAO-ACK, i.e. stop retrying.
     * @param daoAck the DAO-ACK
     * @param from the sender
     */
    void HandleDaoAck(const RplDaoAckHeader& daoAck, Ipv6Address from);

    /**
     * @brief Drop the topology entries whose lifetime has run out.
     * @param dodag the DODAG membership to purge (the root's own only, since
     *              only the root holds a topology in non-storing mode)
     */
    void PurgeTopology(DodagMembership& dodag);

    /**
     * @brief Find a membership by its RPLInstanceID alone.
     *
     * The only lookup a packet's own RPL Option (RFC 6553's RPI, which
     * carries no DODAGID -- @see ReadRpiInstanceId()) lets a relaying or
     * rank-checking node do. m_dodags sorts by (instanceId, dodagId)
     * (DodagKey::operator<), so the first entry with a matching instanceId
     * is found in O(log n) via lower_bound() rather than a linear scan.
     *
     * If more than one membership shares instanceId -- this module's own
     * DodagKey design allows joining two DODAGs under the same
     * RPLInstanceID at once, looser than RFC 6550 section 3.4's one-DODAG-
     * per-Instance model -- the answer is deterministic (the lowest
     * DODAGID) but not necessarily the "right" one for a given packet: the
     * wire format has nothing left to disambiguate with. Documented as a
     * known limitation rather than solved, since the motivating use case
     * (CreateLocalDodag()'s local instances) mints a distinct instanceId
     * per call and never hits it.
     *
     * @param instanceId the RPLInstanceID to search for
     * @return the membership, nullptr if this node holds none under it
     */
    DodagMembership* FindDodagByInstance(uint8_t instanceId);
    /**
     * @brief FindDodagByInstance(), const overload.
     * @param instanceId the RPLInstanceID to search for
     * @return the membership, nullptr if this node holds none under it
     */
    const DodagMembership* FindDodagByInstance(uint8_t instanceId) const;

    /**
     * @brief Find whichever DODAG this node roots that can reach a
     *        destination, base included.
     *
     * The generalisation of "the root computes a source route"
     * (RouteOutput()'s and PrepareOutgoingPacket()'s own root branches used
     * to hardcode GetBaseDodag()) to any DODAG this node happens to root,
     * including one CreateLocalDodag() formed at runtime. The base
     * membership is tried first (keeps today's single-DODAG behaviour and
     * its performance exactly unchanged), then every other membership with
     * isRoot true in map order; the first one whose topology actually
     * reaches @p destination wins. Calls PurgeTopology() on each membership
     * it tries, the same lazy-cleanup-on-the-hot-path timing RouteOutput()
     * already used for the base case.
     *
     * @param destination the address to reach
     * @param [out] hops as ComputeSourceRoute()'s own out-parameter
     * @return the membership the path was found through, nullptr if none of
     *         this node's root memberships can reach @p destination
     */
    DodagMembership* FindRootDodagFor(Ipv6Address destination, std::vector<Ipv6Address>& hops);

    /**
     * @brief The shared implementation both public ComputeSourceRoute()
     *        overloads delegate to, scoped to one already-resolved
     *        membership.
     * @param dodag the DODAG membership to compute the path over
     * @param destination the address to reach, root excluded
     * @param [out] hops as the public overloads' own out-parameter
     * @return true if a path was found
     */
    bool ComputeSourceRoute(const DodagMembership& dodag,
                            Ipv6Address destination,
                            std::vector<Ipv6Address>& hops) const;

    /**
     * @brief The shared implementation both public RouteToNeighbour()
     *        overloads delegate to.
     * @param dodag the DODAG membership to search the Parent set of,
     *              nullptr if this node holds no such membership
     * @param neighbour the address of the neighbour to send to
     * @param dst the destination to put in the route
     * @return the route, nullptr if the neighbour is on no known interface
     */
    Ptr<Ipv6Route> RouteToNeighbour(const DodagMembership* dodag,
                                    Ipv6Address neighbour,
                                    Ipv6Address dst) const;

    /**
     * @brief Build the global address a neighbour has on the DODAG prefix.
     *
     * A DAO has to name the parent by an address the root can use, and RPL
     * only ever learns the link-local address of a neighbour. The global
     * address is rebuilt the way Contiki-NG does it, by putting the interface
     * identifier of the link-local address under the prefix of the DODAGID.
     * This assumes the DODAG runs on a single prefix and that a node keeps one
     * interface identifier across its addresses, which is what an autoconfigured
     * LLN looks like.
     *
     * @param dodag the DODAG membership the neighbour belongs to, for its DODAGID
     * @param linkLocal the link-local address of the neighbour
     * @return the global address of the neighbour, :: if it cannot be built
     */
    Ipv6Address GlobalAddressOf(const DodagMembership& dodag, Ipv6Address linkLocal) const;

    /**
     * @brief Get this node's own global address on a specific DODAG's prefix.
     *
     * GetGlobalAddress() answers "some global address of this node", picked
     * by address-list order, which is fine while at most one exists. Once a
     * node has joined more than one DODAG advertising different prefixes, it
     * SLAACs one GUA per prefix, and a DAO for a given DODAG has to name the
     * GUA that DODAG's own root actually recognises -- not just whichever
     * one happens to enumerate first. Rebuilding the address the way
     * GlobalAddressOf() does for a neighbour is deliberately not reused
     * here: that would keep returning an address even after Duplicate
     * Address Detection rejected it and it was withdrawn, since it is a
     * pure bit rebuild with no knowledge of what is actually still
     * assigned. This scans the real, currently assigned addresses instead,
     * the same as GetGlobalAddress() itself, just filtered to the one
     * DODAG's prefix.
     *
     * @param dodag the DODAG membership to find this node's address on
     * @return the global address on that DODAG's prefix, :: if none is
     *         assigned (including while still TENTATIVE); falls back to
     *         GetGlobalAddress() if the DODAG carries no prefix at all
     */
    Ipv6Address GetGlobalAddressIn(const DodagMembership& dodag) const;

    /**
     * @brief Build the link-local address that shares an interface identifier
     *        with a global address.
     *
     * The inverse of GlobalAddressOf(): used to turn the global addresses
     * ComputeSourceRoute() finds in the topology into the link-local
     * addresses a Routing Header actually carries, under the same
     * one-interface-identifier-per-node assumption.
     *
     * @param global the global address of a node
     * @return the link-local address of the same node
     */
    Ipv6Address LinkLocalOf(Ipv6Address global) const;

    /**
     * @brief Find the interface a one-hop neighbour sits on.
     * @param dodag the DODAG membership to search the parent set of
     * @param neighbour the global address of the neighbour
     * @return the interface index, 0 if it cannot be told
     */
    uint32_t InterfaceForNeighbour(const DodagMembership& dodag, Ipv6Address neighbour) const;

    /**
     * @brief Send an already-built RPL message body on every RPL interface.
     *
     * For a multicast destination, e.g. ff02::1a. A unicast message has to
     * reach only one neighbour, so looping over every interface here would
     * hand every socket the same packet, and each socket's raw send would
     * independently ask RouteOutput() for the way there and each get back the
     * one correct route, resulting in as many duplicate transmissions as this
     * node has RPL interfaces. @see SendRplMessageUnicast for that case.
     *
     * @param packet the ICMPv6 payload, without the ICMPv6 header
     * @param code the RPL message code
     * @param dst the destination address
     */
    void SendRplMessageMulticast(Ptr<Packet> packet, uint8_t code, Ipv6Address dst);

    /**
     * @brief Send an already-built RPL message body to a single destination.
     *
     * For a DAO or a DAO-ACK, both unicast. RouteOutput() resolves the actual
     * next hop for a global destination from this node's own state, the
     * preferred parent or, on the root, the topology learnt from DAOs, rather
     * than from which socket the call came in on, so sending through any one
     * open RPL interface reaches the right neighbour; only one send is needed.
     *
     * @param packet the ICMPv6 payload, without the ICMPv6 header
     * @param code the RPL message code
     * @param dst the destination address
     */
    void SendRplMessageUnicast(Ptr<Packet> packet, uint8_t code, Ipv6Address dst);

    /**
     * @brief Send an already-built RPL message body on one interface.
     * @param interface the interface to send on
     * @param packet the ICMPv6 payload, without the ICMPv6 header
     * @param code the RPL message code
     * @param dst the destination address
     */
    void SendRplMessageOn(uint32_t interface, Ptr<Packet> packet, uint8_t code, Ipv6Address dst);

    /**
     * @brief Find the interface index a socket belongs to.
     * @param socket the socket
     * @return the interface index, or 0 if unknown
     */
    uint32_t GetInterfaceForSocket(Ptr<Socket> socket) const;

    /**
     * @brief Get the link-local address of an interface.
     *
     * RPL control messages are exchanged between link-local addresses, and the
     * RPL sockets are bound to the wildcard address, so the source address has
     * to be looked up here rather than read back from the socket.
     *
     * @param interface the IPv6 interface index
     * @return the link-local address, or :: if the interface has none yet
     */
    Ipv6Address GetLinkLocalAddress(uint32_t interface) const;

    /**
     * @brief Build the route towards the preferred parent.
     * @param dodag the DODAG membership to route within
     * @param dst the destination to put in the route
     * @return the route, nullptr if there is no preferred parent
     */
    Ptr<Ipv6Route> RouteViaPreferredParent(const DodagMembership& dodag, Ipv6Address dst) const;

    /**
     * @brief Construct a new DODAG membership in place and start its Trickle timer.
     *
     * Shared by HandleDadSuccess()'s root branch (RplHelper::SetRoot()'s
     * DODAG) and CreateLocalDodag() (a self-originated local one): both
     * build a fresh root membership, bind its Trickle timer to
     * DioTrickleFire(), and register it as the base DODAG if none exists
     * yet. What differs between the two callers -- Prefix Information,
     * MinHopRankIncrease/Ocp seeding -- is left to them to fill in on the
     * returned reference afterwards.
     *
     * @param key the key to construct the membership under; must not
     *        already exist in m_dodags
     * @param mop the Mode of Operation to advertise
     * @return a reference to the newly constructed membership
     */
    DodagMembership& CreateDodagMembership(DodagKey key, uint8_t mop);

    /**
     * @brief Get this node's membership in the base DODAG, if any.
     *
     * The "base DODAG" is the first DODAG this node ever joined or formed,
     * whether via RplHelper::SetRoot() (HandleDadSuccess()'s root branch),
     * ordinary DIS/DIO bootstrap (JoinDodag()), or CreateLocalDodag().
     * Every public accessor that does not take a DodagKey of its own
     * (GetRank(), IsJoined(), ...) reports this membership specifically, so
     * their meaning stays what it was back when m_dodags could hold only
     * one entry. m_baseDodagKey is what now answers "which one", tracked
     * separately from m_dodags itself so a second (or third...) concurrent
     * membership does not change which one these accessors mean.
     *
     * If the base membership is later left (LeaveDodag()) while others
     * survive, one of them is promoted to base rather than leaving every
     * base-scoped accessor blind to a node that is still very much
     * participating in RPL -- see LeaveDodag().
     *
     * @return a pointer to the membership, nullptr if not currently joined
     *         to anything
     */
    DodagMembership* GetBaseDodag();

    /**
     * @brief Get this node's membership in the base DODAG, if any.
     * @return a pointer to the membership, nullptr if not currently joined
     *         to anything
     */
    const DodagMembership* GetBaseDodag() const;

    Ptr<Ipv6L3Protocol> m_ipv6;                    //!< the IPv6 stack of this node
    std::map<Ptr<Socket>, uint32_t> m_socketToIfc; //!< RPL raw socket -> interface index
    std::map<uint32_t, Ptr<Socket>> m_ifcToSocket; //!< interface index -> RPL raw socket

    bool m_isRoot;                       //!< true if this node is the DODAG root
    Time m_disInterval;                  //!< period of unsolicited multicast DIS
    Timer m_disTimer;                    //!< schedules the periodic DIS
    Ptr<UniformRandomVariable> m_jitter; //!< jitter applied to control messages

    /**
     * @brief The RNG stream number to assign a DODAG membership's Trickle
     *        timer as it is created, -1 if AssignStreams() was never called.
     *
     * AssignStreams() runs once, before the simulation starts, but a
     * DodagMembership -- and the RplTrickleTimer it owns -- is not
     * constructed until this node actually joins or forms a DODAG, which
     * happens dynamically later. This is what carries the number forward to
     * JoinDodag() and HandleDadSuccess()'s root branch, the two places that
     * construct one.
     */
    int64_t m_dioTrickleStream{-1};

    bool m_enableLql;   //!< whether to derive and advertise LQL (RFC 6551 section 4.6)
    Callback<uint8_t, double> m_rssiToLql; //!< RSSI (dBm) -> LQL (0-7) mapping
    // Ocp and MinHopRankIncrease are attributes (RplHelper can configure
    // them) and the root's own DODAG membership seeds its ocp/rank from
    // these scalars when it forms; every other node overwrites its own copy
    // of both, inside DodagMembership, from the DODAG Configuration option
    // (RFC 6550 section 6.7.6) of the DIO it joins on (JoinDodag()).
    // MaxRankIncrease has no attribute of its own -- nothing sets it but the
    // DodagMembership member initializer -- so it does not need a scalar
    // counterpart the way these two do.
    uint16_t m_ocp;                //!< objective code point in use
    uint16_t m_minHopRankIncrease; //!< MinHopRankIncrease, also the rank of the root

    Time m_dioIntervalMin;         //!< Trickle Imin for DIOs
    uint8_t m_dioIntervalDoublings; //!< Trickle doublings for DIOs
    uint8_t m_dioRedundancy;        //!< Trickle redundancy constant for DIOs

    /**
     * @brief Every DODAG this node currently belongs to, keyed by DodagKey.
     *
     * Can hold more than one entry: a node may passively join a second (or
     * further) DODAG on top of its base one (HandleDio()), and/or actively
     * form its own local one (CreateLocalDodag()), e.g. an AODV-RPL (RFC
     * 9854) OrigNode's RREQ-Instance or a P2P-RPL (RFC 6997) Origin's
     * temporary DAG. RouteInput()/PrepareOutgoingPacket() still only ever
     * act on the base DODAG (@see GetBaseDodag()) -- this node originates
     * its own traffic, including its own DAO, on every membership it
     * holds, but does not relay a third node's traffic for anything but
     * the base one.
     *
     * @see DodagMembership for why its entries can never be copied or
     * moved once constructed.
     */
    std::map<DodagKey, DodagMembership> m_dodags;

    bool m_hasBaseDodag{false}; //!< whether m_baseDodagKey currently names a real entry
    //!< key of the base DODAG, meaningful only if m_hasBaseDodag
    DodagKey m_baseDodagKey{0, Ipv6Address::GetAny()};

    /// This node's own Sequence Number (RFC 9854 section 6.1, the RFC 6550
    /// section 7.2 lollipop counter): incremented at the start of each route
    /// discovery this node originates, so that routes an earlier one left
    /// behind can be told apart from the current one's.
    uint8_t m_aodvSeqNo{0};
    /// Imin of the Trickle timer pacing RREQ-DIOs. Separate from
    /// DioIntervalMin because a route discovery has to finish inside its own
    /// 'L' field, which is 16 seconds at the shortest, while the base
    /// DODAG's Imin is chosen for steady-state upkeep instead.
    Time m_aodvDioIntervalMin;
    uint8_t m_aodvDioIntervalDoublings; //!< doublings for the RREQ-DIO Trickle timer
    uint8_t m_aodvRankLimit;   //!< RankLimit put on RREQ-DIOs, 0 meaning no limit
    uint8_t m_aodvLifetime;    //!< the 'L' field put on RREQ-DIOs, 0..3
    /// REJOIN_REENABLE (RFC 9854 section 2): how long after leaving an
    /// RREQ-Instance a node is barred from rejoining the same one.
    Time m_aodvRejoinReenable;
    /// Clear the 'S' bit on every RREQ-DIO propagated from here, forcing the
    /// asymmetric path (RFC 9854 section 6.2.4). @see the AodvForceAsymmetric
    /// attribute for why real link-symmetry detection is not an option here.
    bool m_aodvForceAsymmetric;
    /// When each recently-left RREQ-Instance may be joined again. Without
    /// it, a discovery never really ends: the RREQ-DIOs a neighbour is still
    /// Trickle-pacing pull the node -- the OrigNode very much included --
    /// straight back into the instance it just left, and the OrigNode then
    /// finds itself an ordinary member of its own discovery.
    std::map<DodagKey, Time> m_aodvRejoinBlocked;

    /// A route an AODV-RPL discovery found, held at the OrigNode.
    struct AodvRoute
    {
        /// Every hop from the OrigNode outward, the TargNode last, as global
        /// addresses -- the Address Vector exactly as the RREP delivered it.
        std::vector<Ipv6Address> hops;
        uint8_t rreqInstanceId{0}; //!< the RREQ-InstanceID it was found under
        uint8_t destSeqNo{0};      //!< the TargNode's Sequence Number for it
        Time expire;               //!< when it goes stale
    };

    /// Routes found by AODV-RPL, keyed by TargNode address. Held separately
    /// from the RREQ-Instance that found them because the two have different
    /// lifetimes: the instance is bounded by the RREQ option's 'L' field,
    /// while "the lifetime is set according to DODAG configuration (i.e.,
    /// not the L field)" (RFC 9854 section 6.4.3).
    std::map<Ipv6Address, AodvRoute> m_aodvRoutes;

    /// Imin of the Trickle timer pacing P2P mode DIOs. RFC 6997 section 6.1's
    /// own default DODAG Configuration Option: DIOIntervalMin 6, i.e. 64 ms.
    Time m_p2pDioIntervalMin;
    uint8_t m_p2pDioIntervalDoublings; //!< doublings for the P2P mode DIO Trickle timer
    /// Redundancy constant k for P2P mode DIOs, RFC 6997 section 9.2's own
    /// recommended default of 1; @see the P2pDioRedundancy attribute and
    /// design-constraints.md.
    uint8_t m_p2pDioRedundancy;
    uint8_t m_p2pMaxRank; //!< MaxRank put on P2P mode DIOs, 0 meaning no limit
    uint8_t m_p2pLifetime; //!< the 'L' field put on P2P mode DIOs, 0..3

    /// A route P2P-RPL found, held at the Origin.
    struct P2pRoute
    {
        /// Every hop from the Origin outward, the Target last, as global
        /// addresses -- the Address Vector exactly as the P2P-DRO delivered
        /// it (RFC 6997 section 8.2: "the first element...contains the IPv6
        /// address of the router next to the Origin").
        std::vector<Ipv6Address> hops;
        uint8_t instanceId{0}; //!< the temporary DAG's RPLInstanceID it was found under
        Time expire;           //!< when it goes stale
    };

    /// Routes found by P2P-RPL, keyed by Target address. Held separately
    /// from the temporary DAG that found it for the same reason
    /// m_aodvRoutes is: the DAG's own membership is bounded by the P2P-RDO's
    /// 'L' field, while the route's lifetime instead comes from the DODAG
    /// Configuration Option's Default Lifetime/Lifetime Unit (RFC 6997
    /// sections 9.6, 9.7).
    std::map<Ipv6Address, P2pRoute> m_p2pRoutes;

    // Policy attributes for the DAO/downward-route side, set once via
    // RplHelper and shared by whatever DODAG membership uses them. Nothing
    // besides the base DODAG exercises DAO in this module today -- AODV-RPL
    // does not use RPL's DAO message at all (RFC 9854), and P2P-RPL uses its
    // own P2P-DRO instead of DAO (RFC 6997) -- so there is no present need
    // for these to vary per instance.
    Time m_daoInterval;      //!< how often this node refreshes its DAO
    Time m_daoAckTimeout;    //!< how long to wait for a DAO-ACK
    uint8_t m_daoRetries;    //!< how many times an unacknowledged DAO is resent
    uint8_t m_pathLifetime;  //!< lifetime this node advertises, in lifetime units
    uint16_t m_lifetimeUnit; //!< the unit of the path lifetime, in seconds

    /// How often a root institutes a Global Repair on a DODAG it roots, by
    /// incrementing its DODAGVersionNumber (RFC 6550 section 3.2.2).
    /// Time::Max(), the default, disables it -- GlobalRepairFire() is never
    /// armed at all, so this is a no-op change from every prior release.
    /// @see DodagMembership::globalRepairEvent.
    Time m_globalRepairInterval;

    bool m_p2pDroAckRequested;         //!< whether a Target sets the P2P-DRO's 'A' flag
    Time m_p2pDroAckWaitTime;          //!< P2P_DRO_ACK_WAIT_TIME (RFC 6997 section 9.5)
    uint8_t m_p2pDroMaxRetransmissions; //!< MAX_P2P_DRO_RETRANSMISSIONS (RFC 6997 section 9.5)

    Ipv6Address m_rootPrefix;    //!< the root's own GUA/ULA prefix (RootPrefix attribute)
    uint8_t m_rootPrefixLength; //!< prefix length of m_rootPrefix, in bits

    /**
     * @brief React to Neighbour Discovery confirming an address is unique.
     *
     * Connected once, in DoInitialize(), to Icmpv6L4Protocol's "DadSuccess"
     * trace: the only way, short of polling, to learn that a SLAAC address
     * this node either built for itself (root, from RootPrefix) or asked
     * Ipv6L3Protocol::AddAutoconfiguredAddress() to build (every other node,
     * from the DIO's Prefix Information option, see JoinDodag()) has cleared
     * Duplicate Address Detection and is no longer TENTATIVE.
     *
     * On the root, this is what actually starts the DODAG: DoInitialize()
     * only requests the address, it does not wait for it, since DAD is
     * asynchronous. Every other node needs no action here -- SendDao()
     * already checks GetGlobalAddress() before using it.
     *
     * @param address the address that just passed DAD
     */
    void HandleDadSuccess(const Ipv6Address& address);
};

} // namespace rpl
} // namespace ns3

#endif /* RPL_ROUTING_PROTOCOL_H */
