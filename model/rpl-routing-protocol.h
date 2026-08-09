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
    // model/rpl-routing-protocol.cc. Scoped to source-routed symmetric
    // discovery (H=0, S=1) for a single target; @see design-constraints.md
    // for what that leaves out and why.

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
     * @brief Whether this node is the TargNode of an RREQ-Instance it holds.
     * @param instanceId the RPLInstanceID of the RREQ-Instance
     * @param dodagId the DODAGID of the RREQ-Instance
     * @return true if one of this node's addresses is the instance's target
     */
    bool IsAodvTarget(uint8_t instanceId, Ipv6Address dodagId) const;

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
            uint8_t origSeqNo{0}; //!< Orig SeqNo of the RREQ that formed this
            uint8_t rankLimit{0}; //!< RankLimit, 0 meaning no limit
            uint8_t lifetimeField{0}; //!< the 'L' field this instance was opened with
            Ipv6Address target;   //!< the single ART target being looked for
            /// The route the RREQ-DIO took to get here, OrigNode-side first,
            /// as this node would propagate it: its own address is already
            /// appended (RFC 9854 section 6.2.5).
            std::vector<Ipv6Address> addressVector;
            bool isOrigin{false}; //!< this node started the discovery
            bool isTarget{false}; //!< this node is the TargNode being looked for
            /// When the 'L' field's deadline takes this node out of the
            /// instance (RFC 9854 section 4.1). Never armed for the
            /// unlimited encoding.
            Timer expiry{Timer::CANCEL_ON_DESTROY};
        };

        AodvRreqState aodv; //!< AODV-RPL state; untouched unless mop is 4
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
     */
    void HandleDio(const RplDioHeader& dio,
                   Ipv6Address from,
                   uint32_t interface,
                   uint16_t linkEtx,
                   uint8_t lql);

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
    /// When each recently-left RREQ-Instance may be joined again. Without
    /// it, a discovery never really ends: the RREQ-DIOs a neighbour is still
    /// Trickle-pacing pull the node -- the OrigNode very much included --
    /// straight back into the instance it just left, and the OrigNode then
    /// finds itself an ordinary member of its own discovery.
    std::map<DodagKey, Time> m_aodvRejoinBlocked;

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
