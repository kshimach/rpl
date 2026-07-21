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

#include "ns3/ipv6-address.h"
#include "ns3/ipv6-interface.h"
#include "ns3/ipv6-l3-protocol.h"
#include "ns3/ipv6-routing-protocol.h"
#include "ns3/nstime.h"
#include "ns3/random-variable-stream.h"
#include "ns3/socket.h"
#include "ns3/timer.h"

#include <map>

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
 * whole path into every packet it sends down. @see RplSourceRouteTag for how
 * that path is carried and what it costs in fidelity.
 */
class RplRoutingProtocol : public Ipv6RoutingProtocol
{
  public:
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

    /**
     * @brief Make this node the root of the DODAG.
     *
     * The DODAGID is the node's first global address, so this must be called
     * after the global addresses have been assigned.
     */
    void SetAsRoot();

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
     * @brief Get how many nodes the root has heard a DAO from.
     *
     * Only meaningful on the root, which is the only node that keeps the
     * topology in non-storing mode.
     *
     * @return the number of nodes in the topology this node knows about
     */
    uint32_t GetTopologySize() const;

    /**
     * @brief Get the path the root would put in a packet for a destination.
     *
     * @param destination the address to reach
     * @param [out] hops the routers to traverse, root and destination excluded
     * @return true if a path was found
     */
    bool ComputeSourceRoute(Ipv6Address destination, std::vector<Ipv6Address>& hops) const;

    /**
     * @brief Assign a fixed stream number to the random variables used here.
     * @param stream first stream index to use
     * @return the number of stream indices assigned
     */
    int64_t AssignStreams(int64_t stream);

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
    };

    /// What the root remembers about one node of the DODAG, learnt from DAOs.
    struct TopologyEntry
    {
        Ipv6Address parent;     //!< the parent the node reports sitting under
        uint8_t pathSequence{0}; //!< path sequence of the DAO this came from
        Time expire;            //!< when the entry goes stale
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
     * @param dst destination, ff02::1a for the multicast case
     * @param interface the interface to send on, 0 for all RPL interfaces
     */
    void SendDio(Ipv6Address dst, uint32_t interface = 0);

    /**
     * @brief Send a multicast DIO because the Trickle timer said so.
     */
    void DioTrickleFire();

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
     */
    void HandleDio(const RplDioHeader& dio, Ipv6Address from, uint32_t interface);

    /**
     * @brief Join the DODAG advertised by a DIO, adopting its configuration.
     * @param dio the DIO
     */
    void JoinDodag(const RplDioHeader& dio);

    /**
     * @brief Leave the current DODAG and drop every candidate parent.
     */
    void LeaveDodag();

    /**
     * @brief Compute the rank this node would have through a given parent.
     *
     * OF0 (RFC 6552) with a rank factor of 1, a stretch of 0 and a step of
     * rank of 1: with no link metric available every neighbour is one
     * MinHopRankIncrease away.
     *
     * @param parent the candidate parent
     * @return the resulting rank, RPL_INFINITE_RANK if the parent is unusable
     */
    uint16_t RankViaParent(const Parent& parent) const;

    /**
     * @brief Re-run parent selection and update the rank.
     *
     * Candidates that have not been heard from for two maximum DIO intervals
     * are dropped, since that is two missed DIOs in a row.
     *
     * @return true if the preferred parent or the rank changed
     */
    bool SelectPreferredParent();

    /**
     * @brief Advertise this node to the root, RFC 6550 section 6.4.
     *
     * The DAO travels to the DODAGID like any other upward traffic, so every
     * node on the way just forwards it and only the root ever reads it.
     */
    void SendDao();

    /**
     * @brief Send a DAO now and schedule the next refresh.
     */
    void DaoTimerExpire();

    /**
     * @brief Re-send the DAO that was not acknowledged, or give up.
     */
    void DaoRetry();

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
     */
    void PurgeTopology();

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
     * @param linkLocal the link-local address of the neighbour
     * @return the global address of the neighbour, :: if it cannot be built
     */
    Ipv6Address GlobalAddressOf(Ipv6Address linkLocal) const;

    /**
     * @brief Find the interface a one-hop neighbour sits on.
     * @param neighbour the global address of the neighbour
     * @return the interface index, 0 if it cannot be told
     */
    uint32_t InterfaceForNeighbour(Ipv6Address neighbour) const;

    /**
     * @brief Build a route handing a packet straight to a one-hop neighbour.
     * @param neighbour the address of the neighbour to send to
     * @param dst the destination to put in the route
     * @return the route, nullptr if the neighbour is on no known interface
     */
    Ptr<Ipv6Route> RouteToNeighbour(Ipv6Address neighbour, Ipv6Address dst) const;

    /**
     * @brief Send an already-built RPL message body on every RPL interface.
     * @param packet the ICMPv6 payload, without the ICMPv6 header
     * @param code the RPL message code
     * @param dst the destination address
     */
    void SendRplMessage(Ptr<Packet> packet, uint8_t code, Ipv6Address dst);

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
     * @brief Get the first global address of this node.
     * @return the global address, :: if the node has none
     */
    Ipv6Address GetGlobalAddress() const;

    /**
     * @brief Build the route towards the preferred parent.
     * @param dst the destination to put in the route
     * @return the route, nullptr if there is no preferred parent
     */
    Ptr<Ipv6Route> RouteViaPreferredParent(Ipv6Address dst) const;

    Ptr<Ipv6L3Protocol> m_ipv6;                    //!< the IPv6 stack of this node
    std::map<Ptr<Socket>, uint32_t> m_socketToIfc; //!< RPL raw socket -> interface index
    std::map<uint32_t, Ptr<Socket>> m_ifcToSocket; //!< interface index -> RPL raw socket

    bool m_isRoot;                       //!< true if this node is the DODAG root
    Time m_disInterval;                  //!< period of unsolicited multicast DIS
    Timer m_disTimer;                    //!< schedules the periodic DIS
    Ptr<UniformRandomVariable> m_jitter; //!< jitter applied to control messages

    bool m_joined;         //!< true once this node belongs to a DODAG
    uint8_t m_instanceId;  //!< RPLInstanceID of the DODAG
    Ipv6Address m_dodagId; //!< DODAGID, i.e. the global address of the root
    uint8_t m_version;     //!< DODAG version number
    uint16_t m_rank;       //!< rank of this node in the DODAG
    uint8_t m_mop;         //!< Mode of Operation of the DODAG
    uint8_t m_dtsn;        //!< Destination Advertisement Trigger Sequence Number
    bool m_grounded;       //!< Grounded flag of the DODAG
    uint8_t m_preference;  //!< preference of the DODAG

    uint16_t m_ocp;                //!< objective code point in use
    uint16_t m_minHopRankIncrease; //!< MinHopRankIncrease, also the rank of the root
    uint16_t m_maxRankIncrease;    //!< MaxRankIncrease
    Time m_dioIntervalMin;         //!< Trickle Imin for DIOs
    uint8_t m_dioIntervalDoublings; //!< Trickle doublings for DIOs
    uint8_t m_dioRedundancy;        //!< Trickle redundancy constant for DIOs

    RplTrickleTimer m_dioTrickle;            //!< paces the multicast DIOs
    std::map<Ipv6Address, Parent> m_parents; //!< candidate parents, by link-local address
    Ipv6Address m_preferredParent;           //!< link-local address of the preferred parent

    Time m_daoInterval;      //!< how often this node refreshes its DAO
    Time m_daoAckTimeout;    //!< how long to wait for a DAO-ACK
    uint8_t m_daoRetries;    //!< how many times an unacknowledged DAO is resent
    uint8_t m_pathLifetime;  //!< lifetime this node advertises, in lifetime units
    uint16_t m_lifetimeUnit; //!< the unit of the path lifetime, in seconds

    uint8_t m_daoSequence;   //!< sequence of the last DAO this node sent
    uint8_t m_pathSequence;  //!< path sequence of the route this node advertises
    uint8_t m_daoRetriesLeft; //!< retries left for the DAO awaiting an acknowledgement
    bool m_daoAckPending;    //!< true while a DAO-ACK is being waited for
    EventId m_daoEvent;      //!< schedules the periodic DAO
    EventId m_daoRetryEvent; //!< schedules the retry of an unacknowledged DAO

    /// The root only: which parent each node reports sitting under.
    std::map<Ipv6Address, TopologyEntry> m_topology;
};

} // namespace rpl
} // namespace ns3

#endif /* RPL_ROUTING_PROTOCOL_H */
