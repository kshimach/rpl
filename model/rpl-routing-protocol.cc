/*
 * Copyright (c) 2026 ns-3 RPL module contributors
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * RPL (RFC 6550) in non-storing mode, ported from Contiki-NG rpl-lite
 * (Copyright (c) 2010, Swedish Institute of Computer Science, 3-clause BSD).
 */

#include "rpl-routing-protocol.h"

#include "rpl-header.h"

#include "ns3/icmpv6-header.h"
#include "ns3/icmpv6-l4-protocol.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/ipv6-raw-socket-factory.h"
#include "ns3/ipv6-route.h"
#include "ns3/log.h"
#include "ns3/net-device.h"
#include "ns3/node.h"
#include "ns3/output-stream-wrapper.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/uinteger.h"

#include <algorithm>
#include <cmath>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("RplRoutingProtocol");

namespace rpl
{

NS_OBJECT_ENSURE_REGISTERED(RplRoutingProtocol);

TypeId
RplRoutingProtocol::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::rpl::RplRoutingProtocol")
            .SetParent<Ipv6RoutingProtocol>()
            .SetGroupName("Rpl")
            .AddConstructor<RplRoutingProtocol>()
            .AddAttribute("DisInterval",
                          "Period of the unsolicited multicast DIS sent while this node has not "
                          "joined a DODAG (RPL_DIS_INTERVAL in Contiki-NG).",
                          TimeValue(Seconds(30)),
                          MakeTimeAccessor(&RplRoutingProtocol::m_disInterval),
                          MakeTimeChecker())
            .AddAttribute("DioIntervalMin",
                          "Imin of the Trickle timer pacing the DIOs. Only the root uses the "
                          "value configured here; the other nodes take it from the DODAG "
                          "Configuration option of the DIO they join on.",
                          TimeValue(MilliSeconds(1 << RPL_DIO_INTERVAL_MIN)),
                          MakeTimeAccessor(&RplRoutingProtocol::m_dioIntervalMin),
                          MakeTimeChecker())
            .AddAttribute("DioIntervalDoublings",
                          "Number of doublings between Imin and Imax of the DIO Trickle timer.",
                          UintegerValue(RPL_DIO_INTERVAL_DOUBLINGS),
                          MakeUintegerAccessor(&RplRoutingProtocol::m_dioIntervalDoublings),
                          MakeUintegerChecker<uint8_t>())
            .AddAttribute("DioRedundancy",
                          "Redundancy constant k of the DIO Trickle timer, 0 to never suppress.",
                          UintegerValue(RPL_DIO_REDUNDANCY),
                          MakeUintegerAccessor(&RplRoutingProtocol::m_dioRedundancy),
                          MakeUintegerChecker<uint8_t>())
            .AddAttribute("MinHopRankIncrease",
                          "MinHopRankIncrease, which is also the rank of the root.",
                          UintegerValue(RPL_MIN_HOPRANKINC),
                          MakeUintegerAccessor(&RplRoutingProtocol::m_minHopRankIncrease),
                          MakeUintegerChecker<uint16_t>(1, RPL_INFINITE_RANK));
    return tid;
}

RplRoutingProtocol::RplRoutingProtocol()
    : m_ipv6(nullptr),
      m_isRoot(false),
      m_disInterval(Seconds(30)),
      m_disTimer(Timer::CANCEL_ON_DESTROY),
      m_joined(false),
      m_instanceId(RPL_DEFAULT_INSTANCE),
      m_dodagId(Ipv6Address::GetAny()),
      m_version(0),
      m_rank(RPL_INFINITE_RANK),
      m_mop(RPL_MOP_NON_STORING),
      m_dtsn(0),
      m_grounded(false),
      m_preference(0),
      m_ocp(RPL_OCP_OF0),
      m_minHopRankIncrease(RPL_MIN_HOPRANKINC),
      m_maxRankIncrease(RPL_MAX_RANKINC),
      m_dioIntervalMin(MilliSeconds(1 << RPL_DIO_INTERVAL_MIN)),
      m_dioIntervalDoublings(RPL_DIO_INTERVAL_DOUBLINGS),
      m_dioRedundancy(RPL_DIO_REDUNDANCY),
      m_preferredParent(Ipv6Address::GetAny())
{
    NS_LOG_FUNCTION(this);
    m_jitter = CreateObject<UniformRandomVariable>();
    m_dioTrickle.SetFunction(MakeCallback(&RplRoutingProtocol::DioTrickleFire, this));
}

RplRoutingProtocol::~RplRoutingProtocol()
{
    NS_LOG_FUNCTION(this);
}

void
RplRoutingProtocol::SetIpv6(Ptr<Ipv6> ipv6)
{
    NS_LOG_FUNCTION(this << ipv6);
    NS_ASSERT(ipv6);
    NS_ASSERT(!m_ipv6);
    m_ipv6 = DynamicCast<Ipv6L3Protocol>(ipv6);
    NS_ASSERT_MSG(m_ipv6, "RPL requires an Ipv6L3Protocol");
}

void
RplRoutingProtocol::DoInitialize()
{
    NS_LOG_FUNCTION(this);

    // Interface 0 is the loopback; RPL never runs there.
    for (uint32_t i = 1; i < m_ipv6->GetNInterfaces(); i++)
    {
        if (m_ipv6->IsUp(i))
        {
            StartInterface(i);
        }
    }

    m_dioTrickle.SetParameters(m_dioIntervalMin, m_dioIntervalDoublings, m_dioRedundancy);

    if (m_isRoot)
    {
        // RFC 6550, section 8.2.2.2: the root is at MinHopRankIncrease and the
        // DODAGID is one of its own global addresses.
        m_dodagId = GetGlobalAddress();
        NS_ASSERT_MSG(!m_dodagId.IsAny(), "The DODAG root needs a global address");
        m_joined = true;
        m_grounded = true;
        m_rank = m_minHopRankIncrease;
        m_dioTrickle.Start();
        NS_LOG_INFO("Root of DODAG " << m_dodagId << " at rank " << m_rank);
    }
    else
    {
        m_disTimer.SetFunction(&RplRoutingProtocol::DisTimerExpire, this);
        // Spread the initial solicitations so that a whole network booting at
        // once does not send every DIS in the same slot.
        Simulator::Schedule(Seconds(m_jitter->GetValue(0.0, 1.0)),
                            &RplRoutingProtocol::DisTimerExpire,
                            this);
    }

    Ipv6RoutingProtocol::DoInitialize();
}

void
RplRoutingProtocol::DoDispose()
{
    NS_LOG_FUNCTION(this);

    m_disTimer.Cancel();
    m_dioTrickle.Stop();
    for (auto& [socket, interface] : m_socketToIfc)
    {
        socket->Close();
    }
    m_socketToIfc.clear();
    m_ifcToSocket.clear();
    m_parents.clear();
    m_ipv6 = nullptr;

    Ipv6RoutingProtocol::DoDispose();
}

void
RplRoutingProtocol::StartInterface(uint32_t interface)
{
    NS_LOG_FUNCTION(this << interface);

    if (m_ifcToSocket.find(interface) != m_ifcToSocket.end())
    {
        return;
    }

    Ipv6Address linkLocal = GetLinkLocalAddress(interface);
    if (linkLocal.IsAny())
    {
        NS_LOG_LOGIC("Interface " << interface << " has no link-local address yet, deferring");
        return;
    }

    Ptr<Socket> socket = Socket::CreateSocket(m_ipv6->GetObject<Node>(),
                                              Ipv6RawSocketFactory::GetTypeId());
    NS_ASSERT(socket);
    socket->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));

    // Ipv6RawSocketImpl's ICMPv6 type filter would be the natural way to keep
    // non-RPL traffic out, but its header is not installed as a public ns-3
    // header, so RecvRpl() drops anything that is not ICMPv6 type 155 instead.
    //
    // The bind has to be to the wildcard address: Ipv6RawSocketImpl::ForwardUp()
    // only accepts a packet whose destination equals the bound address, so a
    // socket bound to the link-local address would never see ff02::1a. The
    // BindToNetDevice() below is what keeps the socket to one interface.
    socket->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    socket->BindToNetDevice(m_ipv6->GetNetDevice(interface));
    socket->SetRecvCallback(MakeCallback(&RplRoutingProtocol::RecvRpl, this));

    m_socketToIfc[socket] = interface;
    m_ifcToSocket[interface] = socket;

    // Without this the IPv6 layer discards DIO/DIS: Ipv6L3Protocol::Receive()
    // only delivers a non-all-nodes multicast if the group is registered.
    m_ipv6->AddMulticastAddress(Ipv6Address(RPL_ALL_NODES_MULTICAST), interface);

    NS_LOG_INFO("RPL started on interface " << interface << " (" << linkLocal << ")");
}

void
RplRoutingProtocol::StopInterface(uint32_t interface)
{
    NS_LOG_FUNCTION(this << interface);

    auto it = m_ifcToSocket.find(interface);
    if (it == m_ifcToSocket.end())
    {
        return;
    }

    m_ipv6->RemoveMulticastAddress(Ipv6Address(RPL_ALL_NODES_MULTICAST), interface);
    it->second->Close();
    m_socketToIfc.erase(it->second);
    m_ifcToSocket.erase(it);

    // Drop the neighbours that were only reachable through this interface.
    for (auto parent = m_parents.begin(); parent != m_parents.end();)
    {
        parent = (parent->second.interface == interface) ? m_parents.erase(parent)
                                                         : std::next(parent);
    }
    if (SelectPreferredParent())
    {
        m_dioTrickle.Reset();
    }
}

uint32_t
RplRoutingProtocol::GetInterfaceForSocket(Ptr<Socket> socket) const
{
    auto it = m_socketToIfc.find(socket);
    return it == m_socketToIfc.end() ? 0 : it->second;
}

Ipv6Address
RplRoutingProtocol::GetLinkLocalAddress(uint32_t interface) const
{
    for (uint32_t j = 0; j < m_ipv6->GetNAddresses(interface); j++)
    {
        Ipv6Address addr = m_ipv6->GetAddress(interface, j).GetAddress();
        if (addr.IsLinkLocal())
        {
            return addr;
        }
    }
    return Ipv6Address::GetAny();
}

Ipv6Address
RplRoutingProtocol::GetGlobalAddress() const
{
    for (uint32_t i = 1; i < m_ipv6->GetNInterfaces(); i++)
    {
        for (uint32_t j = 0; j < m_ipv6->GetNAddresses(i); j++)
        {
            Ipv6InterfaceAddress iaddr = m_ipv6->GetAddress(i, j);
            if (iaddr.GetScope() == Ipv6InterfaceAddress::GLOBAL)
            {
                return iaddr.GetAddress();
            }
        }
    }
    return Ipv6Address::GetAny();
}

void
RplRoutingProtocol::RecvRpl(Ptr<Socket> socket)
{
    NS_LOG_FUNCTION(this << socket);

    Address sender;
    Ptr<Packet> packet = socket->RecvFrom(sender);
    if (!packet)
    {
        return;
    }

    // Ipv6RawSocketImpl::ForwardUp() re-attaches the IPv6 header before queuing.
    Ipv6Header ipv6Header;
    packet->RemoveHeader(ipv6Header);

    Icmpv6Header icmpv6Header;
    packet->RemoveHeader(icmpv6Header);
    if (icmpv6Header.GetType() != ICMPV6_RPL)
    {
        return;
    }

    uint32_t interface = GetInterfaceForSocket(socket);
    Ipv6Address from = ipv6Header.GetSource();

    // Our own multicast messages come back through the loopback path.
    if (from == GetLinkLocalAddress(interface))
    {
        return;
    }

    switch (icmpv6Header.GetCode())
    {
    case RPL_CODE_DIS: {
        RplDisHeader dis;
        packet->RemoveHeader(dis);
        NS_LOG_INFO("Received a DIS from " << from << " on interface " << interface);
        HandleDis(from, interface, ipv6Header.GetDestination().IsMulticast());
        break;
    }
    case RPL_CODE_DIO: {
        RplDioHeader dio;
        packet->RemoveHeader(dio);
        NS_LOG_INFO("Received a DIO from " << from << " on interface " << interface << ": " << dio);
        HandleDio(dio, from, interface);
        break;
    }
    case RPL_CODE_DAO:
        NS_LOG_INFO("Received a DAO from " << from << " on interface " << interface);
        break;
    case RPL_CODE_DAO_ACK:
        NS_LOG_INFO("Received a DAO-ACK from " << from << " on interface " << interface);
        break;
    default:
        NS_LOG_WARN("Unsupported RPL message code " << +icmpv6Header.GetCode() << " from " << from);
        break;
    }
}

void
RplRoutingProtocol::SendRplMessage(Ptr<Packet> packet, uint8_t code, Ipv6Address dst)
{
    NS_LOG_FUNCTION(this << packet << +code << dst);

    for (auto& [interface, socket] : m_ifcToSocket)
    {
        SendRplMessageOn(interface, packet->Copy(), code, dst);
    }
}

void
RplRoutingProtocol::SendRplMessageOn(uint32_t interface,
                                     Ptr<Packet> packet,
                                     uint8_t code,
                                     Ipv6Address dst)
{
    NS_LOG_FUNCTION(this << interface << packet << +code << dst);

    auto it = m_ifcToSocket.find(interface);
    if (it == m_ifcToSocket.end())
    {
        NS_LOG_WARN("RPL is not running on interface " << interface);
        return;
    }

    Ipv6Address src = GetLinkLocalAddress(interface);

    // Ipv6RawSocketImpl only fixes up the checksum of echo requests, so the
    // RPL header has to carry a checksum computed against the source address.
    Icmpv6Header icmpv6Header;
    icmpv6Header.SetType(ICMPV6_RPL);
    icmpv6Header.SetCode(code);
    icmpv6Header.CalculatePseudoHeaderChecksum(src,
                                               dst,
                                               packet->GetSize() +
                                                   icmpv6Header.GetSerializedSize(),
                                               Icmpv6L4Protocol::GetStaticProtocolNumber());
    packet->AddHeader(icmpv6Header);

    // Ipv6RawSocketImpl::SendTo() refuses to set a manual hop limit on a
    // multicast destination, so tag the packet directly.
    SocketIpv6HopLimitTag hopLimitTag;
    hopLimitTag.SetHopLimit(255);
    packet->AddPacketTag(hopLimitTag);

    it->second->SendTo(packet, 0, Inet6SocketAddress(dst, 0));
    NS_LOG_LOGIC("Sent RPL code " << +code << " to " << dst << " via interface " << interface);
}

void
RplRoutingProtocol::SendDis(Ipv6Address dst)
{
    NS_LOG_FUNCTION(this << dst);

    RplDisHeader dis;
    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(dis);
    SendRplMessage(packet, RPL_CODE_DIS, dst);
}

void
RplRoutingProtocol::DisTimerExpire()
{
    NS_LOG_FUNCTION(this);

    if (m_joined)
    {
        return;
    }

    SendDis(Ipv6Address(RPL_ALL_NODES_MULTICAST));
    m_disTimer.Cancel();
    m_disTimer.Schedule(m_disInterval);
}

void
RplRoutingProtocol::SendDio(Ipv6Address dst, uint32_t interface)
{
    NS_LOG_FUNCTION(this << dst << interface);

    if (!m_joined)
    {
        return;
    }

    RplDioHeader dio;
    dio.SetInstanceId(m_instanceId);
    dio.SetVersionNumber(m_version);
    dio.SetRank(m_rank);
    dio.SetGrounded(m_grounded);
    dio.SetMop(m_mop);
    dio.SetPreference(m_preference);
    dio.SetDtsn(m_dtsn);
    dio.SetDodagId(m_dodagId);

    // The configuration option is carried by every DIO, not just the root's, so
    // that a node joining deep in the DODAG gets the same Trickle parameters.
    dio.SetDagConfiguration(m_dioIntervalDoublings,
                            static_cast<uint8_t>(std::log2(m_dioIntervalMin.GetMilliSeconds())),
                            m_dioRedundancy,
                            m_maxRankIncrease,
                            m_minHopRankIncrease,
                            m_ocp,
                            RPL_DEFAULT_LIFETIME,
                            RPL_DEFAULT_LIFETIME_UNIT);

    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(dio);

    if (interface == 0)
    {
        SendRplMessage(packet, RPL_CODE_DIO, dst);
    }
    else
    {
        SendRplMessageOn(interface, packet, RPL_CODE_DIO, dst);
    }
}

void
RplRoutingProtocol::DioTrickleFire()
{
    NS_LOG_FUNCTION(this);
    SendDio(Ipv6Address(RPL_ALL_NODES_MULTICAST));
}

void
RplRoutingProtocol::HandleDis(Ipv6Address from, uint32_t interface, bool toMulticast)
{
    NS_LOG_FUNCTION(this << from << interface << toMulticast);

    if (!m_joined)
    {
        return;
    }

    if (toMulticast)
    {
        // RFC 6550, section 8.3: a multicast DIS is an inconsistency, so the
        // Trickle timer restarts and the answer goes out to the whole link.
        m_dioTrickle.Reset();
    }
    else
    {
        SendDio(from, interface);
    }
}

void
RplRoutingProtocol::HandleDio(const RplDioHeader& dio, Ipv6Address from, uint32_t interface)
{
    NS_LOG_FUNCTION(this << from << interface);

    if (m_isRoot)
    {
        // The root originates the DODAG and never takes a parent in it.
        return;
    }

    if (dio.GetMop() != RPL_MOP_NON_STORING)
    {
        NS_LOG_WARN("Ignoring a DIO advertising mode of operation " << +dio.GetMop()
                                                                    << ", only non-storing is "
                                                                       "implemented");
        return;
    }

    if (dio.GetRank() == RPL_INFINITE_RANK)
    {
        // RFC 6550, section 8.2.2.5: an infinite rank poisons the sub-DODAG.
        NS_LOG_LOGIC("Neighbour " << from << " is advertising an infinite rank");
        m_parents.erase(from);
        if (SelectPreferredParent())
        {
            m_dioTrickle.Reset();
        }
        return;
    }

    if (!m_joined)
    {
        JoinDodag(dio);
    }
    else if (dio.GetInstanceId() != m_instanceId || dio.GetDodagId() != m_dodagId)
    {
        NS_LOG_LOGIC("Ignoring a DIO for instance " << +dio.GetInstanceId() << " DODAG "
                                                    << dio.GetDodagId());
        return;
    }
    else if (dio.GetVersionNumber() != m_version)
    {
        // Note that the lollipop comparison of RFC 6550 section 7.2 is not
        // implemented, so a version number wrapping around is not detected.
        if (dio.GetVersionNumber() > m_version)
        {
            NS_LOG_INFO("DODAG " << m_dodagId << " moved to version " << +dio.GetVersionNumber());
            LeaveDodag();
            JoinDodag(dio);
        }
        else
        {
            NS_LOG_LOGIC("Ignoring a DIO for the stale version " << +dio.GetVersionNumber());
            return;
        }
    }

    Parent& parent = m_parents[from];
    parent.address = from;
    parent.interface = interface;
    parent.rank = dio.GetRank();
    parent.dtsn = dio.GetDtsn();
    parent.lastHeard = Simulator::Now();
    parent.freshness = std::min<uint8_t>(parent.freshness + 1, RPL_FRESHNESS_MAX);

    m_dioTrickle.ConsistencyHit();

    if (SelectPreferredParent())
    {
        m_dioTrickle.Reset();
    }
}

void
RplRoutingProtocol::JoinDodag(const RplDioHeader& dio)
{
    NS_LOG_FUNCTION(this);

    m_joined = true;
    m_instanceId = dio.GetInstanceId();
    m_dodagId = dio.GetDodagId();
    m_version = dio.GetVersionNumber();
    m_mop = dio.GetMop();
    m_grounded = dio.GetGrounded();
    m_preference = dio.GetPreference();
    m_rank = RPL_INFINITE_RANK; // until a parent is picked

    if (dio.HasDagConfiguration())
    {
        m_ocp = dio.GetOcp();
        m_minHopRankIncrease = dio.GetMinHopRankIncrease();
        m_maxRankIncrease = dio.GetMaxRankIncrease();
        m_dioIntervalMin = MilliSeconds(int64_t(1) << dio.GetIntervalMin());
        m_dioIntervalDoublings = dio.GetIntervalDoublings();
        m_dioRedundancy = dio.GetRedundancy();

        if (m_ocp != RPL_OCP_OF0)
        {
            NS_LOG_WARN("DODAG " << m_dodagId << " asks for objective code point " << m_ocp
                                 << ", but only OF0 is implemented");
        }
    }

    m_disTimer.Cancel();
    m_dioTrickle.SetParameters(m_dioIntervalMin, m_dioIntervalDoublings, m_dioRedundancy);
    m_dioTrickle.Start();

    NS_LOG_INFO("Joined DODAG " << m_dodagId << " version " << +m_version);
}

void
RplRoutingProtocol::LeaveDodag()
{
    NS_LOG_FUNCTION(this);

    m_joined = false;
    m_rank = RPL_INFINITE_RANK;
    m_preferredParent = Ipv6Address::GetAny();
    m_parents.clear();
    m_dioTrickle.Stop();
}

uint16_t
RplRoutingProtocol::RankViaParent(const Parent& parent) const
{
    if (parent.rank == RPL_INFINITE_RANK)
    {
        return RPL_INFINITE_RANK;
    }

    uint32_t rank = static_cast<uint32_t>(parent.rank) + m_minHopRankIncrease;
    return rank >= RPL_INFINITE_RANK ? RPL_INFINITE_RANK : static_cast<uint16_t>(rank);
}

bool
RplRoutingProtocol::SelectPreferredParent()
{
    NS_LOG_FUNCTION(this);

    if (m_isRoot)
    {
        return false;
    }

    // Two maximum DIO intervals without a DIO is two missed announcements in a
    // row, which is taken as the neighbour being gone.
    Time maxInterval = m_dioIntervalMin * (int64_t(1) << m_dioIntervalDoublings);
    Time staleBefore = Simulator::Now() - 2 * maxInterval;
    for (auto it = m_parents.begin(); it != m_parents.end();)
    {
        if (it->second.lastHeard < staleBefore)
        {
            NS_LOG_LOGIC("Dropping the stale neighbour " << it->first);
            it = m_parents.erase(it);
        }
        else
        {
            it++;
        }
    }

    // A neighbour heard only a handful of times is likely to be a lucky long
    // shot rather than a usable link, so once any neighbour is fresh the stale
    // ones stop being candidates. Before that everything counts, otherwise a
    // node could never bootstrap into the DODAG.
    bool haveFresh = std::any_of(m_parents.begin(), m_parents.end(), [](const auto& entry) {
        return entry.second.freshness >= RPL_FRESHNESS_TARGET;
    });

    // The rank this node had on entry is what decides which neighbours are
    // usable, so that recomputing the rank cannot make a node adopt one of its
    // own children as a parent. The exception is a rank inherited from a
    // neighbour that has since turned out to be stale: keeping it would lock
    // the node onto a bad link, because the fresh neighbours below that rank
    // would all be rejected.
    uint16_t currentRank = m_rank;
    auto preferred = m_parents.find(m_preferredParent);
    if (haveFresh &&
        (preferred == m_parents.end() || preferred->second.freshness < RPL_FRESHNESS_TARGET))
    {
        currentRank = RPL_INFINITE_RANK;
    }

    Ipv6Address best = Ipv6Address::GetAny();
    uint16_t bestRank = RPL_INFINITE_RANK;

    for (const auto& [address, parent] : m_parents)
    {
        if (haveFresh && parent.freshness < RPL_FRESHNESS_TARGET)
        {
            NS_LOG_LOGIC("Neighbour " << address << " has only been heard "
                                      << +parent.freshness << " times");
            continue;
        }

        if (m_joined && currentRank != RPL_INFINITE_RANK && parent.rank >= currentRank)
        {
            NS_LOG_LOGIC("Neighbour " << address << " is not closer to the root than we are");
            continue;
        }

        uint16_t rank = RankViaParent(parent);
        if (rank == RPL_INFINITE_RANK)
        {
            continue;
        }
        // Ties are broken on the address so that the choice is deterministic.
        if (best.IsAny() || rank < bestRank || (rank == bestRank && address < best))
        {
            best = address;
            bestRank = rank;
        }
    }

    bool changed = (best != m_preferredParent) || (bestRank != m_rank);
    if (!changed)
    {
        return false;
    }

    if (best.IsAny())
    {
        NS_LOG_INFO("Lost the last parent of DODAG " << m_dodagId << ", soliciting again");
        LeaveDodag();
        m_disTimer.Cancel();
        m_disTimer.Schedule(Seconds(m_jitter->GetValue(0.0, 1.0)));
        return true;
    }

    NS_LOG_INFO("Preferred parent is " << best << ", rank " << bestRank << " (was "
                                       << m_preferredParent << ", rank " << m_rank << ")");
    m_preferredParent = best;
    m_rank = bestRank;
    return true;
}

Ptr<Ipv6Route>
RplRoutingProtocol::RouteViaPreferredParent(Ipv6Address dst) const
{
    if (m_preferredParent.IsAny())
    {
        return nullptr;
    }

    auto it = m_parents.find(m_preferredParent);
    if (it == m_parents.end())
    {
        return nullptr;
    }

    uint32_t interface = it->second.interface;
    Ptr<Ipv6Route> route = Create<Ipv6Route>();
    route->SetDestination(dst);
    route->SetGateway(m_preferredParent);
    route->SetOutputDevice(m_ipv6->GetNetDevice(interface));
    route->SetSource(m_ipv6->SourceAddressSelection(interface, dst));
    return route;
}

Ptr<Ipv6Route>
RplRoutingProtocol::RouteOutput(Ptr<Packet> p,
                                const Ipv6Header& header,
                                Ptr<NetDevice> oif,
                                Socket::SocketErrno& sockerr)
{
    NS_LOG_FUNCTION(this << p << header << oif);

    Ipv6Address dst = header.GetDestination();
    sockerr = Socket::ERROR_NOTERROR;

    // Pick the interface: the caller's choice wins, otherwise the first
    // interface RPL is running on.
    uint32_t interface = 0;
    if (oif)
    {
        int32_t index = m_ipv6->GetInterfaceForDevice(oif);
        if (index >= 0)
        {
            interface = static_cast<uint32_t>(index);
        }
    }
    else if (!m_ifcToSocket.empty())
    {
        interface = m_ifcToSocket.begin()->first;
    }

    if (interface == 0)
    {
        sockerr = Socket::ERROR_NOROUTETOHOST;
        return nullptr;
    }

    // Link-local and multicast destinations are reached directly.
    if (dst.IsMulticast() || dst.IsLinkLocal())
    {
        Ptr<Ipv6Route> route = Create<Ipv6Route>();
        route->SetDestination(dst);
        route->SetGateway(dst);
        route->SetOutputDevice(m_ipv6->GetNetDevice(interface));
        route->SetSource(m_ipv6->SourceAddressSelection(interface, dst));
        return route;
    }

    // Note that a global destination is never treated as on-link, however well
    // it matches the prefix of one of our own addresses: an LLN shares one
    // prefix across the whole DODAG, most of which is several hops away, which
    // is why RFC 6550 section 6.7.10 has the root advertise the prefix with the
    // on-link flag clear. Everything global therefore goes up the DODAG.
    // Reaching a destination that sits below another node needs the source
    // routing header of RFC 6554, which arrives with the DAO handling.
    Ptr<Ipv6Route> route = RouteViaPreferredParent(dst);
    if (route)
    {
        NS_LOG_LOGIC("Routing " << dst << " via the preferred parent " << m_preferredParent);
        return route;
    }

    NS_LOG_LOGIC("No route to " << dst);
    sockerr = Socket::ERROR_NOROUTETOHOST;
    return nullptr;
}

bool
RplRoutingProtocol::RouteInput(Ptr<const Packet> p,
                               const Ipv6Header& header,
                               Ptr<const NetDevice> idev,
                               const UnicastForwardCallback& ucb,
                               const MulticastForwardCallback& mcb,
                               const LocalDeliverCallback& lcb,
                               const ErrorCallback& ecb)
{
    NS_LOG_FUNCTION(this << p << header << idev);

    // Ipv6L3Protocol::Receive() has already delivered anything addressed to us,
    // so reaching this point means the packet has to be forwarded.
    Ipv6Address dst = header.GetDestination();

    if (dst.IsLinkLocalMulticast())
    {
        // Link-local scope: consumed, never forwarded.
        return true;
    }

    int32_t iif = m_ipv6->GetInterfaceForDevice(idev);
    if (iif < 0 || !m_ipv6->IsForwarding(static_cast<uint32_t>(iif)))
    {
        NS_LOG_LOGIC("Forwarding is disabled on the input interface");
        ecb(p, header, Socket::ERROR_NOROUTETOHOST);
        return false;
    }

    Ptr<Ipv6Route> route = RouteViaPreferredParent(dst);
    if (route)
    {
        NS_LOG_LOGIC("Forwarding " << dst << " via the preferred parent " << m_preferredParent);
        ucb(route->GetOutputDevice(), route, p, header);
        return true;
    }

    NS_LOG_LOGIC("No forwarding route for " << dst);
    ecb(p, header, Socket::ERROR_NOROUTETOHOST);
    return false;
}

void
RplRoutingProtocol::NotifyInterfaceUp(uint32_t interface)
{
    NS_LOG_FUNCTION(this << interface);
    if (IsInitialized())
    {
        StartInterface(interface);
    }
}

void
RplRoutingProtocol::NotifyInterfaceDown(uint32_t interface)
{
    NS_LOG_FUNCTION(this << interface);
    StopInterface(interface);
}

void
RplRoutingProtocol::NotifyAddAddress(uint32_t interface, Ipv6InterfaceAddress address)
{
    NS_LOG_FUNCTION(this << interface << address);
    // A link-local address appearing late is what finally lets StartInterface
    // bind its socket.
    if (IsInitialized() && m_ipv6->IsUp(interface))
    {
        StartInterface(interface);
    }
}

void
RplRoutingProtocol::NotifyRemoveAddress(uint32_t interface, Ipv6InterfaceAddress address)
{
    NS_LOG_FUNCTION(this << interface << address);
}

void
RplRoutingProtocol::NotifyAddRoute(Ipv6Address dst,
                                   Ipv6Prefix mask,
                                   Ipv6Address nextHop,
                                   uint32_t interface,
                                   Ipv6Address prefixToUse)
{
    NS_LOG_FUNCTION(this << dst << mask << nextHop << interface << prefixToUse);
}

void
RplRoutingProtocol::NotifyRemoveRoute(Ipv6Address dst,
                                      Ipv6Prefix mask,
                                      Ipv6Address nextHop,
                                      uint32_t interface,
                                      Ipv6Address prefixToUse)
{
    NS_LOG_FUNCTION(this << dst << mask << nextHop << interface << prefixToUse);
}

void
RplRoutingProtocol::SetAsRoot()
{
    NS_LOG_FUNCTION(this);
    m_isRoot = true;
    m_disTimer.Cancel();
}

bool
RplRoutingProtocol::IsRoot() const
{
    return m_isRoot;
}

bool
RplRoutingProtocol::IsJoined() const
{
    return m_joined;
}

uint16_t
RplRoutingProtocol::GetRank() const
{
    return m_rank;
}

Ipv6Address
RplRoutingProtocol::GetDodagId() const
{
    return m_dodagId;
}

Ipv6Address
RplRoutingProtocol::GetPreferredParent() const
{
    return m_preferredParent;
}

void
RplRoutingProtocol::PrintRoutingTable(Ptr<OutputStreamWrapper> stream, Time::Unit unit) const
{
    std::ostream* os = stream->GetStream();
    std::ios oldState(nullptr);
    oldState.copyfmt(*os);

    *os << "Node: " << m_ipv6->GetObject<Node>()->GetId() << ", Time: " << Now().As(unit)
        << ", RPL routing table" << std::endl;
    *os << "  Role: " << (m_isRoot ? "root" : "router") << std::endl;

    if (!m_joined)
    {
        *os << "  Not part of a DODAG" << std::endl;
        os->copyfmt(oldState);
        return;
    }

    *os << "  DODAG: " << m_dodagId << ", instance " << +m_instanceId << ", version " << +m_version
        << ", rank " << m_rank << std::endl;
    *os << "  Preferred parent: " << m_preferredParent << std::endl;
    *os << "  Candidate parents:" << std::endl;
    for (const auto& [address, parent] : m_parents)
    {
        *os << "    " << address << " rank " << parent.rank << " via interface " << parent.interface
            << ", heard " << +parent.freshness << " times, last "
            << (Now() - parent.lastHeard).As(unit) << " ago" << std::endl;
    }

    os->copyfmt(oldState);
}

int64_t
RplRoutingProtocol::AssignStreams(int64_t stream)
{
    NS_LOG_FUNCTION(this << stream);
    m_jitter->SetStream(stream);
    m_dioTrickle.AssignStreams(stream + 1);
    return 2;
}

} // namespace rpl
} // namespace ns3
