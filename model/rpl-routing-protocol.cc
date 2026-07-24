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
#include "rpl-packet-info-option.h"
#include "rpl-source-routing-extension.h"

#include "ns3/boolean.h"
#include "ns3/icmpv6-header.h"
#include "ns3/icmpv6-l4-protocol.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/ipv6-extension.h"
#include "ns3/ipv6-option-demux.h"
#include "ns3/ipv6-option.h"
#include "ns3/ipv6-raw-socket-factory.h"
#include "ns3/ipv6-route.h"
#include "ns3/log.h"
#include "ns3/net-device.h"
#include "ns3/node.h"
#include "ns3/output-stream-wrapper.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/tag.h"
#include "ns3/uinteger.h"

#include <algorithm>
#include <cmath>
#include <limits>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("RplRoutingProtocol");

namespace rpl
{

namespace
{

/**
 * @brief Stand-in for the wire format ns3::lrwpan::LrWpanLqiTag and
 *        ns3::lrwpan::LrWpanRssiTag share: a single byte payload (an
 *        unsigned LQI or a signed RSSI in dBm, the caller knows which).
 *
 * Used only to decode the byte of a tag added by the real lr-wpan tag,
 * matched by its globally registered TypeId name (see LinkEtxFromPacket()
 * and LinkLqlFromPacket()): PacketTagIterator::Item::GetTag() only checks
 * that GetInstanceTypeId() matches, so this reads the tag's payload without
 * librpl ever #include-ing, or linking against, the lr-wpan module.
 */
class LrWpanPeekByteTag : public Tag
{
  public:
    /**
     * @param tid the real tag's TypeId, looked up by name
     */
    explicit LrWpanPeekByteTag(TypeId tid)
        : m_tid(tid)
    {
    }

    TypeId GetInstanceTypeId() const override
    {
        return m_tid;
    }

    uint32_t GetSerializedSize() const override
    {
        return 1;
    }

    void Serialize(TagBuffer i) const override
    {
        i.WriteU8(m_byte);
    }

    void Deserialize(TagBuffer i) override
    {
        m_byte = i.ReadU8();
    }

    void Print(std::ostream& os) const override
    {
        os << "Byte=" << +m_byte;
    }

    uint8_t m_byte{0}; //!< the decoded payload byte

  private:
    TypeId m_tid; //!< the real tag's TypeId
};

/**
 * @brief The built-in RSSI -> LQL mapping, used until
 *        RplRoutingProtocol::SetRssiToLqlMapping() replaces it.
 *
 * RFC 6551 section 4.6 leaves the computation "implementation specific", so
 * this is a deliberately coarse threshold table, not calibrated against any
 * particular radio, spaced over the receive range of a low-power LLN radio
 * rather than a stronger-signal one (Wi-Fi, cellular): 802.15.4's O-QPZK PHY
 * is usable down to roughly -106 dBm (see the sensitivity figure
 * src/lr-wpan/examples/lr-wpan-per-plot.cc derives its own noise floor from),
 * so this table's worst determined bucket starts well above that, not at a
 * generic "weak signal" threshold that would never actually trigger on this
 * kind of link. 1 is the best determined quality, 7 the worst; 0
 * (undetermined) is never returned here since an actual RSSI reading is, by
 * definition, determined.
 *
 * @param rssiDbm the received signal strength, in dBm
 * @return the LQL, 1 (best) to 7 (worst)
 */
uint8_t
DefaultRssiToLql(double rssiDbm)
{
    static const double thresholds[] = {-75.0, -82.0, -89.0, -96.0, -100.0, -103.0};
    for (uint8_t lql = 1; lql <= 6; lql++)
    {
        if (rssiDbm >= thresholds[lql - 1])
        {
            return lql;
        }
    }
    return RPL_LQL_WORST;
}

} // namespace

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
                          MakeUintegerChecker<uint16_t>(1, RPL_INFINITE_RANK))
            .AddAttribute("Ocp",
                          "Objective Code Point advertised by the root: RPL_OCP_OF0 (RFC "
                          "6552, hop count) or RPL_OCP_MRHOF (RFC 6719, minimum rank with "
                          "hysteresis over the ETX metric). Every other node adopts whatever "
                          "OCP the DIO it joins on advertises, ignoring this attribute.",
                          UintegerValue(RPL_OCP_OF0),
                          MakeUintegerAccessor(&RplRoutingProtocol::m_ocp),
                          MakeUintegerChecker<uint16_t>())
            .AddAttribute("EnableLql",
                          "Whether to derive a Link Quality Level (RFC 6551 section 4.6) "
                          "from RSSI and advertise it in DIOs, alongside whatever OCP is "
                          "running -- LQL is a recorded-only metric (RFC 6551 section 3.4), "
                          "not something an Objective Function computes a rank from. Off by "
                          "default to keep the wire format unchanged unless asked for.",
                          BooleanValue(false),
                          MakeBooleanAccessor(&RplRoutingProtocol::m_enableLql),
                          MakeBooleanChecker())
            .AddAttribute("DaoInterval",
                          "How often a node repeats the DAO that tells the root where it sits. "
                          "It has to stay well below PathLifetime times the lifetime unit, "
                          "otherwise the root lets the entry expire between two DAOs.",
                          TimeValue(Seconds(60)),
                          MakeTimeAccessor(&RplRoutingProtocol::m_daoInterval),
                          MakeTimeChecker())
            .AddAttribute("DaoAckTimeout",
                          "How long a node waits for a DAO-ACK before resending the DAO.",
                          TimeValue(Seconds(5)),
                          MakeTimeAccessor(&RplRoutingProtocol::m_daoAckTimeout),
                          MakeTimeChecker())
            .AddAttribute("DaoRetries",
                          "How many times an unacknowledged DAO is resent.",
                          UintegerValue(3),
                          MakeUintegerAccessor(&RplRoutingProtocol::m_daoRetries),
                          MakeUintegerChecker<uint8_t>())
            .AddAttribute("PathLifetime",
                          "Lifetime of the downward route a node advertises, in lifetime units.",
                          UintegerValue(RPL_DEFAULT_LIFETIME),
                          MakeUintegerAccessor(&RplRoutingProtocol::m_pathLifetime),
                          MakeUintegerChecker<uint8_t>(1, RPL_INFINITE_LIFETIME))
            .AddAttribute("RootPrefix",
                          "The DODAG root's own GUA or ULA prefix, disseminated to every other "
                          "node via the DIO Prefix Information option (RFC 6550 section 6.7.10) "
                          "for SLAAC (RFC 4862). Root only; ignored on every other node, which "
                          "gets the prefix from the DIO it joins on instead. Required on the "
                          "root -- SetAsRoot() asserts it is set.",
                          Ipv6AddressValue(Ipv6Address::GetAny()),
                          MakeIpv6AddressAccessor(&RplRoutingProtocol::m_rootPrefix),
                          MakeIpv6AddressChecker())
            .AddAttribute("RootPrefixLength",
                          "Prefix length, in bits, of RootPrefix.",
                          UintegerValue(64),
                          MakeUintegerAccessor(&RplRoutingProtocol::m_rootPrefixLength),
                          MakeUintegerChecker<uint8_t>(1, 128));
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
      m_pathEtx(0),
      m_enableLql(false),
      m_rssiToLql(MakeCallback(&DefaultRssiToLql)),
      m_minHopRankIncrease(RPL_MIN_HOPRANKINC),
      m_maxRankIncrease(RPL_MAX_RANKINC),
      m_dioIntervalMin(MilliSeconds(1 << RPL_DIO_INTERVAL_MIN)),
      m_dioIntervalDoublings(RPL_DIO_INTERVAL_DOUBLINGS),
      m_dioRedundancy(RPL_DIO_REDUNDANCY),
      m_hasPrefixInfo(false),
      m_prefix(Ipv6Address::GetAny()),
      m_prefixLength(0),
      m_prefixOnLink(false),
      m_prefixAutonomous(false),
      m_prefixValidLifetime(0),
      m_prefixPreferredLifetime(0),
      m_preferredParent(Ipv6Address::GetAny()),
      m_daoInterval(Seconds(60)),
      m_daoAckTimeout(Seconds(5)),
      m_daoRetries(3),
      m_pathLifetime(RPL_DEFAULT_LIFETIME),
      m_lifetimeUnit(RPL_DEFAULT_LIFETIME_UNIT),
      m_daoSequence(0),
      m_pathSequence(0),
      m_daoRetriesLeft(0),
      m_daoAckPending(false),
      m_daoEvent(Timer::CANCEL_ON_DESTROY),
      m_daoRetryEvent(Timer::CANCEL_ON_DESTROY),
      m_rootPrefix(Ipv6Address::GetAny()),
      m_rootPrefixLength(64)
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

    // Every node can end up relaying a source routed packet, not just the
    // root that originates one, since RFC 6554 processing is triggered by the
    // packet being addressed to whichever node currently holds it.
    Ptr<Ipv6ExtensionRoutingDemux> routingExtensionDemux =
        m_ipv6->GetObject<Ipv6ExtensionRoutingDemux>();
    NS_ASSERT_MSG(routingExtensionDemux,
                  "RPL requires Ipv6L3Protocol::RegisterExtensions() to have run, which "
                  "InternetStackHelper does automatically");
    if (!routingExtensionDemux->GetExtensionRouting(RplIpv6ExtensionSourceRouting::TYPE_ROUTING))
    {
        Ptr<RplIpv6ExtensionSourceRouting> sourceRoutingExtension =
            CreateObject<RplIpv6ExtensionSourceRouting>();
        sourceRoutingExtension->SetNode(m_ipv6->GetObject<Node>());
        routingExtensionDemux->Insert(sourceRoutingExtension);
    }

    // Likewise, every node needs to check and update the RPL Option (RFC
    // 6553) of every data packet it is on the path of, not just the ones it
    // originates or is the final destination of: an option carried in a
    // Hop-by-Hop header, unlike a Routing Header, is examined at every hop.
    Ptr<Ipv6OptionDemux> optionDemux = m_ipv6->GetObject<Ipv6OptionDemux>();
    NS_ASSERT_MSG(optionDemux,
                  "RPL requires Ipv6L3Protocol::RegisterOptions() to have run, which "
                  "InternetStackHelper does automatically");
    if (!optionDemux->GetOption(RPL_HBH_OPTION_TYPE))
    {
        Ptr<RplIpv6OptionRpl> packetInfoOption = CreateObject<RplIpv6OptionRpl>();
        packetInfoOption->SetNode(m_ipv6->GetObject<Node>());
        optionDemux->Insert(packetInfoOption);
    }

    // The only way, short of polling, to learn that a SLAAC address has
    // cleared Duplicate Address Detection and stopped being TENTATIVE (RFC
    // 4862): connected once here, for every node, since it drives both the
    // root's own address (below) and every other node's (JoinDodag()).
    m_ipv6->GetIcmpv6()->TraceConnectWithoutContext(
        "DadSuccess",
        MakeCallback(&RplRoutingProtocol::HandleDadSuccess, this));

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
        // DODAGID is one of its own global addresses. Unlike every other
        // node, the root is not handed a prefix by a DIO -- it owns one
        // (RootPrefix) and builds its own address from it the same way SLAAC
        // would (Ipv6Address::MakeAutoconfiguredAddress(), the same
        // derivation Ipv6L3Protocol::AddAutoconfiguredAddress() uses), so a
        // node's global address always follows the same "prefix + this
        // interface's identifier" rule regardless of who assigned it.
        // AddAddress() triggers DAD asynchronously (Ipv6Interface::
        // AddAddress()), so the DODAG is not actually started here --
        // HandleDadSuccess() does that once the address is confirmed unique.
        NS_ASSERT_MSG(!m_rootPrefix.IsAny(), "The DODAG root needs its RootPrefix attribute set");
        Address macAddress = m_ipv6->GetNetDevice(1)->GetAddress();
        Ipv6Address candidate = Ipv6Address::MakeAutoconfiguredAddress(macAddress, m_rootPrefix);
        Ipv6InterfaceAddress rootAddress(candidate, Ipv6Prefix(m_rootPrefixLength));
        rootAddress.SetScope(Ipv6InterfaceAddress::GLOBAL);
        m_ipv6->AddAddress(1, rootAddress);
        NS_LOG_INFO("Root building its own address " << candidate << " from RootPrefix "
                                                      << m_rootPrefix);
    }
    else
    {
        m_disTimer.SetFunction(&RplRoutingProtocol::DisTimerExpire, this);
        m_daoEvent.SetFunction(&RplRoutingProtocol::DaoTimerExpire, this);
        m_daoRetryEvent.SetFunction(&RplRoutingProtocol::DaoRetry, this);
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
    m_daoEvent.Cancel();
    m_daoRetryEvent.Cancel();
    for (auto& [socket, interface] : m_socketToIfc)
    {
        socket->Close();
    }
    m_socketToIfc.clear();
    m_ifcToSocket.clear();
    m_parents.clear();
    m_topology.clear();
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
            // TENTATIVE means Duplicate Address Detection has not finished
            // yet (RFC 4862): the address is not actually usable, so callers
            // that trust this getter (SendDao(), the root's own DoInitialize())
            // must not be handed one still in flight.
            if (iaddr.GetScope() == Ipv6InterfaceAddress::GLOBAL &&
                iaddr.GetState() != Ipv6InterfaceAddress::TENTATIVE)
            {
                return iaddr.GetAddress();
            }
        }
    }
    return Ipv6Address::GetAny();
}

void
RplRoutingProtocol::HandleDadSuccess(const Ipv6Address& address)
{
    NS_LOG_FUNCTION(this << address);

    if (address.IsLinkLocal())
    {
        // Every interface goes through DAD once for its link-local address
        // regardless of RootPrefix/the DIO's Prefix Information option; not
        // interesting here.
        return;
    }

    if (m_isRoot)
    {
        if (m_joined)
        {
            // The DODAG is already running: a later re-run of DAD (e.g. on a
            // route flap) must not restart it.
            return;
        }

        // RFC 6550, section 8.2.2.2: the root is at MinHopRankIncrease and
        // the DODAGID is one of its own global addresses. This fires once
        // DAD has actually confirmed the address DoInitialize() asked for is
        // unique, which is what starting the DODAG on an address that might
        // still get pulled out from under it would risk.
        m_dodagId = address;
        m_joined = true;
        m_grounded = true;
        m_rank = m_minHopRankIncrease;

        // Every DIO this root sends carries the Prefix Information option
        // (RFC 6550 section 6.7.10) so every other node can SLAAC an address
        // on RootPrefix (see SendDio(), JoinDodag()).
        m_hasPrefixInfo = true;
        m_prefix = m_rootPrefix;
        m_prefixLength = m_rootPrefixLength;
        m_prefixOnLink = true;
        m_prefixAutonomous = true;
        m_prefixValidLifetime = RPL_PREFIX_VALID_LIFETIME;
        m_prefixPreferredLifetime = RPL_PREFIX_PREFERRED_LIFETIME;

        m_dioTrickle.Start();
        NS_LOG_INFO("Root of DODAG " << m_dodagId << " at rank " << m_rank);
        return;
    }

    // Non-root: nothing to do. AddAutoconfiguredAddress() (JoinDodag())
    // inserts the address with State_e::TENTATIVE_OPTIMISTIC (RFC 4429),
    // which GetGlobalAddress() already treats as usable -- this node did not
    // need to wait for this trace to fire before advertising or sending a
    // DAO on it.
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
        uint16_t linkEtx = LinkEtxFromPacket(packet);
        uint8_t lql = LinkLqlFromPacket(packet);
        double linkEtxValue = double(linkEtx) / RPL_ETX_FIXED_POINT;
        NS_LOG_INFO("Received a DIO from " << from << " on interface " << interface << " (link ETX "
                                           << linkEtxValue << ", LQL " << +lql << "): " << dio);
        HandleDio(dio, from, interface, linkEtx, lql);
        break;
    }
    case RPL_CODE_DAO: {
        RplDaoHeader dao;
        packet->RemoveHeader(dao);
        NS_LOG_INFO("Received a DAO from " << from << ": " << dao);
        HandleDao(dao, from);
        break;
    }
    case RPL_CODE_DAO_ACK: {
        RplDaoAckHeader daoAck;
        packet->RemoveHeader(daoAck);
        NS_LOG_INFO("Received a DAO-ACK from " << from << ": " << daoAck);
        HandleDaoAck(daoAck, from);
        break;
    }
    default:
        NS_LOG_WARN("Unsupported RPL message code " << +icmpv6Header.GetCode() << " from " << from);
        break;
    }
}

void
RplRoutingProtocol::SendRplMessageMulticast(Ptr<Packet> packet, uint8_t code, Ipv6Address dst)
{
    NS_LOG_FUNCTION(this << packet << +code << dst);

    for (auto& [interface, socket] : m_ifcToSocket)
    {
        SendRplMessageOn(interface, packet->Copy(), code, dst);
    }
}

void
RplRoutingProtocol::SendRplMessageUnicast(Ptr<Packet> packet, uint8_t code, Ipv6Address dst)
{
    NS_LOG_FUNCTION(this << packet << +code << dst);

    if (m_ifcToSocket.empty())
    {
        NS_LOG_WARN("No RPL interface is up, dropping code " << +code << " to " << dst);
        return;
    }

    SendRplMessageOn(m_ifcToSocket.begin()->first, packet, code, dst);
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

    // A DAO travels several hops to the root, so its source has to be the
    // global address rather than the link-local one used on the link-local
    // messages. Ipv6RawSocketImpl::SendTo() sends with the source of the route
    // that RouteOutput() hands back, so asking for the same selection here is
    // what keeps the checksum in step with the address that ends up in the
    // IPv6 header.
    Ipv6Address src = m_ipv6->SourceAddressSelection(interface, dst);

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
    SendRplMessageMulticast(packet, RPL_CODE_DIS, dst);
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

    if (m_ocp == RPL_OCP_MRHOF)
    {
        // RFC 6551 section 4.3, additive aggregation: the root originates the
        // DODAG at path ETX 0, every other node advertises the path cost it
        // computed picking its own preferred parent.
        dio.SetMetricContainer(m_isRoot ? 0 : m_pathEtx);
    }

    if (m_enableLql)
    {
        // LQL is recorded, not aggregated: what is advertised is this node's
        // own link to its preferred parent, not a path-wide value. The root
        // has no upstream link of its own to report.
        auto preferred = m_parents.find(m_preferredParent);
        dio.SetLql(preferred != m_parents.end() ? preferred->second.lql : RPL_LQL_UNDETERMINED);
    }

    if (m_hasPrefixInfo)
    {
        // Carried by every DIO, not just the root's, the same reason as the
        // DODAG Configuration option above: a node joining deep in the
        // DODAG still needs to learn the prefix to SLAAC an address on.
        dio.SetPrefixInfo(m_prefix,
                          m_prefixLength,
                          m_prefixOnLink,
                          m_prefixAutonomous,
                          m_prefixValidLifetime,
                          m_prefixPreferredLifetime);
    }

    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(dio);

    if (interface == 0)
    {
        SendRplMessageMulticast(packet, RPL_CODE_DIO, dst);
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
RplRoutingProtocol::HandleDio(const RplDioHeader& dio,
                              Ipv6Address from,
                              uint32_t interface,
                              uint16_t linkEtx,
                              uint8_t lql)
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
        JoinDodag(dio, interface);
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
            JoinDodag(dio, interface);
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
    UpdateLinkEtx(parent, linkEtx);
    parent.lql = lql;
    if (dio.HasMetricContainer())
    {
        parent.pathEtx = dio.GetPathEtx();
    }

    m_dioTrickle.ConsistencyHit();

    if (SelectPreferredParent())
    {
        m_dioTrickle.Reset();
    }
}

void
RplRoutingProtocol::JoinDodag(const RplDioHeader& dio, uint32_t interface)
{
    NS_LOG_FUNCTION(this << interface);

    m_joined = true;
    m_instanceId = dio.GetInstanceId();
    m_dodagId = dio.GetDodagId();
    m_version = dio.GetVersionNumber();
    m_mop = dio.GetMop();
    m_grounded = dio.GetGrounded();
    m_preference = dio.GetPreference();
    m_rank = RPL_INFINITE_RANK; // until a parent is picked
    m_pathEtx = 0;

    if (dio.HasDagConfiguration())
    {
        m_ocp = dio.GetOcp();
        m_minHopRankIncrease = dio.GetMinHopRankIncrease();
        m_maxRankIncrease = dio.GetMaxRankIncrease();
        m_dioIntervalMin = MilliSeconds(int64_t(1) << dio.GetIntervalMin());
        m_dioIntervalDoublings = dio.GetIntervalDoublings();
        m_dioRedundancy = dio.GetRedundancy();

        if (m_ocp != RPL_OCP_OF0 && m_ocp != RPL_OCP_MRHOF)
        {
            NS_LOG_WARN("DODAG " << m_dodagId << " asks for objective code point " << m_ocp
                                 << ", but only OF0 and MRHOF are implemented");
        }
    }

    if (dio.HasPrefixInfo())
    {
        m_hasPrefixInfo = true;
        m_prefix = dio.GetPrefix();
        m_prefixLength = dio.GetPrefixLength();
        m_prefixOnLink = dio.GetPrefixOnLink();
        m_prefixAutonomous = dio.GetPrefixAutonomous();
        m_prefixValidLifetime = dio.GetPrefixValidLifetime();
        m_prefixPreferredLifetime = dio.GetPrefixPreferredLifetime();

        if (m_prefixAutonomous)
        {
            // The standard SLAAC entry point (RFC 4862): builds the address
            // the same way GlobalAddressOf()/LinkLocalOf() already assume
            // every node's addresses are related (one interface identifier,
            // shared with the link-local address) and starts Duplicate
            // Address Detection on it asynchronously --
            // HandleDadSuccess() is what learns it is ready to use.
            uint8_t flags = (m_prefixOnLink ? Icmpv6OptionPrefixInformation::ONLINK : 0) |
                            Icmpv6OptionPrefixInformation::AUTADDRCONF;
            m_ipv6->AddAutoconfiguredAddress(interface,
                                             m_prefix,
                                             Ipv6Prefix(m_prefixLength),
                                             flags,
                                             m_prefixValidLifetime,
                                             m_prefixPreferredLifetime);
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
    m_pathEtx = 0;
    m_preferredParent = Ipv6Address::GetAny();
    m_parents.clear();
    m_dioTrickle.Stop();
    m_daoEvent.Cancel();
    m_daoRetryEvent.Cancel();
    m_daoAckPending = false;
}

Ipv6Address
RplRoutingProtocol::GlobalAddressOf(Ipv6Address linkLocal) const
{
    if (m_dodagId.IsAny() || linkLocal.IsAny())
    {
        return Ipv6Address::GetAny();
    }

    uint8_t prefix[16];
    uint8_t identifier[16];
    m_dodagId.GetBytes(prefix);
    linkLocal.GetBytes(identifier);

    uint8_t global[16];
    std::copy(prefix, prefix + 8, global);
    std::copy(identifier + 8, identifier + 16, global + 8);
    return Ipv6Address(global);
}

Ipv6Address
RplRoutingProtocol::LinkLocalOf(Ipv6Address global) const
{
    static const uint8_t linkLocalPrefix[8] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0};

    uint8_t identifier[16];
    global.GetBytes(identifier);

    uint8_t linkLocal[16];
    std::copy(linkLocalPrefix, linkLocalPrefix + 8, linkLocal);
    std::copy(identifier + 8, identifier + 16, linkLocal + 8);
    return Ipv6Address(linkLocal);
}

void
RplRoutingProtocol::SendDao()
{
    NS_LOG_FUNCTION(this);

    if (!m_joined || m_isRoot || m_preferredParent.IsAny())
    {
        return;
    }

    Ipv6Address target = GetGlobalAddress();
    Ipv6Address parent = GlobalAddressOf(m_preferredParent);
    if (target.IsAny() || parent.IsAny())
    {
        NS_LOG_LOGIC("Not advertising yet: no global address for this node or its parent");
        return;
    }

    RplDaoHeader dao;
    dao.SetInstanceId(m_instanceId);
    dao.SetDodagId(m_dodagId);
    dao.SetSequence(++m_daoSequence);
    dao.SetAckRequested(true);
    dao.SetTarget(target);
    dao.SetTransitInformation(parent, m_pathSequence, m_pathLifetime);

    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(dao);

    // The DAO is addressed to the root and finds its way there hop by hop, on
    // the upward routes the DIOs built.
    SendRplMessageUnicast(packet, RPL_CODE_DAO, m_dodagId);

    m_daoAckPending = true;
    m_daoRetriesLeft = m_daoRetries;
    m_daoRetryEvent.Cancel();
    m_daoRetryEvent.Schedule(m_daoAckTimeout);
}

void
RplRoutingProtocol::DaoTimerExpire()
{
    NS_LOG_FUNCTION(this);

    SendDao();
    m_daoEvent.Cancel();
    m_daoEvent.Schedule(m_daoInterval);
}

void
RplRoutingProtocol::DaoRetry()
{
    NS_LOG_FUNCTION(this << +m_daoRetriesLeft);

    if (!m_daoAckPending)
    {
        return;
    }

    if (m_daoRetriesLeft == 0)
    {
        // The path is not getting through. The next periodic DAO will try
        // again, by then possibly through a different parent.
        NS_LOG_WARN("No DAO-ACK for sequence " << +m_daoSequence << ", giving up until the "
                                                                    "next refresh");
        m_daoAckPending = false;
        return;
    }

    m_daoRetriesLeft--;

    RplDaoHeader dao;
    dao.SetInstanceId(m_instanceId);
    dao.SetDodagId(m_dodagId);
    dao.SetSequence(m_daoSequence);
    dao.SetAckRequested(true);
    dao.SetTarget(GetGlobalAddress());
    dao.SetTransitInformation(GlobalAddressOf(m_preferredParent), m_pathSequence, m_pathLifetime);

    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(dao);
    SendRplMessageUnicast(packet, RPL_CODE_DAO, m_dodagId);

    m_daoRetryEvent.Cancel();
    m_daoRetryEvent.Schedule(m_daoAckTimeout);
}

void
RplRoutingProtocol::HandleDao(const RplDaoHeader& dao, Ipv6Address from)
{
    NS_LOG_FUNCTION(this << from);

    if (!m_isRoot)
    {
        // In non-storing mode a DAO is addressed to the root, so a node that
        // is not the root only ever forwards one. Getting here means the
        // sender is confused about who the root is.
        NS_LOG_WARN("Ignoring a DAO from " << from << ": this node is not the root");
        return;
    }

    if (dao.GetInstanceId() != m_instanceId ||
        (!dao.GetDodagId().IsAny() && dao.GetDodagId() != m_dodagId))
    {
        NS_LOG_LOGIC("Ignoring a DAO for another DODAG");
        return;
    }

    Ipv6Address target = dao.GetTarget();
    if (target.IsAny())
    {
        NS_LOG_WARN("Ignoring a DAO from " << from << " with no target");
        return;
    }

    if (dao.GetPathLifetime() == 0)
    {
        // A No-Path, RFC 6550 section 6.4.3: the target has moved away.
        NS_LOG_INFO("No-Path for " << target << ", dropping it from the topology");
        m_topology.erase(target);
    }
    else
    {
        // The path sequence is stored but, like the DODAG version number in
        // HandleDio(), never compared: this always accepts the latest DAO
        // that arrived rather than the one with the highest (lollipop, RFC
        // 6550 section 7.2) sequence, so a DAO reordered by the network could
        // overwrite a newer entry with a stale one until the next DAO sets it
        // straight again.
        TopologyEntry& entry = m_topology[target];
        entry.parent = dao.GetParent();
        entry.pathSequence = dao.GetPathSequence();
        entry.expire = Simulator::Now() + Seconds(dao.GetPathLifetime() * m_lifetimeUnit);
        NS_LOG_INFO("Topology: " << target << " sits under " << entry.parent);
    }

    if (dao.GetAckRequested())
    {
        RplDaoAckHeader daoAck;
        daoAck.SetInstanceId(m_instanceId);
        daoAck.SetDodagId(m_dodagId);
        daoAck.SetSequence(dao.GetSequence());
        daoAck.SetStatus(0); // unqualified acceptance

        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(daoAck);
        // The acknowledgement travels back down, which the root can do now
        // that it has just learnt where the sender sits.
        SendRplMessageUnicast(packet, RPL_CODE_DAO_ACK, from);
    }
}

void
RplRoutingProtocol::HandleDaoAck(const RplDaoAckHeader& daoAck, Ipv6Address from)
{
    NS_LOG_FUNCTION(this << from);

    if (daoAck.GetSequence() != m_daoSequence)
    {
        NS_LOG_LOGIC("Ignoring a DAO-ACK for sequence " << +daoAck.GetSequence() << ", waiting "
                                                        << "for " << +m_daoSequence);
        return;
    }

    if (daoAck.GetStatus() != 0)
    {
        NS_LOG_WARN("The root rejected the DAO with status " << +daoAck.GetStatus());
        return;
    }

    NS_LOG_INFO("The root acknowledged DAO " << +m_daoSequence);
    m_daoAckPending = false;
    m_daoRetryEvent.Cancel();
}

void
RplRoutingProtocol::PurgeTopology()
{
    Time now = Simulator::Now();
    for (auto it = m_topology.begin(); it != m_topology.end();)
    {
        it = (it->second.expire <= now) ? m_topology.erase(it) : std::next(it);
    }
}

bool
RplRoutingProtocol::ComputeSourceRoute(Ipv6Address destination,
                                       std::vector<Ipv6Address>& hops) const
{
    hops.clear();

    if (!m_isRoot || m_topology.find(destination) == m_topology.end())
    {
        return false;
    }

    Time now = Simulator::Now();
    Ipv6Address current = destination;
    std::vector<Ipv6Address> globalChain; // destination first, root's direct child last

    // Walk up the parents until the root is reached, collecting the routers in
    // between, destination included. The loop cannot run longer than the
    // topology is wide, which is what keeps a cycle in the reported parents
    // from hanging the simulation.
    for (size_t step = 0; step <= m_topology.size(); step++)
    {
        auto it = m_topology.find(current);
        if (it == m_topology.end() || it->second.expire <= now)
        {
            return false;
        }

        globalChain.push_back(current);
        current = it->second.parent;
        if (current == m_dodagId)
        {
            std::reverse(globalChain.begin(), globalChain.end());
            for (const auto& global : globalChain)
            {
                hops.push_back(LinkLocalOf(global));
            }
            return true;
        }
    }

    NS_LOG_WARN("The reported parents of " << destination << " do not lead to the root");
    hops.clear();
    return false;
}

uint32_t
RplRoutingProtocol::InterfaceForNeighbour(Ipv6Address neighbour) const
{
    // A neighbour is known by its link-local address, so it is the interface
    // identifier that tells which of them the global address belongs to.
    uint8_t wanted[16];
    neighbour.GetBytes(wanted);

    for (const auto& [address, parent] : m_parents)
    {
        uint8_t candidate[16];
        address.GetBytes(candidate);
        if (std::equal(wanted + 8, wanted + 16, candidate + 8))
        {
            return parent.interface;
        }
    }

    // Nothing was ever heard from that neighbour. On a node with a single RPL
    // interface there is only one answer anyway.
    return m_ifcToSocket.empty() ? 0 : m_ifcToSocket.begin()->first;
}

Ptr<Ipv6Route>
RplRoutingProtocol::RouteToNeighbour(Ipv6Address neighbour, Ipv6Address dst) const
{
    uint32_t interface = InterfaceForNeighbour(neighbour);
    if (interface == 0)
    {
        return nullptr;
    }

    Ptr<Ipv6Route> route = Create<Ipv6Route>();
    route->SetDestination(dst);
    // The gateway is what Ipv6Interface::Send() resolves over Neighbour
    // Discovery and hands to the link layer; only a link-local address is
    // guaranteed to resolve over one radio hop the way every other neighbour
    // lookup in this class expects. neighbour is dst's own global address
    // when this is the final hop of a source route
    // (RplIpv6ExtensionSourceRouting::Process()), so it is converted here
    // rather than at that call site: NDP resolution failing (or, worse,
    // Ipv6Interface::Send() treating a global destination that is not this
    // node's own as if it were, since neither check is scoped to "one radio
    // hop away") is exactly the kind of failure RouteOutput()'s own comment
    // warns a global address invites in this LLN.
    route->SetGateway(neighbour.IsLinkLocal() ? neighbour : LinkLocalOf(neighbour));
    route->SetOutputDevice(m_ipv6->GetNetDevice(interface));
    route->SetSource(m_ipv6->SourceAddressSelection(interface, dst));
    return route;
}

uint32_t
RplRoutingProtocol::GetTopologySize() const
{
    return m_topology.size();
}

uint16_t
RplRoutingProtocol::RankViaParent(const Parent& parent, uint32_t* pathCost) const
{
    if (parent.rank == RPL_INFINITE_RANK)
    {
        return RPL_INFINITE_RANK;
    }

    uint32_t rank = static_cast<uint32_t>(parent.rank) + m_minHopRankIncrease;
    if (m_ocp == RPL_OCP_MRHOF)
    {
        // RFC 6719 section 3.3: the path cost through the parent, unless
        // that undercuts the parent's own rank plus MinHopRankIncrease, in
        // which case the rank must not claim a shorter path than the hop
        // count actually taken.
        uint32_t cost = PathCostViaParent(parent);
        if (pathCost)
        {
            *pathCost = cost;
        }
        rank = std::max(rank, cost);
    }
    return rank >= RPL_INFINITE_RANK ? RPL_INFINITE_RANK : static_cast<uint16_t>(rank);
}

uint32_t
RplRoutingProtocol::PathCostViaParent(const Parent& parent) const
{
    return static_cast<uint32_t>(parent.pathEtx) + parent.etx;
}

void
RplRoutingProtocol::UpdateLinkEtx(Parent& parent, uint16_t sample) const
{
    parent.etx = (parent.freshness <= 1) ? sample
                                         : static_cast<uint16_t>(parent.etx - (parent.etx >> 3) +
                                                                 (sample >> 3));
}

uint16_t
RplRoutingProtocol::LinkEtxFromPacket(Ptr<const Packet> packet) const
{
    TypeId lqiTid;
    if (!TypeId::LookupByNameFailSafe("ns3::lrwpan::LrWpanLqiTag", &lqiTid))
    {
        NS_LOG_LOGIC("ns3::lrwpan::LrWpanLqiTag is not registered (lr-wpan not linked in, or "
                     "renamed); link ETX falls back to the neutral default");
        return RPL_ETX_FIXED_POINT;
    }

    PacketTagIterator it = packet->GetPacketTagIterator();
    while (it.HasNext())
    {
        PacketTagIterator::Item item = it.Next();
        if (item.GetTypeId() != lqiTid)
        {
            continue;
        }

        LrWpanPeekByteTag tag(lqiTid);
        item.GetTag(tag);
        if (tag.m_byte == 0)
        {
            // No successful reception at all: as bad a link as this fixed
            // point scale can express.
            return RPL_MRHOF_MAX_LINK_METRIC;
        }

        // The LQI is the packet success rate scaled to 0-255 (LrWpanLqiTag's
        // own doc comment), so 255 / lqi approximates ETX = 1 / PRR.
        uint32_t instantEtx = (255u * RPL_ETX_FIXED_POINT) / tag.m_byte;
        return static_cast<uint16_t>(std::min<uint32_t>(instantEtx, RPL_MRHOF_MAX_LINK_METRIC));
    }
    return RPL_ETX_FIXED_POINT;
}

void
RplRoutingProtocol::SetRssiToLqlMapping(Callback<uint8_t, double> mapping)
{
    NS_LOG_FUNCTION(this);
    m_rssiToLql = mapping;
}

uint8_t
RplRoutingProtocol::RssiToLql(double rssiDbm) const
{
    if (m_rssiToLql.IsNull())
    {
        return RPL_LQL_UNDETERMINED;
    }
    // A user-supplied mapping (SetRssiToLqlMapping()) is free-form and not
    // guaranteed to respect RFC 6551's 0-7 range, so clamp here rather than
    // relying on every caller (and RplDioHeader::SetLql()) to do it.
    return std::min(m_rssiToLql(rssiDbm), RPL_LQL_WORST);
}

uint8_t
RplRoutingProtocol::LinkLqlFromPacket(Ptr<const Packet> packet) const
{
    TypeId rssiTid;
    if (!TypeId::LookupByNameFailSafe("ns3::lrwpan::LrWpanRssiTag", &rssiTid))
    {
        NS_LOG_LOGIC("ns3::lrwpan::LrWpanRssiTag is not registered (lr-wpan not linked in, or "
                     "renamed); LQL falls back to undetermined");
        return RPL_LQL_UNDETERMINED;
    }

    PacketTagIterator it = packet->GetPacketTagIterator();
    while (it.HasNext())
    {
        PacketTagIterator::Item item = it.Next();
        if (item.GetTypeId() != rssiTid)
        {
            continue;
        }

        LrWpanPeekByteTag tag(rssiTid);
        item.GetTag(tag);
        return RssiToLql(double(static_cast<int8_t>(tag.m_byte)));
    }
    return RPL_LQL_UNDETERMINED;
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
    uint32_t bestPathCost = std::numeric_limits<uint32_t>::max();

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

        if (m_ocp == RPL_OCP_MRHOF && parent.etx >= RPL_MRHOF_MAX_LINK_METRIC)
        {
            // RFC 6719 section 3.2: a link this bad is not even considered.
            NS_LOG_LOGIC("Neighbour " << address << " has too high a link ETX");
            continue;
        }

        uint32_t pathCost = 0;
        uint16_t rank = RankViaParent(parent, &pathCost);
        if (rank == RPL_INFINITE_RANK)
        {
            continue;
        }

        if (m_ocp == RPL_OCP_MRHOF)
        {
            if (pathCost >= RPL_MRHOF_MAX_PATH_COST)
            {
                NS_LOG_LOGIC("Neighbour " << address << " has too high a path cost");
                continue;
            }
            // Ties are broken on the address so that the choice is deterministic.
            if (best.IsAny() || pathCost < bestPathCost ||
                (pathCost == bestPathCost && address < best))
            {
                best = address;
                bestRank = rank;
                bestPathCost = pathCost;
            }
        }
        else if (best.IsAny() || rank < bestRank || (rank == bestRank && address < best))
        {
            best = address;
            bestRank = rank;
        }
    }

    if (m_ocp == RPL_OCP_MRHOF && !best.IsAny())
    {
        // RFC 6719 section 3.3: hysteresis. Keep the current preferred
        // parent over a candidate of lower path cost unless the difference
        // exceeds PARENT_SWITCH_THRESHOLD, so the node does not flap between
        // parents of near-identical quality. The current parent still has
        // to clear the same freshness and loop-avoidance filters applied to
        // every other candidate above; otherwise hysteresis could keep a
        // stale or newly-looped parent selected indefinitely.
        auto current = m_parents.find(m_preferredParent);
        if (current != m_parents.end() &&
            (!haveFresh || current->second.freshness >= RPL_FRESHNESS_TARGET) &&
            (!m_joined || currentRank == RPL_INFINITE_RANK || current->second.rank < currentRank) &&
            current->second.etx < RPL_MRHOF_MAX_LINK_METRIC)
        {
            uint32_t currentPathCost = 0;
            uint16_t currentCandidateRank = RankViaParent(current->second, &currentPathCost);
            if (currentCandidateRank != RPL_INFINITE_RANK &&
                currentPathCost < RPL_MRHOF_MAX_PATH_COST &&
                currentPathCost <= bestPathCost + RPL_MRHOF_PARENT_SWITCH_THRESHOLD)
            {
                best = m_preferredParent;
                bestRank = currentCandidateRank;
                bestPathCost = currentPathCost;
            }
        }
    }

    // Under MRHOF the rank can stay floor-clamped at parent.rank +
    // MinHopRankIncrease (RFC 6719 section 3.3) while the underlying path
    // cost still drifts, so the path cost has to be compared too -- looking
    // only at rank/parent would leave the advertised m_pathEtx stale.
    bool pathCostChanged = m_ocp == RPL_OCP_MRHOF && !best.IsAny() &&
                          static_cast<uint16_t>(bestPathCost) != m_pathEtx;
    bool changed = (best != m_preferredParent) || (bestRank != m_rank) || pathCostChanged;
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
    bool parentChanged = (best != m_preferredParent);
    m_preferredParent = best;
    m_rank = bestRank;
    if (m_ocp == RPL_OCP_MRHOF)
    {
        m_pathEtx = static_cast<uint16_t>(bestPathCost);
    }

    if (parentChanged)
    {
        // RFC 6550, section 9.5: a node that changes parent has to tell the
        // root about it. The path sequence is what lets the root tell the new
        // report from the one the old parent may still be relaying.
        m_pathSequence++;
        m_daoEvent.Cancel();
        m_daoEvent.Schedule(Seconds(m_jitter->GetValue(0.0, 1.0)));
    }
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
    // on-link flag clear.
    //
    // The root is the only node that knows how to go down, so it is the only
    // one that can put a path into a packet; everyone else sends everything to
    // its preferred parent and lets the root turn it around.
    if (m_isRoot)
    {
        // Lazy cleanup, on the routing hot path rather than on a dedicated
        // timer, the way AODV's RoutingProtocol::Forwarding() purges its
        // table: the root only needs an up-to-date topology when it is about
        // to use it.
        PurgeTopology();

        std::vector<Ipv6Address> hops;
        if (ComputeSourceRoute(dst, hops))
        {
            NS_ASSERT(!hops.empty());
            NS_LOG_LOGIC("Source routing " << dst << " through " << (hops.size() - 1)
                                           << " intermediate router(s), first hop "
                                           << hops.front());
            Ptr<Ipv6Route> route = RouteToNeighbour(hops.front(), dst);
            if (route)
            {
                return route;
            }
        }
    }

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

void
RplRoutingProtocol::PrepareOutgoingPacket(Ptr<Packet> packet, Ipv6Header& header, Ptr<Ipv6Route> route)
{
    NS_LOG_FUNCTION(this << packet << header << route);

    Ipv6Address dst = header.GetDestination();
    if (dst.IsMulticast() || dst.IsLinkLocal())
    {
        // RPL's own control traffic, and anything already scoped to one hop:
        // never crosses more than one radio hop, so neither the Routing
        // Header nor the RPL Option would have anything to say.
        return;
    }

    uint8_t innerNextHeader = header.GetNextHeader();
    bool hasRoutingHeader = false;

    // The Routing Header (RFC 6554), root only: only the root has the
    // topology to compute a downward path at all; every other node's
    // traffic goes up, which needs no Routing Header.
    if (m_isRoot)
    {
        std::vector<Ipv6Address> hops;
        if (ComputeSourceRoute(dst, hops) && hops.size() > 1)
        {
            std::vector<Ipv6Address> addresses(hops.begin() + 1, hops.end());
            // The last address is the packet's real final destination. Every
            // other entry is only ever a next-hop identifier and is fine as
            // link-local, but this one also becomes the IPv6 header's
            // Destination once segmentsLeft reaches 0
            // (RplIpv6ExtensionSourceRouting::Process()), and from there
            // Icmpv6L4Protocol::HandleEchoRequest() (and any other ICMPv6/UDP
            // responder) echoes it straight back as the reply's source
            // address. A link-local source is scoped to one hop
            // (Ipv6L3Protocol::IpForward() drops it outright further on), so
            // a link-local final hop silently breaks every reply that has to
            // cross more than one hop back to the root. Using the global
            // address here keeps the reply's source address, and so its
            // onward routing, working; RouteToNeighbour() (used below and by
            // RplIpv6ExtensionSourceRouting::Process()) resolves a neighbour
            // by its interface identifier alone, so it still finds the right
            // interface for a global address.
            addresses.back() = dst;
            RplSourceRoutingHeader srh;
            srh.SetNextHeader(innerNextHeader);
            srh.SetSegmentsLeft(static_cast<uint8_t>(hops.size() - 1));
            srh.SetAddresses(addresses);

            packet->AddHeader(srh);
            header.SetDestination(hops.front());
            innerNextHeader = Ipv6Header::IPV6_EXT_ROUTING;
            hasRoutingHeader = true;

            NS_LOG_LOGIC("Attached a Routing Header for "
                        << dst << " with " << (hops.size() - 1) << " address(es), first hop "
                        << hops.front());
        }
    }

    // The RPL Option (RFC 6553), on every node's own traffic: the root's is
    // always heading down, since the root never originates traffic of its
    // own going up, and everyone else's is always heading up, since a
    // non-storing mode node other than the root never originates downward
    // traffic itself, only relays what the root already source routed.
    RplPacketInfoHeader rpi;
    rpi.SetDown(m_isRoot);
    rpi.SetInstanceId(m_instanceId);
    rpi.SetSenderRank(m_rank);

    Ipv6ExtensionHopByHopHeader hbh;
    hbh.AddOption(rpi);
    hbh.SetNextHeader(innerNextHeader);
    packet->AddHeader(hbh);
    header.SetNextHeader(Ipv6Header::IPV6_EXT_HOP_BY_HOP);

    NS_LOG_LOGIC("Attached an RPL Option to a packet for "
                << dst << (hasRoutingHeader ? ", behind the Routing Header" : ""));
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
        // Ipv6ListRouting hands its members a null error callback (it calls the
        // real one itself once every member has declined), so guard before
        // invoking, the way the built-in protocols do.
        if (!ecb.IsNull())
        {
            ecb(p, header, Socket::ERROR_NOROUTETOHOST);
        }
        return false;
    }

    // A source routed downward packet is never seen here: RFC 6554 processing
    // (RplIpv6ExtensionSourceRouting) is driven by the packet being addressed
    // to whichever node currently holds it, so it is handled as a local
    // receive, one hop at a time, and re-injected through RouteOutput()
    // rather than ever reaching RouteInput(). What is left to forward here is
    // upward traffic, which always goes to the preferred parent regardless of
    // its destination.
    Ptr<Ipv6Route> route = RouteViaPreferredParent(dst);
    if (route)
    {
        NS_LOG_LOGIC("Forwarding " << dst << " via the preferred parent " << m_preferredParent);
        ucb(route->GetOutputDevice(), route, p, header);
        return true;
    }

    NS_LOG_LOGIC("No forwarding route for " << dst);
    if (!ecb.IsNull())
    {
        ecb(p, header, Socket::ERROR_NOROUTETOHOST);
    }
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

uint16_t
RplRoutingProtocol::GetPathEtx() const
{
    return m_pathEtx;
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
RplRoutingProtocol::NotifyRankInconsistency()
{
    NS_LOG_FUNCTION(this);
    m_dioTrickle.Reset();
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
        << ", rank " << m_rank;
    if (m_ocp == RPL_OCP_MRHOF)
    {
        *os << ", path ETX " << (double(m_pathEtx) / RPL_ETX_FIXED_POINT);
    }
    *os << std::endl;
    *os << "  Preferred parent: " << m_preferredParent << std::endl;
    *os << "  Candidate parents:" << std::endl;
    for (const auto& [address, parent] : m_parents)
    {
        *os << "    " << address << " rank " << parent.rank << " via interface " << parent.interface
            << ", heard " << +parent.freshness << " times, last "
            << (Now() - parent.lastHeard).As(unit) << " ago";
        if (m_ocp == RPL_OCP_MRHOF)
        {
            *os << ", link ETX " << (double(parent.etx) / RPL_ETX_FIXED_POINT) << ", path ETX "
                << (double(parent.pathEtx) / RPL_ETX_FIXED_POINT);
        }
        if (m_enableLql)
        {
            *os << ", LQL " << +parent.lql;
        }
        *os << std::endl;
    }

    if (m_isRoot)
    {
        *os << "  Topology learnt from the DAOs:" << std::endl;
        for (const auto& [target, entry] : m_topology)
        {
            *os << "    " << target << " under " << entry.parent << ", expires in "
                << (entry.expire - Now()).As(unit) << std::endl;
        }
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
