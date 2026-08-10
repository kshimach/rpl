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
                          MakeUintegerChecker<uint8_t>(1, 128))
            .AddAttribute("AodvDioIntervalMin",
                          "Imin of the Trickle timer pacing AODV-RPL RREQ-DIOs (RFC 9854). "
                          "Deliberately far shorter than DioIntervalMin: a route discovery has "
                          "to reach its target and be answered inside the RREQ option's own 'L' "
                          "field, 16 seconds at the shortest.",
                          TimeValue(MilliSeconds(128)),
                          MakeTimeAccessor(&RplRoutingProtocol::m_aodvDioIntervalMin),
                          MakeTimeChecker())
            .AddAttribute("AodvDioIntervalDoublings",
                          "Number of doublings between Imin and Imax of the RREQ-DIO Trickle "
                          "timer.",
                          UintegerValue(4),
                          MakeUintegerAccessor(&RplRoutingProtocol::m_aodvDioIntervalDoublings),
                          MakeUintegerChecker<uint8_t>())
            .AddAttribute("AodvRankLimit",
                          "RankLimit advertised in RREQ-DIOs (RFC 9854 section 4.1): the upper "
                          "bound on DAGRank() a router may reach and still join the discovery, "
                          "which is what stops an RREQ flooding the whole network. 0 means no "
                          "limit.",
                          UintegerValue(8),
                          MakeUintegerAccessor(&RplRoutingProtocol::m_aodvRankLimit),
                          MakeUintegerChecker<uint8_t>(0, RPL_AODV_RANK_LIMIT_MASK))
            .AddAttribute("AodvLifetime",
                          "The 'L' field of RREQ-DIOs (RFC 9854 section 4.1), how long a node "
                          "stays in the RREQ-Instance: 0 no limit, 1 for 16 s, 2 for 64 s, 3 for "
                          "256 s.",
                          UintegerValue(1),
                          MakeUintegerAccessor(&RplRoutingProtocol::m_aodvLifetime),
                          MakeUintegerChecker<uint8_t>(0, RPL_AODV_LIFETIME_MASK))
            .AddAttribute("AodvRejoinReenable",
                          "REJOIN_REENABLE (RFC 9854 section 2): how long after leaving an "
                          "RREQ-Instance a node refuses to rejoin the same one. Without it a "
                          "discovery never ends, since a neighbour still Trickle-pacing the old "
                          "RREQ-DIOs pulls the node back in immediately.",
                          TimeValue(Minutes(15)),
                          MakeTimeAccessor(&RplRoutingProtocol::m_aodvRejoinReenable),
                          MakeTimeChecker())
            .AddAttribute("AodvForceAsymmetric",
                          "Clear the 'S' bit of every RREQ-DIO this router propagates (RFC 9854 "
                          "section 6.2.4), forcing the discovery onto the asymmetric path: the "
                          "TargNode answers by building an RREP-Instance DODAG of its own and "
                          "flooding it, rather than unicasting back along the RREQ's Address "
                          "Vector. Deciding link symmetry for real is out of the RFC's own scope "
                          "(section 5) and is not implementable here anyway -- both metrics this "
                          "module keeps, ETX and RSSI-derived LQL, are measured on received "
                          "frames, so they describe the same direction and comparing them says "
                          "nothing about asymmetry. This attribute is what makes the asymmetric "
                          "path reachable in a simulation at all.",
                          BooleanValue(false),
                          MakeBooleanAccessor(&RplRoutingProtocol::m_aodvForceAsymmetric),
                          MakeBooleanChecker())
            .AddAttribute("P2pDioIntervalMin",
                          "Imin of the Trickle timer pacing P2P-RPL P2P mode DIOs (RFC 6997). "
                          "Default matches the RFC's own recommended default DODAG "
                          "Configuration Option (section 6.1): DIOIntervalMin 6, i.e. 64 ms.",
                          TimeValue(MilliSeconds(64)),
                          MakeTimeAccessor(&RplRoutingProtocol::m_p2pDioIntervalMin),
                          MakeTimeChecker())
            .AddAttribute("P2pDioIntervalDoublings",
                          "Number of doublings between Imin and Imax of the P2P mode DIO "
                          "Trickle timer. RFC 6997 section 9.2 only says Imax should be 'several "
                          "orders of magnitude higher than Imin' and is 'unlikely to be "
                          "critical', since a temporary DAG rarely lives long enough for the "
                          "timer to grow much; 8 doublings (Imax 16.384 s) comfortably clears "
                          "that bar without approaching the shortest 'L' encoding (1 s).",
                          UintegerValue(8),
                          MakeUintegerAccessor(&RplRoutingProtocol::m_p2pDioIntervalDoublings),
                          MakeUintegerChecker<uint8_t>())
            .AddAttribute("P2pDioRedundancy",
                          "Redundancy constant k of the P2P mode DIO Trickle timer. RFC 6997 "
                          "section 9.2: 'The recommended value...is 1.'",
                          UintegerValue(1),
                          MakeUintegerAccessor(&RplRoutingProtocol::m_p2pDioRedundancy),
                          MakeUintegerChecker<uint8_t>())
            .AddAttribute("P2pMaxRank",
                          "MaxRank advertised in P2P mode DIOs (RFC 6997 section 7): the upper "
                          "bound on DAGRank() a router may reach and still join the temporary "
                          "DAG, which is what stops a P2P-RPL discovery flooding the whole "
                          "network. 0 means no limit.",
                          UintegerValue(8),
                          MakeUintegerAccessor(&RplRoutingProtocol::m_p2pMaxRank),
                          MakeUintegerChecker<uint8_t>(0, RPL_P2P_MAX_RANK_MASK))
            .AddAttribute("P2pLifetime",
                          "The 'L' field of P2P mode DIOs (RFC 6997 section 7), how long a "
                          "router stays in the temporary DAG: 0 for 1 s, 1 for 4 s, 2 for 16 s, "
                          "3 for 64 s.",
                          UintegerValue(2),
                          MakeUintegerAccessor(&RplRoutingProtocol::m_p2pLifetime),
                          MakeUintegerChecker<uint8_t>(0, 3));
    return tid;
}

RplRoutingProtocol::RplRoutingProtocol()
    : m_ipv6(nullptr),
      m_isRoot(false),
      m_disInterval(Seconds(30)),
      m_disTimer(Timer::CANCEL_ON_DESTROY),
      m_enableLql(false),
      m_rssiToLql(MakeCallback(&DefaultRssiToLql)),
      m_ocp(RPL_OCP_OF0),
      m_minHopRankIncrease(RPL_MIN_HOPRANKINC),
      m_dioIntervalMin(MilliSeconds(1 << RPL_DIO_INTERVAL_MIN)),
      m_dioIntervalDoublings(RPL_DIO_INTERVAL_DOUBLINGS),
      m_dioRedundancy(RPL_DIO_REDUNDANCY),
      m_daoInterval(Seconds(60)),
      m_daoAckTimeout(Seconds(5)),
      m_daoRetries(3),
      m_pathLifetime(RPL_DEFAULT_LIFETIME),
      m_lifetimeUnit(RPL_DEFAULT_LIFETIME_UNIT),
      m_rootPrefix(Ipv6Address::GetAny()),
      m_rootPrefixLength(64)
{
    NS_LOG_FUNCTION(this);
    m_jitter = CreateObject<UniformRandomVariable>();
    // dioTrickle's function is bound per DodagMembership, once that
    // membership is created (JoinDodag(), HandleDadSuccess()'s root
    // branch): it needs the DodagKey identifying which membership fired, and
    // no membership -- so no key -- exists yet at construction time.
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

    // m_dioTrickle no longer exists as a persistent scalar to pre-configure
    // here: JoinDodag() and HandleDadSuccess()'s root branch each call
    // SetParameters() on their own freshly constructed DodagMembership's
    // dioTrickle instead, seeded from the same m_dioIntervalMin/Doublings/
    // Redundancy attributes this used to configure ahead of time.

    // Always wired up, even for the base DODAG's own root: m_isRoot only
    // says this node owns the base DODAG, not that every DodagMembership it
    // ever holds is one it roots. AODV-RPL (RFC 9854) lets this same node
    // join someone else's RREQ-Instance as an ordinary (non-root) member --
    // CreateLocalDodag()/HandleAodvRreq() do not consult m_isRoot at all --
    // and SelectPreferredParent() falls back to m_disTimer.Schedule() for
    // any non-root membership that loses its last parent (DodagMembership::
    // isRoot is what actually gates that path, checked per membership).
    // Leaving m_disTimer without a function only for m_isRoot nodes left it
    // Schedule()'d against a Timer that had never had SetFunction() called,
    // asserting "m_impl != nullptr" in Timer::Schedule() the first time a
    // root's own RREQ-Instance membership lost its last neighbour.
    m_disTimer.SetFunction(&RplRoutingProtocol::DisTimerExpire, this);

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
        // daoEvent/daoRetryEvent are bound per DODAG membership instead, in
        // JoinDodag(): each is a fresh Timer, part of a DodagMembership that
        // does not exist yet at this point.
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
    for (auto& [socket, interface] : m_socketToIfc)
    {
        socket->Close();
    }
    m_socketToIfc.clear();
    m_ifcToSocket.clear();
    // Every DodagMembership's own Timer members are Timer::CANCEL_ON_DESTROY
    // (RplTrickleTimer's own two, plus daoEvent/daoRetryEvent), so clearing
    // the map cancels every pending event the same way the explicit
    // Cancel()/Stop() calls above do for the node-wide m_disTimer.
    m_dodags.clear();
    m_ipv6 = nullptr;

    Ipv6RoutingProtocol::DoDispose();
}

RplRoutingProtocol::DodagMembership*
RplRoutingProtocol::GetBaseDodag()
{
    if (!m_hasBaseDodag)
    {
        return nullptr;
    }
    auto it = m_dodags.find(m_baseDodagKey);
    return it == m_dodags.end() ? nullptr : &it->second;
}

const RplRoutingProtocol::DodagMembership*
RplRoutingProtocol::GetBaseDodag() const
{
    if (!m_hasBaseDodag)
    {
        return nullptr;
    }
    auto it = m_dodags.find(m_baseDodagKey);
    return it == m_dodags.end() ? nullptr : &it->second;
}

RplRoutingProtocol::DodagMembership&
RplRoutingProtocol::CreateDodagMembership(DodagKey key, uint8_t mop)
{
    NS_LOG_FUNCTION(this << +key.instanceId << key.dodagId << +mop);
    NS_ASSERT_MSG(m_dodags.find(key) == m_dodags.end(),
                 "CreateDodagMembership() called for a DODAG this node already has a membership "
                 "in");

    // In-place construction only, straight into the map: see
    // DodagMembership's own doc comment for why.
    DodagMembership& dodag = m_dodags[key];
    dodag.instanceId = key.instanceId;
    dodag.dodagId = key.dodagId;
    dodag.isRoot = true;
    dodag.mop = mop;
    dodag.grounded = true;
    dodag.rank = m_minHopRankIncrease;

    // Seeded from this node's own attribute-configured defaults, the same
    // values JoinDodag() would instead read off a received DIO's DODAG
    // Configuration option -- a self-formed DODAG's root is the one node
    // that originates them rather than adopting them from somewhere else.
    dodag.ocp = m_ocp;
    dodag.minHopRankIncrease = m_minHopRankIncrease;
    dodag.dioIntervalMin = m_dioIntervalMin;
    dodag.dioIntervalDoublings = m_dioIntervalDoublings;
    dodag.dioRedundancy = m_dioRedundancy;

    // No daoEvent/daoRetryEvent binding: SendDao() is a no-op for a root
    // (dodag.isRoot), and nothing ever schedules either Timer for one in
    // the first place -- only SelectPreferredParent() does that, on
    // picking a first preferred parent, which a root never has.
    dodag.dioTrickle.SetFunction(MakeCallback(&RplRoutingProtocol::DioTrickleFire, this, key));
    dodag.dioTrickle.SetParameters(dodag.dioIntervalMin,
                                   dodag.dioIntervalDoublings,
                                   dodag.dioRedundancy);
    if (m_dioTrickleStream >= 0)
    {
        dodag.dioTrickle.AssignStreams(m_dioTrickleStream);
    }
    dodag.dioTrickle.Start();

    if (!m_hasBaseDodag && mop != RPL_MOP_P2P_ROUTE_DISCOVERY)
    {
        // A route-discovery instance never becomes the base DODAG, however
        // early it is formed. The base is what every base-scoped accessor
        // (GetRank(), IsJoined(), RouteOutput()'s own fallback, ...) answers
        // for, and an AODV-RPL RREQ-Instance is a transient thing that
        // LeaveDodag() will erase within seconds -- letting it take the slot
        // on a node that has not joined its base DODAG yet would hand all of
        // those the wrong DODAG and then strand them when it expires.
        m_hasBaseDodag = true;
        m_baseDodagKey = key;
    }

    return dodag;
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

    // Drop the neighbours that were only reachable through this interface,
    // in every DODAG this node is part of. The keys are snapshotted first
    // and each looked back up before use: SelectPreferredParent() can erase
    // the very entry being visited (LeaveDodag(), on losing the last
    // parent), which would invalidate a plain range-for's own iterator the
    // moment that happened to the entry currently being visited -- the same
    // hazard DioTrickleFire() and HandleDio() guard against for the single
    // entry they each hold, just across every entry here instead of one.
    std::vector<DodagKey> keys;
    keys.reserve(m_dodags.size());
    for (const auto& [key, dodag] : m_dodags)
    {
        keys.push_back(key);
    }
    for (const DodagKey& key : keys)
    {
        auto it = m_dodags.find(key);
        if (it == m_dodags.end())
        {
            continue;
        }
        DodagMembership& dodag = it->second;

        for (auto parent = dodag.parents.begin(); parent != dodag.parents.end();)
        {
            parent = (parent->second.interface == interface) ? dodag.parents.erase(parent)
                                                              : std::next(parent);
        }
        if (SelectPreferredParent(dodag))
        {
            auto stillPresent = m_dodags.find(key);
            if (stillPresent != m_dodags.end())
            {
                stillPresent->second.dioTrickle.Reset();
            }
        }
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

Ipv6Address
RplRoutingProtocol::GetGlobalAddressIn(const DodagMembership& dodag) const
{
    if (!dodag.hasPrefixInfo)
    {
        // No prefix known for this DODAG (e.g. one CreateLocalDodag()
        // formed, which never carries a Prefix Information option): there
        // is nothing to filter by, so fall back to whichever global
        // address this node has, the same as before this DODAG-aware
        // lookup existed.
        return GetGlobalAddress();
    }

    Ipv6Prefix prefix(dodag.prefixLength);
    for (uint32_t i = 1; i < m_ipv6->GetNInterfaces(); i++)
    {
        for (uint32_t j = 0; j < m_ipv6->GetNAddresses(i); j++)
        {
            Ipv6InterfaceAddress iaddr = m_ipv6->GetAddress(i, j);
            // Same TENTATIVE guard as GetGlobalAddress(): an address DAD
            // has not cleared yet is not actually usable. Matched against
            // the real, currently assigned addresses rather than rebuilt
            // from dodag.dodagId + a link-local (the way GlobalAddressOf()
            // does for a neighbour) precisely so an address DAD rejected
            // and withdrew is not still handed out here.
            if (iaddr.GetScope() == Ipv6InterfaceAddress::GLOBAL &&
                iaddr.GetState() != Ipv6InterfaceAddress::TENTATIVE &&
                prefix.IsMatch(iaddr.GetAddress(), dodag.prefix))
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
        if (GetBaseDodag())
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
        DodagKey key{RPL_DEFAULT_INSTANCE, address};
        DodagMembership& dodag = CreateDodagMembership(key, RPL_MOP_NON_STORING);

        // Every DIO this root sends carries the Prefix Information option
        // (RFC 6550 section 6.7.10) so every other node can SLAAC an address
        // on RootPrefix (see SendDio(), JoinDodag()).
        dodag.hasPrefixInfo = true;
        dodag.prefix = m_rootPrefix;
        dodag.prefixLength = m_rootPrefixLength;
        dodag.prefixOnLink = true;
        dodag.prefixAutonomous = true;
        dodag.prefixValidLifetime = RPL_PREFIX_VALID_LIFETIME;
        dodag.prefixPreferredLifetime = RPL_PREFIX_PREFERRED_LIFETIME;

        NS_LOG_INFO("Root of DODAG " << dodag.dodagId << " at rank " << dodag.rank);
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
        HandleDio(dio, from, interface, linkEtx, lql, ipv6Header.GetDestination().IsMulticast());
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

    if (IsJoined())
    {
        return;
    }

    SendDis(Ipv6Address(RPL_ALL_NODES_MULTICAST));
    m_disTimer.Cancel();
    m_disTimer.Schedule(m_disInterval);
}

void
RplRoutingProtocol::SendDio(DodagMembership& dodag, Ipv6Address dst, uint32_t interface)
{
    NS_LOG_FUNCTION(this << dst << interface);

    RplDioHeader dio;
    dio.SetInstanceId(dodag.instanceId);
    dio.SetVersionNumber(dodag.version);
    dio.SetRank(dodag.rank);
    dio.SetGrounded(dodag.grounded);
    dio.SetMop(dodag.mop);
    dio.SetPreference(dodag.preference);
    dio.SetDtsn(dodag.dtsn);
    dio.SetDodagId(dodag.dodagId);

    // The configuration option is carried by every DIO, not just the root's, so
    // that a node joining deep in the DODAG gets the same Trickle parameters.
    dio.SetDagConfiguration(dodag.dioIntervalDoublings,
                            static_cast<uint8_t>(std::log2(dodag.dioIntervalMin.GetMilliSeconds())),
                            dodag.dioRedundancy,
                            dodag.maxRankIncrease,
                            dodag.minHopRankIncrease,
                            dodag.ocp,
                            RPL_DEFAULT_LIFETIME,
                            RPL_DEFAULT_LIFETIME_UNIT);

    if (dodag.ocp == RPL_OCP_MRHOF)
    {
        // RFC 6551 section 4.3, additive aggregation: the root originates the
        // DODAG at path ETX 0, every other node advertises the path cost it
        // computed picking its own preferred parent.
        dio.SetMetricContainer(dodag.isRoot ? 0 : dodag.pathEtx);
    }

    if (m_enableLql)
    {
        // LQL is recorded, not aggregated: what is advertised is this node's
        // own link to its preferred parent, not a path-wide value. The root
        // has no upstream link of its own to report.
        auto preferred = dodag.parents.find(dodag.preferredParent);
        dio.SetLql(preferred != dodag.parents.end() ? preferred->second.lql
                                                    : RPL_LQL_UNDETERMINED);
    }

    if (dodag.hasPrefixInfo)
    {
        // Carried by every DIO, not just the root's, the same reason as the
        // DODAG Configuration option above: a node joining deep in the
        // DODAG still needs to learn the prefix to SLAAC an address on.
        dio.SetPrefixInfo(dodag.prefix,
                          dodag.prefixLength,
                          dodag.prefixOnLink,
                          dodag.prefixAutonomous,
                          dodag.prefixValidLifetime,
                          dodag.prefixPreferredLifetime);
    }

    if (dodag.mop == RPL_MOP_P2P_ROUTE_DISCOVERY && dodag.aodv.isRrepInstance)
    {
        // An RREP-DIO for an asymmetric route (RFC 9854 section 6.3.2): the
        // TargNode roots this DODAG and floods it, and every router that
        // joins re-advertises it the same way, so this is rebuilt from the
        // membership's own state on each transmission exactly as the RREQ
        // case below is.
        RplDioHeader::RrepOption rrep;
        rrep.gratuitous = false; // section 7's Gratuitous RREP is out of scope
        rrep.hopByHop = false;   // matching the RREQ's own H bit
        rrep.lifetime = dodag.aodv.lifetimeField;
        rrep.rankLimit = dodag.aodv.rankLimit;
        // Section 6.3.3: Delta is what the TargNode added to the
        // RREQ-InstanceID to get this instance's own, so that a receiver can
        // subtract it back off. Held as the pair rather than as Delta itself
        // because every router re-advertising this DODAG has to reproduce
        // the same value the TargNode chose.
        rrep.delta = static_cast<uint8_t>(dodag.instanceId - dodag.aodv.pairedInstanceId);
        rrep.addressVector = dodag.aodv.addressVector;
        dio.SetRrep(rrep);

        RplDioHeader::ArtOption art;
        // "The address of the OrigNode MUST be encapsulated in the ART
        // option and included in this RREP-DIO message along with the SeqNo
        // of TargNode" (section 6.3). origSeqNo holds it: the field means
        // "the Sequence Number of whichever node originated this instance",
        // which for an RREP-Instance is the TargNode rooting it, exactly as
        // it is the OrigNode for an RREQ-Instance.
        art.destSeqNo = dodag.aodv.origSeqNo;
        art.prefixLength = 0; // the field holds an address, not a prefix
        art.target = dodag.aodv.origNode;
        dio.SetArt(art);
    }
    else if (dodag.mop == RPL_MOP_P2P_ROUTE_DISCOVERY && !dodag.aodv.target.IsAny())
    {
        // An RREQ-DIO (RFC 9854 section 4.1): "Exactly one RREQ option MUST
        // be present in an RREQ-DIO message", and section 4.3 "An RREQ-DIO
        // message MUST carry at least one ART option". Both are rebuilt from
        // the membership's own state on every transmission, so a router
        // propagates the Address Vector it recorded on the way in -- its own
        // address already appended by HandleAodvRreq().
        RplDioHeader::RreqOption rreq;
        rreq.symmetric = dodag.aodv.symmetric;
        rreq.hopByHop = false; // source routed; H=1 is out of scope
        // compr left at its default: RplDioHeader::Serialize() computes its
        // own from the addresses below and this DIO's own DODAGID.
        rreq.lifetime = dodag.aodv.lifetimeField;
        rreq.rankLimit = dodag.aodv.rankLimit;
        rreq.origSeqNo = dodag.aodv.origSeqNo;
        rreq.addressVector = dodag.aodv.addressVector;
        dio.SetRreq(rreq);

        RplDioHeader::ArtOption art;
        // The TargNode's own Sequence Number is not known until its RREP
        // arrives; RFC 9854 section 4.3 has the RREQ carry 0 for "no known
        // information about the Sequence Number of TargNode".
        art.destSeqNo = 0;
        art.prefixLength = 0; // the field holds an address, not a prefix
        art.target = dodag.aodv.target;
        dio.SetArt(art);
    }
    else if (dodag.mop == RPL_MOP_P2P_ROUTE_DISCOVERY && !dodag.p2p.target.IsAny())
    {
        // A P2P mode DIO (RFC 6997 section 6): "MUST carry one (and only
        // one) P2P Route Discovery Option." Rebuilt from the membership's
        // own state on every transmission, the same reason the AODV-RPL
        // branches above are -- a router propagates the Address Vector it
        // recorded on the way in, its own address already appended.
        P2pRdoOption rdo;
        rdo.reply = dodag.p2p.reply;
        rdo.hopByHop = dodag.p2p.hopByHop; // always false; H=1 is out of scope
        rdo.numRoutes = 0; // exactly one Source Route; N > 0 is out of scope
        // compr left at its default: P2pRdoSerialize() computes its own
        // from target/addressVector and this DIO's own DODAGID.
        rdo.lifetime = dodag.p2p.lifetimeField;
        rdo.maxRankOrNh = dodag.p2p.maxRank;
        rdo.target = dodag.p2p.target;
        rdo.addressVector = dodag.p2p.addressVector;
        dio.SetP2pRdo(rdo);
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
RplRoutingProtocol::DioTrickleFire(DodagKey key)
{
    NS_LOG_FUNCTION(this);

    auto it = m_dodags.find(key);
    if (it == m_dodags.end())
    {
        // The membership was torn down (e.g. LeaveDodag()) in the same
        // simulation event that scheduled this firing, before it ran.
        return;
    }
    DodagMembership& dodag = it->second;

    // A neighbour that has simply gone quiet is only noticed here. Every
    // other call of SelectPreferredParent() is driven by an incoming DIO
    // (HandleDio()) or by an interface going down (StopInterface()), so a
    // node whose neighbours all stop sending has nothing left to run the
    // staleness check that is meant to catch exactly that: it would keep
    // its last parent selected indefinitely and go on advertising a rank
    // it can no longer reach the root with, poisoning everything that
    // picked it as a parent in turn. The Trickle timer keeps firing
    // whether or not anything is being heard, which is what makes it the
    // right clock for this; the check happens before the DIO goes out, so
    // the DIO carries the rank that comes out of it.
    // The return value, which everywhere else means "reset the Trickle
    // timer", is deliberately ignored here. Resetting it from inside its
    // own transmission event would reschedule the very timer currently
    // being run, and there is nothing to gain from it either: a reset
    // exists to bring the next DIO forward, and the next DIO is the one
    // going out on the line below. If the check above dropped the last
    // parent, LeaveDodag() has already stopped the timer outright (and
    // erased this entry, which is what the lookup above guards against on
    // the next scheduled firing), and SendDio() below would then be
    // reached only if a *different* parent was found instead.
    SelectPreferredParent(dodag);
    if (m_dodags.find(key) == m_dodags.end())
    {
        // SelectPreferredParent() dropped the last parent and LeaveDodag()
        // erased this very entry; dodag is now a dangling reference.
        return;
    }

    SendDio(dodag, Ipv6Address(RPL_ALL_NODES_MULTICAST));
}

void
RplRoutingProtocol::HandleDis(Ipv6Address from, uint32_t interface, bool toMulticast)
{
    NS_LOG_FUNCTION(this << from << interface << toMulticast);

    // Answer for every DODAG this node currently belongs to, not just the
    // base one: a DIS is not addressed to a particular Instance, so a
    // neighbour soliciting one wants to hear about all of them. Neither
    // branch below ever calls LeaveDodag() (dioTrickle.Reset() only
    // perturbs the Trickle timer; SendDio() only serializes and sends), so
    // unlike StopInterface() this plain range-for needs no snapshot-then-
    // refind guard against a mid-loop erase().
    for (auto& [key, dodag] : m_dodags)
    {
        if (dodag.mop == RPL_MOP_P2P_ROUTE_DISCOVERY)
        {
            // Not an ordinary DODAG a neighbour can usefully join: an
            // AODV-RPL RREQ-Instance exists only for the route discovery
            // that created it, is scoped by that discovery's own RankLimit
            // and Address Vector, and is torn down when its 'L' field
            // expires. Answering a DIS with one would pull an uninvolved
            // neighbour into somebody else's discovery.
            continue;
        }

        if (toMulticast)
        {
            // RFC 6550, section 8.3: a multicast DIS is an inconsistency, so
            // the Trickle timer restarts and the answer goes out to the
            // whole link.
            dodag.dioTrickle.Reset();
        }
        else
        {
            SendDio(dodag, from, interface);
        }
    }
}

void
RplRoutingProtocol::HandleDio(const RplDioHeader& dio,
                              Ipv6Address from,
                              uint32_t interface,
                              uint16_t linkEtx,
                              uint8_t lql,
                              bool toMulticast)
{
    NS_LOG_FUNCTION(this << from << interface);

    DodagKey dioKey{dio.GetInstanceId(), dio.GetDodagId()};

    if (m_isRoot && !GetBaseDodag())
    {
        // This node's own base DODAG has not formed yet (HandleDadSuccess()
        // is still waiting on DAD for the address it roots at): ignore
        // every DIO until then, so nothing else can beat it to becoming the
        // base DODAG (@see GetBaseDodag()). Specific to the base's own
        // formation, not the general "root never takes a parent within its
        // own DODAG" rule just below -- a CreateLocalDodag()-formed
        // membership has no equivalent race, it exists synchronously the
        // moment that call returns.
        return;
    }

    auto selfIt = m_dodags.find(dioKey);
    if (selfIt != m_dodags.end() && selfIt->second.isRoot)
    {
        // This node roots the DODAG the DIO names -- the base one or a
        // CreateLocalDodag()-formed local one, either way -- and a root
        // never takes a parent within its own DODAG. Resolved by key
        // rather than GetBaseDodag(): the old base-only version of this
        // check let a local DODAG's own re-advertised DIO reach its root
        // and be treated as an ordinary join candidate, a self-loop.
        return;
    }

    // A DIO for some DODAG this node does not itself root: fall through,
    // including for a root, which may still join another DODAG as a
    // regular (non-root) member -- the way an AODV-RPL (RFC 9854) OrigNode
    // is root of its own RREQ-Instance while remaining an ordinary member
    // of the base DODAG.

    if (dio.GetMop() != RPL_MOP_NON_STORING && dio.GetMop() != RPL_MOP_P2P_ROUTE_DISCOVERY)
    {
        NS_LOG_WARN("Ignoring a DIO advertising mode of operation "
                    << +dio.GetMop()
                    << ", only non-storing and P2P route discovery are implemented");
        return;
    }

    // On a symmetric route an RREP-DIO is not an advertisement to join --
    // "the DODAG in RREP-Instance does not need to be built" (RFC 9854
    // section 6.3.1), it is a unicast carrying a finished route back towards
    // the OrigNode. Handled and returned before any of the ordinary
    // machinery below, which would otherwise have this node join a DODAG
    // rooted at the TargNode.
    //
    // On an asymmetric route the opposite holds: section 6.3.2's
    // RREP-Instance is a real flooded DODAG and this DIO is exactly an
    // invitation to join it, so it falls through to the join logic and is
    // picked up by HandleAodvRrepInstance() at the end, the way an RREQ-DIO
    // is by HandleAodvRreq().
    //
    // How it arrived is what tells the two apart, because that is precisely
    // what the RFC makes different about them -- section 6.3.1 unicasts to
    // the next hop, section 6.3.2 transmits "to multicast group
    // all-AODV-RPL-nodes". The RREP option itself carries nothing to
    // distinguish them (its 'G' is the Gratuitous flag, a different thing),
    // and the paired RREQ-Instance's own 'S' bit cannot stand in for it: at
    // the OrigNode that bit is always 1, since section 6.1 has the OrigNode
    // originate it that way and only the routers downstream ever clear it.
    if (dio.HasRrep() && !toMulticast)
    {
        HandleAodvRrep(dio, from, interface);
        return;
    }

    // RFC 9854 section 6.2.1 puts two checks ahead of joining an
    // RREQ-Instance, so they have to run before the join below rather than
    // in HandleAodvRreq() after it: this node's own address already in the
    // Address Vector, and a rank that would reach the RankLimit.
    if (dio.HasRreq() && ShouldRefuseAodvRreq(dio, from))
    {
        return;
    }

    // An asymmetric RREP-Instance needs the RREQ-Instance's own set of
    // pre-join checks for the same reasons: the rejoin bar (once its own
    // membership has been erased at its 'L' deadline, nothing else stops a
    // TargNode being pulled back into a DODAG rooted at its own address by
    // a straggling RREP-DIO -- the isRoot check above only covers the
    // window while the membership still exists), the loop check, and the
    // RankLimit (RFC 9854 section 6.4.1 gates joining the RREP-Instance DODAG
    // on it exactly as section 6.2.1 gates joining the RREQ-Instance one).
    if (dio.HasRrep() && ShouldRefuseAodvRrep(dio, from))
    {
        return;
    }

    auto existingIt = m_dodags.find(dioKey);
    DodagMembership* existing = existingIt != m_dodags.end() ? &existingIt->second : nullptr;

    if (dio.GetRank() == RPL_INFINITE_RANK)
    {
        // RFC 6550, section 8.2.2.5: an infinite rank poisons the sub-DODAG.
        NS_LOG_LOGIC("Neighbour " << from << " is advertising an infinite rank");
        if (existing)
        {
            // Withdraw before erasing, the same reason and the same order as
            // the staleness sweep in SelectPreferredParent(): once from is
            // gone from the parent set, RouteOutput() has nothing left to
            // resolve a route through, even though the link itself -- this
            // DIO just arrived on it -- is very much still there to send
            // the withdrawal over.
            if (from == existing->preferredParent)
            {
                SendNoPathDao(*existing, from);
            }
            existing->parents.erase(from);
            // SelectPreferredParent() may lose the last parent and call
            // LeaveDodag(), which erases this very entry -- existing would
            // then dangle, so the Trickle reset below re-resolves it by key
            // rather than reusing the pointer already in hand.
            if (SelectPreferredParent(*existing))
            {
                auto it = m_dodags.find(dioKey);
                if (it != m_dodags.end())
                {
                    it->second.dioTrickle.Reset();
                }
            }
        }
        return;
    }

    if (!existing)
    {
        JoinDodag(dio, interface);
    }
    else if (dio.GetVersionNumber() != existing->version)
    {
        // The DODAGVersionNumber is a lollipop counter (RFC 6550 section
        // 7.1), so which of two Versions is the newer one is decided by the
        // comparison of section 7.2 rule 3, not by a plain `>`. The two
        // disagree exactly at the wrap: rule 2 has the counter go from 255
        // "back to zero", which `>` reads as a 255-step decrease. Since the
        // root never goes back to an older Version, that misreading is not
        // something the next DIO puts right -- every node would reject every
        // Version from the wrap onwards, and global repair would stop working
        // permanently. Rule 4 covers the counters that cannot be ordered at
        // all: not migrating is the answer that "minimize[s] the resulting
        // changes to its own state".
        if (RplSequenceNewer(dio.GetVersionNumber(), existing->version))
        {
            NS_LOG_INFO("DODAG " << existing->dodagId << " moved to version "
                                 << +dio.GetVersionNumber());
            // Migrating between DODAG Versions, not detaching: no
            // poisoning, since the node rejoins in this same event.
            LeaveDodag(DodagKey{existing->instanceId, existing->dodagId}, false);
            JoinDodag(dio, interface);
        }
        else
        {
            NS_LOG_LOGIC("Ignoring a DIO for the stale version " << +dio.GetVersionNumber());
            return;
        }
    }

    auto dodagIt = m_dodags.find(dioKey);
    NS_ASSERT_MSG(dodagIt != m_dodags.end(),
                 "JoinDodag() must have created this membership by this point");
    DodagMembership* dodag = &dodagIt->second;

    // RFC 6550 section 9.6, rules 1 and 2: hearing a DAO parent increment
    // its DTSN means new downward state exists to refresh. "DAO parent" is
    // this node's one and only DAO destination in non-storing mode, its
    // preferred parent, so a DTSN bump from anyone else is not this rule's
    // concern (it may still just be a fresh neighbour, whose default-
    // constructed Parent -- dtsn 0 -- would otherwise read as an increment
    // the first time it is heard from at all).
    //
    // "Increment" is the lollipop one of RFC 6550 section 7.2, the same as
    // the DODAG Version above: the DTSN is not among the three counters
    // section 7.1 names, but it is an 8-bit RPL sequence counter that wraps
    // like them, and read with a plain `>` the wrap from 255 to 0 is the one
    // increment in every 256 that goes unnoticed -- leaving the whole
    // sub-DODAG never told to refresh, and its downward routes to expire at
    // the root.
    auto existingParent = dodag->parents.find(from);
    bool preferredParentBumpedDtsn = existingParent != dodag->parents.end() &&
                                     from == dodag->preferredParent &&
                                     RplSequenceNewer(dio.GetDtsn(), existingParent->second.dtsn);

    Parent& parent = dodag->parents[from];
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

    // The DTSN drives the DAO refresh, which an AODV-RPL instance has no
    // DAOs to refresh (@see SendDao()). Skipped rather than left to
    // SendDao()'s own guard so no pointless timer is armed for it at all.
    if (preferredParentBumpedDtsn && dodag->mop != RPL_MOP_P2P_ROUTE_DISCOVERY)
    {
        // Rule 2: in non-storing mode, this node's own DTSN follows its
        // parent's up.
        dodag->dtsn++;
        // Rule 1: schedule a DAO. RFC 6550 section 9.5's DelayDAO jitter is
        // the same one a parent switch already uses just below, for the
        // same reason -- an immediate, unjittered transmission from every
        // node in the sub-DODAG at once would be exactly the kind of burst
        // Trickle-style pacing exists to avoid.
        NS_LOG_INFO("DAO parent " << from << " incremented its DTSN, refreshing this node's DAO");
        dodag->daoEvent.Cancel();
        dodag->daoEvent.Schedule(Seconds(m_jitter->GetValue(0.0, 1.0)));
    }

    dodag->dioTrickle.ConsistencyHit();

    // Same dangling-pointer hazard as the infinite-rank branch above:
    // SelectPreferredParent() can erase this very entry via LeaveDodag().
    if (SelectPreferredParent(*dodag))
    {
        auto it = m_dodags.find(dioKey);
        if (it != m_dodags.end())
        {
            it->second.dioTrickle.Reset();
        }
    }

    // Last, so the AODV-RPL side sees a membership whose rank and preferred
    // parent are already settled -- RFC 9854 section 6.2.5 has the router
    // append the address of the interface it heard the RREQ on, which is
    // only meaningful once that parent is chosen. Re-resolved by key for the
    // same reason the Trickle reset above is.
    if (dio.HasRreq() && m_dodags.find(dioKey) != m_dodags.end())
    {
        HandleAodvRreq(dio, from, interface);
    }

    // The asymmetric RREP-Instance's own equivalent, in the same position
    // and for the same reason: section 6.4.4 has the router append the
    // address of the interface it heard the RREP-DIO on, which only means
    // anything once this membership's preferred parent is settled.
    if (dio.HasRrep() && m_dodags.find(dioKey) != m_dodags.end())
    {
        HandleAodvRrepInstance(dio, from, interface);
    }
}

void
RplRoutingProtocol::JoinDodag(const RplDioHeader& dio, uint32_t interface)
{
    NS_LOG_FUNCTION(this << interface);

    DodagKey key{dio.GetInstanceId(), dio.GetDodagId()};
    // In-place construction only, straight into the map: see
    // DodagMembership's own doc comment for why a copy or move of an
    // existing entry (a temporary built elsewhere and inserted, say) must
    // never happen. operator[] on a not-yet-present key default-constructs
    // the value directly inside the map node, no temporary involved.
    DodagMembership& dodag = m_dodags[key];

    if (!m_hasBaseDodag && dio.GetMop() != RPL_MOP_P2P_ROUTE_DISCOVERY)
    {
        // Never let a route-discovery instance become the base DODAG, for
        // the same reason CreateDodagMembership() refuses to: it is
        // transient, scoped to somebody else's discovery, and every
        // base-scoped accessor would be left answering for it and then
        // stranded when its 'L' field expires. Reached whenever a node hears
        // an AODV-RPL RREQ-DIO before its own base DODAG has formed.
        m_hasBaseDodag = true;
        m_baseDodagKey = key;
    }

    dodag.instanceId = key.instanceId;
    dodag.dodagId = key.dodagId;
    dodag.isRoot = false;
    dodag.version = dio.GetVersionNumber();
    dodag.mop = dio.GetMop();
    dodag.grounded = dio.GetGrounded();
    dodag.preference = dio.GetPreference();
    dodag.rank = RPL_INFINITE_RANK; // until a parent is picked
    dodag.pathEtx = 0;
    // RFC 6550 section 8.2.2.4 rule 3: L starts fresh for every DODAG
    // Version, this join included.
    dodag.lowestRankThisVersion = RPL_INFINITE_RANK;

    if (dio.HasDagConfiguration())
    {
        dodag.ocp = dio.GetOcp();
        dodag.minHopRankIncrease = dio.GetMinHopRankIncrease();
        dodag.maxRankIncrease = dio.GetMaxRankIncrease();
        dodag.dioIntervalMin = MilliSeconds(int64_t(1) << dio.GetIntervalMin());
        dodag.dioIntervalDoublings = dio.GetIntervalDoublings();
        dodag.dioRedundancy = dio.GetRedundancy();

        if (dodag.ocp != RPL_OCP_OF0 && dodag.ocp != RPL_OCP_MRHOF)
        {
            NS_LOG_WARN("DODAG " << dodag.dodagId << " asks for objective code point "
                                 << dodag.ocp << ", but only OF0 and MRHOF are implemented");
        }
    }

    if (dio.HasPrefixInfo())
    {
        dodag.hasPrefixInfo = true;
        dodag.prefix = dio.GetPrefix();
        dodag.prefixLength = dio.GetPrefixLength();
        dodag.prefixOnLink = dio.GetPrefixOnLink();
        dodag.prefixAutonomous = dio.GetPrefixAutonomous();
        dodag.prefixValidLifetime = dio.GetPrefixValidLifetime();
        dodag.prefixPreferredLifetime = dio.GetPrefixPreferredLifetime();

        if (dodag.prefixAutonomous)
        {
            // The standard SLAAC entry point (RFC 4862): builds the address
            // the same way GlobalAddressOf()/LinkLocalOf() already assume
            // every node's addresses are related (one interface identifier,
            // shared with the link-local address) and starts Duplicate
            // Address Detection on it asynchronously --
            // HandleDadSuccess() is what learns it is ready to use.
            uint8_t flags = (dodag.prefixOnLink ? Icmpv6OptionPrefixInformation::ONLINK : 0) |
                            Icmpv6OptionPrefixInformation::AUTADDRCONF;
            m_ipv6->AddAutoconfiguredAddress(interface,
                                             dodag.prefix,
                                             Ipv6Prefix(dodag.prefixLength),
                                             flags,
                                             dodag.prefixValidLifetime,
                                             dodag.prefixPreferredLifetime);
        }
    }

    m_disTimer.Cancel();

    // A freshly constructed DodagMembership's Timer-bearing members start
    // out with no function bound at all (unlike the old scalar members,
    // which were bound once for the node's whole lifetime in the
    // constructor/DoInitialize()): every entry is a new object, so the
    // binding -- to this specific entry's key -- happens here, once per
    // join, instead.
    dodag.dioTrickle.SetFunction(MakeCallback(&RplRoutingProtocol::DioTrickleFire, this, key));
    dodag.dioTrickle.SetParameters(dodag.dioIntervalMin,
                                   dodag.dioIntervalDoublings,
                                   dodag.dioRedundancy);
    if (m_dioTrickleStream >= 0)
    {
        dodag.dioTrickle.AssignStreams(m_dioTrickleStream);
    }
    dodag.dioTrickle.Start();

    dodag.daoEvent.SetFunction(&RplRoutingProtocol::DaoTimerExpire, this);
    dodag.daoEvent.SetArguments(key);
    dodag.daoRetryEvent.SetFunction(&RplRoutingProtocol::DaoRetry, this);
    dodag.daoRetryEvent.SetArguments(key);

    NS_LOG_INFO("Joined DODAG " << dodag.dodagId << " version " << +dodag.version);
}

void
RplRoutingProtocol::LeaveDodag(DodagKey key, bool poison)
{
    NS_LOG_FUNCTION(this << poison);

    auto it = m_dodags.find(key);
    NS_ASSERT_MSG(it != m_dodags.end(), "LeaveDodag() called for a membership that does not exist");
    DodagMembership& dodag = it->second;

    // RFC 6550 section 8.2.2.5: "A node poisons routes by advertising a
    // Rank of INFINITE_RANK", and a node that hears that from a parent
    // "cannot act as a parent any longer and is removed from the parent
    // set". Section 8.2.2.6 makes it the expected behaviour for exactly
    // this situation: a node that cannot retain a non-empty parent set
    // detaches, and SHOULD immediately advertise that.
    //
    // Going quiet instead, which is all this used to do, leaves the
    // sub-DODAG with no way to learn any of it. They keep sending DIOs at
    // this node, and this node -- unjoined from here on, so with no rank
    // of its own left for SelectPreferredParent()'s loop avoidance to
    // compare against -- would take the first one back as its new parent,
    // including one from a node that derived its own rank from this one.
    // The two then route through each other and the packet bounces between
    // them until its Hop Limit runs out.
    //
    // The poisoning DIO goes out before the membership is erased, since
    // SendDio() has nothing left to send once it is, and carries
    // INFINITE_RANK because that is what dodag.rank is set to just below --
    // and, under MRHOF, MAX_PATH_COST in its Metric Container for the same
    // reason (RFC 6719 section 3.2.2 rule 4: "the node does not have a
    // preferred parent and MUST set cur_min_path_cost to MAX_PATH_COST",
    // the worst representable cost, not 0 the best). Both have to be set
    // before this SendDio() call, not after: SendDio() reads dodag.rank and
    // dodag.pathEtx directly, so setting either afterwards would leave this
    // one poisoning DIO carrying the stale values from whatever parent
    // this node just lost.
    if (poison)
    {
        dodag.rank = RPL_INFINITE_RANK;
        dodag.pathEtx = static_cast<uint16_t>(RPL_MRHOF_MAX_PATH_COST);
        NS_LOG_INFO("Poisoning the sub-DODAG on the way out of " << dodag.dodagId);
        SendDio(dodag, Ipv6Address(RPL_ALL_NODES_MULTICAST));
    }

    // This can run from inside dodag's own Trickle-fired transmission
    // (DioTrickleFire() -> SelectPreferredParent() -> LeaveDodag(), on
    // losing the last parent): dioTrickle.Stop() here cancels the very
    // m_transmitTimer event whose callback is still on the call stack at
    // this point, the same self-cancellation DioTrickleFire()'s own comment
    // already relies on being safe (ns-3's EventId is reference-counted
    // independently of the Timer wrapper, so the Simulator's dispatch frame
    // keeps the event alive until it unwinds regardless of what the
    // callback does to the Timer that scheduled it) -- this was already
    // true of the pre-refactor code's equivalent m_dioTrickle.Stop() call
    // here, not something the DodagMembership map introduces. Explicit
    // rather than left to ~DodagMembership() purely so a reader does not
    // have to trust that reasoning about Timer/TimerImpl internals to see
    // that this is safe.
    dodag.dioTrickle.Stop();
    dodag.daoEvent.Cancel();
    dodag.daoRetryEvent.Cancel();
    m_dodags.erase(it);

    if (poison && m_hasBaseDodag && m_baseDodagKey == key)
    {
        // The base DODAG itself was just left for good. Promote a survivor
        // (in an arbitrary but deterministic order) rather than leaving
        // every base-scoped accessor (GetRank(), IsJoined(), RouteOutput(),
        // ...) blind to a node that may still be actively participating in
        // other DODAGs: existing single-DODAG scenarios never reach this
        // branch with a non-empty m_dodags left over (leaving the only
        // membership there is empties it), so this only ever activates
        // once a second membership genuinely exists.
        //
        // Gated on poison rather than running unconditionally: the other
        // caller (HandleDio()'s version-mismatch branch) passes poison =
        // false specifically because it always calls JoinDodag() for this
        // exact same key immediately afterwards, in the same event
        // ("migrating ... not detaching"). Promoting a survivor there too
        // would hand the base slot to some unrelated DODAG for the instant
        // before JoinDodag() puts this key right back -- and, worse, leave
        // it there afterwards, since m_hasBaseDodag would already be true
        // by the time JoinDodag() runs its own "assign if none yet" check.
        // Leaving m_baseDodagKey untouched here instead means it is still
        // exactly the key JoinDodag() is about to reinsert, so the base
        // identity survives the migration unchanged, which is the whole
        // point of not poisoning on the way out.
        m_hasBaseDodag = !m_dodags.empty();
        if (m_hasBaseDodag)
        {
            m_baseDodagKey = m_dodags.begin()->first;
        }
    }
}

Ipv6Address
RplRoutingProtocol::GlobalAddressOf(const DodagMembership& dodag, Ipv6Address linkLocal) const
{
    if (dodag.dodagId.IsAny() || linkLocal.IsAny())
    {
        return Ipv6Address::GetAny();
    }

    uint8_t prefix[16];
    uint8_t identifier[16];
    dodag.dodagId.GetBytes(prefix);
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
RplRoutingProtocol::SendDao(DodagMembership& dodag)
{
    NS_LOG_FUNCTION(this);

    if (dodag.isRoot || dodag.preferredParent.IsAny())
    {
        return;
    }

    if (dodag.mop == RPL_MOP_P2P_ROUTE_DISCOVERY)
    {
        // AODV-RPL "does not utilize the Destination Advertisement Object
        // (DAO) control message of RPL" (RFC 9854 section 1) -- its routes
        // come from the RREQ/RREP exchange instead. The guard above is not
        // enough on its own: an intermediate router in an RREQ-Instance is
        // not the root and does have a preferred parent, so without this it
        // would advertise itself to the OrigNode as if this were an
        // ordinary DODAG.
        return;
    }

    Ipv6Address target = GetGlobalAddressIn(dodag);
    Ipv6Address parent = GlobalAddressOf(dodag, dodag.preferredParent);
    if (target.IsAny() || parent.IsAny())
    {
        NS_LOG_LOGIC("Not advertising yet: no global address for this node or its parent");
        return;
    }

    RplDaoHeader dao;
    dao.SetInstanceId(dodag.instanceId);
    dao.SetDodagId(dodag.dodagId);
    dao.SetSequence(++dodag.daoSequence);
    dao.SetAckRequested(true);
    dao.SetTarget(target);
    dao.SetTransitInformation(parent, dodag.pathSequence, m_pathLifetime);

    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(dao);

    // The DAO is addressed to the root and finds its way there hop by hop, on
    // the upward routes the DIOs built.
    SendRplMessageUnicast(packet, RPL_CODE_DAO, dodag.dodagId);

    dodag.daoAckPending = true;
    dodag.daoRetriesLeft = m_daoRetries;
    dodag.daoRetryEvent.Cancel();
    dodag.daoRetryEvent.Schedule(m_daoAckTimeout);
}

void
RplRoutingProtocol::SendNoPathDao(DodagMembership& dodag, Ipv6Address viaParent)
{
    NS_LOG_FUNCTION(this << viaParent);

    if (dodag.mop == RPL_MOP_P2P_ROUTE_DISCOVERY)
    {
        // The same reason SendDao() refuses: AODV-RPL uses no DAO of any
        // kind (RFC 9854 section 1), a No-Path DAO included. Reached
        // whenever a route-discovery instance loses its last parent, which
        // is exactly what happens as the discovery winds down.
        return;
    }

    Ipv6Address target = GetGlobalAddressIn(dodag);
    Ipv6Address parent = GlobalAddressOf(dodag, viaParent);
    if (target.IsAny() || parent.IsAny())
    {
        NS_LOG_LOGIC("Not withdrawing: no global address for this node or the parent it was "
                    "last reachable through");
        return;
    }

    RplDaoHeader dao;
    dao.SetInstanceId(dodag.instanceId);
    dao.SetDodagId(dodag.dodagId);
    dao.SetSequence(++dodag.daoSequence);
    dao.SetTarget(target);
    // Path Lifetime 0, RFC 6550 section 6.4.3: a No-Path. The path sequence
    // still has to advance, the same as any other DAO with new information
    // (RFC 6550 section 9.3 rule 1) -- this is what lets the root tell an
    // in-flight withdrawal apart from a stale, reordered copy of the
    // advertisement it is withdrawing.
    dao.SetTransitInformation(parent, ++dodag.pathSequence, 0);

    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(dao);

    NS_LOG_INFO("Withdrawing " << target << ", last reachable via " << viaParent);
    SendRplMessageUnicast(packet, RPL_CODE_DAO, dodag.dodagId);
}

void
RplRoutingProtocol::DaoTimerExpire(DodagKey key)
{
    NS_LOG_FUNCTION(this);

    auto it = m_dodags.find(key);
    if (it == m_dodags.end())
    {
        return;
    }
    DodagMembership& dodag = it->second;

    SendDao(dodag);
    dodag.daoEvent.Cancel();
    dodag.daoEvent.Schedule(m_daoInterval);
}

void
RplRoutingProtocol::DaoRetry(DodagKey key)
{
    auto it = m_dodags.find(key);
    if (it == m_dodags.end())
    {
        return;
    }
    DodagMembership& dodag = it->second;

    NS_LOG_FUNCTION(this << +dodag.daoRetriesLeft);

    if (!dodag.daoAckPending)
    {
        return;
    }

    if (dodag.daoRetriesLeft == 0)
    {
        // The path is not getting through. The next periodic DAO will try
        // again, by then possibly through a different parent.
        NS_LOG_WARN("No DAO-ACK for sequence " << +dodag.daoSequence << ", giving up until the "
                                                                    "next refresh");
        dodag.daoAckPending = false;
        return;
    }

    dodag.daoRetriesLeft--;

    RplDaoHeader dao;
    dao.SetInstanceId(dodag.instanceId);
    dao.SetDodagId(dodag.dodagId);
    dao.SetSequence(dodag.daoSequence);
    dao.SetAckRequested(true);
    dao.SetTarget(GetGlobalAddressIn(dodag));
    dao.SetTransitInformation(GlobalAddressOf(dodag, dodag.preferredParent),
                              dodag.pathSequence,
                              m_pathLifetime);

    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(dao);
    SendRplMessageUnicast(packet, RPL_CODE_DAO, dodag.dodagId);

    dodag.daoRetryEvent.Cancel();
    dodag.daoRetryEvent.Schedule(m_daoAckTimeout);
}

void
RplRoutingProtocol::HandleDao(const RplDaoHeader& dao, Ipv6Address from)
{
    NS_LOG_FUNCTION(this << from);

    // Resolved by the DODAG the DAO itself names, not GetBaseDodag(): a
    // node rooting a CreateLocalDodag()-formed DODAG (m_isRoot false, since
    // it never called SetAsRoot() for the base) must still be able to
    // receive DAOs for that DODAG. The D flag clear (RFC 6550 section 6.4,
    // dao.GetDodagId().IsAny()) falls back to resolving by RPLInstanceID
    // alone, the same limit FindDodagByInstance() documents elsewhere.
    DodagMembership* dodag = nullptr;
    if (!dao.GetDodagId().IsAny())
    {
        auto it = m_dodags.find(DodagKey{dao.GetInstanceId(), dao.GetDodagId()});
        if (it != m_dodags.end() && it->second.isRoot)
        {
            dodag = &it->second;
        }
    }
    else
    {
        DodagMembership* candidate = FindDodagByInstance(dao.GetInstanceId());
        if (candidate && candidate->isRoot)
        {
            dodag = candidate;
        }
    }
    if (!dodag)
    {
        // In non-storing mode a DAO is addressed to the root, so either the
        // sender is confused about who the root is, or this DAO belongs to
        // a DODAG this node does not root at all.
        NS_LOG_LOGIC("Ignoring a DAO from " << from << ": this node does not root the DODAG it "
                                                        "names");
        return;
    }

    Ipv6Address target = dao.GetTarget();
    if (target.IsAny())
    {
        NS_LOG_WARN("Ignoring a DAO from " << from << " with no target");
        return;
    }

    // An entry whose lifetime has already run out has no say in what may
    // supersede it: ComputeSourceRoute() refuses to build a path over one
    // regardless, so leaving it standing here would only let a long-dead
    // Path Sequence lock its target out of the topology. Purged on the spot
    // rather than left to PurgeTopology(), which only runs when the root
    // itself has traffic to route.
    auto existing = dodag->topology.find(target);
    if (existing != dodag->topology.end() && existing->second.expire <= Simulator::Now())
    {
        dodag->topology.erase(existing);
        existing = dodag->topology.end();
    }

    // RFC 6550 section 7.1 on the Path Sequence: "An older (lesser) value
    // received from an originating router indicates that the originating
    // router holds stale routing states and the originating router should not
    // be considered anymore as a potential next hop for the target." Section
    // 9.2.1 has the counter advance on exactly the two events that produce
    // the race -- "the Path Lifetime is to be updated (e.g., a refresh or a
    // no-Path)" and "the DODAG Parent Address subfield list is to be changed"
    // -- and a node that switches parent does both at once: it withdraws
    // through the parent it is leaving and re-advertises through the new one,
    // so the two DAOs climb disjoint paths and can arrive in either order.
    // Acting on the withdrawal after the re-advertisement has overtaken it
    // drops the target from the topology altogether, black-holing everything
    // headed its way until its next periodic refresh.
    //
    // An equal Path Sequence is not stale: section 9.2.1's "All DAOs
    // generated at the same time for the same Target MUST be sent with the
    // same Path Sequence" covers the retransmissions DaoRetry() sends, and
    // this implementation's periodic refresh repeats the sequence it last
    // advertised, so refusing equality would expire every route in the DODAG
    // exactly once per PathLifetime. One that cannot be ordered at all is,
    // per section 7.2 rule 4: leaving the entry alone is what "minimize[s]
    // the resulting changes to its own state".
    RplSequenceOrder order = existing == dodag->topology.end()
                                 ? RplSequenceOrder::GREATER
                                 : RplSequenceCompare(dao.GetPathSequence(),
                                                      existing->second.pathSequence);
    bool stale =
        order == RplSequenceOrder::LESS || order == RplSequenceOrder::NOT_COMPARABLE;

    if (stale)
    {
        NS_LOG_INFO("Ignoring a DAO for " << target << " with Path Sequence "
                                          << +dao.GetPathSequence() << ", superseded by "
                                          << +existing->second.pathSequence);
    }
    else if (dao.GetPathLifetime() == 0)
    {
        // A No-Path, RFC 6550 section 6.4.3: the target has moved away.
        NS_LOG_INFO("No-Path for " << target << ", dropping it from the topology");
        dodag->topology.erase(target);
    }
    else
    {
        TopologyEntry& entry = dodag->topology[target];
        entry.parent = dao.GetParent();
        entry.pathSequence = dao.GetPathSequence();
        // RFC 6550 section 6.7.8: the Path Lifetime is "The length of time in
        // Lifetime Units ... that the prefix is valid for route
        // determination", except that "A value of all one bits (0xFF)
        // represents infinity". Multiplied out like any other value, that
        // largest of all lifetimes would instead be a merely long one, and
        // the route the sender asked to have kept indefinitely would be
        // dropped 255 lifetime units in.
        entry.expire = dao.GetPathLifetime() == RPL_INFINITE_LIFETIME
                           ? Time::Max()
                           : Simulator::Now() + Seconds(dao.GetPathLifetime() * m_lifetimeUnit);
        NS_LOG_INFO("Topology: " << target << " sits under " << entry.parent);
    }

    // Acknowledged even when it was ignored as stale above. RFC 6550 section
    // 7.1 has the DAOSequence a DAO-ACK carries be "locally significant to
    // the node that issues a DAO message for its own consumption to detect
    // the loss of a DAO message and enable retries": what it reports is that
    // the message arrived, not what the root did with it. Withholding it
    // would only have the sender retransmit, m_daoRetries times over, a
    // message the root discards on the same grounds every time -- and the
    // sender is by then waiting on the DAO-ACK of the newer DAO that
    // superseded this one, under a DAOSequence this reply does not match.
    if (dao.GetAckRequested())
    {
        RplDaoAckHeader daoAck;
        daoAck.SetInstanceId(dodag->instanceId);
        daoAck.SetDodagId(dodag->dodagId);
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

    // Resolved by the DODAG the DAO-ACK itself names (HandleDao() stamps
    // both onto every DAO-ACK it sends, from the DAO that earned it), not
    // GetBaseDodag(): with more than one membership pending its own DAO at
    // once, a DAO-ACK from a non-base DODAG's root must not be applied to
    // the base membership's daoAckPending/daoRetryEvent instead, which
    // would leave the actual target membership retrying forever despite
    // having already been acknowledged.
    auto it = m_dodags.find(DodagKey{daoAck.GetInstanceId(), daoAck.GetDodagId()});
    if (it == m_dodags.end())
    {
        return;
    }
    DodagMembership* dodag = &it->second;

    if (daoAck.GetSequence() != dodag->daoSequence)
    {
        NS_LOG_LOGIC("Ignoring a DAO-ACK for sequence " << +daoAck.GetSequence() << ", waiting "
                                                        << "for " << +dodag->daoSequence);
        return;
    }

    if (daoAck.GetStatus() != 0)
    {
        NS_LOG_WARN("The root rejected the DAO with status " << +daoAck.GetStatus());
        return;
    }

    NS_LOG_INFO("The root acknowledged DAO " << +dodag->daoSequence);
    dodag->daoAckPending = false;
    dodag->daoRetryEvent.Cancel();
}

void
RplRoutingProtocol::PurgeTopology(DodagMembership& dodag)
{
    Time now = Simulator::Now();
    for (auto it = dodag.topology.begin(); it != dodag.topology.end();)
    {
        it = (it->second.expire <= now) ? dodag.topology.erase(it) : std::next(it);
    }
}

RplRoutingProtocol::DodagMembership*
RplRoutingProtocol::FindDodagByInstance(uint8_t instanceId)
{
    auto it = m_dodags.lower_bound(DodagKey{instanceId, Ipv6Address::GetAny()});
    return (it != m_dodags.end() && it->first.instanceId == instanceId) ? &it->second : nullptr;
}

const RplRoutingProtocol::DodagMembership*
RplRoutingProtocol::FindDodagByInstance(uint8_t instanceId) const
{
    auto it = m_dodags.lower_bound(DodagKey{instanceId, Ipv6Address::GetAny()});
    return (it != m_dodags.end() && it->first.instanceId == instanceId) ? &it->second : nullptr;
}

bool
RplRoutingProtocol::ReadRpiInstanceId(Ptr<const Packet> p,
                                      const Ipv6Header& header,
                                      uint8_t& instanceId) const
{
    if (header.GetNextHeader() != Ipv6Header::IPV6_EXT_HOP_BY_HOP)
    {
        return false;
    }

    // The RPI is always the first (and, on this module's own traffic, only)
    // option in the Hop-by-Hop header, immediately after its own 2-octet
    // Next Header/Hdr Ext Len prefix: PrepareOutgoingPacket() is the only
    // writer, RplPacketInfoHeader declares no alignment that would ever get
    // a Pad1/PadN inserted ahead of it, and every hop after that only
    // rewrites it in place (RplIpv6OptionRpl::Process()), never removes or
    // reorders it. A copy, not the real packet: this is a look, not a
    // consume, and RouteInput()'s caller still owns p.
    Ptr<Packet> fragment = p->Copy();
    if (fragment->GetSize() < 2)
    {
        return false;
    }
    fragment = fragment->CreateFragment(2, fragment->GetSize() - 2);

    RplPacketInfoHeader rpi;
    if (fragment->GetSize() < rpi.GetSerializedSize() || fragment->RemoveHeader(rpi) == 0)
    {
        return false;
    }
    if (rpi.IsMalformed())
    {
        return false;
    }
    // RplPacketInfoHeader::Deserialize() reads whatever Option Type byte is
    // there and stores it (Ipv6OptionHeader::SetType()) without checking it
    // actually is RPL_HBH_OPTION_TYPE (0x63) -- the ordinary Ipv6OptionDemux-
    // driven dispatch path never needs to check because the demux itself
    // already only calls RplIpv6OptionRpl::Process() for that type, but this
    // is a direct, offset-based read with no such dispatch in front of it.
    // Without this, the first Hop-by-Hop option being anything else at all
    // (Pad1/PadN in particular, RFC 8200 section 4.2, needed whenever the
    // real first option does not already land on this header's 2-octet
    // alignment) has its bytes misread as a fabricated RPI, handing an
    // attacker- or protocol-controlled RPLInstanceID straight into the
    // forwarding decision.
    if (rpi.GetType() != RPL_HBH_OPTION_TYPE)
    {
        return false;
    }

    instanceId = rpi.GetInstanceId();
    return true;
}

RplRoutingProtocol::DodagMembership*
RplRoutingProtocol::FindRootDodagFor(Ipv6Address destination, std::vector<Ipv6Address>& hops)
{
    DodagMembership* base = GetBaseDodag();
    if (base && base->isRoot)
    {
        PurgeTopology(*base);
        if (ComputeSourceRoute(*base, destination, hops))
        {
            return base;
        }
    }

    for (auto& [key, other] : m_dodags)
    {
        if (&other == base || !other.isRoot)
        {
            continue;
        }
        PurgeTopology(other);
        if (ComputeSourceRoute(other, destination, hops))
        {
            return &other;
        }
    }

    return nullptr;
}

bool
RplRoutingProtocol::ComputeSourceRoute(const DodagMembership& dodag,
                                       Ipv6Address destination,
                                       std::vector<Ipv6Address>& hops) const
{
    hops.clear();

    if (!dodag.isRoot || dodag.topology.find(destination) == dodag.topology.end())
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
    for (size_t step = 0; step <= dodag.topology.size(); step++)
    {
        auto it = dodag.topology.find(current);
        if (it == dodag.topology.end() || it->second.expire <= now)
        {
            return false;
        }

        globalChain.push_back(current);
        current = it->second.parent;
        if (current == dodag.dodagId)
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

bool
RplRoutingProtocol::ComputeSourceRoute(Ipv6Address destination,
                                       std::vector<Ipv6Address>& hops) const
{
    const DodagMembership* dodag = GetBaseDodag();
    if (!dodag)
    {
        hops.clear();
        return false;
    }
    return ComputeSourceRoute(*dodag, destination, hops);
}

bool
RplRoutingProtocol::ComputeSourceRoute(uint8_t instanceId,
                                       Ipv6Address dodagId,
                                       Ipv6Address destination,
                                       std::vector<Ipv6Address>& hops) const
{
    auto it = m_dodags.find(DodagKey{instanceId, dodagId});
    if (it == m_dodags.end())
    {
        hops.clear();
        return false;
    }
    return ComputeSourceRoute(it->second, destination, hops);
}

uint32_t
RplRoutingProtocol::InterfaceForNeighbour(const DodagMembership& dodag, Ipv6Address neighbour) const
{
    // A neighbour is known by its link-local address, so it is the interface
    // identifier that tells which of them the global address belongs to.
    uint8_t wanted[16];
    neighbour.GetBytes(wanted);

    for (const auto& [address, parent] : dodag.parents)
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
RplRoutingProtocol::RouteToNeighbour(const DodagMembership* dodag,
                                     Ipv6Address neighbour,
                                     Ipv6Address dst) const
{
    uint32_t interface = dodag ? InterfaceForNeighbour(*dodag, neighbour) : 0;
    if (interface == 0)
    {
        // No membership, or nothing was ever heard from that neighbour: on
        // a node with a single RPL interface there is only one answer
        // anyway, which InterfaceForNeighbour() itself falls back to when it
        // has a dodag to consult. Without one at all (this node has not
        // joined anything), the same single-interface fallback still
        // applies, so it is repeated here rather than special-cased away.
        interface = m_ifcToSocket.empty() ? 0 : m_ifcToSocket.begin()->first;
        if (interface == 0)
        {
            return nullptr;
        }
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

Ptr<Ipv6Route>
RplRoutingProtocol::RouteToNeighbour(Ipv6Address neighbour, Ipv6Address dst) const
{
    return RouteToNeighbour(GetBaseDodag(), neighbour, dst);
}

Ptr<Ipv6Route>
RplRoutingProtocol::RouteToNeighbour(uint8_t instanceId, Ipv6Address neighbour, Ipv6Address dst) const
{
    return RouteToNeighbour(FindDodagByInstance(instanceId), neighbour, dst);
}

uint32_t
RplRoutingProtocol::GetTopologySize() const
{
    const DodagMembership* dodag = GetBaseDodag();
    return dodag ? dodag->topology.size() : 0;
}

uint16_t
RplRoutingProtocol::RankViaParent(const DodagMembership& dodag,
                                  const Parent& parent,
                                  uint32_t* pathCost) const
{
    if (parent.rank == RPL_INFINITE_RANK)
    {
        return RPL_INFINITE_RANK;
    }

    uint32_t rank = static_cast<uint32_t>(parent.rank) + dodag.minHopRankIncrease;
    if (dodag.ocp == RPL_OCP_MRHOF)
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
RplRoutingProtocol::SelectPreferredParent(DodagMembership& dodag)
{
    NS_LOG_FUNCTION(this);

    if (dodag.isRoot)
    {
        return false;
    }

    // Two maximum DIO intervals without a DIO is two missed announcements in a
    // row, which is taken as the neighbour being gone.
    Time maxInterval = dodag.dioIntervalMin * (int64_t(1) << dodag.dioIntervalDoublings);
    Time staleBefore = Simulator::Now() - 2 * maxInterval;
    for (auto it = dodag.parents.begin(); it != dodag.parents.end();)
    {
        if (it->second.lastHeard < staleBefore)
        {
            NS_LOG_LOGIC("Dropping the stale neighbour " << it->first);
            // Withdrawing has to happen here, before erase(), rather than
            // down at the best.IsAny() case below: RouteOutput() (and so
            // SendRplMessageUnicast(), which SendNoPathDao() goes through
            // the same way SendDao() does) resolves a route for a
            // non-root node purely from dodag.parents.find(preferredParent)
            // -- with the entry already gone, there would be nothing left
            // to route the withdrawal through even though the address it
            // names is still perfectly reachable.
            if (it->first == dodag.preferredParent)
            {
                SendNoPathDao(dodag, it->first);
            }
            it = dodag.parents.erase(it);
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
    bool haveFresh = std::any_of(dodag.parents.begin(), dodag.parents.end(), [](const auto& entry) {
        return entry.second.freshness >= RPL_FRESHNESS_TARGET;
    });

    // The rank this node had on entry is what decides which neighbours are
    // usable, so that recomputing the rank cannot make a node adopt one of its
    // own children as a parent. The exception is a rank inherited from a
    // neighbour that has since turned out to be stale: keeping it would lock
    // the node onto a bad link, because the fresh neighbours below that rank
    // would all be rejected.
    //
    // That exception is deliberately not a free pass, though: relaxing the
    // bound all the way to INFINITE_RANK would also let back in the
    // neighbours that derived their own rank from this node's DIOs, i.e.
    // this node's sub-DODAG, and adopting one of those is a routing loop
    // (RFC 6550 section 8.2.2.4) -- one that in this implementation cannot
    // even be broken by the RPL Option's rank check, which can trace a
    // packet as dropped but not actually stop it (@see
    // doc/design-constraints.md section 12.1). Any neighbour a full
    // MinHopRankIncrease worse than this node could be exactly that, since
    // that is the rank a child of this node computes; the relaxation stops
    // there. A node with no rank of its own has no sub-DODAG either, so
    // that case relaxes to everything, as before.
    uint16_t currentRank = dodag.rank;
    auto preferred = dodag.parents.find(dodag.preferredParent);
    if (haveFresh &&
        (preferred == dodag.parents.end() || preferred->second.freshness < RPL_FRESHNESS_TARGET))
    {
        uint32_t childRank = uint32_t(dodag.rank) + dodag.minHopRankIncrease;
        currentRank = (childRank >= RPL_INFINITE_RANK) ? RPL_INFINITE_RANK
                                                       : static_cast<uint16_t>(childRank);
    }

    Ipv6Address best = Ipv6Address::GetAny();
    uint16_t bestRank = RPL_INFINITE_RANK;
    uint32_t bestPathCost = std::numeric_limits<uint32_t>::max();

    // Two passes over the candidates. The first keeps to the established
    // neighbours; the second, entered only when the first found nothing at
    // all, drops that restriction.
    //
    // Freshness has to be a preference rather than a requirement, because
    // the two filters below interact badly when it is not: the neighbours
    // that are established can all still be rejected by the rank check
    // (they sit below this node, so taking one would be a loop), and a node
    // that then finds itself with no parent leaves the DODAG, clears its
    // parent set, and takes whichever DIO happens to arrive first -- quite
    // possibly one from its own sub-DODAG, which is the very loop the rank
    // check just refused. A neighbour heard three times is a real
    // neighbour; provisionally trusting it costs far less than that.
    bool requireFresh = haveFresh;
    for (uint8_t pass = 0; pass < 2 && best.IsAny(); pass++)
    {
        requireFresh = haveFresh && pass == 0;

        for (const auto& [address, parent] : dodag.parents)
        {
            if (requireFresh && parent.freshness < RPL_FRESHNESS_TARGET)
            {
                NS_LOG_LOGIC("Neighbour " << address << " has only been heard "
                                          << +parent.freshness << " times");
                continue;
            }

            if (currentRank != RPL_INFINITE_RANK && parent.rank >= currentRank)
            {
                NS_LOG_LOGIC("Neighbour " << address << " is not closer to the root than we are");
                continue;
            }

            if (dodag.ocp == RPL_OCP_MRHOF && parent.etx > RPL_MRHOF_MAX_LINK_METRIC)
            {
                // RFC 6719 section 5, verbatim: "If the selected metric for a
                // link is greater than MAX_LINK_METRIC, the node SHOULD
                // exclude that link from consideration." Strictly greater --
                // MAX_LINK_METRIC is itself the worst *allowed* value (the
                // Terminology section defines it as "Maximum allowed value
                // for the selected link metric"), not the first disallowed
                // one.
                NS_LOG_LOGIC("Neighbour " << address << " has too high a link ETX");
                continue;
            }

            uint32_t pathCost = 0;
            uint16_t rank = RankViaParent(dodag, parent, &pathCost);
            if (rank == RPL_INFINITE_RANK)
            {
                continue;
            }

            if (dodag.ocp == RPL_OCP_MRHOF)
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
    }

    if (dodag.ocp == RPL_OCP_MRHOF && !best.IsAny())
    {
        // RFC 6719 section 3.3: hysteresis. Keep the current preferred
        // parent over a candidate of lower path cost unless the difference
        // exceeds PARENT_SWITCH_THRESHOLD, so the node does not flap between
        // parents of near-identical quality. The current parent still has
        // to clear the same freshness and loop-avoidance filters applied to
        // every other candidate above -- the freshness one exactly as far
        // as the pass that produced best applied it, so that hysteresis
        // neither rejects the current parent on a rule the winner was not
        // held to, nor keeps a stale or newly-looped parent selected
        // indefinitely.
        auto current = dodag.parents.find(dodag.preferredParent);
        if (current != dodag.parents.end() &&
            (!requireFresh || current->second.freshness >= RPL_FRESHNESS_TARGET) &&
            (currentRank == RPL_INFINITE_RANK || current->second.rank < currentRank) &&
            // Mirrors the candidate loop's own link ETX bound above (>
            // RPL_MRHOF_MAX_LINK_METRIC excludes), so a link exactly at
            // MAX_LINK_METRIC is not held to a stricter rule here, as the
            // current preferred parent, than it was as an ordinary candidate.
            current->second.etx <= RPL_MRHOF_MAX_LINK_METRIC)
        {
            uint32_t currentPathCost = 0;
            uint16_t currentCandidateRank = RankViaParent(dodag, current->second, &currentPathCost);
            if (currentCandidateRank != RPL_INFINITE_RANK &&
                currentPathCost < RPL_MRHOF_MAX_PATH_COST &&
                // RFC 6719 section 3.2.2 rule 3, verbatim: "If the smallest
                // path cost for paths through the candidate neighbors is
                // smaller than cur_min_path_cost by less than
                // PARENT_SWITCH_THRESHOLD, the node MAY continue to use the
                // current preferred parent." Strictly less: at a difference
                // of exactly PARENT_SWITCH_THRESHOLD, that condition does not
                // hold, and the MUST rule above it -- select the lowest path
                // cost -- applies instead.
                currentPathCost < bestPathCost + RPL_MRHOF_PARENT_SWITCH_THRESHOLD)
            {
                best = dodag.preferredParent;
                bestRank = currentCandidateRank;
                bestPathCost = currentPathCost;
            }
        }
    }

    // Under MRHOF the rank can stay floor-clamped at parent.rank +
    // MinHopRankIncrease (RFC 6719 section 3.3) while the underlying path
    // cost still drifts, so the path cost has to be compared too -- looking
    // only at rank/parent would leave the advertised pathEtx stale.
    bool pathCostChanged = dodag.ocp == RPL_OCP_MRHOF && !best.IsAny() &&
                          static_cast<uint16_t>(bestPathCost) != dodag.pathEtx;
    bool changed = (best != dodag.preferredParent) || (bestRank != dodag.rank) || pathCostChanged;
    if (!changed)
    {
        return false;
    }

    if (best.IsAny())
    {
        NS_LOG_INFO("Lost the last parent of DODAG " << dodag.dodagId << ", soliciting again");
        // RFC 6550 section 9.8 rule 4 / the general rule a few paragraphs
        // later ("when a DAO entry times out or is invalidated, a node
        // SHOULD make a reasonable attempt to report a No-Path"): tried on
        // a best-effort basis, before LeaveDodag() clears it below. This is
        // the fallback for the rank/ETX case, where the preferred parent
        // fell out of contention without ever going stale, so it is still
        // in dodag.parents (and so still routable, @see the staleness loop
        // above, which already handles the more common stale case before
        // this point, since erasing it there happens after this function
        // was entered but before best.IsAny() could ever be evaluated).
        if (!dodag.preferredParent.IsAny() &&
            dodag.parents.find(dodag.preferredParent) != dodag.parents.end())
        {
            SendNoPathDao(dodag, dodag.preferredParent);
        }
        // Detaching for want of a parent: poison on the way out, so the
        // sub-DODAG stops treating this node as a way to the root. This
        // erases dodag's own entry from m_dodags -- dodag must not be used
        // again after this call.
        DodagKey key{dodag.instanceId, dodag.dodagId};
        LeaveDodag(key, true);
        m_disTimer.Cancel();
        m_disTimer.Schedule(Seconds(m_jitter->GetValue(0.0, 1.0)));
        return true;
    }

    NS_LOG_INFO("Preferred parent is " << best << ", rank " << bestRank << " (was "
                                       << dodag.preferredParent << ", rank " << dodag.rank << ")");
    bool parentChanged = (best != dodag.preferredParent);
    dodag.preferredParent = best;
    dodag.rank = bestRank;
    if (dodag.ocp == RPL_OCP_MRHOF)
    {
        dodag.pathEtx = static_cast<uint16_t>(bestPathCost);
    }

    // RFC 6550 section 8.2.2.4 rule 3: "that node MUST NOT advertise an
    // effective Rank higher than L + DAGMaxRankIncrease. ... If a node's
    // Rank were to be higher than allowed ..., when it advertises Rank, it
    // MUST advertise its Rank as INFINITE_RANK." A guard against
    // count-to-infinity independent of the loop avoidance already applied
    // above (during candidate selection) and in HandleDio()'s poisoning
    // check (once a neighbour's own rank goes infinite): this one catches
    // a rank that keeps climbing gradually, one valid-looking parent
    // switch at a time, without any single step tripping either of those.
    // uint32_t sidesteps lowestRankThisVersion + maxRankIncrease
    // overflowing the uint16_t both operands are.
    if (uint32_t(dodag.rank) > uint32_t(dodag.lowestRankThisVersion) + dodag.maxRankIncrease)
    {
        NS_LOG_INFO("Rank " << dodag.rank << " exceeds L (" << dodag.lowestRankThisVersion
                            << ") + DAGMaxRankIncrease (" << dodag.maxRankIncrease
                            << ") for this DODAG Version, advertising INFINITE_RANK instead");
        dodag.rank = RPL_INFINITE_RANK;
    }
    else
    {
        dodag.lowestRankThisVersion = std::min(dodag.lowestRankThisVersion, dodag.rank);
    }

    if (parentChanged && dodag.mop != RPL_MOP_P2P_ROUTE_DISCOVERY)
    {
        // RFC 6550, section 9.5: a node that changes parent has to tell the
        // root about it. The path sequence is what lets the root tell the new
        // report from the one the old parent may still be relaying. Not for
        // an AODV-RPL instance, which sends no DAOs at all (@see SendDao()).
        dodag.pathSequence++;
        dodag.daoEvent.Cancel();
        dodag.daoEvent.Schedule(Seconds(m_jitter->GetValue(0.0, 1.0)));
    }
    return true;
}

Ptr<Ipv6Route>
RplRoutingProtocol::RouteViaPreferredParent(const DodagMembership& dodag, Ipv6Address dst) const
{
    if (dodag.preferredParent.IsAny())
    {
        return nullptr;
    }

    auto it = dodag.parents.find(dodag.preferredParent);
    if (it == dodag.parents.end())
    {
        return nullptr;
    }

    uint32_t interface = it->second.interface;

    // Ipv6L3Protocol::SourceAddressSelection() asserts outright if the
    // interface has no global address at all, rather than returning a
    // sentinel this caller could check -- reasonable for its own callers,
    // which only ever ask once a node's addressing has settled, but not
    // for a route that can be requested (RouteInput() forwarding another
    // node's packet, in particular) before this node's own SLAAC on the
    // relevant DODAG has necessarily finished. Checked here instead of
    // relying on the caller to know when that is safe: "no route yet" is
    // this function's ordinary way of saying not ready, everywhere else it
    // already applies (dodag.preferredParent.IsAny(), the parents lookup
    // above), so a transiently addressless interface joins them rather
    // than crashing the node that happened to be relaying at the wrong
    // moment.
    bool hasGlobalAddress = false;
    for (uint32_t i = 0; i < m_ipv6->GetNAddresses(interface); i++)
    {
        if (m_ipv6->GetAddress(interface, i).GetScope() == Ipv6InterfaceAddress::GLOBAL)
        {
            hasGlobalAddress = true;
            break;
        }
    }
    if (!hasGlobalAddress)
    {
        return nullptr;
    }

    Ptr<Ipv6Route> route = Create<Ipv6Route>();
    route->SetDestination(dst);
    route->SetGateway(dodag.preferredParent);
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
    // Any DODAG this node itself roots can put a path into a packet -- the
    // base one, or one CreateLocalDodag() formed at runtime -- not only the
    // base (FindRootDodagFor() tries the base first, so a node with only
    // that one behaves exactly as before). dodag itself stays the base
    // membership below: the two blocks after this one deliberately still
    // mean "the base DODAG", for the non-base-DODAG's-own-DODAGID fallback
    // and the base fallback respectively.
    DodagMembership* dodag = GetBaseDodag();
    {
        // A route an AODV-RPL discovery found, tried first: it was asked for
        // explicitly, for this destination, and is by construction shorter
        // than the path through the base DODAG's root that the fallbacks
        // below would take.
        std::vector<Ipv6Address> aodvHops;
        uint8_t aodvInstanceId = 0;
        if (FindAodvRoute(dst, aodvHops, aodvInstanceId))
        {
            NS_ASSERT(!aodvHops.empty());
            NS_LOG_LOGIC("Source routing " << dst << " over an AODV-RPL route of "
                                           << aodvHops.size() << " hop(s), first hop "
                                           << aodvHops.front());
            Ptr<Ipv6Route> route = RouteToNeighbour(aodvInstanceId, aodvHops.front(), dst);
            if (route)
            {
                return route;
            }
        }
    }

    {
        std::vector<Ipv6Address> hops;
        if (DodagMembership* root = FindRootDodagFor(dst, hops))
        {
            NS_ASSERT(!hops.empty());
            NS_LOG_LOGIC("Source routing " << dst << " through " << (hops.size() - 1)
                                           << " intermediate router(s), first hop "
                                           << hops.front());
            Ptr<Ipv6Route> route = RouteToNeighbour(root->instanceId, hops.front(), dst);
            if (route)
            {
                return route;
            }
        }
    }

    // dst may be some OTHER DODAG's own DODAGID: the only unicast traffic a
    // non-root membership ever originates besides its DIOs (multicast, so
    // never seen here) is its own DAO/DAO-ACK-retry, always addressed to
    // that DODAG's DODAGID (SendDao(), SendNoPathDao(), DaoRetry()).
    // Checked, and returned on a match, before the base DODAG's fallback
    // below: RouteViaPreferredParent() builds a route from nothing but
    // dodag.preferredParent and dodag.parents -- it does not check dst
    // against the DODAG at all -- so the base DODAG's own attempt would
    // otherwise succeed unconditionally for ANY destination as long as it
    // has picked a preferred parent, silently absorbing this traffic
    // before this loop ever ran. Without this running first, a non-base
    // membership could join and rank successfully but never actually get a
    // route registered at its own root, its DAO instead heading towards
    // the base DODAG's parent, who has no idea what to do with it.
    for (auto& [key, other] : m_dodags)
    {
        if (dodag == &other || other.dodagId != dst)
        {
            continue;
        }
        Ptr<Ipv6Route> route = RouteViaPreferredParent(other, dst);
        if (route)
        {
            NS_LOG_LOGIC("Routing " << dst << " (a non-base DODAG's own DODAGID) via its "
                                    << "preferred parent " << other.preferredParent);
            return route;
        }
    }

    if (dodag)
    {
        Ptr<Ipv6Route> route = RouteViaPreferredParent(*dodag, dst);
        if (route)
        {
            NS_LOG_LOGIC("Routing " << dst << " via the preferred parent "
                                    << dodag->preferredParent);
            return route;
        }
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

    // route is whatever RouteOutput() (this node's own, or Ipv6ListRouting
    // fanning this hook out to every member protocol when RPL is composed
    // with another one -- see Ipv6ListRouting::PrepareOutgoingPacket())
    // resolved for this packet. If it does not actually leave on an
    // interface RPL runs on, this packet is not RPL's to touch: neither the
    // Routing Header nor the RPL Option belong on wire the packet takes some
    // other way out, and the RPL Option in particular has its Option Type's
    // "unrecognized option" bits set to discard the whole packet, which a
    // receiver that never runs RPL has no way to make sense of.
    int32_t outInterface = m_ipv6->GetInterfaceForDevice(route->GetOutputDevice());
    if (outInterface < 0 || m_ifcToSocket.find(static_cast<uint32_t>(outInterface)) ==
                                m_ifcToSocket.end())
    {
        return;
    }

    uint8_t innerNextHeader = header.GetNextHeader();
    bool hasRoutingHeader = false;

    // The Routing Header (RFC 6554): only a node that roots the DODAG dst
    // belongs to -- the base one, or one CreateLocalDodag() formed at
    // runtime -- has the topology to compute a downward path at all; every
    // other node's traffic goes up, which needs no Routing Header. The
    // membership found here (if any) is reused below for the RPL Option
    // this same packet also needs, rather than resolving twice.
    std::vector<Ipv6Address> hops;
    uint8_t aodvInstanceId = 0;
    bool overAodvRoute = FindAodvRoute(dst, hops, aodvInstanceId);
    DodagMembership* originDodag = overAodvRoute ? nullptr : FindRootDodagFor(dst, hops);
    if ((overAodvRoute || originDodag) && hops.size() > 1)
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
        srh.SetAddresses(addresses);

        // Both Segments Left and Hdr Ext Len are eight-bit fields (RFC
        // 8200 section 4.4), so a path this long cannot be written down
        // as one Routing Header, and writing one anyway would wrap the
        // length silently. A DODAG deep enough to hit this is not
        // something this implementation can source route through at
        // all, so the packet goes out with only the RPL Option and is
        // dropped by the first hop that finds no route -- which is at
        // least a visible failure rather than a corrupted header.
        if (addresses.size() > std::numeric_limits<uint8_t>::max() ||
            srh.GetSerializedSize() > RplSourceRoutingHeader::MAX_SERIALIZED_SIZE)
        {
            NS_LOG_WARN("The path to " << dst << " needs " << addresses.size()
                                       << " addresses, too many for one Routing Header");
        }
        else
        {
            srh.SetSegmentsLeft(static_cast<uint8_t>(hops.size() - 1));
            packet->AddHeader(srh);
            header.SetDestination(hops.front());
            innerNextHeader = Ipv6Header::IPV6_EXT_ROUTING;
            hasRoutingHeader = true;

            NS_LOG_LOGIC("Attached a Routing Header for "
                        << dst << " with " << (hops.size() - 1) << " address(es), first hop "
                        << hops.front());
        }
    }

    if (overAodvRoute)
    {
        // No RPL Option on an AODV-RPL source-routed packet. RFC 6553
        // section 4 allows leaving it off outright -- "A datagram including
        // a Source Routing Header (SRH) does not need to include a RPL
        // Option since both the source and intermediate routers ensure that
        // the SRH does not contain loops" -- and here it would actively
        // break the packet: on a symmetric route no RREP-Instance DODAG is
        // built anywhere (RFC 9854 section 6.3.1), so a relay looking the
        // RPI's RPLInstanceID up would find no membership,
        // GetRankForInstance() would answer RPL_INFINITE_RANK, and
        // RplIpv6OptionRpl::Process() would call every such packet rank
        // inconsistent and drop it at the second hop.
        //
        // The IPv6 header's own Next Header has to be pointed at whatever
        // was actually attached before returning. On the ordinary path that
        // happens as a side effect of adding the Hop-by-Hop header below;
        // skipping that block would otherwise leave the header still
        // naming the upper-layer protocol while a Routing Header sits in
        // front of it, and the first hop would hand the Routing Header's
        // bytes to UDP.
        header.SetNextHeader(innerNextHeader);
        NS_LOG_LOGIC("Attached a Routing Header for " << dst
                                                      << " with no RPL Option: an AODV-RPL "
                                                         "source route needs none");
        return;
    }

    if (!originDodag)
    {
        // Not this node's own downward traffic (no membership it roots
        // reaches dst): either upward traffic on some membership -- the
        // same "dst is some non-base membership's own DODAGID" case
        // RouteOutput()'s own fallback loop resolves, covering
        // SendDao()/SendNoPathDao()/DaoRetry() addressed to a non-base
        // root -- or, if that finds nothing either, the base DODAG, the
        // same fallback RouteOutput() itself ends on.
        originDodag = GetBaseDodag();
        for (auto& [key, other] : m_dodags)
        {
            if (&other == originDodag || other.dodagId != dst)
            {
                continue;
            }
            originDodag = &other;
            break;
        }
    }

    // The RPL Option (RFC 6553), on every node's own traffic: down if
    // originDodag is a DODAG this node roots (its own downward traffic),
    // up otherwise (this node's own upward traffic on some membership, or
    // nothing recognised at all).
    RplPacketInfoHeader rpi;
    rpi.SetDown(originDodag ? originDodag->isRoot : false);
    rpi.SetInstanceId(originDodag ? originDodag->instanceId : RPL_DEFAULT_INSTANCE);
    rpi.SetSenderRank(originDodag ? originDodag->rank : RPL_INFINITE_RANK);

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
    // upward traffic, which always goes to the preferred parent -- but which
    // DODAG's preferred parent depends on which DODAG this packet's own
    // sender attached it to, not always the base one, once this node holds
    // more than one membership. The RPI (RFC 6553) that sender's own
    // PrepareOutgoingPacket() stamped on it is still on the packet, still
    // readable here (@see ReadRpiInstanceId()); base is kept as both the
    // starting guess and the fallback, so a single-DODAG node (the common
    // case) never pays for a parse it cannot possibly need.
    const DodagMembership* dodag = GetBaseDodag();
    if (m_dodags.size() > 1)
    {
        uint8_t instanceId;
        if (ReadRpiInstanceId(p, header, instanceId))
        {
            if (const DodagMembership* forInstance = FindDodagByInstance(instanceId))
            {
                dodag = forInstance;
            }
        }
    }
    Ptr<Ipv6Route> route = dodag ? RouteViaPreferredParent(*dodag, dst) : nullptr;
    if (route)
    {
        NS_LOG_LOGIC("Forwarding " << dst << " via the preferred parent "
                                   << dodag->preferredParent);
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

RplRoutingProtocol::DodagKey
RplRoutingProtocol::CreateLocalDodag(uint8_t instanceId, uint8_t mop)
{
    NS_LOG_FUNCTION(this << +instanceId << +mop);

    Ipv6Address address = GetGlobalAddress();
    if (address.IsAny())
    {
        NS_LOG_WARN("Cannot form a local DODAG: this node has no global address yet");
        return DodagKey{instanceId, Ipv6Address::GetAny()};
    }

    // RFC 6550 section 5.1: a Local RPLInstanceID's own 'D' flag "is always
    // set to 0 in RPL control messages". Every control message this DODAG
    // ever sends (SendDio()/SendDao()/DaoRetry()/the root's own DAO-ACK
    // reply) just copies dodag.instanceId verbatim, so clearing the flag
    // once here is what keeps all of them compliant regardless of what the
    // caller passed, rather than needing every one of those call sites to
    // know about it. Left untouched when the top bit (RPL_LOCAL_INSTANCE_
    // FLAG) is clear: for a Global RPLInstanceID this same bit is simply
    // part of its own 7-bit ID space (0..127), not a flag at all.
    if (instanceId & RPL_LOCAL_INSTANCE_FLAG)
    {
        instanceId &= static_cast<uint8_t>(~RPL_LOCAL_INSTANCE_D_FLAG);
    }

    DodagKey key{instanceId, address};
    // No Prefix Information option: unlike RplHelper::SetRoot()'s DODAG,
    // neither AODV-RPL (RFC 9854) nor P2P-RPL (RFC 6997) SLAAC an address
    // on their local instance -- every participant already has whatever
    // address the base DODAG gave it.
    CreateDodagMembership(key, mop);

    NS_LOG_INFO("Formed local DODAG " << key.dodagId << " under instance " << +instanceId);
    return key;
}

bool
RplRoutingProtocol::IsRoot() const
{
    return m_isRoot;
}

bool
RplRoutingProtocol::IsJoined() const
{
    return GetBaseDodag() != nullptr;
}

uint16_t
RplRoutingProtocol::GetRank() const
{
    const DodagMembership* dodag = GetBaseDodag();
    return dodag ? dodag->rank : RPL_INFINITE_RANK;
}

uint16_t
RplRoutingProtocol::GetPathEtx() const
{
    const DodagMembership* dodag = GetBaseDodag();
    return dodag ? dodag->pathEtx : 0;
}

Ipv6Address
RplRoutingProtocol::GetDodagId() const
{
    const DodagMembership* dodag = GetBaseDodag();
    return dodag ? dodag->dodagId : Ipv6Address::GetAny();
}

Ipv6Address
RplRoutingProtocol::GetPreferredParent() const
{
    const DodagMembership* dodag = GetBaseDodag();
    return dodag ? dodag->preferredParent : Ipv6Address::GetAny();
}

bool
RplRoutingProtocol::IsJoinedTo(uint8_t instanceId, Ipv6Address dodagId) const
{
    return m_dodags.find(DodagKey{instanceId, dodagId}) != m_dodags.end();
}

uint16_t
RplRoutingProtocol::GetRankIn(uint8_t instanceId, Ipv6Address dodagId) const
{
    auto it = m_dodags.find(DodagKey{instanceId, dodagId});
    return it != m_dodags.end() ? it->second.rank : RPL_INFINITE_RANK;
}

uint16_t
RplRoutingProtocol::GetRankForInstance(uint8_t instanceId) const
{
    const DodagMembership* dodag = FindDodagByInstance(instanceId);
    return dodag ? dodag->rank : RPL_INFINITE_RANK;
}

bool
RplRoutingProtocol::IsDaoAckPendingIn(uint8_t instanceId, Ipv6Address dodagId) const
{
    auto it = m_dodags.find(DodagKey{instanceId, dodagId});
    return it != m_dodags.end() && it->second.daoAckPending;
}

uint32_t
RplRoutingProtocol::GetDodagCount() const
{
    return static_cast<uint32_t>(m_dodags.size());
}

void
RplRoutingProtocol::NotifyRankInconsistency(uint8_t instanceId)
{
    NS_LOG_FUNCTION(this << +instanceId);
    DodagMembership* dodag = FindDodagByInstance(instanceId);
    if (dodag)
    {
        dodag->dioTrickle.Reset();
    }
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

    const DodagMembership* dodag = GetBaseDodag();
    if (!dodag)
    {
        *os << "  Not part of a DODAG" << std::endl;
        os->copyfmt(oldState);
        return;
    }

    *os << "  DODAG: " << dodag->dodagId << ", instance " << +dodag->instanceId << ", version "
        << +dodag->version << ", rank " << dodag->rank;
    if (dodag->ocp == RPL_OCP_MRHOF)
    {
        *os << ", path ETX " << (double(dodag->pathEtx) / RPL_ETX_FIXED_POINT);
    }
    *os << std::endl;
    *os << "  Preferred parent: " << dodag->preferredParent << std::endl;
    *os << "  Candidate parents:" << std::endl;
    for (const auto& [address, parent] : dodag->parents)
    {
        *os << "    " << address << " rank " << parent.rank << " via interface " << parent.interface
            << ", heard " << +parent.freshness << " times, last "
            << (Now() - parent.lastHeard).As(unit) << " ago";
        if (dodag->ocp == RPL_OCP_MRHOF)
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
        for (const auto& [target, entry] : dodag->topology)
        {
            *os << "    " << target << " under " << entry.parent << ", expires in ";
            // An entry advertised with the infinite Path Lifetime (RFC 6550
            // section 6.7.8, @see HandleDao()) is held at Time::Max(), which
            // subtracted from the current time is a number of no use to
            // anyone reading this.
            if (entry.expire == Time::Max())
            {
                *os << "never";
            }
            else
            {
                *os << (entry.expire - Now()).As(unit);
            }
            *os << std::endl;
        }
    }

    // Not root-gated like the DAO topology above: an AODV-RPL (RFC 9854)
    // route is discovered and held at whichever node called DiscoverRoute(),
    // which need not be the root at all.
    if (!m_aodvRoutes.empty())
    {
        *os << "  AODV-RPL routes:" << std::endl;
        Time now = Now();
        for (const auto& [target, route] : m_aodvRoutes)
        {
            if (route.expire <= now)
            {
                continue;
            }
            *os << "    " << target << " over " << route.hops.size() << " hop(s), first via "
                << route.hops.front() << ", RREQ-Instance " << +route.rreqInstanceId
                << ", expires in " << (route.expire - now).As(unit) << std::endl;
        }
    }

    os->copyfmt(oldState);
}

void
RplRoutingProtocol::PrintRoutingTableJson(Ptr<OutputStreamWrapper> stream) const
{
    std::ostream* os = stream->GetStream();
    std::ios oldState(nullptr);
    oldState.copyfmt(*os);

    // Nothing written below needs escaping: every value is a number, a
    // boolean, one of two fixed role strings, or an IPv6 address, and
    // Ipv6Address's own operator<< emits nothing but hex digits, colons and
    // dots. That is what lets this get away without a JSON library.
    auto quoted = [os](const Ipv6Address& address) { *os << '"' << address << '"'; };

    // AODV-RPL (RFC 9854) routes are node-level state, independent of the
    // base DODAG membership dodag below (GetBaseDodag() can come back null
    // while m_aodvRoutes still holds routes discovered earlier), so this is
    // written the same way in both the joined and not-joined branches.
    auto writeAodvRoutes = [&]() {
        *os << "\"aodvRoutes\":[";
        bool firstRoute = true;
        Time now = Now();
        for (const auto& [target, route] : m_aodvRoutes)
        {
            if (route.expire <= now)
            {
                continue;
            }
            *os << (firstRoute ? "" : ",") << "{\"target\":";
            quoted(target);
            *os << ",\"hops\":[";
            bool firstHop = true;
            for (const auto& hop : route.hops)
            {
                *os << (firstHop ? "" : ",");
                quoted(hop);
                firstHop = false;
            }
            *os << "],\"rreqInstance\":" << +route.rreqInstanceId
                << ",\"expiresIn\":" << (route.expire - now).GetSeconds() << "}";
            firstRoute = false;
        }
        *os << "]";
    };

    *os << "{\"node\":" << m_ipv6->GetObject<Node>()->GetId()
        << ",\"time\":" << Now().GetSeconds() << ",\"role\":\""
        << (m_isRoot ? "root" : "router") << "\",\"joined\":";

    const DodagMembership* dodag = GetBaseDodag();
    *os << (dodag ? "true" : "false");

    if (!dodag)
    {
        // Every key a joined node has, so that a consumer can read the same
        // fields either way rather than branching on "joined" first.
        *os << ",\"dodagId\":null,\"instance\":null,\"version\":null,\"ocp\":null"
               ",\"rank\":null,\"pathEtx\":null,\"preferredParent\":null"
               ",\"parents\":[],\"topology\":[],";
        writeAodvRoutes();
        *os << "}" << std::endl;
        os->copyfmt(oldState);
        return;
    }

    bool mrhof = dodag->ocp == RPL_OCP_MRHOF;

    *os << ",\"dodagId\":";
    quoted(dodag->dodagId);
    *os << ",\"instance\":" << +dodag->instanceId << ",\"version\":" << +dodag->version
        << ",\"ocp\":\"" << (mrhof ? "mrhof" : "of0") << "\",\"rank\":" << dodag->rank
        << ",\"pathEtx\":";
    if (mrhof)
    {
        *os << (double(dodag->pathEtx) / RPL_ETX_FIXED_POINT);
    }
    else
    {
        // OF0 derives no path cost, so there is no number to report here --
        // as opposed to one that happens to be zero.
        *os << "null";
    }
    *os << ",\"preferredParent\":";
    quoted(dodag->preferredParent);

    *os << ",\"parents\":[";
    bool first = true;
    for (const auto& [address, parent] : dodag->parents)
    {
        *os << (first ? "" : ",") << "{\"address\":";
        quoted(address);
        *os << ",\"rank\":" << parent.rank << ",\"interface\":" << parent.interface
            << ",\"freshness\":" << +parent.freshness
            << ",\"lastHeardAgo\":" << (Now() - parent.lastHeard).GetSeconds() << ",\"linkEtx\":";
        if (mrhof)
        {
            *os << (double(parent.etx) / RPL_ETX_FIXED_POINT) << ",\"pathEtx\":"
                << (double(parent.pathEtx) / RPL_ETX_FIXED_POINT);
        }
        else
        {
            // The link ETX is tracked whatever the objective function is, but
            // only MRHOF gives it a meaning; reporting it under OF0 would
            // invite reading a number into a decision it played no part in.
            *os << "null,\"pathEtx\":null";
        }
        *os << ",\"lql\":";
        if (m_enableLql)
        {
            *os << +parent.lql;
        }
        else
        {
            *os << "null";
        }
        *os << "}";
        first = false;
    }
    *os << "],\"topology\":[";

    // Empty for every node but the root, which is the only one that holds a
    // topology at all in non-storing mode.
    first = true;
    for (const auto& [target, entry] : dodag->topology)
    {
        *os << (first ? "" : ",") << "{\"target\":";
        quoted(target);
        *os << ",\"parent\":";
        quoted(entry.parent);
        *os << ",\"pathSequence\":" << +entry.pathSequence << ",\"expiresIn\":";
        // Time::Max() is how HandleDao() records the infinite Path Lifetime
        // of RFC 6550 section 6.7.8. Reported as null rather than as the
        // seconds between now and the end of representable time.
        if (entry.expire == Time::Max())
        {
            *os << "null";
        }
        else
        {
            *os << (entry.expire - Now()).GetSeconds();
        }
        *os << "}";
        first = false;
    }
    *os << "],";
    writeAodvRoutes();
    *os << "}" << std::endl;

    os->copyfmt(oldState);
}

int64_t
RplRoutingProtocol::AssignStreams(int64_t stream)
{
    NS_LOG_FUNCTION(this << stream);
    m_jitter->SetStream(stream);
    // No DodagMembership -- and so no RplTrickleTimer to assign this to --
    // necessarily exists yet (this runs before Simulator::Run()); JoinDodag()
    // and HandleDadSuccess()'s root branch apply it once one is constructed.
    m_dioTrickleStream = stream + 1;
    return 2;
}

} // namespace rpl
} // namespace ns3
