/*
 * Copyright (c) 2026 ns-3 RPL module contributors
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "ns3/boolean.h"
#include "ns3/icmpv6-header.h"
#include "ns3/icmpv6-l4-protocol.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/internet-stack-helper.h"
#include "ns3/ipv6-address-helper.h"
#include "ns3/ipv6-extension.h"
#include "ns3/ipv6-l3-protocol.h"
#include "ns3/ipv6-option-demux.h"
#include "ns3/ipv6-raw-socket-factory.h"
#include "ns3/ipv6-route.h"
#include "ns3/node-container.h"
#include "ns3/output-stream-wrapper.h"
#include "ns3/packet.h"
#include "ns3/rpl-header.h"
#include "ns3/rpl-helper.h"
#include "ns3/rpl-packet-info-option.h"
#include "ns3/rpl-routing-protocol.h"
#include "ns3/rpl-source-routing-extension.h"
#include "ns3/rpl-trickle-timer.h"
#include "ns3/simple-channel.h"
#include "ns3/simple-net-device-helper.h"
#include "ns3/simple-net-device.h"
#include "ns3/simulator.h"
#include "ns3/socket.h"
#include "ns3/tag.h"
#include "ns3/test.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/uinteger.h"

#include <algorithm>
#include <sstream>
#include <vector>

using namespace ns3;
using namespace ns3::rpl;

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Send a hand-built RPL control message from a node's own raw socket,
 *        bypassing RplRoutingProtocol entirely.
 *
 * This is what lets a test drive RecvRpl() with a message the protocol itself
 * would never construct, e.g. a No-Path DAO, which nothing in this
 * implementation sends yet even though HandleDao() knows how to act on one.
 *
 * @param node the node to send from
 * @param interface the interface to send on
 * @param body the RPL message body, e.g. a RplDaoHeader
 * @param code the RPL message code
 * @param src the source address to check the ICMPv6 checksum against
 * @param dst the destination address
 */
template <typename T>
static void
SendRawRplMessage(Ptr<Node> node,
                  uint32_t interface,
                  const T& body,
                  uint8_t code,
                  Ipv6Address src,
                  Ipv6Address dst)
{
    Ptr<Ipv6L3Protocol> ipv6 = node->GetObject<Ipv6L3Protocol>();
    Ptr<Socket> socket = Socket::CreateSocket(node, Ipv6RawSocketFactory::GetTypeId());
    socket->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    socket->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    socket->BindToNetDevice(ipv6->GetNetDevice(interface));

    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(body);

    Icmpv6Header icmpv6Header;
    icmpv6Header.SetType(ICMPV6_RPL);
    icmpv6Header.SetCode(code);
    icmpv6Header.CalculatePseudoHeaderChecksum(src,
                                               dst,
                                               packet->GetSize() + icmpv6Header.GetSerializedSize(),
                                               Icmpv6L4Protocol::GetStaticProtocolNumber());
    packet->AddHeader(icmpv6Header);

    SocketIpv6HopLimitTag hopLimitTag;
    hopLimitTag.SetHopLimit(255);
    packet->AddPacketTag(hopLimitTag);

    socket->SendTo(packet, 0, Inet6SocketAddress(dst, 0));
    socket->Close();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Hand a hand-built RPL control message directly to a node's
 *        Ipv6L3Protocol::Receive(), as if it had just arrived over its
 *        interface 1 -- bypassing the channel, any blacklist on it, and
 *        Neighbour Discovery address resolution entirely.
 *
 * SendRawRplMessage() drives the same scenario through a real send, which
 * is the more faithful choice whenever the path between the two nodes is
 * otherwise ordinary. It stops being the right tool the moment a test also
 * needs a directed blacklist to stay in effect while the message gets
 * through anyway (lifting it, even briefly, risks letting an unrelated
 * message -- e.g. the real root's own reply to whatever the child was
 * about to retry -- slip through the same gap), or needs the message
 * delivered from a node that has never exchanged anything with the
 * recipient before (Neighbour Discovery has nothing cached for that pair
 * yet, and would have to resolve it first). This is the tool for those
 * cases: nothing about how the message reaches Receive() is being tested
 * here, only what the recipient does once it has it.
 *
 * @param node the node to deliver to
 * @param interface the interface the message is delivered on
 * @param body the RPL message body, e.g. a RplDaoAckHeader
 * @param code the RPL message code
 * @param src the source address, both for the ICMPv6 checksum and the IPv6
 *        header actually carried in
 * @param dst the destination address, likewise
 */
template <typename T>
static void
DeliverRawRplMessage(Ptr<Node> node,
                     uint32_t interface,
                     const T& body,
                     uint8_t code,
                     Ipv6Address src,
                     Ipv6Address dst)
{
    Ptr<Ipv6L3Protocol> ipv6 = node->GetObject<Ipv6L3Protocol>();
    Ptr<NetDevice> device = ipv6->GetNetDevice(interface);

    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(body);

    Icmpv6Header icmpv6Header;
    icmpv6Header.SetType(ICMPV6_RPL);
    icmpv6Header.SetCode(code);
    icmpv6Header.CalculatePseudoHeaderChecksum(src,
                                               dst,
                                               packet->GetSize() + icmpv6Header.GetSerializedSize(),
                                               Icmpv6L4Protocol::GetStaticProtocolNumber());
    packet->AddHeader(icmpv6Header);

    Ipv6Header ipv6Header;
    ipv6Header.SetSource(src);
    ipv6Header.SetDestination(dst);
    ipv6Header.SetNextHeader(Icmpv6L4Protocol::GetStaticProtocolNumber());
    ipv6Header.SetPayloadLength(packet->GetSize());
    ipv6Header.SetHopLimit(255);
    packet->AddHeader(ipv6Header);

    // 0x86dd is IPv6's EtherType, the protocol number Ipv6L3Protocol is
    // itself registered under as a protocol handler
    // (Node::RegisterProtocolHandler(), see ipv6-l3-protocol.cc). The L2
    // from/to addresses matter for only one thing past logging -- an
    // opportunistic Neighbour Discovery cache refresh keyed on "from"
    // (Ipv6L3Protocol::Receive(), the NdiscCache::LookupInverse() branch) --
    // which the device's own address standing in for both simply misses
    // (an empty lookup, not an error): harmless, since nothing this
    // function delivers needs that cache warm.
    ipv6->Receive(device,
                 packet,
                 0x86dd,
                 device->GetAddress(),
                 device->GetAddress(),
                 NetDevice::PACKET_HOST);
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check that a DIS survives a serialize and deserialize round trip.
 */
class RplDisHeaderTestCase : public TestCase
{
  public:
    RplDisHeaderTestCase();

  private:
    void DoRun() override;
};

RplDisHeaderTestCase::RplDisHeaderTestCase()
    : TestCase("DIS serialization")
{
}

void
RplDisHeaderTestCase::DoRun()
{
    RplDisHeader dis;
    NS_TEST_ASSERT_MSG_EQ(dis.GetSerializedSize(), 2, "A DIS is a flags and a reserved byte");

    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(dis);
    NS_TEST_ASSERT_MSG_EQ(packet->GetSize(), 2, "Unexpected packet size");

    RplDisHeader received;
    NS_TEST_ASSERT_MSG_EQ(packet->RemoveHeader(received), 2, "Unexpected deserialized size");
    NS_TEST_ASSERT_MSG_EQ(packet->GetSize(), 0, "The DIS did not consume the whole packet");
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check that a DIO survives a serialize and deserialize round trip,
 *        both bare and carrying a DODAG Configuration option.
 */
class RplDioHeaderTestCase : public TestCase
{
  public:
    RplDioHeaderTestCase();

  private:
    void DoRun() override;
};

RplDioHeaderTestCase::RplDioHeaderTestCase()
    : TestCase("DIO serialization")
{
}

void
RplDioHeaderTestCase::DoRun()
{
    RplDioHeader dio;
    dio.SetInstanceId(7);
    dio.SetVersionNumber(3);
    dio.SetRank(384);
    dio.SetGrounded(true);
    dio.SetMop(RPL_MOP_NON_STORING);
    dio.SetPreference(5);
    dio.SetDtsn(42);
    dio.SetDodagId(Ipv6Address("2001:1::1"));

    NS_TEST_ASSERT_MSG_EQ(dio.GetSerializedSize(), 24, "The DIO base object is 24 bytes");
    NS_TEST_ASSERT_MSG_EQ(dio.HasDagConfiguration(), false, "There is no option yet");

    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(dio);

    RplDioHeader received;
    packet->RemoveHeader(received);

    NS_TEST_ASSERT_MSG_EQ(received.GetInstanceId(), 7, "Wrong RPLInstanceID");
    NS_TEST_ASSERT_MSG_EQ(received.GetVersionNumber(), 3, "Wrong version number");
    NS_TEST_ASSERT_MSG_EQ(received.GetRank(), 384, "Wrong rank");
    NS_TEST_ASSERT_MSG_EQ(received.GetGrounded(), true, "Wrong Grounded flag");
    NS_TEST_ASSERT_MSG_EQ(received.GetMop(), RPL_MOP_NON_STORING, "Wrong mode of operation");
    NS_TEST_ASSERT_MSG_EQ(received.GetPreference(), 5, "Wrong preference");
    NS_TEST_ASSERT_MSG_EQ(received.GetDtsn(), 42, "Wrong DTSN");
    NS_TEST_ASSERT_MSG_EQ(received.GetDodagId(), Ipv6Address("2001:1::1"), "Wrong DODAGID");
    NS_TEST_ASSERT_MSG_EQ(received.HasDagConfiguration(), false, "There should be no option");
    NS_TEST_ASSERT_MSG_EQ(received.HasMetricContainer(), false, "There should be no option");

    // The Grounded flag, the mode of operation and the preference share a byte,
    // so a DIO that has none of them set has to come back clean.
    RplDioHeader bare;
    bare.SetMop(RPL_MOP_NO_DOWNWARD_ROUTES);
    packet = Create<Packet>();
    packet->AddHeader(bare);
    packet->RemoveHeader(received);
    NS_TEST_ASSERT_MSG_EQ(received.GetGrounded(), false, "The Grounded flag leaked");
    NS_TEST_ASSERT_MSG_EQ(received.GetMop(), RPL_MOP_NO_DOWNWARD_ROUTES, "Wrong mode of operation");
    NS_TEST_ASSERT_MSG_EQ(received.GetPreference(), 0, "The preference leaked");

    // Now with the DODAG Configuration option.
    dio.SetDagConfiguration(6, 10, 2, 1024, 256, RPL_OCP_OF0, 20, 30);
    NS_TEST_ASSERT_MSG_EQ(dio.GetSerializedSize(), 40, "The option adds 16 bytes");

    packet = Create<Packet>();
    packet->AddHeader(dio);
    packet->RemoveHeader(received);

    NS_TEST_ASSERT_MSG_EQ(received.HasDagConfiguration(), true, "The option was lost");
    NS_TEST_ASSERT_MSG_EQ(received.GetIntervalDoublings(), 6, "Wrong DIOIntervalDoublings");
    NS_TEST_ASSERT_MSG_EQ(received.GetIntervalMin(), 10, "Wrong DIOIntervalMin");
    NS_TEST_ASSERT_MSG_EQ(received.GetRedundancy(), 2, "Wrong DIORedundancyConstant");
    NS_TEST_ASSERT_MSG_EQ(received.GetMaxRankIncrease(), 1024, "Wrong MaxRankIncrease");
    NS_TEST_ASSERT_MSG_EQ(received.GetMinHopRankIncrease(), 256, "Wrong MinHopRankIncrease");
    NS_TEST_ASSERT_MSG_EQ(received.GetOcp(), RPL_OCP_OF0, "Wrong objective code point");
    NS_TEST_ASSERT_MSG_EQ(received.GetDefaultLifetime(), 20, "Wrong default lifetime");
    NS_TEST_ASSERT_MSG_EQ(received.GetLifetimeUnit(), 30, "Wrong lifetime unit");
    NS_TEST_ASSERT_MSG_EQ(received.GetRank(), 384, "The option ate part of the base object");

    // Now also with the DAG Metric Container (RFC 6551 ETX object), as MRHOF
    // carries alongside the DODAG Configuration option.
    dio.SetMetricContainer(320); // ETX 2.5
    NS_TEST_ASSERT_MSG_EQ(dio.GetSerializedSize(), 48, "The metric container adds 8 bytes");

    packet = Create<Packet>();
    packet->AddHeader(dio);
    packet->RemoveHeader(received);

    NS_TEST_ASSERT_MSG_EQ(received.HasMetricContainer(), true, "The metric container was lost");
    NS_TEST_ASSERT_MSG_EQ(received.GetPathEtx(), 320, "Wrong path ETX");
    NS_TEST_ASSERT_MSG_EQ(received.HasDagConfiguration(), true, "The other option was lost");
    NS_TEST_ASSERT_MSG_EQ(received.GetOcp(), RPL_OCP_OF0, "The other option's content was lost");
    NS_TEST_ASSERT_MSG_EQ(received.GetRank(), 384, "An option ate part of the base object");

    // A DIO can carry more than one Routing-MC-Type object (RFC 6551): add an
    // LQL one (section 4.6) alongside the ETX one already on this DIO and
    // check both survive together.
    NS_TEST_ASSERT_MSG_EQ(dio.HasLql(), false, "There is no LQL option yet");
    dio.SetLql(3);
    NS_TEST_ASSERT_MSG_EQ(dio.GetSerializedSize(), 56, "The LQL option adds 8 more bytes");

    packet = Create<Packet>();
    packet->AddHeader(dio);
    packet->RemoveHeader(received);

    NS_TEST_ASSERT_MSG_EQ(received.HasLql(), true, "The LQL option was lost");
    NS_TEST_ASSERT_MSG_EQ(received.GetLql(), 3, "Wrong LQL");
    NS_TEST_ASSERT_MSG_EQ(received.HasMetricContainer(), true, "The ETX option was lost");
    NS_TEST_ASSERT_MSG_EQ(received.GetPathEtx(), 320, "The ETX option's content was lost");
    NS_TEST_ASSERT_MSG_EQ(received.HasDagConfiguration(), true, "The DAG Configuration was lost");
    NS_TEST_ASSERT_MSG_EQ(received.GetRank(), 384, "An option ate part of the base object");

    // The Prefix Information option (RFC 6550 section 6.7.10), the root's
    // GUA/ULA prefix disseminated for SLAAC (RFC 4862): carried alongside
    // every other option already on this DIO.
    NS_TEST_ASSERT_MSG_EQ(dio.HasPrefixInfo(), false, "There is no Prefix Information option yet");
    dio.SetPrefixInfo(Ipv6Address("2001:1::"), 64, true, true, 86400, 14400);
    NS_TEST_ASSERT_MSG_EQ(dio.GetSerializedSize(), 84, "The Prefix Information option adds 28 bytes");

    packet = Create<Packet>();
    packet->AddHeader(dio);
    packet->RemoveHeader(received);

    NS_TEST_ASSERT_MSG_EQ(received.HasPrefixInfo(), true, "The Prefix Information option was lost");
    NS_TEST_ASSERT_MSG_EQ(received.GetPrefix(), Ipv6Address("2001:1::"), "Wrong prefix");
    NS_TEST_ASSERT_MSG_EQ(received.GetPrefixLength(), 64, "Wrong prefix length");
    NS_TEST_ASSERT_MSG_EQ(received.GetPrefixOnLink(), true, "Wrong 'L' flag");
    NS_TEST_ASSERT_MSG_EQ(received.GetPrefixAutonomous(), true, "Wrong 'A' flag");
    NS_TEST_ASSERT_MSG_EQ(received.GetPrefixValidLifetime(), 86400, "Wrong Valid Lifetime");
    NS_TEST_ASSERT_MSG_EQ(received.GetPrefixPreferredLifetime(), 14400, "Wrong Preferred Lifetime");
    NS_TEST_ASSERT_MSG_EQ(received.HasLql(), true, "An earlier option was lost");
    NS_TEST_ASSERT_MSG_EQ(received.GetRank(), 384, "An option ate part of the base object");

    // The 'L'/'A' flags share a byte with 6 reserved bits: clearing both must
    // not leak into the rest of the option.
    RplDioHeader noFlags;
    noFlags.SetPrefixInfo(Ipv6Address("fd00::"), 48, false, false, 0, 0);
    packet = Create<Packet>();
    packet->AddHeader(noFlags);
    packet->RemoveHeader(received);
    NS_TEST_ASSERT_MSG_EQ(received.GetPrefixOnLink(), false, "The 'L' flag leaked");
    NS_TEST_ASSERT_MSG_EQ(received.GetPrefixAutonomous(), false, "The 'A' flag leaked");
    NS_TEST_ASSERT_MSG_EQ(received.GetPrefix(), Ipv6Address("fd00::"), "Wrong ULA prefix");

    // The AODV-RPL RREQ option (RFC 9854 section 4.1), carried alongside
    // everything already on the DIO above. Two Address Vector entries that
    // share their first 8 octets with the DODAGID set above (2001:1::1), so
    // Serialize() elides them (@see RplDioHeader::ElidedPrefixLength()):
    // 2 (Type+Length) + 3 (the fixed part) + 2 * (16 - 8).
    NS_TEST_ASSERT_MSG_EQ(dio.HasRreq(), false, "There is no RREQ option yet");
    RplDioHeader::RreqOption rreq;
    rreq.symmetric = true;
    rreq.hopByHop = false;
    rreq.lifetime = 2; // 64 seconds
    rreq.rankLimit = 5;
    rreq.origSeqNo = 42;
    rreq.addressVector = {Ipv6Address("2001:1::1"), Ipv6Address("2001:1::2")};
    dio.SetRreq(rreq);
    NS_TEST_ASSERT_MSG_EQ(dio.GetSerializedSize(), 105, "The RREQ option adds 21 bytes");

    packet = Create<Packet>();
    packet->AddHeader(dio);
    packet->RemoveHeader(received);

    NS_TEST_ASSERT_MSG_EQ(received.HasRreq(), true, "The RREQ option was lost");
    NS_TEST_ASSERT_MSG_EQ(received.GetRreq().symmetric, true, "Wrong 'S' flag");
    NS_TEST_ASSERT_MSG_EQ(received.GetRreq().hopByHop, false, "Wrong 'H' flag");
    NS_TEST_ASSERT_MSG_EQ(received.GetRreq().compr,
                          8,
                          "Wrong Compr: both Address Vector entries share the DODAGID's prefix, "
                          "so Serialize() should have elided it");
    // 'L' straddles the two flag octets, so a wrong shift on either side
    // shows up here and nowhere else.
    NS_TEST_ASSERT_MSG_EQ(received.GetRreq().lifetime, 2, "Wrong 'L' field");
    NS_TEST_ASSERT_MSG_EQ(received.GetRreq().rankLimit, 5, "Wrong RankLimit");
    NS_TEST_ASSERT_MSG_EQ(received.GetRreq().origSeqNo, 42, "Wrong Orig SeqNo");
    NS_TEST_ASSERT_MSG_EQ(received.GetRreq().addressVector.size(), 2, "Wrong Address Vector size");
    NS_TEST_ASSERT_MSG_EQ(received.GetRreq().addressVector[0],
                          Ipv6Address("2001:1::1"),
                          "Wrong first Address Vector entry");
    NS_TEST_ASSERT_MSG_EQ(received.GetRreq().addressVector[1],
                          Ipv6Address("2001:1::2"),
                          "Wrong second Address Vector entry");
    NS_TEST_ASSERT_MSG_EQ(received.HasPrefixInfo(), true, "An earlier option was lost");
    NS_TEST_ASSERT_MSG_EQ(received.GetRank(), 384, "An option ate part of the base object");

    // The RREP option (RFC 9854 section 4.2): the same shape, with 'G' in
    // place of 'S' and Delta in place of Orig SeqNo. An empty Address Vector
    // here, the boundary the length arithmetic has to get right, so
    // 2 + 3 + 0 * 16.
    NS_TEST_ASSERT_MSG_EQ(dio.HasRrep(), false, "There is no RREP option yet");
    RplDioHeader::RrepOption rrep;
    rrep.gratuitous = false;
    rrep.hopByHop = false;
    rrep.lifetime = 1; // 16 seconds
    rrep.rankLimit = 0;
    rrep.delta = 6;
    dio.SetRrep(rrep);
    NS_TEST_ASSERT_MSG_EQ(dio.GetSerializedSize(),
                          110,
                          "The RREP option with an empty Address Vector adds 5 bytes");

    packet = Create<Packet>();
    packet->AddHeader(dio);
    packet->RemoveHeader(received);

    NS_TEST_ASSERT_MSG_EQ(received.HasRrep(), true, "The RREP option was lost");
    NS_TEST_ASSERT_MSG_EQ(received.GetRrep().gratuitous, false, "Wrong 'G' flag");
    NS_TEST_ASSERT_MSG_EQ(received.GetRrep().lifetime, 1, "Wrong 'L' field");
    NS_TEST_ASSERT_MSG_EQ(received.GetRrep().rankLimit, 0, "Wrong RankLimit");
    NS_TEST_ASSERT_MSG_EQ(received.GetRrep().delta, 6, "Wrong Delta");
    NS_TEST_ASSERT_MSG_EQ(received.GetRrep().addressVector.size(),
                          0,
                          "An empty Address Vector came back non-empty");
    NS_TEST_ASSERT_MSG_EQ(received.HasRreq(), true, "The RREQ option was lost");
    NS_TEST_ASSERT_MSG_EQ(received.GetRreq().origSeqNo, 42, "The RREQ option's content was lost");
    NS_TEST_ASSERT_MSG_EQ(received.GetRank(), 384, "An option ate part of the base object");

    // The ART option (RFC 9854 section 4.3), a fixed 20 bytes at Prefix
    // Length 0 -- which the RFC defines as "this is an address, not a
    // prefix", the only form this implementation sends.
    NS_TEST_ASSERT_MSG_EQ(dio.HasArt(), false, "There is no ART option yet");
    RplDioHeader::ArtOption art;
    art.destSeqNo = 7;
    art.prefixLength = 0;
    art.target = Ipv6Address("2001:2::9");
    dio.SetArt(art);
    NS_TEST_ASSERT_MSG_EQ(dio.GetSerializedSize(), 130, "The ART option adds 20 bytes");

    packet = Create<Packet>();
    packet->AddHeader(dio);
    packet->RemoveHeader(received);

    NS_TEST_ASSERT_MSG_EQ(received.HasArt(), true, "The ART option was lost");
    NS_TEST_ASSERT_MSG_EQ(received.GetArt().destSeqNo, 7, "Wrong Dest SeqNo");
    NS_TEST_ASSERT_MSG_EQ(received.GetArt().prefixLength, 0, "Wrong Prefix Length");
    NS_TEST_ASSERT_MSG_EQ(received.GetArt().target, Ipv6Address("2001:2::9"), "Wrong target");
    NS_TEST_ASSERT_MSG_EQ(received.HasRrep(), true, "An earlier option was lost");
    NS_TEST_ASSERT_MSG_EQ(received.GetRank(), 384, "An option ate part of the base object");

    // The P2P Route Discovery Option (RFC 6997 section 7), carried alongside
    // everything already on the DIO above. TargetAddr and the one Address
    // Vector entry both share their first 8 octets with the DODAGID set
    // above (2001:1::1), so Serialize() elides them the same way it does the
    // AODV-RPL RREQ/RREP options' own Address Vectors -- except RFC 6997
    // section 7 elides Compr octets "from the Target field and the Address
    // vector" alike, unlike RFC 9854's ART option, which is a separate
    // option never elided: 2 (Type+Length) + 2 (flags+L/MaxRank) +
    // 2 * (16 - 8).
    NS_TEST_ASSERT_MSG_EQ(dio.HasP2pRdo(), false, "There is no P2P-RDO yet");
    P2pRdoOption rdo;
    rdo.reply = true;
    rdo.hopByHop = false;
    rdo.numRoutes = 0;
    rdo.lifetime = 2; // 16 seconds
    rdo.maxRankOrNh = 10;
    rdo.target = Ipv6Address("2001:1::9");
    rdo.addressVector = {Ipv6Address("2001:1::5")};
    dio.SetP2pRdo(rdo);
    NS_TEST_ASSERT_MSG_EQ(dio.GetSerializedSize(), 150, "The P2P-RDO adds 20 bytes");

    packet = Create<Packet>();
    packet->AddHeader(dio);
    packet->RemoveHeader(received);

    NS_TEST_ASSERT_MSG_EQ(received.HasP2pRdo(), true, "The P2P-RDO was lost");
    NS_TEST_ASSERT_MSG_EQ(received.GetP2pRdo().reply, true, "Wrong 'R' flag");
    NS_TEST_ASSERT_MSG_EQ(received.GetP2pRdo().hopByHop, false, "Wrong 'H' flag");
    NS_TEST_ASSERT_MSG_EQ(received.GetP2pRdo().numRoutes, 0, "Wrong 'N' field");
    NS_TEST_ASSERT_MSG_EQ(received.GetP2pRdo().compr,
                          8,
                          "Wrong Compr: TargetAddr and the Address Vector entry both share the "
                          "DODAGID's prefix, so Serialize() should have elided it");
    NS_TEST_ASSERT_MSG_EQ(received.GetP2pRdo().lifetime, 2, "Wrong 'L' field");
    NS_TEST_ASSERT_MSG_EQ(received.GetP2pRdo().maxRankOrNh, 10, "Wrong MaxRank/NH");
    NS_TEST_ASSERT_MSG_EQ(received.GetP2pRdo().target, Ipv6Address("2001:1::9"), "Wrong TargetAddr");
    NS_TEST_ASSERT_MSG_EQ(received.GetP2pRdo().addressVector.size(), 1, "Wrong Address Vector size");
    NS_TEST_ASSERT_MSG_EQ(received.GetP2pRdo().addressVector[0],
                          Ipv6Address("2001:1::5"),
                          "Wrong Address Vector entry");
    NS_TEST_ASSERT_MSG_EQ(received.HasArt(), true, "An earlier option was lost");
    NS_TEST_ASSERT_MSG_EQ(received.GetRank(), 384, "An option ate part of the base object");

    // 'S'/'G' and 'H' share their octet with Compr and the high bit of 'L':
    // a DIO that sets every one of them at its maximum must not have any of
    // them bleed into a neighbour. RankLimit at 127 is its own 7-bit
    // maximum, which is the field RFC 9854's prose and figure disagree
    // about (@see design-constraints.md) -- 127 is what the figure allows.
    // compr is set here too, but Serialize() ignores it and computes its
    // own from the (empty) Address Vector and the DODAGID instead (@see
    // ElidedPrefixLengthTestCase for that behaviour); 0 is what an empty
    // Address Vector always elides, so this is really exercising the other
    // fields' bit-packing, not Compr's.
    RplDioHeader packed;
    RplDioHeader::RreqOption dense;
    dense.symmetric = true;
    dense.hopByHop = true;
    dense.compr = 15;
    dense.lifetime = 3;
    dense.rankLimit = 127;
    dense.origSeqNo = 255;
    packed.SetRreq(dense);
    packet = Create<Packet>();
    packet->AddHeader(packed);
    packet->RemoveHeader(received);
    NS_TEST_ASSERT_MSG_EQ(received.GetRreq().symmetric, true, "'S' was lost when every bit was set");
    NS_TEST_ASSERT_MSG_EQ(received.GetRreq().hopByHop, true, "'H' was lost when every bit was set");
    NS_TEST_ASSERT_MSG_EQ(received.GetRreq().compr,
                          0,
                          "Serialize() should have computed its own Compr (0, an empty Address "
                          "Vector elides nothing) rather than sending the caller's 15");
    NS_TEST_ASSERT_MSG_EQ(received.GetRreq().lifetime, 3, "'L' was truncated at its maximum");
    NS_TEST_ASSERT_MSG_EQ(received.GetRreq().rankLimit, 127, "RankLimit was truncated at its 7-bit maximum");
    NS_TEST_ASSERT_MSG_EQ(received.GetRreq().origSeqNo, 255, "Orig SeqNo was truncated");

    // The same extreme-bits check for the P2P-RDO's own flag octet and
    // 'L'/MaxRank-NH octet, alongside the RREQ set above on the same DIO.
    // compr is set to 15 here too, but ignored the same way: 'packed' keeps
    // its default (unset) "::" DODAGID, and a concrete target address does
    // not share "::"'s all-zero prefix, so Serialize() computes 0 regardless
    // of what the caller put in rdo.compr.
    P2pRdoOption denseRdo;
    denseRdo.reply = true;
    denseRdo.hopByHop = true;
    denseRdo.numRoutes = 3;    // 2-bit maximum
    denseRdo.compr = 15;       // ignored, Serialize() computes its own
    denseRdo.lifetime = 3;     // 2-bit maximum
    denseRdo.maxRankOrNh = 63; // 6-bit maximum
    denseRdo.target = Ipv6Address("2001:9::1");
    packed.SetP2pRdo(denseRdo);
    packet = Create<Packet>();
    packet->AddHeader(packed);
    packet->RemoveHeader(received);
    NS_TEST_ASSERT_MSG_EQ(received.GetP2pRdo().reply, true, "'R' was lost when every bit was set");
    NS_TEST_ASSERT_MSG_EQ(received.GetP2pRdo().hopByHop, true, "'H' was lost when every bit was set");
    NS_TEST_ASSERT_MSG_EQ(received.GetP2pRdo().numRoutes, 3, "'N' was truncated at its 2-bit maximum");
    NS_TEST_ASSERT_MSG_EQ(received.GetP2pRdo().compr,
                          0,
                          "Serialize() should have computed its own Compr (0, TargetAddr does not "
                          "share '::' DODAGID's prefix) rather than sending the caller's 15");
    NS_TEST_ASSERT_MSG_EQ(received.GetP2pRdo().lifetime, 3, "'L' was truncated at its 2-bit maximum");
    NS_TEST_ASSERT_MSG_EQ(received.GetP2pRdo().maxRankOrNh,
                          63,
                          "MaxRank/NH was truncated at its 6-bit maximum");
    NS_TEST_ASSERT_MSG_EQ(received.GetP2pRdo().target,
                          Ipv6Address("2001:9::1"),
                          "TargetAddr was corrupted");
    NS_TEST_ASSERT_MSG_EQ(received.GetRreq().symmetric,
                          true,
                          "The RREQ option set earlier on 'packed' was lost");
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Compr elision is all-or-nothing: one Address Vector entry that
 *        does not share the DODAGID's first 8 octets is enough to leave
 *        every entry uncompressed.
 *
 * RplDioHeaderTestCase already covers the all-entries-match case (Compr 8,
 * every entry 8 octets on the wire) as part of its own round trip. This is
 * the other half: RplDioHeader::ElidedPrefixLength() has to actually check
 * every entry, not just the first, or a mismatched later one would be
 * reconstructed wrong on the far end.
 */
class RplAodvComprMixedAddressVectorTestCase : public TestCase
{
  public:
    RplAodvComprMixedAddressVectorTestCase();

  private:
    void DoRun() override;
};

RplAodvComprMixedAddressVectorTestCase::RplAodvComprMixedAddressVectorTestCase()
    : TestCase("A mismatched Address Vector entry disables Compr for the whole RREQ")
{
}

void
RplAodvComprMixedAddressVectorTestCase::DoRun()
{
    RplDioHeader dio;
    dio.SetRank(256);
    dio.SetDodagId(Ipv6Address("2001:1::1")); // first 8 octets: 2001:0001:0000:0000

    RplDioHeader::RreqOption rreq;
    rreq.symmetric = true;
    rreq.hopByHop = false;
    rreq.lifetime = 0;
    rreq.rankLimit = 0;
    rreq.origSeqNo = 1;
    // The first entry shares the DODAGID's prefix; the second is under a
    // completely different one and must veto compression for both.
    rreq.addressVector = {Ipv6Address("2001:1::42"), Ipv6Address("fd00:9::1")};
    dio.SetRreq(rreq);

    // 2 (Type+Length) + 3 (base) + 2 * 16 (nothing elided).
    NS_TEST_ASSERT_MSG_EQ(dio.GetSerializedSize(), 24 + 2 + 3 + 32, "Compression was not vetoed");

    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(dio);
    RplDioHeader received;
    packet->RemoveHeader(received);

    NS_TEST_ASSERT_MSG_EQ(received.GetRreq().compr, 0, "Wrong Compr");
    NS_TEST_ASSERT_MSG_EQ(received.GetRreq().addressVector.size(), 2, "Wrong vector size");
    NS_TEST_ASSERT_MSG_EQ(received.GetRreq().addressVector[0],
                          Ipv6Address("2001:1::42"),
                          "Wrong first Address Vector entry");
    NS_TEST_ASSERT_MSG_EQ(received.GetRreq().addressVector[1],
                          Ipv6Address("fd00:9::1"),
                          "Wrong second Address Vector entry");
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check every DIO field at the extremes of the width RFC 6550
 *        section 6.3 gives it, including the ones packed into shared
 *        octets, where an off-by-one shift or a missing mask only shows up
 *        at the top of the range.
 */
class RplDioBoundaryTestCase : public TestCase
{
  public:
    RplDioBoundaryTestCase();

  private:
    void DoRun() override;
};

RplDioBoundaryTestCase::RplDioBoundaryTestCase()
    : TestCase("DIO field boundary values")
{
}

void
RplDioBoundaryTestCase::DoRun()
{
    // The G/MOP/Prf octet: Grounded is one bit, the Mode of Operation
    // three, DAGPreference the remaining three. Every combination of the
    // two three-bit fields, with Grounded both ways, has to come back
    // exactly as it went in.
    for (uint8_t mop = 0; mop <= 7; mop++)
    {
        for (uint8_t preference = 0; preference <= 7; preference++)
        {
            for (bool grounded : {false, true})
            {
                RplDioHeader dio;
                dio.SetMop(mop);
                dio.SetPreference(preference);
                dio.SetGrounded(grounded);

                Ptr<Packet> packet = Create<Packet>();
                packet->AddHeader(dio);
                RplDioHeader received;
                packet->RemoveHeader(received);

                NS_TEST_ASSERT_MSG_EQ(+received.GetMop(),
                                      +mop,
                                      "MOP " << +mop << " did not survive alongside preference "
                                             << +preference);
                NS_TEST_ASSERT_MSG_EQ(+received.GetPreference(),
                                      +preference,
                                      "Preference " << +preference << " did not survive alongside "
                                                    << "MOP " << +mop);
                NS_TEST_ASSERT_MSG_EQ(received.GetGrounded(),
                                      grounded,
                                      "The Grounded flag did not survive alongside MOP "
                                          << +mop << " preference " << +preference);
            }
        }
    }

    // Rank is 16 bits, with 0xffff reserved as INFINITE_RANK (RFC 6550
    // section 17). The eight-bit fields around it take their whole range.
    for (uint16_t rank : {uint16_t(0), uint16_t(1), RPL_MIN_HOPRANKINC, RPL_INFINITE_RANK})
    {
        for (uint8_t byteField : {uint8_t(0), uint8_t(255)})
        {
            RplDioHeader dio;
            dio.SetRank(rank);
            dio.SetInstanceId(byteField);
            dio.SetVersionNumber(byteField);
            dio.SetDtsn(byteField);

            Ptr<Packet> packet = Create<Packet>();
            packet->AddHeader(dio);
            RplDioHeader received;
            packet->RemoveHeader(received);

            NS_TEST_ASSERT_MSG_EQ(received.GetRank(), rank, "Rank " << rank << " did not survive");
            NS_TEST_ASSERT_MSG_EQ(+received.GetInstanceId(),
                                  +byteField,
                                  "RPLInstanceID " << +byteField << " did not survive");
            NS_TEST_ASSERT_MSG_EQ(+received.GetVersionNumber(),
                                  +byteField,
                                  "Version number " << +byteField << " did not survive");
            NS_TEST_ASSERT_MSG_EQ(+received.GetDtsn(),
                                  +byteField,
                                  "DTSN " << +byteField << " did not survive");
        }
    }

    // The DODAG Configuration option (RFC 6550 section 6.7.6) at both ends
    // of every field it holds.
    {
        RplDioHeader dio;
        dio.SetDagConfiguration(0, 0, 0, 0, 0, 0, 0, 0);
        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(dio);
        RplDioHeader received;
        packet->RemoveHeader(received);
        NS_TEST_ASSERT_MSG_EQ(received.HasDagConfiguration(), true, "The all-zero option was lost");
        NS_TEST_ASSERT_MSG_EQ(+received.GetIntervalDoublings(), 0, "Wrong DIOIntervalDoublings");
        NS_TEST_ASSERT_MSG_EQ(+received.GetIntervalMin(), 0, "Wrong DIOIntervalMin");
        NS_TEST_ASSERT_MSG_EQ(+received.GetRedundancy(), 0, "Wrong DIORedundancyConstant");
        NS_TEST_ASSERT_MSG_EQ(received.GetMaxRankIncrease(), 0, "Wrong MaxRankIncrease");
        NS_TEST_ASSERT_MSG_EQ(received.GetMinHopRankIncrease(), 0, "Wrong MinHopRankIncrease");
        NS_TEST_ASSERT_MSG_EQ(received.GetOcp(), 0, "Wrong objective code point");
        NS_TEST_ASSERT_MSG_EQ(+received.GetDefaultLifetime(), 0, "Wrong default lifetime");
        NS_TEST_ASSERT_MSG_EQ(received.GetLifetimeUnit(), 0, "Wrong lifetime unit");

        RplDioHeader saturated;
        saturated.SetDagConfiguration(255, 255, 255, 0xffff, 0xffff, 0xffff, 255, 0xffff);
        packet = Create<Packet>();
        packet->AddHeader(saturated);
        packet->RemoveHeader(received);
        NS_TEST_ASSERT_MSG_EQ(+received.GetIntervalDoublings(), 255, "Wrong DIOIntervalDoublings");
        NS_TEST_ASSERT_MSG_EQ(+received.GetIntervalMin(), 255, "Wrong DIOIntervalMin");
        NS_TEST_ASSERT_MSG_EQ(+received.GetRedundancy(), 255, "Wrong DIORedundancyConstant");
        NS_TEST_ASSERT_MSG_EQ(received.GetMaxRankIncrease(), 0xffff, "Wrong MaxRankIncrease");
        NS_TEST_ASSERT_MSG_EQ(received.GetMinHopRankIncrease(), 0xffff, "Wrong MinHopRankIncrease");
        NS_TEST_ASSERT_MSG_EQ(received.GetOcp(), 0xffff, "Wrong objective code point");
        NS_TEST_ASSERT_MSG_EQ(+received.GetDefaultLifetime(), 255, "Wrong default lifetime");
        NS_TEST_ASSERT_MSG_EQ(received.GetLifetimeUnit(), 0xffff, "Wrong lifetime unit");
    }

    // The ETX metric container, both extremes of its 16-bit fixed-point
    // value (RFC 6551 section 4.3).
    for (uint16_t pathEtx : {uint16_t(0), uint16_t(0xffff)})
    {
        RplDioHeader dio;
        dio.SetMetricContainer(pathEtx);
        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(dio);
        RplDioHeader received;
        packet->RemoveHeader(received);
        NS_TEST_ASSERT_MSG_EQ(received.HasMetricContainer(), true, "The metric container was lost");
        NS_TEST_ASSERT_MSG_EQ(received.GetPathEtx(), pathEtx, "Wrong path ETX");
    }

    // LQL is a four-bit Val sub-field (RFC 6551 section 4.6) of which only
    // 0 to 7 are defined, so the whole defined range has to survive and
    // anything above it must be clamped rather than truncated on the shift.
    for (uint8_t lql = 0; lql <= RPL_LQL_WORST; lql++)
    {
        RplDioHeader dio;
        dio.SetLql(lql);
        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(dio);
        RplDioHeader received;
        packet->RemoveHeader(received);
        NS_TEST_ASSERT_MSG_EQ(received.HasLql(), true, "The LQL option was lost");
        NS_TEST_ASSERT_MSG_EQ(+received.GetLql(), +lql, "LQL " << +lql << " did not survive");
    }

    for (uint8_t lql : {uint8_t(8), uint8_t(15), uint8_t(255)})
    {
        RplDioHeader dio;
        dio.SetLql(lql);
        NS_TEST_ASSERT_MSG_EQ(+dio.GetLql(),
                              +RPL_LQL_WORST,
                              "LQL " << +lql << " was not clamped to the worst defined value");
    }

    // The Prefix Information option (RFC 6550 section 6.7.10): both flags
    // in every combination, the ends of the prefix length, and both
    // lifetimes at their extremes.
    for (bool onLink : {false, true})
    {
        for (bool autonomous : {false, true})
        {
            for (uint8_t prefixLength : {uint8_t(0), uint8_t(64), uint8_t(128)})
            {
                RplDioHeader dio;
                dio.SetPrefixInfo(Ipv6Address("2001:db8::"),
                                  prefixLength,
                                  onLink,
                                  autonomous,
                                  onLink ? 0xffffffff : 0,
                                  autonomous ? 0xffffffff : 0);

                Ptr<Packet> packet = Create<Packet>();
                packet->AddHeader(dio);
                RplDioHeader received;
                packet->RemoveHeader(received);

                NS_TEST_ASSERT_MSG_EQ(received.HasPrefixInfo(), true, "The option was lost");
                NS_TEST_ASSERT_MSG_EQ(received.GetPrefixOnLink(), onLink, "Wrong 'L' flag");
                NS_TEST_ASSERT_MSG_EQ(received.GetPrefixAutonomous(),
                                      autonomous,
                                      "Wrong 'A' flag");
                NS_TEST_ASSERT_MSG_EQ(+received.GetPrefixLength(),
                                      +prefixLength,
                                      "Wrong prefix length");
                NS_TEST_ASSERT_MSG_EQ(received.GetPrefixValidLifetime(),
                                      onLink ? 0xffffffff : 0,
                                      "Wrong Valid Lifetime");
                NS_TEST_ASSERT_MSG_EQ(received.GetPrefixPreferredLifetime(),
                                      autonomous ? 0xffffffff : 0,
                                      "Wrong Preferred Lifetime");
            }
        }
    }
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check that a DIO carrying an option this implementation does not know
 *        is still parsed, i.e. the unknown option is skipped rather than
 *        derailing the rest of the message.
 */
class RplDioUnknownOptionTestCase : public TestCase
{
  public:
    RplDioUnknownOptionTestCase();

  private:
    void DoRun() override;
};

RplDioUnknownOptionTestCase::RplDioUnknownOptionTestCase()
    : TestCase("DIO with an unknown option")
{
}

void
RplDioUnknownOptionTestCase::DoRun()
{
    RplDioHeader dio;
    dio.SetRank(256);
    dio.SetDodagId(Ipv6Address("2001:1::1"));
    dio.SetDagConfiguration(8, 12, 0, 1024, 128, RPL_OCP_OF0, 30, 60);

    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(dio);

    // A Prefix Information option, which this implementation does not read,
    // appended after the DIO the way a real sender would place it.
    uint8_t prefixOption[32] = {RPL_OPTION_PREFIX_INFO, 30};
    Ptr<Packet> trailer = Create<Packet>(prefixOption, sizeof(prefixOption));
    packet->AddAtEnd(trailer);

    RplDioHeader received;
    packet->RemoveHeader(received);

    NS_TEST_ASSERT_MSG_EQ(received.GetRank(), 256, "Wrong rank");
    NS_TEST_ASSERT_MSG_EQ(received.GetDodagId(), Ipv6Address("2001:1::1"), "Wrong DODAGID");
    NS_TEST_ASSERT_MSG_EQ(received.HasDagConfiguration(),
                          true,
                          "The known option was lost behind the unknown one");
    NS_TEST_ASSERT_MSG_EQ(received.GetMinHopRankIncrease(), 128, "Wrong MinHopRankIncrease");
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check that an option whose declared Length claims more bytes than
 *        are actually left in the packet is treated as truncated rather
 *        than read past the buffer's end.
 */
class RplDioTruncatedOptionTestCase : public TestCase
{
  public:
    RplDioTruncatedOptionTestCase();

  private:
    void DoRun() override;
};

RplDioTruncatedOptionTestCase::RplDioTruncatedOptionTestCase()
    : TestCase("DIO with an option whose declared Length exceeds the packet")
{
}

void
RplDioTruncatedOptionTestCase::DoRun()
{
    RplDioHeader dio;
    dio.SetRank(256);
    dio.SetDodagId(Ipv6Address("2001:1::1"));

    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(dio);

    // A DAG Configuration option (type 4, real Length 14) that claims its
    // real Length but is cut off after 4 of the 14 body bytes: the option
    // parser must not walk past the end of what actually follows.
    uint8_t truncated[] = {RPL_OPTION_DAG_CONF, 14, 0, 0, 0, 0};
    Ptr<Packet> trailer = Create<Packet>(truncated, sizeof(truncated));
    packet->AddAtEnd(trailer);

    RplDioHeader received;
    packet->RemoveHeader(received);

    NS_TEST_ASSERT_MSG_EQ(received.HasDagConfiguration(),
                          false,
                          "A truncated option must not be parsed as if it were complete");
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check that a DAG Metric Container option carrying a Routing
 *        Metric/Constraint object type this implementation does not know
 *        is skipped using the option's own validated size, not the
 *        attacker-controlled object-length field inside it.
 */
class RplDioUnknownMetricTypeTestCase : public TestCase
{
  public:
    RplDioUnknownMetricTypeTestCase();

  private:
    void DoRun() override;
};

RplDioUnknownMetricTypeTestCase::RplDioUnknownMetricTypeTestCase()
    : TestCase("DIO with an unknown Routing Metric-Constraint type")
{
}

void
RplDioUnknownMetricTypeTestCase::DoRun()
{
    RplDioHeader dio;
    dio.SetRank(256);
    dio.SetDodagId(Ipv6Address("2001:1::1"));

    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(dio);

    // A DAG Metric Container option (type 2, length 6, i.e.
    // METRIC_CONTAINER_OPTION_LENGTH) whose Routing Metric/Constraint object
    // type (0xff) is not one this implementation understands. Its
    // object-length byte claims 255 bytes of body, far beyond what the
    // option actually carries; a correct parser skips the option using its
    // own validated length (6), not this attacker-controlled value.
    uint8_t unknownMetric[8] = {
        RPL_OPTION_DAG_METRIC_CONTAINER,
        6,    // length
        0xff, // mcType: not RPL_DAG_MC_ETX or RPL_DAG_MC_LQL
        0,    // Res+P+C+O+R
        0,    // A+Prec
        255,  // objLength: bogus, must not be trusted
        0xaa,
        0xbb,
    };
    Ptr<Packet> trailer = Create<Packet>(unknownMetric, sizeof(unknownMetric));
    packet->AddAtEnd(trailer);

    // A known ETX metric container right after it. If the unknown option
    // above was skipped by its own size, this one parses cleanly; if the
    // parser instead trusted objLength=255, it would run off the end of the
    // buffer before ever reaching this option.
    RplDioHeader known;
    known.SetRank(256);
    known.SetDodagId(Ipv6Address("2001:1::1"));
    known.SetMetricContainer(320);
    Ptr<Packet> knownOptionPacket = Create<Packet>();
    knownOptionPacket->AddHeader(known);
    // The ETX option is the last 8 bytes of that serialization.
    Ptr<Packet> etxOption =
        knownOptionPacket->CreateFragment(knownOptionPacket->GetSize() - 8, 8);
    packet->AddAtEnd(etxOption);

    RplDioHeader received;
    packet->RemoveHeader(received);

    NS_TEST_ASSERT_MSG_EQ(received.GetRank(), 256, "Wrong rank");
    NS_TEST_ASSERT_MSG_EQ(received.HasMetricContainer(),
                          true,
                          "The unknown option was not skipped by its own size, so the "
                          "known ETX option after it was never reached");
    NS_TEST_ASSERT_MSG_EQ(received.GetPathEtx(), 320, "The known ETX option was misparsed");
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Walk the remaining shapes an option list can take on the wire
 *        (RFC 6550 section 6.7): padding, an option cut off before its
 *        Length octet, a known option type carrying the wrong Length, and a
 *        metric container whose object body is not the size the type calls
 *        for.
 *
 * All of these have to leave the base object intact and either skip the
 * option or stop cleanly, never mistake part of one option for another.
 */
class RplDioOptionEdgeTestCase : public TestCase
{
  public:
    RplDioOptionEdgeTestCase();

  private:
    void DoRun() override;

    /**
     * @brief Build a DIO with a known rank and DODAGID, with the given
     *        bytes appended as its option list.
     *
     * @param options the raw option bytes to append
     * @param length how many bytes of options
     * @return the DIO as it comes back off the wire
     */
    RplDioHeader RoundTrip(const uint8_t* options, uint32_t length);
};

RplDioOptionEdgeTestCase::RplDioOptionEdgeTestCase()
    : TestCase("DIO option list edge cases")
{
}

RplDioHeader
RplDioOptionEdgeTestCase::RoundTrip(const uint8_t* options, uint32_t length)
{
    RplDioHeader dio;
    dio.SetRank(256);
    dio.SetDodagId(Ipv6Address("2001:1::1"));

    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(dio);
    if (length > 0)
    {
        packet->AddAtEnd(Create<Packet>(options, length));
    }

    RplDioHeader received;
    packet->RemoveHeader(received);
    return received;
}

void
RplDioOptionEdgeTestCase::DoRun()
{
    // Pad1 (RFC 6550 section 6.7.2) is a lone zero octet with no Length of
    // its own; a run of them must be skipped one at a time.
    {
        const uint8_t pad1[4] = {RPL_OPTION_PAD1,
                                 RPL_OPTION_PAD1,
                                 RPL_OPTION_PAD1,
                                 RPL_OPTION_PAD1};
        RplDioHeader received = RoundTrip(pad1, sizeof(pad1));
        NS_TEST_ASSERT_MSG_EQ(received.GetRank(), 256, "Padding ate part of the base object");
        NS_TEST_ASSERT_MSG_EQ(received.HasDagConfiguration(), false, "Padding became an option");
    }

    // PadN (section 6.7.3): a Length and that many zero octets.
    {
        const uint8_t padN[6] = {RPL_OPTION_PADN, 4, 0, 0, 0, 0};
        RplDioHeader received = RoundTrip(padN, sizeof(padN));
        NS_TEST_ASSERT_MSG_EQ(received.GetRank(), 256, "PadN ate part of the base object");
        NS_TEST_ASSERT_MSG_EQ(received.GetDodagId(),
                              Ipv6Address("2001:1::1"),
                              "PadN corrupted the DODAGID");
    }

    // An option type with no Length octet behind it at all: the list ends
    // mid-option and there is nothing to skip by.
    {
        const uint8_t stub[1] = {RPL_OPTION_DAG_CONF};
        RplDioHeader received = RoundTrip(stub, sizeof(stub));
        NS_TEST_ASSERT_MSG_EQ(received.GetRank(), 256, "A one-byte option ate the base object");
        NS_TEST_ASSERT_MSG_EQ(received.HasDagConfiguration(),
                              false,
                              "An option with no Length octet was parsed as if complete");
    }

    // A known option type whose Length is not the one that type has: the
    // implementation only understands the fixed size it emits, so this is
    // skipped as if it were an unknown option, and whatever follows still
    // parses.
    for (uint8_t wrongLength : {uint8_t(0), uint8_t(13), uint8_t(15)})
    {
        std::vector<uint8_t> options;
        options.push_back(RPL_OPTION_DAG_CONF);
        options.push_back(wrongLength);
        options.insert(options.end(), wrongLength, 0);

        // A real ETX metric container right after it, to prove the walk
        // resumed at the right offset rather than somewhere inside the
        // option just skipped.
        const uint8_t etx[8] =
            {RPL_OPTION_DAG_METRIC_CONTAINER, 6, RPL_DAG_MC_ETX, 0, 0, 2, 0x01, 0x40};
        options.insert(options.end(), etx, etx + sizeof(etx));

        RplDioHeader received = RoundTrip(options.data(), options.size());
        NS_TEST_ASSERT_MSG_EQ(received.HasDagConfiguration(),
                              false,
                              "A DAG Configuration option of length " << +wrongLength
                                                                       << " was parsed anyway");
        NS_TEST_ASSERT_MSG_EQ(received.HasMetricContainer(),
                              true,
                              "The option after a length-" << +wrongLength
                                                            << " one was never reached");
        NS_TEST_ASSERT_MSG_EQ(received.GetPathEtx(), 320, "The following option was misparsed");
    }

    // A metric container of the right option length whose ETX object body
    // is not the two octets an ETX object is: not a value this
    // implementation can read, so the metric is not adopted.
    {
        const uint8_t badBody[8] =
            {RPL_OPTION_DAG_METRIC_CONTAINER, 6, RPL_DAG_MC_ETX, 0, 0, 4, 0x01, 0x40};
        RplDioHeader received = RoundTrip(badBody, sizeof(badBody));
        NS_TEST_ASSERT_MSG_EQ(received.HasMetricContainer(),
                              false,
                              "An ETX object of the wrong body length was adopted");
        NS_TEST_ASSERT_MSG_EQ(received.GetRank(), 256, "It also ate part of the base object");
    }

    // The LQL sub-object's Counter nibble (RFC 6551 section 4.6) is not one
    // this implementation reads: whatever it says, the Val nibble above it
    // is what comes out.
    {
        const uint8_t counter[8] =
            {RPL_OPTION_DAG_METRIC_CONTAINER, 6, RPL_DAG_MC_LQL, 0, 0, 2, 0, 0x3f};
        RplDioHeader received = RoundTrip(counter, sizeof(counter));
        NS_TEST_ASSERT_MSG_EQ(received.HasLql(), true, "The LQL option was lost");
        NS_TEST_ASSERT_MSG_EQ(+received.GetLql(), 3, "The Counter nibble leaked into the Val");
    }

    // An empty option list, i.e. a DIO that is only its base object.
    {
        RplDioHeader received = RoundTrip(nullptr, 0);
        NS_TEST_ASSERT_MSG_EQ(received.HasDagConfiguration(), false, "An option appeared");
        NS_TEST_ASSERT_MSG_EQ(received.HasMetricContainer(), false, "An option appeared");
        NS_TEST_ASSERT_MSG_EQ(received.HasLql(), false, "An option appeared");
        NS_TEST_ASSERT_MSG_EQ(received.HasPrefixInfo(), false, "An option appeared");
        NS_TEST_ASSERT_MSG_EQ(received.GetRank(), 256, "Wrong rank");
    }

    // The AODV-RPL RREQ/RREP options (RFC 9854 sections 4.1, 4.2) are the
    // only variable-length options here, so they cannot use the exact
    // `length == <X>_OPTION_LENGTH` guard the four RFC 6550 options above
    // do. What replaces it is a shape check -- a 3-byte fixed part plus a
    // whole number of 16-byte Address Vector entries -- and these cases are
    // what hold that check to the same standard: a length that is not of
    // that shape must be skipped whole, exactly as a wrong fixed length is.
    for (uint8_t badLength : {uint8_t(0), uint8_t(2), uint8_t(4), uint8_t(18), uint8_t(20)})
    {
        std::vector<uint8_t> options;
        options.push_back(RPL_OPTION_AODV_RREQ);
        options.push_back(badLength);
        options.insert(options.end(), badLength, 0);

        // A real ETX metric container behind it, the same way the wrong-length
        // cases above prove the walk resumed at the right offset.
        const uint8_t etx[8] =
            {RPL_OPTION_DAG_METRIC_CONTAINER, 6, RPL_DAG_MC_ETX, 0, 0, 2, 0x01, 0x40};
        options.insert(options.end(), etx, etx + sizeof(etx));

        RplDioHeader received = RoundTrip(options.data(), options.size());
        NS_TEST_ASSERT_MSG_EQ(received.HasRreq(),
                              false,
                              "An RREQ option of length "
                                  << +badLength
                                  << ", which is not 3 + a multiple of 16, was parsed anyway");
        NS_TEST_ASSERT_MSG_EQ(received.HasMetricContainer(),
                              true,
                              "The option after a length-" << +badLength
                                                            << " RREQ was never reached");
        NS_TEST_ASSERT_MSG_EQ(received.GetPathEtx(), 320, "The following option was misparsed");
    }

    // The two lengths that ARE of the right shape at the small end: 3 (an
    // empty Address Vector) and 19 (exactly one entry). Both must parse.
    {
        const uint8_t empty[5] = {RPL_OPTION_AODV_RREQ, 3, 0x80, 0x05, 42};
        RplDioHeader received = RoundTrip(empty, sizeof(empty));
        NS_TEST_ASSERT_MSG_EQ(received.HasRreq(), true, "An empty Address Vector was rejected");
        NS_TEST_ASSERT_MSG_EQ(received.GetRreq().addressVector.size(), 0, "Wrong vector size");
        NS_TEST_ASSERT_MSG_EQ(received.GetRreq().symmetric, true, "Wrong 'S' flag");
        NS_TEST_ASSERT_MSG_EQ(received.GetRreq().rankLimit, 5, "Wrong RankLimit");
        NS_TEST_ASSERT_MSG_EQ(received.GetRreq().origSeqNo, 42, "Wrong Orig SeqNo");
        NS_TEST_ASSERT_MSG_EQ(received.GetRank(), 256, "The option ate part of the base object");
    }
    {
        std::vector<uint8_t> options = {RPL_OPTION_AODV_RREQ, 19, 0x00, 0x00, 1};
        options.insert(options.end(), 16, 0xAB);
        RplDioHeader received = RoundTrip(options.data(), options.size());
        NS_TEST_ASSERT_MSG_EQ(received.HasRreq(), true, "A one-entry Address Vector was rejected");
        NS_TEST_ASSERT_MSG_EQ(received.GetRreq().addressVector.size(), 1, "Wrong vector size");
        NS_TEST_ASSERT_MSG_EQ(received.GetRank(), 256, "The option ate part of the base object");
    }

    // The ART option is fixed at 20 bytes (Prefix Length 0, a full address),
    // so it keeps the ordinary exact-length guard -- checked here so that
    // stays true if the variable-length work above is ever generalised to it.
    {
        std::vector<uint8_t> options = {RPL_OPTION_AODV_ART, 17};
        options.insert(options.end(), 17, 0);
        const uint8_t etx[8] =
            {RPL_OPTION_DAG_METRIC_CONTAINER, 6, RPL_DAG_MC_ETX, 0, 0, 2, 0x01, 0x40};
        options.insert(options.end(), etx, etx + sizeof(etx));

        RplDioHeader received = RoundTrip(options.data(), options.size());
        NS_TEST_ASSERT_MSG_EQ(received.HasArt(), false, "An ART option of length 17 was parsed");
        NS_TEST_ASSERT_MSG_EQ(received.HasMetricContainer(),
                              true,
                              "The option after a wrong-length ART was never reached");
    }

    // An RREQ option whose declared length runs past the end of the packet:
    // the loop's own remaining-size check has to stop the walk before the
    // Address Vector read below it ever runs.
    {
        const uint8_t truncated[6] = {RPL_OPTION_AODV_RREQ, 51, 0x80, 0x00, 1, 0};
        RplDioHeader received = RoundTrip(truncated, sizeof(truncated));
        NS_TEST_ASSERT_MSG_EQ(received.HasRreq(),
                              false,
                              "An RREQ claiming more bytes than the packet holds was parsed");
        NS_TEST_ASSERT_MSG_EQ(received.GetRank(), 256, "It also ate part of the base object");
    }

    // A hand-built RREQ using Compr = 8 (RFC 9854 section 4.1), the way a
    // real interoperating sender might even though this module's own
    // Serialize() only ever emits 0 or 8 -- so a positive, deliberately
    // chosen 8 here still stands in for "some other implementation's
    // choice", not just this module's own. RoundTrip()'s DODAGID is
    // 2001:1::1, whose first 8 octets are 20:01:00:01:00:00:00:00; the
    // entry's remaining 8 octets on the wire are arbitrary bytes standing
    // in for the rest of a real address.
    {
        const uint8_t compressed[13] = {RPL_OPTION_AODV_RREQ,
                                        11, // 3 (base) + 1 * (16 - 8)
                                        0x90, // S=1, Compr=8 ((8 << 1) & 0x1E)
                                        0x05, // RankLimit 5
                                        42,   // Orig SeqNo
                                        0xAA,
                                        0xBB,
                                        0xCC,
                                        0xDD,
                                        0xEE,
                                        0xFF,
                                        0x00,
                                        0x01};
        RplDioHeader received = RoundTrip(compressed, sizeof(compressed));
        NS_TEST_ASSERT_MSG_EQ(received.HasRreq(), true, "A Compr=8 RREQ option was rejected");
        NS_TEST_ASSERT_MSG_EQ(received.GetRreq().compr, 8, "Wrong Compr");
        NS_TEST_ASSERT_MSG_EQ(received.GetRreq().addressVector.size(), 1, "Wrong vector size");
        NS_TEST_ASSERT_MSG_EQ(received.GetRreq().addressVector[0],
                              Ipv6Address("2001:1::aabb:ccdd:eeff:1"),
                              "The DODAGID's first 8 octets were not prepended correctly");
        NS_TEST_ASSERT_MSG_EQ(received.GetRank(), 256, "The option ate part of the base object");
    }

    // The P2P-RDO (RFC 6997 section 7) is variable-length like the AODV-RPL
    // RREQ/RREP options above, but its shape check differs: TargetAddr
    // shares the option with the Address Vector rather than living in a
    // separate option, so the fixed part is 2 bytes (flags + L/MaxRank) and
    // a well-formed option needs at least one (16 - Compr)-sized block (for
    // TargetAddr) plus a whole number of further ones. These lengths are not
    // of that shape at Compr 0 (16-byte blocks) and must be skipped whole.
    for (uint8_t badLength :
        {uint8_t(0), uint8_t(1), uint8_t(3), uint8_t(10), uint8_t(17), uint8_t(19)})
    {
        std::vector<uint8_t> options;
        options.push_back(RPL_OPTION_P2P_RDO);
        options.push_back(badLength);
        options.insert(options.end(), badLength, 0);

        const uint8_t etx[8] =
            {RPL_OPTION_DAG_METRIC_CONTAINER, 6, RPL_DAG_MC_ETX, 0, 0, 2, 0x01, 0x40};
        options.insert(options.end(), etx, etx + sizeof(etx));

        RplDioHeader received = RoundTrip(options.data(), options.size());
        NS_TEST_ASSERT_MSG_EQ(received.HasP2pRdo(),
                              false,
                              "A P2P-RDO of length " << +badLength << ", which cannot hold at "
                                                     << "least a TargetAddr, was parsed anyway");
        NS_TEST_ASSERT_MSG_EQ(received.HasMetricContainer(),
                              true,
                              "The option after a length-" << +badLength
                                                            << " P2P-RDO was never reached");
        NS_TEST_ASSERT_MSG_EQ(received.GetPathEtx(), 320, "The following option was misparsed");
    }

    // The smallest valid shape: TargetAddr only, no Address Vector entries
    // (18 bytes at Compr 0: 2 fixed + one 16-byte block for TargetAddr).
    {
        std::vector<uint8_t> options = {RPL_OPTION_P2P_RDO, 18, 0x00, 0x05};
        options.insert(options.end(), 16, 0xAB);
        RplDioHeader received = RoundTrip(options.data(), options.size());
        NS_TEST_ASSERT_MSG_EQ(received.HasP2pRdo(), true, "A target-only P2P-RDO was rejected");
        NS_TEST_ASSERT_MSG_EQ(received.GetP2pRdo().addressVector.size(), 0, "Wrong vector size");
        NS_TEST_ASSERT_MSG_EQ(received.GetP2pRdo().maxRankOrNh, 5, "Wrong MaxRank/NH");
        NS_TEST_ASSERT_MSG_EQ(received.GetRank(), 256, "The option ate part of the base object");
    }

    // A P2P-RDO whose declared length runs past the end of the packet: the
    // loop's own remaining-size check has to stop the walk before the
    // TargetAddr read below it ever runs.
    {
        const uint8_t truncated[6] = {RPL_OPTION_P2P_RDO, 51, 0x00, 0x0A, 0, 0};
        RplDioHeader received = RoundTrip(truncated, sizeof(truncated));
        NS_TEST_ASSERT_MSG_EQ(received.HasP2pRdo(),
                              false,
                              "A P2P-RDO claiming more bytes than the packet holds was parsed");
        NS_TEST_ASSERT_MSG_EQ(received.GetRank(), 256, "It also ate part of the base object");
    }

    // A hand-built P2P-RDO using Compr = 8, with both TargetAddr and one
    // Address Vector entry compressed -- RFC 6997 section 7 elides both
    // alike, unlike RFC 9854's ART option (@see the RREQ Compr=8 case
    // above).
    {
        const uint8_t compressed[20] = {RPL_OPTION_P2P_RDO,
                                        18, // 2 (flags+L/MaxRank) + 2 * (16 - 8)
                                        0x08, // R=0, H=0, N=0, Compr=8
                                        0x0A, // L=0, MaxRank=10
                                        0x00,
                                        0x00,
                                        0x00,
                                        0x00,
                                        0x00,
                                        0x00,
                                        0x00,
                                        0x09, // TargetAddr suffix
                                        0xAA,
                                        0xBB,
                                        0xCC,
                                        0xDD,
                                        0xEE,
                                        0xFF,
                                        0x00,
                                        0x01}; // Address Vector entry suffix
        RplDioHeader received = RoundTrip(compressed, sizeof(compressed));
        NS_TEST_ASSERT_MSG_EQ(received.HasP2pRdo(), true, "A Compr=8 P2P-RDO was rejected");
        NS_TEST_ASSERT_MSG_EQ(received.GetP2pRdo().compr, 8, "Wrong Compr");
        NS_TEST_ASSERT_MSG_EQ(received.GetP2pRdo().maxRankOrNh, 10, "Wrong MaxRank/NH");
        NS_TEST_ASSERT_MSG_EQ(received.GetP2pRdo().target,
                              Ipv6Address("2001:1::9"),
                              "The DODAGID's first 8 octets were not prepended to TargetAddr "
                              "correctly");
        NS_TEST_ASSERT_MSG_EQ(received.GetP2pRdo().addressVector.size(), 1, "Wrong vector size");
        NS_TEST_ASSERT_MSG_EQ(received.GetP2pRdo().addressVector[0],
                              Ipv6Address("2001:1::aabb:ccdd:eeff:1"),
                              "The DODAGID's first 8 octets were not prepended to the Address "
                              "Vector entry correctly");
        NS_TEST_ASSERT_MSG_EQ(received.GetRank(), 256, "The option ate part of the base object");
    }
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief RPL Target options (RFC 6550 section 6.7.7) on a DIO -- RFC
 *        6997's own reuse of them to name additional P2P-RPL Targets
 *        beyond the P2P-RDO's own primary one.
 *
 * Round trip with 0, 1, and 3 entries (the normal and boundary cases), a
 * Target option with a non-zero declared Prefix Length that this
 * implementation does not support and a truncated one, both of which
 * should be skipped like any other option this implementation does not
 * recognise (RplDioOptionEdgeTestCase's own discipline, applied here
 * since AddTarget()/GetTargets() only ever produces the one shape this
 * implementation supports and so cannot exercise either by itself).
 */
class RplDioTargetOptionTestCase : public TestCase
{
  public:
    RplDioTargetOptionTestCase();

  private:
    void DoRun() override;
};

RplDioTargetOptionTestCase::RplDioTargetOptionTestCase()
    : TestCase("DIO RPL Target options")
{
}

void
RplDioTargetOptionTestCase::DoRun()
{
    // No Target options at all: the common case, since only P2P-RPL
    // multi-Target discoveries ever carry one.
    {
        RplDioHeader dio;
        dio.SetRank(256);
        dio.SetDodagId(Ipv6Address("2001:1::1"));

        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(dio);

        RplDioHeader received;
        packet->RemoveHeader(received);
        NS_TEST_ASSERT_MSG_EQ(received.GetTargets().size(),
                              0,
                              "A Target option appeared from nowhere");
    }

    // One, the minimum a multi-Target discovery actually adds beyond the
    // P2P-RDO's own primary TargetAddr.
    {
        RplDioHeader dio;
        dio.SetRank(256);
        dio.SetDodagId(Ipv6Address("2001:1::1"));
        RplDioHeader::TargetOption target;
        target.target = Ipv6Address("2001:1::9");
        dio.AddTarget(target);

        NS_TEST_ASSERT_MSG_EQ(dio.GetSerializedSize(),
                              24 + 20, // TARGET_OPTION_SIZE, private to RplDioHeader
                              "Wrong serialized size for one Target option");

        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(dio);

        RplDioHeader received;
        packet->RemoveHeader(received);
        NS_TEST_ASSERT_MSG_EQ(received.GetTargets().size(), 1, "Wrong number of Target options");
        NS_TEST_ASSERT_MSG_EQ(received.GetTargets()[0].target,
                              Ipv6Address("2001:1::9"),
                              "Wrong Target address");
        NS_TEST_ASSERT_MSG_EQ(received.GetTargets()[0].prefixLength, 0, "Wrong Prefix Length");
    }

    // Three, in the order added -- AddTarget() appends rather than
    // replaces, unlike every other DIO option this implementation has.
    {
        RplDioHeader dio;
        dio.SetRank(256);
        dio.SetDodagId(Ipv6Address("2001:1::1"));
        for (uint8_t i = 2; i <= 4; i++)
        {
            RplDioHeader::TargetOption target;
            std::ostringstream address;
            address << "2001:1::" << +i;
            target.target = Ipv6Address(address.str().c_str());
            dio.AddTarget(target);
        }

        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(dio);

        RplDioHeader received;
        packet->RemoveHeader(received);
        NS_TEST_ASSERT_MSG_EQ(received.GetTargets().size(), 3, "Wrong number of Target options");
        NS_TEST_ASSERT_MSG_EQ(received.GetTargets()[0].target,
                              Ipv6Address("2001:1::2"),
                              "Wrong first Target address");
        NS_TEST_ASSERT_MSG_EQ(received.GetTargets()[1].target,
                              Ipv6Address("2001:1::3"),
                              "Wrong second Target address");
        NS_TEST_ASSERT_MSG_EQ(received.GetTargets()[2].target,
                              Ipv6Address("2001:1::4"),
                              "Wrong third Target address");
    }

    // A Target option with a nonzero declared Prefix Length: not the
    // fixed 20-byte shape this implementation supports (@see
    // RplDioHeader::TargetOption's own doc comment), but still a
    // well-formed option as far as the generic option loop is concerned,
    // so it is skipped rather than misread -- the same discipline every
    // other option type this implementation does not recognise gets.
    {
        RplDioHeader dio;
        dio.SetRank(256);
        dio.SetDodagId(Ipv6Address("2001:1::1"));

        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(dio);

        // Type, Length (10, a shorter Target Prefix than the 16-byte one
        // TARGET_OPTION_LENGTH itself implies), Flags, Prefix Length (64),
        // and 8 bytes of prefix.
        uint8_t shortPrefixTarget[12] = {
            RPL_OPTION_TARGET, 10, 0, 64, 0x20, 0x01, 0, 1, 0, 0, 0, 0};
        packet->AddAtEnd(Create<Packet>(shortPrefixTarget, sizeof(shortPrefixTarget)));

        RplDioHeader received;
        uint32_t consumed = packet->RemoveHeader(received);
        NS_TEST_ASSERT_MSG_EQ(consumed,
                              24 + sizeof(shortPrefixTarget),
                              "The whole packet, option included, should still have been "
                              "consumed -- skipping is not discarding");
        NS_TEST_ASSERT_MSG_EQ(received.GetTargets().size(),
                              0,
                              "A Target option with an unsupported Prefix Length was accepted "
                              "instead of skipped");
        NS_TEST_ASSERT_MSG_EQ(received.GetRank(), 256, "The option ate part of the base object");
    }

    // A Target option truncated shorter than its own declared Length: the
    // generic option loop's own bounds check (RplDioOptionEdgeTestCase
    // already covers this for other option types; repeated here because
    // AddTarget()/GetTargets() is the first option in this class that can
    // appear more than once, so a truncated one could in principle
    // corrupt the count rather than just being dropped).
    {
        RplDioHeader dio;
        dio.SetRank(256);
        dio.SetDodagId(Ipv6Address("2001:1::1"));

        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(dio);

        // Declares TARGET_OPTION_LENGTH (18) but only 4 bytes actually
        // follow.
        uint8_t truncatedTarget[6] = {RPL_OPTION_TARGET, 18, // TARGET_OPTION_LENGTH, private
                                      0,                 0,
                                      0x20,              0x01};
        packet->AddAtEnd(Create<Packet>(truncatedTarget, sizeof(truncatedTarget)));

        RplDioHeader received;
        packet->RemoveHeader(received);
        NS_TEST_ASSERT_MSG_EQ(received.GetTargets().size(),
                              0,
                              "A truncated Target option should not have been recorded");
        NS_TEST_ASSERT_MSG_EQ(received.GetRank(), 256, "The option ate part of the base object");
    }
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Multiple AODV-RPL Target (ART) options (RFC 9854 section 6.1) on
 *        an RREQ-DIO, via AddArt()/GetArts().
 *
 * SetArt()/GetArt() (RplDioHeaderTestCase's own concern) keep working
 * unchanged -- SetArt() still replaces down to a single entry, matching
 * the RREP-DIO case (section 4.3: "MUST carry exactly one"), which never
 * uses the list API at all.
 */
class RplDioMultiArtTestCase : public TestCase
{
  public:
    RplDioMultiArtTestCase();

  private:
    void DoRun() override;
};

RplDioMultiArtTestCase::RplDioMultiArtTestCase()
    : TestCase("DIO with multiple ART options")
{
}

void
RplDioMultiArtTestCase::DoRun()
{
    // No ART options at all.
    {
        RplDioHeader dio;
        dio.SetRank(256);
        dio.SetDodagId(Ipv6Address("2001:1::1"));

        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(dio);

        RplDioHeader received;
        packet->RemoveHeader(received);
        NS_TEST_ASSERT_MSG_EQ(received.HasArt(), false, "An ART option appeared from nowhere");
        NS_TEST_ASSERT_MSG_EQ(received.GetArts().size(), 0, "Wrong ART count");
    }

    // Three, in the order added.
    {
        RplDioHeader dio;
        dio.SetRank(256);
        dio.SetDodagId(Ipv6Address("2001:1::1"));
        for (uint8_t i = 2; i <= 4; i++)
        {
            RplDioHeader::ArtOption art;
            art.destSeqNo = i;
            std::ostringstream address;
            address << "2001:1::" << +i;
            art.target = Ipv6Address(address.str().c_str());
            dio.AddArt(art);
        }

        NS_TEST_ASSERT_MSG_EQ(dio.GetSerializedSize(), 24 + 3 * 20, "Wrong size for 3 ART options");

        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(dio);

        RplDioHeader received;
        packet->RemoveHeader(received);
        NS_TEST_ASSERT_MSG_EQ(received.HasArt(), true, "The ART options were lost");
        NS_TEST_ASSERT_MSG_EQ(received.GetArts().size(), 3, "Wrong ART count");
        NS_TEST_ASSERT_MSG_EQ(received.GetArts()[0].target,
                              Ipv6Address("2001:1::2"),
                              "Wrong first ART target");
        NS_TEST_ASSERT_MSG_EQ(received.GetArts()[0].destSeqNo, 2, "Wrong first ART Dest SeqNo");
        NS_TEST_ASSERT_MSG_EQ(received.GetArts()[1].target,
                              Ipv6Address("2001:1::3"),
                              "Wrong second ART target");
        NS_TEST_ASSERT_MSG_EQ(received.GetArts()[2].target,
                              Ipv6Address("2001:1::4"),
                              "Wrong third ART target");
        // GetArt() (the single-entry accessor RREP-DIO handling still uses)
        // sees the first of the list, not an error or a default.
        NS_TEST_ASSERT_MSG_EQ(received.GetArt().target,
                              Ipv6Address("2001:1::2"),
                              "GetArt() should see the first of several ART options");
    }

    // SetArt() after AddArt() calls replaces the whole list, not just the
    // first entry -- the "at most one" contract RREP-DIO handling relies
    // on still has to hold even if some other code path built up a list on
    // the same header first.
    {
        RplDioHeader dio;
        dio.SetRank(256);
        dio.SetDodagId(Ipv6Address("2001:1::1"));
        RplDioHeader::ArtOption first;
        first.target = Ipv6Address("2001:1::2");
        dio.AddArt(first);
        RplDioHeader::ArtOption second;
        second.target = Ipv6Address("2001:1::3");
        dio.AddArt(second);

        RplDioHeader::ArtOption replacement;
        replacement.target = Ipv6Address("2001:1::9");
        dio.SetArt(replacement);

        NS_TEST_ASSERT_MSG_EQ(dio.GetArts().size(), 1, "SetArt() should have replaced the list");
        NS_TEST_ASSERT_MSG_EQ(dio.GetArt().target,
                              Ipv6Address("2001:1::9"),
                              "SetArt() did not replace the earlier entries");
    }
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check that a DAO and a DAO-ACK survive a round trip.
 */
class RplDaoHeaderTestCase : public TestCase
{
  public:
    RplDaoHeaderTestCase();

  private:
    void DoRun() override;
};

RplDaoHeaderTestCase::RplDaoHeaderTestCase()
    : TestCase("DAO and DAO-ACK serialization")
{
}

void
RplDaoHeaderTestCase::DoRun()
{
    RplDaoHeader dao;
    dao.SetInstanceId(9);
    dao.SetSequence(77);
    dao.SetAckRequested(true);
    dao.SetDodagId(Ipv6Address("2001:1::1"));
    dao.SetTarget(Ipv6Address("2001:1::5"));
    dao.SetTransitInformation(Ipv6Address("2001:1::4"), 3, 30);

    // Four bytes of base object, the DODAGID, then the Target and the Transit
    // Information options.
    NS_TEST_ASSERT_MSG_EQ(dao.GetSerializedSize(), 4 + 16 + 20 + 22, "Unexpected DAO size");

    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(dao);

    RplDaoHeader received;
    packet->RemoveHeader(received);

    NS_TEST_ASSERT_MSG_EQ(received.GetInstanceId(), 9, "Wrong RPLInstanceID");
    NS_TEST_ASSERT_MSG_EQ(received.GetSequence(), 77, "Wrong DAO sequence");
    NS_TEST_ASSERT_MSG_EQ(received.GetAckRequested(), true, "The K flag was lost");
    NS_TEST_ASSERT_MSG_EQ(received.GetDodagId(), Ipv6Address("2001:1::1"), "Wrong DODAGID");
    NS_TEST_ASSERT_MSG_EQ(received.GetTarget(), Ipv6Address("2001:1::5"), "Wrong target");
    NS_TEST_ASSERT_MSG_EQ(received.GetTargetPrefixLength(), 128, "Wrong target prefix length");
    NS_TEST_ASSERT_MSG_EQ(received.GetParent(), Ipv6Address("2001:1::4"), "Wrong parent");
    NS_TEST_ASSERT_MSG_EQ(received.GetPathSequence(), 3, "Wrong path sequence");
    NS_TEST_ASSERT_MSG_EQ(received.GetPathLifetime(), 30, "Wrong path lifetime");

    // Without the DODAGID the 'D' flag has to stay clear and the header shrink.
    RplDaoHeader noPath;
    noPath.SetTarget(Ipv6Address("2001:1::5"));
    noPath.SetTransitInformation(Ipv6Address("2001:1::4"), 4, 0);
    NS_TEST_ASSERT_MSG_EQ(noPath.GetSerializedSize(), 4 + 20 + 22, "Unexpected DAO size");

    packet = Create<Packet>();
    packet->AddHeader(noPath);
    packet->RemoveHeader(received);
    NS_TEST_ASSERT_MSG_EQ(received.GetDodagId(), Ipv6Address::GetAny(), "The D flag leaked");
    NS_TEST_ASSERT_MSG_EQ(received.GetAckRequested(), false, "The K flag leaked");
    NS_TEST_ASSERT_MSG_EQ(received.GetPathLifetime(), 0, "A No-Path did not survive");

    RplDaoAckHeader daoAck;
    daoAck.SetInstanceId(9);
    daoAck.SetSequence(77);
    daoAck.SetStatus(0);
    daoAck.SetDodagId(Ipv6Address("2001:1::1"));
    NS_TEST_ASSERT_MSG_EQ(daoAck.GetSerializedSize(), 20, "Unexpected DAO-ACK size");

    packet = Create<Packet>();
    packet->AddHeader(daoAck);

    RplDaoAckHeader receivedAck;
    packet->RemoveHeader(receivedAck);
    NS_TEST_ASSERT_MSG_EQ(receivedAck.GetInstanceId(), 9, "Wrong RPLInstanceID");
    NS_TEST_ASSERT_MSG_EQ(receivedAck.GetSequence(), 77, "Wrong DAO sequence");
    NS_TEST_ASSERT_MSG_EQ(receivedAck.GetStatus(), 0, "Wrong status");
    NS_TEST_ASSERT_MSG_EQ(receivedAck.GetDodagId(), Ipv6Address("2001:1::1"), "Wrong DODAGID");
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A DAO aggregating several targets (RFC 6550 section 9.4 rule 3)
 *        survives a serialize/deserialize round trip: the primary target
 *        and every AddTarget()-appended one, in order, each with its own
 *        Path Sequence and Path Lifetime, all sharing the message's single
 *        Transit Information parent field.
 */
class RplDaoMultiTargetHeaderTestCase : public TestCase
{
  public:
    RplDaoMultiTargetHeaderTestCase();

  private:
    void DoRun() override;
};

RplDaoMultiTargetHeaderTestCase::RplDaoMultiTargetHeaderTestCase()
    : TestCase("A DAO aggregating several targets survives serialization")
{
}

void
RplDaoMultiTargetHeaderTestCase::DoRun()
{
    RplDaoHeader dao;
    dao.SetInstanceId(9);
    dao.SetSequence(5);
    dao.SetDodagId(Ipv6Address("2001:1::1"));
    dao.SetTarget(Ipv6Address("2001:1::5"));
    dao.SetTransitInformation(Ipv6Address("2001:1::4"), 3, 30);

    RplDaoHeader::AdditionalTarget second;
    second.target = Ipv6Address("2001:1::6");
    second.targetPrefixLength = 128;
    second.pathSequence = 7;
    second.pathLifetime = 60;
    dao.AddTarget(second);

    RplDaoHeader::AdditionalTarget third;
    third.target = Ipv6Address("2001:1::7");
    third.targetPrefixLength = 128;
    third.pathSequence = 0;
    third.pathLifetime = 0; // a No-Path riding along with two live targets
    dao.AddTarget(third);

    // Base object + DODAGID + 3 * (Target option + Transit Information option).
    NS_TEST_ASSERT_MSG_EQ(dao.GetSerializedSize(),
                          4 + 16 + 3 * (20 + 22),
                          "Unexpected size for a 3-target DAO");

    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(dao);

    RplDaoHeader received;
    packet->RemoveHeader(received);

    // The primary target: unaffected by aggregation, same accessors as a
    // single-target DAO.
    NS_TEST_ASSERT_MSG_EQ(received.GetTarget(), Ipv6Address("2001:1::5"), "Wrong primary target");
    NS_TEST_ASSERT_MSG_EQ(received.GetParent(), Ipv6Address("2001:1::4"), "Wrong primary parent");
    NS_TEST_ASSERT_MSG_EQ(received.GetPathSequence(), 3, "Wrong primary path sequence");
    NS_TEST_ASSERT_MSG_EQ(received.GetPathLifetime(), 30, "Wrong primary path lifetime");

    const auto& additional = received.GetAdditionalTargets();
    NS_TEST_ASSERT_MSG_EQ(additional.size(), 2, "Wrong number of additional targets");

    NS_TEST_ASSERT_MSG_EQ(additional[0].target,
                          Ipv6Address("2001:1::6"),
                          "Wrong 1st additional target");
    NS_TEST_ASSERT_MSG_EQ(+additional[0].pathSequence, 7, "Wrong 1st additional path sequence");
    NS_TEST_ASSERT_MSG_EQ(+additional[0].pathLifetime, 60, "Wrong 1st additional path lifetime");

    NS_TEST_ASSERT_MSG_EQ(additional[1].target,
                          Ipv6Address("2001:1::7"),
                          "Wrong 2nd additional target");
    NS_TEST_ASSERT_MSG_EQ(+additional[1].pathSequence, 0, "Wrong 2nd additional path sequence");
    NS_TEST_ASSERT_MSG_EQ(+additional[1].pathLifetime,
                          0,
                          "Wrong 2nd additional path lifetime: the No-Path riding along with the "
                          "other two live targets did not survive as one");

    // A single-target DAO (every existing caller's own shape) still
    // reports zero additional targets, not a stray empty-but-present one.
    RplDaoHeader single;
    single.SetTarget(Ipv6Address("2001:1::5"));
    single.SetTransitInformation(Ipv6Address("2001:1::4"), 1, 30);
    packet = Create<Packet>();
    packet->AddHeader(single);
    packet->RemoveHeader(received);
    NS_TEST_ASSERT_MSG_EQ(received.GetAdditionalTargets().size(),
                          0,
                          "An ordinary single-target DAO reported additional targets");
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief RFC 6550 section 9.4 rule 3's general form -- N Target options
 *        followed by M Transit Information options, all M applying to all N
 *        -- is a grouping this module's Deserialize() does not implement
 *        (@see its own doc comment). Rather than silently misparse it (an
 *        earlier version overwrote an earlier pending Target with a later
 *        one and paired a Transit Information option with the wrong
 *        Target, losing data without any sign anything was wrong), the
 *        whole message must be discarded per rule 6.
 */
class RplDaoGroupedTargetTransitTestCase : public TestCase
{
  public:
    RplDaoGroupedTargetTransitTestCase();

  private:
    void DoRun() override;

    /// @brief Append one raw Target option (RFC 6550 section 6.7.7).
    /// @param wire the byte buffer to append to
    /// @param target the target address
    /// @param prefixLength the target prefix length
    static void PushTargetOption(std::vector<uint8_t>& wire,
                                 Ipv6Address target,
                                 uint8_t prefixLength);

    /// @brief Append one raw Transit Information option (RFC 6550 section
    ///        6.7.8).
    /// @param wire the byte buffer to append to
    /// @param parent the DODAG Parent Address subfield
    /// @param pathSequence the Path Sequence
    /// @param pathLifetime the Path Lifetime
    static void PushTransitOption(std::vector<uint8_t>& wire,
                                  Ipv6Address parent,
                                  uint8_t pathSequence,
                                  uint8_t pathLifetime);
};

RplDaoGroupedTargetTransitTestCase::RplDaoGroupedTargetTransitTestCase()
    : TestCase("A DAO grouping N Target options with M Transit Information options is discarded "
              "wholesale, not misparsed")
{
}

void
RplDaoGroupedTargetTransitTestCase::PushTargetOption(std::vector<uint8_t>& wire,
                                                      Ipv6Address target,
                                                      uint8_t prefixLength)
{
    wire.push_back(RPL_OPTION_TARGET);
    wire.push_back(18); // Option Length: Flags + Prefix Length + 16-byte address
    wire.push_back(0);  // Flags
    wire.push_back(prefixLength);
    uint8_t buf[16];
    target.Serialize(buf);
    wire.insert(wire.end(), buf, buf + 16);
}

void
RplDaoGroupedTargetTransitTestCase::PushTransitOption(std::vector<uint8_t>& wire,
                                                       Ipv6Address parent,
                                                       uint8_t pathSequence,
                                                       uint8_t pathLifetime)
{
    wire.push_back(RPL_OPTION_TRANSIT);
    wire.push_back(20); // Option Length: flags + Path Control + Seq + Lifetime + 16-byte parent
    wire.push_back(0);  // E flag and flags
    wire.push_back(0);  // Path Control
    wire.push_back(pathSequence);
    wire.push_back(pathLifetime);
    uint8_t buf[16];
    parent.Serialize(buf);
    wire.insert(wire.end(), buf, buf + 16);
}

void
RplDaoGroupedTargetTransitTestCase::DoRun()
{
    // Two Targets followed by three Transit Information options -- RFC
    // 6550 section 6.7.8's own worked example of a non-storing node with
    // more than one DAO parent, legal per rule 3 but not a shape this
    // module supports.
    {
        std::vector<uint8_t> wire{9, 0, 0, 1}; // InstanceId, Flags, Reserved, Sequence
        PushTargetOption(wire, Ipv6Address("2001:1::1"), 128);
        PushTargetOption(wire, Ipv6Address("2001:1::2"), 128);
        PushTransitOption(wire, Ipv6Address("2001:1::10"), 1, 10);
        PushTransitOption(wire, Ipv6Address("2001:1::11"), 2, 20);
        PushTransitOption(wire, Ipv6Address("2001:1::12"), 3, 30);

        Ptr<Packet> packet = Create<Packet>(wire.data(), wire.size());
        RplDaoHeader received;
        packet->RemoveHeader(received);

        NS_TEST_ASSERT_MSG_EQ(received.GetTarget(),
                              Ipv6Address::GetAny(),
                              "A grouped N-Target/M-Transit DAO was not discarded wholesale -- it "
                              "reported a primary target");
        NS_TEST_ASSERT_MSG_EQ(received.GetAdditionalTargets().size(),
                              0,
                              "A grouped N-Target/M-Transit DAO was not discarded wholesale -- it "
                              "reported additional targets");
    }

    // A well-formed pair ahead of the grouped, unsupported tail must not
    // survive either: rule 6 discards the whole message, not just the part
    // that broke the pattern.
    {
        std::vector<uint8_t> wire{9, 0, 0, 1};
        PushTargetOption(wire, Ipv6Address("2001:1::5"), 128);
        PushTransitOption(wire, Ipv6Address("2001:1::4"), 1, 30); // one well-formed pair first
        PushTargetOption(wire, Ipv6Address("2001:1::6"), 128);
        PushTargetOption(wire, Ipv6Address("2001:1::7"), 128); // then two Targets in a row

        Ptr<Packet> packet = Create<Packet>(wire.data(), wire.size());
        RplDaoHeader received;
        packet->RemoveHeader(received);

        NS_TEST_ASSERT_MSG_EQ(received.GetTarget(),
                              Ipv6Address::GetAny(),
                              "A DAO with a well-formed pair ahead of an unsupported grouping "
                              "kept that pair instead of discarding the whole message");
    }
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief P2P-DRO serialization (RFC 6997 section 8): the base object's own
 *        bit-packed S/A/Seq octet, and the one P2P-RDO it carries.
 */
class RplP2pDroHeaderTestCase : public TestCase
{
  public:
    RplP2pDroHeaderTestCase();

  private:
    void DoRun() override;
};

RplP2pDroHeaderTestCase::RplP2pDroHeaderTestCase()
    : TestCase("P2P-DRO serialization")
{
}

void
RplP2pDroHeaderTestCase::DoRun()
{
    RplP2pDroHeader dro;
    dro.SetInstanceId(9);
    dro.SetStop(false);
    dro.SetAckRequested(true);
    dro.SetSequence(2);
    dro.SetDodagId(Ipv6Address("2001:1::1")); // the Origin

    NS_TEST_ASSERT_MSG_EQ(dro.GetSerializedSize(), 20, "The P2P-DRO base object is 20 bytes");
    NS_TEST_ASSERT_MSG_EQ(dro.HasP2pRdo(), false, "There is no P2P-RDO yet");

    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(dro);

    RplP2pDroHeader received;
    packet->RemoveHeader(received);

    NS_TEST_ASSERT_MSG_EQ(received.GetInstanceId(), 9, "Wrong RPLInstanceID");
    NS_TEST_ASSERT_MSG_EQ(received.GetStop(), false, "The 'S' flag leaked");
    NS_TEST_ASSERT_MSG_EQ(received.GetAckRequested(), true, "Wrong 'A' flag");
    NS_TEST_ASSERT_MSG_EQ(received.GetSequence(), 2, "Wrong Seq");
    NS_TEST_ASSERT_MSG_EQ(received.GetDodagId(), Ipv6Address("2001:1::1"), "Wrong DODAGID");
    NS_TEST_ASSERT_MSG_EQ(received.HasP2pRdo(), false, "A P2P-RDO appeared from nowhere");

    // Now with the one P2P-RDO a P2P-DRO MUST carry (RFC 6997 section 8),
    // the Address Vector this time being the whole discovered route back to
    // the Origin -- reusing P2pRdoOption and its Compr elision exactly as
    // the P2P mode DIO side does, since RFC 6997 section 8.2 defines this
    // occurrence of the option "as defined in Section 7".
    P2pRdoOption rdo;
    rdo.reply = false; // section 8.2: "MUST be set to zero on transmission"
    rdo.hopByHop = false;
    rdo.maxRankOrNh = 2; // the NH index, not a MaxRank, inside a P2P-DRO
    rdo.target = Ipv6Address("2001:1::9"); // the Target that generated this P2P-DRO
    rdo.addressVector = {Ipv6Address("2001:1::2"), Ipv6Address("2001:1::3")};
    dro.SetP2pRdo(rdo);
    // 20 (base) + 2 (Type+Length) + 2 (flags+L/MaxRank) + 3 * (16 - 8): the
    // target and both entries share the DODAGID's first 8 octets.
    NS_TEST_ASSERT_MSG_EQ(dro.GetSerializedSize(), 20 + 2 + 2 + 3 * 8, "The P2P-RDO adds 28 bytes");

    packet = Create<Packet>();
    packet->AddHeader(dro);
    packet->RemoveHeader(received);

    NS_TEST_ASSERT_MSG_EQ(received.HasP2pRdo(), true, "The P2P-RDO was lost");
    NS_TEST_ASSERT_MSG_EQ(received.GetP2pRdo().reply, false, "Wrong 'R' flag");
    NS_TEST_ASSERT_MSG_EQ(received.GetP2pRdo().compr,
                          8,
                          "Wrong Compr: TargetAddr and both Address Vector entries share the "
                          "DODAGID's prefix");
    NS_TEST_ASSERT_MSG_EQ(received.GetP2pRdo().maxRankOrNh, 2, "Wrong NH index");
    NS_TEST_ASSERT_MSG_EQ(received.GetP2pRdo().target, Ipv6Address("2001:1::9"), "Wrong TargetAddr");
    NS_TEST_ASSERT_MSG_EQ(received.GetP2pRdo().addressVector.size(), 2, "Wrong Address Vector size");
    NS_TEST_ASSERT_MSG_EQ(received.GetP2pRdo().addressVector[0],
                          Ipv6Address("2001:1::2"),
                          "Wrong first Address Vector entry");
    NS_TEST_ASSERT_MSG_EQ(received.GetP2pRdo().addressVector[1],
                          Ipv6Address("2001:1::3"),
                          "Wrong second Address Vector entry");
    NS_TEST_ASSERT_MSG_EQ(received.GetInstanceId(), 9, "An option ate part of the base object");
    NS_TEST_ASSERT_MSG_EQ(received.GetAckRequested(), true, "An option ate part of the base object");

    // 'S'/'A'/Seq share one octet: the Stop flag set with Seq at its 2-bit
    // maximum must not bleed into the reserved bits around them.
    RplP2pDroHeader packed;
    packed.SetStop(true);
    packed.SetAckRequested(false);
    packed.SetSequence(3);
    packet = Create<Packet>();
    packet->AddHeader(packed);
    packet->RemoveHeader(received);
    NS_TEST_ASSERT_MSG_EQ(received.GetStop(), true, "'S' was lost");
    NS_TEST_ASSERT_MSG_EQ(received.GetAckRequested(), false, "'A' leaked when 'S' was set");
    NS_TEST_ASSERT_MSG_EQ(received.GetSequence(), 3, "Seq was truncated at its 2-bit maximum");

    // RFC 6997 section 8's fixed base object -- RPLInstanceID, Version,
    // flags, Reserved, DODAGID, 20 bytes -- has no length field of its own
    // to validate a received packet against, unlike an option, whose
    // declared length the option loop checks before trusting. Found via
    // /protocol-test-matrix: an earlier version of
    // RplP2pDroHeader::Deserialize() read those 20 bytes unconditionally
    // and crashed on the NS_ASSERT in src/network/model/buffer.h ("You
    // have attempted to read beyond the bounds of the available buffer
    // space") given a packet shorter than that.
    {
        uint8_t shortBody[5] = {0x81, 0, 0, 0, 0};
        Ptr<Packet> shortPacket = Create<Packet>(shortBody, sizeof(shortBody));
        RplP2pDroHeader shortDro;
        uint32_t consumed = shortPacket->RemoveHeader(shortDro);
        NS_TEST_ASSERT_MSG_EQ(consumed, 0, "A truncated P2P-DRO should consume nothing");
        NS_TEST_ASSERT_MSG_EQ(shortDro.HasP2pRdo(),
                              false,
                              "A truncated P2P-DRO should not have produced a P2P-RDO");
    }
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Round-trip the P2P-DRO-ACK (RFC 6997 section 10) and check its
 *        short-packet handling.
 */
class RplP2pDroAckHeaderTestCase : public TestCase
{
  public:
    RplP2pDroAckHeaderTestCase();

  private:
    void DoRun() override;
};

RplP2pDroAckHeaderTestCase::RplP2pDroAckHeaderTestCase()
    : TestCase("P2P-DRO-ACK serialization")
{
}

void
RplP2pDroAckHeaderTestCase::DoRun()
{
    RplP2pDroAckHeader ack;
    ack.SetInstanceId(9);
    ack.SetSequence(2);
    ack.SetDodagId(Ipv6Address("2001:1::1")); // the Origin

    NS_TEST_ASSERT_MSG_EQ(ack.GetSerializedSize(), 20, "The P2P-DRO-ACK is a fixed 20 bytes");

    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(ack);

    RplP2pDroAckHeader received;
    uint32_t consumed = packet->RemoveHeader(received);

    NS_TEST_ASSERT_MSG_EQ(consumed, 20, "Wrong number of bytes consumed");
    NS_TEST_ASSERT_MSG_EQ(received.GetInstanceId(), 9, "Wrong RPLInstanceID");
    NS_TEST_ASSERT_MSG_EQ(received.GetSequence(), 2, "Wrong Seq");
    NS_TEST_ASSERT_MSG_EQ(received.GetDodagId(), Ipv6Address("2001:1::1"), "Wrong DODAGID");

    // Seq is 2 bits, positioned differently from the P2P-DRO's own Seq: no
    // 'S'/'A' flags precede it here (RFC 6997 section 10's Figure 3 has
    // none), so it sits at the top of the third octet rather than after
    // them (@see RPL_P2P_DRO_ACK_SEQ_MASK). Check its 2-bit maximum does
    // not bleed into the Reserved bits around it.
    RplP2pDroAckHeader packed;
    packed.SetSequence(3);
    packet = Create<Packet>();
    packet->AddHeader(packed);
    packet->RemoveHeader(received);
    NS_TEST_ASSERT_MSG_EQ(received.GetSequence(), 3, "Seq was truncated at its 2-bit maximum");

    // Same short-packet discipline as RplP2pDroHeader::Deserialize(): a
    // fixed base object with no length field of its own has to check a
    // received packet's remaining size explicitly before reading it.
    {
        uint8_t shortBody[5] = {9, 0, 0, 0, 0};
        Ptr<Packet> shortPacket = Create<Packet>(shortBody, sizeof(shortBody));
        RplP2pDroAckHeader shortAck;
        uint32_t shortConsumed = shortPacket->RemoveHeader(shortAck);
        NS_TEST_ASSERT_MSG_EQ(shortConsumed, 0, "A truncated P2P-DRO-ACK should consume nothing");
    }
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check the DAO and DAO-ACK at their field boundaries, and against
 *        the option lists a peer could send that this implementation never
 *        does: no Target, no Transit Information, a truncated option, an
 *        unknown one.
 *
 * A DAO with no Target is the case that matters most: RplRoutingProtocol::
 * HandleDao() decides what to do from GetTarget(), so it has to come back
 * as the unspecified address rather than as whatever the previous parse, or
 * the constructor, happened to leave behind.
 */
class RplDaoBoundaryTestCase : public TestCase
{
  public:
    RplDaoBoundaryTestCase();

  private:
    void DoRun() override;
};

RplDaoBoundaryTestCase::RplDaoBoundaryTestCase()
    : TestCase("DAO and DAO-ACK boundary values and option list edge cases")
{
}

void
RplDaoBoundaryTestCase::DoRun()
{
    // Path lifetime 0 is a No-Path (RFC 6550 section 6.4.3) and 0xff is the
    // infinite lifetime; the sequence numbers and prefix length take their
    // whole range.
    for (uint8_t pathLifetime : {uint8_t(0), uint8_t(1), RPL_INFINITE_LIFETIME})
    {
        for (uint8_t sequence : {uint8_t(0), uint8_t(255)})
        {
            for (uint8_t prefixLength : {uint8_t(0), uint8_t(64), uint8_t(128)})
            {
                RplDaoHeader dao;
                dao.SetSequence(sequence);
                dao.SetTarget(Ipv6Address("2001:1::5"), prefixLength);
                dao.SetTransitInformation(Ipv6Address("2001:1::4"), sequence, pathLifetime);

                Ptr<Packet> packet = Create<Packet>();
                packet->AddHeader(dao);
                RplDaoHeader received;
                packet->RemoveHeader(received);

                NS_TEST_ASSERT_MSG_EQ(+received.GetSequence(),
                                      +sequence,
                                      "DAO sequence " << +sequence << " did not survive");
                NS_TEST_ASSERT_MSG_EQ(+received.GetPathSequence(),
                                      +sequence,
                                      "Path sequence " << +sequence << " did not survive");
                NS_TEST_ASSERT_MSG_EQ(+received.GetPathLifetime(),
                                      +pathLifetime,
                                      "Path lifetime " << +pathLifetime << " did not survive");
                NS_TEST_ASSERT_MSG_EQ(+received.GetTargetPrefixLength(),
                                      +prefixLength,
                                      "Target prefix length " << +prefixLength
                                                              << " did not survive");
            }
        }
    }

    // A DAO whose option list is empty: neither a Target nor a Transit
    // Information option. RFC 6550 section 6.4 allows the base object on
    // its own; nothing usable can be read out of it.
    {
        const uint8_t bare[4] = {0, 0, 0, 42};
        Ptr<Packet> packet = Create<Packet>(bare, sizeof(bare));
        RplDaoHeader received;
        packet->RemoveHeader(received);
        NS_TEST_ASSERT_MSG_EQ(received.GetTarget(),
                              Ipv6Address::GetAny(),
                              "A DAO with no Target option reported one anyway");
        NS_TEST_ASSERT_MSG_EQ(received.GetParent(),
                              Ipv6Address::GetAny(),
                              "A DAO with no Transit Information option reported a parent");
        NS_TEST_ASSERT_MSG_EQ(+received.GetSequence(), 42, "Wrong DAO sequence");
        NS_TEST_ASSERT_MSG_EQ(received.GetDodagId(),
                              Ipv6Address::GetAny(),
                              "The 'D' flag was clear but a DODAGID was read");
    }

    // Reusing a header object must not let the previous parse's Target or
    // parent show through the next one.
    {
        RplDaoHeader full;
        full.SetTarget(Ipv6Address("2001:1::5"));
        full.SetTransitInformation(Ipv6Address("2001:1::4"), 1, 30);
        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(full);

        RplDaoHeader received;
        packet->RemoveHeader(received);
        NS_TEST_ASSERT_MSG_EQ(received.GetTarget(), Ipv6Address("2001:1::5"), "Wrong target");

        const uint8_t bare[4] = {0, 0, 0, 1};
        Ptr<Packet> barePacket = Create<Packet>(bare, sizeof(bare));
        barePacket->RemoveHeader(received);
        NS_TEST_ASSERT_MSG_EQ(received.GetTarget(),
                              Ipv6Address::GetAny(),
                              "The previous DAO's target leaked into the next parse");
        NS_TEST_ASSERT_MSG_EQ(received.GetParent(),
                              Ipv6Address::GetAny(),
                              "The previous DAO's parent leaked into the next parse");
    }

    // The same option-length guard the DIO parser has: an option whose
    // declared Length claims more bytes than are left must stop the walk
    // rather than read past the buffer's end. The real options before it
    // still have to come out intact.
    {
        RplDaoHeader dao;
        dao.SetTarget(Ipv6Address("2001:1::5"));
        dao.SetTransitInformation(Ipv6Address("2001:1::4"), 1, 30);
        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(dao);

        const uint8_t truncated[4] = {RPL_OPTION_TARGET, 18, 0, 0};
        packet->AddAtEnd(Create<Packet>(truncated, sizeof(truncated)));

        RplDaoHeader received;
        packet->RemoveHeader(received);
        NS_TEST_ASSERT_MSG_EQ(received.GetTarget(),
                              Ipv6Address("2001:1::5"),
                              "A truncated trailing option overwrote the real target");
        NS_TEST_ASSERT_MSG_EQ(received.GetParent(),
                              Ipv6Address("2001:1::4"),
                              "A truncated trailing option overwrote the real parent");
    }

    // An option this implementation does not know, sitting between the two
    // it does: skipped by its own Length, with the Transit Information
    // behind it still found.
    {
        RplDaoHeader targetOnly;
        targetOnly.SetTarget(Ipv6Address("2001:1::7"));
        targetOnly.SetTransitInformation(Ipv6Address("2001:1::6"), 2, 30);
        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(targetOnly);

        const uint8_t unknown[6] = {RPL_OPTION_TARGET_DESC, 4, 0xde, 0xad, 0xbe, 0xef};
        packet->AddAtEnd(Create<Packet>(unknown, sizeof(unknown)));

        RplDaoHeader received;
        packet->RemoveHeader(received);
        NS_TEST_ASSERT_MSG_EQ(received.GetTarget(), Ipv6Address("2001:1::7"), "Wrong target");
        NS_TEST_ASSERT_MSG_EQ(received.GetParent(), Ipv6Address("2001:1::6"), "Wrong parent");
    }

    // The DAO-ACK's 'D' flag decides whether the DODAGID is on the wire at
    // all (RFC 6550 section 6.5), so the header is 4 or 20 octets.
    {
        RplDaoAckHeader compact;
        compact.SetInstanceId(255);
        compact.SetSequence(255);
        compact.SetStatus(255);
        NS_TEST_ASSERT_MSG_EQ(compact.GetSerializedSize(),
                              4,
                              "A DAO-ACK with no DODAGID is four octets");

        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(compact);
        RplDaoAckHeader received;
        NS_TEST_ASSERT_MSG_EQ(packet->RemoveHeader(received), 4, "Unexpected deserialized size");
        NS_TEST_ASSERT_MSG_EQ(+received.GetInstanceId(), 255, "Wrong RPLInstanceID");
        NS_TEST_ASSERT_MSG_EQ(+received.GetSequence(), 255, "Wrong DAO sequence");
        NS_TEST_ASSERT_MSG_EQ(+received.GetStatus(), 255, "Wrong status");
        NS_TEST_ASSERT_MSG_EQ(received.GetDodagId(),
                              Ipv6Address::GetAny(),
                              "A DODAGID was read out of a four-octet DAO-ACK");

        // And back the other way: a DODAGID set on the same object has to
        // make the header grow again.
        received.SetDodagId(Ipv6Address("2001:1::1"));
        NS_TEST_ASSERT_MSG_EQ(received.GetSerializedSize(),
                              20,
                              "Setting a DODAGID did not grow the DAO-ACK");
    }
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check that the RFC 6554 Routing Header survives a serialize and
 *        deserialize round trip, at the size an uncompressed RH3 costs.
 */
class RplSourceRoutingHeaderTestCase : public TestCase
{
  public:
    RplSourceRoutingHeaderTestCase();

  private:
    void DoRun() override;
};

RplSourceRoutingHeaderTestCase::RplSourceRoutingHeaderTestCase()
    : TestCase("Source routing header")
{
}

void
RplSourceRoutingHeaderTestCase::DoRun()
{
    std::vector<Ipv6Address> addresses = {Ipv6Address("fe80::2"), Ipv6Address("fe80::3")};

    RplSourceRoutingHeader srh;
    srh.SetNextHeader(17); // UDP, as an example inner protocol
    srh.SetSegmentsLeft(2);
    srh.SetAddresses(addresses);

    NS_TEST_ASSERT_MSG_EQ(srh.GetTypeRouting(), RPL_RH_TYPE_SRH, "Wrong Routing Type");

    // Both addresses are link-local, so both get compressed: CmprI=8 elides
    // fe80:: from the first (there is one non-last entry), CmprE=8 elides it
    // from the last -- eight bytes of RH3 plus 8 bytes per entry.
    NS_TEST_ASSERT_MSG_EQ(srh.GetSerializedSize(), 8 + 8 + 8, "Unexpected header size");

    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(srh);
    NS_TEST_ASSERT_MSG_EQ(packet->GetSize(), 8 + 8 + 8, "Unexpected packet size");

    RplSourceRoutingHeader received;
    NS_TEST_ASSERT_MSG_EQ(packet->RemoveHeader(received), 8 + 8 + 8, "Unexpected deserialized size");
    NS_TEST_ASSERT_MSG_EQ(received.GetNextHeader(), 17, "Wrong next header");
    NS_TEST_ASSERT_MSG_EQ(received.GetTypeRouting(), RPL_RH_TYPE_SRH, "Wrong Routing Type");
    NS_TEST_ASSERT_MSG_EQ(received.GetSegmentsLeft(), 2, "Wrong number of segments left");
    NS_TEST_ASSERT_MSG_EQ(received.GetAddresses().size(), 2, "Wrong number of addresses");
    NS_TEST_ASSERT_MSG_EQ(received.GetAddress(0), addresses[0], "Wrong first address");
    NS_TEST_ASSERT_MSG_EQ(received.GetAddress(1), addresses[1], "Wrong second address");
    NS_TEST_ASSERT_MSG_EQ(packet->GetSize(), 0, "The header did not consume the whole packet");
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check RH3 address compression (RFC 6554 section 3): an entry is
 *        elided against fe80:: exactly when it is link-local, in the mixed
 *        shape RplRoutingProtocol::PrepareOutgoingPacket() actually
 *        produces (every hop but the last link-local, the last one global),
 *        and in the fully-uncompressible shape of a path to a multicast or
 *        otherwise non-link-local intermediate hop.
 */
class RplSourceRoutingCompressionTestCase : public TestCase
{
  public:
    RplSourceRoutingCompressionTestCase();

  private:
    void DoRun() override;
};

RplSourceRoutingCompressionTestCase::RplSourceRoutingCompressionTestCase()
    : TestCase("Source routing header address compression")
{
}

void
RplSourceRoutingCompressionTestCase::DoRun()
{
    // Two link-local relay hops, then the global final destination: exactly
    // the shape PrepareOutgoingPacket() builds. CmprI=8 (both relay entries
    // are link-local), CmprE=0 (the last one is global, never compressed).
    {
        std::vector<Ipv6Address> addresses = {Ipv6Address("fe80::2"),
                                              Ipv6Address("fe80::3"),
                                              Ipv6Address("2001:1::ff:fe00:4")};
        RplSourceRoutingHeader srh;
        srh.SetNextHeader(17);
        srh.SetSegmentsLeft(3);
        srh.SetAddresses(addresses);

        NS_TEST_ASSERT_MSG_EQ(srh.GetSerializedSize(),
                              8 + 8 + 8 + 16,
                              "Unexpected size for two compressed relay hops and an "
                              "uncompressed final destination");

        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(srh);

        RplSourceRoutingHeader received;
        NS_TEST_ASSERT_MSG_EQ(packet->RemoveHeader(received),
                              8 + 8 + 8 + 16,
                              "Unexpected deserialized size");
        NS_TEST_ASSERT_MSG_EQ(received.GetAddresses().size(), 3, "Wrong number of addresses");
        NS_TEST_ASSERT_MSG_EQ(received.GetAddress(0), addresses[0], "Wrong first relay hop");
        NS_TEST_ASSERT_MSG_EQ(received.GetAddress(1), addresses[1], "Wrong second relay hop");
        NS_TEST_ASSERT_MSG_EQ(received.GetAddress(2),
                              addresses[2],
                              "Wrong final destination, or its global prefix was corrupted "
                              "by treating it as elided");
    }

    // A single, global-only address (as ComputeSourceRoute() produces for a
    // direct grandchild): CmprI does not apply (no non-last entry), CmprE=0.
    {
        RplSourceRoutingHeader srh;
        srh.SetNextHeader(17);
        srh.SetSegmentsLeft(1);
        srh.SetAddresses({Ipv6Address("2001:1::ff:fe00:9")});

        NS_TEST_ASSERT_MSG_EQ(srh.GetSerializedSize(),
                              8 + 16,
                              "A lone global address must not be compressed");

        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(srh);
        RplSourceRoutingHeader received;
        packet->RemoveHeader(received);
        NS_TEST_ASSERT_MSG_EQ(received.GetAddress(0),
                              Ipv6Address("2001:1::ff:fe00:9"),
                              "Wrong address after a round trip with no compression");
    }
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check the RFC 6554 Routing Header at the edges of its wire format:
 *        an empty address list, the longest list an eight-bit Hdr Ext Len
 *        can describe in either compression regime, and the extremes of
 *        Segments Left.
 */
class RplSourceRoutingBoundaryTestCase : public TestCase
{
  public:
    RplSourceRoutingBoundaryTestCase();

  private:
    void DoRun() override;
};

RplSourceRoutingBoundaryTestCase::RplSourceRoutingBoundaryTestCase()
    : TestCase("Source routing header boundary sizes")
{
}

void
RplSourceRoutingBoundaryTestCase::DoRun()
{
    // No addresses at all: the fixed eight octets and nothing else. Never
    // sent by this implementation (PrepareOutgoingPacket() only attaches a
    // Routing Header for a path of more than one hop), but a header of this
    // shape is well formed and must round trip.
    {
        RplSourceRoutingHeader srh;
        srh.SetNextHeader(59);
        srh.SetSegmentsLeft(0);
        srh.SetAddresses({});
        NS_TEST_ASSERT_MSG_EQ(srh.GetSerializedSize(), 8, "An empty RH3 is eight octets");

        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(srh);
        RplSourceRoutingHeader received;
        NS_TEST_ASSERT_MSG_EQ(packet->RemoveHeader(received), 8, "Unexpected deserialized size");
        NS_TEST_ASSERT_MSG_EQ(received.GetAddresses().size(), 0, "An address appeared from nowhere");
        NS_TEST_ASSERT_MSG_EQ(received.GetSegmentsLeft(), 0, "Wrong number of segments left");
    }

    // 127 global addresses: (127 - 1) * 16 + 16 + 8 = 2040 octets, Hdr Ext
    // Len 254. One more would not fit the eight-bit field at all.
    {
        std::vector<Ipv6Address> addresses(127, Ipv6Address("2001:1::ff:fe00:1"));
        RplSourceRoutingHeader srh;
        srh.SetNextHeader(59);
        srh.SetSegmentsLeft(127);
        srh.SetAddresses(addresses);
        NS_TEST_ASSERT_MSG_EQ(srh.GetSerializedSize(),
                              2040,
                              "Wrong size for the longest uncompressed address list");
        NS_TEST_ASSERT_MSG_LT_OR_EQ(srh.GetSerializedSize(),
                                    RplSourceRoutingHeader::MAX_SERIALIZED_SIZE,
                                    "The longest uncompressed list does not fit Hdr Ext Len");

        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(srh);
        RplSourceRoutingHeader received;
        NS_TEST_ASSERT_MSG_EQ(packet->RemoveHeader(received), 2040, "Unexpected deserialized size");
        NS_TEST_ASSERT_MSG_EQ(received.GetAddresses().size(), 127, "Wrong number of addresses");
        NS_TEST_ASSERT_MSG_EQ(received.GetAddress(126),
                              Ipv6Address("2001:1::ff:fe00:1"),
                              "The last of 127 addresses was lost");
    }

    // Rewriting one entry can change how much of the list compresses, and
    // so the size of the whole header: this is why a hop that relays a
    // source routed packet has to recompute the IPv6 Payload Length from
    // the rebuilt header rather than carry the one it arrived with
    // (RplIpv6ExtensionSourceRouting::Process()).
    {
        RplSourceRoutingHeader srh;
        srh.SetNextHeader(59);
        srh.SetSegmentsLeft(3);
        srh.SetAddresses({Ipv6Address("fe80::2"),
                          Ipv6Address("fe80::3"),
                          Ipv6Address("2001:1::ff:fe00:4")});
        // CmprI = 8 (both relay hops are link-local), CmprE = 0.
        NS_TEST_ASSERT_MSG_EQ(srh.GetSerializedSize(), 8 + 8 + 8 + 16, "Unexpected initial size");

        // What a relay hop does: the slot it was addressed under takes the
        // packet's current destination, a global address here, which stops
        // the non-last entries from all being link-local and so turns
        // CmprI off.
        srh.SetAddress(0, Ipv6Address("2001:1::ff:fe00:1"));
        NS_TEST_ASSERT_MSG_EQ(srh.GetSerializedSize(),
                              8 + 16 + 16 + 16,
                              "Rewriting an entry did not change the compressed size");

        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(srh);
        RplSourceRoutingHeader received;
        NS_TEST_ASSERT_MSG_EQ(packet->RemoveHeader(received),
                              8 + 16 + 16 + 16,
                              "The rewritten header did not round trip at its new size");
        NS_TEST_ASSERT_MSG_EQ(received.GetAddress(0),
                              Ipv6Address("2001:1::ff:fe00:1"),
                              "The rewritten entry was lost");
        NS_TEST_ASSERT_MSG_EQ(received.GetAddress(1),
                              Ipv6Address("fe80::3"),
                              "An entry that was not rewritten changed");
    }

    // 255 link-local addresses: every entry compresses to eight octets, so
    // 255 * 8 + 8 = 2048, Hdr Ext Len 255, the largest RH3 there is.
    {
        std::vector<Ipv6Address> addresses(255, Ipv6Address("fe80::1"));
        RplSourceRoutingHeader srh;
        srh.SetNextHeader(59);
        srh.SetSegmentsLeft(255);
        srh.SetAddresses(addresses);
        NS_TEST_ASSERT_MSG_EQ(srh.GetSerializedSize(),
                              RplSourceRoutingHeader::MAX_SERIALIZED_SIZE,
                              "Wrong size for the longest compressed address list");

        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(srh);
        RplSourceRoutingHeader received;
        NS_TEST_ASSERT_MSG_EQ(packet->RemoveHeader(received), 2048, "Unexpected deserialized size");
        NS_TEST_ASSERT_MSG_EQ(received.GetAddresses().size(), 255, "Wrong number of addresses");
        NS_TEST_ASSERT_MSG_EQ(received.GetSegmentsLeft(), 255, "Wrong number of segments left");
        NS_TEST_ASSERT_MSG_EQ(received.GetAddress(254),
                              Ipv6Address("fe80::1"),
                              "The last of 255 compressed addresses was lost");
    }
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check that a Routing Header whose Hdr Ext Len claims more octets
 *        than the packet actually carries is clamped to what is really
 *        there rather than read past the end of the buffer.
 *
 * RFC 8200 section 4.4's Hdr Ext Len is written by the sender, so a
 * truncated or hand-built header can claim any length at all. ns-3's
 * Buffer::Iterator only range-checks under NS_ASSERT, which an optimized
 * build compiles out, so the parser has to do the checking itself.
 */
class RplSourceRoutingTruncatedTestCase : public TestCase
{
  public:
    RplSourceRoutingTruncatedTestCase();

  private:
    void DoRun() override;
};

RplSourceRoutingTruncatedTestCase::RplSourceRoutingTruncatedTestCase()
    : TestCase("Source routing header with a Hdr Ext Len past the end of the packet")
{
}

void
RplSourceRoutingTruncatedTestCase::DoRun()
{
    // Eight octets of RH3 and nothing else, claiming 30 more eight-octet
    // units (248 octets of addresses) follow.
    {
        uint8_t raw[8] = {59, 30, RPL_RH_TYPE_SRH, 1, 0x00, 0, 0, 0};
        Ptr<Packet> packet = Create<Packet>(raw, sizeof(raw));

        RplSourceRoutingHeader received;
        NS_TEST_ASSERT_MSG_EQ(packet->RemoveHeader(received),
                              8,
                              "A Hdr Ext Len past the end of the packet was not clamped");
        NS_TEST_ASSERT_MSG_EQ(received.GetAddresses().size(),
                              0,
                              "Addresses were reconstructed out of bytes that are not there");
        NS_TEST_ASSERT_MSG_EQ(packet->GetSize(), 0, "More was consumed than the packet held");
    }

    // Partially truncated: room for one uncompressed address, but the
    // header claims two.
    {
        uint8_t raw[24] = {59, 2, RPL_RH_TYPE_SRH, 2, 0x00, 0, 0, 0};
        Ipv6Address("2001:1::5").Serialize(raw + 8);
        // Only 24 of the 40 octets a Hdr Ext Len of 2 would need.
        Ptr<Packet> packet = Create<Packet>(raw, sizeof(raw));

        RplSourceRoutingHeader received;
        NS_TEST_ASSERT_MSG_EQ(packet->RemoveHeader(received),
                              24,
                              "The size consumed was not clamped to the packet");
        NS_TEST_ASSERT_MSG_EQ(received.GetAddresses().size(),
                              1,
                              "Wrong number of addresses recovered from a truncated header");
        NS_TEST_ASSERT_MSG_EQ(received.GetAddress(0),
                              Ipv6Address("2001:1::5"),
                              "The one address that was really there was misparsed");
    }

    // A Hdr Ext Len of 0, i.e. the eight fixed octets and no address, with
    // Segments Left claiming otherwise: nothing to read, and the
    // inconsistency is Process()'s to reject, not Deserialize()'s.
    {
        uint8_t raw[8] = {59, 0, RPL_RH_TYPE_SRH, 4, 0x00, 0, 0, 0};
        Ptr<Packet> packet = Create<Packet>(raw, sizeof(raw));

        RplSourceRoutingHeader received;
        NS_TEST_ASSERT_MSG_EQ(packet->RemoveHeader(received), 8, "Unexpected deserialized size");
        NS_TEST_ASSERT_MSG_EQ(received.GetAddresses().size(), 0, "An address appeared from nowhere");
        NS_TEST_ASSERT_MSG_EQ(received.GetSegmentsLeft(), 4, "Segments Left was not read");
    }
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check the Trickle timer of RFC 6206: the interval doubles up to Imax,
 *        every transmission falls in [I/2, I), a reset goes back to Imin and
 *        the redundancy constant suppresses a redundant transmission.
 */
class RplTrickleTimerTestCase : public TestCase
{
  public:
    RplTrickleTimerTestCase();

  private:
    void DoRun() override;

    /**
     * @brief Record a transmission.
     */
    void Transmit();

    std::vector<Time> m_transmissions; //!< when the timer decided to transmit
};

RplTrickleTimerTestCase::RplTrickleTimerTestCase()
    : TestCase("Trickle timer")
{
}

void
RplTrickleTimerTestCase::Transmit()
{
    m_transmissions.push_back(Simulator::Now());
}

void
RplTrickleTimerTestCase::DoRun()
{
    // Imin = 1 s, two doublings, so Imax = 4 s.
    RplTrickleTimer trickle;
    trickle.SetParameters(Seconds(1), 2, 0);
    trickle.SetFunction(MakeCallback(&RplTrickleTimerTestCase::Transmit, this));
    trickle.AssignStreams(1);

    NS_TEST_ASSERT_MSG_EQ(trickle.IsRunning(), false, "The timer runs before it was started");

    // Stopping on an interval boundary keeps the count deterministic: the
    // intervals are [0,1), [1,3), [3,7), [7,11), [11,15), [15,19), [19,23) and
    // [23,27), and the transmission of the interval starting at 27 s cannot
    // happen before 29 s.
    Simulator::Schedule(Seconds(0), &RplTrickleTimer::Start, &trickle);
    Simulator::Stop(Seconds(27));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(trickle.IsRunning(), true, "The timer stopped on its own");
    NS_TEST_ASSERT_MSG_EQ(trickle.GetInterval(), Seconds(4), "The interval did not reach Imax");

    // Intervals are [0,1), [1,3), [3,7), [7,11), [11,15) and so on, and each
    // one transmits exactly once, in its second half.
    NS_TEST_ASSERT_MSG_EQ(m_transmissions.size(), 8, "Wrong number of transmissions");

    Time start = Seconds(0);
    Time interval = Seconds(1);
    for (auto transmission : m_transmissions)
    {
        NS_TEST_ASSERT_MSG_GT_OR_EQ(transmission,
                                    start + interval / 2,
                                    "A transmission happened in the first half of the interval");
        NS_TEST_ASSERT_MSG_LT(transmission,
                              start + interval,
                              "A transmission happened after the end of the interval");
        start += interval;
        interval = std::min(interval + interval, Seconds(4));
    }

    trickle.Reset();
    NS_TEST_ASSERT_MSG_EQ(trickle.GetInterval(), Seconds(1), "A reset did not go back to Imin");

    trickle.Stop();
    NS_TEST_ASSERT_MSG_EQ(trickle.IsRunning(), false, "The timer kept running after Stop()");
    Simulator::Destroy();

    // With k = 1, one consistent message heard during the interval is enough
    // to suppress the transmission.
    m_transmissions.clear();
    RplTrickleTimer suppressed;
    suppressed.SetParameters(Seconds(1), 0, 1);
    suppressed.SetFunction(MakeCallback(&RplTrickleTimerTestCase::Transmit, this));
    suppressed.AssignStreams(1);

    Simulator::Schedule(Seconds(0), &RplTrickleTimer::Start, &suppressed);
    for (uint32_t i = 0; i < 3; i++)
    {
        // One hit per interval, before the transmission can happen at I/2.
        Simulator::Schedule(Seconds(i) + MilliSeconds(1),
                            &RplTrickleTimer::ConsistencyHit,
                            &suppressed);
    }
    Simulator::Stop(Seconds(3));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(m_transmissions.size(), 0, "The redundancy constant did not suppress");
    suppressed.Stop();
    Simulator::Destroy();

    // A timer that was never started ignores a reset: Reset() reschedules,
    // and rescheduling one that is not running would start it behind the
    // caller's back.
    RplTrickleTimer idle;
    idle.SetParameters(Seconds(1), 2, 0);
    idle.SetFunction(MakeCallback(&RplTrickleTimerTestCase::Transmit, this));
    idle.AssignStreams(1);
    idle.Reset();
    NS_TEST_ASSERT_MSG_EQ(idle.IsRunning(), false, "A reset started a timer that was not running");

    m_transmissions.clear();
    Simulator::Stop(Seconds(5));
    Simulator::Run();
    NS_TEST_ASSERT_MSG_EQ(m_transmissions.size(), 0, "A timer that was never started transmitted");
    Simulator::Destroy();

    // Zero doublings: Imax equals Imin, so the interval never grows and
    // every interval is one second long. Stopping at 10 s, on an interval
    // boundary, makes the count exact.
    m_transmissions.clear();
    RplTrickleTimer flat;
    flat.SetParameters(Seconds(1), 0, 0);
    flat.SetFunction(MakeCallback(&RplTrickleTimerTestCase::Transmit, this));
    flat.AssignStreams(1);

    Simulator::Schedule(Seconds(0), &RplTrickleTimer::Start, &flat);
    Simulator::Stop(Seconds(10));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(flat.GetInterval(), Seconds(1), "Imax should equal Imin at 0 doublings");
    NS_TEST_ASSERT_MSG_EQ(m_transmissions.size(),
                          10,
                          "One transmission per one-second interval was expected");

    // A reset while already at Imin changes nothing, and in particular must
    // not reschedule the transmission that is already pending for this
    // interval into an extra one.
    size_t before = m_transmissions.size();
    flat.Reset();
    NS_TEST_ASSERT_MSG_EQ(flat.GetInterval(), Seconds(1), "A reset at Imin moved the interval");
    // One more interval: Simulator::Stop() takes a delay from now, not an
    // absolute time.
    Simulator::Stop(Seconds(1));
    Simulator::Run();
    NS_TEST_ASSERT_MSG_EQ(m_transmissions.size(),
                          before + 1,
                          "A reset at Imin produced an extra transmission");

    flat.Stop();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Build a DODAG over a line of three nodes and check the ranks, the
 *        preferred parents and the upward route that comes out of it.
 *
 * All three nodes sit on one SimpleNetDevice channel, with the two ends
 * blacklisted against each other so that only neighbours hear one another.
 * Giving every node a single interface on a single prefix is what an LLN looks
 * like, and what RPL assumes: a node learns the address of a neighbour by
 * putting the interface identifier of its link-local address under the prefix
 * of the DODAGID, which only works when there is one of each.
 */
class RplDodagFormationTestCase : public TestCase
{
  public:
    RplDodagFormationTestCase();

  private:
    void DoRun() override;
};

RplDodagFormationTestCase::RplDodagFormationTestCase()
    : TestCase("DODAG formation over a line of three nodes")
{
}

void
RplDodagFormationTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(3);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    // The two ends of the line cannot hear each other, which is what makes it
    // a line rather than one big neighbourhood.
    Ptr<SimpleNetDevice> first = DynamicCast<SimpleNetDevice>(devices.Get(0));
    Ptr<SimpleNetDevice> last = DynamicCast<SimpleNetDevice>(devices.Get(2));
    channel->BlackList(first, last);
    channel->BlackList(last, first);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);

    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    // Imin is 4.096 s and the Trickle interval doubles every time, so the
    // second hop needs a couple of minutes to settle. DAD (RFC 4862) adds
    // about a second on top of that, both for the root's own SLAAC address
    // and, once the DIO carrying it arrives, each other node's.
    Simulator::Stop(Seconds(200));
    Simulator::Run();

    Ptr<RplRoutingProtocol> root = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> middle = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> leaf = nodes.Get(2)->GetObject<RplRoutingProtocol>();

    Ipv6Address dodagId = root->GetGlobalAddress();
    Ipv6Address middleAddress = middle->GetGlobalAddress();
    Ipv6Address leafAddress = leaf->GetGlobalAddress();

    NS_TEST_ASSERT_MSG_EQ(root->IsRoot(), true, "Node 0 is not the root");
    NS_TEST_ASSERT_MSG_EQ(root->IsJoined(), true, "The root is not in its own DODAG");
    NS_TEST_ASSERT_MSG_EQ(root->GetDodagId(), dodagId, "The DODAGID is not the root's address");
    NS_TEST_ASSERT_MSG_EQ(root->GetRank(),
                          RPL_MIN_HOPRANKINC,
                          "The root is not at MinHopRankIncrease");
    NS_TEST_ASSERT_MSG_EQ(root->GetPreferredParent(),
                          Ipv6Address::GetAny(),
                          "The root took a parent");

    NS_TEST_ASSERT_MSG_EQ(middle->IsJoined(), true, "Node 1 did not join the DODAG");
    NS_TEST_ASSERT_MSG_EQ(middle->GetDodagId(), dodagId, "Node 1 joined another DODAG");
    NS_TEST_ASSERT_MSG_EQ(middle->GetRank(), 2 * RPL_MIN_HOPRANKINC, "Node 1 is one hop out");

    NS_TEST_ASSERT_MSG_EQ(leaf->IsJoined(), true, "Node 2 did not join the DODAG");
    NS_TEST_ASSERT_MSG_EQ(leaf->GetDodagId(), dodagId, "Node 2 joined another DODAG");
    NS_TEST_ASSERT_MSG_EQ(leaf->GetRank(), 3 * RPL_MIN_HOPRANKINC, "Node 2 is two hops out");

    // The preferred parents have to be the link-local addresses of the
    // neighbour towards the root, which is what makes the line a line.
    Ptr<Ipv6L3Protocol> rootIpv6 = nodes.Get(0)->GetObject<Ipv6L3Protocol>();
    Ptr<Ipv6L3Protocol> middleIpv6 = nodes.Get(1)->GetObject<Ipv6L3Protocol>();

    NS_TEST_ASSERT_MSG_EQ(middle->GetPreferredParent(),
                          rootIpv6->GetAddress(1, 0).GetAddress(),
                          "Node 1 did not pick the root as its parent");
    NS_TEST_ASSERT_MSG_EQ(leaf->GetPreferredParent(),
                          middleIpv6->GetAddress(1, 0).GetAddress(),
                          "Node 2 did not pick node 1 as its parent");

    // An upward route exists and points at the preferred parent.
    Ipv6Header header;
    header.SetDestination(dodagId);
    Socket::SocketErrno sockerr;
    Ptr<Ipv6Route> route =
        leaf->RouteOutput(Create<Packet>(), header, nullptr, sockerr);
    NS_TEST_ASSERT_MSG_EQ(route != nullptr, true, "Node 2 has no route to the root");
    NS_TEST_ASSERT_MSG_EQ(route->GetGateway(),
                          leaf->GetPreferredParent(),
                          "The route to the root does not go through the preferred parent");

    // The DAOs told the root where both other nodes sit.
    NS_TEST_ASSERT_MSG_EQ(root->GetTopologySize(), 2, "The root did not hear from both nodes");
    NS_TEST_ASSERT_MSG_EQ(middle->GetTopologySize(), 0, "A node that is not the root kept a topology");

    // A Routing Header carries link-local addresses, one radio hop apart, the
    // same as any other RPL neighbour address.
    Ipv6Address middleLinkLocal = middleIpv6->GetAddress(1, 0).GetAddress();
    Ptr<Ipv6L3Protocol> leafIpv6 = nodes.Get(2)->GetObject<Ipv6L3Protocol>();
    Ipv6Address leafLinkLocal = leafIpv6->GetAddress(1, 0).GetAddress();

    // Node 1 hangs off the root: one hop, itself, so no Routing Header is
    // needed to reach it.
    std::vector<Ipv6Address> hops;
    NS_TEST_ASSERT_MSG_EQ(root->ComputeSourceRoute(middleAddress, hops),
                          true,
                          "The root cannot reach node 1");
    NS_TEST_ASSERT_MSG_EQ(hops.size(), 1, "A direct child is one hop: itself");
    NS_TEST_ASSERT_MSG_EQ(hops[0], middleLinkLocal, "Wrong hop for node 1");

    // Node 2 is behind node 1, so the path has to name node 1, then node 2.
    NS_TEST_ASSERT_MSG_EQ(root->ComputeSourceRoute(leafAddress, hops),
                          true,
                          "The root cannot reach node 2");
    NS_TEST_ASSERT_MSG_EQ(hops.size(), 2, "The path to node 2 should hold two hops");
    NS_TEST_ASSERT_MSG_EQ(hops[0], middleLinkLocal, "The path to node 2 does not go through node 1");
    NS_TEST_ASSERT_MSG_EQ(hops[1], leafLinkLocal, "The path to node 2 does not end at node 2");

    NS_TEST_ASSERT_MSG_EQ(root->ComputeSourceRoute(Ipv6Address("2001:9::1"), hops),
                          false,
                          "The root invented a path to a node it never heard of");

    // A packet the root sends to node 2 leaves towards node 1, and
    // PrepareOutgoingPacket() -- called by Ipv6L3Protocol::Send() right
    // before a packet reaches the wire -- attaches the real Routing Header
    // that gets it the rest of the way, behind an RPL Option (RFC 6553) that
    // every packet gets regardless of whether it needs a Routing Header too.
    Ptr<Packet> downward = Create<Packet>();
    header.SetDestination(leafAddress);
    header.SetNextHeader(17); // UDP, as an example inner protocol
    route = root->RouteOutput(downward, header, nullptr, sockerr);
    NS_TEST_ASSERT_MSG_EQ(route != nullptr, true, "The root has no route down to node 2");
    NS_TEST_ASSERT_MSG_EQ(route->GetGateway(),
                          middleLinkLocal,
                          "The packet for node 2 does not leave towards node 1");

    root->PrepareOutgoingPacket(downward, header, route);
    NS_TEST_ASSERT_MSG_EQ(header.GetDestination(),
                          middleLinkLocal,
                          "The wire header was not redirected to the first hop");
    NS_TEST_ASSERT_MSG_EQ(header.GetNextHeader(),
                          Ipv6Header::IPV6_EXT_HOP_BY_HOP,
                          "The next header was not set to Hop-by-Hop");

    // The RPL Option: Next Header, Hdr Ext Len, then the option itself
    // (Type, Length, Flags, RPLInstanceID, SenderRank), 8 bytes total, no
    // padding needed.
    uint8_t hbh[8];
    downward->CopyData(hbh, sizeof(hbh));
    NS_TEST_ASSERT_MSG_EQ(+hbh[0], Ipv6Header::IPV6_EXT_ROUTING, "Hop-by-Hop does not lead to Routing");
    NS_TEST_ASSERT_MSG_EQ(+hbh[2], RPL_HBH_OPTION_TYPE, "Wrong option type");
    NS_TEST_ASSERT_MSG_EQ(+hbh[4] & RPL_HDR_OPT_DOWN, RPL_HDR_OPT_DOWN, "The 'O' flag was not set");
    NS_TEST_ASSERT_MSG_EQ((hbh[6] << 8) | hbh[7], root->GetRank(), "Wrong SenderRank");
    downward->RemoveAtStart(sizeof(hbh));

    RplSourceRoutingHeader srh;
    NS_TEST_ASSERT_MSG_EQ(downward->RemoveHeader(srh), 8 + 16, "Unexpected Routing Header size");
    NS_TEST_ASSERT_MSG_EQ(srh.GetNextHeader(), 17, "The inner protocol was not carried forward");
    NS_TEST_ASSERT_MSG_EQ(srh.GetSegmentsLeft(), 1, "Wrong number of segments left");
    NS_TEST_ASSERT_MSG_EQ(srh.GetAddresses().size(), 1, "Wrong number of addresses");
    // The final entry is the global address, not the link-local one
    // ComputeSourceRoute() returns: a link-local final hop becomes the wire
    // destination once segmentsLeft reaches 0
    // (RplIpv6ExtensionSourceRouting::Process()), which the reply an
    // application sends back echoes as its own source address
    // (Icmpv6L4Protocol::HandleEchoRequest() and friends), and a link-local
    // source address is scoped to one hop -- it gets silently dropped by
    // Ipv6L3Protocol::IpForward() on any hop after that on the way back to
    // the root.
    NS_TEST_ASSERT_MSG_EQ(srh.GetAddress(0), leafAddress, "Wrong final address");

    // Node 1 is one hop away, so its packet gets no Routing Header, only the
    // RPL Option, and the wire destination stays node 1's own address.
    Ptr<Packet> direct = Create<Packet>();
    header.SetDestination(middleAddress);
    header.SetNextHeader(17);
    route = root->RouteOutput(direct, header, nullptr, sockerr);
    NS_TEST_ASSERT_MSG_EQ(route != nullptr, true, "The root has no route down to node 1");
    root->PrepareOutgoingPacket(direct, header, route);
    NS_TEST_ASSERT_MSG_EQ(direct->GetSize(), 8, "Wrong size for an RPL Option with no Routing Header");
    NS_TEST_ASSERT_MSG_EQ(header.GetNextHeader(),
                          Ipv6Header::IPV6_EXT_HOP_BY_HOP,
                          "The next header was not set to Hop-by-Hop");
    NS_TEST_ASSERT_MSG_EQ(header.GetDestination(),
                          middleAddress,
                          "A direct child's packet had its destination rewritten");

    direct->CopyData(hbh, sizeof(hbh));
    NS_TEST_ASSERT_MSG_EQ(+hbh[0], 17, "Hop-by-Hop does not lead to the inner protocol");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Build a Storing mode (RFC 6550 section 9.8) DODAG over a line of
 *        four nodes and check that every non-leaf node's own downward route
 *        table -- not the root-only topology Non-Storing mode uses -- is
 *        what carries data both ways.
 *
 *     root(0) ---- relay1(1) ---- relay2(2) ---- leaf(3)
 *
 * Unlike RplDodagFormationTestCase's Non-Storing DODAG, where only the root
 * ever learns anything and every downward packet carries its own path in a
 * Routing Header, here every one of relay1/relay2/root has to learn its own
 * next hop toward leaf from the DAOs relay2/relay1 each relay in turn (RFC
 * 6550 section 9.8 rule 2) -- root's own route to leaf, two hops away, is
 * the one assertion RplDodagFormationTestCase has no equivalent of at all,
 * since Non-Storing mode never needs an intermediate router to know
 * anything.
 */
class RplStoringModeDownwardRouteTestCase : public TestCase
{
  public:
    RplStoringModeDownwardRouteTestCase();

  private:
    void DoRun() override;

    /// @brief Count a datagram delivered at either end.
    /// @param socket the receiving socket
    void CountDelivery(Ptr<Socket> socket);

    /// @brief Send one datagram, as a named method Simulator::Schedule() can
    ///        resolve (Socket::Send is overloaded).
    /// @param socket the sending socket
    void SendOne(Ptr<Socket> socket);

    uint32_t m_delivered{0}; //!< datagrams delivered, either direction
};

RplStoringModeDownwardRouteTestCase::RplStoringModeDownwardRouteTestCase()
    : TestCase("A Storing mode DODAG learns downward routes at every hop and carries data both "
              "ways")
{
}

void
RplStoringModeDownwardRouteTestCase::CountDelivery(Ptr<Socket> socket)
{
    Ptr<Packet> packet = socket->Recv();
    while (packet)
    {
        m_delivered++;
        packet = socket->Recv();
    }
}

void
RplStoringModeDownwardRouteTestCase::SendOne(Ptr<Socket> socket)
{
    socket->Send(Create<Packet>(64));
}

void
RplStoringModeDownwardRouteTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(4); // 0 = root, 1 and 2 = relays, 3 = leaf

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    auto blacklist = [&](uint32_t a, uint32_t b) {
        Ptr<SimpleNetDevice> devA = DynamicCast<SimpleNetDevice>(devices.Get(a));
        Ptr<SimpleNetDevice> devB = DynamicCast<SimpleNetDevice>(devices.Get(b));
        channel->BlackList(devA, devB);
        channel->BlackList(devB, devA);
    };
    blacklist(0, 2);
    blacklist(0, 3);
    blacklist(1, 3);

    RplHelper rplHelper;
    rplHelper.Set("Mop", UintegerValue(RPL_MOP_STORING_NO_MULTICAST));
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(250));
    Simulator::Run();

    Ptr<RplRoutingProtocol> root = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay1 = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay2 = nodes.Get(2)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> leaf = nodes.Get(3)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(leaf->IsJoined(), true, "The Storing mode DODAG did not reach the far end");

    Ipv6Address dodagId = root->GetGlobalAddress();
    Ipv6Address relay1Address = relay1->GetGlobalAddress();
    Ipv6Address relay2Address = relay2->GetGlobalAddress();
    Ipv6Address leafAddress = leaf->GetGlobalAddress();

    Ipv6Address relay1LinkLocal =
        nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address relay2LinkLocal =
        nodes.Get(2)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address leafLinkLocal =
        nodes.Get(3)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    // Non-Storing mode's own root-only topology plays no part here at all
    // (@see HandleDao()'s mode branch): everything this DODAG learned went
    // into downwardRoutes instead.
    NS_TEST_ASSERT_MSG_EQ(root->GetTopologySize(),
                          0,
                          "A Storing mode root should never populate the Non-Storing topology");

    // The root: two direct entries (relay1, its own child) and one relayed
    // one (leaf, relay1's own child) -- three descendants total, but only
    // two DAOs ever cross this link at a time, since relay1 relays leaf's
    // own DAO onward under its own DAOSequence rather than root learning
    // about relay2 and leaf as separate hops.
    Ipv6Address nextHop;
    NS_TEST_ASSERT_MSG_EQ(
        root->GetDownwardRoute(RPL_DEFAULT_INSTANCE, dodagId, relay1Address, nextHop),
        true,
        "The root never learned a downward route to relay1");
    NS_TEST_ASSERT_MSG_EQ(nextHop, relay1LinkLocal, "The root's route to relay1 is not direct");

    NS_TEST_ASSERT_MSG_EQ(
        root->GetDownwardRoute(RPL_DEFAULT_INSTANCE, dodagId, relay2Address, nextHop),
        true,
        "The root never learned a downward route to relay2");
    NS_TEST_ASSERT_MSG_EQ(nextHop,
                          relay1LinkLocal,
                          "The root's route to relay2 should go through relay1, not direct");

    NS_TEST_ASSERT_MSG_EQ(
        root->GetDownwardRoute(RPL_DEFAULT_INSTANCE, dodagId, leafAddress, nextHop),
        true,
        "The root never learned a downward route to the leaf, two hops away");
    NS_TEST_ASSERT_MSG_EQ(nextHop,
                          relay1LinkLocal,
                          "The root's route to the leaf should go through relay1, not direct");

    // relay1: itself excluded, two descendants (relay2 direct, leaf relayed
    // through relay2).
    NS_TEST_ASSERT_MSG_EQ(
        relay1->GetDownwardRoute(RPL_DEFAULT_INSTANCE, dodagId, relay2Address, nextHop),
        true,
        "relay1 never learned a downward route to relay2");
    NS_TEST_ASSERT_MSG_EQ(nextHop, relay2LinkLocal, "relay1's route to relay2 is not direct");
    NS_TEST_ASSERT_MSG_EQ(
        relay1->GetDownwardRoute(RPL_DEFAULT_INSTANCE, dodagId, leafAddress, nextHop),
        true,
        "relay1 never learned a downward route to the leaf");
    NS_TEST_ASSERT_MSG_EQ(nextHop,
                          relay2LinkLocal,
                          "relay1's route to the leaf should go through relay2, not direct");

    // relay2: one descendant, the leaf, direct.
    NS_TEST_ASSERT_MSG_EQ(relay2->GetDownwardRouteCount(RPL_DEFAULT_INSTANCE, dodagId),
                          1,
                          "relay2 should know of exactly one descendant, the leaf");
    NS_TEST_ASSERT_MSG_EQ(
        relay2->GetDownwardRoute(RPL_DEFAULT_INSTANCE, dodagId, leafAddress, nextHop),
        true,
        "relay2 never learned a downward route to the leaf");
    NS_TEST_ASSERT_MSG_EQ(nextHop, leafLinkLocal, "relay2's route to the leaf is not direct");

    // The leaf has no descendants of its own.
    NS_TEST_ASSERT_MSG_EQ(leaf->GetDownwardRouteCount(RPL_DEFAULT_INSTANCE, dodagId),
                          0,
                          "The leaf should know of no descendants");

    // A downward packet from the root needs no Routing Header at all (RFC
    // 6550 section 9.8): only the RPL Option, the same size
    // RplDodagFormationTestCase's own direct-child case ends up with, even
    // though the leaf here sits two hops out.
    Ipv6Header header;
    header.SetDestination(leafAddress);
    header.SetNextHeader(17); // UDP, as an example inner protocol
    Socket::SocketErrno sockerr;
    Ptr<Packet> downward = Create<Packet>();
    Ptr<Ipv6Route> route = root->RouteOutput(downward, header, nullptr, sockerr);
    NS_TEST_ASSERT_MSG_EQ(route != nullptr, true, "The root has no route down to the leaf");
    NS_TEST_ASSERT_MSG_EQ(route->GetGateway(),
                          relay1LinkLocal,
                          "The packet for the leaf does not leave towards relay1");
    root->PrepareOutgoingPacket(downward, header, route);
    NS_TEST_ASSERT_MSG_EQ(downward->GetSize(),
                          8,
                          "A Storing mode downward packet should carry no Routing Header");
    NS_TEST_ASSERT_MSG_EQ(header.GetDestination(),
                          leafAddress,
                          "A Storing mode downward packet's wire destination should stay the "
                          "leaf itself, not rewritten to the first hop");

    // And the route works, both directions, over real UDP sockets: two hops
    // of relaying each way, so a delivery only arrives if RouteInput()'s new
    // downwardRoutes lookup found the right next hop at both relay1 and
    // relay2 in turn.
    uint16_t downPort = 4248;
    Ptr<Socket> downReceiver = Socket::CreateSocket(nodes.Get(3), UdpSocketFactory::GetTypeId());
    downReceiver->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), downPort));
    downReceiver->SetRecvCallback(
        MakeCallback(&RplStoringModeDownwardRouteTestCase::CountDelivery, this));
    Ptr<Socket> downSender = Socket::CreateSocket(nodes.Get(0), UdpSocketFactory::GetTypeId());
    downSender->Connect(Inet6SocketAddress(leafAddress, downPort));
    Simulator::Schedule(Seconds(1), &RplStoringModeDownwardRouteTestCase::SendOne, this, downSender);

    uint16_t upPort = 4249;
    Ptr<Socket> upReceiver = Socket::CreateSocket(nodes.Get(0), UdpSocketFactory::GetTypeId());
    upReceiver->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), upPort));
    upReceiver->SetRecvCallback(
        MakeCallback(&RplStoringModeDownwardRouteTestCase::CountDelivery, this));
    Ptr<Socket> upSender = Socket::CreateSocket(nodes.Get(3), UdpSocketFactory::GetTypeId());
    upSender->Connect(Inet6SocketAddress(dodagId, upPort));
    Simulator::Schedule(Seconds(1), &RplStoringModeDownwardRouteTestCase::SendOne, this, upSender);

    Simulator::Stop(Seconds(5));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(m_delivered,
                          2,
                          "Both the downward and the upward datagram should have been delivered");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Storing mode's downward route table rejects a stale Path Sequence,
 *        propagates a genuinely newer one even when the next hop has not
 *        changed, and a No-Path withdrawal removes an entry two hops up.
 *
 * root(0)--relay(1)--probe(2), the same shape RplStoringModeDownwardRouteTestCase
 * uses, but this test drives HandleDao() directly with hand-built DAOs (all
 * "from" probe, RFC 6550 section 9.1 rule 4's link-local addressing) for a
 * fictitious target neither node ever organically advertises, so every Path
 * Sequence value in this test is exactly what this test says it is rather
 * than whatever DODAG formation happened to leave behind.
 *
 * RFC 6550 section 9.2.2 defines a Storing mode DAO as "new" -- worth
 * generating a fresh DAO of one's own over, per section 9.8 rule 2 -- when
 * it "has a newer Path Sequence number" or "is a No-Path DAO message that
 * removes the last Downward route to a prefix". Both are exercised here:
 * the first DAO below is a newer sequence with no other change at all
 * (same reporting node, same fictitious target), which HandleDao()'s own
 * "changed" computation has to catch even though the next hop is identical
 * to whatever might already be stored.
 */
class RplStoringModeStaleDaoAndNoPathTestCase : public TestCase
{
  public:
    RplStoringModeStaleDaoAndNoPathTestCase();

  private:
    void DoRun() override;
};

RplStoringModeStaleDaoAndNoPathTestCase::RplStoringModeStaleDaoAndNoPathTestCase()
    : TestCase("Storing mode rejects a stale DAO and propagates a No-Path withdrawal two hops up")
{
}

void
RplStoringModeStaleDaoAndNoPathTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(3); // 0 = root, 1 = relay, 2 = probe

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    Ptr<SimpleNetDevice> first = DynamicCast<SimpleNetDevice>(devices.Get(0));
    Ptr<SimpleNetDevice> last = DynamicCast<SimpleNetDevice>(devices.Get(2));
    channel->BlackList(first, last);
    channel->BlackList(last, first);

    RplHelper rplHelper;
    rplHelper.Set("Mop", UintegerValue(RPL_MOP_STORING_NO_MULTICAST));
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(200));
    Simulator::Run();

    Ptr<RplRoutingProtocol> root = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> probe = nodes.Get(2)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(probe->IsJoined(), true, "The probe never joined the Storing mode DODAG");

    Ipv6Address dodagId = root->GetGlobalAddress();
    Ipv6Address probeLinkLocal =
        nodes.Get(2)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address relayLinkLocal =
        nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address rootLinkLocal =
        nodes.Get(0)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    // A fictitious target neither node ever organically advertises, the
    // same style RplComputeSourceRouteFailureTestCase's own cycleA/cycleB
    // use: nothing about it depends on what DODAG formation happened to do.
    Ipv6Address fictitious("2001:1::ff:fe00:aa");

    auto sendDaoFrom = [&](Ptr<Node> sender,
                           Ipv6Address senderLinkLocal,
                           Ipv6Address dst,
                           uint8_t pathSequence,
                           uint8_t pathLifetime) {
        RplDaoHeader dao;
        dao.SetInstanceId(RPL_DEFAULT_INSTANCE);
        dao.SetDodagId(dodagId);
        dao.SetSequence(1);
        dao.SetTarget(fictitious);
        dao.SetTransitInformation(Ipv6Address::GetAny(), pathSequence, pathLifetime);
        Simulator::Schedule(Seconds(0),
                            &SendRawRplMessage<RplDaoHeader>,
                            sender,
                            1,
                            dao,
                            static_cast<uint8_t>(RPL_CODE_DAO),
                            senderLinkLocal,
                            dst);
        Simulator::Stop(MilliSeconds(50));
        Simulator::Run();
    };
    auto sendDao = [&](uint8_t pathSequence, uint8_t pathLifetime) {
        sendDaoFrom(nodes.Get(2), probeLinkLocal, relayLinkLocal, pathSequence, pathLifetime);
    };

    Ipv6Address nextHop;

    // A brand new target (order == GREATER, since nothing is stored yet):
    // accepted at relay, and -- since HandleDao()'s own "changed" ==
    // (order == GREATER || noPath) -- propagated up to root too, two hops
    // from probe.
    sendDao(5, RPL_DEFAULT_LIFETIME);
    NS_TEST_ASSERT_MSG_EQ(relay->GetDownwardRoute(RPL_DEFAULT_INSTANCE, dodagId, fictitious, nextHop),
                          true,
                          "relay did not accept a brand new target");
    NS_TEST_ASSERT_MSG_EQ(nextHop, probeLinkLocal, "relay's next hop for it is wrong");
    NS_TEST_ASSERT_MSG_EQ(root->GetDownwardRoute(RPL_DEFAULT_INSTANCE, dodagId, fictitious, nextHop),
                          true,
                          "root never learned the fictitious target two hops out");

    // A refresh from the very same next hop, only a newer Path Sequence (7
    // > 5): RFC 6550 section 9.2.2 defines this alone -- "it has a newer
    // Path Sequence number" -- as "new" and so, per section 9.8 rule 2,
    // worth telling the preferred parent about, even though nothing about
    // *which* neighbour relay reaches it through has changed at all.
    sendDao(7, RPL_DEFAULT_LIFETIME);
    NS_TEST_ASSERT_MSG_EQ(relay->GetDownwardRoute(RPL_DEFAULT_INSTANCE, dodagId, fictitious, nextHop),
                          true,
                          "relay dropped the target on its own refresh");

    // Whether that refresh actually reached root cannot be read directly
    // off GetDownwardRoute() (it returns the next hop, not the stored Path
    // Sequence), so it is probed indirectly: a hand-built No-Path,
    // impersonating relay's own real link-local address straight to root,
    // carrying a Path Sequence (6) that sits strictly between the original
    // advertisement (5) and the refresh (7). If the refresh propagated,
    // root's own stored Path Sequence is 7 and this probe (6 < 7) is stale
    // and must be ignored, leaving root's entry standing. If the refresh
    // did not propagate, root would still be sitting on the original 5, the
    // probe's 6 would look newer, and root would incorrectly drop the
    // entry -- exactly the bug this test exists to catch.
    sendDaoFrom(nodes.Get(1), relayLinkLocal, rootLinkLocal, 6, 0);
    NS_TEST_ASSERT_MSG_EQ(
        root->GetDownwardRoute(RPL_DEFAULT_INSTANCE, dodagId, fictitious, nextHop),
        true,
        "root's own copy of the target was not refreshed to the newer Path Sequence: a "
        "same-next-hop refresh was not propagated up from relay");

    // A strictly older Path Sequence (3 < 7, RFC 6550 section 7.1): must be
    // ignored outright, leaving the stored entry exactly as it was.
    sendDao(3, RPL_DEFAULT_LIFETIME);
    NS_TEST_ASSERT_MSG_EQ(relay->GetDownwardRoute(RPL_DEFAULT_INSTANCE, dodagId, fictitious, nextHop),
                          true,
                          "relay dropped the target on a stale DAO");

    // A No-Path with a Path Sequence (4) still older than what is stored
    // (7): the withdrawal itself must be judged stale the same way an
    // ordinary refresh would be, or the entry would be removable by an
    // attacker (or a reordered stale message) replaying an old sequence
    // number with the Path Lifetime field zeroed.
    sendDao(4, 0);
    NS_TEST_ASSERT_MSG_EQ(
        relay->GetDownwardRoute(RPL_DEFAULT_INSTANCE, dodagId, fictitious, nextHop),
        true,
        "A stale No-Path (lower Path Sequence than what is stored) removed the entry anyway");

    // A genuinely newer No-Path (8 > 7): accepted, removed from relay, and
    // -- RFC 6550 section 9.8 rule 2's "Such a change includes receiving a
    // No-Path DAO" -- propagated up to root, which must lose the entry too.
    sendDao(8, 0);
    NS_TEST_ASSERT_MSG_EQ(
        relay->GetDownwardRoute(RPL_DEFAULT_INSTANCE, dodagId, fictitious, nextHop),
        false,
        "A genuinely newer No-Path did not remove relay's own entry");
    NS_TEST_ASSERT_MSG_EQ(
        root->GetDownwardRoute(RPL_DEFAULT_INSTANCE, dodagId, fictitious, nextHop),
        false,
        "The No-Path withdrawal was not propagated two hops up to root");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief DaoRetry() addresses a Storing mode retry the same mode-aware way
 *        SendDao() does -- link-local to the preferred parent, not globally
 *        to the root.
 *
 * root(0)--relay(1)--probe(2), Storing mode, with DaoAckTimeout set to a
 * handful of milliseconds so every DAO-ACK is certain to be judged lost and
 * DaoRetry() fires for real, deterministically, without needing to actually
 * drop a packet on the channel.
 *
 * Caught by an independent review of the Storing mode implementation
 * (@see design-constraints.md section 56): DaoRetry() was never updated
 * alongside SendDao()/HandleDao()'s own relay path to route through the new
 * SendDaoMessage() helper, so it kept building the original Non-Storing-only
 * DAO -- global Transit Information parent field (RFC 6550 section 9.8 rule
 * 1 violated) addressed to the root's own global DODAGID (section 9.1 rule 4
 * violated) -- on every retry. Reaching the root directly bypasses relay's
 * own HandleDao() entirely (ordinary IP forwarding carries it straight
 * through), so the root ends up storing probe's own *global* address as the
 * next hop for probe -- a bogus one-hop "neighbour" no Storing mode relay
 * ever actually advertised, silently blackholing every downward packet to
 * probe once RouteToNeighbourOn() tries to reach it.
 */
class RplStoringModeDaoRetryTestCase : public TestCase
{
  public:
    RplStoringModeDaoRetryTestCase();

  private:
    void DoRun() override;
};

RplStoringModeDaoRetryTestCase::RplStoringModeDaoRetryTestCase()
    : TestCase("A Storing mode DAO retry is addressed link-local to the preferred parent, not "
              "globally to the root")
{
}

void
RplStoringModeDaoRetryTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(3); // 0 = root, 1 = relay, 2 = probe

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    // SimpleChannel's own default Delay is zero, so a DAO-ACK round trip
    // (probe -> relay, then straight back, one hop each way in Storing
    // mode) would otherwise complete instantly -- racing, and usually
    // winning, against any DaoAckTimeout short enough to be practical for a
    // test. An explicit, non-trivial delay makes the round trip (2 * this,
    // at least) reliably longer than DaoAckTimeout below, so DaoRetry() is
    // guaranteed to fire before any real reply could possibly arrive.
    channel->SetAttribute("Delay", TimeValue(Seconds(1)));
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    Ptr<SimpleNetDevice> first = DynamicCast<SimpleNetDevice>(devices.Get(0));
    Ptr<SimpleNetDevice> last = DynamicCast<SimpleNetDevice>(devices.Get(2));
    channel->BlackList(first, last);
    channel->BlackList(last, first);

    RplHelper rplHelper;
    rplHelper.Set("Mop", UintegerValue(RPL_MOP_STORING_NO_MULTICAST));
    // Shorter than the >= 2 s a real DAO-ACK round trip now takes (@see the
    // channel Delay above), forcing DaoRetry() to run at least once,
    // deterministically, for both relay's and probe's own
    // self-advertisements, without depending on real packet loss.
    rplHelper.Set("DaoAckTimeout", TimeValue(MilliSeconds(200)));
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(200));
    Simulator::Run();

    Ptr<RplRoutingProtocol> root = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> probe = nodes.Get(2)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(probe->IsJoined(), true, "The probe never joined the Storing mode DODAG");

    Ipv6Address dodagId = root->GetGlobalAddress();
    Ipv6Address probeAddress = probe->GetGlobalAddress();
    Ipv6Address relayLinkLocal =
        nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    // With the bug, a globally-addressed retry from probe reaches root
    // directly, and root records probe's own *global* address as the next
    // hop -- observably different from the correct outcome, root learning
    // of probe only through relay's own relayed DAO, next hop relay's
    // link-local address.
    Ipv6Address nextHop;
    NS_TEST_ASSERT_MSG_EQ(root->GetDownwardRoute(RPL_DEFAULT_INSTANCE, dodagId, probeAddress, nextHop),
                          true,
                          "The root never learned a downward route to the probe at all");
    NS_TEST_ASSERT_MSG_EQ(
        nextHop,
        relayLinkLocal,
        "The root's route to the probe does not go through relay's own link-local address -- a "
        "Storing mode DAO retry addressed itself globally, straight to the root, bypassing "
        "relay's own HandleDao() entirely");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Storing mode's HandleDao() rejects three kinds of untrustworthy
 *        input: a source address that is not link-local, a Target claiming
 *        to be the root or this node's own address, and a No-Path DAO for
 *        a target this node never held anything for.
 *
 * root(0)--relay(1)--probe(2), the same shape RplStoringModeStaleDaoAndNoPathTestCase
 * uses. Found by an independent /protocol-test-matrix audit of the Storing
 * mode implementation (@see design-constraints.md section 57): none of
 * these three were checked at all before this test existed.
 */
class RplStoringModeInputValidationTestCase : public TestCase
{
  public:
    RplStoringModeInputValidationTestCase();

  private:
    void DoRun() override;

    /// @brief Count a DAO delivered to the monitoring socket.
    /// @param socket the receiving socket
    void CountDao(Ptr<Socket> socket);

    uint32_t m_daoCount{0}; //!< DAOs observed on the monitoring socket
};

RplStoringModeInputValidationTestCase::RplStoringModeInputValidationTestCase()
    : TestCase("Storing mode rejects a non-link-local source, a Target claiming to be an "
              "ancestor, and a No-Path for a never-held target")
{
}

void
RplStoringModeInputValidationTestCase::CountDao(Ptr<Socket> socket)
{
    Ptr<Packet> packet = socket->Recv();
    while (packet)
    {
        // Unlike SendRawRplMessage()'s own send side (which builds a
        // packet starting from the ICMPv6 header, letting the IP layer
        // prepend its own IPv6 header on the way out), a raw socket's own
        // Recv() hands back the packet with the IPv6 header still
        // attached in front -- skip its fixed 40 bytes (no extension
        // headers on any RPL control message this module sends) to reach
        // the ICMPv6 Type/Code this callback actually needs.
        Ipv6Header ipv6Header;
        if (packet->RemoveHeader(ipv6Header) != 0)
        {
            uint8_t icmpv6[2];
            if (packet->CopyData(icmpv6, sizeof(icmpv6)) == sizeof(icmpv6) &&
                icmpv6[1] == RPL_CODE_DAO)
            {
                m_daoCount++;
            }
        }
        packet = socket->Recv();
    }
}

void
RplStoringModeInputValidationTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(3); // 0 = root, 1 = relay, 2 = probe

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    Ptr<SimpleNetDevice> first = DynamicCast<SimpleNetDevice>(devices.Get(0));
    Ptr<SimpleNetDevice> last = DynamicCast<SimpleNetDevice>(devices.Get(2));
    channel->BlackList(first, last);
    channel->BlackList(last, first);

    RplHelper rplHelper;
    rplHelper.Set("Mop", UintegerValue(RPL_MOP_STORING_NO_MULTICAST));
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(200));
    Simulator::Run();

    Ptr<RplRoutingProtocol> root = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> probe = nodes.Get(2)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(probe->IsJoined(), true, "The probe never joined the Storing mode DODAG");

    Ipv6Address dodagId = root->GetGlobalAddress();
    Ipv6Address relayAddress = relay->GetGlobalAddress();
    Ipv6Address probeLinkLocal =
        nodes.Get(2)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address relayLinkLocal =
        nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    Ipv6Address nextHop;

    // A spoofed non-link-local source (RFC 6550 section 9.1 rule 4):
    // delivered directly to relay's own Receive() (DeliverRawRplMessage(),
    // not a real send) since the point is precisely that no real device
    // backs this source address.
    {
        Ipv6Address fictitious("2001:1::ff:fe00:aa");
        Ipv6Address spoofedGlobalSource("2001:1::ff:fe00:99");
        RplDaoHeader dao;
        dao.SetInstanceId(RPL_DEFAULT_INSTANCE);
        dao.SetDodagId(dodagId);
        dao.SetSequence(1);
        dao.SetTarget(fictitious);
        dao.SetTransitInformation(Ipv6Address::GetAny(), 5, RPL_DEFAULT_LIFETIME);
        Simulator::Schedule(Seconds(0),
                            &DeliverRawRplMessage<RplDaoHeader>,
                            nodes.Get(1),
                            1,
                            dao,
                            static_cast<uint8_t>(RPL_CODE_DAO),
                            spoofedGlobalSource,
                            relayLinkLocal);
        Simulator::Stop(MilliSeconds(50));
        Simulator::Run();
        NS_TEST_ASSERT_MSG_EQ(
            relay->GetDownwardRoute(RPL_DEFAULT_INSTANCE, dodagId, fictitious, nextHop),
            false,
            "A DAO with a non-link-local source address was accepted into downwardRoutes");

        // Positive control: the identical DAO, genuinely from probe's own
        // link-local address, must be accepted -- proving the rejection
        // above was really about the source address, not some other
        // difference between the two deliveries.
        Simulator::Schedule(Seconds(0),
                            &SendRawRplMessage<RplDaoHeader>,
                            nodes.Get(2),
                            1,
                            dao,
                            static_cast<uint8_t>(RPL_CODE_DAO),
                            probeLinkLocal,
                            relayLinkLocal);
        Simulator::Stop(MilliSeconds(50));
        Simulator::Run();
        NS_TEST_ASSERT_MSG_EQ(
            relay->GetDownwardRoute(RPL_DEFAULT_INSTANCE, dodagId, fictitious, nextHop),
            true,
            "The identical DAO from a genuine link-local source was not accepted");
    }

    // A Target claiming to be the root, or this node's own address: both
    // would let a single DAO redirect this node's own upward traffic down
    // towards whoever sent it.
    {
        auto sendClaiming = [&](Ipv6Address claimedTarget) {
            RplDaoHeader dao;
            dao.SetInstanceId(RPL_DEFAULT_INSTANCE);
            dao.SetDodagId(dodagId);
            dao.SetSequence(1);
            dao.SetTarget(claimedTarget);
            dao.SetTransitInformation(Ipv6Address::GetAny(), 5, RPL_DEFAULT_LIFETIME);
            Simulator::Schedule(Seconds(0),
                                &SendRawRplMessage<RplDaoHeader>,
                                nodes.Get(2),
                                1,
                                dao,
                                static_cast<uint8_t>(RPL_CODE_DAO),
                                probeLinkLocal,
                                relayLinkLocal);
            Simulator::Stop(MilliSeconds(50));
            Simulator::Run();
        };

        sendClaiming(dodagId);
        NS_TEST_ASSERT_MSG_EQ(
            relay->GetDownwardRoute(RPL_DEFAULT_INSTANCE, dodagId, dodagId, nextHop),
            false,
            "A DAO claiming the root itself as a downward target was accepted");

        sendClaiming(relayAddress);
        NS_TEST_ASSERT_MSG_EQ(
            relay->GetDownwardRoute(RPL_DEFAULT_INSTANCE, dodagId, relayAddress, nextHop),
            false,
            "A DAO claiming this node's own address as a downward target was accepted");
    }

    // A No-Path DAO for a target this node never held anything for must not
    // be relayed upstream (RFC 6550 section 9.2.2: a No-Path is "new" only
    // when it "removes the last Downward route to a prefix" -- there was
    // none to remove here). Observed directly on a monitoring socket at
    // root, rather than through root's own downwardRoutes state, since an
    // incorrectly-relayed No-Path for a target root also never held would
    // leave root's state identical either way.
    {
        Ptr<Socket> monitor = Socket::CreateSocket(nodes.Get(0), Ipv6RawSocketFactory::GetTypeId());
        monitor->SetAttribute("Protocol",
                              UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
        monitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
        monitor->SetRecvCallback(
            MakeCallback(&RplStoringModeInputValidationTestCase::CountDao, this));

        Ipv6Address neverHeld("2001:1::ff:fe00:bb");
        RplDaoHeader dao;
        dao.SetInstanceId(RPL_DEFAULT_INSTANCE);
        dao.SetDodagId(dodagId);
        dao.SetSequence(1);
        dao.SetTarget(neverHeld);
        dao.SetTransitInformation(Ipv6Address::GetAny(), 5, 0); // No-Path
        Simulator::Schedule(Seconds(0),
                            &SendRawRplMessage<RplDaoHeader>,
                            nodes.Get(2),
                            1,
                            dao,
                            static_cast<uint8_t>(RPL_CODE_DAO),
                            probeLinkLocal,
                            relayLinkLocal);
        Simulator::Stop(MilliSeconds(50));
        Simulator::Run();
        NS_TEST_ASSERT_MSG_EQ(
            m_daoCount,
            0,
            "A No-Path DAO for a target relay never held anything for was relayed to root anyway");
        monitor->Close();
    }

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief RFC 6550 section 6.7.8's RPL_INFINITE_LIFETIME (0xFF) survives a
 *        Storing mode relay hop, rather than being silently replaced by the
 *        relaying node's own, unrelated PathLifetime attribute.
 *
 * root(0)--relay(1)--probe(2), Storing mode, with the PathLifetime
 * attribute set low (finite) on every node -- deliberately the opposite of
 * what probe advertises for its own fictitious target, so that a relay
 * mistakenly substituting its own attribute instead of forwarding what it
 * was actually told is directly observable two hops out.
 */
class RplStoringModeInfiniteLifetimeRelayedTestCase : public TestCase
{
  public:
    RplStoringModeInfiniteLifetimeRelayedTestCase();

  private:
    void DoRun() override;
};

RplStoringModeInfiniteLifetimeRelayedTestCase::RplStoringModeInfiniteLifetimeRelayedTestCase()
    : TestCase("Storing mode preserves RPL_INFINITE_LIFETIME across a relay hop")
{
}

void
RplStoringModeInfiniteLifetimeRelayedTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(3); // 0 = root, 1 = relay, 2 = probe

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    Ptr<SimpleNetDevice> first = DynamicCast<SimpleNetDevice>(devices.Get(0));
    Ptr<SimpleNetDevice> last = DynamicCast<SimpleNetDevice>(devices.Get(2));
    channel->BlackList(first, last);
    channel->BlackList(last, first);

    RplHelper rplHelper;
    rplHelper.Set("Mop", UintegerValue(RPL_MOP_STORING_NO_MULTICAST));
    // Deliberately low: every node's own self-advertisement (and, before
    // the fix, what a relay would substitute for anything it relays) is
    // valid for only PathLifetime * the 60 s default lifetime unit -- 60 s
    // here. probe's own fictitious target below advertises
    // RPL_INFINITE_LIFETIME instead, the opposite end of the scale.
    rplHelper.Set("PathLifetime", UintegerValue(1));
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(200));
    Simulator::Run();

    Ptr<RplRoutingProtocol> root = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> probe = nodes.Get(2)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(probe->IsJoined(), true, "The probe never joined the Storing mode DODAG");

    Ipv6Address dodagId = root->GetGlobalAddress();
    Ipv6Address probeLinkLocal =
        nodes.Get(2)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address relayLinkLocal =
        nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address fictitious("2001:1::ff:fe00:aa");

    RplDaoHeader dao;
    dao.SetInstanceId(RPL_DEFAULT_INSTANCE);
    dao.SetDodagId(dodagId);
    dao.SetSequence(1);
    dao.SetTarget(fictitious);
    dao.SetTransitInformation(Ipv6Address::GetAny(), 5, RPL_INFINITE_LIFETIME);
    Simulator::Schedule(Seconds(0),
                        &SendRawRplMessage<RplDaoHeader>,
                        nodes.Get(2),
                        1,
                        dao,
                        static_cast<uint8_t>(RPL_CODE_DAO),
                        probeLinkLocal,
                        relayLinkLocal);
    Simulator::Stop(MilliSeconds(50));
    Simulator::Run();

    Ipv6Address nextHop;
    NS_TEST_ASSERT_MSG_EQ(relay->GetDownwardRoute(RPL_DEFAULT_INSTANCE, dodagId, fictitious, nextHop),
                          true,
                          "relay did not accept the infinite-lifetime advertisement");
    NS_TEST_ASSERT_MSG_EQ(root->GetDownwardRoute(RPL_DEFAULT_INSTANCE, dodagId, fictitious, nextHop),
                          true,
                          "root never learned of the target two hops out");

    // Well past the 60 s a *finite* (PathLifetime=1) relay would have used:
    // if relay substituted its own PathLifetime attribute instead of
    // forwarding probe's own RPL_INFINITE_LIFETIME, root's copy would have
    // expired by now.
    Simulator::Stop(Seconds(120));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(
        root->GetDownwardRoute(RPL_DEFAULT_INSTANCE, dodagId, fictitious, nextHop),
        true,
        "root's copy of an advertised-infinite route expired: the relay substituted its own "
        "finite PathLifetime instead of forwarding the one it was actually told");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A relay carrying several downward routes reports all of them to
 *        its own preferred parent in one aggregated DAO message (RFC 6550
 *        section 9.4 rule 3), not one message per route.
 *
 * root(0)--relay(1)--probe(2), Storing mode. Once relay knows of three
 * downward targets (probe's own organic self-advertisement plus two
 * fictitious ones injected directly, standing in for further descendants
 * relay would ordinarily learn of the same way), its next periodic refresh
 * (DaoTimerExpire() -> SendDao()) is observed at root through a raw
 * monitoring socket: exactly one DAO arrives, and it is the one that leaves
 * root knowing about all three targets, not the first of three separate
 * ones.
 */
class RplStoringModeAggregatedRefreshTestCase : public TestCase
{
  public:
    RplStoringModeAggregatedRefreshTestCase();

  private:
    void DoRun() override;

    /// @brief Count a DAO delivered to the monitoring socket.
    /// @param socket the receiving socket
    void CountDao(Ptr<Socket> socket);

    uint32_t m_daoCount{0}; //!< DAOs observed on the monitoring socket
};

RplStoringModeAggregatedRefreshTestCase::RplStoringModeAggregatedRefreshTestCase()
    : TestCase("A relay reports several downward routes in one aggregated DAO, not one per route")
{
}

void
RplStoringModeAggregatedRefreshTestCase::CountDao(Ptr<Socket> socket)
{
    Ptr<Packet> packet = socket->Recv();
    while (packet)
    {
        // @see RplStoringModeInputValidationTestCase::CountDao()'s own
        // comment: a raw socket's own Recv() hands back the packet with
        // its IPv6 header still attached in front.
        Ipv6Header ipv6Header;
        if (packet->RemoveHeader(ipv6Header) != 0)
        {
            uint8_t icmpv6[2];
            if (packet->CopyData(icmpv6, sizeof(icmpv6)) == sizeof(icmpv6) &&
                icmpv6[1] == RPL_CODE_DAO)
            {
                m_daoCount++;
            }
        }
        packet = socket->Recv();
    }
}

void
RplStoringModeAggregatedRefreshTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(3); // 0 = root, 1 = relay, 2 = probe

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    Ptr<SimpleNetDevice> first = DynamicCast<SimpleNetDevice>(devices.Get(0));
    Ptr<SimpleNetDevice> last = DynamicCast<SimpleNetDevice>(devices.Get(2));
    channel->BlackList(first, last);
    channel->BlackList(last, first);

    RplHelper rplHelper;
    rplHelper.Set("Mop", UintegerValue(RPL_MOP_STORING_NO_MULTICAST));
    // Short enough to observe a periodic refresh without an unreasonably
    // long test, long enough that it cannot coincide with the initial
    // formation's own DAO traffic.
    rplHelper.Set("DaoInterval", TimeValue(Seconds(5)));
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(200));
    Simulator::Run();

    Ptr<RplRoutingProtocol> root = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> probe = nodes.Get(2)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(probe->IsJoined(), true, "The probe never joined the Storing mode DODAG");

    Ipv6Address dodagId = root->GetGlobalAddress();
    Ipv6Address probeLinkLocal =
        nodes.Get(2)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address relayLinkLocal =
        nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    NS_TEST_ASSERT_MSG_EQ(relay->GetDownwardRouteCount(RPL_DEFAULT_INSTANCE, dodagId),
                          1,
                          "relay should know of exactly one descendant (probe) so far");

    // Two more descendants relay learns of directly, standing in for
    // further real ones it would ordinarily hear from the same way.
    Ipv6Address fictitiousA("2001:1::ff:fe00:aa");
    Ipv6Address fictitiousB("2001:1::ff:fe00:bb");
    for (auto fictitious : {fictitiousA, fictitiousB})
    {
        RplDaoHeader dao;
        dao.SetInstanceId(RPL_DEFAULT_INSTANCE);
        dao.SetDodagId(dodagId);
        dao.SetSequence(1);
        dao.SetTarget(fictitious);
        dao.SetTransitInformation(Ipv6Address::GetAny(), 5, RPL_DEFAULT_LIFETIME);
        Simulator::Schedule(Seconds(0),
                            &SendRawRplMessage<RplDaoHeader>,
                            nodes.Get(2),
                            1,
                            dao,
                            static_cast<uint8_t>(RPL_CODE_DAO),
                            probeLinkLocal,
                            relayLinkLocal);
        Simulator::Stop(MilliSeconds(50));
        Simulator::Run();
    }

    NS_TEST_ASSERT_MSG_EQ(relay->GetDownwardRouteCount(RPL_DEFAULT_INSTANCE, dodagId),
                          3,
                          "relay should now know of three descendants");

    // A monitor at root, reset just before relay's own next periodic
    // refresh -- the two DAOs injected above already triggered their own
    // immediate relay-propagation to root (HandleDao()'s own "changed"
    // path), which would otherwise be indistinguishable here from the
    // periodic refresh this test actually wants to observe.
    Ptr<Socket> monitor = Socket::CreateSocket(nodes.Get(0), Ipv6RawSocketFactory::GetTypeId());
    monitor->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    monitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    monitor->SetRecvCallback(
        MakeCallback(&RplStoringModeAggregatedRefreshTestCase::CountDao, this));

    // DaoInterval is 5 s; relay's own periodic refresh timer was last
    // (re)armed no later than the formation stop above, so waiting 6 s is
    // certain to cross it at least once without also reaching a second
    // one.
    Simulator::Stop(Seconds(6));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(m_daoCount,
                          1,
                          "relay's own periodic refresh sent more than one DAO for its three "
                          "downward routes -- they were not aggregated into a single message");

    Ipv6Address nextHop;
    NS_TEST_ASSERT_MSG_EQ(root->GetDownwardRoute(RPL_DEFAULT_INSTANCE, dodagId, fictitiousA, nextHop),
                          true,
                          "root did not learn the 1st additional target from the aggregated DAO");
    NS_TEST_ASSERT_MSG_EQ(root->GetDownwardRoute(RPL_DEFAULT_INSTANCE, dodagId, fictitiousB, nextHop),
                          true,
                          "root did not learn the 2nd additional target from the aggregated DAO");

    monitor->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief HandleDao() no longer discards a whole aggregated DAO just because
 *        its primary target happens to be the unspecified address: an
 *        otherwise well-formed additional target riding alongside it is
 *        still processed, the same as if it had arrived on its own.
 */
class RplStoringModeBogusPrimaryTargetTestCase : public TestCase
{
  public:
    RplStoringModeBogusPrimaryTargetTestCase();

  private:
    void DoRun() override;
};

RplStoringModeBogusPrimaryTargetTestCase::RplStoringModeBogusPrimaryTargetTestCase()
    : TestCase("A DAO with a bogus primary target still processes a legitimate additional "
              "target riding alongside it")
{
}

void
RplStoringModeBogusPrimaryTargetTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2); // 0 = root, 1 = child

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    rplHelper.Set("Mop", UintegerValue(RPL_MOP_STORING_NO_MULTICAST));
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(200));
    Simulator::Run();

    Ptr<RplRoutingProtocol> root = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> child = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(child->IsJoined(), true, "The child never joined the Storing mode DODAG");

    Ipv6Address dodagId = root->GetGlobalAddress();
    Ipv6Address childLinkLocal =
        nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address rootLinkLocal =
        nodes.Get(0)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    Ipv6Address legitimate("2001:1::ff:fe00:77");
    RplDaoHeader dao;
    dao.SetInstanceId(RPL_DEFAULT_INSTANCE);
    dao.SetDodagId(dodagId);
    dao.SetSequence(1);
    dao.SetTarget(Ipv6Address::GetAny()); // bogus primary
    dao.SetTransitInformation(Ipv6Address::GetAny(), 0, 0);
    RplDaoHeader::AdditionalTarget additional;
    additional.target = legitimate;
    additional.targetPrefixLength = 128;
    additional.pathSequence = 5;
    additional.pathLifetime = RPL_DEFAULT_LIFETIME;
    dao.AddTarget(additional);

    Simulator::Schedule(Seconds(0),
                        &SendRawRplMessage<RplDaoHeader>,
                        nodes.Get(1),
                        1,
                        dao,
                        static_cast<uint8_t>(RPL_CODE_DAO),
                        childLinkLocal,
                        rootLinkLocal);
    Simulator::Stop(MilliSeconds(50));
    Simulator::Run();

    Ipv6Address nextHop;
    NS_TEST_ASSERT_MSG_EQ(root->GetDownwardRoute(RPL_DEFAULT_INSTANCE, dodagId, legitimate, nextHop),
                          true,
                          "A legitimate additional target was dropped because the DAO's primary "
                          "target was bogus");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A target appearing twice in one incoming aggregated DAO (once as
 *        the primary, once as an additional target, with a fresher Path
 *        Sequence) must not be relayed onward as two separate Target +
 *        Transit Information groups, one of them stale.
 */
class RplDaoDuplicateTargetDedupedTestCase : public TestCase
{
  public:
    RplDaoDuplicateTargetDedupedTestCase();

  private:
    void DoRun() override;

    /// @brief Decode a DAO delivered to the monitoring socket.
    /// @param socket the receiving socket
    void CaptureDao(Ptr<Socket> socket);

    std::vector<RplDaoHeader> m_captured; //!< every DAO seen on the monitoring socket
};

RplDaoDuplicateTargetDedupedTestCase::RplDaoDuplicateTargetDedupedTestCase()
    : TestCase("A target appearing twice in one aggregated DAO is relayed only once, with its "
              "freshest Path Sequence")
{
}

void
RplDaoDuplicateTargetDedupedTestCase::CaptureDao(Ptr<Socket> socket)
{
    Ptr<Packet> packet = socket->Recv();
    while (packet)
    {
        // A raw socket's own Recv() hands back the packet with its IPv6
        // header still attached in front (@see
        // RplStoringModeAggregatedRefreshTestCase::CountDao()'s own
        // comment).
        Ipv6Header ipv6Header;
        if (packet->RemoveHeader(ipv6Header) != 0)
        {
            Icmpv6Header icmpv6Header;
            if (packet->RemoveHeader(icmpv6Header) != 0 && icmpv6Header.GetCode() == RPL_CODE_DAO)
            {
                RplDaoHeader dao;
                packet->RemoveHeader(dao);
                m_captured.push_back(dao);
            }
        }
        packet = socket->Recv();
    }
}

void
RplDaoDuplicateTargetDedupedTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(3); // 0 = root, 1 = relay, 2 = probe

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    Ptr<SimpleNetDevice> first = DynamicCast<SimpleNetDevice>(devices.Get(0));
    Ptr<SimpleNetDevice> last = DynamicCast<SimpleNetDevice>(devices.Get(2));
    channel->BlackList(first, last);
    channel->BlackList(last, first);

    RplHelper rplHelper;
    rplHelper.Set("Mop", UintegerValue(RPL_MOP_STORING_NO_MULTICAST));
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(200));
    Simulator::Run();

    Ptr<RplRoutingProtocol> root = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> probe = nodes.Get(2)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(probe->IsJoined(), true, "The probe never joined the Storing mode DODAG");

    Ipv6Address dodagId = root->GetGlobalAddress();
    Ipv6Address probeLinkLocal =
        nodes.Get(2)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address relayLinkLocal =
        nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    Ipv6Address duplicated("2001:1::ff:fe00:dd");

    Ptr<Socket> monitor = Socket::CreateSocket(nodes.Get(0), Ipv6RawSocketFactory::GetTypeId());
    monitor->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    monitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    monitor->SetRecvCallback(MakeCallback(&RplDaoDuplicateTargetDedupedTestCase::CaptureDao, this));

    RplDaoHeader dao;
    dao.SetInstanceId(RPL_DEFAULT_INSTANCE);
    dao.SetDodagId(dodagId);
    dao.SetSequence(1);
    dao.SetTarget(duplicated);
    dao.SetTransitInformation(Ipv6Address::GetAny(), 3, 10); // stale, seen first as the primary
    RplDaoHeader::AdditionalTarget again;
    again.target = duplicated; // the same address, again
    again.targetPrefixLength = 128;
    again.pathSequence = 5; // fresher
    again.pathLifetime = 20;
    dao.AddTarget(again);

    Simulator::Schedule(Seconds(0),
                        &SendRawRplMessage<RplDaoHeader>,
                        nodes.Get(2),
                        1,
                        dao,
                        static_cast<uint8_t>(RPL_CODE_DAO),
                        probeLinkLocal,
                        relayLinkLocal);
    Simulator::Stop(MilliSeconds(50));
    Simulator::Run();

    Ipv6Address nextHop;
    NS_TEST_ASSERT_MSG_EQ(relay->GetDownwardRoute(RPL_DEFAULT_INSTANCE, dodagId, duplicated, nextHop),
                          true,
                          "relay did not accept the duplicated target at all");

    NS_TEST_ASSERT_MSG_EQ(m_captured.size(),
                          1,
                          "relay relayed the duplicated target in more than one outgoing DAO");

    uint32_t occurrences = 0;
    uint8_t seenPathSequence = 0;
    const RplDaoHeader& relayed = m_captured.front();
    if (relayed.GetTarget() == duplicated)
    {
        occurrences++;
        seenPathSequence = relayed.GetPathSequence();
    }
    for (const auto& additionalTarget : relayed.GetAdditionalTargets())
    {
        if (additionalTarget.target == duplicated)
        {
            occurrences++;
            seenPathSequence = additionalTarget.pathSequence;
        }
    }
    NS_TEST_ASSERT_MSG_EQ(occurrences,
                          1,
                          "the relayed DAO carried the same target twice, once stale and once "
                          "fresh, instead of being deduplicated");
    NS_TEST_ASSERT_MSG_EQ(+seenPathSequence,
                          5,
                          "the relayed DAO kept the stale Path Sequence instead of the fresh one");

    monitor->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Two targets that both change in one incoming aggregated DAO are
 *        relayed together, in one outgoing DAO -- not split into two --
 *        the same aggregation SendDao()'s own periodic refresh applies.
 */
class RplHandleDaoAggregatesSimultaneousChangesTestCase : public TestCase
{
  public:
    RplHandleDaoAggregatesSimultaneousChangesTestCase();

  private:
    void DoRun() override;

    /// @brief Decode a DAO delivered to the monitoring socket.
    /// @param socket the receiving socket
    void CaptureDao(Ptr<Socket> socket);

    std::vector<RplDaoHeader> m_captured; //!< every DAO seen on the monitoring socket
};

RplHandleDaoAggregatesSimultaneousChangesTestCase::
    RplHandleDaoAggregatesSimultaneousChangesTestCase()
    : TestCase("Two targets that both change in one incoming DAO are relayed together in one "
              "outgoing DAO, not two")
{
}

void
RplHandleDaoAggregatesSimultaneousChangesTestCase::CaptureDao(Ptr<Socket> socket)
{
    Ptr<Packet> packet = socket->Recv();
    while (packet)
    {
        Ipv6Header ipv6Header;
        if (packet->RemoveHeader(ipv6Header) != 0)
        {
            Icmpv6Header icmpv6Header;
            if (packet->RemoveHeader(icmpv6Header) != 0 && icmpv6Header.GetCode() == RPL_CODE_DAO)
            {
                RplDaoHeader dao;
                packet->RemoveHeader(dao);
                m_captured.push_back(dao);
            }
        }
        packet = socket->Recv();
    }
}

void
RplHandleDaoAggregatesSimultaneousChangesTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(3); // 0 = root, 1 = relay, 2 = probe

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    Ptr<SimpleNetDevice> first = DynamicCast<SimpleNetDevice>(devices.Get(0));
    Ptr<SimpleNetDevice> last = DynamicCast<SimpleNetDevice>(devices.Get(2));
    channel->BlackList(first, last);
    channel->BlackList(last, first);

    RplHelper rplHelper;
    rplHelper.Set("Mop", UintegerValue(RPL_MOP_STORING_NO_MULTICAST));
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(200));
    Simulator::Run();

    Ptr<RplRoutingProtocol> root = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> probe = nodes.Get(2)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(probe->IsJoined(), true, "The probe never joined the Storing mode DODAG");

    Ipv6Address dodagId = root->GetGlobalAddress();
    Ipv6Address probeLinkLocal =
        nodes.Get(2)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address relayLinkLocal =
        nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    Ipv6Address targetX("2001:1::ff:fe00:11");
    Ipv6Address targetY("2001:1::ff:fe00:22");

    Ptr<Socket> monitor = Socket::CreateSocket(nodes.Get(0), Ipv6RawSocketFactory::GetTypeId());
    monitor->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    monitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    monitor->SetRecvCallback(
        MakeCallback(&RplHandleDaoAggregatesSimultaneousChangesTestCase::CaptureDao, this));

    RplDaoHeader dao;
    dao.SetInstanceId(RPL_DEFAULT_INSTANCE);
    dao.SetDodagId(dodagId);
    dao.SetSequence(1);
    dao.SetTarget(targetX);
    dao.SetTransitInformation(Ipv6Address::GetAny(), 1, 30);
    RplDaoHeader::AdditionalTarget additionalY;
    additionalY.target = targetY;
    additionalY.targetPrefixLength = 128;
    additionalY.pathSequence = 1;
    additionalY.pathLifetime = 30;
    dao.AddTarget(additionalY);

    Simulator::Schedule(Seconds(0),
                        &SendRawRplMessage<RplDaoHeader>,
                        nodes.Get(2),
                        1,
                        dao,
                        static_cast<uint8_t>(RPL_CODE_DAO),
                        probeLinkLocal,
                        relayLinkLocal);
    Simulator::Stop(MilliSeconds(50));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(m_captured.size(),
                          1,
                          "relay split two simultaneously-changed targets from one incoming DAO "
                          "into more than one outgoing DAO");

    const RplDaoHeader& relayed = m_captured.front();
    bool sawX = relayed.GetTarget() == targetX;
    bool sawY = relayed.GetTarget() == targetY;
    for (const auto& additionalTarget : relayed.GetAdditionalTargets())
    {
        sawX = sawX || additionalTarget.target == targetX;
        sawY = sawY || additionalTarget.target == targetY;
    }
    NS_TEST_ASSERT_MSG_EQ(sawX, true, "relay's single outgoing DAO did not carry the 1st target");
    NS_TEST_ASSERT_MSG_EQ(sawY, true, "relay's single outgoing DAO did not carry the 2nd target");

    monitor->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief DaoRetry()'s own additionalTargets rebuild (from the sender's
 *        current downwardRoutes, not whatever the original unacknowledged
 *        DAO happened to carry) must actually reflect real content, not
 *        silently retry an empty or wrong aggregate.
 */
class RplStoringModeDaoRetryContentTestCase : public TestCase
{
  public:
    RplStoringModeDaoRetryContentTestCase();

  private:
    void DoRun() override;

    /// @brief Decode a DAO delivered to the monitoring socket.
    /// @param socket the receiving socket
    void CaptureDao(Ptr<Socket> socket);

    std::vector<RplDaoHeader> m_captured; //!< every DAO seen on the monitoring socket
};

RplStoringModeDaoRetryContentTestCase::RplStoringModeDaoRetryContentTestCase()
    : TestCase("DaoRetry() rebuilds its additional targets from the sender's own current "
              "downward routes, not empty or stale data")
{
}

void
RplStoringModeDaoRetryContentTestCase::CaptureDao(Ptr<Socket> socket)
{
    Ptr<Packet> packet = socket->Recv();
    while (packet)
    {
        Ipv6Header ipv6Header;
        if (packet->RemoveHeader(ipv6Header) != 0)
        {
            Icmpv6Header icmpv6Header;
            if (packet->RemoveHeader(icmpv6Header) != 0 && icmpv6Header.GetCode() == RPL_CODE_DAO)
            {
                RplDaoHeader dao;
                packet->RemoveHeader(dao);
                m_captured.push_back(dao);
            }
        }
        packet = socket->Recv();
    }
}

void
RplStoringModeDaoRetryContentTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(3); // 0 = root, 1 = relay, 2 = probe

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    // Same reasoning as RplStoringModeDaoRetryTestCase: a non-trivial delay
    // makes a real DAO-ACK round trip reliably longer than DaoAckTimeout
    // below, so relay's own self-advertisement is guaranteed to retry at
    // least once.
    channel->SetAttribute("Delay", TimeValue(Seconds(1)));
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    Ptr<SimpleNetDevice> first = DynamicCast<SimpleNetDevice>(devices.Get(0));
    Ptr<SimpleNetDevice> last = DynamicCast<SimpleNetDevice>(devices.Get(2));
    channel->BlackList(first, last);
    channel->BlackList(last, first);

    RplHelper rplHelper;
    rplHelper.Set("Mop", UintegerValue(RPL_MOP_STORING_NO_MULTICAST));
    rplHelper.Set("DaoAckTimeout", TimeValue(MilliSeconds(200)));
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    Ptr<Socket> monitor = Socket::CreateSocket(nodes.Get(0), Ipv6RawSocketFactory::GetTypeId());
    monitor->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    monitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    monitor->SetRecvCallback(MakeCallback(&RplStoringModeDaoRetryContentTestCase::CaptureDao, this));

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(200));
    Simulator::Run();

    Ptr<RplRoutingProtocol> root = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> probe = nodes.Get(2)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(probe->IsJoined(), true, "The probe never joined the Storing mode DODAG");

    Ipv6Address relayGlobal = relay->GetGlobalAddress();
    Ipv6Address probeGlobal = probe->GetGlobalAddress();

    // Among every DAO root captured over the whole run (formation, every
    // periodic refresh, and every DaoRetry() along the way), find one that
    // is relay's own self-advertisement (primary target == relay's own
    // address, the shape both SendDao() and DaoRetry() build the same way)
    // and check it actually carries probe as an additional target -- not
    // empty, and not some other node's data. This topology's own 1 s
    // channel delay against a 200 ms DaoAckTimeout guarantees at least one
    // of relay's own self-advertisements is a genuine DaoRetry() retry, not
    // just SendDao()'s first attempt (@see RplStoringModeDaoRetryTestCase's
    // own comment).
    bool foundProbeAggregated = false;
    for (const auto& dao : m_captured)
    {
        if (dao.GetTarget() != relayGlobal)
        {
            continue;
        }
        for (const auto& additional : dao.GetAdditionalTargets())
        {
            if (additional.target == probeGlobal && additional.pathLifetime > 0)
            {
                foundProbeAggregated = true;
            }
        }
    }
    NS_TEST_ASSERT_MSG_EQ(foundProbeAggregated,
                          true,
                          "relay never sent a self-advertisement (initial or retried) that "
                          "correctly aggregated its own downward route to the probe");

    monitor->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief An ordinary preferred-parent switch (a strictly better parent
 *        found, the old one still live) sends a No-Path DAO to the parent
 *        being left, RFC 6550 section 9.8 rule 4.
 *
 * root(0)--A(1), T(2) initially only reaching A (root--T blocked), so T
 * joins two hops out via A. Root--T is then unblocked and T is handed a
 * fabricated DIO claiming to be from root's own real link-local address,
 * advertising a rank T cannot reach through A -- root itself, one hop
 * closer than A. This is deliberately not the stale-neighbour or
 * lost-last-parent path (@see SelectPreferredParent()'s own three existing
 * SendNoPathDao() call sites): A never goes quiet and is never dropped from
 * T's own candidate set, so this exercises the ordinary "found something
 * better" switch specifically.
 */
class RplStoringModeOrdinarySwitchNoPathTestCase : public TestCase
{
  public:
    RplStoringModeOrdinarySwitchNoPathTestCase();

  private:
    void DoRun() override;
};

RplStoringModeOrdinarySwitchNoPathTestCase::RplStoringModeOrdinarySwitchNoPathTestCase()
    : TestCase("An ordinary preferred-parent switch sends a No-Path DAO to the parent being left")
{
}

void
RplStoringModeOrdinarySwitchNoPathTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(3); // 0 = root, 1 = A, 2 = T (under test)

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    Ptr<SimpleNetDevice> rootDevice = DynamicCast<SimpleNetDevice>(devices.Get(0));
    Ptr<SimpleNetDevice> tDevice = DynamicCast<SimpleNetDevice>(devices.Get(2));
    channel->BlackList(rootDevice, tDevice);
    channel->BlackList(tDevice, rootDevice);

    RplHelper rplHelper;
    rplHelper.Set("Mop", UintegerValue(RPL_MOP_STORING_NO_MULTICAST));
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(200));
    Simulator::Run();

    Ptr<RplRoutingProtocol> root = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> a = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> t = nodes.Get(2)->GetObject<RplRoutingProtocol>();
    Ipv6Address dodagId = root->GetGlobalAddress();
    Ipv6Address tAddress = t->GetGlobalAddress();
    Ipv6Address rootLinkLocal =
        nodes.Get(0)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address aLinkLocal =
        nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    NS_TEST_ASSERT_MSG_EQ(t->IsJoined(), true, "T never joined the Storing mode DODAG");
    NS_TEST_ASSERT_MSG_EQ(t->GetPreferredParent(), aLinkLocal, "T did not join via A");
    NS_TEST_ASSERT_MSG_EQ(t->GetRank(), 3 * RPL_MIN_HOPRANKINC, "T is not two hops out via A");

    Ipv6Address nextHop;
    NS_TEST_ASSERT_MSG_EQ(a->GetDownwardRoute(RPL_DEFAULT_INSTANCE, dodagId, tAddress, nextHop),
                          true,
                          "A never learned a downward route to T");

    // Root and T can now genuinely hear each other, so whatever T decides
    // to do about its preferred parent can actually be delivered.
    channel->UnBlackList(rootDevice, tDevice);
    channel->UnBlackList(tDevice, rootDevice);

    // A fabricated DIO, claiming to be from root's own real link-local
    // address (so anything T subsequently sends there really arrives),
    // advertising root's own real rank -- one hop closer than A, which T
    // cannot reach through A at all (RankViaParent() via root:
    // 2*MinHopRankInc, strictly less than T's current 3*MinHopRankInc via
    // A). Driving this directly, rather than waiting on root's own Trickle
    // schedule, keeps the test's timing independent of wherever root's
    // Trickle counter happens to be by t=200s.
    RplDioHeader dio;
    dio.SetInstanceId(RPL_DEFAULT_INSTANCE);
    dio.SetVersionNumber(0);
    dio.SetRank(RPL_MIN_HOPRANKINC);
    dio.SetMop(RPL_MOP_STORING_NO_MULTICAST);
    dio.SetDodagId(dodagId);
    dio.SetDagConfiguration(RPL_DIO_INTERVAL_DOUBLINGS,
                            RPL_DIO_INTERVAL_MIN,
                            RPL_DIO_REDUNDANCY,
                            RPL_MAX_RANKINC,
                            RPL_MIN_HOPRANKINC,
                            RPL_OCP_OF0,
                            RPL_DEFAULT_LIFETIME,
                            RPL_DEFAULT_LIFETIME_UNIT);
    // DeliverRawRplMessage(), not SendRawRplMessage(): every other synthetic
    // multicast DIO in this test suite uses it too (SendRawRplMessage()'s
    // own real send via a raw socket does not reliably reach a multicast
    // destination the way delivering straight to T's own Receive() does).
    // Only this one injection is synthetic -- T's own subsequent real
    // traffic (its new DAO to root, its No-Path to A) still goes out for
    // real, over the now-unblocked channel.
    //
    // Delivered RPL_FRESHNESS_TARGET times, not once:
    // SelectPreferredParent()'s own two-pass structure only relaxes the
    // freshness requirement (pass 1) when pass 0 finds no candidate at
    // all, and A -- already well past the freshness target from the whole
    // formation above -- still clears pass 0 as an unchanged candidate
    // even though root's own rank is better, so pass 1 (which would
    // otherwise let a freshly-heard root through despite its low
    // freshness) never runs and root is silently ignored until it, too,
    // reaches the target.
    for (uint8_t i = 0; i < RPL_FRESHNESS_TARGET; i++)
    {
        Simulator::Schedule(Seconds(0),
                            &DeliverRawRplMessage<RplDioHeader>,
                            nodes.Get(2),
                            1,
                            dio,
                            static_cast<uint8_t>(RPL_CODE_DIO),
                            rootLinkLocal,
                            Ipv6Address(RPL_ALL_NODES_MULTICAST));
        Simulator::Stop(MilliSeconds(50));
        Simulator::Run();
    }
    Simulator::Stop(Seconds(10));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(t->GetPreferredParent(),
                          rootLinkLocal,
                          "T did not switch to the strictly better parent");
    NS_TEST_ASSERT_MSG_EQ(t->GetRank(), 2 * RPL_MIN_HOPRANKINC, "T's rank did not improve");

    NS_TEST_ASSERT_MSG_EQ(
        a->GetDownwardRoute(RPL_DEFAULT_INSTANCE, dodagId, tAddress, nextHop),
        false,
        "A still has a downward route to T after T switched away to a still-live root: no "
        "No-Path DAO was sent for this ordinary switch");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A locally clock-expired downwardRoutes entry is not erased on the
 *        spot; a stale, reordered duplicate arriving after that expiry is
 *        still correctly rejected rather than resurrected.
 *
 * root(0)--probe(1), Storing mode. Erasing an expired entry the moment
 * HandleDao() happens to notice it (the behaviour before this fix) throws
 * away the last Path Sequence this node ever saw for the target -- so any
 * later DAO for it, however old, would be compared against nothing and
 * treated as unconditionally new. This drives a fictitious target directly
 * at root: establish it, let it expire, then deliver a duplicate carrying
 * an older Path Sequence than what was ever stored, and confirm it is still
 * recognised as stale.
 */
class RplStoringModeStaleAfterExpiryTestCase : public TestCase
{
  public:
    RplStoringModeStaleAfterExpiryTestCase();

  private:
    void DoRun() override;
};

RplStoringModeStaleAfterExpiryTestCase::RplStoringModeStaleAfterExpiryTestCase()
    : TestCase("A stale duplicate DAO is rejected even after the entry it would supersede has "
              "locally expired")
{
}

void
RplStoringModeStaleAfterExpiryTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2); // 0 = root, 1 = probe

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    rplHelper.Set("Mop", UintegerValue(RPL_MOP_STORING_NO_MULTICAST));
    // Large enough that no periodic purge (SendDao()'s own loop, or root's
    // own PurgeDownwardRoutesTimerExpire()) sweeps the entry out from under
    // this test before it gets a chance to check that leaving it standing,
    // past its own expiry, is what keeps the staleness check meaningful.
    rplHelper.Set("DaoInterval", TimeValue(Seconds(600)));
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(60));
    Simulator::Run();

    Ptr<RplRoutingProtocol> root = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ipv6Address dodagId = root->GetGlobalAddress();
    Ipv6Address rootLinkLocal =
        nodes.Get(0)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address probeLinkLocal =
        nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address fictitious("2001:1::ff:fe00:aa");

    auto sendDao = [&](uint8_t pathSequence, uint8_t pathLifetime) {
        RplDaoHeader dao;
        dao.SetInstanceId(RPL_DEFAULT_INSTANCE);
        dao.SetDodagId(dodagId);
        dao.SetSequence(1);
        dao.SetTarget(fictitious);
        dao.SetTransitInformation(Ipv6Address::GetAny(), pathSequence, pathLifetime);
        Simulator::Schedule(Seconds(0),
                            &SendRawRplMessage<RplDaoHeader>,
                            nodes.Get(1),
                            1,
                            dao,
                            static_cast<uint8_t>(RPL_CODE_DAO),
                            probeLinkLocal,
                            rootLinkLocal);
        Simulator::Stop(MilliSeconds(50));
        Simulator::Run();
    };

    // PathLifetime 1: 60 s (the default lifetime unit).
    sendDao(5, 1);
    Ipv6Address nextHop;
    NS_TEST_ASSERT_MSG_EQ(root->GetDownwardRoute(RPL_DEFAULT_INSTANCE, dodagId, fictitious, nextHop),
                          true,
                          "root did not accept the initial advertisement");

    // Past the 60 s expiry, with nothing else (DaoInterval is far longer)
    // touching this entry in between.
    Simulator::Stop(Seconds(61));
    Simulator::Run();
    NS_TEST_ASSERT_MSG_EQ(
        root->GetDownwardRoute(RPL_DEFAULT_INSTANCE, dodagId, fictitious, nextHop),
        false,
        "the entry did not correctly read as expired");

    // A stale, reordered duplicate -- an older Path Sequence than what was
    // ever stored (3 < 5) -- arriving after the entry's own local expiry.
    // With the entry erased on sight instead of left standing, this would
    // be compared against nothing and accepted as unconditionally new.
    sendDao(3, 1);
    NS_TEST_ASSERT_MSG_EQ(
        root->GetDownwardRoute(RPL_DEFAULT_INSTANCE, dodagId, fictitious, nextHop),
        false,
        "a stale, reordered duplicate was incorrectly resurrected after the entry's own local "
        "expiry");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A Storing mode root that never itself originates a downward
 *        packet (a pure traffic sink) still eventually purges a downward
 *        route to a descendant that disappears without ever sending a
 *        No-Path DAO.
 *
 * root(0)--probe(1). SendDao() is a no-op for a root, and RouteOutput()'s
 * own purge only runs when the root itself locally originates a packet --
 * neither of which this test's root ever does (@see
 * PurgeDownwardRoutesTimerExpire()'s own doc comment). probe is blacklisted
 * away after root has learned of it, simulating a descendant that vanishes
 * (crash, moved out of range) rather than politely withdrawing.
 *
 * GetDownwardRoutesRawCount(), not GetDownwardRouteCount(): the latter
 * filters expired entries out regardless of whether they were ever
 * actually reclaimed, so it cannot tell "correctly ignored but still
 * sitting in the map" apart from "purged" -- the distinction this test
 * exists to check.
 */
class RplStoringModeRootPurgeTestCase : public TestCase
{
  public:
    RplStoringModeRootPurgeTestCase();

  private:
    void DoRun() override;
};

RplStoringModeRootPurgeTestCase::RplStoringModeRootPurgeTestCase()
    : TestCase("A Storing mode root that never originates traffic still purges a downward route "
              "to a vanished descendant")
{
}

void
RplStoringModeRootPurgeTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2); // 0 = root, 1 = probe

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    rplHelper.Set("Mop", UintegerValue(RPL_MOP_STORING_NO_MULTICAST));
    rplHelper.Set("PathLifetime", UintegerValue(1));    // 60 s
    rplHelper.Set("DaoInterval", TimeValue(Seconds(10))); // root's own purge cadence
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(60));
    Simulator::Run();

    Ptr<RplRoutingProtocol> root = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> probe = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(probe->IsJoined(), true, "probe never joined the Storing mode DODAG");

    Ipv6Address dodagId = root->GetGlobalAddress();
    NS_TEST_ASSERT_MSG_EQ(root->GetDownwardRoutesRawCount(RPL_DEFAULT_INSTANCE, dodagId),
                          1,
                          "root never learned of probe at all");

    // probe vanishes: no more DIOs, no No-Path DAO, nothing -- root simply
    // stops hearing from it, the way a crash or moving out of range would
    // look, as opposed to a graceful withdrawal.
    Ptr<SimpleNetDevice> rootDevice = DynamicCast<SimpleNetDevice>(devices.Get(0));
    Ptr<SimpleNetDevice> probeDevice = DynamicCast<SimpleNetDevice>(devices.Get(1));
    channel->BlackList(rootDevice, probeDevice);
    channel->BlackList(probeDevice, rootDevice);

    // Well past the 60 s PathLifetime, with several of root's own 10 s
    // purge cycles (PurgeDownwardRoutesTimerExpire()) along the way -- root
    // itself never calls RouteOutput() for probe's address anywhere in
    // this test, so PurgeDownwardRoutes()'s other call site never runs
    // either.
    Simulator::Stop(Seconds(120));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(
        root->GetDownwardRoutesRawCount(RPL_DEFAULT_INSTANCE, dodagId),
        0,
        "root's downwardRoutes entry for the vanished probe was never actually purged");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A node in radio range of two independent DODAG roots joins both at
 *        once, and each root's own topology genuinely learns about it.
 *
 * Two roots, each with its own RootPrefix, sit on either end of a line; the
 * node between them cannot avoid hearing both. The two roots are
 * blacklisted against each other so this test only has to reason about the
 * shared node's own behaviour, not whether a root also ends up a passive
 * member of the other root's DODAG (which HandleDio()'s relaxed root gate
 * now allows, but is not what this test is checking).
 *
 * GetTopologySize() == 1 on both roots is the real assertion here: without
 * RouteOutput()'s non-base-DODAG fallback and GetGlobalAddressIn() (the two
 * fixes a plain "the join happened" check would not catch), the shared
 * node's DAO for its second DODAG would either misroute through the first
 * DODAG's preferred parent or advertise the wrong DODAG's address as its
 * Target, and the second root's topology would stay empty.
 */
class RplMultiDodagTestCase : public TestCase
{
  public:
    RplMultiDodagTestCase();

  private:
    void DoRun() override;
};

RplMultiDodagTestCase::RplMultiDodagTestCase()
    : TestCase("A node can join two independent DODAGs at once")
{
}

void
RplMultiDodagTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(3); // 0 = root A, 1 = shared node, 2 = root B

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    Ptr<SimpleNetDevice> rootADevice = DynamicCast<SimpleNetDevice>(devices.Get(0));
    Ptr<SimpleNetDevice> rootBDevice = DynamicCast<SimpleNetDevice>(devices.Get(2));
    channel->BlackList(rootADevice, rootBDevice);
    channel->BlackList(rootBDevice, rootADevice);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.SetRoot(nodes.Get(2), Ipv6Address("2001:2::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    // Same margin RplDodagFormationTestCase gives a one-hop DODAG: Imin plus
    // DAD for both the roots' own addresses and the shared node's two SLAAC
    // addresses (one per prefix).
    Simulator::Stop(Seconds(200));
    Simulator::Run();

    Ptr<RplRoutingProtocol> rootA = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> shared = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> rootB = nodes.Get(2)->GetObject<RplRoutingProtocol>();

    Ipv6Address dodagAId = rootA->GetGlobalAddress();
    Ipv6Address dodagBId = rootB->GetGlobalAddress();
    NS_TEST_ASSERT_MSG_NE(dodagAId, Ipv6Address::GetAny(), "Root A never started its DODAG");
    NS_TEST_ASSERT_MSG_NE(dodagBId, Ipv6Address::GetAny(), "Root B never started its DODAG");

    NS_TEST_ASSERT_MSG_EQ(shared->GetDodagCount(), 2, "The shared node did not join both DODAGs");

    // Whichever DIO happened to arrive first becomes the base; this test
    // does not care which, only that the base is one of the two and the
    // other is reachable through the key-scoped accessors.
    Ipv6Address baseDodagId = shared->GetDodagId();
    NS_TEST_ASSERT_MSG_EQ(baseDodagId == dodagAId || baseDodagId == dodagBId,
                          true,
                          "The base DODAG is neither root A nor root B");
    Ipv6Address otherDodagId = (baseDodagId == dodagAId) ? dodagBId : dodagAId;

    NS_TEST_ASSERT_MSG_EQ(shared->IsJoined(), true, "The shared node left its base DODAG");
    NS_TEST_ASSERT_MSG_NE(shared->GetRank(), RPL_INFINITE_RANK, "The base DODAG rank is infinite");

    NS_TEST_ASSERT_MSG_EQ(shared->IsJoinedTo(RPL_DEFAULT_INSTANCE, otherDodagId),
                          true,
                          "The shared node did not join the second DODAG");
    NS_TEST_ASSERT_MSG_NE(shared->GetRankIn(RPL_DEFAULT_INSTANCE, otherDodagId),
                          RPL_INFINITE_RANK,
                          "The second DODAG's rank is infinite");

    // The real proof that the second membership is not just tracking rank:
    // its DAO reached its own root, which needed RouteOutput()'s non-base
    // fallback (to leave via the right preferred parent) and
    // GetGlobalAddressIn() (to advertise the right Target address) both to
    // be correct.
    //
    // Checked with ComputeSourceRoute() for the shared node's own address on
    // each prefix specifically, rather than GetTopologySize() == 1: the
    // shared node is not the only thing that can end up in either topology
    // here. Once it holds both memberships it also re-advertises both in
    // its own DIOs (SendDio() carries every DODAG's Configuration/Prefix
    // options onward, not just the root's), which the OTHER root -- within
    // radio range of the shared node even though the two roots are
    // blacklisted from hearing each other directly -- can and does pick up
    // and passively join in turn. That transitive join is correct RPL
    // behaviour in general (this is exactly how a DIO propagates outward
    // through a real multi-hop DODAG) and is not what this test is
    // checking, so the assertions below must not assume either topology
    // holds only the shared node.
    auto addressOnPrefix = [](Ptr<Node> node, Ipv6Address dodagId) {
        Ptr<Ipv6L3Protocol> ipv6 = node->GetObject<Ipv6L3Protocol>();
        Ipv6Prefix prefix(64);
        for (uint32_t j = 0; j < ipv6->GetNAddresses(1); j++)
        {
            Ipv6InterfaceAddress iaddr = ipv6->GetAddress(1, j);
            if (iaddr.GetScope() == Ipv6InterfaceAddress::GLOBAL &&
                prefix.IsMatch(iaddr.GetAddress(), dodagId))
            {
                return iaddr.GetAddress();
            }
        }
        return Ipv6Address::GetAny();
    };

    Ipv6Address sharedOnDodagA = addressOnPrefix(nodes.Get(1), dodagAId);
    Ipv6Address sharedOnDodagB = addressOnPrefix(nodes.Get(1), dodagBId);
    NS_TEST_ASSERT_MSG_NE(sharedOnDodagA,
                          Ipv6Address::GetAny(),
                          "The shared node never SLAACed an address on DODAG A's prefix");
    NS_TEST_ASSERT_MSG_NE(sharedOnDodagB,
                          Ipv6Address::GetAny(),
                          "The shared node never SLAACed an address on DODAG B's prefix");

    std::vector<Ipv6Address> hops;
    NS_TEST_ASSERT_MSG_EQ(rootA->ComputeSourceRoute(sharedOnDodagA, hops),
                          true,
                          "Root A cannot reach the shared node: its DAO for DODAG A never "
                          "registered");
    NS_TEST_ASSERT_MSG_EQ(rootB->ComputeSourceRoute(sharedOnDodagB, hops),
                          true,
                          "Root B cannot reach the shared node: its DAO for DODAG B never "
                          "registered");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief CreateLocalDodag() lets a node form its own DODAG at runtime, on
 *        top of (not instead of) whatever base DODAG it already has.
 *
 * The primitive AODV-RPL/P2P-RPL will need to root their own local
 * instance: this checks it in isolation, without either protocol built on
 * top of it yet. A neighbour picking up the resulting DIO and joining
 * passively re-uses the exact mechanism RplMultiDodagTestCase checks, so
 * this only has to confirm the local DODAG itself forms correctly.
 */
class RplCreateLocalDodagTestCase : public TestCase
{
  public:
    RplCreateLocalDodagTestCase();

  private:
    void DoRun() override;
};

RplCreateLocalDodagTestCase::RplCreateLocalDodagTestCase()
    : TestCase("CreateLocalDodag() forms a self-rooted DODAG at runtime")
{
}

void
RplCreateLocalDodagTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2); // 0 = base DODAG root, also forms a local one; 1 = neighbour

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    // Long enough for DAD to clear on the root's base address before
    // CreateLocalDodag() is called on it below.
    Simulator::Stop(Seconds(5));
    Simulator::Run();

    Ptr<RplRoutingProtocol> root = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(root->IsJoined(), true, "The base DODAG never formed");

    static constexpr uint8_t LOCAL_INSTANCE = 0x80; // high bit set, RFC 6550 section 5.1
    RplRoutingProtocol::DodagKey localKey = root->CreateLocalDodag(LOCAL_INSTANCE, RPL_MOP_NON_STORING);

    NS_TEST_ASSERT_MSG_EQ(localKey.instanceId, LOCAL_INSTANCE, "Wrong instanceId in the returned key");
    NS_TEST_ASSERT_MSG_NE(localKey.dodagId, Ipv6Address::GetAny(), "No DODAGID in the returned key");
    NS_TEST_ASSERT_MSG_EQ(localKey.dodagId,
                          root->GetGlobalAddress(),
                          "The local DODAG is not rooted at this node's own address");

    // The base DODAG (RplHelper::SetRoot()'s) is untouched: CreateLocalDodag()
    // adds a second membership, it does not replace the first. DODAGID
    // alone cannot tell the two apart here -- both are rooted at this same
    // node's one global address, RFC 9854/6997 fashion -- only instanceId
    // differs (RPL_DEFAULT_INSTANCE vs LOCAL_INSTANCE), which is exactly
    // what GetDodagCount() == 2 plus the IsJoinedTo() check just below
    // together confirm: two distinct keyed memberships, not one replaced by
    // the other.
    NS_TEST_ASSERT_MSG_EQ(root->GetDodagCount(), 2, "CreateLocalDodag() did not add a membership");

    NS_TEST_ASSERT_MSG_EQ(root->IsJoinedTo(localKey.instanceId, localKey.dodagId),
                          true,
                          "Not joined to the DODAG CreateLocalDodag() just formed");
    NS_TEST_ASSERT_MSG_EQ(root->GetRankIn(localKey.instanceId, localKey.dodagId),
                          RPL_MIN_HOPRANKINC,
                          "The local DODAG's root is not at MinHopRankIncrease");

    // The local DODAG carries no Prefix Information, unlike the base one:
    // a neighbour joining it must not attempt SLAAC on it.
    Ptr<RplRoutingProtocol> neighbour = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Simulator::Stop(Seconds(200));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(neighbour->IsJoinedTo(localKey.instanceId, localKey.dodagId),
                          true,
                          "The neighbour did not passively join the local DODAG");
    // Exactly one link-local plus one global (SLAACed on the base DODAG's
    // RootPrefix): if the local DODAG had wrongly carried Prefix
    // Information, the neighbour would have SLAACed a second global address
    // on it too. Checked as a final count rather than a before/after delta
    // around CreateLocalDodag() -- the base DODAG's own DIO is paced by a
    // Trickle timer whose very first firing is itself randomised within
    // [Imin/2, Imin) (RFC 6206), so whether the neighbour has already
    // SLAACed the base address by the time CreateLocalDodag() is called a
    // few seconds in is not deterministic, only that it has by the time the
    // full run ends.
    NS_TEST_ASSERT_MSG_EQ(nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetNAddresses(1),
                          2,
                          "The neighbour has the wrong number of addresses: the local DODAG must not "
                          "have triggered a second SLAAC");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief CreateLocalDodag() clears a Local RPLInstanceID's own 'D' flag,
 *        regardless of what the caller passed, and leaves a Global
 *        RPLInstanceID's identical bit position untouched.
 *
 * Found auditing CreateLocalDodag() with the protocol-test-matrix skill,
 * against RFC 6550 section 5.1: the Local RPLInstanceID field is
 * "|1|D|ID|" (top bit marks it Local, the next is the 'D' flag, the
 * remaining six are the actual ID, 0..63), and "the 'D' flag ... is always
 * set to 0 in RPL control messages". Every control message a DODAG sends
 * (SendDio(), SendDao(), ...) just copies DodagMembership::instanceId
 * verbatim, so an uncorrected 'D' flag on it would land on the wire in
 * every one of them. A probe (scratch/rpl-local-instance-d-flag-probe.cc,
 * deleted once this was confirmed and fixed) confirmed the DODAG's own key
 * carried the caller's uncorrected byte straight through before this fix.
 *
 * The Global case matters just as much here: the exact same bit position
 * (0x40) is simply part of a Global RPLInstanceID's own 7-bit ID space
 * (0..127) when the top bit is clear, not a flag at all -- masking it
 * unconditionally would silently corrupt an otherwise ordinary Global ID
 * like 64 (0x40) into 0.
 */
class RplCreateLocalDodagClearsDFlagTestCase : public TestCase
{
  public:
    RplCreateLocalDodagClearsDFlagTestCase();

  private:
    void DoRun() override;
};

RplCreateLocalDodagClearsDFlagTestCase::RplCreateLocalDodagClearsDFlagTestCase()
    : TestCase("CreateLocalDodag() clears the Local RPLInstanceID's own 'D' flag")
{
}

void
RplCreateLocalDodagClearsDFlagTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(1);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    ipv6.AssignWithoutAddress(devices);

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    Simulator::Stop(Seconds(2));
    Simulator::Run();

    Ptr<RplRoutingProtocol> rpl = nodes.Get(0)->GetObject<RplRoutingProtocol>();

    struct
    {
        uint8_t requested;      //!< instanceId passed to CreateLocalDodag()
        uint8_t expected;       //!< instanceId the resulting key should carry
        const char* what;       //!< what the case is, for the failure message
    } cases[] = {
        // Local, D already clear: minimum ID (0) and maximum ID (63)
        // together with D=0, both already compliant, must pass through as
        // is. Every case below deliberately maps to a distinct final
        // instanceId, since a repeated key would trip
        // CreateDodagMembership()'s own "already has a membership"
        // assertion on the second CreateLocalDodag() call for this same
        // node (same DODAGID throughout: its own one global address).
        {0x80, 0x80, "a Local instanceId with D already clear, minimum ID"},
        {0xBF, 0xBF, "a Local instanceId with D already clear, maximum ID"},
        // Local, D set: the actual regression case, at two different ID
        // values from the pair above.
        {0xC1, 0x81, "a Local instanceId with D set, ID one above the minimum"},
        {0xFE, 0xBE, "a Local instanceId with D set, ID one below the maximum"},
        // Global: bit 0x40 is part of the 7-bit ID space here, not a flag,
        // and must never be touched. RPL_DEFAULT_INSTANCE (0) itself is not
        // included here: the root already holds the base DODAG's own
        // membership under that exact key (RplHelper::SetRoot() forms it at
        // this same node's own global address), and CreateDodagMembership()
        // asserts against forming a second membership under a key that is
        // already taken.
        {0x40, 0x40, "a Global instanceId that happens to have bit 0x40 set"},
        {0x7F, 0x7F, "the maximum Global instanceId (127)"},
    };

    for (const auto& testCase : cases)
    {
        RplRoutingProtocol::DodagKey key =
            rpl->CreateLocalDodag(testCase.requested, RPL_MOP_NON_STORING);
        NS_TEST_ASSERT_MSG_NE(key.dodagId,
                              Ipv6Address::GetAny(),
                              "CreateLocalDodag() failed for " << testCase.what);
        NS_TEST_ASSERT_MSG_EQ(static_cast<uint32_t>(key.instanceId),
                              static_cast<uint32_t>(testCase.expected),
                              "Wrong resulting instanceId for " << testCase.what);
        NS_TEST_ASSERT_MSG_EQ(rpl->IsJoinedTo(testCase.expected, key.dodagId),
                              true,
                              "Not joined under the expected (corrected) key for "
                                  << testCase.what);
    }

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief The DODAG Version Number lollipop counter (RFC 6550 section 7.2) is
 *        tracked and compared per DODAG, not shared node-wide.
 *
 * One node under test hears two peers, each advertising its own DODAG
 * (hand-built DIOs, RplVersionWrapTestCase's style). Every step below is
 * applied to DODAG A only and checked against DODAG B's rank
 * (GetRankIn()) to confirm nothing leaked across: a semi-normal step
 * (an ordinary version bump), an abnormal one (a stale version rejected),
 * and the boundary the lollipop encoding exists for (the 255 -> 0 wrap,
 * both accepted forward and refused backward, mirroring
 * RplVersionWrapTestCase but now with a second, untouched DODAG alongside
 * it). The two DODAGs share one RPLInstanceID (RPL_DEFAULT_INSTANCE) and
 * are told apart purely by DODAGID, the ordinary case this module forms
 * today (@see DodagKey).
 */
class RplMultiDodagVersionIsolationTestCase : public TestCase
{
  public:
    RplMultiDodagVersionIsolationTestCase();

  private:
    void DoRun() override;
};

RplMultiDodagVersionIsolationTestCase::RplMultiDodagVersionIsolationTestCase()
    : TestCase("DODAG Version Number sequencing is independent per DODAG")
{
}

void
RplMultiDodagVersionIsolationTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(3); // 0 = node under test, 1 = peer advertising DODAG A, 2 = peer advertising DODAG B

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }
    rplHelper.AssignStreams(nodes, 1);

    Ptr<RplRoutingProtocol> node = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ipv6Address dodagAId("2001:1::1");
    Ipv6Address dodagBId("2001:2::1");
    Ipv6Address nodeLinkLocal =
        nodes.Get(0)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address peerALinkLocal =
        nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address peerBLinkLocal =
        nodes.Get(2)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    auto buildDio = [](Ipv6Address dodagId, uint8_t version, uint16_t rank) {
        RplDioHeader dio;
        dio.SetInstanceId(RPL_DEFAULT_INSTANCE);
        dio.SetVersionNumber(version);
        dio.SetRank(rank);
        dio.SetMop(RPL_MOP_NON_STORING);
        dio.SetDodagId(dodagId);
        dio.SetDagConfiguration(RPL_DIO_INTERVAL_DOUBLINGS,
                                RPL_DIO_INTERVAL_MIN,
                                RPL_DIO_REDUNDANCY,
                                RPL_MAX_RANKINC,
                                RPL_MIN_HOPRANKINC,
                                RPL_OCP_OF0,
                                RPL_DEFAULT_LIFETIME,
                                RPL_DEFAULT_LIFETIME_UNIT);
        return dio;
    };

    auto sendFrom = [&](Ptr<Node> peer, Ipv6Address peerLinkLocal, const RplDioHeader& dio) {
        Simulator::Schedule(Seconds(0),
                            &SendRawRplMessage<RplDioHeader>,
                            peer,
                            1,
                            dio,
                            static_cast<uint8_t>(RPL_CODE_DIO),
                            peerLinkLocal,
                            nodeLinkLocal);
        Simulator::Stop(MilliSeconds(10));
        Simulator::Run();
    };

    // Join both DODAGs. A starts at 253, three short of its own wrap (room
    // for two ordinary small steps -- RplSequenceCompare()'s SEQUENCE_WINDOW
    // is 16, well clear of a single increment -- before the boundary step
    // reaches it); B starts at 50, deep in the lollipop's circular region
    // and nowhere near either version. B is never touched again after this:
    // the strongest isolation proof is everything below happening to A
    // alone while B provably does not move at all.
    sendFrom(nodes.Get(1), peerALinkLocal, buildDio(dodagAId, 253, RPL_MIN_HOPRANKINC));
    NS_TEST_ASSERT_MSG_EQ(node->IsJoined(), true, "DODAG A did not bootstrap");
    NS_TEST_ASSERT_MSG_EQ(node->GetDodagId(), dodagAId, "Joined the wrong base DODAG");

    sendFrom(nodes.Get(2), peerBLinkLocal, buildDio(dodagBId, 50, RPL_MIN_HOPRANKINC));
    NS_TEST_ASSERT_MSG_EQ(node->IsJoinedTo(RPL_DEFAULT_INSTANCE, dodagBId),
                          true,
                          "DODAG B did not bootstrap");
    NS_TEST_ASSERT_MSG_EQ(node->GetRankIn(RPL_DEFAULT_INSTANCE, dodagBId),
                          2 * RPL_MIN_HOPRANKINC,
                          "Wrong initial rank in DODAG B");

    // Semi-normal: an ordinary version bump on A alone (253 -> 254, both in
    // the lollipop's linear region, RFC 6550 section 7.2 rule 3.2). The
    // peer's own advertised rank goes from 1x to 2x MinHopRankIncrease, so
    // the node's resulting rank (peer's rank + one more hop) goes from 2x
    // to 3x.
    sendFrom(nodes.Get(1), peerALinkLocal, buildDio(dodagAId, 254, 2 * RPL_MIN_HOPRANKINC));
    NS_TEST_ASSERT_MSG_EQ(node->GetRank(),
                          3 * RPL_MIN_HOPRANKINC,
                          "DODAG A did not migrate to version 254");
    NS_TEST_ASSERT_MSG_EQ(node->GetRankIn(RPL_DEFAULT_INSTANCE, dodagBId),
                          2 * RPL_MIN_HOPRANKINC,
                          "DODAG B's rank moved when only A's version changed");

    // Abnormal: a stale version for A (253, already superseded by 254) is
    // rejected -- neither A nor B's rank may move.
    sendFrom(nodes.Get(1), peerALinkLocal, buildDio(dodagAId, 253, RPL_MIN_HOPRANKINC));
    NS_TEST_ASSERT_MSG_EQ(node->GetRank(),
                          3 * RPL_MIN_HOPRANKINC,
                          "A stale DODAG A version was adopted");
    NS_TEST_ASSERT_MSG_EQ(node->GetRankIn(RPL_DEFAULT_INSTANCE, dodagBId),
                          2 * RPL_MIN_HOPRANKINC,
                          "DODAG B's rank moved when A's stale DIO was (correctly) rejected");

    // Boundary: A advances to 255, then wraps 255 -> 0 (RFC 6550 section
    // 7.2 rule 3.1), while B -- still at 50 the whole time -- must not move
    // just because A did.
    sendFrom(nodes.Get(1), peerALinkLocal, buildDio(dodagAId, 255, RPL_MIN_HOPRANKINC));
    NS_TEST_ASSERT_MSG_EQ(node->GetRank(),
                          2 * RPL_MIN_HOPRANKINC,
                          "DODAG A did not migrate to version 255");
    sendFrom(nodes.Get(1), peerALinkLocal, buildDio(dodagAId, 0, 2 * RPL_MIN_HOPRANKINC));
    NS_TEST_ASSERT_MSG_EQ(node->GetRank(),
                          3 * RPL_MIN_HOPRANKINC,
                          "DODAG A did not migrate across its own wrap to version 0");
    NS_TEST_ASSERT_MSG_EQ(node->GetRankIn(RPL_DEFAULT_INSTANCE, dodagBId),
                          2 * RPL_MIN_HOPRANKINC,
                          "DODAG B's rank moved when only A crossed its version wrap");

    // And the other direction still has to be refused for A specifically,
    // or the wrap above would just be "accept anything that differs": 255
    // is now the stale side of the wrap it already crossed.
    sendFrom(nodes.Get(1), peerALinkLocal, buildDio(dodagAId, 255, RPL_MIN_HOPRANKINC));
    NS_TEST_ASSERT_MSG_EQ(node->GetRank(),
                          3 * RPL_MIN_HOPRANKINC,
                          "DODAG A migrated backwards into the version it had already left");
    NS_TEST_ASSERT_MSG_EQ(node->GetRankIn(RPL_DEFAULT_INSTANCE, dodagBId),
                          2 * RPL_MIN_HOPRANKINC,
                          "DODAG B's rank moved when A's backward wrap attempt was (correctly) "
                          "rejected");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief The DTSN lollipop counter (RFC 6550 section 7.2) and the DAO
 *        refresh it triggers (section 9.6 rules 1/2) are per DODAG, not
 *        shared node-wide.
 *
 * A node is a member of two independently rooted DODAGs at once (the same
 * shape as RplMultiDodagTestCase). A DAO-count monitor sits on each root:
 * a DTSN bump hand-delivered as though from the shared node's DODAG A
 * parent must refresh only the DAO count at root A (semi-normal), a
 * same-or-stale DTSN must refresh neither (abnormal -- RplSequenceNewer()
 * rule 1/2 only fires on a genuine increment), and a DTSN wrapping past
 * its maximum must still be read as newer for A alone (boundary, the same
 * wrap RplDtsnWrapTestCase checks for a single DODAG).
 */
class RplMultiDodagDtsnIsolationTestCase : public TestCase
{
  public:
    RplMultiDodagDtsnIsolationTestCase();

  private:
    void DoRun() override;

    /**
     * @brief Count an arriving DAO at root A's monitor.
     * @param socket the monitoring socket
     */
    void RecordDaoA(Ptr<Socket> socket);

    /**
     * @brief Count an arriving DAO at root B's monitor.
     * @param socket the monitoring socket
     */
    void RecordDaoB(Ptr<Socket> socket);

    /**
     * @brief Shared implementation of RecordDaoA()/RecordDaoB().
     * @param socket the monitoring socket
     * @param count the counter to increment on a DAO
     */
    void RecordDaoOn(Ptr<Socket> socket, uint32_t& count);

    uint32_t m_daoCountA{0}; //!< DAOs seen at root A
    uint32_t m_daoCountB{0}; //!< DAOs seen at root B
};

RplMultiDodagDtsnIsolationTestCase::RplMultiDodagDtsnIsolationTestCase()
    : TestCase("DTSN sequencing and the DAO refresh it triggers are independent per DODAG")
{
}

void
RplMultiDodagDtsnIsolationTestCase::RecordDaoOn(Ptr<Socket> socket, uint32_t& count)
{
    Address sender;
    Ptr<Packet> packet = socket->RecvFrom(sender);
    if (!packet)
    {
        return;
    }
    Ipv6Header ipv6Header;
    packet->RemoveHeader(ipv6Header);
    Icmpv6Header icmpv6Header;
    packet->RemoveHeader(icmpv6Header);
    if (icmpv6Header.GetType() != ICMPV6_RPL || icmpv6Header.GetCode() != RPL_CODE_DAO)
    {
        return;
    }
    count++;
}

void
RplMultiDodagDtsnIsolationTestCase::RecordDaoA(Ptr<Socket> socket)
{
    RecordDaoOn(socket, m_daoCountA);
}

void
RplMultiDodagDtsnIsolationTestCase::RecordDaoB(Ptr<Socket> socket)
{
    RecordDaoOn(socket, m_daoCountB);
}

void
RplMultiDodagDtsnIsolationTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(3); // 0 = root A, 1 = shared node, 2 = root B

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    Ptr<SimpleNetDevice> rootADevice = DynamicCast<SimpleNetDevice>(devices.Get(0));
    Ptr<SimpleNetDevice> rootBDevice = DynamicCast<SimpleNetDevice>(devices.Get(2));
    channel->BlackList(rootADevice, rootBDevice);
    channel->BlackList(rootBDevice, rootADevice);

    RplHelper rplHelper;
    // Deliberately never refires on its own within this test: every DIO
    // that matters below, including the very first, join-bootstrapping one,
    // is hand-built and injected explicitly (see sendFromRootA()/the B
    // bootstrap below). If either root's own Trickle timer were also live,
    // its own un-bumped DTSN=0 background DIOs would race the hand-built
    // bumps below and silently reset dodag.parents[from].dtsn back to 0
    // between them, making a repeat of an already-adopted DTSN look like a
    // fresh increment again purely by accident of timing.
    rplHelper.Set("DioIntervalMin", TimeValue(Seconds(3600)));

    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.SetRoot(nodes.Get(2), Ipv6Address("2001:2::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Ptr<Node> rootANode = nodes.Get(0);
    Ptr<Node> sharedNode = nodes.Get(1);
    Ptr<Node> rootBNode = nodes.Get(2);

    Ptr<Socket> daoMonitorA = Socket::CreateSocket(rootANode, Ipv6RawSocketFactory::GetTypeId());
    daoMonitorA->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    daoMonitorA->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    daoMonitorA->BindToNetDevice(rootANode->GetObject<Ipv6L3Protocol>()->GetNetDevice(1));
    daoMonitorA->SetRecvCallback(
        MakeCallback(&RplMultiDodagDtsnIsolationTestCase::RecordDaoA, this));

    Ptr<Socket> daoMonitorB = Socket::CreateSocket(rootBNode, Ipv6RawSocketFactory::GetTypeId());
    daoMonitorB->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    daoMonitorB->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    daoMonitorB->BindToNetDevice(rootBNode->GetObject<Ipv6L3Protocol>()->GetNetDevice(1));
    daoMonitorB->SetRecvCallback(
        MakeCallback(&RplMultiDodagDtsnIsolationTestCase::RecordDaoB, this));

    // Just long enough for DAD to clear on both roots' own addresses; with
    // DioIntervalMin above, neither root says anything on its own beyond
    // that.
    Simulator::Stop(Seconds(2));
    Simulator::Run();

    Ptr<RplRoutingProtocol> rootA = rootANode->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> rootB = rootBNode->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> shared = sharedNode->GetObject<RplRoutingProtocol>();

    Ipv6Address dodagAId = rootA->GetGlobalAddress();
    Ipv6Address dodagBId = rootB->GetGlobalAddress();
    NS_TEST_ASSERT_MSG_NE(dodagAId, Ipv6Address::GetAny(), "Root A's own DODAG never formed");
    NS_TEST_ASSERT_MSG_NE(dodagBId, Ipv6Address::GetAny(), "Root B's own DODAG never formed");

    Ipv6Address rootALinkLocal =
        rootANode->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address rootBLinkLocal =
        rootBNode->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address sharedLinkLocal =
        sharedNode->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    auto buildDio = [](Ipv6Address dodagId, Ipv6Address prefix, uint8_t dtsn) {
        RplDioHeader dio;
        dio.SetInstanceId(RPL_DEFAULT_INSTANCE);
        dio.SetVersionNumber(0);
        dio.SetRank(RPL_MIN_HOPRANKINC); // the root's own, fixed rank
        dio.SetMop(RPL_MOP_NON_STORING);
        dio.SetDodagId(dodagId);
        dio.SetDtsn(dtsn);
        // Without this, the shared node never SLAACs a global address on
        // either prefix (JoinDodag() only calls AddAutoconfiguredAddress()
        // when HasPrefixInfo()), so SendDao() perpetually logs "no global
        // address for this node or its parent" and no DAO -- the very
        // thing daoCountA/B exist to observe -- is ever actually sent.
        dio.SetPrefixInfo(prefix,
                          64,
                          true,
                          true,
                          RPL_PREFIX_VALID_LIFETIME,
                          RPL_PREFIX_PREFERRED_LIFETIME);
        // Needed even for a DODAG the shared node has already joined: this
        // test's roots never send a real DIO of their own (DioIntervalMin
        // above), so the very first DIO carrying this is also what seeds
        // Trickle parameters on JoinDodag() -- omitting it would leave a
        // zero-length interval instead of one this test can control.
        //
        // The interval itself is deliberately huge (2^20 ms, ~17 min), the
        // same reasoning as the node-wide DioIntervalMin attribute above,
        // extended to what JoinDodag() actually adopts: RplHelper's
        // attribute only seeds a *root's own* membership (HandleDadSuccess()'s
        // root branch), not one formed by joining a DIO, so the shared
        // node's own re-advertisements of DODAG A/B need their Trickle
        // pace fixed here instead. Left at the fast default, the shared
        // node keeps re-advertising both DODAGs' Configuration/Prefix
        // options at the normal cadence, which root B can and does pick up
        // and passively join DODAG A through in turn (the same transitive
        // join RplMultiDodagTestCase documents, @see design-constraints.md
        // section 32.5) -- and root B's own resulting DAO for that
        // membership then needs relaying through the shared node, which
        // RouteInput() does not support for a non-base DODAG (section
        // 32.6), so this test would otherwise flirt with that unsupported
        // path by accident of timing rather than by anything it means to
        // exercise.
        dio.SetDagConfiguration(0,
                                20,
                                RPL_DIO_REDUNDANCY,
                                RPL_MAX_RANKINC,
                                RPL_MIN_HOPRANKINC,
                                RPL_OCP_OF0,
                                RPL_DEFAULT_LIFETIME,
                                RPL_DEFAULT_LIFETIME_UNIT);
        return dio;
    };

    auto sendFromRootA = [&](uint8_t dtsn) {
        Simulator::Schedule(Seconds(0),
                            &SendRawRplMessage<RplDioHeader>,
                            rootANode,
                            1,
                            buildDio(dodagAId, Ipv6Address("2001:1::"), dtsn),
                            static_cast<uint8_t>(RPL_CODE_DIO),
                            rootALinkLocal,
                            sharedLinkLocal);
        Simulator::Stop(Seconds(1));
        Simulator::Run();
    };

    // Bootstrap both memberships by hand: neither root's own Trickle timer
    // will ever do it within this test (see the DioIntervalMin comment
    // above). A starts at 253, three short of its own wrap and in the
    // lollipop's linear region throughout (RFC 6550 section 7.2 rule 3.2
    // does not wrap within that region, so every step on A below stays
    // safely comparable until the boundary step deliberately crosses into
    // the wrap); B starts at 0 and is never touched again. One second
    // gives SelectPreferredParent()'s jittered daoEvent (0-1s) room to fire
    // and the resulting DAO to reach and be ACKed by the real root on each
    // side.
    sendFromRootA(253);
    Simulator::Schedule(Seconds(0),
                        &SendRawRplMessage<RplDioHeader>,
                        rootBNode,
                        1,
                        buildDio(dodagBId, Ipv6Address("2001:2::"), 0),
                        static_cast<uint8_t>(RPL_CODE_DIO),
                        rootBLinkLocal,
                        sharedLinkLocal);
    Simulator::Stop(Seconds(1));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(shared->GetDodagCount(), 2, "The shared node did not join both DODAGs");
    NS_TEST_ASSERT_MSG_GT_OR_EQ(m_daoCountA, 1, "Root A never saw the shared node's initial DAO");
    NS_TEST_ASSERT_MSG_GT_OR_EQ(m_daoCountB, 1, "Root B never saw the shared node's initial DAO");

    // Semi-normal: DTSN 253 -> 254 from root A, the shared node's actual
    // DAO parent for DODAG A, is a genuine increment (RplSequenceNewer
    // rule 1/2) and must refresh the DAO at root A alone.
    uint32_t daoCountABefore = m_daoCountA;
    uint32_t daoCountBBefore = m_daoCountB;
    sendFromRootA(254);
    NS_TEST_ASSERT_MSG_GT(m_daoCountA, daoCountABefore, "The DTSN bump on A did not refresh A's DAO");
    NS_TEST_ASSERT_MSG_EQ(m_daoCountB,
                          daoCountBBefore,
                          "A DTSN bump on DODAG A refreshed DODAG B's DAO too");

    // Abnormal: the same DTSN again (254, not newer than the 254 just
    // adopted) must not trigger another refresh on either side.
    daoCountABefore = m_daoCountA;
    daoCountBBefore = m_daoCountB;
    sendFromRootA(254);
    NS_TEST_ASSERT_MSG_EQ(m_daoCountA,
                          daoCountABefore,
                          "A DTSN that was not actually newer still refreshed A's DAO");
    NS_TEST_ASSERT_MSG_EQ(m_daoCountB, daoCountBBefore, "DODAG B's DAO moved on A's unchanged DTSN");

    // Boundary: DTSN wraps 255 -> 0 for DODAG A (RFC 6550 section 7.2 rule
    // 3.1, the same wrap RplDtsnWrapTestCase checks for a single DODAG).
    // Getting there first needs one more real increment (254 -> 255, still
    // within the linear region), so the wrap itself is the second of two
    // DIOs.
    sendFromRootA(255);
    daoCountABefore = m_daoCountA;
    daoCountBBefore = m_daoCountB;
    sendFromRootA(0);
    NS_TEST_ASSERT_MSG_GT(m_daoCountA,
                          daoCountABefore,
                          "DODAG A's DTSN wrap (255 -> 0) was not read as newer");
    NS_TEST_ASSERT_MSG_EQ(m_daoCountB,
                          daoCountBBefore,
                          "DODAG B's DAO moved when only A's DTSN wrapped");

    daoMonitorA->Close();
    daoMonitorB->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief The Path Sequence lollipop counter (RFC 6550 section 7.1/9.2.1)
 *        that orders DAOs for one target is scoped to one root's own
 *        topology, not shared across DODAGs.
 *
 * Two independent roots, each with their own topology (RplStaleDaoTestCase
 * runs this exact staleness logic against a single one). Both are handed
 * DAOs for the identical numeric target address, on purpose: if Path
 * Sequence state were ever accidentally keyed by target address alone
 * rather than being a genuinely separate map per DodagMembership, a stale
 * DAO rejected at root A could still be leaking state that corrupts root
 * B's independent judgement of the very same target.
 */
class RplMultiDodagPathSequenceIsolationTestCase : public TestCase
{
  public:
    RplMultiDodagPathSequenceIsolationTestCase();

  private:
    void DoRun() override;
};

RplMultiDodagPathSequenceIsolationTestCase::RplMultiDodagPathSequenceIsolationTestCase()
    : TestCase("Path Sequence ordering of DAOs is independent per DODAG's own topology")
{
}

void
RplMultiDodagPathSequenceIsolationTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2); // 0 = root A, 1 = root B -- neither hears the other

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    Ptr<SimpleNetDevice> rootADevice = DynamicCast<SimpleNetDevice>(devices.Get(0));
    Ptr<SimpleNetDevice> rootBDevice = DynamicCast<SimpleNetDevice>(devices.Get(1));
    channel->BlackList(rootADevice, rootBDevice);
    channel->BlackList(rootBDevice, rootADevice);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.SetRoot(nodes.Get(1), Ipv6Address("2001:2::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(5));
    Simulator::Run();

    Ptr<RplRoutingProtocol> rootA = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> rootB = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(rootA->IsJoined(), true, "Root A's own DODAG never formed");
    NS_TEST_ASSERT_MSG_EQ(rootB->IsJoined(), true, "Root B's own DODAG never formed");

    // The identical target and "nowhere" addresses under each root's own
    // prefix: deliberately the same low bits, so a leak between the two
    // topology maps would be indistinguishable from correct isolation if
    // the addresses also happened to differ.
    Ipv6Address targetA("2001:1::ff:fe00:aa");
    Ipv6Address nowhereA("2001:1::ff:fe00:bb");
    Ipv6Address targetB("2001:2::ff:fe00:aa");
    Ipv6Address nowhereB("2001:2::ff:fe00:bb");

    auto sendDao = [&](Ptr<Node> rootNode,
                       Ipv6Address rootAddress,
                       Ipv6Address target,
                       Ipv6Address parent,
                       uint8_t pathSequence,
                       uint8_t lifetime) {
        RplDaoHeader dao;
        dao.SetInstanceId(RPL_DEFAULT_INSTANCE);
        dao.SetSequence(pathSequence);
        dao.SetTarget(target);
        dao.SetTransitInformation(parent, pathSequence, lifetime);
        // DeliverRawRplMessage(), not SendRawRplMessage(): unlike
        // RplStaleDaoTestCase's identical-looking helper, which sends from
        // a real, distinct child node whose own address genuinely matches
        // the src it hands to the checksum, this test has no such node --
        // both "sources" below are addresses of convenience (target itself,
        // standing in for whatever unspecified child would really send
        // this), not a real device's own address. Routed through a real
        // send, that mismatch would leave the wire packet's actual source
        // (the real sending interface's own address) disagreeing with the
        // checksum computed against the fake one, and the receiver would
        // silently drop it on a checksum failure -- indistinguishable from
        // "the DAO was rejected as stale" without a deeper look, which is
        // exactly the failure mode this test needs to rule out to mean
        // anything. Delivering directly to rootNode's own Receive() (like
        // RplDaoAckSequenceTestCase's/RplDtsnWrapTestCase's own equally
        // fully-fabricated senders) sidesteps needing a real device to back
        // the address at all: HandleDao() only ever reads the DAO's own
        // fields.
        Simulator::Schedule(Seconds(0),
                            &DeliverRawRplMessage<RplDaoHeader>,
                            rootNode,
                            1,
                            dao,
                            static_cast<uint8_t>(RPL_CODE_DAO),
                            target,
                            rootAddress);
        Simulator::Stop(MilliSeconds(10));
        Simulator::Run();
    };

    std::vector<Ipv6Address> hops;

    // Semi-normal: an ordinary fresh DAO registers at A; B's topology,
    // touched by nothing yet, stays empty. Parent is the root's own
    // address -- the simplest valid entry, a direct child one hop out --
    // so ComputeSourceRoute() below has an actual path to find; "nowhere"
    // is reserved for the deliberately-unroutable stale attempts further
    // down.
    sendDao(nodes.Get(0),
           rootA->GetGlobalAddress(),
           targetA,
           rootA->GetGlobalAddress(),
           20,
           RPL_DEFAULT_LIFETIME);
    NS_TEST_ASSERT_MSG_EQ(rootA->GetTopologySize(), 1, "Root A's fresh DAO was not recorded");
    NS_TEST_ASSERT_MSG_EQ(rootB->GetTopologySize(),
                          0,
                          "Root B's topology grew from a DAO sent only to root A");

    // The matching fresh DAO at B, for the numerically identical target.
    sendDao(nodes.Get(1),
           rootB->GetGlobalAddress(),
           targetB,
           rootB->GetGlobalAddress(),
           5,
           RPL_DEFAULT_LIFETIME);
    NS_TEST_ASSERT_MSG_EQ(rootB->GetTopologySize(), 1, "Root B's fresh DAO was not recorded");
    NS_TEST_ASSERT_MSG_EQ(rootA->GetTopologySize(),
                          1,
                          "Root A's topology changed size from a DAO sent only to root B");
    NS_TEST_ASSERT_MSG_EQ(rootA->ComputeSourceRoute(targetA, hops),
                          true,
                          "Root A's own route was disturbed by root B's unrelated DAO");

    // Abnormal: a stale DAO for A's target (Path Sequence 19, superseded by
    // the 20 already recorded) must be rejected at A, and must not touch
    // B's independent Path Sequence bookkeeping for the same numeric
    // target (still on its own sequence, currently 5).
    sendDao(nodes.Get(0), rootA->GetGlobalAddress(), targetA, nowhereA, 19, RPL_DEFAULT_LIFETIME);
    NS_TEST_ASSERT_MSG_EQ(rootA->ComputeSourceRoute(targetA, hops),
                          true,
                          "Root A's stale DAO overwrote the newer entry it was overtaken by");
    // Proven by B still rejecting a stale Path Sequence for its own target
    // (4, lower than the 5 already recorded -- an equal one is not stale,
    // RFC 6550 section 9.2.1's retransmission case, RplStaleDaoTestCase
    // covers that distinction for a single DODAG): if the two roots shared
    // any Path Sequence state, root A's unrelated stale DAO just above
    // (Path Sequence 19) would already have left something for this one to
    // disagree with.
    sendDao(nodes.Get(1), rootB->GetGlobalAddress(), targetB, nowhereB, 4, RPL_DEFAULT_LIFETIME);
    NS_TEST_ASSERT_MSG_EQ(rootB->ComputeSourceRoute(targetB, hops),
                          true,
                          "Root B accepted a stale Path Sequence, or root A's stale DAO corrupted "
                          "root B's own Path Sequence state for the identical target");

    // Boundary: Path Sequence wraps 255 -> 0 for A's target, independently
    // of B, which is nowhere near its own wrap (still at 5).
    sendDao(nodes.Get(0),
           rootA->GetGlobalAddress(),
           targetA,
           rootA->GetGlobalAddress(),
           255,
           RPL_DEFAULT_LIFETIME);
    NS_TEST_ASSERT_MSG_EQ(rootA->GetTopologySize(), 1, "Root A did not accept Path Sequence 255");
    sendDao(nodes.Get(0),
           rootA->GetGlobalAddress(),
           targetA,
           rootA->GetGlobalAddress(),
           0,
           RPL_DEFAULT_LIFETIME);
    NS_TEST_ASSERT_MSG_EQ(rootA->ComputeSourceRoute(targetA, hops),
                          true,
                          "Root A did not accept its own Path Sequence wrap (255 -> 0)");
    NS_TEST_ASSERT_MSG_EQ(rootB->GetTopologySize(),
                          1,
                          "Root B's topology changed when only root A's Path Sequence wrapped");
    NS_TEST_ASSERT_MSG_EQ(rootB->ComputeSourceRoute(targetB, hops),
                          true,
                          "Root B's own route was disturbed by root A's unrelated Path Sequence "
                          "wrap");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A DAO-ACK is matched against the membership its own
 *        (RPLInstanceID, DODAGID) names, not just against its DAOSequence.
 *
 * The regression test for HandleDaoAck()'s key resolution. Before that was
 * fixed it resolved through GetBaseDodag() unconditionally and compared
 * only the sequence, so an acknowledgement from one DODAG's root could
 * clear another membership's pending state -- leaving the membership that
 * really was waiting to retransmit forever despite having been
 * acknowledged. The fix was made on a design review's word alone, with no
 * test to hold it; this is that test.
 *
 * One node joins two independently rooted DODAGs. Neither root is a real,
 * behaving node: both DODAGs are bootstrapped by hand-built DIOs
 * (DeliverRawRplMessage(), so no real device or channel round trip is
 * needed at all) naming addresses nothing on the channel answers to.
 * SendDao() marks a membership's own daoAckPending true and arms its
 * retry timer unconditionally, before the packet it just built ever
 * reaches RouteOutput() -- so both memberships end up genuinely pending,
 * with no need to actually deliver anything to a listening root, and
 * nothing in this test depends on Neighbour Discovery ever resolving a
 * gateway (the earlier version of this test did, over a channel with a
 * blacklist raised mid-run, and that dependency on which of two
 * unrelated nodes' Neighbour Discovery cache happened to still be warm
 * made it flaky enough to replace outright). Every acknowledgement from
 * there on is hand-built too (IsDaoAckPendingIn(), not a wire capture,
 * is what each step checks):
 *
 * - semi-normal: the right key and the right sequence clears that
 *   membership's pending state, and only that one's;
 * - abnormal: the right sequence carried under the *other* DODAG's key
 *   (exactly the confusion the old code fell for), or under a DODAG this
 *   node has never joined, clears neither;
 * - boundary: the right DODAGID paired with a *Local* RPLInstanceID (high
 *   bit set, RFC 6550 section 5.1) rather than the Global one the
 *   membership actually holds -- the two halves of the key's own
 *   namespace, which a comparison looking at DODAGID alone would not tell
 *   apart.
 *
 * The two memberships' DAOSequences start identical by construction (both
 * memberships' first-ever SendDao() lands on 1, DodagMembership::daoSequence
 * pre-incrementing from a fresh 0) and are deliberately left that way for
 * the first abnormal case, so "A's real pending sequence" is also exactly
 * what B is (not) waiting on -- the coincidence a sequence-only comparison
 * could hide behind. A DTSN bump on DODAG A alone then earns it one extra
 * DAO (RFC 6550 section 9.6 rule 1) before the rest of the cases run, so
 * from there on the two sequences are provably out of step too.
 */
class RplMultiDodagDaoAckIsolationTestCase : public TestCase
{
  public:
    RplMultiDodagDaoAckIsolationTestCase();

  private:
    void DoRun() override;
};

RplMultiDodagDaoAckIsolationTestCase::RplMultiDodagDaoAckIsolationTestCase()
    : TestCase("A DAO-ACK is matched per DODAG, not by DAOSequence alone")
{
}

void
RplMultiDodagDaoAckIsolationTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(1); // the only node under test; both DODAGs' roots are addresses of convenience

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    rplHelper.Set("DaoAckTimeout", TimeValue(Seconds(1)));
    rplHelper.Set("DaoRetries", UintegerValue(30));

    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    interfaces.SetForwarding(0, true);
    rplHelper.AssignStreams(nodes, 1);

    Ptr<Node> node = nodes.Get(0);
    Ptr<RplRoutingProtocol> rpl = node->GetObject<RplRoutingProtocol>();
    Ipv6Address nodeLinkLocal = node->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    // Neither address below corresponds to a real node on the channel:
    // nothing here needs a reply, only a DODAGID and a link-local to source
    // the hand-built DIOs from.
    Ipv6Address dodagAId("2001:1::1");
    Ipv6Address dodagBId("2001:2::1");
    Ipv6Address rootALinkLocal("fe80::a");
    Ipv6Address rootBLinkLocal("fe80::b");

    auto buildDio = [](Ipv6Address dodagId, Ipv6Address prefix, uint8_t dtsn) {
        RplDioHeader dio;
        dio.SetInstanceId(RPL_DEFAULT_INSTANCE);
        dio.SetVersionNumber(0);
        dio.SetRank(RPL_MIN_HOPRANKINC);
        dio.SetMop(RPL_MOP_NON_STORING);
        dio.SetDodagId(dodagId);
        dio.SetDtsn(dtsn);
        // Without the Configuration option a joining node adopts a
        // zero-length Trickle interval; without Prefix Information it never
        // SLAACs an address and SendDao() gives up before sending anything
        // at all (RplMultiDodagDtsnIsolationTestCase hit both the same way).
        dio.SetDagConfiguration(0,
                                20,
                                RPL_DIO_REDUNDANCY,
                                RPL_MAX_RANKINC,
                                RPL_MIN_HOPRANKINC,
                                RPL_OCP_OF0,
                                RPL_DEFAULT_LIFETIME,
                                RPL_DEFAULT_LIFETIME_UNIT);
        dio.SetPrefixInfo(prefix,
                          64,
                          true,
                          true,
                          RPL_PREFIX_VALID_LIFETIME,
                          RPL_PREFIX_PREFERRED_LIFETIME);
        return dio;
    };
    auto deliverDio = [&](Ipv6Address rootLinkLocal,
                          Ipv6Address dodagId,
                          Ipv6Address prefix,
                          uint8_t dtsn) {
        Simulator::Schedule(Seconds(0),
                            &DeliverRawRplMessage<RplDioHeader>,
                            node,
                            1,
                            buildDio(dodagId, prefix, dtsn),
                            static_cast<uint8_t>(RPL_CODE_DIO),
                            rootLinkLocal,
                            nodeLinkLocal);
    };

    // Join both DODAGs. GetGlobalAddress() is usable on a TENTATIVE_OPTIMISTIC
    // address (RFC 4429, HandleDadSuccess()'s own comment on this), so
    // nothing here needs to wait out DAD before SelectPreferredParent()'s
    // parent-changed branch schedules the first SendDao() -- 2s is ample
    // margin over its own [0, 1) jitter for both.
    deliverDio(rootALinkLocal, dodagAId, Ipv6Address("2001:1::"), 0);
    deliverDio(rootBLinkLocal, dodagBId, Ipv6Address("2001:2::"), 0);
    Simulator::Stop(Seconds(2));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(rpl->GetDodagCount(), 2, "Did not join both DODAGs");
    NS_TEST_ASSERT_MSG_EQ(rpl->IsDaoAckPendingIn(RPL_DEFAULT_INSTANCE, dodagAId),
                          true,
                          "DODAG A's initial DAO should still be unacknowledged");
    NS_TEST_ASSERT_MSG_EQ(rpl->IsDaoAckPendingIn(RPL_DEFAULT_INSTANCE, dodagBId),
                          true,
                          "DODAG B's initial DAO should still be unacknowledged");

    auto deliverAck = [&](uint8_t instanceId,
                          Ipv6Address dodagId,
                          Ipv6Address fromAddress,
                          uint8_t sequence) {
        RplDaoAckHeader ack;
        ack.SetInstanceId(instanceId);
        ack.SetDodagId(dodagId);
        ack.SetSequence(sequence);
        ack.SetStatus(0); // unqualified acceptance
        Simulator::Schedule(Seconds(0),
                            &DeliverRawRplMessage<RplDaoAckHeader>,
                            node,
                            1,
                            ack,
                            static_cast<uint8_t>(RPL_CODE_DAO_ACK),
                            fromAddress,
                            nodeLinkLocal);
        Simulator::Stop(MilliSeconds(10));
        Simulator::Run();
    };

    // Abnormal, and exactly the confusion the old code fell for: DODAG A's
    // real pending sequence (1, both memberships' first ever) carried under
    // DODAG B's key. The fix resolves this by key to DODAG B, whose own
    // pending sequence really is 1 too, so it clears B correctly -- the
    // assertion that matters is the one right after, that A (whose own
    // sequence the acknowledgement also happens to equal) is still pending:
    // the old code, matching by sequence against whatever GetBaseDodag()
    // returned, would have cleared A here instead.
    deliverAck(RPL_DEFAULT_INSTANCE, dodagBId, rootBLinkLocal, 1);
    NS_TEST_ASSERT_MSG_EQ(rpl->IsDaoAckPendingIn(RPL_DEFAULT_INSTANCE, dodagBId),
                          false,
                          "DODAG B's own acknowledgement (sequence 1) did not clear DODAG B");
    NS_TEST_ASSERT_MSG_EQ(rpl->IsDaoAckPendingIn(RPL_DEFAULT_INSTANCE, dodagAId),
                          true,
                          "A DAO-ACK carrying DODAG B's key cleared DODAG A instead: the "
                          "acknowledgement was matched by sequence alone, GetBaseDodag()-style");

    // Desync the two DAOSequences properly before the rest of the cases: a
    // DTSN bump from A's own DAO parent earns it one extra DAO (RFC 6550
    // section 9.6 rule 1), landing A on sequence 2 while B stays acknowledged.
    deliverDio(rootALinkLocal, dodagAId, Ipv6Address("2001:1::"), 1);
    Simulator::Stop(Seconds(2));
    Simulator::Run();
    NS_TEST_ASSERT_MSG_EQ(rpl->IsDaoAckPendingIn(RPL_DEFAULT_INSTANCE, dodagAId),
                          true,
                          "The DTSN-triggered refresh DAO for DODAG A should be unacknowledged");

    // Boundary: the right DODAGID, but paired with a Local RPLInstanceID
    // (high bit set, RFC 6550 section 5.1) where the membership holds the
    // Global one -- the two halves of the key's namespace, told apart only
    // if the comparison actually looks at the RPLInstanceID too.
    static constexpr uint8_t LOCAL_INSTANCE = 0x80;
    deliverAck(LOCAL_INSTANCE, dodagAId, rootALinkLocal, 2);
    NS_TEST_ASSERT_MSG_EQ(rpl->IsDaoAckPendingIn(RPL_DEFAULT_INSTANCE, dodagAId),
                          true,
                          "A DAO-ACK naming a Local RPLInstanceID cleared a membership held under "
                          "the Global one: the RPLInstanceID half of the key is not being compared");

    // Abnormal: a DODAG this node has never joined at all.
    deliverAck(RPL_DEFAULT_INSTANCE, Ipv6Address("2001:9::1"), rootALinkLocal, 2);
    NS_TEST_ASSERT_MSG_EQ(rpl->IsDaoAckPendingIn(RPL_DEFAULT_INSTANCE, dodagAId),
                          true,
                          "A DAO-ACK for a DODAG this node never joined cleared DODAG A");
    NS_TEST_ASSERT_MSG_EQ(rpl->IsDaoAckPendingIn(RPL_DEFAULT_INSTANCE, dodagBId),
                          false,
                          "A DAO-ACK for a DODAG this node never joined disturbed DODAG B, which "
                          "was already acknowledged");

    // Semi-normal: DODAG A's own key and its own (now desynced) pending
    // sequence clears it, without disturbing DODAG B (already acknowledged
    // above, and confirmed to stay that way).
    deliverAck(RPL_DEFAULT_INSTANCE, dodagAId, rootALinkLocal, 2);
    NS_TEST_ASSERT_MSG_EQ(rpl->IsDaoAckPendingIn(RPL_DEFAULT_INSTANCE, dodagAId),
                          false,
                          "DODAG A's own correct acknowledgement did not clear it");
    NS_TEST_ASSERT_MSG_EQ(rpl->IsDaoAckPendingIn(RPL_DEFAULT_INSTANCE, dodagBId),
                          false,
                          "Acknowledging DODAG A disturbed DODAG B's already-acknowledged state");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A non-base DODAG's DAO is relayed through intermediate nodes, not
 *        just originated by them.
 *
 * The regression test for RouteInput()'s own generalisation: before that
 * was fixed, an intermediate node only ever forwarded traffic via its base
 * DODAG's preferred parent, so a DAO for any other DODAG this node happened
 * to relay for -- a CreateLocalDodag()-formed one in particular -- was
 * silently absorbed instead of passed on.
 *
 * A 4-node line: root0 roots both the base DODAG (RplHelper::SetRoot()) and,
 * once that has converged, a local one (CreateLocalDodag()); relay1 and
 * relay2 sit in between; leaf3 is at the far end, three hops out on either
 * DODAG. All four join the base DODAG normally, then relay1/relay2/leaf3
 * each passively pick up the local DODAG's own DIO too, the same
 * transitive-join mechanism RplMultiDodagTestCase documents -- but relaying
 * leaf3's own DAO for that local DODAG back to root0 needs relay2 and then
 * relay1 to each forward it correctly, which is what actually proves this
 * fix: ComputeSourceRoute() only succeeds at root0 if both hops resolved
 * the right (non-base) preferred parent for it.
 */
class RplNonBaseDodagRelayTestCase : public TestCase
{
  public:
    RplNonBaseDodagRelayTestCase();

  private:
    void DoRun() override;
};

RplNonBaseDodagRelayTestCase::RplNonBaseDodagRelayTestCase()
    : TestCase("A non-base DODAG's DAO is relayed through intermediate nodes")
{
}

void
RplNonBaseDodagRelayTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(4); // 0 = root, 1 = relay1, 2 = relay2, 3 = leaf, a line

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    // Only adjacent nodes hear each other, RplDodagFormationTestCase's own
    // line-topology recipe for 3 nodes, extended to 4.
    auto blacklist = [&](uint32_t a, uint32_t b) {
        Ptr<SimpleNetDevice> devA = DynamicCast<SimpleNetDevice>(devices.Get(a));
        Ptr<SimpleNetDevice> devB = DynamicCast<SimpleNetDevice>(devices.Get(b));
        channel->BlackList(devA, devB);
        channel->BlackList(devB, devA);
    };
    blacklist(0, 2);
    blacklist(0, 3);
    blacklist(1, 3);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    // The base DODAG across all three hops first: RplDodagFormationTestCase's
    // own budget for two hops, with margin for the extra one here.
    Simulator::Stop(Seconds(250));
    Simulator::Run();

    Ptr<RplRoutingProtocol> root = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay1 = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay2 = nodes.Get(2)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> leaf = nodes.Get(3)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(leaf->IsJoined(), true, "The base DODAG did not reach the far end");

    static constexpr uint8_t LOCAL_INSTANCE = 0x80; // high bit set, RFC 6550 section 5.1
    RplRoutingProtocol::DodagKey localKey =
        root->CreateLocalDodag(LOCAL_INSTANCE, RPL_MOP_NON_STORING);
    NS_TEST_ASSERT_MSG_NE(localKey.dodagId, Ipv6Address::GetAny(), "The local DODAG did not form");

    // The local DODAG's own DIO needs the same multi-hop cascade to reach
    // leaf3, and leaf3's own DAO for it the same distance back.
    Simulator::Stop(Seconds(250));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(root->GetDodagCount(), 2, "The root did not form both DODAGs");
    NS_TEST_ASSERT_MSG_EQ(relay1->IsJoinedTo(LOCAL_INSTANCE, localKey.dodagId),
                          true,
                          "relay1 did not join the local DODAG");
    NS_TEST_ASSERT_MSG_EQ(relay2->IsJoinedTo(LOCAL_INSTANCE, localKey.dodagId),
                          true,
                          "relay2 did not join the local DODAG");
    NS_TEST_ASSERT_MSG_EQ(leaf->IsJoinedTo(LOCAL_INSTANCE, localKey.dodagId),
                          true,
                          "leaf3 did not join the local DODAG");

    std::vector<Ipv6Address> hops;
    NS_TEST_ASSERT_MSG_EQ(root->ComputeSourceRoute(LOCAL_INSTANCE,
                                                    localKey.dodagId,
                                                    leaf->GetGlobalAddress(),
                                                    hops),
                          true,
                          "leaf3's DAO for the local DODAG was not relayed back to the root");
    NS_TEST_ASSERT_MSG_EQ(hops.size(), 3u, "Wrong hop count for the local DODAG's path to leaf3");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A CreateLocalDodag()-formed root can receive and act on a DAO for
 *        its own DODAG even though it never called SetAsRoot() (m_isRoot
 *        stays false).
 *
 * The regression test for HandleDao()'s own generalisation. Before that was
 * fixed, HandleDao() refused every DAO outright unless m_isRoot was true --
 * exactly the case an AODV-RPL (RFC 9854) OrigNode is in: root of its own
 * RREQ-Instance while remaining an ordinary member of the base DODAG, never
 * the base's own root.
 *
 * A 3-node line: R roots the base DODAG; A is an ordinary base member that
 * additionally CreateLocalDodag()s (A->IsRoot() stays false, the base
 * root's own node-wide flag it never sets); B, A's neighbour, joins A's
 * local DODAG. The only thing this test needs to prove is that A actually
 * processed B's DAO.
 */
class RplLocalDodagRootWithoutSetAsRootTestCase : public TestCase
{
  public:
    RplLocalDodagRootWithoutSetAsRootTestCase();

  private:
    void DoRun() override;
};

RplLocalDodagRootWithoutSetAsRootTestCase::RplLocalDodagRootWithoutSetAsRootTestCase()
    : TestCase("A CreateLocalDodag() root without SetAsRoot() still accepts a DAO")
{
}

void
RplLocalDodagRootWithoutSetAsRootTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(3); // 0 = R (base root), 1 = A (base member, local root), 2 = B

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    Ptr<SimpleNetDevice> first = DynamicCast<SimpleNetDevice>(devices.Get(0));
    Ptr<SimpleNetDevice> last = DynamicCast<SimpleNetDevice>(devices.Get(2));
    channel->BlackList(first, last);
    channel->BlackList(last, first);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(200));
    Simulator::Run();

    Ptr<RplRoutingProtocol> a = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> b = nodes.Get(2)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(b->IsJoined(), true, "The base DODAG did not reach B");

    static constexpr uint8_t LOCAL_INSTANCE = 0x80;
    RplRoutingProtocol::DodagKey localKey = a->CreateLocalDodag(LOCAL_INSTANCE, RPL_MOP_NON_STORING);
    NS_TEST_ASSERT_MSG_NE(localKey.dodagId, Ipv6Address::GetAny(), "A's local DODAG did not form");
    NS_TEST_ASSERT_MSG_EQ(a->IsRoot(),
                          false,
                          "A is the base root; this test needs it not to be, to prove HandleDao() "
                          "does not need m_isRoot");

    Simulator::Stop(Seconds(200));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(b->IsJoinedTo(LOCAL_INSTANCE, localKey.dodagId),
                          true,
                          "B did not join A's local DODAG");

    std::vector<Ipv6Address> hops;
    NS_TEST_ASSERT_MSG_EQ(
        a->ComputeSourceRoute(LOCAL_INSTANCE, localKey.dodagId, b->GetGlobalAddress(), hops),
        true,
        "A did not accept B's DAO for A's own local DODAG: HandleDao() still needs m_isRoot");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Rank-inconsistency checking (RFC 6550 section 11.2) is scoped per
 *        RPLInstanceID, not always the base DODAG.
 *
 * The regression test for RplIpv6OptionRpl::Process()'s own generalisation
 * (GetRankForInstance()/NotifyRankInconsistency(instanceId), driven by the
 * RPI's own RPLInstanceID): before that was fixed, every rank check and
 * every SenderRank rewrite used GetRank() (the base DODAG's own rank)
 * regardless of which DODAG the packet actually named.
 *
 * One node roots the base DODAG (a fixed, known rank) and separately joins
 * a second, fabricated DODAG under a Local RPLInstanceID (high bit set,
 * RFC 6550 section 5.1) as an ordinary member, at a rank deliberately
 * different from the base's own -- what actually lets this test tell
 * "checked against the right membership" apart from "checked against
 * whichever one happened to agree anyway". The same SenderRank is then fed
 * through option->Process() twice, once under each RPLInstanceID: it must
 * come out consistent against one and inconsistent against the other.
 */
class RplRankInconsistencyPerInstanceTestCase : public TestCase
{
  public:
    RplRankInconsistencyPerInstanceTestCase();

  private:
    void DoRun() override;
};

RplRankInconsistencyPerInstanceTestCase::RplRankInconsistencyPerInstanceTestCase()
    : TestCase("Rank-inconsistency checking is scoped per RPLInstanceID, not always the base")
{
}

void
RplRankInconsistencyPerInstanceTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(1);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    ipv6.AssignWithoutAddress(devices);

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);

    Simulator::Stop(Seconds(2));
    Simulator::Run();

    Ptr<Node> node = nodes.Get(0);
    Ptr<RplRoutingProtocol> rpl = node->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(rpl->GetRank(), RPL_MIN_HOPRANKINC, "The base root is not at a fixed rank");

    Ipv6Address nodeLinkLocal = node->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    // A fabricated DODAG under a Local RPLInstanceID, joined as an ordinary
    // member -- rank ends up as the peer's own advertised rank (200) plus
    // one hop increment, RplVersionWrapTestCase's own established
    // convention for this DIO field.
    static constexpr uint8_t LOCAL_INSTANCE = 0x80;
    Ipv6Address localDodagId("2001:9::1");
    Ipv6Address peerLinkLocal("fe80::9");
    RplDioHeader dio;
    dio.SetInstanceId(LOCAL_INSTANCE);
    dio.SetVersionNumber(0);
    dio.SetRank(200);
    dio.SetMop(RPL_MOP_NON_STORING);
    dio.SetDodagId(localDodagId);
    dio.SetDtsn(0);
    dio.SetDagConfiguration(0,
                            20,
                            RPL_DIO_REDUNDANCY,
                            RPL_MAX_RANKINC,
                            RPL_MIN_HOPRANKINC,
                            RPL_OCP_OF0,
                            RPL_DEFAULT_LIFETIME,
                            RPL_DEFAULT_LIFETIME_UNIT);
    DeliverRawRplMessage<RplDioHeader>(node,
                                       1,
                                       dio,
                                       static_cast<uint8_t>(RPL_CODE_DIO),
                                       peerLinkLocal,
                                       nodeLinkLocal);

    NS_TEST_ASSERT_MSG_EQ(rpl->IsJoinedTo(LOCAL_INSTANCE, localDodagId),
                          true,
                          "Did not join the fabricated local-instance DODAG");
    uint16_t localRank = rpl->GetRankIn(LOCAL_INSTANCE, localDodagId);
    NS_TEST_ASSERT_MSG_NE(static_cast<uint32_t>(localRank),
                          static_cast<uint32_t>(RPL_MIN_HOPRANKINC),
                          "The local-instance rank coincides with the base's; cannot discriminate "
                          "between them below");

    Ptr<Ipv6OptionDemux> demux = node->GetObject<Ipv6OptionDemux>();
    Ptr<Ipv6Option> option = demux->GetOption(RPL_HBH_OPTION_TYPE);
    Ipv6Header ipv6Header;
    ipv6Header.SetSource(Ipv6Address("fe80::99"));
    ipv6Header.SetDestination(nodeLinkLocal);
    ipv6Header.SetHopLimit(64);

    // Consistent against the base (200 > 128, moving up): checked against
    // the base's own rank when the RPI names the Global RPLInstanceID.
    {
        RplPacketInfoHeader rpi;
        rpi.SetInstanceId(RPL_DEFAULT_INSTANCE);
        rpi.SetDown(false);
        rpi.SetSenderRank(200);

        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(rpi);
        bool isDropped = false;
        option->Process(packet, 0, ipv6Header, isDropped);
        NS_TEST_ASSERT_MSG_EQ(isDropped,
                              false,
                              "A packet consistent against the base's own rank was dropped");

        RplPacketInfoHeader received;
        packet->RemoveHeader(received);
        NS_TEST_ASSERT_MSG_EQ(received.GetRankError(),
                              false,
                              "Flagged inconsistent against the base when it should not have been");
        NS_TEST_ASSERT_MSG_EQ(received.GetSenderRank(),
                              RPL_MIN_HOPRANKINC,
                              "SenderRank was not rewritten to the base's own rank");
    }

    // The identical SenderRank, but under the local instance's own key:
    // inconsistent there (200 is not greater than localRank), and rewritten
    // to the local membership's own rank, not the base's.
    {
        RplPacketInfoHeader rpi;
        rpi.SetInstanceId(LOCAL_INSTANCE);
        rpi.SetDown(false);
        rpi.SetSenderRank(200);

        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(rpi);
        bool isDropped = false;
        option->Process(packet, 0, ipv6Header, isDropped);
        NS_TEST_ASSERT_MSG_EQ(isDropped,
                              false,
                              "The first inconsistency was already treated as confirmed");

        RplPacketInfoHeader received;
        packet->RemoveHeader(received);
        NS_TEST_ASSERT_MSG_EQ(received.GetRankError(),
                              true,
                              "Not flagged inconsistent against the local instance's own rank: the "
                              "base's rank was used instead");
        NS_TEST_ASSERT_MSG_EQ(received.GetSenderRank(),
                              localRank,
                              "SenderRank was rewritten to the base's rank, not the local "
                              "membership's own");
    }

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief RouteOutput()/PrepareOutgoingPacket() compute and stamp a correct
 *        downward path through a CreateLocalDodag()-formed root, not only
 *        the base one.
 *
 * The regression test for FindRootDodagFor()'s own generalisation and for
 * PrepareOutgoingPacket()'s originDodag resolution (the RPL Option this
 * same outgoing packet gets stamped with): before that was fixed, both were
 * hardcoded to the base DODAG's own topology and rank/instanceId, so a
 * CreateLocalDodag()-formed root's own downward traffic either found no
 * route at all or carried the base's identity on the wire instead of its
 * own.
 *
 * One node roots both the base DODAG and, once that has settled, a local
 * one. A two-level topology is hand-built directly into the local
 * membership (fabricated DAOs, RplMultiDodagPathSequenceIsolationTestCase's
 * own recipe: HandleDao() only ever reads the DAO's own fields, so no real
 * second node is needed), deliberately naming addresses that never appear
 * in the base DODAG's own topology at all -- both DODAGs are rooted at this
 * same node's one global address, so reusing a real base member's address
 * here would leave RouteOutput()'s base-first attempt silently satisfying
 * the request and prove nothing about the local DODAG's own path.
 */
class RplNonBaseRootDownwardPacketTestCase : public TestCase
{
  public:
    RplNonBaseRootDownwardPacketTestCase();

  private:
    void DoRun() override;
};

RplNonBaseRootDownwardPacketTestCase::RplNonBaseRootDownwardPacketTestCase()
    : TestCase("A CreateLocalDodag() root computes and stamps its own downward path")
{
}

void
RplNonBaseRootDownwardPacketTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(1);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    ipv6.AssignWithoutAddress(devices);

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);

    Simulator::Stop(Seconds(2));
    Simulator::Run();

    Ptr<Node> node = nodes.Get(0);
    Ptr<RplRoutingProtocol> root = node->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(root->IsJoined(), true, "The base DODAG never formed");

    static constexpr uint8_t LOCAL_INSTANCE = 0x80;
    RplRoutingProtocol::DodagKey localKey =
        root->CreateLocalDodag(LOCAL_INSTANCE, RPL_MOP_NON_STORING);
    NS_TEST_ASSERT_MSG_NE(localKey.dodagId, Ipv6Address::GetAny(), "The local DODAG did not form");

    Ipv6Address child("2001:9::ff:fe00:aa");      // a direct child of the local root
    Ipv6Address grandchild("2001:9::ff:fe00:bb"); // one hop further out than child

    auto deliverDao = [&](Ipv6Address target, Ipv6Address parent) {
        RplDaoHeader dao;
        dao.SetInstanceId(LOCAL_INSTANCE);
        dao.SetDodagId(localKey.dodagId);
        dao.SetSequence(1);
        dao.SetTarget(target);
        dao.SetTransitInformation(parent, 1, RPL_DEFAULT_LIFETIME);
        Simulator::Schedule(Seconds(0),
                            &DeliverRawRplMessage<RplDaoHeader>,
                            node,
                            1,
                            dao,
                            static_cast<uint8_t>(RPL_CODE_DAO),
                            target,
                            localKey.dodagId);
        Simulator::Stop(MilliSeconds(10));
        Simulator::Run();
    };
    deliverDao(child, localKey.dodagId);
    deliverDao(grandchild, child);

    std::vector<Ipv6Address> hops;
    NS_TEST_ASSERT_MSG_EQ(
        root->ComputeSourceRoute(LOCAL_INSTANCE, localKey.dodagId, grandchild, hops),
        true,
        "The fabricated local-DODAG topology was not recorded");
    NS_TEST_ASSERT_MSG_EQ(hops.size(), 2u, "Wrong hop count for the fabricated 2-level topology");

    // Nothing of this exists in the base DODAG's own (empty) topology: a
    // route found here can only have come from the local membership.
    Ipv6Header header;
    header.SetDestination(grandchild);
    Socket::SocketErrno sockerr;
    Ptr<Ipv6Route> route = root->RouteOutput(Create<Packet>(), header, nullptr, sockerr);
    NS_TEST_ASSERT_MSG_EQ(route != nullptr,
                          true,
                          "RouteOutput() found no path through the local DODAG's own root");

    Ptr<Packet> packet = Create<Packet>();
    root->PrepareOutgoingPacket(packet, header, route);

    // ReadRpiInstanceId() reading back exactly what PrepareOutgoingPacket()
    // just wrote is itself the proof that PrepareOutgoingPacket() resolved
    // this outgoing packet's own RPL Option against the local membership
    // (originDodag), not the base's: an untouched Ipv6Header passed to
    // RouteOutput() above, so header.GetNextHeader() here is still whatever
    // it was before this call, checked instead through the RPI itself.
    Ipv6Header afterPrepare;
    afterPrepare.SetNextHeader(header.GetNextHeader());
    uint8_t instanceId = 0;
    NS_TEST_ASSERT_MSG_EQ(root->ReadRpiInstanceId(packet, afterPrepare, instanceId),
                          true,
                          "No RPL Option was attached to the outgoing packet");
    NS_TEST_ASSERT_MSG_EQ(static_cast<uint32_t>(instanceId),
                          static_cast<uint32_t>(LOCAL_INSTANCE),
                          "The RPL Option named the base DODAG's RPLInstanceID, not the local "
                          "membership's own");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief ReadRpiInstanceId() refuses to read a Hop-by-Hop option that is not
 *        actually the RPL Option (RFC 6553), rather than misreading whatever
 *        bytes happen to be there as one.
 *
 * Found while building this fix's own test matrix, not requested by any
 * prior bug report: RplPacketInfoHeader::Deserialize() reads and stores
 * whatever Option Type byte is on the wire (Ipv6OptionHeader::SetType())
 * without ever checking it is really RPL_HBH_OPTION_TYPE (0x63) -- safe for
 * the ordinary Ipv6OptionDemux-driven dispatch path, which only ever calls
 * RplIpv6OptionRpl::Process() once the demux itself has already matched that
 * type, but ReadRpiInstanceId() reads directly at a fixed offset with no
 * such dispatch in front of it. A Pad1/PadN option (RFC 8200 section 4.2,
 * needed whenever the real first option does not already land on the RPL
 * Option's own alignment) sitting first in the Hop-by-Hop header would have
 * its Length/padding bytes misread as Flags/RPLInstanceID/SenderRank,
 * handing whatever those padding bytes happen to be straight into
 * RouteInput()'s forwarding decision as if it were a trustworthy
 * RPLInstanceID.
 *
 * A probe (scratch/rpl-rpi-typecheck-probe.cc, deleted once this was
 * confirmed and fixed) reproduced this directly: a PadN option, Opt Data
 * Len 4, whose four padding bytes were chosen so the byte at the position
 * SenderRank... no, InstanceId would land on read back as 0x55 --
 * ReadRpiInstanceId() returned true with instanceId 0x55, a value that
 * appeared nowhere in any real RPL Option at all.
 */
class RplReadRpiInstanceIdRejectsWrongOptionTypeTestCase : public TestCase
{
  public:
    RplReadRpiInstanceIdRejectsWrongOptionTypeTestCase();

  private:
    void DoRun() override;
};

RplReadRpiInstanceIdRejectsWrongOptionTypeTestCase::
    RplReadRpiInstanceIdRejectsWrongOptionTypeTestCase()
    : TestCase("ReadRpiInstanceId() does not misread a non-RPL Hop-by-Hop option as one")
{
}

void
RplReadRpiInstanceIdRejectsWrongOptionTypeTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(1);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    ipv6.AssignWithoutAddress(devices);

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    Simulator::Stop(Seconds(2));
    Simulator::Run();

    Ptr<RplRoutingProtocol> rpl = nodes.Get(0)->GetObject<RplRoutingProtocol>();

    // A fabricated Hop-by-Hop payload: the mandatory 2-octet Next Header/Hdr
    // Ext Len prefix, then a PadN option (Option Type 0x01, Opt Data Len 4)
    // whose four padding octets are deliberately non-zero. Read as if it
    // were an RPI (2 bytes skipped, then Type/Length/Flags/InstanceId/
    // SenderRank), byte 5 here (0x55) would land exactly on InstanceId.
    uint8_t bytes[] = {
        59,   // HBH Next Header: No Next Header
        0,    // HBH Hdr Ext Len
        0x01, // PadN Option Type -- not RPL_HBH_OPTION_TYPE (0x63)
        0x04, // PadN Opt Data Len: 4 bytes of padding follow
        0x00, // padding: would read as RPI Flags if misread
        0x55, // padding: would read as RPI InstanceId if misread
        0x00,
        0x00, // padding: would read as RPI SenderRank if misread
    };
    Ptr<Packet> packet = Create<Packet>(bytes, sizeof(bytes));

    Ipv6Header header;
    header.SetNextHeader(Ipv6Header::IPV6_EXT_HOP_BY_HOP);

    uint8_t instanceId = 0xAB; // a value neither 0 nor 0x55, so either bug leaves a trace
    bool ok = rpl->ReadRpiInstanceId(packet, header, instanceId);

    NS_TEST_ASSERT_MSG_EQ(ok,
                          false,
                          "A PadN option was accepted as if it were the RPL Option");
    NS_TEST_ASSERT_MSG_EQ(static_cast<uint32_t>(instanceId),
                          0xABu,
                          "instanceId was written even though ReadRpiInstanceId() reported "
                          "failure");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check MRHOF (RFC 6719) parent selection: path cost, not just hop
 *        count, decides the preferred parent, and hysteresis
 *        (PARENT_SWITCH_THRESHOLD) keeps it from flapping over a marginal
 *        improvement.
 *
 * One node ("leaf") is driven purely by hand-built DIOs sourced from two
 * other real nodes ("peerA"/"peerB"), which need nothing more than a real
 * link-local address of their own: nothing here depends on either of them
 * running RPL themselves. None of the three is the DODAG root, so the very
 * first DIO leaf ever sees is what bootstraps it into the DODAG, adopting
 * MRHOF from that DIO's DODAG Configuration option exactly as any node deep
 * in a real DODAG would. The test binary links neither lr-wpan nor its
 * LrWpanLqiTag, so the link ETX to both peers is always the neutral default
 * (RPL_ETX_FIXED_POINT): every difference in path cost between them comes
 * from the path ETX each one advertises in its DAG Metric Container, which
 * is exactly what this test controls.
 */
class RplMrhofSelectionTestCase : public TestCase
{
  public:
    RplMrhofSelectionTestCase();

  private:
    void DoRun() override;
};

RplMrhofSelectionTestCase::RplMrhofSelectionTestCase()
    : TestCase("MRHOF path cost selection and hysteresis")
{
}

void
RplMrhofSelectionTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(3); // 0 = leaf under test, 1 = peerA, 2 = peerB

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.AssignStreams(nodes, 1);

    Ptr<RplRoutingProtocol> leaf = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ipv6Address dodagId("2001:1::1");
    Ipv6Address leafLinkLocal =
        nodes.Get(0)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address peerALinkLocal =
        nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address peerBLinkLocal =
        nodes.Get(2)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    auto buildDio = [&dodagId](uint16_t pathEtx) {
        RplDioHeader dio;
        dio.SetInstanceId(RPL_DEFAULT_INSTANCE);
        dio.SetVersionNumber(1);
        dio.SetRank(RPL_MIN_HOPRANKINC);
        dio.SetMop(RPL_MOP_NON_STORING);
        dio.SetDodagId(dodagId);
        dio.SetDagConfiguration(RPL_DIO_INTERVAL_DOUBLINGS,
                                RPL_DIO_INTERVAL_MIN,
                                RPL_DIO_REDUNDANCY,
                                RPL_MAX_RANKINC,
                                RPL_MIN_HOPRANKINC,
                                RPL_OCP_MRHOF,
                                RPL_DEFAULT_LIFETIME,
                                RPL_DEFAULT_LIFETIME_UNIT);
        dio.SetMetricContainer(pathEtx);
        return dio;
    };

    // peerA advertises a path ETX of 300: path cost 300 + 128 (neutral link
    // ETX) = 428. Being the first DIO leaf ever sees, it also bootstraps the
    // join and MRHOF adoption.
    RplDioHeader dioA = buildDio(300);
    Simulator::Schedule(Seconds(0),
                       &SendRawRplMessage<RplDioHeader>,
                       nodes.Get(1),
                       1,
                       dioA,
                       static_cast<uint8_t>(RPL_CODE_DIO),
                       peerALinkLocal,
                       leafLinkLocal);
    Simulator::Stop(MilliSeconds(10));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(leaf->IsJoined(), true, "The DIO did not bootstrap a DODAG");
    NS_TEST_ASSERT_MSG_EQ(leaf->GetPreferredParent(),
                          peerALinkLocal,
                          "peerA should be preferred, being the only parent so far");
    NS_TEST_ASSERT_MSG_EQ(leaf->GetPathEtx(), 428, "Wrong path cost via peerA");
    NS_TEST_ASSERT_MSG_EQ(leaf->GetRank(), 428, "Wrong MRHOF rank via peerA");

    // peerB advertises a path ETX of 250: path cost 378, only 50 better than
    // peerA's 428. RFC 6719's hysteresis (PARENT_SWITCH_THRESHOLD = 192)
    // keeps peerA preferred rather than flapping over a marginal improvement.
    RplDioHeader dioB1 = buildDio(250);
    Simulator::Schedule(Seconds(0),
                       &SendRawRplMessage<RplDioHeader>,
                       nodes.Get(2),
                       1,
                       dioB1,
                       static_cast<uint8_t>(RPL_CODE_DIO),
                       peerBLinkLocal,
                       leafLinkLocal);
    Simulator::Stop(MilliSeconds(10));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(leaf->GetPreferredParent(),
                          peerALinkLocal,
                          "A marginal improvement should not switch the preferred parent");
    NS_TEST_ASSERT_MSG_EQ(leaf->GetPathEtx(), 428, "The path cost should still be through peerA");

    // peerB improves further, to a path ETX of 0: path cost 128, well beyond
    // the hysteresis threshold below peerA's 428. Now it takes over.
    RplDioHeader dioB2 = buildDio(0);
    Simulator::Schedule(Seconds(0),
                       &SendRawRplMessage<RplDioHeader>,
                       nodes.Get(2),
                       1,
                       dioB2,
                       static_cast<uint8_t>(RPL_CODE_DIO),
                       peerBLinkLocal,
                       leafLinkLocal);
    Simulator::Stop(MilliSeconds(10));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(leaf->GetPreferredParent(),
                          peerBLinkLocal,
                          "A large enough improvement should switch the preferred parent");
    NS_TEST_ASSERT_MSG_EQ(leaf->GetPathEtx(), 128, "Wrong path cost via peerB");
    NS_TEST_ASSERT_MSG_EQ(leaf->GetRank(), 256, "Wrong MRHOF rank via peerB");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check the exact boundary of MRHOF's hysteresis, RFC 6719 section
 *        3.2.2 rule 3.
 *
 * The rule, verbatim: "If the smallest path cost for paths through the
 * candidate neighbors is smaller than cur_min_path_cost by less than
 * PARENT_SWITCH_THRESHOLD, the node MAY continue to use the current
 * preferred parent." A difference one below the threshold keeps the current
 * parent; a difference of exactly the threshold does not -- "less than" is
 * strict -- and the MUST rule the paragraph opens with ("select the
 * candidate neighbor with the lowest path cost") applies instead.
 *
 * Driven the same way RplMrhofSelectionTestCase is, through the advertised
 * path ETX alone, so this does not need the link-layer LQI tag the
 * MAX_LINK_METRIC boundary test below does.
 */
class RplMrhofHysteresisBoundaryTestCase : public TestCase
{
  public:
    RplMrhofHysteresisBoundaryTestCase();

  private:
    void DoRun() override;
};

RplMrhofHysteresisBoundaryTestCase::RplMrhofHysteresisBoundaryTestCase()
    : TestCase("MRHOF hysteresis boundary: a difference of exactly PARENT_SWITCH_THRESHOLD")
{
}

void
RplMrhofHysteresisBoundaryTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(3); // 0 = leaf under test, 1 = peerA (current parent), 2 = peerB (the rival)

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.AssignStreams(nodes, 1);

    Ptr<RplRoutingProtocol> leaf = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ipv6Address dodagId("2001:1::1");
    Ipv6Address leafLinkLocal =
        nodes.Get(0)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address peerALinkLocal =
        nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address peerBLinkLocal =
        nodes.Get(2)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    auto buildDio = [&dodagId](uint16_t pathEtx) {
        RplDioHeader dio;
        dio.SetInstanceId(RPL_DEFAULT_INSTANCE);
        dio.SetVersionNumber(1);
        dio.SetRank(RPL_MIN_HOPRANKINC);
        dio.SetMop(RPL_MOP_NON_STORING);
        dio.SetDodagId(dodagId);
        dio.SetDagConfiguration(RPL_DIO_INTERVAL_DOUBLINGS,
                                RPL_DIO_INTERVAL_MIN,
                                RPL_DIO_REDUNDANCY,
                                RPL_MAX_RANKINC,
                                RPL_MIN_HOPRANKINC,
                                RPL_OCP_MRHOF,
                                RPL_DEFAULT_LIFETIME,
                                RPL_DEFAULT_LIFETIME_UNIT);
        dio.SetMetricContainer(pathEtx);
        return dio;
    };

    auto send = [&](Ptr<Node> from, Ipv6Address fromAddress, const RplDioHeader& dio) {
        Simulator::Schedule(Seconds(0),
                            &SendRawRplMessage<RplDioHeader>,
                            from,
                            1,
                            dio,
                            static_cast<uint8_t>(RPL_CODE_DIO),
                            fromAddress,
                            leafLinkLocal);
        Simulator::Stop(MilliSeconds(10));
        Simulator::Run();
    };

    // peerA advertises a path ETX of 300, both link ETXes staying at the
    // neutral default of 128 (no LQI tag on either DIO): path cost via
    // peerA is 428, and being the only DIO leaf has heard, peerA becomes the
    // preferred parent outright.
    send(nodes.Get(1), peerALinkLocal, buildDio(300));
    NS_TEST_ASSERT_MSG_EQ(leaf->GetPreferredParent(),
                          peerALinkLocal,
                          "peerA should be preferred, being the only parent so far");
    NS_TEST_ASSERT_MSG_EQ(leaf->GetPathEtx(), 428, "Wrong path cost via peerA");

    // peerB one short of the threshold: path cost 237, 191 below peerA's
    // 428. 191 < PARENT_SWITCH_THRESHOLD (192), so hysteresis keeps peerA.
    send(nodes.Get(2), peerBLinkLocal, buildDio(109));
    NS_TEST_ASSERT_MSG_EQ(leaf->GetPreferredParent(),
                          peerALinkLocal,
                          "A difference one short of PARENT_SWITCH_THRESHOLD switched anyway");
    NS_TEST_ASSERT_MSG_EQ(leaf->GetPathEtx(), 428, "The path cost should still be through peerA");

    // peerB improves by exactly one more: path cost 236, exactly
    // PARENT_SWITCH_THRESHOLD (192) below peerA's 428. Not "less than" the
    // threshold, so hysteresis no longer applies and the MUST rule (lowest
    // path cost wins) takes over.
    send(nodes.Get(2), peerBLinkLocal, buildDio(108));
    NS_TEST_ASSERT_MSG_EQ(leaf->GetPreferredParent(),
                          peerBLinkLocal,
                          "A difference of exactly PARENT_SWITCH_THRESHOLD did not switch, so "
                          "hysteresis was applied one unit past where the RFC's \"less than\" "
                          "stops");
    NS_TEST_ASSERT_MSG_EQ(leaf->GetPathEtx(), 236, "Wrong path cost via peerB");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check the exact boundary of MRHOF's link exclusion rule, RFC 6719
 *        section 5.
 *
 * The rule, verbatim: "If the selected metric for a link is greater than
 * MAX_LINK_METRIC, the node SHOULD exclude that link from consideration
 * during parent selection." MAX_LINK_METRIC is defined, in the same
 * section, as "Maximum allowed value for the selected link metric" -- the
 * worst value a link may still have and be considered, not the first value
 * excluded.
 *
 * The only way this implementation ever sets a link ETX away from the
 * neutral default is LinkEtxFromPacket() reading the real lr-wpan LQI tag
 * off the received packet (@see rpl-routing-protocol.cc). This does not
 * link librpl against lr-wpan -- the tag is matched purely by its globally
 * registered TypeId name, the same trick LinkEtxFromPacket() itself uses to
 * decode it -- but does rely on lr-wpan being linked into whatever binary
 * runs this test suite so that TypeId is actually registered, true of the
 * monolithic test-runner this suite is normally run from.
 */
class RplMrhofLinkMetricBoundaryTestCase : public TestCase
{
  public:
    RplMrhofLinkMetricBoundaryTestCase();

  private:
    void DoRun() override;
};

RplMrhofLinkMetricBoundaryTestCase::RplMrhofLinkMetricBoundaryTestCase()
    : TestCase("MRHOF link metric boundary: a link at exactly MAX_LINK_METRIC")
{
}

namespace
{

/// Writes an arbitrary tag's single-byte wire format under an arbitrary
/// TypeId, the same encode-by-name trick RplRoutingProtocol's own
/// LrWpanPeekByteTag uses to decode -- see that class's doc comment in
/// rpl-routing-protocol.cc for why PacketTagIterator::Item::GetTag() only
/// checking GetInstanceTypeId() makes this safe without #include-ing, or
/// linking against, the lr-wpan module from this test.
class TestLqiByteTag : public Tag
{
  public:
    /**
     * @param tid the real tag's TypeId, looked up by name
     * @param value the byte to encode
     */
    TestLqiByteTag(TypeId tid, uint8_t value)
        : m_tid(tid),
          m_byte(value)
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

  private:
    TypeId m_tid;     //!< the real tag's TypeId
    uint8_t m_byte;   //!< the byte to encode
};

} // namespace

void
RplMrhofLinkMetricBoundaryTestCase::DoRun()
{
    TypeId lqiTid;
    bool haveLqiTag = TypeId::LookupByNameFailSafe("ns3::lrwpan::LrWpanLqiTag", &lqiTid);
    NS_TEST_ASSERT_MSG_EQ(haveLqiTag,
                          true,
                          "ns3::lrwpan::LrWpanLqiTag is not registered in this test binary "
                          "(lr-wpan not linked in), so the link ETX boundary this test targets "
                          "cannot be produced");

    NodeContainer nodes;
    nodes.Create(2); // 0 = leaf under test, 1 = the one neighbour

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.AssignStreams(nodes, 1);

    Ptr<RplRoutingProtocol> leaf = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ipv6Address dodagId("2001:1::1");
    Ipv6Address leafLinkLocal =
        nodes.Get(0)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address peerLinkLocal =
        nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    RplDioHeader dio;
    dio.SetInstanceId(RPL_DEFAULT_INSTANCE);
    dio.SetVersionNumber(1);
    dio.SetRank(RPL_MIN_HOPRANKINC);
    dio.SetMop(RPL_MOP_NON_STORING);
    dio.SetDodagId(dodagId);
    dio.SetDagConfiguration(RPL_DIO_INTERVAL_DOUBLINGS,
                            RPL_DIO_INTERVAL_MIN,
                            RPL_DIO_REDUNDANCY,
                            RPL_MAX_RANKINC,
                            RPL_MIN_HOPRANKINC,
                            RPL_OCP_MRHOF,
                            RPL_DEFAULT_LIFETIME,
                            RPL_DEFAULT_LIFETIME_UNIT);
    dio.SetMetricContainer(0); // the peer is the root: path ETX 0

    // Built by hand rather than through SendRawRplMessage(), so a packet tag
    // can be attached before anything is sent. LQI 0 is LinkEtxFromPacket()'s
    // own special case for "no successful reception at all", which it clips
    // to RPL_MRHOF_MAX_LINK_METRIC directly rather than computing 255/LQI --
    // exactly the boundary value this test needs, reached without having to
    // reverse the fixed-point conversion to land on it.
    Ptr<Packet> packet = Create<Packet>();
    packet->AddPacketTag(TestLqiByteTag(lqiTid, 0));
    packet->AddHeader(dio);

    Icmpv6Header icmpv6Header;
    icmpv6Header.SetType(ICMPV6_RPL);
    icmpv6Header.SetCode(static_cast<uint8_t>(RPL_CODE_DIO));
    icmpv6Header.CalculatePseudoHeaderChecksum(peerLinkLocal,
                                               leafLinkLocal,
                                               packet->GetSize() + icmpv6Header.GetSerializedSize(),
                                               Icmpv6L4Protocol::GetStaticProtocolNumber());
    packet->AddHeader(icmpv6Header);

    Ptr<Socket> socket = Socket::CreateSocket(nodes.Get(1), Ipv6RawSocketFactory::GetTypeId());
    socket->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    socket->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    socket->BindToNetDevice(nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetNetDevice(1));

    SocketIpv6HopLimitTag hopLimitTag;
    hopLimitTag.SetHopLimit(255);
    packet->AddPacketTag(hopLimitTag);

    Simulator::Schedule(Seconds(0),
                       [socket, packet, leafLinkLocal]() {
                           socket->SendTo(packet, 0, Inet6SocketAddress(leafLinkLocal, 0));
                       });
    Simulator::Stop(MilliSeconds(10));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(leaf->IsJoined(),
                          true,
                          "A link at exactly MAX_LINK_METRIC was excluded outright, so the only "
                          "neighbour ever heard never bootstrapped a DODAG");
    NS_TEST_ASSERT_MSG_EQ(leaf->GetPreferredParent(),
                          peerLinkLocal,
                          "The only neighbour there was did not become the preferred parent");
    NS_TEST_ASSERT_MSG_EQ(leaf->GetPathEtx(),
                          RPL_MRHOF_MAX_LINK_METRIC,
                          "Wrong path cost through a link exactly at MAX_LINK_METRIC");

    socket->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A DIO advertising the P2P Route Discovery mode of operation (MOP 4,
 *        AODV-RPL) is joined, but the membership it forms takes no part in
 *        core RPL's own DAO and DIS machinery.
 *
 * MOP 4 was refused outright until AODV-RPL (RFC 9854) work began. Letting
 * it in means a membership now exists that looks ordinary to every piece of
 * core RPL it flows past but must not behave like one:
 *
 * - it sends no DAO, because "AODV-RPL does not utilize the Destination
 *   Advertisement Object (DAO) control message of RPL" (RFC 9854 section 1).
 *   SendDao()'s pre-existing guard is not enough on its own -- an
 *   intermediate router in an RREQ-Instance is neither the root nor without
 *   a preferred parent, which is exactly the shape that guard lets through;
 * - it never answers a DIS, since a route-discovery instance is scoped to
 *   the discovery that created it and pulling an uninvolved neighbour into
 *   one would be meaningless;
 * - it never becomes the base DODAG, however early it is heard. The base is
 *   what every base-scoped accessor answers for, and this one is torn down
 *   when its 'L' field expires.
 */
class RplAodvMopAcceptedTestCase : public TestCase
{
  public:
    RplAodvMopAcceptedTestCase();

  private:
    void DoRun() override;

    /**
     * @brief Count an RPL message seen at the monitor, by code and, for a
     *        DIO, by mode of operation.
     * @param socket the monitoring socket
     */
    void CountRplMessage(Ptr<Socket> socket);

    uint32_t m_dioCount{0};     //!< DIOs seen at the monitor
    uint32_t m_mop4DioCount{0}; //!< of those, ones advertising MOP 4
    uint32_t m_daoCount{0};     //!< DAOs seen at the monitor
};

RplAodvMopAcceptedTestCase::RplAodvMopAcceptedTestCase()
    : TestCase("A MOP 4 DIO is joined but stays out of core RPL's DAO and DIS machinery")
{
}

void
RplAodvMopAcceptedTestCase::CountRplMessage(Ptr<Socket> socket)
{
    Address sender;
    Ptr<Packet> packet = socket->RecvFrom(sender);
    if (!packet)
    {
        return;
    }
    Ipv6Header ipv6Header;
    packet->RemoveHeader(ipv6Header);
    Icmpv6Header icmpv6Header;
    packet->RemoveHeader(icmpv6Header);
    if (icmpv6Header.GetType() != ICMPV6_RPL)
    {
        return;
    }
    if (icmpv6Header.GetCode() == RPL_CODE_DAO)
    {
        m_daoCount++;
        return;
    }
    if (icmpv6Header.GetCode() != RPL_CODE_DIO)
    {
        return;
    }
    RplDioHeader dio;
    packet->RemoveHeader(dio);
    m_dioCount++;
    if (dio.GetMop() == RPL_MOP_P2P_ROUTE_DISCOVERY)
    {
        m_mop4DioCount++;
    }
}

void
RplAodvMopAcceptedTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2); // 0 = the node under test, 1 = a peer that need not run RPL itself

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    interfaces.SetForwarding(0, true);
    interfaces.SetForwarding(1, true);

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    // Long enough for the peer to have joined the base DODAG and SLAACed an
    // address on it: the first Trickle-paced DIO fires somewhere in
    // [Imin/2, Imin) = [2.048, 4.096) seconds, and Duplicate Address
    // Detection takes about a second after that.
    Simulator::Stop(Seconds(10));
    Simulator::Run();

    Ptr<Node> node = nodes.Get(0);
    Ptr<RplRoutingProtocol> rpl = node->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> peer = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(rpl->IsJoined(), true, "The base DODAG never formed");
    NS_TEST_ASSERT_MSG_EQ(peer->IsJoined(), true, "The peer never joined the base DODAG");
    Ipv6Address baseDodagId = rpl->GetDodagId();

    Ipv6Address nodeLinkLocal = node->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address peerLinkLocal = nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    // Watching from the peer, which is where anything the node under test
    // unicasts upward has to go: its preferred parent in the route-discovery
    // instance below is the peer, so a DAO for that instance would pass here.
    // Installed before the RREQ-DIO so nothing sent in response to it is
    // missed.
    Ptr<Socket> monitor = Socket::CreateSocket(nodes.Get(1), Ipv6RawSocketFactory::GetTypeId());
    monitor->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    monitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    monitor->BindToNetDevice(nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetNetDevice(1));
    monitor->SetRecvCallback(MakeCallback(&RplAodvMopAcceptedTestCase::CountRplMessage, this));

    // An RREQ-DIO under a Local RPLInstanceID, cast as if the peer itself
    // were the OrigNode. Its DODAGID is the peer's own address rather than a
    // fabricated one for a specific reason: a DAO for this instance would be
    // addressed to the DODAGID and routed via this node's preferred parent
    // in it, which is the peer. Addressed to any other host the peer would
    // merely forward it, and a raw socket only ever sees what is delivered
    // locally -- so the monitor below would count nothing whether or not a
    // DAO was sent, and the assertion would be vacuous.
    static constexpr uint8_t LOCAL_INSTANCE = 0x81;
    Ipv6Address origNode = peer->GetGlobalAddress();
    NS_TEST_ASSERT_MSG_NE(origNode, Ipv6Address::GetAny(), "The peer has no global address yet");
    RplDioHeader rreqDio;
    rreqDio.SetInstanceId(LOCAL_INSTANCE);
    rreqDio.SetVersionNumber(0);
    rreqDio.SetRank(RPL_MIN_HOPRANKINC);
    rreqDio.SetMop(RPL_MOP_P2P_ROUTE_DISCOVERY);
    rreqDio.SetDodagId(origNode);
    rreqDio.SetDtsn(0);
    rreqDio.SetDagConfiguration(0,
                                20,
                                RPL_DIO_REDUNDANCY,
                                RPL_MAX_RANKINC,
                                RPL_MIN_HOPRANKINC,
                                RPL_OCP_OF0,
                                RPL_DEFAULT_LIFETIME,
                                RPL_DEFAULT_LIFETIME_UNIT);
    // No Prefix Information: an AODV-RPL local instance never SLAACs
    // (@see CreateLocalDodag()).
    DeliverRawRplMessage<RplDioHeader>(node,
                                       1,
                                       rreqDio,
                                       static_cast<uint8_t>(RPL_CODE_DIO),
                                       peerLinkLocal,
                                       nodeLinkLocal);

    NS_TEST_ASSERT_MSG_EQ(rpl->IsJoinedTo(LOCAL_INSTANCE, origNode),
                          true,
                          "A MOP 4 DIO was turned away: the mode of operation gate still "
                          "refuses P2P route discovery");
    NS_TEST_ASSERT_MSG_EQ(rpl->GetDodagCount(), 2, "The MOP 4 membership was not added");

    // The base DODAG is untouched: the route-discovery instance did not take
    // its slot, and every base-scoped accessor still answers for the base.
    NS_TEST_ASSERT_MSG_EQ(rpl->GetDodagId(),
                          baseDodagId,
                          "The route-discovery instance took the base DODAG's slot");

    // Long enough for the jittered DAO a parent change would have scheduled
    // (SelectPreferredParent() uses [0, 1) seconds) and for several of its
    // DaoAckTimeout retries on top. Counted as packets on the wire rather
    // than read off daoAckPending: that flag is cleared again once DaoRetry()
    // exhausts DaoRetries and gives up, so a test that sampled it after the
    // fact would pass whether or not a DAO was ever sent.
    Simulator::Stop(Seconds(5));
    Simulator::Run();
    NS_TEST_ASSERT_MSG_EQ(m_daoCount,
                          0,
                          "A DAO was sent for the route-discovery instance, which AODV-RPL does "
                          "not use at all (RFC 9854 section 1)");

    // A unicast DIS must be answered for the base DODAG and for that one
    // only.
    RplDisHeader dis;
    Simulator::Schedule(Seconds(0),
                        &SendRawRplMessage<RplDisHeader>,
                        nodes.Get(1),
                        1,
                        dis,
                        static_cast<uint8_t>(RPL_CODE_DIS),
                        peerLinkLocal,
                        nodeLinkLocal);
    Simulator::Stop(Seconds(1));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_GT_OR_EQ(m_dioCount, 1, "The unicast DIS was never answered at all");
    NS_TEST_ASSERT_MSG_EQ(m_mop4DioCount,
                          0,
                          "A DIS was answered with the route-discovery instance's own DIO");

    monitor->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief An intermediate router's Address Vector follows its preferred
 *        parent, even when a better RREQ arrives after a worse one already
 *        joined the instance.
 *
 * Found auditing the AODV-RPL implementation with the protocol-test-matrix
 * skill, against RFC 9854 section 6.2.1's MaxUsefulRank language: a router
 * already in an RREQ-Instance re-evaluates a later RREQ against the best
 * Rank it has seen, rather than keeping only the first one it heard.
 * HandleAodvRreq() ignored every repeat unconditionally once its Address
 * Vector was non-empty, so core RPL's own SelectPreferredParent() (run
 * before HandleAodvRreq(), and entirely unaware that this membership is
 * AODV-RPL's) would switch the preferred parent to a better neighbour while
 * the Address Vector -- and so the route eventually propagated onward --
 * kept pointing at the worse one.
 *
 * One node under test, fed two hand-built RREQ-DIOs for the same
 * RREQ-Instance from two fabricated neighbours: B first, at a rank three
 * hops out, then A, at a rank one hop out. Neither is a real node -- this
 * is deliberately a unit-style test of HandleAodvRreq()/
 * SelectPreferredParent()'s interaction, not a topology -- so both are
 * addresses of convenience, RplMultiDodagVersionIsolationTestCase's own
 * pattern for exactly this reason.
 */
class RplAodvAddressVectorFollowsParentTestCase : public TestCase
{
  public:
    RplAodvAddressVectorFollowsParentTestCase();

  private:
    void DoRun() override;
};

RplAodvAddressVectorFollowsParentTestCase::RplAodvAddressVectorFollowsParentTestCase()
    : TestCase("An AODV-RPL Address Vector follows a switch to a better preferred parent")
{
}

void
RplAodvAddressVectorFollowsParentTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(1);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    ipv6.AssignWithoutAddress(devices);

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    Simulator::Stop(Seconds(2));
    Simulator::Run();

    Ptr<Node> node = nodes.Get(0);
    Ptr<RplRoutingProtocol> rpl = node->GetObject<RplRoutingProtocol>();
    Ipv6Address nodeLinkLocal = node->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    static constexpr uint8_t RREQ_INSTANCE = 0x81;
    Ipv6Address origNode("2001:9::1");
    Ipv6Address neighbourB("fe80::b"); // worse: rank 384, 3 hops from OrigNode
    Ipv6Address neighbourA("fe80::a"); // better: rank 128, 1 hop from OrigNode
    Ipv6Address hopViaB("2001:9::b0");

    auto buildRreq = [&](uint16_t rank, const std::vector<Ipv6Address>& av) {
        RplDioHeader dio;
        dio.SetInstanceId(RREQ_INSTANCE);
        dio.SetVersionNumber(0);
        dio.SetRank(rank);
        dio.SetMop(RPL_MOP_P2P_ROUTE_DISCOVERY);
        dio.SetDodagId(origNode);
        dio.SetDtsn(0);
        dio.SetDagConfiguration(0,
                                8,
                                RPL_DIO_REDUNDANCY,
                                RPL_MAX_RANKINC,
                                RPL_MIN_HOPRANKINC,
                                RPL_OCP_OF0,
                                RPL_DEFAULT_LIFETIME,
                                RPL_DEFAULT_LIFETIME_UNIT);
        RplDioHeader::RreqOption rreq;
        rreq.symmetric = true;
        rreq.hopByHop = false;
        rreq.compr = 0;
        rreq.lifetime = 0; // no limit, keeps this test's timing simple
        rreq.rankLimit = 0;
        rreq.origSeqNo = 1;
        rreq.addressVector = av;
        dio.SetRreq(rreq);
        RplDioHeader::ArtOption art;
        art.destSeqNo = 0;
        art.prefixLength = 0;
        art.target = Ipv6Address("2001:9::99"); // a fake target, not this node
        dio.SetArt(art);
        return dio;
    };
    auto deliverRreq = [&](Ipv6Address from, uint16_t rank, const std::vector<Ipv6Address>& av) {
        Simulator::Schedule(Seconds(0),
                            &DeliverRawRplMessage<RplDioHeader>,
                            node,
                            1,
                            buildRreq(rank, av),
                            static_cast<uint8_t>(RPL_CODE_DIO),
                            from,
                            nodeLinkLocal);
        Simulator::Stop(MilliSeconds(10));
        Simulator::Run();
    };

    // The worse RREQ, from B, arrives first and is joined.
    deliverRreq(neighbourB, 384, {hopViaB});
    NS_TEST_ASSERT_MSG_EQ(rpl->GetRankIn(RREQ_INSTANCE, origNode),
                          512,
                          "Did not join the RREQ-Instance via B at the expected rank");
    std::vector<Ipv6Address> addressVector;
    NS_TEST_ASSERT_MSG_EQ(rpl->GetAodvAddressVector(RREQ_INSTANCE, origNode, addressVector),
                          true,
                          "No Address Vector after joining via B");
    NS_TEST_ASSERT_MSG_EQ(addressVector.size(), 2, "Wrong Address Vector size after B");
    NS_TEST_ASSERT_MSG_EQ(addressVector[0], hopViaB, "Wrong hop recorded for the path via B");

    // The better RREQ, from A, arrives second.
    deliverRreq(neighbourA, 128, {});

    NS_TEST_ASSERT_MSG_EQ(rpl->GetRankIn(RREQ_INSTANCE, origNode),
                          256,
                          "The preferred parent did not switch to the better neighbour A");
    NS_TEST_ASSERT_MSG_EQ(rpl->GetAodvAddressVector(RREQ_INSTANCE, origNode, addressVector),
                          true,
                          "No Address Vector after the switch to A");
    NS_TEST_ASSERT_MSG_EQ(addressVector.size(),
                          1,
                          "The Address Vector still reflects the path through B, not A: it "
                          "should hold only this node's own address now, one hop from A");
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief An AODV-RPL Hop-by-hop Route (H=1) rejects a stale Orig SeqNo,
 *        keeping the fresher route it already holds.
 *
 * RFC 9854 section 6.2.1: "When H=1 in the incoming RREQ, the router MUST
 * drop the RREQ message if the Orig SeqNo field of the RREQ is older than
 * the SeqNo value that X has stored for a route to OrigNode." Delivered
 * directly (DeliverRawRplMessage(), bypassing the channel) to a single node
 * under test, the same style RplAodvAddressVectorFollowsParentTestCase uses
 * for its own AODV-RPL bookkeeping.
 *
 * The second (stale) delivery deliberately offers a better Rank than the
 * first: if section 6.2.1's own staleness check were not run at all,
 * SelectPreferredParent() would happily switch to it on Rank alone, so the
 * route staying unchanged proves the staleness check itself is what stops
 * it, not an incidental loss on Rank. The third delivery, from the same
 * better-Rank neighbour but with a fresher Orig SeqNo, then confirms the
 * check is not simply refusing that neighbour outright.
 */
class RplAodvHopByHopStaleSeqNoRejectedTestCase : public TestCase
{
  public:
    RplAodvHopByHopStaleSeqNoRejectedTestCase();

  private:
    void DoRun() override;
};

RplAodvHopByHopStaleSeqNoRejectedTestCase::RplAodvHopByHopStaleSeqNoRejectedTestCase()
    : TestCase("An AODV-RPL Hop-by-hop Route (H=1) rejects a stale Orig SeqNo")
{
}

void
RplAodvHopByHopStaleSeqNoRejectedTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(1);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    ipv6.AssignWithoutAddress(devices);

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    Simulator::Stop(Seconds(2));
    Simulator::Run();

    Ptr<Node> node = nodes.Get(0);
    Ptr<RplRoutingProtocol> rpl = node->GetObject<RplRoutingProtocol>();
    Ipv6Address nodeLinkLocal = node->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    static constexpr uint8_t RREQ_INSTANCE = 0x81;
    Ipv6Address origNode("2001:9::1");
    Ipv6Address neighbourA("fe80::a"); // first offer, kept
    Ipv6Address neighbourB("fe80::b"); // second/third offer: better Rank

    auto buildRreq = [&](uint16_t rank, uint8_t seqNo) {
        RplDioHeader dio;
        dio.SetInstanceId(RREQ_INSTANCE);
        dio.SetVersionNumber(0);
        dio.SetRank(rank);
        dio.SetMop(RPL_MOP_P2P_ROUTE_DISCOVERY);
        dio.SetDodagId(origNode);
        dio.SetDtsn(0);
        dio.SetDagConfiguration(0,
                                8,
                                RPL_DIO_REDUNDANCY,
                                RPL_MAX_RANKINC,
                                RPL_MIN_HOPRANKINC,
                                RPL_OCP_OF0,
                                RPL_DEFAULT_LIFETIME,
                                RPL_DEFAULT_LIFETIME_UNIT);
        RplDioHeader::RreqOption rreq;
        rreq.symmetric = true;
        rreq.hopByHop = true;
        rreq.compr = 0;
        rreq.lifetime = 0; // no limit, keeps this test's timing simple
        rreq.rankLimit = 0;
        rreq.origSeqNo = seqNo;
        // Left empty: RFC 9854 section 4.1's "In hop-by-hop mode (H=1),
        // this field MUST be set to zero and ignored".
        dio.SetRreq(rreq);
        RplDioHeader::ArtOption art;
        art.destSeqNo = 0;
        art.prefixLength = 0;
        art.target = Ipv6Address("2001:9::99"); // a fake target, not this node
        dio.SetArt(art);
        return dio;
    };
    auto deliverRreq = [&](Ipv6Address from, uint16_t rank, uint8_t seqNo) {
        Simulator::Schedule(Seconds(0),
                            &DeliverRawRplMessage<RplDioHeader>,
                            node,
                            1,
                            buildRreq(rank, seqNo),
                            static_cast<uint8_t>(RPL_CODE_DIO),
                            from,
                            nodeLinkLocal);
        Simulator::Stop(MilliSeconds(10));
        Simulator::Run();
    };

    // First delivery, from A: establishes the upward route, Orig SeqNo 5.
    deliverRreq(neighbourA, 384, 5);
    Ipv6Address nextHop;
    uint8_t instanceId = 0;
    NS_TEST_ASSERT_MSG_EQ(rpl->GetHopByHopRoute(origNode, nextHop, instanceId),
                          true,
                          "The first RREQ-DIO did not establish an upward Hop-by-hop Route");
    NS_TEST_ASSERT_MSG_EQ(nextHop, neighbourA, "Wrong next hop after the first delivery");
    NS_TEST_ASSERT_MSG_EQ(rpl->GetRankIn(RREQ_INSTANCE, origNode),
                          512,
                          "Did not join the RREQ-Instance via A at the expected rank");

    // Second delivery, from B: a better Rank (128 < 384) but a staler Orig
    // SeqNo (3 < 5). RFC 9854 section 6.2.1 has this dropped outright,
    // before ShouldRefuseAodvRreq() even lets it join -- the route must
    // still point at A afterward, and -- checked separately from that,
    // since StoreHopByHopRoute()'s own internal staleness check would also
    // catch this on its own even if ShouldRefuseAodvRreq()'s pre-join gate
    // did not run at all -- the preferred parent (and so the joined rank)
    // must not have switched to B either, proving it is genuinely the
    // pre-join gate stopping this, not a same-outcome coincidence from the
    // later check alone.
    deliverRreq(neighbourB, 128, 3);
    NS_TEST_ASSERT_MSG_EQ(rpl->GetHopByHopRoute(origNode, nextHop, instanceId),
                          true,
                          "The stale RREQ-DIO's rejection should not have removed the route");
    NS_TEST_ASSERT_MSG_EQ(nextHop,
                          neighbourA,
                          "A stale Orig SeqNo was accepted, overwriting a fresher route");
    NS_TEST_ASSERT_MSG_EQ(rpl->GetRankIn(RREQ_INSTANCE, origNode),
                          512,
                          "The stale RREQ-DIO's better Rank switched the preferred parent to B, "
                          "meaning ShouldRefuseAodvRreq() let it join instead of dropping it "
                          "outright");

    // Third delivery, from B again: the same better Rank, but now a fresher
    // Orig SeqNo (7 > 5) -- accepted, and the route switches to B.
    deliverRreq(neighbourB, 128, 7);
    NS_TEST_ASSERT_MSG_EQ(rpl->GetHopByHopRoute(origNode, nextHop, instanceId),
                          true,
                          "A fresher RREQ-DIO should still leave an upward Hop-by-hop Route");
    NS_TEST_ASSERT_MSG_EQ(nextHop,
                          neighbourB,
                          "A fresher Orig SeqNo from a better Rank was not accepted");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief An asymmetric AODV-RPL Hop-by-hop Route's downward next hop
 *        follows a switch to a better preferred parent within the
 *        RREP-Instance's own topology.
 *
 * RFC 9854 section 6.4.3: an asymmetric route's downward next hop is "the
 * preferred parent in the DODAG of RREP-Instance", read fresh from
 * dodag.preferredParent every time HandleAodvRrepInstance() stores it --
 * unlike the symmetric case, which can just use from because the RREP-DIO
 * there is unicast hop-by-hop (@see design-constraints.md section 50.2).
 * This is what makes that design sound even when the RREP-Instance's own
 * flood reaches a router from more than one neighbour: a worse-Rank copy
 * arrives first and is joined, then a better-Rank copy arrives from a
 * different neighbour and SelectPreferredParent() switches to it (the same
 * scenario RplAodvAddressVectorFollowsParentTestCase covers for the RREQ
 * side) -- the stored downward route has to follow that switch, not stay
 * pinned to whichever neighbour's copy happened to be processed first.
 *
 * Delivered directly (DeliverRawRplMessage(), multicast so it reads as RFC
 * 9854 section 6.3.2's flood) to a single node under test, acting as an
 * intermediate router for a fabricated RREP-Instance neither OrigNode nor
 * TargNode itself.
 */
class RplAodvAsymmetricHopByHopRouteFollowsParentTestCase : public TestCase
{
  public:
    RplAodvAsymmetricHopByHopRouteFollowsParentTestCase();

  private:
    void DoRun() override;
};

RplAodvAsymmetricHopByHopRouteFollowsParentTestCase::
    RplAodvAsymmetricHopByHopRouteFollowsParentTestCase()
    : TestCase("An asymmetric AODV-RPL Hop-by-hop Route's downward next hop follows the "
               "RREP-Instance's own preferred parent")
{
}

void
RplAodvAsymmetricHopByHopRouteFollowsParentTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(1);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    ipv6.AssignWithoutAddress(devices);

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    Simulator::Stop(Seconds(2));
    Simulator::Run();

    Ptr<Node> node = nodes.Get(0);
    Ptr<RplRoutingProtocol> rpl = node->GetObject<RplRoutingProtocol>();

    static constexpr uint8_t RREQ_INSTANCE = 0x81;
    static constexpr uint8_t DELTA = 3;
    static constexpr uint8_t RREP_INSTANCE = static_cast<uint8_t>(RREQ_INSTANCE + DELTA);
    Ipv6Address targNode("2001:9::1");  // the RREP-Instance's own DODAGID
    Ipv6Address origNode("2001:9::99"); // a fake OrigNode, not this node
    Ipv6Address neighbourA("fe80::a");  // worse: rank 384
    Ipv6Address neighbourB("fe80::b");  // better: rank 128

    auto buildRrep = [&](uint16_t rank, uint8_t seqNo) {
        RplDioHeader dio;
        dio.SetInstanceId(RREP_INSTANCE);
        dio.SetVersionNumber(0);
        dio.SetRank(rank);
        dio.SetMop(RPL_MOP_P2P_ROUTE_DISCOVERY);
        dio.SetDodagId(targNode);
        dio.SetDtsn(0);
        dio.SetDagConfiguration(0,
                                8,
                                RPL_DIO_REDUNDANCY,
                                RPL_MAX_RANKINC,
                                RPL_MIN_HOPRANKINC,
                                RPL_OCP_OF0,
                                RPL_DEFAULT_LIFETIME,
                                RPL_DEFAULT_LIFETIME_UNIT);
        RplDioHeader::RrepOption rrep;
        rrep.gratuitous = false;
        rrep.hopByHop = true;
        rrep.lifetime = 0; // no limit, keeps this test's timing simple
        rrep.rankLimit = 0;
        rrep.delta = DELTA;
        // Left empty: RFC 9854 section 4.1's "In hop-by-hop mode (H=1),
        // this field MUST be set to zero and ignored".
        dio.SetRrep(rrep);
        RplDioHeader::ArtOption art;
        art.destSeqNo = seqNo;
        art.prefixLength = 0;
        art.target = origNode;
        dio.SetArt(art);
        return dio;
    };
    auto deliverRrep = [&](Ipv6Address from, uint16_t rank, uint8_t seqNo) {
        Simulator::Schedule(Seconds(0),
                            &DeliverRawRplMessage<RplDioHeader>,
                            node,
                            1,
                            buildRrep(rank, seqNo),
                            static_cast<uint8_t>(RPL_CODE_DIO),
                            from,
                            Ipv6Address(RPL_ALL_NODES_MULTICAST));
        Simulator::Stop(MilliSeconds(10));
        Simulator::Run();
    };

    // First delivery, from A: establishes the downward route, next hop A.
    deliverRrep(neighbourA, 384, 5);
    Ipv6Address nextHop;
    uint8_t instanceId = 0;
    NS_TEST_ASSERT_MSG_EQ(rpl->GetHopByHopRoute(targNode, nextHop, instanceId),
                          true,
                          "The first RREP-Instance DIO did not establish a downward Hop-by-hop "
                          "Route");
    NS_TEST_ASSERT_MSG_EQ(nextHop, neighbourA, "Wrong next hop after the first delivery");
    NS_TEST_ASSERT_MSG_EQ(instanceId,
                          RREQ_INSTANCE,
                          "The stored instanceId should be the RREQ-InstanceID (Delta "
                          "subtracted), not the RREP-Instance's own");

    // Second delivery, from B: a better Rank (128 < 384). Same Dest SeqNo as
    // the first, so this pins down that the switch follows from
    // SelectPreferredParent() choosing the better neighbour, not from a
    // seqNo-freshness win.
    deliverRrep(neighbourB, 128, 5);
    NS_TEST_ASSERT_MSG_EQ(rpl->GetRankIn(RREP_INSTANCE, targNode),
                          256,
                          "The preferred parent did not switch to the better neighbour B");
    NS_TEST_ASSERT_MSG_EQ(rpl->GetHopByHopRoute(targNode, nextHop, instanceId),
                          true,
                          "The downward Hop-by-hop Route disappeared after the switch");
    NS_TEST_ASSERT_MSG_EQ(nextHop,
                          neighbourB,
                          "The downward next hop did not follow the switch to the better "
                          "preferred parent B");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief An AODV-RPL route discovery floods an RREQ outward, each hop
 *        appending its own address to the Address Vector.
 *
 * The first half of RFC 9854's route discovery: DiscoverRoute() at the
 * OrigNode forms an RREQ-Instance rooted at itself (section 6.1) and
 * Trickle-paces RREQ-DIOs into it; every router that hears one joins,
 * appends the address of the interface it heard it on (section 6.2.5), and
 * propagates. What comes back the other way is a later increment's business.
 *
 * A four-node line, so the Address Vector has to grow by exactly one entry
 * per hop and the far end has to be reached through two routers that were
 * never told about the discovery in advance:
 *
 *     orig(0) ---- relay1(1) ---- relay2(2) ---- targ(3)
 *
 * Non-adjacent pairs are blacklisted, RplDodagFormationTestCase's own
 * line-topology recipe. Every node also belongs to an ordinary base DODAG
 * rooted at node 0 -- AODV-RPL runs alongside core RPL rather than instead
 * of it (RFC 9854 section 1) -- which is also what gives each node the
 * global address its Address Vector entry has to be.
 */
class RplAodvRreqFloodTestCase : public TestCase
{
  public:
    RplAodvRreqFloodTestCase();

  private:
    void DoRun() override;
};

RplAodvRreqFloodTestCase::RplAodvRreqFloodTestCase()
    : TestCase("An AODV-RPL RREQ floods outward, each hop appending itself to the Address Vector")
{
}

void
RplAodvRreqFloodTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(4); // 0 = OrigNode and base root, 1 and 2 = relays, 3 = TargNode

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    auto blacklist = [&](uint32_t a, uint32_t b) {
        Ptr<SimpleNetDevice> devA = DynamicCast<SimpleNetDevice>(devices.Get(a));
        Ptr<SimpleNetDevice> devB = DynamicCast<SimpleNetDevice>(devices.Get(b));
        channel->BlackList(devA, devB);
        channel->BlackList(devB, devA);
    };
    blacklist(0, 2);
    blacklist(0, 3);
    blacklist(1, 3);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    // The base DODAG across all three hops first, so every node has SLAACed
    // the global address its Address Vector entry has to be.
    // RplDodagFormationTestCase's own budget for two hops, with margin.
    Simulator::Stop(Seconds(250));
    Simulator::Run();

    Ptr<RplRoutingProtocol> orig = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay1 = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay2 = nodes.Get(2)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> targ = nodes.Get(3)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(targ->IsJoined(), true, "The base DODAG did not reach the far end");

    Ipv6Address relay1Address = relay1->GetGlobalAddress();
    Ipv6Address relay2Address = relay2->GetGlobalAddress();
    Ipv6Address targAddress = targ->GetGlobalAddress();
    NS_TEST_ASSERT_MSG_NE(targAddress, Ipv6Address::GetAny(), "The TargNode has no address");

    RplRoutingProtocol::DodagKey key = orig->DiscoverRoute(targAddress);
    NS_TEST_ASSERT_MSG_NE(key.dodagId, Ipv6Address::GetAny(), "The discovery did not start");
    NS_TEST_ASSERT_MSG_EQ(key.dodagId,
                          orig->GetGlobalAddress(),
                          "The RREQ-Instance is not rooted at the OrigNode's own address");
    // RFC 6550 section 5.1's Local RPLInstanceID: the top bit set to mark it
    // Local, the 'D' flag below it clear in a control message.
    NS_TEST_ASSERT_MSG_NE(key.instanceId & RPL_LOCAL_INSTANCE_FLAG,
                          0,
                          "The RREQ-Instance did not get a Local RPLInstanceID");
    NS_TEST_ASSERT_MSG_EQ(key.instanceId & RPL_LOCAL_INSTANCE_D_FLAG,
                          0,
                          "The Local RPLInstanceID's 'D' flag is set in a control message");

    // Three hops of Trickle-paced RREQ-DIOs at AodvDioIntervalMin (128 ms,
    // doubling), well inside the 16 seconds the default 'L' field allows.
    Simulator::Stop(Seconds(10));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(orig->IsJoinedTo(key.instanceId, key.dodagId),
                          true,
                          "The OrigNode is not in its own RREQ-Instance");
    NS_TEST_ASSERT_MSG_EQ(relay1->IsJoinedTo(key.instanceId, key.dodagId),
                          true,
                          "relay1 did not join the RREQ-Instance");
    NS_TEST_ASSERT_MSG_EQ(relay2->IsJoinedTo(key.instanceId, key.dodagId),
                          true,
                          "relay2 did not join the RREQ-Instance: the RREQ was not propagated "
                          "past the first hop");
    NS_TEST_ASSERT_MSG_EQ(targ->IsJoinedTo(key.instanceId, key.dodagId),
                          true,
                          "The TargNode never heard the RREQ");

    // The Address Vector grows by exactly one entry per hop, in order, and
    // holds global addresses -- it becomes a source route later, so a
    // link-local entry would be unusable from more than one hop away.
    std::vector<Ipv6Address> addressVector;

    NS_TEST_ASSERT_MSG_EQ(orig->GetAodvAddressVector(key.instanceId, key.dodagId, addressVector),
                          true,
                          "The OrigNode has no Address Vector");
    NS_TEST_ASSERT_MSG_EQ(addressVector.size(),
                          0,
                          "The OrigNode put itself in its own Address Vector; RFC 9854 section "
                          "6.2.5 has only intermediate routers append to it");

    NS_TEST_ASSERT_MSG_EQ(relay1->GetAodvAddressVector(key.instanceId, key.dodagId, addressVector),
                          true,
                          "relay1 has no Address Vector");
    NS_TEST_ASSERT_MSG_EQ(addressVector.size(), 1, "relay1's Address Vector is the wrong length");
    NS_TEST_ASSERT_MSG_EQ(addressVector[0], relay1Address, "relay1 did not append its own address");

    NS_TEST_ASSERT_MSG_EQ(relay2->GetAodvAddressVector(key.instanceId, key.dodagId, addressVector),
                          true,
                          "relay2 has no Address Vector");
    NS_TEST_ASSERT_MSG_EQ(addressVector.size(), 2, "relay2's Address Vector is the wrong length");
    NS_TEST_ASSERT_MSG_EQ(addressVector[0], relay1Address, "relay2 lost the hop before it");
    NS_TEST_ASSERT_MSG_EQ(addressVector[1], relay2Address, "relay2 did not append its own address");

    NS_TEST_ASSERT_MSG_EQ(targ->GetAodvAddressVector(key.instanceId, key.dodagId, addressVector),
                          true,
                          "The TargNode has no Address Vector");
    NS_TEST_ASSERT_MSG_EQ(addressVector.size(), 3, "The TargNode's Address Vector is the wrong length");
    NS_TEST_ASSERT_MSG_EQ(addressVector[0], relay1Address, "The first hop is wrong at the TargNode");
    NS_TEST_ASSERT_MSG_EQ(addressVector[1], relay2Address, "The second hop is wrong at the TargNode");
    NS_TEST_ASSERT_MSG_EQ(addressVector[2], targAddress, "The TargNode did not append its own address");

    // Only the node the ART option names knows itself to be the target.
    NS_TEST_ASSERT_MSG_EQ(targ->IsAodvTarget(key.instanceId, key.dodagId),
                          true,
                          "The TargNode did not recognise itself in the ART option");
    NS_TEST_ASSERT_MSG_EQ(relay1->IsAodvTarget(key.instanceId, key.dodagId),
                          false,
                          "relay1 thinks it is the target");
    NS_TEST_ASSERT_MSG_EQ(relay2->IsAodvTarget(key.instanceId, key.dodagId),
                          false,
                          "relay2 thinks it is the target");

    // The base DODAG is untouched by any of this: it is a separate RPL
    // Instance and keeps its own rank and parent (RFC 9854 section 1,
    // "AODV-RPL can be operated whether or not ... RPL is also running").
    NS_TEST_ASSERT_MSG_EQ(targ->IsJoined(), true, "The base DODAG membership was disturbed");
    NS_TEST_ASSERT_MSG_EQ(targ->GetDodagId(),
                          orig->GetGlobalAddress(),
                          "The base DODAG's own DODAGID changed");
    NS_TEST_ASSERT_MSG_EQ(targ->GetDodagCount(), 2, "The TargNode holds the wrong number of DODAGs");

    // The 'L' field takes every node back out again. The default is 1, which
    // RFC 9854 section 4.1 tabulates as 16 seconds, measured from when each
    // node last heard the discovery was live.
    Simulator::Stop(Seconds(30));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(relay1->IsJoinedTo(key.instanceId, key.dodagId),
                          false,
                          "relay1 stayed in the RREQ-Instance past its 'L' deadline");
    NS_TEST_ASSERT_MSG_EQ(targ->IsJoinedTo(key.instanceId, key.dodagId),
                          false,
                          "The TargNode stayed in the RREQ-Instance past its 'L' deadline");
    NS_TEST_ASSERT_MSG_EQ(orig->IsJoinedTo(key.instanceId, key.dodagId),
                          false,
                          "The OrigNode stayed in its own RREQ-Instance past its 'L' deadline");
    // Leaving the discovery must not have taken the base DODAG with it.
    NS_TEST_ASSERT_MSG_EQ(targ->IsJoined(), true, "Leaving the RREQ-Instance dropped the base DODAG");
    NS_TEST_ASSERT_MSG_EQ(targ->GetDodagCount(), 1, "Only the base DODAG should be left");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief An intermediate router intersects the ART target lists of two
 *        RREQ-DIOs for the same RREQ-Instance, exactly the RFC's own worked
 *        example.
 *
 * RFC 9854 section 6.2.2: "suppose two RREQ-DIOs are received with the same
 * RPL Instance and OrigNode. Suppose further that the first RREQ has (T1, T2)
 * as the targets, and the second one has (T2, T4) as targets. Then, only T2
 * needs to be included in the generated RREQ-DIO." One fabricated node under
 * test, fed both hand-built RREQ-DIOs from two fabricated neighbours -- B
 * first (T1, T2), then A, at a better Rank so its own copy is not turned away
 * as a stale repeat (RplAodvAddressVectorFollowsParentTestCase's own recipe
 * for exactly that), carrying (T2, T4). Neither T1, T2, nor T4 names this
 * node, so it stays a pure intermediate router throughout -- this is a unit
 * test of the intersection bookkeeping in HandleAodvRreq() alone, not of
 * TargNode matching, which RplAodvMultiArtTwoTargetsAnsweredTestCase covers
 * separately.
 */
class RplAodvMultiArtIntersectionTestCase : public TestCase
{
  public:
    RplAodvMultiArtIntersectionTestCase();

  private:
    void DoRun() override;
};

RplAodvMultiArtIntersectionTestCase::RplAodvMultiArtIntersectionTestCase()
    : TestCase("An AODV-RPL intermediate router intersects two RREQ-DIOs' ART target lists")
{
}

void
RplAodvMultiArtIntersectionTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(1);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    ipv6.AssignWithoutAddress(devices);

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    Simulator::Stop(Seconds(2));
    Simulator::Run();

    Ptr<Node> node = nodes.Get(0);
    Ptr<RplRoutingProtocol> rpl = node->GetObject<RplRoutingProtocol>();
    Ipv6Address nodeLinkLocal = node->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    static constexpr uint8_t RREQ_INSTANCE = 0x82;
    Ipv6Address origNode("2001:9::1");
    Ipv6Address neighbourB("fe80::b"); // worse: rank 384, carries (T1, T2)
    Ipv6Address neighbourA("fe80::a"); // better: rank 128, carries (T2, T4)
    Ipv6Address hopViaB("2001:9::b0");
    Ipv6Address t1("2001:9::11");
    Ipv6Address t2("2001:9::12");
    Ipv6Address t4("2001:9::14");

    auto buildRreq = [&](uint16_t rank,
                         const std::vector<Ipv6Address>& av,
                         const std::vector<Ipv6Address>& targets) {
        RplDioHeader dio;
        dio.SetInstanceId(RREQ_INSTANCE);
        dio.SetVersionNumber(0);
        dio.SetRank(rank);
        dio.SetMop(RPL_MOP_P2P_ROUTE_DISCOVERY);
        dio.SetDodagId(origNode);
        dio.SetDtsn(0);
        dio.SetDagConfiguration(0,
                                8,
                                RPL_DIO_REDUNDANCY,
                                RPL_MAX_RANKINC,
                                RPL_MIN_HOPRANKINC,
                                RPL_OCP_OF0,
                                RPL_DEFAULT_LIFETIME,
                                RPL_DEFAULT_LIFETIME_UNIT);
        RplDioHeader::RreqOption rreq;
        rreq.symmetric = true;
        rreq.hopByHop = false;
        rreq.compr = 0;
        rreq.lifetime = 0; // no limit, keeps this test's timing simple
        rreq.rankLimit = 0;
        rreq.origSeqNo = 1;
        rreq.addressVector = av;
        dio.SetRreq(rreq);
        for (const auto& target : targets)
        {
            RplDioHeader::ArtOption art;
            art.destSeqNo = 0;
            art.prefixLength = 0;
            art.target = target;
            dio.AddArt(art);
        }
        return dio;
    };
    auto deliverRreq = [&](Ipv6Address from,
                           uint16_t rank,
                           const std::vector<Ipv6Address>& av,
                           const std::vector<Ipv6Address>& targets) {
        Simulator::Schedule(Seconds(0),
                            &DeliverRawRplMessage<RplDioHeader>,
                            node,
                            1,
                            buildRreq(rank, av, targets),
                            static_cast<uint8_t>(RPL_CODE_DIO),
                            from,
                            nodeLinkLocal);
        Simulator::Stop(MilliSeconds(10));
        Simulator::Run();
    };

    // The first RREQ-DIO, from B, carries (T1, T2). Nothing to intersect
    // against yet, so it seeds the record outright.
    deliverRreq(neighbourB, 384, {hopViaB}, {t1, t2});
    std::vector<Ipv6Address> targets;
    NS_TEST_ASSERT_MSG_EQ(rpl->GetAodvTargets(RREQ_INSTANCE, origNode, targets),
                          true,
                          "Not joined to the RREQ-Instance after the first RREQ-DIO");
    NS_TEST_ASSERT_MSG_EQ(targets.size(), 2, "Wrong target count after the first RREQ-DIO");
    NS_TEST_ASSERT_MSG_EQ(targets[0], t1, "T1 missing after the first RREQ-DIO");
    NS_TEST_ASSERT_MSG_EQ(targets[1], t2, "T2 missing after the first RREQ-DIO");
    NS_TEST_ASSERT_MSG_EQ(rpl->IsAodvTarget(RREQ_INSTANCE, origNode),
                          false,
                          "This node matched a target that does not name it");

    // The second, from A (a better Rank, so its own copy is accepted rather
    // than turned away as a stale repeat), carries (T2, T4). RFC 9854 section
    // 6.2.2's own worked example: only T2 survives the intersection.
    deliverRreq(neighbourA, 128, {}, {t2, t4});
    NS_TEST_ASSERT_MSG_EQ(rpl->GetAodvTargets(RREQ_INSTANCE, origNode, targets),
                          true,
                          "Not joined to the RREQ-Instance after the second RREQ-DIO");
    NS_TEST_ASSERT_MSG_EQ(targets.size(),
                          1,
                          "The intersection of (T1, T2) and (T2, T4) should leave exactly one "
                          "target");
    NS_TEST_ASSERT_MSG_EQ(targets[0], t2, "The surviving target should be T2");
    NS_TEST_ASSERT_MSG_EQ(rpl->IsAodvTarget(RREQ_INSTANCE, origNode),
                          false,
                          "This node still does not name itself among the targets");
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Two TargNodes named by the same RREQ-DIO's two ART options each
 *        recognise themselves, delete only their own entry, and keep
 *        relaying the other one onward.
 *
 * RFC 9854 section 6.1: "the OrigNode can initiate the route discovery
 * process for multiple targets simultaneously by including multiple ART
 * options", and section 6.2.2: "If the OrigNode tries to reach multiple
 * TargNodes in a single RREQ-Instance, one of the TargNodes can be an
 * intermediate router to other TargNodes. In this case ... a TargNode MUST
 * delete the Target option encapsulating its own address."
 *
 * A relay with two real TargNode children, fed a single hand-built RREQ-DIO
 * naming both of them (standing in for a real OrigNode, the same
 * unit-of-the-relay style RplAodvAddressVectorFollowsParentTestCase uses --
 * DiscoverRoute() itself only ever starts a discovery for one target, so a
 * genuine two-ART RREQ-DIO has to be fabricated regardless of how the rest of
 * the topology is built):
 *
 *                targA(1)
 *               /
 *     relay(0)
 *               \
 *                targB(2)
 *
 * targA and targB are blacklisted from each other so the only way either
 * learns of the other's continued existence is via relay's own, real,
 * channel-propagated re-transmission of its RREQ-DIO -- confirming SendDio()
 * rebuilds a multi-entry outgoing ART list, not just a single-entry one.
 */
class RplAodvMultiArtTwoTargetsAnsweredTestCase : public TestCase
{
  public:
    RplAodvMultiArtTwoTargetsAnsweredTestCase();

  private:
    void DoRun() override;
};

RplAodvMultiArtTwoTargetsAnsweredTestCase::RplAodvMultiArtTwoTargetsAnsweredTestCase()
    : TestCase("An AODV-RPL RREQ-DIO naming two TargNodes reaches both, each self-deleting only "
               "its own ART entry")
{
}

void
RplAodvMultiArtTwoTargetsAnsweredTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(3); // 0 = relay, 1 = targA, 2 = targB

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    Ptr<SimpleNetDevice> devTargA = DynamicCast<SimpleNetDevice>(devices.Get(1));
    Ptr<SimpleNetDevice> devTargB = DynamicCast<SimpleNetDevice>(devices.Get(2));
    channel->BlackList(devTargA, devTargB);
    channel->BlackList(devTargB, devTargA);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    // The base DODAG across both hops first, so relay, targA and targB all
    // have the global addresses their Address Vector entries have to be.
    Simulator::Stop(Seconds(10));
    Simulator::Run();

    Ptr<RplRoutingProtocol> relay = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> targA = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> targB = nodes.Get(2)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(targA->IsJoined(), true, "targA never joined the base DODAG");
    NS_TEST_ASSERT_MSG_EQ(targB->IsJoined(), true, "targB never joined the base DODAG");

    Ipv6Address relayLinkLocal =
        nodes.Get(0)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address targAAddress = targA->GetGlobalAddress();
    Ipv6Address targBAddress = targB->GetGlobalAddress();
    NS_TEST_ASSERT_MSG_NE(targAAddress, Ipv6Address::GetAny(), "targA has no address");
    NS_TEST_ASSERT_MSG_NE(targBAddress, Ipv6Address::GetAny(), "targB has no address");

    static constexpr uint8_t RREQ_INSTANCE = 0x83;
    Ipv6Address origNode("2001:9::1"); // fabricated: no real node behind it
    RplDioHeader rreqDio;
    rreqDio.SetInstanceId(RREQ_INSTANCE);
    rreqDio.SetVersionNumber(0);
    rreqDio.SetRank(RPL_MIN_HOPRANKINC);
    rreqDio.SetMop(RPL_MOP_P2P_ROUTE_DISCOVERY);
    rreqDio.SetDodagId(origNode);
    rreqDio.SetDtsn(0);
    rreqDio.SetDagConfiguration(0,
                                8,
                                RPL_DIO_REDUNDANCY,
                                RPL_MAX_RANKINC,
                                RPL_MIN_HOPRANKINC,
                                RPL_OCP_OF0,
                                RPL_DEFAULT_LIFETIME,
                                RPL_DEFAULT_LIFETIME_UNIT);
    RplDioHeader::RreqOption rreq;
    rreq.symmetric = true;
    rreq.hopByHop = false;
    rreq.compr = 0;
    rreq.lifetime = 0;
    rreq.rankLimit = 0;
    rreq.origSeqNo = 1;
    rreqDio.SetRreq(rreq);
    RplDioHeader::ArtOption artA;
    artA.destSeqNo = 0;
    artA.prefixLength = 0;
    artA.target = targAAddress;
    rreqDio.AddArt(artA);
    RplDioHeader::ArtOption artB;
    artB.destSeqNo = 0;
    artB.prefixLength = 0;
    artB.target = targBAddress;
    rreqDio.AddArt(artB);

    // Re-delivered every 100 ms, not just once: a fabricated upstream
    // sender that is never heard from again goes stale and drops out of
    // relay's own dodag.parents like any other neighbour would (@see
    // SelectPreferredParent()'s staleness sweep, keyed off this DIO's own
    // DodagConfiguration -- dioIntervalMin 256 ms here), and relay then
    // poisons and leaves this RREQ-Instance for want of a parent before
    // ever relaying anything onward. That is ordinary, pre-existing RPL
    // behaviour, not anything to do with multi-ART, but a one-shot
    // fabricated sender is the only thing in this test that could ever
    // trigger it -- RplAodvRreqFloodTestCase avoids it by using a real,
    // continuously Trickle-firing OrigNode instead of a fabricated one.
    for (uint32_t i = 0; i < 30; i++)
    {
        Simulator::Schedule(MilliSeconds(100 * i),
                            &DeliverRawRplMessage<RplDioHeader>,
                            nodes.Get(0),
                            1,
                            rreqDio,
                            static_cast<uint8_t>(RPL_CODE_DIO),
                            Ipv6Address("fe80::f1"),
                            relayLinkLocal);
    }

    // Several Trickle-paced re-transmissions at relay's AodvDioIntervalMin
    // (128 ms, doubling), well inside the default 16-second 'L'.
    Simulator::Stop(Seconds(3));
    Simulator::Run();

    // relay is neither target, so it keeps the untouched two-entry record --
    // nothing has come in to intersect it against, and it names neither of
    // its own addresses to delete.
    std::vector<Ipv6Address> relayTargets;
    NS_TEST_ASSERT_MSG_EQ(relay->GetAodvTargets(RREQ_INSTANCE, origNode, relayTargets),
                          true,
                          "relay did not join the RREQ-Instance");
    NS_TEST_ASSERT_MSG_EQ(relayTargets.size(), 2, "relay's own target record should list both");
    NS_TEST_ASSERT_MSG_EQ(relay->IsAodvTarget(RREQ_INSTANCE, origNode),
                          false,
                          "relay thinks it is one of the targets");

    NS_TEST_ASSERT_MSG_EQ(targA->IsAodvTarget(RREQ_INSTANCE, origNode),
                          true,
                          "targA did not recognise itself in relay's re-transmitted ART option");
    NS_TEST_ASSERT_MSG_EQ(targB->IsAodvTarget(RREQ_INSTANCE, origNode),
                          true,
                          "targB did not recognise itself in relay's re-transmitted ART option");

    // Each TargNode deletes only its own entry (RFC 9854 section 6.2.2),
    // leaving the other target intact to still relay onward as an
    // intermediate router would, per that same section's "one of the
    // TargNodes can be an intermediate router to other TargNodes".
    std::vector<Ipv6Address> targATargets;
    NS_TEST_ASSERT_MSG_EQ(targA->GetAodvTargets(RREQ_INSTANCE, origNode, targATargets),
                          true,
                          "targA did not join the RREQ-Instance");
    NS_TEST_ASSERT_MSG_EQ(targATargets.size(),
                          1,
                          "targA should have deleted only its own ART entry");
    NS_TEST_ASSERT_MSG_EQ(targATargets[0],
                          targBAddress,
                          "targA deleted the wrong entry, or kept its own");

    std::vector<Ipv6Address> targBTargets;
    NS_TEST_ASSERT_MSG_EQ(targB->GetAodvTargets(RREQ_INSTANCE, origNode, targBTargets),
                          true,
                          "targB did not join the RREQ-Instance");
    NS_TEST_ASSERT_MSG_EQ(targBTargets.size(),
                          1,
                          "targB should have deleted only its own ART entry");
    NS_TEST_ASSERT_MSG_EQ(targBTargets[0],
                          targAAddress,
                          "targB deleted the wrong entry, or kept its own");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A TargNode that still has another target outstanding relays it
 *        onward as an intermediate router would, reaching a second TargNode
 *        that is otherwise unreachable except through the first.
 *
 * RFC 9854 section 6.2.2: "If the OrigNode tries to reach multiple TargNodes
 * in a single RREQ-Instance, one of the TargNodes can be an intermediate
 * router to other TargNodes." RplAodvMultiArtTwoTargetsAnsweredTestCase's own
 * targA/targB sit as siblings under a shared relay, so targB is reached by
 * relay's own re-transmission regardless of whether targA relays anything --
 * that topology cannot actually tell "targA's continued relay reached targB"
 * apart from "targB heard relay directly". This is the genuinely chained
 * case the sentence above describes:
 *
 *     relay(0) ---- targA(1) ---- targB(2)
 *
 * relay is blacklisted from targB directly, so the only way targB can ever
 * learn of the discovery is through targA's own, real, channel-propagated
 * re-transmission of its RREQ-DIO -- confirming that a TargNode with other
 * targets still outstanding does not simply stop at answering its own RREP,
 * the way the pre-multi-ART code always did once dodag.aodv.isTarget became
 * true.
 */
class RplAodvMultiArtTargNodeRelaysToFartherTargetTestCase : public TestCase
{
  public:
    RplAodvMultiArtTargNodeRelaysToFartherTargetTestCase();

  private:
    void DoRun() override;
};

RplAodvMultiArtTargNodeRelaysToFartherTargetTestCase::
    RplAodvMultiArtTargNodeRelaysToFartherTargetTestCase()
    : TestCase("An AODV-RPL TargNode relays a remaining ART onward to reach a farther TargNode")
{
}

void
RplAodvMultiArtTargNodeRelaysToFartherTargetTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(3); // 0 = relay (neither target), 1 = targA, 2 = targB (only reachable via targA)

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    Ptr<SimpleNetDevice> devRelay = DynamicCast<SimpleNetDevice>(devices.Get(0));
    Ptr<SimpleNetDevice> devTargB = DynamicCast<SimpleNetDevice>(devices.Get(2));
    channel->BlackList(devRelay, devTargB);
    channel->BlackList(devTargB, devRelay);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    // The base DODAG across both hops first, so relay, targA and targB all
    // have the global addresses their Address Vector entries have to be.
    Simulator::Stop(Seconds(10));
    Simulator::Run();

    Ptr<RplRoutingProtocol> relay = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> targA = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> targB = nodes.Get(2)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(targA->IsJoined(), true, "targA never joined the base DODAG");
    NS_TEST_ASSERT_MSG_EQ(targB->IsJoined(), true, "targB never joined the base DODAG");

    Ipv6Address relayLinkLocal =
        nodes.Get(0)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address targAAddress = targA->GetGlobalAddress();
    Ipv6Address targBAddress = targB->GetGlobalAddress();
    NS_TEST_ASSERT_MSG_NE(targAAddress, Ipv6Address::GetAny(), "targA has no address");
    NS_TEST_ASSERT_MSG_NE(targBAddress, Ipv6Address::GetAny(), "targB has no address");

    static constexpr uint8_t RREQ_INSTANCE = 0x85;
    Ipv6Address origNode("2001:9::1"); // fabricated: no real node behind it
    RplDioHeader rreqDio;
    rreqDio.SetInstanceId(RREQ_INSTANCE);
    rreqDio.SetVersionNumber(0);
    rreqDio.SetRank(RPL_MIN_HOPRANKINC);
    rreqDio.SetMop(RPL_MOP_P2P_ROUTE_DISCOVERY);
    rreqDio.SetDodagId(origNode);
    rreqDio.SetDtsn(0);
    rreqDio.SetDagConfiguration(0,
                                8,
                                RPL_DIO_REDUNDANCY,
                                RPL_MAX_RANKINC,
                                RPL_MIN_HOPRANKINC,
                                RPL_OCP_OF0,
                                RPL_DEFAULT_LIFETIME,
                                RPL_DEFAULT_LIFETIME_UNIT);
    RplDioHeader::RreqOption rreq;
    rreq.symmetric = true;
    rreq.hopByHop = false;
    rreq.compr = 0;
    rreq.lifetime = 0;
    rreq.rankLimit = 0;
    rreq.origSeqNo = 1;
    rreqDio.SetRreq(rreq);
    RplDioHeader::ArtOption artA;
    artA.destSeqNo = 0;
    artA.prefixLength = 0;
    artA.target = targAAddress;
    rreqDio.AddArt(artA);
    RplDioHeader::ArtOption artB;
    artB.destSeqNo = 0;
    artB.prefixLength = 0;
    artB.target = targBAddress;
    rreqDio.AddArt(artB);

    // Kept fresh the same way RplAodvMultiArtTwoTargetsAnsweredTestCase's
    // own injection is: a one-shot fabricated sender goes stale and would
    // otherwise poison relay's own RREQ-Instance out from under it before
    // targA ever gets a chance to relay anything onward to targB. @see
    // design-constraints.md section 42.3.
    for (uint32_t i = 0; i < 30; i++)
    {
        Simulator::Schedule(MilliSeconds(100 * i),
                            &DeliverRawRplMessage<RplDioHeader>,
                            nodes.Get(0),
                            1,
                            rreqDio,
                            static_cast<uint8_t>(RPL_CODE_DIO),
                            Ipv6Address("fe80::f1"),
                            relayLinkLocal);
    }

    // Two hops of Trickle-paced re-transmission at AodvDioIntervalMin
    // (128 ms, doubling), well inside the default 16-second 'L'.
    Simulator::Stop(Seconds(3));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(targA->IsAodvTarget(RREQ_INSTANCE, origNode),
                          true,
                          "targA did not recognise itself in relay's re-transmitted ART option");
    NS_TEST_ASSERT_MSG_EQ(
        targB->IsJoinedTo(RREQ_INSTANCE, origNode),
        true,
        "targB never joined the RREQ-Instance at all: it is blacklisted from relay directly, so "
        "this can only have come from targA's own relay of its remaining ART");
    NS_TEST_ASSERT_MSG_EQ(
        targB->IsAodvTarget(RREQ_INSTANCE, origNode),
        true,
        "targB did not recognise itself in the ART option targA relayed onward -- the RFC 9854 "
        "section 6.2.2 scenario of a TargNode acting as an intermediate router to another "
        "TargNode is not actually reaching that farther TargNode");

    // targB's Address Vector must show it arrived via relay then targA, in
    // that order, each hop having appended its own address including
    // targB's own -- the same three-entries-for-two-relayed-hops shape
    // RplAodvRreqFloodTestCase's own targ (also a leaf two hops beyond the
    // first relay) confirms, and here the only way to have picked up
    // targA's entry at all is a route that genuinely passed through it.
    std::vector<Ipv6Address> targBAddressVector;
    NS_TEST_ASSERT_MSG_EQ(targB->GetAodvAddressVector(RREQ_INSTANCE, origNode, targBAddressVector),
                          true,
                          "targB has no Address Vector");
    NS_TEST_ASSERT_MSG_EQ(targBAddressVector.size(),
                          3,
                          "targB's Address Vector should be relay, targA, targB itself");
    NS_TEST_ASSERT_MSG_EQ(targBAddressVector[0],
                          relay->GetGlobalAddress(),
                          "The first hop is wrong at targB");
    NS_TEST_ASSERT_MSG_EQ(targBAddressVector[1],
                          targAAddress,
                          "targB's route did not pass through targA");
    NS_TEST_ASSERT_MSG_EQ(targBAddressVector[2],
                          targBAddress,
                          "targB did not append its own address");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief An intermediate router does not let a worse-Rank sender's RREQ-DIO
 *        overwrite the target record a better-Rank sender already
 *        contributed.
 *
 * RFC 9854 section 6.2.2: "An incoming RREQ-DIO message having multiple ART
 * options coming from a router with higher Rank than the Rank of the stored
 * targets is ignored." design-constraints.md section 42.2 records the design
 * decision not to track a separate per-target Rank for this: the existing
 * from != dodag.preferredParent guard in HandleAodvRreq(), combined with
 * SelectPreferredParent() only ever moving to an equal-or-better Rank,
 * already keeps a worse-Rank sender's copy from reaching the intersection
 * step at all. RplAodvMultiArtIntersectionTestCase only exercises the
 * opposite order (worse first, then better); this is the order that
 * actually matters for the RFC sentence above -- a worse-Rank copy arriving
 * *after* a better one is already established must be ignored outright, not
 * intersected in.
 */
class RplAodvMultiArtWorseRankIgnoredTestCase : public TestCase
{
  public:
    RplAodvMultiArtWorseRankIgnoredTestCase();

  private:
    void DoRun() override;
};

RplAodvMultiArtWorseRankIgnoredTestCase::RplAodvMultiArtWorseRankIgnoredTestCase()
    : TestCase("An AODV-RPL intermediate router ignores a worse-Rank sender's multi-ART RREQ-DIO")
{
}

void
RplAodvMultiArtWorseRankIgnoredTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(1);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    ipv6.AssignWithoutAddress(devices);

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    Simulator::Stop(Seconds(2));
    Simulator::Run();

    Ptr<Node> node = nodes.Get(0);
    Ptr<RplRoutingProtocol> rpl = node->GetObject<RplRoutingProtocol>();
    Ipv6Address nodeLinkLocal = node->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    static constexpr uint8_t RREQ_INSTANCE = 0x86;
    Ipv6Address origNode("2001:9::1");
    Ipv6Address neighbourA("fe80::a"); // better: rank 128, carries (T1, T2)
    Ipv6Address neighbourB("fe80::b"); // worse: rank 384, carries (T2, T4)
    Ipv6Address t1("2001:9::11");
    Ipv6Address t2("2001:9::12");
    Ipv6Address t4("2001:9::14");

    auto buildRreq = [&](uint16_t rank, const std::vector<Ipv6Address>& targets) {
        RplDioHeader dio;
        dio.SetInstanceId(RREQ_INSTANCE);
        dio.SetVersionNumber(0);
        dio.SetRank(rank);
        dio.SetMop(RPL_MOP_P2P_ROUTE_DISCOVERY);
        dio.SetDodagId(origNode);
        dio.SetDtsn(0);
        dio.SetDagConfiguration(0,
                                8,
                                RPL_DIO_REDUNDANCY,
                                RPL_MAX_RANKINC,
                                RPL_MIN_HOPRANKINC,
                                RPL_OCP_OF0,
                                RPL_DEFAULT_LIFETIME,
                                RPL_DEFAULT_LIFETIME_UNIT);
        RplDioHeader::RreqOption rreq;
        rreq.symmetric = true;
        rreq.hopByHop = false;
        rreq.compr = 0;
        rreq.lifetime = 0;
        rreq.rankLimit = 0;
        rreq.origSeqNo = 1;
        rreq.addressVector = {};
        dio.SetRreq(rreq);
        for (const auto& target : targets)
        {
            RplDioHeader::ArtOption art;
            art.destSeqNo = 0;
            art.prefixLength = 0;
            art.target = target;
            dio.AddArt(art);
        }
        return dio;
    };
    auto deliverRreq = [&](Ipv6Address from, uint16_t rank, const std::vector<Ipv6Address>& targets) {
        Simulator::Schedule(Seconds(0),
                            &DeliverRawRplMessage<RplDioHeader>,
                            node,
                            1,
                            buildRreq(rank, targets),
                            static_cast<uint8_t>(RPL_CODE_DIO),
                            from,
                            nodeLinkLocal);
        Simulator::Stop(MilliSeconds(10));
        Simulator::Run();
    };

    // The better RREQ-DIO, from A, arrives first and is joined -- seeding
    // the target record outright, the same as RplAodvMultiArtIntersectionTestCase's
    // own first delivery.
    deliverRreq(neighbourA, 128, {t1, t2});
    std::vector<Ipv6Address> targets;
    NS_TEST_ASSERT_MSG_EQ(rpl->GetAodvTargets(RREQ_INSTANCE, origNode, targets),
                          true,
                          "Not joined to the RREQ-Instance after the first RREQ-DIO");
    NS_TEST_ASSERT_MSG_EQ(targets.size(), 2, "Wrong target count after the first RREQ-DIO");

    // The worse RREQ-DIO, from B, arrives second, carrying a different
    // target list (T2, T4). RFC 9854 section 6.2.2: a worse-Rank sender's
    // multi-ART RREQ-DIO "is ignored" -- the stored record must stay
    // exactly (T1, T2), not shrink to the intersection with (T2, T4), which
    // would incorrectly drop T1.
    deliverRreq(neighbourB, 384, {t2, t4});
    NS_TEST_ASSERT_MSG_EQ(rpl->GetAodvTargets(RREQ_INSTANCE, origNode, targets),
                          true,
                          "Not joined to the RREQ-Instance after the second RREQ-DIO");
    NS_TEST_ASSERT_MSG_EQ(targets.size(),
                          2,
                          "A worse-Rank sender's RREQ-DIO was intersected in instead of ignored");
    NS_TEST_ASSERT_MSG_EQ(targets[0], t1, "T1 was incorrectly dropped by the worse-Rank sender");
    NS_TEST_ASSERT_MSG_EQ(targets[1], t2, "T2 is still present");
    NS_TEST_ASSERT_MSG_EQ(rpl->GetRankIn(RREQ_INSTANCE, origNode),
                          256,
                          "The preferred parent should still be A, not have switched to B");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A TargNode with no other targets left to relay stops transmitting
 *        RREQ-DIOs for that instance altogether.
 *
 * RFC 9854 section 6.2.2: "If the intersection is empty, it means that all
 * the targets have been reached, and the router MUST NOT transmit any
 * RREQ-DIO." A sole-target discovery's TargNode reaches that state the moment
 * it deletes its own (only) ART entry, so this is also a regression check
 * against the pre-multi-ART behaviour, which kept Trickle-firing an
 * RREQ-DIO for as long as the RREQ-Instance's own 'L' deadline allowed even
 * after the sole TargNode had already answered.
 *
 * One node under test and a peer that doubles as both the fabricated
 * OrigNode and the monitor for anything the node under test transmits --
 * RplAodvMopAcceptedTestCase's own two-node recipe, reused here because a
 * plain unit-style single node (as the other new test cases in this file
 * use) cannot observe what does or does not go out over the wire.
 */
class RplAodvMultiArtStopsWhenExhaustedTestCase : public TestCase
{
  public:
    RplAodvMultiArtStopsWhenExhaustedTestCase();

  private:
    void DoRun() override;

    /**
     * @brief Count an RREQ-DIO seen at the monitor.
     * @param socket the monitoring socket
     */
    void CountRreqDio(Ptr<Socket> socket);

    uint32_t m_rreqDioCount{0}; //!< RREQ-DIOs (dio.HasRreq()) seen at the monitor
};

RplAodvMultiArtStopsWhenExhaustedTestCase::RplAodvMultiArtStopsWhenExhaustedTestCase()
    : TestCase("An AODV-RPL TargNode with no targets left to relay stops sending RREQ-DIOs")
{
}

void
RplAodvMultiArtStopsWhenExhaustedTestCase::CountRreqDio(Ptr<Socket> socket)
{
    Address sender;
    Ptr<Packet> packet = socket->RecvFrom(sender);
    if (!packet)
    {
        return;
    }
    Ipv6Header ipv6Header;
    packet->RemoveHeader(ipv6Header);
    Icmpv6Header icmpv6Header;
    packet->RemoveHeader(icmpv6Header);
    if (icmpv6Header.GetType() != ICMPV6_RPL || icmpv6Header.GetCode() != RPL_CODE_DIO)
    {
        return;
    }
    RplDioHeader dio;
    packet->RemoveHeader(dio);
    if (dio.HasRreq())
    {
        m_rreqDioCount++;
    }
}

void
RplAodvMultiArtStopsWhenExhaustedTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2); // 0 = the node under test, 1 = peer/OrigNode/monitor

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    interfaces.SetForwarding(0, true);
    interfaces.SetForwarding(1, true);

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(10));
    Simulator::Run();

    Ptr<Node> node = nodes.Get(0);
    Ptr<RplRoutingProtocol> rpl = node->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> peer = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(rpl->IsJoined(), true, "The base DODAG never formed");
    NS_TEST_ASSERT_MSG_EQ(peer->IsJoined(), true, "The peer never joined the base DODAG");

    Ipv6Address nodeLinkLocal = node->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address peerLinkLocal =
        nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    Ptr<Socket> monitor = Socket::CreateSocket(nodes.Get(1), Ipv6RawSocketFactory::GetTypeId());
    monitor->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    monitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    monitor->BindToNetDevice(nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetNetDevice(1));
    monitor->SetRecvCallback(MakeCallback(&RplAodvMultiArtStopsWhenExhaustedTestCase::CountRreqDio,
                                          this));

    static constexpr uint8_t RREQ_INSTANCE = 0x84;
    Ipv6Address origNode = peer->GetGlobalAddress();
    NS_TEST_ASSERT_MSG_NE(origNode, Ipv6Address::GetAny(), "The peer has no global address yet");
    Ipv6Address nodeAddress = rpl->GetGlobalAddress();
    NS_TEST_ASSERT_MSG_NE(nodeAddress, Ipv6Address::GetAny(), "The node has no global address yet");

    RplDioHeader rreqDio;
    rreqDio.SetInstanceId(RREQ_INSTANCE);
    rreqDio.SetVersionNumber(0);
    rreqDio.SetRank(RPL_MIN_HOPRANKINC);
    rreqDio.SetMop(RPL_MOP_P2P_ROUTE_DISCOVERY);
    rreqDio.SetDodagId(origNode);
    rreqDio.SetDtsn(0);
    rreqDio.SetDagConfiguration(0,
                                20,
                                RPL_DIO_REDUNDANCY,
                                RPL_MAX_RANKINC,
                                RPL_MIN_HOPRANKINC,
                                RPL_OCP_OF0,
                                RPL_DEFAULT_LIFETIME,
                                RPL_DEFAULT_LIFETIME_UNIT);
    RplDioHeader::RreqOption rreq;
    rreq.symmetric = true;
    rreq.hopByHop = false;
    rreq.compr = 0;
    rreq.lifetime = 0;
    rreq.rankLimit = 0;
    rreq.origSeqNo = 1;
    rreqDio.SetRreq(rreq);
    // The node under test's own address as the sole ART target: it becomes
    // the TargNode of a single-target discovery, the case that used to keep
    // Trickle-firing RREQ-DIOs indefinitely.
    RplDioHeader::ArtOption art;
    art.destSeqNo = 0;
    art.prefixLength = 0;
    art.target = nodeAddress;
    rreqDio.AddArt(art);

    DeliverRawRplMessage<RplDioHeader>(node,
                                       1,
                                       rreqDio,
                                       static_cast<uint8_t>(RPL_CODE_DIO),
                                       peerLinkLocal,
                                       nodeLinkLocal);

    NS_TEST_ASSERT_MSG_EQ(rpl->IsAodvTarget(RREQ_INSTANCE, origNode),
                          true,
                          "The node did not recognise itself in the ART option");
    std::vector<Ipv6Address> targets;
    NS_TEST_ASSERT_MSG_EQ(rpl->GetAodvTargets(RREQ_INSTANCE, origNode, targets),
                          true,
                          "The node did not join the RREQ-Instance");
    NS_TEST_ASSERT_MSG_EQ(targets.empty(),
                          true,
                          "The sole target should have been deleted from its own record");

    // AodvDioIntervalMin defaults to 128 ms; several doublings still land
    // well inside this wait, 2*Imax margin against catching zero firings by
    // sheer bad luck (@see ns3-debug-pitfalls).
    Simulator::Stop(Seconds(5));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(m_rreqDioCount,
                          0,
                          "An RREQ-DIO was sent after the sole target had already been reached");

    monitor->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief AodvForceAsymmetric clears the 'S' bit an intermediate router
 *        propagates, and a cleared bit stays cleared the rest of the way.
 *
 * RFC 9854 section 6.2.4 has each intermediate router decide whether the
 * link it just heard an RREQ-DIO on is symmetric, clearing 'S' if not, and
 * makes a cleared bit final: "If the S bit arrives already set to be 0, then
 * it is set to be 0 when the RREQ-DIO is propagated". Deciding symmetry for
 * real is out of the RFC's own scope (section 5) and is not implementable in
 * this module -- both metrics it keeps, ETX and RSSI-derived LQL, come off
 * received frames, so they measure the same direction and comparing them (as
 * Appendix A's example method does, against a transmit-side ETX this module
 * has no equivalent of) says nothing about asymmetry. The
 * AodvForceAsymmetric attribute stands in for that decision so the
 * asymmetric path is reachable at all.
 *
 * The same four-node line as the flood test, with the attribute set on
 * relay1 only:
 *
 *     orig(0) ---- relay1(1) ---- relay2(2) ---- targ(3)
 *
 * The OrigNode still starts at S=1 (section 6.1 gives it no choice), relay1
 * clears it, and relay2 -- which does *not* have the attribute set -- has to
 * keep it cleared rather than deciding for itself that its own link was
 * fine.
 */
class RplAodvForcedAsymmetricSBitTestCase : public TestCase
{
  public:
    RplAodvForcedAsymmetricSBitTestCase();

  private:
    void DoRun() override;
};

RplAodvForcedAsymmetricSBitTestCase::RplAodvForcedAsymmetricSBitTestCase()
    : TestCase("AodvForceAsymmetric clears the RREQ's 'S' bit, and it stays cleared downstream")
{
}

void
RplAodvForcedAsymmetricSBitTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(4); // 0 = OrigNode and base root, 1 and 2 = relays, 3 = TargNode

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    auto blacklist = [&](uint32_t a, uint32_t b) {
        Ptr<SimpleNetDevice> devA = DynamicCast<SimpleNetDevice>(devices.Get(a));
        Ptr<SimpleNetDevice> devB = DynamicCast<SimpleNetDevice>(devices.Get(b));
        channel->BlackList(devA, devB);
        channel->BlackList(devB, devA);
    };
    blacklist(0, 2);
    blacklist(0, 3);
    blacklist(1, 3);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(250));
    Simulator::Run();

    Ptr<RplRoutingProtocol> orig = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay1 = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay2 = nodes.Get(2)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> targ = nodes.Get(3)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(targ->IsJoined(), true, "The base DODAG did not reach the far end");

    // Only relay1 decides its link is asymmetric. Set after the base DODAG
    // has formed so nothing about that formation is affected either.
    relay1->SetAttribute("AodvForceAsymmetric", BooleanValue(true));

    Ipv6Address targAddress = targ->GetGlobalAddress();
    RplRoutingProtocol::DodagKey key = orig->DiscoverRoute(targAddress);
    NS_TEST_ASSERT_MSG_NE(key.dodagId, Ipv6Address::GetAny(), "The discovery did not start");

    Simulator::Stop(Seconds(10));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(relay2->IsJoinedTo(key.instanceId, key.dodagId),
                          true,
                          "relay2 never heard the RREQ");
    NS_TEST_ASSERT_MSG_EQ(targ->IsJoinedTo(key.instanceId, key.dodagId),
                          true,
                          "The TargNode never heard the RREQ");

    // The OrigNode is unaffected: section 6.1 has it originate S=1, and it
    // does not run the intermediate-router decision on its own RREQ at all.
    NS_TEST_ASSERT_MSG_EQ(orig->IsAodvSymmetric(key.instanceId, key.dodagId),
                          true,
                          "The OrigNode cleared its own 'S' bit");

    NS_TEST_ASSERT_MSG_EQ(relay1->IsAodvSymmetric(key.instanceId, key.dodagId),
                          false,
                          "AodvForceAsymmetric did not clear relay1's 'S' bit");
    NS_TEST_ASSERT_MSG_EQ(relay2->IsAodvSymmetric(key.instanceId, key.dodagId),
                          false,
                          "relay2 put the 'S' bit back up: a cleared bit is final (RFC 9854 "
                          "section 6.2.4), whatever the receiving router thinks of its own link");
    NS_TEST_ASSERT_MSG_EQ(targ->IsAodvSymmetric(key.instanceId, key.dodagId),
                          false,
                          "The TargNode saw a symmetric route despite a relay clearing 'S'");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief On an asymmetric (S=0) discovery the TargNode roots an
 *        RREP-Instance DODAG of its own instead of unicasting an answer.
 *
 * RFC 9854 section 6.3.2: with 'S' cleared, the reverse of the path the
 * RREQ took is by definition not usable, so the TargNode "MUST build a
 * DODAG in the RREP-Instance corresponding to the RREQ-DIO rooted at
 * itself" and flood it, rather than section 6.3.1's unicast back along the
 * Address Vector.
 *
 * The same four-node line, with every node forcing asymmetry so the RREQ
 * reaches the far end with 'S' clear:
 *
 *     orig(0) ---- relay1(1) ---- relay2(2) ---- targ(3)
 *
 * What this pins down is the TargNode's side only -- that the second DODAG
 * exists, is rooted at the TargNode rather than the OrigNode, carries a
 * Delta that pairs it back to the RREQ-Instance (section 6.3.3), and that
 * the RREP-DIO actually goes out. Whether the relays then join it is the
 * next test's business.
 */
class RplAodvAsymmetricRrepInstanceTestCase : public TestCase
{
  public:
    RplAodvAsymmetricRrepInstanceTestCase();

  private:
    void DoRun() override;

    /// @brief Count an RREP-DIO seen at the monitor.
    /// @param socket the monitoring socket
    void CountRrepDio(Ptr<Socket> socket);

    uint32_t m_rrepDioCount{0}; //!< RREP-carrying DIOs seen at the monitor
    uint8_t m_seenDelta{0};     //!< Delta off the last one
};

RplAodvAsymmetricRrepInstanceTestCase::RplAodvAsymmetricRrepInstanceTestCase()
    : TestCase("An asymmetric discovery has the TargNode root and flood an RREP-Instance")
{
}

void
RplAodvAsymmetricRrepInstanceTestCase::CountRrepDio(Ptr<Socket> socket)
{
    Address sender;
    Ptr<Packet> packet = socket->RecvFrom(sender);
    if (!packet)
    {
        return;
    }
    Ipv6Header ipv6Header;
    packet->RemoveHeader(ipv6Header);
    Icmpv6Header icmpv6Header;
    packet->RemoveHeader(icmpv6Header);
    if (icmpv6Header.GetType() != ICMPV6_RPL || icmpv6Header.GetCode() != RPL_CODE_DIO)
    {
        return;
    }
    RplDioHeader dio;
    packet->RemoveHeader(dio);
    if (dio.HasRrep())
    {
        m_rrepDioCount++;
        m_seenDelta = dio.GetRrep().delta;
    }
}

void
RplAodvAsymmetricRrepInstanceTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(4); // 0 = OrigNode and base root, 1 and 2 = relays, 3 = TargNode

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    auto blacklist = [&](uint32_t a, uint32_t b) {
        Ptr<SimpleNetDevice> devA = DynamicCast<SimpleNetDevice>(devices.Get(a));
        Ptr<SimpleNetDevice> devB = DynamicCast<SimpleNetDevice>(devices.Get(b));
        channel->BlackList(devA, devB);
        channel->BlackList(devB, devA);
    };
    blacklist(0, 2);
    blacklist(0, 3);
    blacklist(1, 3);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(250));
    Simulator::Run();

    Ptr<RplRoutingProtocol> orig = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay1 = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> targ = nodes.Get(3)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(targ->IsJoined(), true, "The base DODAG did not reach the far end");

    // Every relay declares its link asymmetric, so the RREQ arrives at the
    // far end with 'S' clear whichever way it was relayed.
    for (uint32_t i = 1; i < nodes.GetN(); i++)
    {
        nodes.Get(i)->GetObject<RplRoutingProtocol>()->SetAttribute("AodvForceAsymmetric",
                                                                    BooleanValue(true));
    }

    Ipv6Address origAddress = orig->GetGlobalAddress();
    Ipv6Address targAddress = targ->GetGlobalAddress();

    // Watching from relay2, the TargNode's only neighbour, so the flooded
    // RREP-DIO has somewhere real to arrive.
    Ptr<Socket> monitor = Socket::CreateSocket(nodes.Get(2), Ipv6RawSocketFactory::GetTypeId());
    monitor->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    monitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    monitor->BindToNetDevice(nodes.Get(2)->GetObject<Ipv6L3Protocol>()->GetNetDevice(1));
    monitor->SetRecvCallback(
        MakeCallback(&RplAodvAsymmetricRrepInstanceTestCase::CountRrepDio, this));

    RplRoutingProtocol::DodagKey rreqKey = orig->DiscoverRoute(targAddress);
    NS_TEST_ASSERT_MSG_NE(rreqKey.dodagId, Ipv6Address::GetAny(), "The discovery did not start");

    Simulator::Stop(Seconds(10));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(targ->IsAodvSymmetric(rreqKey.instanceId, rreqKey.dodagId),
                          false,
                          "The RREQ reached the TargNode still marked symmetric");

    // The second DODAG: rooted at the TargNode, not at the OrigNode.
    RplRoutingProtocol::DodagKey rrepKey;
    NS_TEST_ASSERT_MSG_EQ(targ->FindAodvRrepInstance(origAddress, rrepKey),
                          true,
                          "The TargNode never rooted an RREP-Instance for the asymmetric route");
    NS_TEST_ASSERT_MSG_EQ(rrepKey.dodagId,
                          targAddress,
                          "The RREP-Instance is not rooted at the TargNode's own address");
    NS_TEST_ASSERT_MSG_EQ(rrepKey.instanceId & RPL_LOCAL_INSTANCE_D_FLAG,
                          0,
                          "The RREP-Instance's Local RPLInstanceID has its 'D' flag set");

    // Section 6.3.3: Delta is what a receiver subtracts to get back to the
    // RREQ-InstanceID. Nothing else is competing for an ID at this TargNode,
    // so the first candidate (Delta 0) should have been free.
    uint8_t expectedDelta = static_cast<uint8_t>(rrepKey.instanceId - rreqKey.instanceId);
    NS_TEST_ASSERT_MSG_EQ(expectedDelta, 0, "Delta should be 0 with no competing RREP-Instance");

    // Both DODAGs at once, plus the base one.
    NS_TEST_ASSERT_MSG_EQ(targ->GetDodagCount(),
                          3,
                          "The TargNode should hold the base DODAG, the RREQ-Instance and the "
                          "RREP-Instance");

    // And the RREP-DIO actually went out, carrying that Delta.
    NS_TEST_ASSERT_MSG_GT_OR_EQ(m_rrepDioCount, 1, "No RREP-DIO was ever flooded");
    NS_TEST_ASSERT_MSG_EQ(m_seenDelta, expectedDelta, "The flooded RREP-DIO carried a wrong Delta");

    // The symmetric path is untouched: nothing was unicast back along the
    // Address Vector, so relay1 -- which would have relayed such a unicast --
    // holds no RREP-Instance of its own from that route.
    NS_TEST_ASSERT_MSG_EQ(relay1->GetAodvRouteCount(),
                          0,
                          "A relay recorded a route: the symmetric unicast path ran anyway");

    monitor->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief The RREP-Instance floods back towards the OrigNode, each relay
 *        joining it and appending itself to the RREP's own Address Vector.
 *
 * The return half of an asymmetric discovery, on the same four-node line:
 *
 *     orig(0) ---- relay1(1) ---- relay2(2) ---- targ(3)
 *
 * The RREQ-Instance floods outward O to T accumulating [relay1, relay2, T];
 * with 'S' cleared the TargNode answers by rooting an RREP-Instance and
 * flooding it back, and that flood accumulates a vector of its own in the
 * opposite order, [relay2, relay1], as RFC 9854 section 4.2 describes ("for
 * an asymmetric route, the Address Vector represents the IPv6 addresses of
 * the path through the network the RREP-DIO has passed").
 *
 * Also pins down that section 6.4.1's "discard an RREP if one of its
 * addresses is present in the Address Vector" applies here: on the
 * asymmetric path the vector really is the RREP's own, so a copy that has
 * already run through a router is a loop -- unlike on the symmetric path,
 * where the vector is the RREQ's and holds every relay by construction.
 * That relay-count assertion is what would catch the rule being applied to
 * the wrong one of the two.
 */
class RplAodvAsymmetricRrepFloodTestCase : public TestCase
{
  public:
    RplAodvAsymmetricRrepFloodTestCase();

  private:
    void DoRun() override;
};

RplAodvAsymmetricRrepFloodTestCase::RplAodvAsymmetricRrepFloodTestCase()
    : TestCase("An asymmetric RREP-Instance floods back, each relay appending itself")
{
}

void
RplAodvAsymmetricRrepFloodTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(4); // 0 = OrigNode and base root, 1 and 2 = relays, 3 = TargNode

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    auto blacklist = [&](uint32_t a, uint32_t b) {
        Ptr<SimpleNetDevice> devA = DynamicCast<SimpleNetDevice>(devices.Get(a));
        Ptr<SimpleNetDevice> devB = DynamicCast<SimpleNetDevice>(devices.Get(b));
        channel->BlackList(devA, devB);
        channel->BlackList(devB, devA);
    };
    blacklist(0, 2);
    blacklist(0, 3);
    blacklist(1, 3);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(250));
    Simulator::Run();

    Ptr<RplRoutingProtocol> orig = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay1 = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay2 = nodes.Get(2)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> targ = nodes.Get(3)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(targ->IsJoined(), true, "The base DODAG did not reach the far end");

    for (uint32_t i = 1; i < nodes.GetN(); i++)
    {
        nodes.Get(i)->GetObject<RplRoutingProtocol>()->SetAttribute("AodvForceAsymmetric",
                                                                    BooleanValue(true));
    }

    Ipv6Address origAddress = orig->GetGlobalAddress();
    Ipv6Address relay1Address = relay1->GetGlobalAddress();
    Ipv6Address relay2Address = relay2->GetGlobalAddress();
    Ipv6Address targAddress = targ->GetGlobalAddress();

    RplRoutingProtocol::DodagKey rreqKey = orig->DiscoverRoute(targAddress);
    NS_TEST_ASSERT_MSG_NE(rreqKey.dodagId, Ipv6Address::GetAny(), "The discovery did not start");

    Simulator::Stop(Seconds(10));
    Simulator::Run();

    // The RREP-Instance the TargNode rooted, found by the OrigNode it names.
    RplRoutingProtocol::DodagKey rrepKey;
    NS_TEST_ASSERT_MSG_EQ(targ->FindAodvRrepInstance(origAddress, rrepKey),
                          true,
                          "The TargNode never rooted an RREP-Instance");

    // Both relays joined it on the way back.
    NS_TEST_ASSERT_MSG_EQ(relay2->IsJoinedTo(rrepKey.instanceId, rrepKey.dodagId),
                          true,
                          "relay2 did not join the RREP-Instance");
    NS_TEST_ASSERT_MSG_EQ(relay1->IsJoinedTo(rrepKey.instanceId, rrepKey.dodagId),
                          true,
                          "relay1 did not join the RREP-Instance: the flood stopped after one hop");
    NS_TEST_ASSERT_MSG_EQ(orig->IsJoinedTo(rrepKey.instanceId, rrepKey.dodagId),
                          true,
                          "The OrigNode never heard the RREP-Instance");

    // And the Address Vector grew by one entry per hop, TargNode-side first
    // -- the opposite order from the RREQ's own vector.
    std::vector<Ipv6Address> vector;
    NS_TEST_ASSERT_MSG_EQ(targ->GetAodvAddressVector(rrepKey.instanceId, rrepKey.dodagId, vector),
                          true,
                          "No Address Vector at the TargNode");
    NS_TEST_ASSERT_MSG_EQ(vector.size(), 0, "The TargNode put itself in its own Address Vector");

    NS_TEST_ASSERT_MSG_EQ(relay2->GetAodvAddressVector(rrepKey.instanceId, rrepKey.dodagId, vector),
                          true,
                          "No Address Vector at relay2");
    NS_TEST_ASSERT_MSG_EQ(vector.size(), 1, "Wrong Address Vector size at relay2");
    NS_TEST_ASSERT_MSG_EQ(vector[0], relay2Address, "relay2 recorded the wrong address");

    NS_TEST_ASSERT_MSG_EQ(relay1->GetAodvAddressVector(rrepKey.instanceId, rrepKey.dodagId, vector),
                          true,
                          "No Address Vector at relay1");
    NS_TEST_ASSERT_MSG_EQ(vector.size(), 2, "Wrong Address Vector size at relay1");
    NS_TEST_ASSERT_MSG_EQ(vector[0],
                          relay2Address,
                          "relay1's Address Vector does not start at the TargNode's side");
    NS_TEST_ASSERT_MSG_EQ(vector[1], relay1Address, "relay1 did not append itself last");

    NS_TEST_ASSERT_MSG_EQ(orig->GetAodvAddressVector(rrepKey.instanceId, rrepKey.dodagId, vector),
                          true,
                          "No Address Vector at the OrigNode");
    NS_TEST_ASSERT_MSG_EQ(vector.size(),
                          3,
                          "The OrigNode's Address Vector should hold both relays and itself");
    NS_TEST_ASSERT_MSG_EQ(vector[0], relay2Address, "Wrong first entry at the OrigNode");
    NS_TEST_ASSERT_MSG_EQ(vector[1], relay1Address, "Wrong second entry at the OrigNode");
    NS_TEST_ASSERT_MSG_EQ(vector[2], origAddress, "The OrigNode did not append itself");

    // The base DODAG is untouched by any of this.
    NS_TEST_ASSERT_MSG_EQ(relay1->IsJoined(), true, "The base DODAG membership was lost");
    NS_TEST_ASSERT_MSG_EQ(relay1->GetDodagId(), origAddress, "The base DODAG's DODAGID changed");

    // The 'L' field takes everyone back out of the RREP-Instance too, and
    // REJOIN_REENABLE has to keep them out: neighbours are still
    // Trickle-pacing RREP-DIOs for it as each node's own deadline passes, so
    // without the bar they rejoin immediately and the instance never dies.
    // The TargNode is the worst case, exactly as the OrigNode is on the RREQ
    // side -- once its own membership is erased, nothing else stops it
    // rejoining a DODAG rooted at its own address as an ordinary member
    // (@see design-constraints.md section 35.10 for what that led to there).
    Simulator::Stop(Seconds(30));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(relay2->IsJoinedTo(rrepKey.instanceId, rrepKey.dodagId),
                          false,
                          "relay2 stayed in the RREP-Instance past its 'L' deadline");
    NS_TEST_ASSERT_MSG_EQ(relay1->IsJoinedTo(rrepKey.instanceId, rrepKey.dodagId),
                          false,
                          "relay1 stayed in the RREP-Instance past its 'L' deadline");
    NS_TEST_ASSERT_MSG_EQ(orig->IsJoinedTo(rrepKey.instanceId, rrepKey.dodagId),
                          false,
                          "The OrigNode stayed in the RREP-Instance past its 'L' deadline");
    NS_TEST_ASSERT_MSG_EQ(targ->IsJoinedTo(rrepKey.instanceId, rrepKey.dodagId),
                          false,
                          "The TargNode stayed in its own RREP-Instance past its 'L' deadline");

    // Only the base DODAG should be left anywhere.
    NS_TEST_ASSERT_MSG_EQ(targ->GetDodagCount(), 1, "The TargNode holds more than the base DODAG");
    NS_TEST_ASSERT_MSG_EQ(relay1->GetDodagCount(), 1, "relay1 holds more than the base DODAG");
    NS_TEST_ASSERT_MSG_EQ(orig->IsJoined(), true, "The OrigNode lost its base DODAG");

    // A straggler RREP-DIO for the instance everyone has just left. Every
    // node above expired within milliseconds of each other, so the flood
    // died out on its own rather than by anything refusing it; this puts
    // the refusal itself under test. Delivered straight in, addressed to
    // all-RPL-nodes so it reads as the section 6.3.2 flood it would be
    // (@see the ns3-debug-pitfalls note on why injection beats a real send
    // for this), and sourced from a fabricated neighbour so nothing else
    // has to be kept alive to produce it.
    RplDioHeader straggler;
    straggler.SetInstanceId(rrepKey.instanceId);
    straggler.SetVersionNumber(0);
    straggler.SetRank(RPL_MIN_HOPRANKINC);
    straggler.SetMop(RPL_MOP_P2P_ROUTE_DISCOVERY);
    straggler.SetDodagId(rrepKey.dodagId); // the TargNode's own address
    straggler.SetDtsn(0);
    straggler.SetDagConfiguration(0,
                                  8,
                                  RPL_DIO_REDUNDANCY,
                                  RPL_MAX_RANKINC,
                                  RPL_MIN_HOPRANKINC,
                                  RPL_OCP_OF0,
                                  RPL_DEFAULT_LIFETIME,
                                  RPL_DEFAULT_LIFETIME_UNIT);
    RplDioHeader::RrepOption stragglerRrep;
    stragglerRrep.gratuitous = false;
    stragglerRrep.hopByHop = false;
    stragglerRrep.lifetime = 1;
    stragglerRrep.rankLimit = 0;
    stragglerRrep.delta = static_cast<uint8_t>(rrepKey.instanceId - rreqKey.instanceId);
    stragglerRrep.addressVector = {};
    straggler.SetRrep(stragglerRrep);
    RplDioHeader::ArtOption stragglerArt;
    stragglerArt.destSeqNo = 1;
    stragglerArt.prefixLength = 0;
    stragglerArt.target = origAddress;
    straggler.SetArt(stragglerArt);

    DeliverRawRplMessage<RplDioHeader>(nodes.Get(3),
                                       1,
                                       straggler,
                                       static_cast<uint8_t>(RPL_CODE_DIO),
                                       Ipv6Address("fe80::c0ff:ee"),
                                       Ipv6Address(RPL_ALL_NODES_MULTICAST));

    NS_TEST_ASSERT_MSG_EQ(targ->IsJoinedTo(rrepKey.instanceId, rrepKey.dodagId),
                          false,
                          "The TargNode rejoined its own former RREP-Instance as an ordinary "
                          "member: REJOIN_REENABLE (RFC 9854 section 4.1) has to bar an "
                          "RREP-Instance the same way it bars an RREQ-Instance");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief An asymmetric discovery completes end to end: the OrigNode turns
 *        the RREP-Instance's Address Vector round into a source route, and
 *        that route carries data.
 *
 * The asymmetric counterpart of RplAodvRrepCompletesTestCase, on the same
 * four-node line:
 *
 *     orig(0) ---- relay1(1) ---- relay2(2) ---- targ(3)
 *
 * The direction of the Address Vector is what this exists to pin down. On a
 * symmetric route it is the RREQ's own, accumulated OrigNode-outward and
 * carried back unchanged (RFC 9854 section 4.2), so the OrigNode can use it
 * as it stands. On an asymmetric route it is the RREP's, accumulated as the
 * flood ran the other way, so it arrives at the OrigNode reading
 * [relay2, relay1, orig] and has to be turned round into the
 * [relay1, relay2, targ] AodvRoute::hops is defined to hold. Getting that
 * backwards yields a route that looks plausible and delivers nothing, which
 * is why the check is not just on the stored hops but on a datagram
 * actually arriving.
 */
class RplAodvAsymmetricRouteCompletesTestCase : public TestCase
{
  public:
    RplAodvAsymmetricRouteCompletesTestCase();

  private:
    void DoRun() override;

    /// @brief Count a datagram delivered at the TargNode.
    /// @param socket the receiving socket
    void CountDelivery(Ptr<Socket> socket);

    /// @brief Send one datagram, as a named method Simulator::Schedule() can
    ///        resolve (Socket::Send is overloaded).
    /// @param socket the sending socket
    void SendOne(Ptr<Socket> socket);

    uint32_t m_delivered{0}; //!< datagrams that reached the TargNode
    int m_sendResult{0};     //!< what Socket::Send() returned, -1 on refusal
};

RplAodvAsymmetricRouteCompletesTestCase::RplAodvAsymmetricRouteCompletesTestCase()
    : TestCase("An asymmetric AODV-RPL route is stored the right way round and carries data")
{
}

void
RplAodvAsymmetricRouteCompletesTestCase::CountDelivery(Ptr<Socket> socket)
{
    Ptr<Packet> packet = socket->Recv();
    while (packet)
    {
        m_delivered++;
        packet = socket->Recv();
    }
}

void
RplAodvAsymmetricRouteCompletesTestCase::SendOne(Ptr<Socket> socket)
{
    m_sendResult = socket->Send(Create<Packet>(64));
}

void
RplAodvAsymmetricRouteCompletesTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(4); // 0 = OrigNode and base root, 1 and 2 = relays, 3 = TargNode

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    auto blacklist = [&](uint32_t a, uint32_t b) {
        Ptr<SimpleNetDevice> devA = DynamicCast<SimpleNetDevice>(devices.Get(a));
        Ptr<SimpleNetDevice> devB = DynamicCast<SimpleNetDevice>(devices.Get(b));
        channel->BlackList(devA, devB);
        channel->BlackList(devB, devA);
    };
    blacklist(0, 2);
    blacklist(0, 3);
    blacklist(1, 3);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(250));
    Simulator::Run();

    Ptr<RplRoutingProtocol> orig = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay1 = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay2 = nodes.Get(2)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> targ = nodes.Get(3)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(targ->IsJoined(), true, "The base DODAG did not reach the far end");

    for (uint32_t i = 1; i < nodes.GetN(); i++)
    {
        nodes.Get(i)->GetObject<RplRoutingProtocol>()->SetAttribute("AodvForceAsymmetric",
                                                                    BooleanValue(true));
    }

    Ipv6Address relay1Address = relay1->GetGlobalAddress();
    Ipv6Address relay2Address = relay2->GetGlobalAddress();
    Ipv6Address targAddress = targ->GetGlobalAddress();

    NS_TEST_ASSERT_MSG_EQ(orig->GetAodvRouteCount(), 0, "A route exists before any discovery");

    RplRoutingProtocol::DodagKey rreqKey = orig->DiscoverRoute(targAddress);
    NS_TEST_ASSERT_MSG_NE(rreqKey.dodagId, Ipv6Address::GetAny(), "The discovery did not start");

    Simulator::Stop(Seconds(10));
    Simulator::Run();

    // The route runs OrigNode-outward, whatever direction the RREP's own
    // vector accumulated in.
    std::vector<Ipv6Address> hops;
    NS_TEST_ASSERT_MSG_EQ(orig->GetAodvRoute(targAddress, hops),
                          true,
                          "The asymmetric RREP never produced a route at the OrigNode");
    NS_TEST_ASSERT_MSG_EQ(hops.size(), 3, "The discovered route has the wrong length");
    NS_TEST_ASSERT_MSG_EQ(hops[0],
                          relay1Address,
                          "The route starts at the wrong end: relay1 is the OrigNode's own "
                          "neighbour, so it has to come first");
    NS_TEST_ASSERT_MSG_EQ(hops[1], relay2Address, "Wrong second hop");
    NS_TEST_ASSERT_MSG_EQ(hops[2], targAddress, "The route does not end at the TargNode");
    NS_TEST_ASSERT_MSG_EQ(orig->GetAodvRouteCount(), 1, "Wrong number of routes");

    // Source routing keeps no per-hop state, on this path as on the
    // symmetric one.
    NS_TEST_ASSERT_MSG_EQ(relay1->GetAodvRouteCount(), 0, "relay1 recorded a route it should not");
    NS_TEST_ASSERT_MSG_EQ(relay2->GetAodvRouteCount(), 0, "relay2 recorded a route it should not");

    // And it works. A route stored backwards would still have three entries
    // and still look like a path; only actually sending over it tells the
    // difference.
    uint16_t port = 4243;
    Ptr<Socket> receiver = Socket::CreateSocket(nodes.Get(3), UdpSocketFactory::GetTypeId());
    receiver->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), port));
    receiver->SetRecvCallback(
        MakeCallback(&RplAodvAsymmetricRouteCompletesTestCase::CountDelivery, this));

    Ptr<Socket> sender = Socket::CreateSocket(nodes.Get(0), UdpSocketFactory::GetTypeId());
    sender->Connect(Inet6SocketAddress(targAddress, port));
    Simulator::Schedule(Seconds(1),
                        &RplAodvAsymmetricRouteCompletesTestCase::SendOne,
                        this,
                        sender);

    Simulator::Stop(Seconds(5));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_GT(m_sendResult, 0, "Socket::Send() refused the datagram outright");
    NS_TEST_ASSERT_MSG_EQ(m_delivered,
                          1,
                          "The datagram never reached the TargNode over the asymmetric route");

    receiver->Close();
    sender->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief An asymmetric AODV-RPL Hop-by-hop Route (H=1) discovery completes,
 *        using the RREP-Instance's own preferred parent as the downward next
 *        hop, and carries data ("Increment B").
 *
 * The H=1 analogue of RplAodvAsymmetricRouteCompletesTestCase, on the same
 * four-node line with AodvForceAsymmetric set the same way (every node but
 * the OrigNode). RFC 9854 section 6.4.3: "For an asymmetric route, the Next
 * Hop [of the downward route entry] is the preferred parent in the DODAG of
 * RREP-Instance" -- unlike the symmetric case, where the RREP-DIO is
 * unicast hop-by-hop so the sender (from) already is the next hop by
 * construction, the RREP-Instance is a flooded DODAG, so what matters is
 * dodag.preferredParent as SelectPreferredParent() has resolved it, not
 * whichever copy HandleAodvRrepInstance() happens to be processing. Getting
 * that backwards is exactly the kind of thing that looks plausible in the
 * stored state but delivers nothing, which is why this checks a datagram
 * actually arriving, not just the recorded next hops.
 *
 * Also confirms the upward route toward OrigNode still forms at every hop
 * despite the S bit clearing partway through the discovery: RFC 9854
 * section 6.2.3's own upward-route-building step has no S bit qualifier at
 * all, unlike section 6.2.4's choice of which kind of reply to generate --
 * this module used to (incorrectly) refuse H=1 outright once S cleared,
 * fixed as part of enabling this increment.
 */
class RplAodvAsymmetricHopByHopRouteCompletesTestCase : public TestCase
{
  public:
    RplAodvAsymmetricHopByHopRouteCompletesTestCase();

  private:
    void DoRun() override;

    /// @brief Count a datagram delivered at the TargNode.
    /// @param socket the receiving socket
    void CountDelivery(Ptr<Socket> socket);

    uint32_t m_delivered{0}; //!< datagrams that reached the TargNode
};

RplAodvAsymmetricHopByHopRouteCompletesTestCase::RplAodvAsymmetricHopByHopRouteCompletesTestCase()
    : TestCase("An asymmetric AODV-RPL Hop-by-hop Route (H=1) uses the preferred parent and "
               "carries data")
{
}

void
RplAodvAsymmetricHopByHopRouteCompletesTestCase::CountDelivery(Ptr<Socket> socket)
{
    Ptr<Packet> packet = socket->Recv();
    while (packet)
    {
        m_delivered++;
        packet = socket->Recv();
    }
}

void
RplAodvAsymmetricHopByHopRouteCompletesTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(4); // 0 = OrigNode and base root, 1 and 2 = relays, 3 = TargNode

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    auto blacklist = [&](uint32_t a, uint32_t b) {
        Ptr<SimpleNetDevice> devA = DynamicCast<SimpleNetDevice>(devices.Get(a));
        Ptr<SimpleNetDevice> devB = DynamicCast<SimpleNetDevice>(devices.Get(b));
        channel->BlackList(devA, devB);
        channel->BlackList(devB, devA);
    };
    blacklist(0, 2);
    blacklist(0, 3);
    blacklist(1, 3);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(250));
    Simulator::Run();

    Ptr<RplRoutingProtocol> orig = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay1 = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay2 = nodes.Get(2)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> targ = nodes.Get(3)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(targ->IsJoined(), true, "The base DODAG did not reach the far end");

    for (uint32_t i = 1; i < nodes.GetN(); i++)
    {
        nodes.Get(i)->GetObject<RplRoutingProtocol>()->SetAttribute("AodvForceAsymmetric",
                                                                    BooleanValue(true));
    }

    Ipv6Address origAddress = orig->GetGlobalAddress();
    Ipv6Address targAddress = targ->GetGlobalAddress();
    Ipv6Address origLinkLocal =
        nodes.Get(0)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address relay1LinkLocal =
        nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address relay2LinkLocal =
        nodes.Get(2)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address targLinkLocal =
        nodes.Get(3)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    RplRoutingProtocol::DodagKey rreqKey = orig->DiscoverRoute(targAddress, true);
    NS_TEST_ASSERT_MSG_NE(rreqKey.dodagId, Ipv6Address::GetAny(), "The discovery did not start");

    Simulator::Stop(Seconds(10));
    Simulator::Run();

    // No H=0 route recorded anywhere.
    NS_TEST_ASSERT_MSG_EQ(orig->GetAodvRouteCount(), 0, "A source-routed route was recorded");

    // The downward route toward TargNode, from each router's own preferred
    // parent in the RREP-Instance -- link-local, the same reason the
    // symmetric case's own upward/downward entries are (@see
    // RplAodvHopByHopRouteCompletesTestCase, no Address Vector to draw a
    // global address from).
    Ipv6Address nextHop;
    uint8_t hopInstanceId = 0;
    NS_TEST_ASSERT_MSG_EQ(orig->GetHopByHopRoute(targAddress, nextHop, hopInstanceId),
                          true,
                          "OrigNode never recorded a downward Hop-by-hop Route");
    NS_TEST_ASSERT_MSG_EQ(nextHop, relay1LinkLocal, "OrigNode's own downward next hop is wrong");
    NS_TEST_ASSERT_MSG_EQ(hopInstanceId,
                          rreqKey.instanceId,
                          "The stored instanceId should be the RREQ-InstanceID, not the "
                          "RREP-Instance's own");

    NS_TEST_ASSERT_MSG_EQ(relay1->GetHopByHopRoute(targAddress, nextHop, hopInstanceId),
                          true,
                          "relay1 never recorded a downward Hop-by-hop Route");
    NS_TEST_ASSERT_MSG_EQ(nextHop, relay2LinkLocal, "relay1's own downward next hop is wrong");

    NS_TEST_ASSERT_MSG_EQ(relay2->GetHopByHopRoute(targAddress, nextHop, hopInstanceId),
                          true,
                          "relay2 never recorded a downward Hop-by-hop Route");
    NS_TEST_ASSERT_MSG_EQ(nextHop, targLinkLocal, "relay2's own downward next hop is wrong");

    // The upward route toward OrigNode still forms at every hop, despite S
    // clearing partway through -- section 6.2.3 is unconditional on S.
    NS_TEST_ASSERT_MSG_EQ(relay1->GetHopByHopRoute(origAddress, nextHop, hopInstanceId),
                          true,
                          "relay1 never recorded an upward Hop-by-hop Route");
    NS_TEST_ASSERT_MSG_EQ(nextHop, origLinkLocal, "relay1's own upward next hop is wrong");
    NS_TEST_ASSERT_MSG_EQ(relay2->GetHopByHopRoute(origAddress, nextHop, hopInstanceId),
                          true,
                          "relay2 never recorded an upward Hop-by-hop Route");
    NS_TEST_ASSERT_MSG_EQ(nextHop, relay1LinkLocal, "relay2's own upward next hop is wrong");
    NS_TEST_ASSERT_MSG_EQ(targ->GetHopByHopRoute(origAddress, nextHop, hopInstanceId),
                          true,
                          "targ never recorded an upward Hop-by-hop Route");
    NS_TEST_ASSERT_MSG_EQ(nextHop, relay2LinkLocal, "targ's own upward next hop is wrong");

    // And it works: a datagram sent to the TargNode has to traverse both
    // relays via their own independent next-hop lookups, not a Routing
    // Header (none was ever attached).
    uint16_t port = 4250;
    Ptr<Socket> receiver = Socket::CreateSocket(nodes.Get(3), UdpSocketFactory::GetTypeId());
    receiver->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), port));
    receiver->SetRecvCallback(
        MakeCallback(&RplAodvAsymmetricHopByHopRouteCompletesTestCase::CountDelivery, this));

    Ptr<Socket> sender = Socket::CreateSocket(nodes.Get(0), UdpSocketFactory::GetTypeId());
    sender->Connect(Inet6SocketAddress(targAddress, port));
    sender->Send(Create<Packet>(64));

    Simulator::Stop(Seconds(2));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(m_delivered,
                          1,
                          "The datagram never reached the TargNode over the asymmetric "
                          "Hop-by-hop Route");

    receiver->Close();
    sender->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief An AODV-RPL discovery completes end to end: the RREP comes back
 *        along the Address Vector and the route it delivers carries data.
 *
 * The return half of RFC 9854 route discovery, on the same four-node line
 * the outward half uses:
 *
 *     orig(0) ---- relay1(1) ---- relay2(2) ---- targ(3)
 *
 * The TargNode answers the RREQ with an RREP-DIO unicast back along the
 * Address Vector (section 6.3.1); each relay passes it one hop further
 * without recording anything, since a source-routed (H=0) route keeps no
 * per-hop state; the OrigNode recognises its own address in the ART option
 * (section 6.4.2) and keeps the vector as a source route.
 *
 * What this pins down beyond the bookkeeping is that the route works:
 * a UDP datagram sent to the TargNode has to traverse both relays, which
 * only happens if RouteOutput() picked the discovered route, if
 * PrepareOutgoingPacket() turned it into a Routing Header, and if
 * RplIpv6ExtensionSourceRouting::Process() walked it hop by hop.
 */
class RplAodvRrepCompletesTestCase : public TestCase
{
  public:
    RplAodvRrepCompletesTestCase();

  private:
    void DoRun() override;

    /**
     * @brief Count a datagram delivered at the TargNode.
     * @param socket the receiving socket
     */
    void CountDelivery(Ptr<Socket> socket);

    /**
     * @brief Send one datagram. A named method rather than the Socket::Send
     *        overload set, which Simulator::Schedule() cannot resolve.
     * @param socket the sending socket
     */
    void SendOne(Ptr<Socket> socket);

    uint32_t m_delivered{0}; //!< datagrams that reached the TargNode
    int m_sendResult{0};     //!< what Socket::Send() returned, -1 on refusal
};

RplAodvRrepCompletesTestCase::RplAodvRrepCompletesTestCase()
    : TestCase("An AODV-RPL RREP returns a source route that carries data end to end")
{
}

void
RplAodvRrepCompletesTestCase::CountDelivery(Ptr<Socket> socket)
{
    Ptr<Packet> packet = socket->Recv();
    while (packet)
    {
        m_delivered++;
        packet = socket->Recv();
    }
}

void
RplAodvRrepCompletesTestCase::SendOne(Ptr<Socket> socket)
{
    m_sendResult = socket->Send(Create<Packet>(64));
}

void
RplAodvRrepCompletesTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(4); // 0 = OrigNode and base root, 1 and 2 = relays, 3 = TargNode

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    auto blacklist = [&](uint32_t a, uint32_t b) {
        Ptr<SimpleNetDevice> devA = DynamicCast<SimpleNetDevice>(devices.Get(a));
        Ptr<SimpleNetDevice> devB = DynamicCast<SimpleNetDevice>(devices.Get(b));
        channel->BlackList(devA, devB);
        channel->BlackList(devB, devA);
    };
    blacklist(0, 2);
    blacklist(0, 3);
    blacklist(1, 3);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(250));
    Simulator::Run();

    Ptr<RplRoutingProtocol> orig = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay1 = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay2 = nodes.Get(2)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> targ = nodes.Get(3)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(targ->IsJoined(), true, "The base DODAG did not reach the far end");

    Ipv6Address relay1Address = relay1->GetGlobalAddress();
    Ipv6Address relay2Address = relay2->GetGlobalAddress();
    Ipv6Address targAddress = targ->GetGlobalAddress();

    NS_TEST_ASSERT_MSG_EQ(orig->GetAodvRouteCount(), 0, "A route exists before any discovery");

    RplRoutingProtocol::DodagKey key = orig->DiscoverRoute(targAddress);
    NS_TEST_ASSERT_MSG_NE(key.dodagId, Ipv6Address::GetAny(), "The discovery did not start");

    Simulator::Stop(Seconds(10));
    Simulator::Run();

    // The OrigNode holds the whole path, TargNode last.
    std::vector<Ipv6Address> hops;
    NS_TEST_ASSERT_MSG_EQ(orig->GetAodvRoute(targAddress, hops),
                          true,
                          "The RREP never made it back to the OrigNode");
    NS_TEST_ASSERT_MSG_EQ(hops.size(), 3, "The discovered route has the wrong length");
    NS_TEST_ASSERT_MSG_EQ(hops[0], relay1Address, "Wrong first hop");
    NS_TEST_ASSERT_MSG_EQ(hops[1], relay2Address, "Wrong second hop");
    NS_TEST_ASSERT_MSG_EQ(hops[2], targAddress, "The route does not end at the TargNode");
    NS_TEST_ASSERT_MSG_EQ(orig->GetAodvRouteCount(), 1, "Wrong number of routes");

    // A source-routed route leaves nothing behind on the way: RFC 9854
    // section 6.4.3 builds a per-hop route entry only for H=1.
    NS_TEST_ASSERT_MSG_EQ(relay1->GetAodvRouteCount(), 0, "relay1 recorded a route it should not");
    NS_TEST_ASSERT_MSG_EQ(relay2->GetAodvRouteCount(), 0, "relay2 recorded a route it should not");
    NS_TEST_ASSERT_MSG_EQ(targ->GetAodvRouteCount(), 0, "The TargNode recorded a route");

    // And the route works. Two hops of relaying, so this only arrives if the
    // Routing Header was built from the discovered route and processed at
    // each hop.
    uint16_t port = 4242;
    Ptr<Socket> receiver = Socket::CreateSocket(nodes.Get(3), UdpSocketFactory::GetTypeId());
    receiver->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), port));
    receiver->SetRecvCallback(MakeCallback(&RplAodvRrepCompletesTestCase::CountDelivery, this));

    Ptr<Socket> sender = Socket::CreateSocket(nodes.Get(0), UdpSocketFactory::GetTypeId());
    sender->Connect(Inet6SocketAddress(targAddress, port));
    Simulator::Schedule(Seconds(1), &RplAodvRrepCompletesTestCase::SendOne, this, sender);

    Simulator::Stop(Seconds(5));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_GT(m_sendResult, 0, "Socket::Send() refused the datagram outright");
    NS_TEST_ASSERT_MSG_EQ(m_delivered,
                          1,
                          "The datagram never reached the TargNode over the discovered route");

    receiver->Close();
    sender->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief AODV-RPL's own Hop-by-hop Route (H=1) discovery completes a
 *        symmetric route and carries data end to end in both directions.
 *
 * The AODV-RPL analogue of RplP2pHopByHopRouteCompletesTestCase, over the
 * same four-node line RplAodvRrepCompletesTestCase's own H=0 test uses:
 *
 *     orig(0) ---- relay1(1) ---- relay2(2) ---- targ(3)
 *
 * Unlike P2P-RPL's H=1, which only ever travels one way (Origin to Target,
 * RFC 6997 sections 9.6/9.7), AODV-RPL's is bidirectional (RFC 9854 section
 * 4.1's 'D' flag): OrigNode needs a downward route to TargNode and TargNode
 * needs an upward one back to OrigNode, and every router in between holds
 * both, recorded from opposite ends -- the upward one when the RREQ-DIO
 * passed through (HandleAodvRreq()), the downward one when the RREP-DIO
 * passed back through (HandleAodvRrep()). @see design-constraints.md.
 */
class RplAodvHopByHopRouteCompletesTestCase : public TestCase
{
  public:
    RplAodvHopByHopRouteCompletesTestCase();

  private:
    void DoRun() override;

    /// @brief Count a datagram delivered at either end.
    /// @param socket the receiving socket
    void CountDelivery(Ptr<Socket> socket);

    /// @brief Send one datagram, as a named method Simulator::Schedule() can
    ///        resolve (Socket::Send is overloaded).
    /// @param socket the sending socket
    void SendOne(Ptr<Socket> socket);

    uint32_t m_delivered{0}; //!< datagrams delivered, either direction
};

RplAodvHopByHopRouteCompletesTestCase::RplAodvHopByHopRouteCompletesTestCase()
    : TestCase("An AODV-RPL Hop-by-hop Route (H=1) carries data end to end, both directions")
{
}

void
RplAodvHopByHopRouteCompletesTestCase::CountDelivery(Ptr<Socket> socket)
{
    Ptr<Packet> packet = socket->Recv();
    while (packet)
    {
        m_delivered++;
        packet = socket->Recv();
    }
}

void
RplAodvHopByHopRouteCompletesTestCase::SendOne(Ptr<Socket> socket)
{
    socket->Send(Create<Packet>(64));
}

void
RplAodvHopByHopRouteCompletesTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(4); // 0 = OrigNode and base root, 1 and 2 = relays, 3 = TargNode

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    auto blacklist = [&](uint32_t a, uint32_t b) {
        Ptr<SimpleNetDevice> devA = DynamicCast<SimpleNetDevice>(devices.Get(a));
        Ptr<SimpleNetDevice> devB = DynamicCast<SimpleNetDevice>(devices.Get(b));
        channel->BlackList(devA, devB);
        channel->BlackList(devB, devA);
    };
    blacklist(0, 2);
    blacklist(0, 3);
    blacklist(1, 3);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(250));
    Simulator::Run();

    Ptr<RplRoutingProtocol> orig = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay1 = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay2 = nodes.Get(2)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> targ = nodes.Get(3)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(targ->IsJoined(), true, "The base DODAG did not reach the far end");

    Ipv6Address origAddress = orig->GetGlobalAddress();
    Ipv6Address targAddress = targ->GetGlobalAddress();

    // AODV-RPL's H=1 has no Address Vector to draw a global next-hop
    // address from at all (that is the whole point), so it records each
    // hop's own link-local address instead, straight off the DIO's own
    // sender -- unlike P2P-RPL's H=1 and AODV-RPL's own H=0, both of which
    // resolve a global address out of an Address Vector entry (@see
    // HopByHopRoute::nextHop's own doc comment).
    Ipv6Address origLinkLocal =
        nodes.Get(0)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address relay1LinkLocal =
        nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address relay2LinkLocal =
        nodes.Get(2)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address targLinkLocal =
        nodes.Get(3)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    RplRoutingProtocol::DodagKey key = orig->DiscoverRoute(targAddress, true);
    NS_TEST_ASSERT_MSG_NE(key.dodagId, Ipv6Address::GetAny(), "The discovery did not start");

    Simulator::Stop(Seconds(10));
    Simulator::Run();

    // No H=0 route recorded anywhere: RFC 9854 sections 6.2.3/6.4.3's own
    // per-hop next-hop entries replace it entirely for H=1.
    NS_TEST_ASSERT_MSG_EQ(orig->GetAodvRouteCount(), 0, "A source-routed route was recorded");
    NS_TEST_ASSERT_MSG_EQ(relay1->GetAodvRouteCount(), 0, "relay1 recorded a source-routed route");
    NS_TEST_ASSERT_MSG_EQ(relay2->GetAodvRouteCount(), 0, "relay2 recorded a source-routed route");
    NS_TEST_ASSERT_MSG_EQ(targ->GetAodvRouteCount(), 0, "targ recorded a source-routed route");

    // The Address Vector stays empty throughout, at every router (RFC 9854
    // section 4.1: "In hop-by-hop mode (H=1), this field MUST be set to
    // zero and ignored").
    std::vector<Ipv6Address> addressVector;
    NS_TEST_ASSERT_MSG_EQ(
        orig->GetAodvAddressVector(key.instanceId, origAddress, addressVector) &&
            addressVector.empty(),
        true,
        "OrigNode's Address Vector should stay empty for H=1");
    NS_TEST_ASSERT_MSG_EQ(
        relay1->GetAodvAddressVector(key.instanceId, origAddress, addressVector) &&
            addressVector.empty(),
        true,
        "relay1's Address Vector should stay empty for H=1");
    NS_TEST_ASSERT_MSG_EQ(
        relay2->GetAodvAddressVector(key.instanceId, origAddress, addressVector) &&
            addressVector.empty(),
        true,
        "relay2's Address Vector should stay empty for H=1");
    NS_TEST_ASSERT_MSG_EQ(
        targ->GetAodvAddressVector(key.instanceId, origAddress, addressVector) &&
            addressVector.empty(),
        true,
        "targ's Address Vector should stay empty for H=1");

    // Each router's own next hop, in whichever direction(s) it needs one:
    // OrigNode and every relay need a downward one toward TargNode, and
    // every relay and TargNode need an upward one toward OrigNode -- but
    // OrigNode needs no upward one (it is already there) and TargNode needs
    // no downward one (nothing downstream of it to relay for).
    Ipv6Address nextHop;
    uint8_t hopInstanceId = 0;
    NS_TEST_ASSERT_MSG_EQ(orig->GetHopByHopRoute(targAddress, nextHop, hopInstanceId),
                          true,
                          "OrigNode never recorded a downward Hop-by-hop Route");
    NS_TEST_ASSERT_MSG_EQ(nextHop, relay1LinkLocal, "OrigNode's own downward next hop is wrong");
    NS_TEST_ASSERT_MSG_EQ(hopInstanceId, key.instanceId, "OrigNode's own instanceId is wrong");

    NS_TEST_ASSERT_MSG_EQ(relay1->GetHopByHopRoute(origAddress, nextHop, hopInstanceId),
                          true,
                          "relay1 never recorded an upward Hop-by-hop Route");
    NS_TEST_ASSERT_MSG_EQ(nextHop, origLinkLocal, "relay1's own upward next hop is wrong");
    NS_TEST_ASSERT_MSG_EQ(relay1->GetHopByHopRoute(targAddress, nextHop, hopInstanceId),
                          true,
                          "relay1 never recorded a downward Hop-by-hop Route");
    NS_TEST_ASSERT_MSG_EQ(nextHop, relay2LinkLocal, "relay1's own downward next hop is wrong");

    NS_TEST_ASSERT_MSG_EQ(relay2->GetHopByHopRoute(origAddress, nextHop, hopInstanceId),
                          true,
                          "relay2 never recorded an upward Hop-by-hop Route");
    NS_TEST_ASSERT_MSG_EQ(nextHop, relay1LinkLocal, "relay2's own upward next hop is wrong");
    NS_TEST_ASSERT_MSG_EQ(relay2->GetHopByHopRoute(targAddress, nextHop, hopInstanceId),
                          true,
                          "relay2 never recorded a downward Hop-by-hop Route");
    NS_TEST_ASSERT_MSG_EQ(nextHop, targLinkLocal, "relay2's own downward next hop is wrong");

    NS_TEST_ASSERT_MSG_EQ(targ->GetHopByHopRoute(origAddress, nextHop, hopInstanceId),
                          true,
                          "targ never recorded an upward Hop-by-hop Route");
    NS_TEST_ASSERT_MSG_EQ(nextHop, relay2LinkLocal, "targ's own upward next hop is wrong");

    // And the route works, both directions: two hops of relaying each way,
    // so a delivery only arrives if every hop's own RPI-based lookup (not a
    // Routing Header, unlike H=0) found the right next hop -- including
    // reading RFC 6550 section 5.1's 'D' flag correctly to tell the two
    // directions apart at every relay.
    uint16_t downPort = 4246;
    Ptr<Socket> downReceiver = Socket::CreateSocket(nodes.Get(3), UdpSocketFactory::GetTypeId());
    downReceiver->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), downPort));
    downReceiver->SetRecvCallback(
        MakeCallback(&RplAodvHopByHopRouteCompletesTestCase::CountDelivery, this));
    Ptr<Socket> downSender = Socket::CreateSocket(nodes.Get(0), UdpSocketFactory::GetTypeId());
    downSender->Connect(Inet6SocketAddress(targAddress, downPort));
    Simulator::Schedule(Seconds(1), &RplAodvHopByHopRouteCompletesTestCase::SendOne, this, downSender);

    uint16_t upPort = 4247;
    Ptr<Socket> upReceiver = Socket::CreateSocket(nodes.Get(0), UdpSocketFactory::GetTypeId());
    upReceiver->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), upPort));
    upReceiver->SetRecvCallback(
        MakeCallback(&RplAodvHopByHopRouteCompletesTestCase::CountDelivery, this));
    Ptr<Socket> upSender = Socket::CreateSocket(nodes.Get(3), UdpSocketFactory::GetTypeId());
    upSender->Connect(Inet6SocketAddress(origAddress, upPort));
    Simulator::Schedule(Seconds(1), &RplAodvHopByHopRouteCompletesTestCase::SendOne, this, upSender);

    Simulator::Stop(Seconds(5));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(m_delivered,
                          2,
                          "Data did not reach both ends over the discovered Hop-by-hop Route");

    downReceiver->Close();
    downSender->Close();
    upReceiver->Close();
    upSender->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief An AODV-RPL Hop-by-hop Route (H=1) discovery completes with zero
 *        intermediate routers, OrigNode and TargNode directly adjacent.
 *
 * The boundary RplAodvHopByHopRouteCompletesTestCase's own four-node line
 * cannot reach: with no relay in between, SendAodvRrep() has to source its
 * next hop from the upward Hop-by-hop Route entry pointing straight at
 * OrigNode rather than at some intermediate router, and HandleAodvRrep()'s
 * OrigNode branch has to store its own downward entry with TargNode itself
 * as the next hop, both one radio hop away in either direction.
 */
class RplAodvHopByHopRouteDirectNeighbourTestCase : public TestCase
{
  public:
    RplAodvHopByHopRouteDirectNeighbourTestCase();

  private:
    void DoRun() override;

    /// @brief Count a datagram delivered at either end.
    /// @param socket the receiving socket
    void CountDelivery(Ptr<Socket> socket);

    uint32_t m_delivered{0}; //!< datagrams delivered, either direction
};

RplAodvHopByHopRouteDirectNeighbourTestCase::RplAodvHopByHopRouteDirectNeighbourTestCase()
    : TestCase("An AODV-RPL Hop-by-hop Route (H=1) completes with no intermediate router")
{
}

void
RplAodvHopByHopRouteDirectNeighbourTestCase::CountDelivery(Ptr<Socket> socket)
{
    Ptr<Packet> packet = socket->Recv();
    while (packet)
    {
        m_delivered++;
        packet = socket->Recv();
    }
}

void
RplAodvHopByHopRouteDirectNeighbourTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2); // 0 = OrigNode and base root, 1 = TargNode

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(250));
    Simulator::Run();

    Ptr<RplRoutingProtocol> orig = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> targ = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(targ->IsJoined(), true, "The base DODAG did not reach the far end");

    Ipv6Address origAddress = orig->GetGlobalAddress();
    Ipv6Address targAddress = targ->GetGlobalAddress();
    Ipv6Address origLinkLocal =
        nodes.Get(0)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address targLinkLocal =
        nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    RplRoutingProtocol::DodagKey key = orig->DiscoverRoute(targAddress, true);
    NS_TEST_ASSERT_MSG_NE(key.dodagId, Ipv6Address::GetAny(), "The discovery did not start");

    Simulator::Stop(Seconds(5));
    Simulator::Run();

    Ipv6Address nextHop;
    uint8_t hopInstanceId = 0;
    NS_TEST_ASSERT_MSG_EQ(orig->GetHopByHopRoute(targAddress, nextHop, hopInstanceId),
                          true,
                          "OrigNode never recorded a downward Hop-by-hop Route");
    NS_TEST_ASSERT_MSG_EQ(nextHop, targLinkLocal, "OrigNode's next hop should be TargNode itself");
    NS_TEST_ASSERT_MSG_EQ(targ->GetHopByHopRoute(origAddress, nextHop, hopInstanceId),
                          true,
                          "TargNode never recorded an upward Hop-by-hop Route");
    NS_TEST_ASSERT_MSG_EQ(nextHop, origLinkLocal, "TargNode's next hop should be OrigNode itself");

    uint16_t port = 4248;
    Ptr<Socket> receiver = Socket::CreateSocket(nodes.Get(1), UdpSocketFactory::GetTypeId());
    receiver->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), port));
    receiver->SetRecvCallback(
        MakeCallback(&RplAodvHopByHopRouteDirectNeighbourTestCase::CountDelivery, this));

    Ptr<Socket> sender = Socket::CreateSocket(nodes.Get(0), UdpSocketFactory::GetTypeId());
    sender->Connect(Inet6SocketAddress(targAddress, port));
    sender->Send(Create<Packet>(64));

    Simulator::Stop(Seconds(2));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(m_delivered, 1, "Data did not reach TargNode over one radio hop");

    receiver->Close();
    sender->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief An AODV-RPL Hop-by-hop Route (H=1) keeps carrying data after the
 *        RREQ-Instance that discovered it has left, at every hop.
 *
 * The AODV-RPL analogue of RplP2pHopByHopRouteOutlivesTemporaryDagTestCase:
 * RFC 9854 section 6.2.3/6.4.3's "the lifetime is set according to DODAG
 * configuration (i.e., not the L field)" applies just as much to AODV-RPL's
 * own route entries as to P2P-RPL's, so an RREQ-Instance reaching its own
 * (typically much shorter) 'L' deadline and leaving must not disturb the
 * Hop-by-hop Route it already established. The same four-node line as
 * RplAodvHopByHopRouteCompletesTestCase, but AodvLifetime is set short and
 * data is sent only once every node's own RREQ-Instance membership has
 * already expired.
 */
class RplAodvHopByHopRouteOutlivesRreqInstanceTestCase : public TestCase
{
  public:
    RplAodvHopByHopRouteOutlivesRreqInstanceTestCase();

  private:
    void DoRun() override;

    /// @brief Count a datagram delivered at TargNode.
    /// @param socket the receiving socket
    void CountDelivery(Ptr<Socket> socket);

    uint32_t m_delivered{0}; //!< datagrams delivered at TargNode
};

RplAodvHopByHopRouteOutlivesRreqInstanceTestCase::
    RplAodvHopByHopRouteOutlivesRreqInstanceTestCase()
    : TestCase("An AODV-RPL Hop-by-hop Route (H=1) outlives the RREQ-Instance that found it")
{
}

void
RplAodvHopByHopRouteOutlivesRreqInstanceTestCase::CountDelivery(Ptr<Socket> socket)
{
    Ptr<Packet> packet = socket->Recv();
    while (packet)
    {
        m_delivered++;
        packet = socket->Recv();
    }
}

void
RplAodvHopByHopRouteOutlivesRreqInstanceTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(4); // 0 = OrigNode and base root, 1 and 2 = relays, 3 = TargNode

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    auto blacklist = [&](uint32_t a, uint32_t b) {
        Ptr<SimpleNetDevice> devA = DynamicCast<SimpleNetDevice>(devices.Get(a));
        Ptr<SimpleNetDevice> devB = DynamicCast<SimpleNetDevice>(devices.Get(b));
        channel->BlackList(devA, devB);
        channel->BlackList(devB, devA);
    };
    blacklist(0, 2);
    blacklist(0, 3);
    blacklist(1, 3);

    RplHelper rplHelper;
    // RFC 9854 section 4.1's 'L' field: 0x01 encodes 16 seconds, ample
    // margin over the discovery itself (a few hundred ms) and short enough
    // that waiting well past it is not the dominant cost of the test.
    rplHelper.Set("AodvLifetime", UintegerValue(1));
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(250));
    Simulator::Run();

    Ptr<RplRoutingProtocol> orig = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay1 = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay2 = nodes.Get(2)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> targ = nodes.Get(3)->GetObject<RplRoutingProtocol>();
    Ipv6Address targAddress = targ->GetGlobalAddress();

    RplRoutingProtocol::DodagKey key = orig->DiscoverRoute(targAddress, true);
    NS_TEST_ASSERT_MSG_NE(key.dodagId, Ipv6Address::GetAny(), "The discovery did not start");

    Simulator::Stop(Seconds(10));
    Simulator::Run();

    Ipv6Address nextHop;
    uint8_t hopInstanceId = 0;
    NS_TEST_ASSERT_MSG_EQ(orig->GetHopByHopRoute(targAddress, nextHop, hopInstanceId),
                          true,
                          "The discovery did not complete before waiting for the RREQ-Instance "
                          "to expire");

    // Wait well past AodvLifetime's own 60 seconds for every node's own
    // RREQ-Instance membership to expire.
    Simulator::Stop(Seconds(90));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(orig->IsJoinedTo(key.instanceId, key.dodagId),
                          false,
                          "OrigNode's own RREQ-Instance membership should have expired by now");
    NS_TEST_ASSERT_MSG_EQ(relay1->IsJoinedTo(key.instanceId, key.dodagId),
                          false,
                          "relay1's own RREQ-Instance membership should have expired by now");
    NS_TEST_ASSERT_MSG_EQ(relay2->IsJoinedTo(key.instanceId, key.dodagId),
                          false,
                          "relay2's own RREQ-Instance membership should have expired by now");
    NS_TEST_ASSERT_MSG_EQ(targ->IsJoinedTo(key.instanceId, key.dodagId),
                          false,
                          "targ's own RREQ-Instance membership should have expired by now");

    // The Hop-by-hop Route itself is unaffected: its own lifetime comes from
    // the DODAG Configuration Option's Default Lifetime/Lifetime Unit, not
    // the 'L' field that just took the RREQ-Instance membership away.
    NS_TEST_ASSERT_MSG_EQ(orig->GetHopByHopRoute(targAddress, nextHop, hopInstanceId),
                          true,
                          "The Hop-by-hop Route did not outlive the RREQ-Instance membership");

    uint16_t port = 4249;
    Ptr<Socket> receiver = Socket::CreateSocket(nodes.Get(3), UdpSocketFactory::GetTypeId());
    receiver->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), port));
    receiver->SetRecvCallback(
        MakeCallback(&RplAodvHopByHopRouteOutlivesRreqInstanceTestCase::CountDelivery, this));

    Ptr<Socket> sender = Socket::CreateSocket(nodes.Get(0), UdpSocketFactory::GetTypeId());
    sender->Connect(Inet6SocketAddress(targAddress, port));
    sender->Send(Create<Packet>(64));

    Simulator::Stop(Seconds(2));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(m_delivered,
                          1,
                          "Data did not reach TargNode after the RREQ-Instance had expired");

    receiver->Close();
    sender->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief An intermediate router that already caches a Hop-by-hop Route to
 *        the target short-circuits a new RREQ with a Gratuitous RREP
 *        (G-RREP), before the discovery it is relaying completes.
 *
 * RFC 9854 section 7: an intermediate router MAY unicast a G-RREP (the
 * RREP option's own 'G' bit) back towards OrigNode as soon as it finds it
 * already holds a downward route to the target at least as fresh as what
 * OrigNode already knows -- read off the RREQ-DIO's own ART option
 * destSeqNo (0 meaning "no known information"), not the RREQ option's own
 * Orig SeqNo, a different node's freshness entirely.
 *
 * Three nodes in a line, relay in the middle:
 *
 *     origB(0) ---- relay(1) ---- targ(2)
 *
 * relay first runs its own, unrelated H=1 discovery to targ (one hop,
 * direct), populating its own cache. Only then does origB start its own
 * discovery for the same target -- relay, receiving origB's RREQ, already
 * holds a fresh-enough cached route and answers directly rather than
 * waiting for the RREQ to reach targ and a real RREP to come all the way
 * back. Monitored at origB's own interface (an ICMPv6 raw socket, the same
 * technique RplAodvAsymmetricRrepInstanceTestCase uses) for an incoming
 * RREP-carrying DIO with the 'G' bit set, and confirms the resulting
 * downward Hop-by-hop Route actually carries data.
 */
class RplAodvGratuitousRrepTestCase : public TestCase
{
  public:
    RplAodvGratuitousRrepTestCase();

  private:
    void DoRun() override;

    /// @brief Note whether an RREP-carrying DIO seen at the monitor is
    ///        gratuitous.
    /// @param socket the monitoring socket
    void CountRrepDio(Ptr<Socket> socket);

    /// @brief Count a datagram delivered at TargNode.
    /// @param socket the receiving socket
    void CountDelivery(Ptr<Socket> socket);

    uint32_t m_rrepDioCount{0};      //!< RREP-carrying DIOs seen at the monitor
    uint32_t m_gratuitousCount{0};   //!< of those, how many had 'G' set
    uint32_t m_delivered{0};         //!< datagrams that reached TargNode
};

RplAodvGratuitousRrepTestCase::RplAodvGratuitousRrepTestCase()
    : TestCase("An AODV-RPL intermediate router answers a cached-route RREQ with a Gratuitous "
               "RREP")
{
}

void
RplAodvGratuitousRrepTestCase::CountRrepDio(Ptr<Socket> socket)
{
    Address sender;
    Ptr<Packet> packet = socket->RecvFrom(sender);
    if (!packet)
    {
        return;
    }
    Ipv6Header ipv6Header;
    packet->RemoveHeader(ipv6Header);
    Icmpv6Header icmpv6Header;
    packet->RemoveHeader(icmpv6Header);
    if (icmpv6Header.GetType() != ICMPV6_RPL || icmpv6Header.GetCode() != RPL_CODE_DIO)
    {
        return;
    }
    RplDioHeader dio;
    packet->RemoveHeader(dio);
    if (dio.HasRrep())
    {
        m_rrepDioCount++;
        if (dio.GetRrep().gratuitous)
        {
            m_gratuitousCount++;
        }
    }
}

void
RplAodvGratuitousRrepTestCase::CountDelivery(Ptr<Socket> socket)
{
    Ptr<Packet> packet = socket->Recv();
    while (packet)
    {
        m_delivered++;
        packet = socket->Recv();
    }
}

void
RplAodvGratuitousRrepTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(3); // 0 = origB and base root, 1 = relay, 2 = targ

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    Ptr<SimpleNetDevice> devA = DynamicCast<SimpleNetDevice>(devices.Get(0));
    Ptr<SimpleNetDevice> devC = DynamicCast<SimpleNetDevice>(devices.Get(2));
    channel->BlackList(devA, devC);
    channel->BlackList(devC, devA);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(250));
    Simulator::Run();

    Ptr<RplRoutingProtocol> origB = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> targ = nodes.Get(2)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(targ->IsJoined(), true, "The base DODAG did not reach the far end");

    Ipv6Address targAddress = targ->GetGlobalAddress();

    // relay's own, unrelated discovery: one hop, direct to targ, populating
    // relay's own cache the way any ordinary H=1 discovery would.
    RplRoutingProtocol::DodagKey relayKey = relay->DiscoverRoute(targAddress, true);
    NS_TEST_ASSERT_MSG_NE(relayKey.dodagId, Ipv6Address::GetAny(), "relay's discovery did not "
                                                                   "start");

    Simulator::Stop(Seconds(5));
    Simulator::Run();

    Ipv6Address nextHop;
    uint8_t hopInstanceId = 0;
    NS_TEST_ASSERT_MSG_EQ(relay->GetHopByHopRoute(targAddress, nextHop, hopInstanceId),
                          true,
                          "relay never cached its own route to targ");

    // Now watch origB's own interface for the G-RREP that should follow.
    Ptr<Socket> monitor = Socket::CreateSocket(nodes.Get(0), Ipv6RawSocketFactory::GetTypeId());
    monitor->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    monitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    monitor->BindToNetDevice(nodes.Get(0)->GetObject<Ipv6L3Protocol>()->GetNetDevice(1));
    monitor->SetRecvCallback(MakeCallback(&RplAodvGratuitousRrepTestCase::CountRrepDio, this));

    RplRoutingProtocol::DodagKey origKey = origB->DiscoverRoute(targAddress, true);
    NS_TEST_ASSERT_MSG_NE(origKey.dodagId, Ipv6Address::GetAny(), "origB's discovery did not "
                                                                  "start");

    Simulator::Stop(Seconds(2));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_GT_OR_EQ(m_rrepDioCount, 1, "No RREP-DIO reached origB at all");
    NS_TEST_ASSERT_MSG_GT_OR_EQ(m_gratuitousCount,
                               1,
                               "relay never answered origB's RREQ with a Gratuitous RREP, "
                               "despite already caching a route to targ");

    NS_TEST_ASSERT_MSG_EQ(origB->GetHopByHopRoute(targAddress, nextHop, hopInstanceId),
                          true,
                          "The Gratuitous RREP did not leave origB with a downward Hop-by-hop "
                          "Route");
    NS_TEST_ASSERT_MSG_EQ(hopInstanceId,
                          origKey.instanceId,
                          "The route's own instanceId should be origB's RREQ-InstanceID");

    // And it works: relay's own next hop (one radio hop from origB) has to
    // be exercised for a datagram to arrive.
    uint16_t port = 4251;
    Ptr<Socket> receiver = Socket::CreateSocket(nodes.Get(2), UdpSocketFactory::GetTypeId());
    receiver->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), port));
    receiver->SetRecvCallback(MakeCallback(&RplAodvGratuitousRrepTestCase::CountDelivery, this));

    Ptr<Socket> sender = Socket::CreateSocket(nodes.Get(0), UdpSocketFactory::GetTypeId());
    sender->Connect(Inet6SocketAddress(targAddress, port));
    sender->Send(Create<Packet>(64));

    Simulator::Stop(Seconds(2));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(m_delivered,
                          1,
                          "Data did not reach targ over the route the Gratuitous RREP provided");

    monitor->Close();
    receiver->Close();
    sender->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A Gratuitous RREP (G-RREP) fires exactly at RFC 9854 section 7's
 *        own freshness boundary: "at least as large as" includes equal,
 *        but not an incoming RREQ that already claims to know better.
 *
 * The cached route this router already holds is established via direct
 * synthetic RREQ+RREP injection (DeliverRawRplMessage(), the same style
 * RplAodvAsymmetricHopByHopRouteFollowsParentTestCase uses), which is what
 * makes its own Sequence Number precisely controllable rather than
 * whatever a real round trip through TargNode would happen to produce.
 * Both the equal case and the strictly-newer case are checked against the
 * very same cached route, ruling out a test that only demonstrates one
 * side of the boundary by coincidence of setup.
 *
 * Two nodes: node (under test) and neighbour, a real one so the resulting
 * G-RREP -- unicast to whichever address last supplied a fresh-enough
 * RREQ -- actually has somewhere to be captured and inspected.
 */
class RplAodvGratuitousRrepFreshnessBoundaryTestCase : public TestCase
{
  public:
    RplAodvGratuitousRrepFreshnessBoundaryTestCase();

  private:
    void DoRun() override;

    /// @brief Note whether an RREP-carrying DIO seen at the monitor is
    ///        gratuitous.
    /// @param socket the monitoring socket
    void CountRrepDio(Ptr<Socket> socket);

    uint32_t m_rrepDioCount{0};    //!< RREP-carrying DIOs seen at the monitor
    uint32_t m_gratuitousCount{0}; //!< of those, how many had 'G' set
};

RplAodvGratuitousRrepFreshnessBoundaryTestCase::RplAodvGratuitousRrepFreshnessBoundaryTestCase()
    : TestCase("A Gratuitous RREP fires on an equal Dest SeqNo, not a strictly newer one")
{
}

void
RplAodvGratuitousRrepFreshnessBoundaryTestCase::CountRrepDio(Ptr<Socket> socket)
{
    Address sender;
    Ptr<Packet> packet = socket->RecvFrom(sender);
    if (!packet)
    {
        return;
    }
    Ipv6Header ipv6Header;
    packet->RemoveHeader(ipv6Header);
    Icmpv6Header icmpv6Header;
    packet->RemoveHeader(icmpv6Header);
    if (icmpv6Header.GetType() != ICMPV6_RPL || icmpv6Header.GetCode() != RPL_CODE_DIO)
    {
        return;
    }
    RplDioHeader dio;
    packet->RemoveHeader(dio);
    if (dio.HasRrep())
    {
        m_rrepDioCount++;
        if (dio.GetRrep().gratuitous)
        {
            m_gratuitousCount++;
        }
    }
}

void
RplAodvGratuitousRrepFreshnessBoundaryTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2); // 0 = node under test and base root, 1 = neighbour

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(2));
    Simulator::Run();

    Ptr<Node> node = nodes.Get(0);
    Ptr<RplRoutingProtocol> rpl = node->GetObject<RplRoutingProtocol>();
    Ipv6Address nodeLinkLocal = node->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address neighbourLinkLocal =
        nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    static constexpr uint8_t CACHE_INSTANCE = 0x81;
    static constexpr uint8_t QUERY_INSTANCE_A = 0x85;
    static constexpr uint8_t QUERY_INSTANCE_B = 0x86;
    static constexpr uint8_t CACHED_SEQNO = 5;
    Ipv6Address cacheOrigin("2001:9::1");  // the discovery that seeds the cache
    Ipv6Address target("2001:9::99");      // this node is neither -- purely a relay
    Ipv6Address cacheFrom("fe80::c");      // this cache's own next hop, disposable

    auto buildRreq = [&](uint8_t instanceId, Ipv6Address dodagId, uint8_t artSeqNo) {
        RplDioHeader dio;
        dio.SetInstanceId(instanceId);
        dio.SetVersionNumber(0);
        dio.SetRank(RPL_MIN_HOPRANKINC);
        dio.SetMop(RPL_MOP_P2P_ROUTE_DISCOVERY);
        dio.SetDodagId(dodagId);
        dio.SetDtsn(0);
        dio.SetDagConfiguration(0,
                                8,
                                RPL_DIO_REDUNDANCY,
                                RPL_MAX_RANKINC,
                                RPL_MIN_HOPRANKINC,
                                RPL_OCP_OF0,
                                RPL_DEFAULT_LIFETIME,
                                RPL_DEFAULT_LIFETIME_UNIT);
        RplDioHeader::RreqOption rreq;
        rreq.symmetric = true;
        rreq.hopByHop = true;
        rreq.compr = 0;
        rreq.lifetime = 0; // no limit, keeps this test's timing simple
        rreq.rankLimit = 0;
        rreq.origSeqNo = 1;
        dio.SetRreq(rreq);
        RplDioHeader::ArtOption art;
        art.destSeqNo = artSeqNo;
        art.prefixLength = 0;
        art.target = target;
        dio.SetArt(art);
        return dio;
    };
    auto buildRrep = [&](uint8_t instanceId, Ipv6Address dodagId, uint8_t destSeqNo) {
        RplDioHeader dio;
        dio.SetInstanceId(instanceId);
        dio.SetVersionNumber(0);
        dio.SetRank(RPL_MIN_HOPRANKINC);
        dio.SetMop(RPL_MOP_P2P_ROUTE_DISCOVERY);
        dio.SetDodagId(dodagId);
        dio.SetDtsn(0);
        RplDioHeader::RrepOption rrep;
        rrep.gratuitous = false;
        rrep.hopByHop = true;
        rrep.lifetime = 0;
        rrep.rankLimit = 0;
        rrep.delta = 0;
        dio.SetRrep(rrep);
        RplDioHeader::ArtOption art;
        art.destSeqNo = destSeqNo;
        art.prefixLength = 0;
        art.target = cacheOrigin;
        dio.SetArt(art);
        return dio;
    };

    // Seed the cache: a synthetic RREQ (establishing the membership and this
    // node's own upward route towards cacheOrigin) followed by a synthetic
    // RREP (establishing the downward Hop-by-hop Route this test's own
    // Gratuitous RREP checks will be answered from), both unrelated to
    // either query that follows.
    DeliverRawRplMessage<RplDioHeader>(node,
                                       1,
                                       buildRreq(CACHE_INSTANCE, cacheOrigin, 0),
                                       static_cast<uint8_t>(RPL_CODE_DIO),
                                       cacheFrom,
                                       nodeLinkLocal);
    DeliverRawRplMessage<RplDioHeader>(node,
                                       1,
                                       buildRrep(CACHE_INSTANCE, target, CACHED_SEQNO),
                                       static_cast<uint8_t>(RPL_CODE_DIO),
                                       cacheFrom,
                                       nodeLinkLocal);
    Simulator::Stop(MilliSeconds(10));
    Simulator::Run();

    Ipv6Address nextHop;
    uint8_t hopInstanceId = 0;
    NS_TEST_ASSERT_MSG_EQ(rpl->GetHopByHopRoute(target, nextHop, hopInstanceId),
                          true,
                          "The synthetic setup did not leave a cached downward route");
    NS_TEST_ASSERT_MSG_EQ(nextHop, cacheFrom, "Wrong cached next hop after setup");

    Ptr<Socket> monitor = Socket::CreateSocket(nodes.Get(1), Ipv6RawSocketFactory::GetTypeId());
    monitor->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    monitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    monitor->BindToNetDevice(nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetNetDevice(1));
    monitor->SetRecvCallback(
        MakeCallback(&RplAodvGratuitousRrepFreshnessBoundaryTestCase::CountRrepDio, this));

    // Query A: a different OrigNode and RREQ-Instance, ART destSeqNo equal
    // to the cached route's own (5 == 5). RFC 9854 section 7's own "at
    // least as large as" includes equal -- this MUST fire.
    Ipv6Address origA("2001:9::10");
    DeliverRawRplMessage<RplDioHeader>(node,
                                       1,
                                       buildRreq(QUERY_INSTANCE_A, origA, CACHED_SEQNO),
                                       static_cast<uint8_t>(RPL_CODE_DIO),
                                       neighbourLinkLocal,
                                       nodeLinkLocal);
    Simulator::Stop(MilliSeconds(10));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(m_rrepDioCount, 1, "No RREP-DIO was sent for the equal-SeqNo query");
    NS_TEST_ASSERT_MSG_EQ(m_gratuitousCount,
                          1,
                          "An equal Dest SeqNo (RFC 9854 section 7's own \"at least as large "
                          "as\") should still fire the Gratuitous RREP");

    // Query B: yet another OrigNode and RREQ-Instance, ART destSeqNo one
    // past the cached route's own (6 > 5) -- OrigNode already claims to
    // know a fresher route than this one can offer. MUST NOT fire.
    Ipv6Address origB("2001:9::11");
    DeliverRawRplMessage<RplDioHeader>(
        node,
        1,
        buildRreq(QUERY_INSTANCE_B, origB, static_cast<uint8_t>(CACHED_SEQNO + 1)),
        static_cast<uint8_t>(RPL_CODE_DIO),
        neighbourLinkLocal,
        nodeLinkLocal);
    Simulator::Stop(MilliSeconds(10));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(m_rrepDioCount,
                          1,
                          "A strictly newer Dest SeqNo than the cached route's own should not "
                          "have produced a Gratuitous RREP");
    NS_TEST_ASSERT_MSG_EQ(m_gratuitousCount, 1, "The Gratuitous count should not have changed");

    monitor->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A Gratuitous RREP that answers OrigNode first is not disturbed by
 *        the real RREP-DIO from TargNode arriving later.
 *
 * A Gratuitous RREP is deliberately not exclusive of the ordinary
 * discovery: this module keeps relaying the RREQ over the normal multicast
 * Trickle flood regardless (RFC 9854 section 7's own further optimization
 * of unicast-relaying the RREQ along the cached route is out of scope,
 * @see design-constraints.md), so TargNode still eventually receives it and
 * answers for real -- after OrigNode already has a route from the G-RREP.
 * DodagMembership::AodvRreqState::rrepHandled, the same repeat guard
 * RplAodvRrepDuplicateRelayedOnceTestCase already covers for the ordinary
 * case, has to keep that late arrival from disturbing the state the G-RREP
 * already established.
 *
 * The same three-node line as RplAodvGratuitousRrepTestCase
 * (origB(0)--relay(1)--targ(2)), just waited on for long enough after
 * starting origB's own discovery for the ordinary flood to also reach targ
 * and a real RREP-DIO to come all the way back, on top of the G-RREP that
 * arrives first.
 */
class RplAodvGratuitousRrepThenRealRrepTestCase : public TestCase
{
  public:
    RplAodvGratuitousRrepThenRealRrepTestCase();

  private:
    void DoRun() override;
};

RplAodvGratuitousRrepThenRealRrepTestCase::RplAodvGratuitousRrepThenRealRrepTestCase()
    : TestCase("A late real RREP-DIO does not disturb a Gratuitous RREP's own state")
{
}

void
RplAodvGratuitousRrepThenRealRrepTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(3); // 0 = origB and base root, 1 = relay, 2 = targ

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    Ptr<SimpleNetDevice> devA = DynamicCast<SimpleNetDevice>(devices.Get(0));
    Ptr<SimpleNetDevice> devC = DynamicCast<SimpleNetDevice>(devices.Get(2));
    channel->BlackList(devA, devC);
    channel->BlackList(devC, devA);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(250));
    Simulator::Run();

    Ptr<RplRoutingProtocol> origB = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> targ = nodes.Get(2)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(targ->IsJoined(), true, "The base DODAG did not reach the far end");

    Ipv6Address targAddress = targ->GetGlobalAddress();
    Ipv6Address relayLinkLocal =
        nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    // relay's own, unrelated discovery seeds its cache exactly as
    // RplAodvGratuitousRrepTestCase's own does.
    RplRoutingProtocol::DodagKey relayKey = relay->DiscoverRoute(targAddress, true);
    NS_TEST_ASSERT_MSG_NE(relayKey.dodagId, Ipv6Address::GetAny(), "relay's discovery did not "
                                                                   "start");

    Simulator::Stop(Seconds(5));
    Simulator::Run();

    Ipv6Address nextHop;
    uint8_t hopInstanceId = 0;
    NS_TEST_ASSERT_MSG_EQ(relay->GetHopByHopRoute(targAddress, nextHop, hopInstanceId),
                          true,
                          "relay never cached its own route to targ");

    RplRoutingProtocol::DodagKey origKey = origB->DiscoverRoute(targAddress, true);
    NS_TEST_ASSERT_MSG_NE(origKey.dodagId, Ipv6Address::GetAny(), "origB's discovery did not "
                                                                  "start");

    // Long enough for the G-RREP to arrive almost immediately, and then for
    // the ordinary Trickle flood to also reach targ and its own real
    // RREP-DIO to come all the way back -- RplAodvHopByHopRouteCompletesTest
    // Case's own end-to-end discovery over this many hops completes well
    // within 10 seconds, so this leaves ample margin for the second,
    // slower arrival on top of that.
    Simulator::Stop(Seconds(15));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(origB->GetHopByHopRoute(targAddress, nextHop, hopInstanceId),
                          true,
                          "The downward Hop-by-hop Route disappeared once the real RREP-DIO "
                          "arrived");
    NS_TEST_ASSERT_MSG_EQ(nextHop,
                          relayLinkLocal,
                          "The route should still point at relay, whichever RREP -- Gratuitous "
                          "or real -- last happened to win rrepHandled's repeat guard");
    NS_TEST_ASSERT_MSG_EQ(hopInstanceId,
                          origKey.instanceId,
                          "The route's own instanceId should still be origB's RREQ-InstanceID");

    // And data still flows: the state the late real RREP-DIO found was not
    // left half-updated or otherwise broken.
    uint16_t port = 4252;
    Ptr<Socket> receiver = Socket::CreateSocket(nodes.Get(2), UdpSocketFactory::GetTypeId());
    receiver->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), port));
    Ptr<Socket> sender = Socket::CreateSocket(nodes.Get(0), UdpSocketFactory::GetTypeId());
    sender->Connect(Inet6SocketAddress(targAddress, port));
    int sendResult = sender->Send(Create<Packet>(64));
    NS_TEST_ASSERT_MSG_GT(sendResult, 0, "Socket::Send() refused the datagram outright");

    receiver->Close();
    sender->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A base-DODAG root that also joins another RREQ-Instance as an
 *        ordinary member must not crash when it loses that RREQ-Instance's
 *        last parent.
 *
 * RplRoutingProtocol::DoInitialize() used to call m_disTimer.SetFunction()
 * only for non-root nodes, on the assumption that a base-DODAG root
 * (m_isRoot) never needs to solicit a DODAG via DIS. AODV-RPL (RFC 9854)
 * breaks that assumption: CreateLocalDodag()/HandleAodvRreq() do not consult
 * m_isRoot at all, so the very node that roots the base DODAG can also join
 * someone else's RREQ-Instance as an ordinary (non-root) member --
 * DodagMembership::isRoot, not the node-wide m_isRoot, is what
 * SelectPreferredParent() actually checks. When that membership's only
 * neighbour goes stale, SelectPreferredParent() falls through to its generic
 * "lost the last parent, solicit again" path (the same one an ordinary
 * node's own base DODAG membership already exercises safely) and calls
 * m_disTimer.Schedule() -- asserting "m_impl != nullptr" in
 * Timer::Schedule() the first time a root ever reached it, since m_disTimer
 * had never had SetFunction() called on a root node.
 *
 * Found running an ns3-editor-generated scenario (a 5-node mesh where the
 * base DODAG root also relayed an AODV-RPL discovery between two other
 * nodes); reproduced here without ns3-editor, the same way
 * RplAodvAddressVectorFollowsParentTestCase injects a fabricated RREQ-DIO.
 */
class RplRootJoinsForeignRreqInstanceParentLossTestCase : public TestCase
{
  public:
    RplRootJoinsForeignRreqInstanceParentLossTestCase();

  private:
    void DoRun() override;
};

RplRootJoinsForeignRreqInstanceParentLossTestCase::
    RplRootJoinsForeignRreqInstanceParentLossTestCase()
    : TestCase("A base-DODAG root losing an RREQ-Instance's last parent does not crash")
{
}

void
RplRootJoinsForeignRreqInstanceParentLossTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(1);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    ipv6.AssignWithoutAddress(devices);

    // The node under test is the base DODAG's own root -- m_isRoot ends up
    // true, which is this bug's precondition.
    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    Simulator::Stop(Seconds(2));
    Simulator::Run();

    Ptr<Node> node = nodes.Get(0);
    Ptr<RplRoutingProtocol> rpl = node->GetObject<RplRoutingProtocol>();
    Ipv6Address nodeLinkLocal = node->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    static constexpr uint8_t RREQ_INSTANCE = 0x81;
    Ipv6Address origNode("2001:9::1");
    Ipv6Address onlyNeighbour("fe80::a");

    RplDioHeader dio;
    dio.SetInstanceId(RREQ_INSTANCE);
    dio.SetVersionNumber(0);
    dio.SetRank(128);
    dio.SetMop(RPL_MOP_P2P_ROUTE_DISCOVERY);
    dio.SetDodagId(origNode);
    dio.SetDtsn(0);
    dio.SetDagConfiguration(0,
                            8,
                            RPL_DIO_REDUNDANCY,
                            RPL_MAX_RANKINC,
                            RPL_MIN_HOPRANKINC,
                            RPL_OCP_OF0,
                            RPL_DEFAULT_LIFETIME,
                            RPL_DEFAULT_LIFETIME_UNIT);
    RplDioHeader::RreqOption rreq;
    rreq.symmetric = true;
    rreq.hopByHop = false;
    rreq.compr = 0;
    // Unlimited: only the staleness path below should ever fire in this
    // test, not AodvInstanceExpired()'s own (already-guarded, poison=false)
    // one -- they are different bugs, and this test is only about the first.
    rreq.lifetime = 0;
    rreq.rankLimit = 0;
    rreq.origSeqNo = 1;
    rreq.addressVector = {};
    dio.SetRreq(rreq);
    RplDioHeader::ArtOption art;
    art.destSeqNo = 0;
    art.prefixLength = 0;
    art.target = Ipv6Address("2001:9::99"); // a fake target, not this node
    dio.SetArt(art);

    Simulator::Schedule(Seconds(0),
                        &DeliverRawRplMessage<RplDioHeader>,
                        node,
                        1,
                        dio,
                        static_cast<uint8_t>(RPL_CODE_DIO),
                        onlyNeighbour,
                        nodeLinkLocal);
    Simulator::Stop(MilliSeconds(10));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(rpl->IsJoinedTo(RREQ_INSTANCE, origNode),
                          true,
                          "Did not join the fabricated RREQ-Instance");

    // Nothing more is ever sent from onlyNeighbour. Two full Trickle
    // intervals is the staleness threshold SelectPreferredParent() itself
    // uses (AodvDioIntervalMin/AodvDioIntervalDoublings default to 128ms/4,
    // so Imax is ~2.048s); waiting well past that lets the root's own
    // Trickle-fired re-evaluation of this membership find no parent left in
    // it and take the "lost the last parent" path -- which is exactly what
    // used to crash the whole process before a single assertion below could
    // even run.
    Simulator::Stop(Seconds(10));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(rpl->IsJoinedTo(RREQ_INSTANCE, origNode),
                          false,
                          "Should have left the RREQ-Instance after losing its last parent");
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A router only joins an RREP-Instance if its own Rank would stay
 *        within the RankLimit, with the OrigNode's bound relaxed by one
 *        step, mirroring the RREQ-Instance's own RankLimit check.
 *
 * RFC 9854 section 6.4.1: "If the S bit of the RREQ-Instance is set to 0,
 * the router MUST determine whether the downward direction of the link ...
 * satisfies the OF and whether the router's Rank would not exceed the
 * RankLimit. If these are true, the router joins the DODAG of the
 * RREP-Instance." Section 4.2 defines the RREP option's own RankLimit field
 * "similarly to RankLimit in the RREQ message", whose section 4.1 spells the
 * asymmetric relaxation out: "TargNode can join the RREQ-Instance at a Rank
 * ... less than or equal to the RankLimit. Any other node MUST NOT join ...
 * if its own Rank would be equal to or higher than the RankLimit." Found
 * with `/protocol-test-matrix`'s Phase 0 re-read after the S=0 work landed:
 * HandleAodvRrepInstance() had no RankLimit check of any kind, while
 * ShouldRefuseAodvRreq() already had the RREQ-Instance's own equivalent.
 *
 * One node under test, already an ordinary member of a fabricated
 * RREQ-Instance (RankLimit 3), fed fabricated RREP-DIOs for the paired
 * RREP-Instance at the boundary. With MinHopRankIncrease at its default
 * (128) and a RankLimit of 3, DAGRank 2 (rank 256) is the exact edge: a
 * relay's own resulting DAGRank would be 3, at the limit and so refused;
 * for the node the RREP-Instance is addressed to (the ART option's target,
 * i.e. this node acting as OrigNode) that same DAGRank 3 is exactly the
 * relaxed bound and so accepted -- the two cases fabricated identically
 * except for which address the ART option names.
 */
class RplAodvRrepInstanceRankLimitTestCase : public TestCase
{
  public:
    RplAodvRrepInstanceRankLimitTestCase();

  private:
    void DoRun() override;

    /**
     * @brief Fabricate a paired RREQ-Instance, then feed one RREP-DIO into
     *        it and report whether the RREP-Instance was joined.
     *
     * A fresh OrigNode/TargNode pair per call, so the sub-cases cannot
     * contaminate each other's state.
     *
     * @param rrepRank the Rank the fabricated RREP-DIO advertises
     * @param asOrigin whether the ART option should name this node (the
     *                 relaxed bound) or a fake address (the strict one)
     * @return true if the node ended up joined to the RREP-Instance
     */
    bool TryJoin(Ptr<Node> node, Ipv6Address nodeLinkLocal, uint16_t rrepRank, bool asOrigin);
};

RplAodvRrepInstanceRankLimitTestCase::RplAodvRrepInstanceRankLimitTestCase()
    : TestCase("An RREP-Instance is only joined within its RankLimit, relaxed for the OrigNode")
{
}

bool
RplAodvRrepInstanceRankLimitTestCase::TryJoin(Ptr<Node> node,
                                              Ipv6Address nodeLinkLocal,
                                              uint16_t rrepRank,
                                              bool asOrigin)
{
    static uint16_t sequence = 0;
    sequence++;
    // A fresh pair per call: fabricated addresses of convenience, distinct
    // each time so no earlier sub-case's membership or REJOIN_REENABLE
    // entry can interfere with this one's.
    std::ostringstream origSuffix;
    origSuffix << "2001:9::" << sequence << ":1";
    std::ostringstream targSuffix;
    targSuffix << "2001:9::" << sequence << ":99";
    Ipv6Address origNode(origSuffix.str().c_str());
    Ipv6Address targNode(targSuffix.str().c_str());
    Ipv6Address neighbour("fe80::a");

    static constexpr uint8_t RREQ_INSTANCE = 0x81;
    static constexpr uint8_t DELTA = 0; // RREP-InstanceID == RREQ-InstanceID

    Ptr<RplRoutingProtocol> rpl = node->GetObject<RplRoutingProtocol>();

    // An ordinary RREQ-Instance membership, well within its own RankLimit,
    // to pair the RREP-Instance against. Its own Rank does not matter to
    // this test -- only that the membership exists so HandleAodvRrepInstance()
    // can look it up.
    RplDioHeader rreqDio;
    rreqDio.SetInstanceId(RREQ_INSTANCE);
    rreqDio.SetVersionNumber(0);
    rreqDio.SetRank(RPL_MIN_HOPRANKINC);
    rreqDio.SetMop(RPL_MOP_P2P_ROUTE_DISCOVERY);
    rreqDio.SetDodagId(origNode);
    rreqDio.SetDtsn(0);
    RplDioHeader::RreqOption rreq;
    rreq.symmetric = false; // irrelevant here, but honest: this test is S=0 throughout
    rreq.hopByHop = false;
    rreq.lifetime = 0; // no limit, keeps this test's timing simple
    rreq.rankLimit = 3;
    rreq.origSeqNo = 1;
    rreq.addressVector = {};
    rreqDio.SetRreq(rreq);
    RplDioHeader::ArtOption rreqArt;
    rreqArt.destSeqNo = 0;
    rreqArt.prefixLength = 0;
    rreqArt.target = targNode;
    rreqDio.SetArt(rreqArt);
    DeliverRawRplMessage<RplDioHeader>(node,
                                       1,
                                       rreqDio,
                                       static_cast<uint8_t>(RPL_CODE_DIO),
                                       neighbour,
                                       nodeLinkLocal);

    // The RREP-DIO under test.
    RplDioHeader rrepDio;
    rrepDio.SetInstanceId(static_cast<uint8_t>(RREQ_INSTANCE + DELTA));
    rrepDio.SetVersionNumber(0);
    rrepDio.SetRank(rrepRank);
    rrepDio.SetMop(RPL_MOP_P2P_ROUTE_DISCOVERY);
    rrepDio.SetDodagId(targNode);
    rrepDio.SetDtsn(0);
    RplDioHeader::RrepOption rrep;
    rrep.gratuitous = false;
    rrep.hopByHop = false;
    rrep.lifetime = 0;
    rrep.rankLimit = 3;
    rrep.delta = DELTA;
    rrep.addressVector = {};
    rrepDio.SetRrep(rrep);
    RplDioHeader::ArtOption rrepArt;
    rrepArt.destSeqNo = 1;
    rrepArt.prefixLength = 0;
    rrepArt.target = asOrigin ? rpl->GetGlobalAddress() : origNode;
    rrepDio.SetArt(rrepArt);
    // Multicast, not nodeLinkLocal: HandleDio() uses the destination address
    // alone to tell an RREP-Instance's flood (section 6.3.2) apart from a
    // symmetric route's unicast reply (section 6.3.1), and only the former
    // reaches the join path this test is about.
    DeliverRawRplMessage<RplDioHeader>(node,
                                       1,
                                       rrepDio,
                                       static_cast<uint8_t>(RPL_CODE_DIO),
                                       neighbour,
                                       Ipv6Address(RPL_ALL_NODES_MULTICAST));

    return rpl->IsJoinedTo(static_cast<uint8_t>(RREQ_INSTANCE + DELTA), targNode);
}

void
RplAodvRrepInstanceRankLimitTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(1);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    ipv6.AssignWithoutAddress(devices);

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    Simulator::Stop(Seconds(2));
    Simulator::Run();

    Ptr<Node> node = nodes.Get(0);
    Ipv6Address nodeLinkLocal = node->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    // Comfortably under the limit (DAGRank 1, own DAGRank 2 < 3): joined
    // whichever role this node plays.
    NS_TEST_ASSERT_MSG_EQ(TryJoin(node, nodeLinkLocal, RPL_MIN_HOPRANKINC, false),
                          true,
                          "A relay well within the RankLimit was refused");
    NS_TEST_ASSERT_MSG_EQ(TryJoin(node, nodeLinkLocal, RPL_MIN_HOPRANKINC, true),
                          true,
                          "The OrigNode well within the RankLimit was refused");

    // The exact boundary (DAGRank 2, own DAGRank 3 == the RankLimit): an
    // ordinary relay must not join, the OrigNode must.
    uint16_t boundaryRank = static_cast<uint16_t>(2 * RPL_MIN_HOPRANKINC);
    NS_TEST_ASSERT_MSG_EQ(TryJoin(node, nodeLinkLocal, boundaryRank, false),
                          false,
                          "An ordinary relay joined at exactly the RankLimit: "
                          "RFC 9854 section 4.1 relaxes that bound for the OrigNode only");
    NS_TEST_ASSERT_MSG_EQ(TryJoin(node, nodeLinkLocal, boundaryRank, true),
                          true,
                          "The OrigNode was refused at exactly the RankLimit, where section "
                          "4.1's relaxation should have let it in");

    // The sender's own advertised DAGRank already at the limit: refused
    // outright, no relaxation for anyone (RFC 9854 section 4.1's first
    // sentence has no exception in it).
    uint16_t pastLimitRank = static_cast<uint16_t>(3 * RPL_MIN_HOPRANKINC);
    NS_TEST_ASSERT_MSG_EQ(TryJoin(node, nodeLinkLocal, pastLimitRank, false),
                          false,
                          "A relay joined past the RankLimit");
    NS_TEST_ASSERT_MSG_EQ(TryJoin(node, nodeLinkLocal, pastLimitRank, true),
                          false,
                          "The OrigNode joined past the RankLimit: the relaxation only ever "
                          "applies to this node's own resulting DAGRank, never to the sender's "
                          "already-too-high one");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A router leaves rather than joins an RREP-Instance whose Address
 *        Vector already has no room left for its own entry.
 *
 * The RREP option's Address Vector shares the RREQ option's own 8-bit Opt
 * Data Len, which bounds it at AODV_ADDRESS_VECTOR_MAX_ENTRIES (15) entries
 * (@see RplDioHeader). HandleAodvRrepInstance() checks the received vector's
 * size before appending this router's own address to it; without that
 * check, a vector already at 15 entries would grow to 16 and hit
 * RplDioHeader::Serialize()'s NS_ASSERT_MSG bounding it, crashing the next
 * time this instance's Trickle timer fires SendDio(). RankLimit normally
 * stops a discovery long before the vector could ever get this long, so
 * reaching this case in practice means RankLimit was configured away
 * (RPL_AODV_RANK_LIMIT_INFINITE), which is what this test fabricates.
 *
 * One node under test, fed a fabricated RREP-DIO for a fresh RREP-Instance
 * each call, with a fabricated Address Vector of a chosen length -- 14
 * entries (room for one more) versus 15 (none left).
 */
class RplAodvRrepInstanceAddressVectorFullTestCase : public TestCase
{
  public:
    RplAodvRrepInstanceAddressVectorFullTestCase();

  private:
    void DoRun() override;

    /**
     * @brief Feed one fabricated RREP-DIO, with an Address Vector of the
     *        given length, and report whether the RREP-Instance was joined.
     *
     * @param node the node under test
     * @param vectorEntries how many fabricated hops to put in the RREP's
     *                      Address Vector before delivery
     * @return true if the node ended up joined to the RREP-Instance
     */
    bool TryJoin(Ptr<Node> node, uint8_t vectorEntries);
};

RplAodvRrepInstanceAddressVectorFullTestCase::RplAodvRrepInstanceAddressVectorFullTestCase()
    : TestCase("An RREP-Instance whose Address Vector is already full is left, not joined")
{
}

bool
RplAodvRrepInstanceAddressVectorFullTestCase::TryJoin(Ptr<Node> node, uint8_t vectorEntries)
{
    static uint16_t sequence = 0;
    sequence++;
    // A fresh DODAGID (TargNode address) per call: distinct each time so no
    // earlier sub-case's membership or REJOIN_REENABLE entry interferes.
    std::ostringstream targSuffix;
    targSuffix << "2001:a::" << sequence << ":99";
    Ipv6Address targNode(targSuffix.str().c_str());
    Ipv6Address origNode("2001:a::dead:1"); // never this node: an ordinary relay throughout
    Ipv6Address neighbour("fe80::a");

    static constexpr uint8_t RREP_INSTANCE = 0x81;

    Ptr<RplRoutingProtocol> rpl = node->GetObject<RplRoutingProtocol>();

    RplDioHeader rrepDio;
    rrepDio.SetInstanceId(RREP_INSTANCE);
    rrepDio.SetVersionNumber(0);
    rrepDio.SetRank(RPL_MIN_HOPRANKINC);
    rrepDio.SetMop(RPL_MOP_P2P_ROUTE_DISCOVERY);
    rrepDio.SetDodagId(targNode);
    rrepDio.SetDtsn(0);

    RplDioHeader::RrepOption rrep;
    rrep.gratuitous = false;
    rrep.hopByHop = false;
    rrep.lifetime = 0;
    rrep.rankLimit = RPL_AODV_RANK_LIMIT_INFINITE; // out of the way: this test is about the AV
    rrep.delta = 0;
    for (uint8_t i = 0; i < vectorEntries; i++)
    {
        std::ostringstream hopSuffix;
        hopSuffix << "2001:a::" << sequence << ":" << +i;
        rrep.addressVector.push_back(Ipv6Address(hopSuffix.str().c_str()));
    }
    rrepDio.SetRrep(rrep);

    RplDioHeader::ArtOption art;
    art.destSeqNo = 1;
    art.prefixLength = 0;
    art.target = origNode;
    rrepDio.SetArt(art);

    // Multicast: an RREP-Instance flood, section 6.3.2, not a symmetric
    // unicast reply -- @see the RankLimit test case just above for why this
    // destination is what selects the join path under test.
    DeliverRawRplMessage<RplDioHeader>(node,
                                       1,
                                       rrepDio,
                                       static_cast<uint8_t>(RPL_CODE_DIO),
                                       neighbour,
                                       Ipv6Address(RPL_ALL_NODES_MULTICAST));

    return rpl->IsJoinedTo(RREP_INSTANCE, targNode);
}

void
RplAodvRrepInstanceAddressVectorFullTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(1);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    ipv6.AssignWithoutAddress(devices);

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    Simulator::Stop(Seconds(2));
    Simulator::Run();

    Ptr<Node> node = nodes.Get(0);

    NS_TEST_ASSERT_MSG_EQ(
        TryJoin(node, RplDioHeader::AODV_ADDRESS_VECTOR_MAX_ENTRIES - 1),
        true,
        "A relay was refused an RREP-Instance whose Address Vector still had room for its own "
        "entry");
    NS_TEST_ASSERT_MSG_EQ(
        TryJoin(node, RplDioHeader::AODV_ADDRESS_VECTOR_MAX_ENTRIES),
        false,
        "A relay joined an RREP-Instance whose Address Vector was already full, with no room "
        "left to append its own entry");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A duplicate physical delivery of the same RREP-DIO is relayed only
 *        once by an intermediate router.
 *
 * RFC 9854 section 6.4's own dedup rule ("a router that already belongs to
 * the RREP-Instance SHOULD drop the RREP-DIO") assumes an RREP-Instance
 * DODAG to check membership against, which a symmetric route never forms
 * (section 6.3.1). HandleAodvRrep() had no dedup of its own, so a second
 * physical delivery of the same RREP-DIO (e.g. a link-layer retransmission)
 * got relayed a second time. Harmless by itself -- the Address Vector is
 * fixed-length, so it does not amplify hop by hop -- but pure waste.
 *
 * One node under test, already an intermediate router in a fabricated
 * RREQ-Instance (joined via an RREQ heard from a real peer), fed the same
 * fabricated RREP-DIO twice. The peer doubles as the "next hop back" the
 * RREP should relay to, so its own monitor socket can count how many times
 * the relay actually went out.
 */
class RplAodvRrepDuplicateRelayedOnceTestCase : public TestCase
{
  public:
    RplAodvRrepDuplicateRelayedOnceTestCase();

  private:
    void DoRun() override;

    /// @brief Count a DIO seen at the monitor.
    /// @param socket the monitoring socket
    void CountDio(Ptr<Socket> socket);

    uint32_t m_dioCount{0}; //!< DIOs seen at the monitor
};

RplAodvRrepDuplicateRelayedOnceTestCase::RplAodvRrepDuplicateRelayedOnceTestCase()
    : TestCase("A duplicate RREP-DIO delivery is relayed only once")
{
}

void
RplAodvRrepDuplicateRelayedOnceTestCase::CountDio(Ptr<Socket> socket)
{
    Address sender;
    Ptr<Packet> packet = socket->RecvFrom(sender);
    if (!packet)
    {
        return;
    }
    Ipv6Header ipv6Header;
    packet->RemoveHeader(ipv6Header);
    Icmpv6Header icmpv6Header;
    packet->RemoveHeader(icmpv6Header);
    if (icmpv6Header.GetType() == ICMPV6_RPL && icmpv6Header.GetCode() == RPL_CODE_DIO)
    {
        m_dioCount++;
    }
}

void
RplAodvRrepDuplicateRelayedOnceTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2); // 0 = the node under test, 1 = a real peer/next hop

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    interfaces.SetForwarding(0, true);
    interfaces.SetForwarding(1, true);

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    // Long enough for the peer to join the base DODAG and SLAAC an address,
    // same reasoning and timing as RplAodvMopAcceptedTestCase.
    Simulator::Stop(Seconds(10));
    Simulator::Run();

    Ptr<Node> node = nodes.Get(0);
    Ptr<RplRoutingProtocol> rpl = node->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> peer = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(peer->IsJoined(), true, "The peer never joined the base DODAG");
    Ipv6Address peerGlobal = peer->GetGlobalAddress();
    NS_TEST_ASSERT_MSG_NE(peerGlobal, Ipv6Address::GetAny(), "The peer has no global address yet");

    Ipv6Address nodeLinkLocal = node->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address peerLinkLocal = nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    static constexpr uint8_t RREQ_INSTANCE = 0x81;
    Ipv6Address origNode("2001:9::1");  // fake OrigNode, not a real node
    Ipv6Address targNode("2001:9::99"); // fake TargNode, not a real node

    // The node under test joins as an intermediate router, one hop past the
    // peer: the peer already put its own address in the Address Vector
    // before forwarding, exactly what an RREQ that genuinely came through
    // the peer would carry.
    RplDioHeader rreqDio;
    rreqDio.SetInstanceId(RREQ_INSTANCE);
    rreqDio.SetVersionNumber(0);
    rreqDio.SetRank(RPL_MIN_HOPRANKINC);
    rreqDio.SetMop(RPL_MOP_P2P_ROUTE_DISCOVERY);
    rreqDio.SetDodagId(origNode);
    rreqDio.SetDtsn(0);
    rreqDio.SetDagConfiguration(0,
                                20,
                                RPL_DIO_REDUNDANCY,
                                RPL_MAX_RANKINC,
                                RPL_MIN_HOPRANKINC,
                                RPL_OCP_OF0,
                                RPL_DEFAULT_LIFETIME,
                                RPL_DEFAULT_LIFETIME_UNIT);
    RplDioHeader::RreqOption rreq;
    rreq.symmetric = true;
    rreq.hopByHop = false;
    rreq.compr = 0;
    rreq.lifetime = 0; // no limit, keeps this test's timing simple
    rreq.rankLimit = 0;
    rreq.origSeqNo = 1;
    rreq.addressVector = {peerGlobal};
    rreqDio.SetRreq(rreq);
    RplDioHeader::ArtOption rreqArt;
    rreqArt.destSeqNo = 0;
    rreqArt.prefixLength = 0;
    rreqArt.target = targNode;
    rreqDio.SetArt(rreqArt);
    DeliverRawRplMessage<RplDioHeader>(node,
                                       1,
                                       rreqDio,
                                       static_cast<uint8_t>(RPL_CODE_DIO),
                                       peerLinkLocal,
                                       nodeLinkLocal);

    std::vector<Ipv6Address> addressVector;
    NS_TEST_ASSERT_MSG_EQ(rpl->GetAodvAddressVector(RREQ_INSTANCE, origNode, addressVector),
                          true,
                          "Did not join the fabricated RREQ-Instance");
    NS_TEST_ASSERT_MSG_EQ(addressVector.size(), 2, "Wrong Address Vector size after joining");
    NS_TEST_ASSERT_MSG_EQ(addressVector[0], peerGlobal, "Wrong hop recorded before this node");

    // Watching from the peer, which is exactly the "next hop back" the RREP
    // relay below should unicast to (hops[ownIndex - 1] in the fixed Address
    // Vector), same reasoning as RplAodvMopAcceptedTestCase's monitor.
    Ptr<Socket> monitor = Socket::CreateSocket(nodes.Get(1), Ipv6RawSocketFactory::GetTypeId());
    monitor->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    monitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    monitor->BindToNetDevice(nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetNetDevice(1));
    monitor->SetRecvCallback(MakeCallback(&RplAodvRrepDuplicateRelayedOnceTestCase::CountDio, this));

    RplDioHeader rrepDio;
    rrepDio.SetInstanceId(RREQ_INSTANCE); // Delta 0
    rrepDio.SetVersionNumber(0);
    rrepDio.SetRank(RPL_MIN_HOPRANKINC);
    rrepDio.SetMop(RPL_MOP_P2P_ROUTE_DISCOVERY);
    rrepDio.SetDodagId(targNode);
    rrepDio.SetDtsn(0);
    RplDioHeader::RrepOption rrep;
    rrep.gratuitous = false;
    rrep.hopByHop = false;
    rrep.compr = 0;
    rrep.lifetime = 0;
    rrep.rankLimit = 0;
    rrep.delta = 0;
    rrep.addressVector = addressVector; // the same fixed vector formed above
    rrepDio.SetRrep(rrep);
    RplDioHeader::ArtOption rrepArt;
    rrepArt.destSeqNo = 1;
    rrepArt.prefixLength = 0;
    rrepArt.target = origNode;
    rrepDio.SetArt(rrepArt);

    // Delivered twice, as if the same physical frame had been received (and
    // handed up to RPL) more than once. Neither delivery's "from" matters to
    // HandleAodvRrep(), which reads the fixed Address Vector rather than the
    // sender -- a fake downstream neighbour is fine.
    Ipv6Address fakeDownstream("fe80::66");
    for (int i = 0; i < 2; i++)
    {
        DeliverRawRplMessage<RplDioHeader>(node,
                                           1,
                                           rrepDio,
                                           static_cast<uint8_t>(RPL_CODE_DIO),
                                           fakeDownstream,
                                           nodeLinkLocal);
    }

    Simulator::Stop(Seconds(1));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(m_dioCount,
                          1,
                          "The duplicate RREP-DIO was relayed more than once (or not at all)");

    monitor->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief An AODV-RPL route the OrigNode discovered shows up in both
 *        PrintRoutingTable() and PrintRoutingTableJson(), and only there --
 *        not at the TargNode, which keeps no per-hop state of its own for a
 *        source-routed (H=0) discovery.
 *
 * Neither printer used to mention AODV-RPL routes at all: PrintRoutingTable()
 * only ever walked the DAO-derived topology (root-only, non-storing mode),
 * and PrintRoutingTableJson() had no key for it, so ns3-editor's "RPL
 * table" tab (and anything else consuming the JSON) had no way to show a
 * discovery's result. m_aodvRoutes is node-level state independent of
 * GetBaseDodag(), so it is written in both the joined and not-joined JSON
 * shapes.
 */
class RplAodvRoutesInPrintedTablesTestCase : public TestCase
{
  public:
    RplAodvRoutesInPrintedTablesTestCase();

  private:
    void DoRun() override;
};

RplAodvRoutesInPrintedTablesTestCase::RplAodvRoutesInPrintedTablesTestCase()
    : TestCase("AODV-RPL discovered routes appear in PrintRoutingTable() and its JSON form")
{
}

void
RplAodvRoutesInPrintedTablesTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2); // 0 = OrigNode and base root, 1 = TargNode, one hop away

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    interfaces.SetForwarding(0, true);
    interfaces.SetForwarding(1, true);

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(10));
    Simulator::Run();

    Ptr<RplRoutingProtocol> orig = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> targ = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(targ->IsJoined(), true, "The base DODAG did not reach the peer");
    Ipv6Address targAddress = targ->GetGlobalAddress();

    RplRoutingProtocol::DodagKey key = orig->DiscoverRoute(targAddress);
    NS_TEST_ASSERT_MSG_NE(key.dodagId, Ipv6Address::GetAny(), "The discovery did not start");

    Simulator::Stop(Seconds(5));
    Simulator::Run();

    std::vector<Ipv6Address> hops;
    NS_TEST_ASSERT_MSG_EQ(orig->GetAodvRoute(targAddress, hops),
                          true,
                          "The RREP never made it back to the OrigNode");

    std::ostringstream targetLine;
    targetLine << targAddress;

    std::ostringstream text;
    orig->PrintRoutingTable(Create<OutputStreamWrapper>(&text));
    std::string dump = text.str();
    NS_TEST_ASSERT_MSG_EQ(dump.find("AODV-RPL routes:") != std::string::npos,
                          true,
                          "The text routing table did not mention the discovered route: " << dump);
    NS_TEST_ASSERT_MSG_EQ(dump.find(targetLine.str()) != std::string::npos,
                          true,
                          "The text routing table did not name the TargNode: " << dump);

    std::ostringstream json;
    orig->PrintRoutingTableJson(Create<OutputStreamWrapper>(&json));
    std::string line = json.str();
    NS_TEST_ASSERT_MSG_EQ(line.find("\"aodvRoutes\":[{") != std::string::npos,
                          true,
                          "The JSON snapshot's aodvRoutes array is empty: " << line);
    NS_TEST_ASSERT_MSG_EQ(line.find(targetLine.str()) != std::string::npos,
                          true,
                          "The JSON snapshot did not name the TargNode: " << line);

    // Source routing (H=0) leaves no per-hop state at the TargNode (RFC 9854
    // section 6.4.3 builds a route entry only for H=1).
    std::ostringstream targJson;
    targ->PrintRoutingTableJson(Create<OutputStreamWrapper>(&targJson));
    NS_TEST_ASSERT_MSG_EQ(targJson.str().find("\"aodvRoutes\":[]") != std::string::npos,
                          true,
                          "The TargNode recorded an AODV-RPL route it should not have: "
                              << targJson.str());

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A P2P-RPL route the Origin discovered shows up in both
 *        PrintRoutingTable() and PrintRoutingTableJson(), and only there --
 *        not at the Target, which keeps no per-hop state of its own for a
 *        Source Route (H=0) discovery.
 *
 * The P2P-RPL analogue of RplAodvRoutesInPrintedTablesTestCase: neither
 * printer mentioned m_p2pRoutes at all before this, which is exactly the
 * same gap that test's own doc comment describes for m_aodvRoutes -- a
 * consumer of PrintRoutingTableJson() (ns3-editor's "RPL table" tab in
 * particular) had no way to show a P2P-RPL discovery's result. m_p2pRoutes
 * is node-level state independent of GetBaseDodag(), so it is written in
 * both the joined and not-joined JSON shapes, the same as m_aodvRoutes.
 */
class RplP2pRoutesInPrintedTablesTestCase : public TestCase
{
  public:
    RplP2pRoutesInPrintedTablesTestCase();

  private:
    void DoRun() override;
};

RplP2pRoutesInPrintedTablesTestCase::RplP2pRoutesInPrintedTablesTestCase()
    : TestCase("P2P-RPL discovered routes appear in PrintRoutingTable() and its JSON form")
{
}

void
RplP2pRoutesInPrintedTablesTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2); // 0 = Origin and base root, 1 = Target, one hop away

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    interfaces.SetForwarding(0, true);
    interfaces.SetForwarding(1, true);

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(10));
    Simulator::Run();

    Ptr<RplRoutingProtocol> orig = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> targ = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(targ->IsJoined(), true, "The base DODAG did not reach the peer");
    Ipv6Address targAddress = targ->GetGlobalAddress();

    RplRoutingProtocol::DodagKey key = orig->DiscoverP2pRoute(targAddress);
    NS_TEST_ASSERT_MSG_NE(key.dodagId, Ipv6Address::GetAny(), "The discovery did not start");

    Simulator::Stop(Seconds(5));
    Simulator::Run();

    std::vector<Ipv6Address> hops;
    NS_TEST_ASSERT_MSG_EQ(orig->GetP2pRoute(targAddress, hops),
                          true,
                          "The P2P-DRO never made it back to the Origin");

    std::ostringstream targetLine;
    targetLine << targAddress;

    std::ostringstream text;
    orig->PrintRoutingTable(Create<OutputStreamWrapper>(&text));
    std::string dump = text.str();
    NS_TEST_ASSERT_MSG_EQ(dump.find("P2P-RPL routes:") != std::string::npos,
                          true,
                          "The text routing table did not mention the discovered route: " << dump);
    NS_TEST_ASSERT_MSG_EQ(dump.find(targetLine.str()) != std::string::npos,
                          true,
                          "The text routing table did not name the Target: " << dump);

    std::ostringstream json;
    orig->PrintRoutingTableJson(Create<OutputStreamWrapper>(&json));
    std::string line = json.str();
    NS_TEST_ASSERT_MSG_EQ(line.find("\"p2pRoutes\":[{") != std::string::npos,
                          true,
                          "The JSON snapshot's p2pRoutes array is empty: " << line);
    NS_TEST_ASSERT_MSG_EQ(line.find(targetLine.str()) != std::string::npos,
                          true,
                          "The JSON snapshot did not name the Target: " << line);

    // A Source Route (H=0) leaves no per-hop state at the Target (RFC 6997
    // sections 9.6/9.7 build a route entry only for H=1).
    std::ostringstream targJson;
    targ->PrintRoutingTableJson(Create<OutputStreamWrapper>(&targJson));
    NS_TEST_ASSERT_MSG_EQ(targJson.str().find("\"p2pRoutes\":[]") != std::string::npos,
                          true,
                          "The Target recorded a P2P-RPL route it should not have: "
                              << targJson.str());

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A P2P-RPL route discovery forms a temporary DAG at the Origin and
 *        floods a P2P mode DIO carrying the fixed values RFC 6997 section
 *        6.1 requires.
 *
 * The first half of RFC 6997's route discovery (increment 2 of this
 * module's P2P-RPL support): DiscoverP2pRoute() forms the temporary DAG and
 * Trickle-paces P2P mode DIOs into it. Nothing processes the DIO on the
 * receiving end yet -- HandleDio() does not special-case P2P-RPL until a
 * later increment -- so this only pins down what the Origin itself sends,
 * captured off the wire by a monitor socket on a second node the same way
 * RplAodvAsymmetricRrepInstanceTestCase captures an RREP-DIO.
 */
class RplP2pDiscoverRouteTestCase : public TestCase
{
  public:
    RplP2pDiscoverRouteTestCase();

  private:
    void DoRun() override;

    /// @brief Capture a P2P mode DIO seen at the monitor.
    /// @param socket the monitoring socket
    void CaptureDio(Ptr<Socket> socket);

    bool m_seenP2pDio{false}; //!< a DIO carrying a P2P-RDO was seen
    RplDioHeader m_captured;  //!< the last one seen
};

RplP2pDiscoverRouteTestCase::RplP2pDiscoverRouteTestCase()
    : TestCase("A P2P-RPL route discovery forms a temporary DAG and floods a P2P mode DIO")
{
}

void
RplP2pDiscoverRouteTestCase::CaptureDio(Ptr<Socket> socket)
{
    Address sender;
    Ptr<Packet> packet = socket->RecvFrom(sender);
    if (!packet)
    {
        return;
    }
    Ipv6Header ipv6Header;
    packet->RemoveHeader(ipv6Header);
    Icmpv6Header icmpv6Header;
    packet->RemoveHeader(icmpv6Header);
    if (icmpv6Header.GetType() != ICMPV6_RPL || icmpv6Header.GetCode() != RPL_CODE_DIO)
    {
        return;
    }
    RplDioHeader dio;
    packet->RemoveHeader(dio);
    if (dio.HasP2pRdo())
    {
        m_seenP2pDio = true;
        m_captured = dio;
    }
}

void
RplP2pDiscoverRouteTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2); // 0 = Origin and base root, 1 = a real neighbour to monitor from

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    ipv6.AssignWithoutAddress(devices);

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    Simulator::Stop(Seconds(2));
    Simulator::Run();

    Ptr<RplRoutingProtocol> orig = nodes.Get(0)->GetObject<RplRoutingProtocol>();

    Ptr<Socket> monitor = Socket::CreateSocket(nodes.Get(1), Ipv6RawSocketFactory::GetTypeId());
    monitor->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    monitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    monitor->BindToNetDevice(nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetNetDevice(1));
    monitor->SetRecvCallback(MakeCallback(&RplP2pDiscoverRouteTestCase::CaptureDio, this));

    // A fabricated address: increment 3 onward is what makes a real Target
    // process and reply to this, not this increment's concern.
    Ipv6Address target("2001:9::99");
    RplRoutingProtocol::DodagKey key = orig->DiscoverP2pRoute(target);
    NS_TEST_ASSERT_MSG_NE(key.dodagId, Ipv6Address::GetAny(), "The discovery did not start");
    NS_TEST_ASSERT_MSG_EQ(key.dodagId,
                          orig->GetGlobalAddress(),
                          "The temporary DAG is not rooted at the Origin's own address");
    NS_TEST_ASSERT_MSG_EQ(key.instanceId & RPL_LOCAL_INSTANCE_FLAG,
                          RPL_LOCAL_INSTANCE_FLAG,
                          "The temporary DAG's RPLInstanceID is not a Local one");
    NS_TEST_ASSERT_MSG_EQ(key.instanceId & RPL_LOCAL_INSTANCE_D_FLAG,
                          0,
                          "The temporary DAG's Local RPLInstanceID has its 'D' flag set");

    Simulator::Stop(Seconds(2));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(m_seenP2pDio, true, "No P2P mode DIO was ever flooded");
    NS_TEST_ASSERT_MSG_EQ(m_captured.GetInstanceId(), key.instanceId, "Wrong RPLInstanceID");
    NS_TEST_ASSERT_MSG_EQ(m_captured.GetVersionNumber(),
                          0,
                          "Version must always be zero (RFC 6997 section 6.1)");
    NS_TEST_ASSERT_MSG_EQ(m_captured.GetGrounded(),
                          true,
                          "'G' must always be set (RFC 6997 section 6.1)");
    NS_TEST_ASSERT_MSG_EQ(m_captured.GetMop(), RPL_MOP_P2P_ROUTE_DISCOVERY, "Wrong MOP");
    NS_TEST_ASSERT_MSG_EQ(m_captured.GetPreference(),
                          0,
                          "Prf must always be zero (RFC 6997 section 6.1)");
    NS_TEST_ASSERT_MSG_EQ(m_captured.GetDtsn(),
                          0,
                          "DTSN must always be zero (RFC 6997 section 6.1)");
    NS_TEST_ASSERT_MSG_EQ(m_captured.GetDodagId(), key.dodagId, "Wrong DODAGID");
    NS_TEST_ASSERT_MSG_EQ(m_captured.HasDagConfiguration(),
                          true,
                          "A P2P mode DIO must carry a DODAG Configuration option");
    NS_TEST_ASSERT_MSG_EQ(m_captured.GetMaxRankIncrease(),
                          0,
                          "MaxRankIncrease must always be zero (RFC 6997 section 6.1)");
    NS_TEST_ASSERT_MSG_EQ(m_captured.HasP2pRdo(), true, "No P2P-RDO");
    NS_TEST_ASSERT_MSG_EQ(m_captured.GetP2pRdo().reply, true, "Wrong 'R' flag");
    NS_TEST_ASSERT_MSG_EQ(m_captured.GetP2pRdo().hopByHop, false, "Wrong 'H' flag");
    NS_TEST_ASSERT_MSG_EQ(m_captured.GetP2pRdo().numRoutes, 0, "Wrong 'N' field");
    NS_TEST_ASSERT_MSG_EQ(m_captured.GetP2pRdo().target, target, "Wrong TargetAddr");
    NS_TEST_ASSERT_MSG_EQ(m_captured.GetP2pRdo().addressVector.size(),
                          0,
                          "The Origin's own Address Vector should start empty");

    monitor->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A P2P-RPL route discovery floods a P2P mode DIO outward, each hop
 *        appending its own address to the Address Vector, and the Target
 *        recognises itself.
 *
 * The increment 3 counterpart of RplAodvRreqFloodTestCase, on the same
 * four-node line:
 *
 *     orig(0) ---- relay1(1) ---- relay2(2) ---- targ(3)
 *
 * DiscoverP2pRoute() at the Origin forms a temporary DAG rooted at itself
 * (RFC 6997 section 6.1) and Trickle-paces P2P mode DIOs into it; every
 * router that hears one joins (ShouldRefuseP2pRdo() having let it through),
 * appends the address of the interface it heard it on (section 9.4), and
 * propagates -- except the Target, which recognises itself and stops
 * (section 9.5). Actually replying is a later increment's business.
 */
class RplP2pFloodTestCase : public TestCase
{
  public:
    RplP2pFloodTestCase();

  private:
    void DoRun() override;
};

RplP2pFloodTestCase::RplP2pFloodTestCase()
    : TestCase("A P2P mode DIO floods outward, each hop appending itself to the Address Vector")
{
}

void
RplP2pFloodTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(4); // 0 = Origin and base root, 1 and 2 = relays, 3 = Target

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    auto blacklist = [&](uint32_t a, uint32_t b) {
        Ptr<SimpleNetDevice> devA = DynamicCast<SimpleNetDevice>(devices.Get(a));
        Ptr<SimpleNetDevice> devB = DynamicCast<SimpleNetDevice>(devices.Get(b));
        channel->BlackList(devA, devB);
        channel->BlackList(devB, devA);
    };
    blacklist(0, 2);
    blacklist(0, 3);
    blacklist(1, 3);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    // The base DODAG across all three hops first, so every node has SLAACed
    // the global address its Address Vector entry has to be.
    Simulator::Stop(Seconds(250));
    Simulator::Run();

    Ptr<RplRoutingProtocol> orig = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay1 = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay2 = nodes.Get(2)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> targ = nodes.Get(3)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(targ->IsJoined(), true, "The base DODAG did not reach the far end");

    Ipv6Address relay1Address = relay1->GetGlobalAddress();
    Ipv6Address relay2Address = relay2->GetGlobalAddress();
    Ipv6Address targAddress = targ->GetGlobalAddress();
    NS_TEST_ASSERT_MSG_NE(targAddress, Ipv6Address::GetAny(), "The Target has no address");

    RplRoutingProtocol::DodagKey key = orig->DiscoverP2pRoute(targAddress);
    NS_TEST_ASSERT_MSG_NE(key.dodagId, Ipv6Address::GetAny(), "The discovery did not start");

    // Three hops of Trickle-paced P2P mode DIOs at P2pDioIntervalMin
    // (64 ms, doubling), well inside the default 'L' field's 16 seconds.
    Simulator::Stop(Seconds(10));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(orig->IsJoinedTo(key.instanceId, key.dodagId),
                          true,
                          "The Origin is not in its own temporary DAG");
    NS_TEST_ASSERT_MSG_EQ(relay1->IsJoinedTo(key.instanceId, key.dodagId),
                          true,
                          "relay1 did not join the temporary DAG");
    NS_TEST_ASSERT_MSG_EQ(relay2->IsJoinedTo(key.instanceId, key.dodagId),
                          true,
                          "relay2 did not join the temporary DAG: the DIO was not propagated "
                          "past the first hop");
    NS_TEST_ASSERT_MSG_EQ(targ->IsJoinedTo(key.instanceId, key.dodagId),
                          true,
                          "The Target never heard the P2P mode DIO");

    std::vector<Ipv6Address> addressVector;

    NS_TEST_ASSERT_MSG_EQ(orig->GetP2pAddressVector(key.instanceId, key.dodagId, addressVector),
                          true,
                          "The Origin has no Address Vector");
    NS_TEST_ASSERT_MSG_EQ(addressVector.size(),
                          0,
                          "The Origin put itself in its own Address Vector; RFC 6997 section 7 "
                          "says the Origin and Target addresses MUST NOT be included");

    NS_TEST_ASSERT_MSG_EQ(relay1->GetP2pAddressVector(key.instanceId, key.dodagId, addressVector),
                          true,
                          "relay1 has no Address Vector");
    NS_TEST_ASSERT_MSG_EQ(addressVector.size(), 1, "relay1's Address Vector is the wrong length");
    NS_TEST_ASSERT_MSG_EQ(addressVector[0], relay1Address, "relay1 did not append its own address");

    NS_TEST_ASSERT_MSG_EQ(relay2->GetP2pAddressVector(key.instanceId, key.dodagId, addressVector),
                          true,
                          "relay2 has no Address Vector");
    NS_TEST_ASSERT_MSG_EQ(addressVector.size(), 2, "relay2's Address Vector is the wrong length");
    NS_TEST_ASSERT_MSG_EQ(addressVector[0], relay1Address, "relay2 lost the hop before it");
    NS_TEST_ASSERT_MSG_EQ(addressVector[1], relay2Address, "relay2 did not append its own address");

    NS_TEST_ASSERT_MSG_EQ(targ->GetP2pAddressVector(key.instanceId, key.dodagId, addressVector),
                          true,
                          "The Target has no Address Vector");
    NS_TEST_ASSERT_MSG_EQ(addressVector.size(), 3, "The Target's Address Vector is the wrong length");
    NS_TEST_ASSERT_MSG_EQ(addressVector[0], relay1Address, "The first hop is wrong at the Target");
    NS_TEST_ASSERT_MSG_EQ(addressVector[1], relay2Address, "The second hop is wrong at the Target");
    NS_TEST_ASSERT_MSG_EQ(addressVector[2], targAddress, "The Target did not append its own address");

    // Only the node the P2P-RDO's TargetAddr names knows itself to be the
    // Target.
    NS_TEST_ASSERT_MSG_EQ(targ->IsP2pTarget(key.instanceId, key.dodagId),
                          true,
                          "The Target did not recognise itself in the P2P-RDO");
    NS_TEST_ASSERT_MSG_EQ(relay1->IsP2pTarget(key.instanceId, key.dodagId),
                          false,
                          "relay1 thinks it is the Target");
    NS_TEST_ASSERT_MSG_EQ(relay2->IsP2pTarget(key.instanceId, key.dodagId),
                          false,
                          "relay2 thinks it is the Target");

    // The base DODAG is untouched: a separate RPL Instance with its own
    // rank and parent.
    NS_TEST_ASSERT_MSG_EQ(targ->IsJoined(), true, "The base DODAG membership was disturbed");
    NS_TEST_ASSERT_MSG_EQ(targ->GetDodagCount(), 2, "The Target holds the wrong number of DODAGs");

    // The 'L' field takes every node back out again: the default P2pLifetime
    // attribute value (2) is RFC 6997 section 7's 16-second encoding.
    Simulator::Stop(Seconds(30));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(relay1->IsJoinedTo(key.instanceId, key.dodagId),
                          false,
                          "relay1 stayed in the temporary DAG past its 'L' deadline");
    NS_TEST_ASSERT_MSG_EQ(targ->IsJoinedTo(key.instanceId, key.dodagId),
                          false,
                          "The Target stayed in the temporary DAG past its 'L' deadline");
    NS_TEST_ASSERT_MSG_EQ(orig->IsJoinedTo(key.instanceId, key.dodagId),
                          false,
                          "The Origin stayed in its own temporary DAG past its 'L' deadline");
    NS_TEST_ASSERT_MSG_EQ(targ->IsJoined(),
                          true,
                          "Leaving the temporary DAG dropped the base DODAG");
    NS_TEST_ASSERT_MSG_EQ(targ->GetDodagCount(), 1, "Only the base DODAG should be left");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A P2P mode DIO is only joined if the router's own resulting
 *        DAGRank would stay within the MaxRank, relaxed by one step for the
 *        Target, mirroring AODV-RPL's own RankLimit boundary test.
 *
 * RFC 6997 section 7: "An Intermediate Router MUST NOT join a temporary DAG
 * ... if the integer portion of its rank would be equal to or higher ...
 * than the MaxRank limit. A Target can join the temporary DAG at a rank
 * whose integer portion is equal to the MaxRank." One node under test, fed
 * fabricated P2P mode DIOs directly (no paired instance to set up first,
 * unlike AODV-RPL's RREP-Instance: a P2P-RDO's join check depends only on
 * the DIO itself).
 */
class RplP2pMaxRankTestCase : public TestCase
{
  public:
    RplP2pMaxRankTestCase();

  private:
    void DoRun() override;

    /**
     * @brief Fabricate one P2P mode DIO and report whether it was joined.
     *
     * A fresh DODAGID per call, so the sub-cases cannot contaminate each
     * other's state.
     *
     * @param node the node under test
     * @param dioRank the Rank the fabricated DIO advertises
     * @param asTarget whether the P2P-RDO's TargetAddr should name this
     *                 node (the relaxed bound) or a fake address (the
     *                 strict one)
     * @return true if the node ended up joined to the temporary DAG
     */
    bool TryJoin(Ptr<Node> node, uint16_t dioRank, bool asTarget);
};

RplP2pMaxRankTestCase::RplP2pMaxRankTestCase()
    : TestCase("A P2P mode DIO is only joined within its MaxRank, relaxed for the Target")
{
}

bool
RplP2pMaxRankTestCase::TryJoin(Ptr<Node> node, uint16_t dioRank, bool asTarget)
{
    static uint16_t sequence = 0;
    sequence++;
    // A fresh Origin address per call: distinct each time so no earlier
    // sub-case's membership can interfere with this one's.
    std::ostringstream originSuffix;
    originSuffix << "2001:9::" << sequence << ":1";
    Ipv6Address origin(originSuffix.str().c_str());
    Ipv6Address neighbour("fe80::a");

    static constexpr uint8_t INSTANCE = 0x81;

    Ptr<RplRoutingProtocol> rpl = node->GetObject<RplRoutingProtocol>();

    RplDioHeader dio;
    dio.SetInstanceId(INSTANCE);
    dio.SetVersionNumber(0);
    dio.SetRank(dioRank);
    dio.SetMop(RPL_MOP_P2P_ROUTE_DISCOVERY);
    dio.SetGrounded(true);
    dio.SetDodagId(origin);
    dio.SetDtsn(0);
    P2pRdoOption rdo;
    rdo.reply = true;
    rdo.hopByHop = false;
    rdo.numRoutes = 0;
    rdo.lifetime = 0; // 1 second; timing is not this test's concern
    rdo.maxRankOrNh = 3;
    // A harmless placeholder no one is, when this node is not meant to be
    // the Target: the Origin's own address is convenient and already fresh.
    rdo.target = asTarget ? rpl->GetGlobalAddress() : origin;
    rdo.addressVector = {};
    dio.SetP2pRdo(rdo);

    DeliverRawRplMessage<RplDioHeader>(node,
                                       1,
                                       dio,
                                       static_cast<uint8_t>(RPL_CODE_DIO),
                                       neighbour,
                                       Ipv6Address(RPL_ALL_NODES_MULTICAST));

    return rpl->IsJoinedTo(INSTANCE, origin);
}

void
RplP2pMaxRankTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(1);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    ipv6.AssignWithoutAddress(devices);

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    Simulator::Stop(Seconds(2));
    Simulator::Run();

    Ptr<Node> node = nodes.Get(0);

    // Comfortably under the limit (DAGRank 1, own DAGRank 2 < 3): joined
    // whichever role this node plays.
    NS_TEST_ASSERT_MSG_EQ(TryJoin(node, RPL_MIN_HOPRANKINC, false),
                          true,
                          "An ordinary router well within MaxRank was refused");
    NS_TEST_ASSERT_MSG_EQ(TryJoin(node, RPL_MIN_HOPRANKINC, true),
                          true,
                          "The Target well within MaxRank was refused");

    // The exact boundary (DAGRank 2, own DAGRank 3 == the MaxRank): an
    // ordinary router must not join, the Target must.
    uint16_t boundaryRank = static_cast<uint16_t>(2 * RPL_MIN_HOPRANKINC);
    NS_TEST_ASSERT_MSG_EQ(TryJoin(node, boundaryRank, false),
                          false,
                          "An ordinary router joined at exactly the MaxRank: RFC 6997 section 7 "
                          "relaxes that bound for the Target only");
    NS_TEST_ASSERT_MSG_EQ(TryJoin(node, boundaryRank, true),
                          true,
                          "The Target was refused at exactly the MaxRank, where section 7's "
                          "relaxation should have let it in");

    // The sender's own advertised DAGRank already at the limit: refused
    // outright, no relaxation for anyone.
    uint16_t pastLimitRank = static_cast<uint16_t>(3 * RPL_MIN_HOPRANKINC);
    NS_TEST_ASSERT_MSG_EQ(TryJoin(node, pastLimitRank, false),
                          false,
                          "An ordinary router joined past the MaxRank");
    NS_TEST_ASSERT_MSG_EQ(TryJoin(node, pastLimitRank, true),
                          false,
                          "The Target joined past the MaxRank: the relaxation only ever applies "
                          "to this node's own resulting DAGRank, never to the sender's "
                          "already-too-high one");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief RFC 6997 section 9.2's rule 3 (a non-parent's at-least-as-good P2P
 *        mode DIO) counts as Trickle-consistent and can suppress a
 *        transmission; rules 2 and 4 (the parent's own non-improving
 *        re-announcement, and a non-parent's worse-Rank DIO) do not.
 *
 * design-constraints.md section 39.2 implemented HandleDio()'s own 4-rule
 * classification for a P2P mode DIO's Trickle consistency but left the
 * P2pDioRedundancy default at 0 (never suppress), because at that setting
 * ConsistencyHit() being called or not has no observable effect at all --
 * RplTrickleTimer::TransmitEvent() only ever checks
 * "m_redundancy == 0 || m_counter < m_redundancy", which is unconditionally
 * true whenever m_redundancy is 0. This is the test that was missing before
 * changing the default: with P2pDioRedundancy raised to 1 for the duration
 * of this test only, rule 3 firing must suppress the following
 * transmission, and rules 2 and 4 firing must not -- the latter checking
 * that the else-if's own Rank comparison is genuinely exclusive rather
 * than treating every non-parent DIO alike regardless of Rank.
 *
 * One node under test, a peer that doubles as both the fabricated
 * neighbours' relay and the monitor for anything the node under test
 * transmits (RplAodvMultiArtStopsWhenExhaustedTestCase's own two-node
 * recipe, needed here for the same reason: a lone node cannot observe
 * whether it suppressed its own transmission). Three independent temporary
 * DAGs (different fabricated DODAGIDs), one per rule under test, so none
 * of their Trickle state can contaminate another's.
 */
class RplP2pTrickleRuleSuppressionTestCase : public TestCase
{
  public:
    RplP2pTrickleRuleSuppressionTestCase();

  private:
    void DoRun() override;

    /**
     * @brief Count a P2P mode DIO seen at the monitor, by DODAGID.
     * @param socket the monitoring socket
     */
    void CountP2pDio(Ptr<Socket> socket);

    /// P2P mode DIOs seen at the monitor, keyed by DODAGID (one temporary
    /// DAG per sub-case, so counts never mix).
    std::map<Ipv6Address, uint32_t> m_p2pDioCount;
};

RplP2pTrickleRuleSuppressionTestCase::RplP2pTrickleRuleSuppressionTestCase()
    : TestCase("RFC 6997 section 9.2 rule 3 suppresses a P2P mode DIO under P2pDioRedundancy, "
               "rule 2 does not")
{
}

void
RplP2pTrickleRuleSuppressionTestCase::CountP2pDio(Ptr<Socket> socket)
{
    Address sender;
    Ptr<Packet> packet = socket->RecvFrom(sender);
    if (!packet)
    {
        return;
    }
    Ipv6Header ipv6Header;
    packet->RemoveHeader(ipv6Header);
    Icmpv6Header icmpv6Header;
    packet->RemoveHeader(icmpv6Header);
    if (icmpv6Header.GetType() != ICMPV6_RPL || icmpv6Header.GetCode() != RPL_CODE_DIO)
    {
        return;
    }
    RplDioHeader dio;
    packet->RemoveHeader(dio);
    if (dio.HasP2pRdo())
    {
        m_p2pDioCount[dio.GetDodagId()]++;
    }
}

void
RplP2pTrickleRuleSuppressionTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2); // 0 = the node under test, 1 = peer/monitor

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    // Raised from the default of 0 for this test only: at 0, whether
    // ConsistencyHit() is called or not (the very thing under test) has no
    // observable effect on transmission at all. @see design-constraints.md
    // section 39.2/43 (or wherever the default itself is documented).
    //
    // Set inside each fabricated DIO's own DODAG Configuration option
    // below, not via a P2pDioRedundancy attribute on this helper: that
    // attribute only seeds dodag.dioRedundancy for a temporary DAG this
    // node *originates* (DiscoverP2pRoute()); a temporary DAG this node
    // only *joins*, as every one of them is in this test, takes its
    // dioRedundancy from the DIO that formed it instead
    // (JoinDodag()/HandleDio()'s own "propagate the root's Trickle
    // parameters to every joiner" rule, the same one dioIntervalMin
    // follows) -- found by this test itself keeping the attribute at 1 yet
    // observing m_redundancy=0 in the Trickle timer's own NS_LOG_FUNCTION
    // trace, since RPL_DIO_REDUNDANCY (0) was still what the fabricated
    // DIO's own DagConfiguration carried.
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    interfaces.SetForwarding(0, true);
    interfaces.SetForwarding(1, true);

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(10));
    Simulator::Run();

    Ptr<Node> node = nodes.Get(0);
    Ptr<RplRoutingProtocol> rpl = node->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(rpl->IsJoined(), true, "The base DODAG never formed");

    Ipv6Address nodeLinkLocal = node->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    Ptr<Socket> monitor = Socket::CreateSocket(nodes.Get(1), Ipv6RawSocketFactory::GetTypeId());
    monitor->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    monitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    monitor->BindToNetDevice(nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetNetDevice(1));
    monitor->SetRecvCallback(
        MakeCallback(&RplP2pTrickleRuleSuppressionTestCase::CountP2pDio, this));

    auto buildRdo = [&](Ipv6Address origin, uint16_t rank) {
        RplDioHeader dio;
        dio.SetInstanceId(0x81);
        dio.SetVersionNumber(0);
        dio.SetRank(rank);
        dio.SetMop(RPL_MOP_P2P_ROUTE_DISCOVERY);
        dio.SetGrounded(true);
        dio.SetDodagId(origin);
        dio.SetDtsn(0);
        // Imin 64 ms (2^6), 0 doublings: Imax stays 64 ms, so the single
        // interval this test observes never grows out from under it.
        // MaxRankIncrease 0, not RPL_MAX_RANKINC: RFC 6997 section 6.1
        // requires it for a P2P mode DIO ("the Origin MUST set the
        // MaxRankIncrease parameter to zero"), and ShouldRefuseP2pRdo()
        // refuses a nonzero one outright -- found by this test itself
        // refusing every delivery and both assertions passing vacuously
        // (nothing had joined at all) until this was fixed. Redundancy 1,
        // not RPL_DIO_REDUNDANCY (0): this is the field this test actually
        // depends on, propagated into dodag.dioRedundancy by JoinDodag()/
        // HandleDio() for every node that joins off this DIO -- @see this
        // test's own P2pDioRedundancy comment above for why the node
        // attribute alone does not reach a joined (non-origin) membership.
        dio.SetDagConfiguration(0,
                                6,
                                1,
                                0,
                                RPL_MIN_HOPRANKINC,
                                RPL_OCP_OF0,
                                RPL_DEFAULT_LIFETIME,
                                RPL_DEFAULT_LIFETIME_UNIT);
        P2pRdoOption rdo;
        rdo.reply = false; // this test only cares about the RREQ-DIO side
        rdo.hopByHop = false;
        rdo.numRoutes = 0;
        rdo.lifetime = 0; // no limit, keeps this test's timing simple
        rdo.maxRankOrNh = 0; // no limit
        rdo.target = origin; // a harmless placeholder no one here is
        rdo.addressVector = {};
        dio.SetP2pRdo(rdo);
        return dio;
    };
    auto deliver = [&](Time at, Ipv6Address from, Ipv6Address origin, uint16_t rank) {
        Simulator::Schedule(at,
                            &DeliverRawRplMessage<RplDioHeader>,
                            node,
                            1,
                            buildRdo(origin, rank),
                            static_cast<uint8_t>(RPL_CODE_DIO),
                            from,
                            nodeLinkLocal);
    };

    Ipv6Address neighbourA("fe80::a");
    Ipv6Address neighbourB("fe80::b");

    // Rule 3: the first DIO (from A) joins the temporary DAG and resets
    // Trickle to Imin (rule 1, "the first receipt...is always considered
    // inconsistent"). The second, delivered 5 ms later -- comfortably
    // before Imin/2 = 32 ms, so it lands in the same fresh interval -- is
    // from a different neighbour (B, so not rule 2's "from the parent")
    // and advertises the very same Rank A did, which is at least as good
    // as this node's own resulting Rank: rule 3, ConsistencyHit(). With
    // P2pDioRedundancy=1, m_counter(1) is no longer < m_redundancy(1), so
    // the transmission due somewhere in [32, 64) ms is suppressed.
    Ipv6Address originRule3("2001:9:3::1");
    deliver(Seconds(0), neighbourA, originRule3, RPL_MIN_HOPRANKINC);
    deliver(MilliSeconds(5), neighbourB, originRule3, RPL_MIN_HOPRANKINC);

    // Rule 2 (the control): the same recipe, but the second DIO comes from
    // A again -- the same neighbour as the first, i.e. "from the parent" --
    // with a Rank that does not improve on it either. Rule 2 is neither
    // consistent nor inconsistent, so ConsistencyHit() is never called;
    // m_counter stays 0 < m_redundancy(1), and the transmission proceeds
    // normally.
    Ipv6Address originRule2("2001:9:2::1");
    deliver(Seconds(0), neighbourA, originRule2, RPL_MIN_HOPRANKINC);
    deliver(MilliSeconds(5), neighbourA, originRule2, RPL_MIN_HOPRANKINC);

    // Rule 4 (the boundary the else-if's own condition draws): a non-parent
    // again, but this time advertising a worse Rank than this node's own
    // resulting one -- the mirror image of rule 3's condition
    // (dio.GetRank() <= after.rank), checking that the comparison is
    // genuinely exclusive rather than firing for every non-parent DIO
    // regardless of Rank.
    Ipv6Address neighbourC("fe80::c");
    Ipv6Address originRule4("2001:9:4::1");
    deliver(Seconds(0), neighbourA, originRule4, RPL_MIN_HOPRANKINC);
    deliver(MilliSeconds(5), neighbourC, originRule4, 1000);

    // Stopped at 80 ms: past the 64 ms interval boundary, so whatever this
    // interval's transmission slot decided has already happened, but
    // before the next interval's own earliest possible slot at 64 + 32 =
    // 96 ms, so that interval's own (unsuppressed, since its counter has
    // since reset to 0) transmission cannot leak into this count.
    Simulator::Stop(MilliSeconds(80));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(m_p2pDioCount[originRule3],
                          0,
                          "Rule 3 (a non-parent's at-least-as-good DIO) should have counted as "
                          "Trickle-consistent and suppressed this interval's transmission");
    NS_TEST_ASSERT_MSG_EQ(m_p2pDioCount[originRule2],
                          1,
                          "Rule 2 (the parent's own non-improving re-announcement) must not "
                          "count as consistent: the transmission should have gone out normally");
    NS_TEST_ASSERT_MSG_EQ(m_p2pDioCount[originRule4],
                          1,
                          "Rule 4 (a non-parent's worse-Rank DIO) must not count as consistent "
                          "either: the transmission should have gone out normally");

    monitor->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A P2P-RPL Target answers a P2P mode DIO with a P2P-DRO carrying
 *        the fixed values RFC 6997 section 8.2 requires, its Address
 *        Vector trimmed of the Target's own trailing entry.
 *
 * The increment 4 counterpart of RplP2pFloodTestCase, on the same
 * four-node line:
 *
 *     orig(0) ---- relay1(1) ---- relay2(2) ---- targ(3)
 *
 * By the time the DIO flood (already covered by RplP2pFloodTestCase)
 * reaches the Target, its own dodag.p2p.addressVector is [relay1, relay2,
 * targ] -- the Target appends itself exactly like an ordinary Intermediate
 * Router does. Section 8.2 has the P2P-DRO's own Address vector end at
 * "the router next to the Target" instead, so the outgoing P2P-RDO should
 * carry only [relay1, relay2], not the Target's own address a third time.
 * Nothing processes the P2P-DRO on the receiving end yet -- that is a
 * later increment's job -- so this only pins down what the Target itself
 * sends, captured off the wire by a monitor socket on relay2 the same way
 * RplP2pDiscoverRouteTestCase captures a DIO.
 */
class RplP2pDroGeneratedTestCase : public TestCase
{
  public:
    RplP2pDroGeneratedTestCase();

  private:
    void DoRun() override;

    /// @brief Capture a P2P-DRO seen at the monitor.
    /// @param socket the monitoring socket
    void CaptureDro(Ptr<Socket> socket);

    bool m_seenDro{false};      //!< a P2P-DRO was seen
    RplP2pDroHeader m_captured; //!< the last one seen
};

RplP2pDroGeneratedTestCase::RplP2pDroGeneratedTestCase()
    : TestCase("A P2P-RPL Target answers a P2P mode DIO with a P2P-DRO")
{
}

void
RplP2pDroGeneratedTestCase::CaptureDro(Ptr<Socket> socket)
{
    Address sender;
    Ptr<Packet> packet = socket->RecvFrom(sender);
    if (!packet)
    {
        return;
    }
    Ipv6Header ipv6Header;
    packet->RemoveHeader(ipv6Header);
    Icmpv6Header icmpv6Header;
    packet->RemoveHeader(icmpv6Header);
    if (icmpv6Header.GetType() != ICMPV6_RPL || icmpv6Header.GetCode() != RPL_CODE_P2P_DRO)
    {
        return;
    }
    if (m_seenDro)
    {
        // Only the first one, straight from the Target: relay2 is itself a
        // full RPL node, so once HandleP2pDro() exists it relays this same
        // P2P-DRO onward (NH decremented) and the monitor would otherwise
        // see that copy too and overwrite m_captured with it.
        return;
    }
    m_seenDro = true;
    packet->RemoveHeader(m_captured);
}

void
RplP2pDroGeneratedTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(4); // 0 = Origin and base root, 1 and 2 = relays, 3 = Target

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    auto blacklist = [&](uint32_t a, uint32_t b) {
        Ptr<SimpleNetDevice> devA = DynamicCast<SimpleNetDevice>(devices.Get(a));
        Ptr<SimpleNetDevice> devB = DynamicCast<SimpleNetDevice>(devices.Get(b));
        channel->BlackList(devA, devB);
        channel->BlackList(devB, devA);
    };
    blacklist(0, 2);
    blacklist(0, 3);
    blacklist(1, 3);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(250));
    Simulator::Run();

    Ptr<RplRoutingProtocol> orig = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay1 = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay2 = nodes.Get(2)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> targ = nodes.Get(3)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(targ->IsJoined(), true, "The base DODAG did not reach the far end");

    Ipv6Address relay1Address = relay1->GetGlobalAddress();
    Ipv6Address relay2Address = relay2->GetGlobalAddress();
    Ipv6Address targAddress = targ->GetGlobalAddress();

    // Watching from relay2, the Target's only neighbour, so the P2P-DRO has
    // somewhere real to arrive.
    Ptr<Socket> monitor = Socket::CreateSocket(nodes.Get(2), Ipv6RawSocketFactory::GetTypeId());
    monitor->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    monitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    monitor->BindToNetDevice(nodes.Get(2)->GetObject<Ipv6L3Protocol>()->GetNetDevice(1));
    monitor->SetRecvCallback(MakeCallback(&RplP2pDroGeneratedTestCase::CaptureDro, this));

    RplRoutingProtocol::DodagKey key = orig->DiscoverP2pRoute(targAddress);
    NS_TEST_ASSERT_MSG_NE(key.dodagId, Ipv6Address::GetAny(), "The discovery did not start");

    Simulator::Stop(Seconds(10));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(targ->IsP2pTarget(key.instanceId, key.dodagId),
                          true,
                          "The Target never recognised itself");
    NS_TEST_ASSERT_MSG_EQ(m_seenDro, true, "No P2P-DRO was ever sent");
    NS_TEST_ASSERT_MSG_EQ(m_captured.GetInstanceId(), key.instanceId, "Wrong RPLInstanceID");
    // RFC 6997 section 9.5: 'S' is set because this Target is the only one
    // named and has already selected its one route -- always true in this
    // implementation's scope. 'A' follows the P2pDroAckRequested attribute,
    // true by default.
    NS_TEST_ASSERT_MSG_EQ(m_captured.GetStop(), true, "Wrong 'S' flag");
    NS_TEST_ASSERT_MSG_EQ(m_captured.GetAckRequested(), true, "Wrong 'A' flag");
    NS_TEST_ASSERT_MSG_EQ(m_captured.GetSequence(), 1, "First P2P-DRO should carry Seq 1");
    NS_TEST_ASSERT_MSG_EQ(m_captured.GetDodagId(), key.dodagId, "Wrong DODAGID");
    NS_TEST_ASSERT_MSG_EQ(m_captured.HasP2pRdo(), true, "No P2P-RDO");
    NS_TEST_ASSERT_MSG_EQ(m_captured.GetP2pRdo().reply,
                          false,
                          "'R' must always be zero on transmission (RFC 6997 section 8.2)");
    NS_TEST_ASSERT_MSG_EQ(m_captured.GetP2pRdo().hopByHop, false, "Wrong 'H' flag");
    NS_TEST_ASSERT_MSG_EQ(m_captured.GetP2pRdo().numRoutes,
                          0,
                          "'N' must always be zero on transmission (RFC 6997 section 8.2)");
    NS_TEST_ASSERT_MSG_EQ(m_captured.GetP2pRdo().lifetime,
                          0,
                          "'L' must always be zero on transmission (RFC 6997 section 8.2)");
    NS_TEST_ASSERT_MSG_EQ(m_captured.GetP2pRdo().target, targAddress, "Wrong TargetAddr");
    // The Target's own dodag.p2p.addressVector is [relay1, relay2, targ] by
    // the time it answers -- it appends itself exactly like an ordinary
    // Intermediate Router (@see RplP2pFloodTestCase). The outgoing P2P-RDO
    // should carry only [relay1, relay2]: the Target's own trailing entry
    // trimmed off, ending at "the router next to the Target" (relay2) per
    // section 8.2, not at the Target a second time.
    NS_TEST_ASSERT_MSG_EQ(m_captured.GetP2pRdo().addressVector.size(),
                          2,
                          "The Target's own trailing entry should have been trimmed, leaving "
                          "just the two routers before it");
    NS_TEST_ASSERT_MSG_EQ(m_captured.GetP2pRdo().addressVector[0],
                          relay1Address,
                          "Wrong first Address Vector entry");
    NS_TEST_ASSERT_MSG_EQ(m_captured.GetP2pRdo().addressVector[1],
                          relay2Address,
                          "Wrong second Address Vector entry: should be the router next to the "
                          "Target");
    NS_TEST_ASSERT_MSG_EQ(m_captured.GetP2pRdo().maxRankOrNh, 2, "Wrong NH");

    monitor->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief An unacknowledged P2P-DRO is retransmitted up to
 *        P2pDroMaxRetransmissions times, then abandoned.
 *
 * Two nodes: node 0 the base-RPL root, purely a monitor here; node 1 the
 * node under test, fed a fabricated P2P mode DIO directly
 * (DeliverRawRplMessage()) naming it the Target and an Origin address
 * ("2001:9::1") that belongs to no real node in the topology -- nobody
 * can ever answer with a P2P-DRO-ACK, however many times node 1 retries,
 * which is exactly the condition P2pDroRetry() is meant to handle.
 *
 * The channel is blacklisted one-way (0 -> 1 only, SimpleChannel::
 * BlackList()'s block is unidirectional) once the base DODAG has formed:
 * node 1's own transmissions still reach node 0's monitor, but node 0
 * (which is not part of the fabricated temporary DAG, but would
 * otherwise join it as an ordinary Intermediate Router the first time it
 * hears one of node 1's re-broadcasts) can never answer back. Without
 * this, an earlier version of this test used a single self-rooted node
 * instead and hung: SimpleNetDevice's local delivery lets a node hear its
 * own multicast, and each such self-reception fed straight back into
 * SelectPreferredParent(), triggering dioTrickle.Reset() and an immediate
 * re-transmission at the same simulated instant with no advancing time in
 * between -- a livelock, not a crash, so Simulator::Run() never returned.
 * P2pDroAckWaitTime and P2pDroMaxRetransmissions are set to small values
 * so the test does not have to wait out the 1 s default.
 */
class RplP2pDroRetryTestCase : public TestCase
{
  public:
    RplP2pDroRetryTestCase();

  private:
    void DoRun() override;

    /// @brief Count each P2P-DRO seen at the monitor.
    /// @param socket the monitoring socket
    void CaptureDro(Ptr<Socket> socket);

    uint32_t m_droCount{0}; //!< how many times node 1 has sent a P2P-DRO
};

RplP2pDroRetryTestCase::RplP2pDroRetryTestCase()
    : TestCase("An unacknowledged P2P-DRO is retried, then given up on")
{
}

void
RplP2pDroRetryTestCase::CaptureDro(Ptr<Socket> socket)
{
    Address sender;
    Ptr<Packet> packet = socket->RecvFrom(sender);
    if (!packet)
    {
        return;
    }
    Ipv6Header ipv6Header;
    packet->RemoveHeader(ipv6Header);
    Icmpv6Header icmpv6Header;
    packet->RemoveHeader(icmpv6Header);
    if (icmpv6Header.GetType() != ICMPV6_RPL || icmpv6Header.GetCode() != RPL_CODE_P2P_DRO)
    {
        return;
    }
    m_droCount++;
}

void
RplP2pDroRetryTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    rplHelper.Set("P2pDroAckWaitTime", TimeValue(MilliSeconds(100)));
    rplHelper.Set("P2pDroMaxRetransmissions", UintegerValue(2));
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    ipv6.AssignWithoutAddress(devices);

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    // Base RPL's own DioIntervalMin (4.096 s by default) means the root's
    // first DIO can take up to that long to go out at all (Trickle's
    // Start() picks the first firing in [Imin/2, Imin]); 10 s leaves a
    // comfortable margin for one hop.
    Simulator::Stop(Seconds(10));
    Simulator::Run();

    Ptr<Node> node = nodes.Get(1);
    Ptr<RplRoutingProtocol> rpl = node->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(rpl->IsJoined(), true, "The base DODAG did not reach node 1");

    // One-way only: node 1 -> node 0 stays open for the monitor, node 0 ->
    // node 1 is cut so nothing node 0 does in response can ever reach node
    // 1 back (@see this class's own doc comment).
    Ptr<SimpleNetDevice> dev0 = DynamicCast<SimpleNetDevice>(devices.Get(0));
    Ptr<SimpleNetDevice> dev1 = DynamicCast<SimpleNetDevice>(devices.Get(1));
    channel->BlackList(dev0, dev1);

    Ptr<Socket> monitor =
        Socket::CreateSocket(nodes.Get(0), Ipv6RawSocketFactory::GetTypeId());
    monitor->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    monitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    monitor->BindToNetDevice(nodes.Get(0)->GetObject<Ipv6L3Protocol>()->GetNetDevice(1));
    monitor->SetRecvCallback(MakeCallback(&RplP2pDroRetryTestCase::CaptureDro, this));

    Ipv6Address origin("2001:9::1"); // no real node owns this address
    Ipv6Address neighbour("fe80::a");
    static constexpr uint8_t INSTANCE = 0x81;

    RplDioHeader dio;
    dio.SetInstanceId(INSTANCE);
    dio.SetVersionNumber(0);
    dio.SetRank(RPL_MIN_HOPRANKINC);
    dio.SetMop(RPL_MOP_P2P_ROUTE_DISCOVERY);
    dio.SetGrounded(true);
    dio.SetDodagId(origin);
    dio.SetDtsn(0);
    // Without this, dodag.dioIntervalMin stays at its Time-default of zero
    // (JoinDodag() only sets it from a DIO that HasDagConfiguration()),
    // which makes RplTrickleTimer::NewInterval()'s Uniform(half, interval)
    // draw deterministically 0 -- a zero-delay livelock, every firing
    // rescheduling the next one at the same simulated instant, so
    // Simulator::Run() never returns. Hung this exact way once already
    // writing this test (@see design-constraints.md).
    dio.SetDagConfiguration(4, // doublings, matching P2pDioIntervalDoublings's own default
                            6, // Imin = 2^6 ms = 64 ms
                            0,
                            0,
                            RPL_MIN_HOPRANKINC,
                            RPL_OCP_OF0,
                            RPL_DEFAULT_LIFETIME,
                            RPL_DEFAULT_LIFETIME_UNIT);
    P2pRdoOption rdo;
    rdo.reply = true;
    rdo.hopByHop = false;
    rdo.numRoutes = 0;
    rdo.lifetime = 2; // 16 seconds, comfortably past this test's own window
    rdo.maxRankOrNh = 3;
    rdo.target = rpl->GetGlobalAddress(); // node 1 is the Target
    rdo.addressVector = {};
    dio.SetP2pRdo(rdo);

    DeliverRawRplMessage<RplDioHeader>(node,
                                       1,
                                       dio,
                                       static_cast<uint8_t>(RPL_CODE_DIO),
                                       neighbour,
                                       Ipv6Address(RPL_ALL_NODES_MULTICAST));

    NS_TEST_ASSERT_MSG_EQ(rpl->IsP2pTarget(INSTANCE, origin),
                          true,
                          "The node did not recognise itself as the Target");

    // Long enough for the original P2P-DRO plus 2 retries at 100 ms apart
    // (400 ms) with a comfortable margin, but short enough that the
    // temporary DAG's own 'L' deadline (16 s) is nowhere close.
    Simulator::Stop(Seconds(2));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(m_droCount,
                          3,
                          "Expected the original P2P-DRO plus 2 retransmissions "
                          "(P2pDroMaxRetransmissions=2)");

    // Confirm P2pDroRetry() actually gave up rather than the test window
    // merely being too short to see a 4th: running well past another
    // P2P_DRO_ACK_WAIT_TIME must not raise the count any further.
    Simulator::Stop(Seconds(3));
    Simulator::Run();
    NS_TEST_ASSERT_MSG_EQ(m_droCount, 3, "P2pDroRetry() should have given up after 2 retries");

    monitor->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A node named only by an RPL Target option (not the P2P-RDO's own
 *        primary TargetAddr) recognises itself as a Target, and its
 *        P2P-DRO's 'S' flag stays clear while another, still-undiscovered
 *        Target option remains.
 *
 * RFC 6997 section 9.3: "The router MUST check the Target addresses
 * listed in the P2P-RDO and any RPL Target options included in the
 * received DIO." Same single-node-under-test construction as
 * RplP2pDroRetryTestCase (@see its own doc comment for why a lone
 * self-rooted node needs the one-way blacklist), fed a P2P mode DIO whose
 * P2P-RDO names an unrelated primary Target and two RPL Target options:
 * this node's own address, and a second, still-outstanding one. Section
 * 9.5's Stop condition ("no other Targets...specified via RPL Target
 * options") is false here regardless of which entry matched, since the
 * raw list this node stores is never filtered down as it matches
 * (@see DodagMembership::P2pState::additionalTargets).
 */
class RplP2pMultiTargetTestCase : public TestCase
{
  public:
    RplP2pMultiTargetTestCase();

  private:
    void DoRun() override;

    /// @brief Capture a P2P-DRO seen at the monitor.
    /// @param socket the monitoring socket
    void CaptureDro(Ptr<Socket> socket);

    bool m_seenDro{false};      //!< a P2P-DRO was seen
    RplP2pDroHeader m_captured; //!< the first one seen
};

RplP2pMultiTargetTestCase::RplP2pMultiTargetTestCase()
    : TestCase("A node matched via an RPL Target option recognises itself as a Target")
{
}

void
RplP2pMultiTargetTestCase::CaptureDro(Ptr<Socket> socket)
{
    Address sender;
    Ptr<Packet> packet = socket->RecvFrom(sender);
    if (!packet)
    {
        return;
    }
    Ipv6Header ipv6Header;
    packet->RemoveHeader(ipv6Header);
    Icmpv6Header icmpv6Header;
    packet->RemoveHeader(icmpv6Header);
    if (icmpv6Header.GetType() != ICMPV6_RPL || icmpv6Header.GetCode() != RPL_CODE_P2P_DRO)
    {
        return;
    }
    if (m_seenDro)
    {
        return; // only the first, same reason RplP2pDroGeneratedTestCase's own does
    }
    m_seenDro = true;
    packet->RemoveHeader(m_captured);
}

void
RplP2pMultiTargetTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    ipv6.AssignWithoutAddress(devices);

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    // Same margin as RplP2pDroRetryTestCase: base RPL's DioIntervalMin
    // default (4.096 s) means the root's first DIO can take that long.
    Simulator::Stop(Seconds(10));
    Simulator::Run();

    Ptr<Node> node = nodes.Get(1);
    Ptr<RplRoutingProtocol> rpl = node->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(rpl->IsJoined(), true, "The base DODAG did not reach node 1");

    Ptr<SimpleNetDevice> dev0 = DynamicCast<SimpleNetDevice>(devices.Get(0));
    Ptr<SimpleNetDevice> dev1 = DynamicCast<SimpleNetDevice>(devices.Get(1));
    channel->BlackList(dev0, dev1);

    Ptr<Socket> monitor =
        Socket::CreateSocket(nodes.Get(0), Ipv6RawSocketFactory::GetTypeId());
    monitor->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    monitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    monitor->BindToNetDevice(nodes.Get(0)->GetObject<Ipv6L3Protocol>()->GetNetDevice(1));
    monitor->SetRecvCallback(MakeCallback(&RplP2pMultiTargetTestCase::CaptureDro, this));

    Ipv6Address origin("2001:9::1");      // no real node owns this address
    Ipv6Address primaryTarget("2001:9::99"); // unrelated to node 1, still undiscovered
    Ipv6Address otherTarget("2001:9::77");   // likewise, a second Target option
    Ipv6Address neighbour("fe80::a");
    static constexpr uint8_t INSTANCE = 0x81;

    RplDioHeader dio;
    dio.SetInstanceId(INSTANCE);
    dio.SetVersionNumber(0);
    dio.SetRank(RPL_MIN_HOPRANKINC);
    dio.SetMop(RPL_MOP_P2P_ROUTE_DISCOVERY);
    dio.SetGrounded(true);
    dio.SetDodagId(origin);
    dio.SetDtsn(0);
    dio.SetDagConfiguration(4, 6, 0, 0, RPL_MIN_HOPRANKINC, RPL_OCP_OF0, RPL_DEFAULT_LIFETIME,
                            RPL_DEFAULT_LIFETIME_UNIT);
    P2pRdoOption rdo;
    rdo.reply = true;
    rdo.hopByHop = false;
    rdo.numRoutes = 0;
    rdo.lifetime = 2;
    rdo.maxRankOrNh = 3;
    rdo.target = primaryTarget; // not node 1 -- only the Target options below are
    rdo.addressVector = {};
    dio.SetP2pRdo(rdo);

    RplDioHeader::TargetOption ownTarget;
    ownTarget.target = rpl->GetGlobalAddress();
    dio.AddTarget(ownTarget);
    RplDioHeader::TargetOption stillOutstanding;
    stillOutstanding.target = otherTarget;
    dio.AddTarget(stillOutstanding);

    DeliverRawRplMessage<RplDioHeader>(node,
                                       1,
                                       dio,
                                       static_cast<uint8_t>(RPL_CODE_DIO),
                                       neighbour,
                                       Ipv6Address(RPL_ALL_NODES_MULTICAST));

    NS_TEST_ASSERT_MSG_EQ(rpl->IsP2pTarget(INSTANCE, origin),
                          true,
                          "The node did not recognise itself as a Target via an RPL Target "
                          "option, only checking the P2P-RDO's own primary TargetAddr");

    // SendP2pDro()'s multicast is scheduled onto the channel, not delivered
    // synchronously (@see RplP2pDroAckWrongSequenceTestCase's own comment).
    Simulator::Stop(MilliSeconds(10));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(m_seenDro, true, "No P2P-DRO was ever sent");
    NS_TEST_ASSERT_MSG_EQ(m_captured.GetStop(),
                          false,
                          "'S' was set even though a second RPL Target option (a still-"
                          "undiscovered Target) remains unaddressed");
    NS_TEST_ASSERT_MSG_EQ(m_captured.HasP2pRdo(), true, "No P2P-RDO");
    NS_TEST_ASSERT_MSG_EQ(m_captured.GetP2pRdo().target,
                          rpl->GetGlobalAddress(),
                          "The P2P-DRO's own TargetAddr should be this node's address, not the "
                          "DIO's original primary TargetAddr");

    monitor->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A relay that matches none of a P2P mode DIO's Targets still
 *        carries every RPL Target option forward when it re-broadcasts,
 *        so a Target two hops from the Origin still gets discovered.
 *
 * Found by /protocol-test-matrix auditing this feature after the fact:
 * RplP2pMultiTargetTestCase only ever checked the single node a DIO was
 * delivered straight to, never that a relay's own re-transmission
 * (SendDio(), which rebuilds every DIO from a membership's own stored
 * state) actually re-attached the RPL Target options it had recorded.
 * It did not: SendDio()'s P2P branch built the P2P-RDO from
 * dodag.p2p.addressVector/target but never called AddTarget() for
 * dodag.p2p.additionalTargets, so a multi-Target discovery silently lost
 * every Target beyond the primary one after a single hop. This is the
 * regression test for the fix.
 *
 *     node0 (base root) ---- node1 (relay) ---- node2 (Target)
 *
 * node1 is fed a DIO naming an unrelated primary Target plus one RPL
 * Target option naming node2's address; node1 itself matches neither.
 * If node1's own re-broadcast (over the real channel, not injected)
 * still carries that Target option, node2 -- a real node, not a
 * synthetic delivery -- recognises itself as the Target.
 */
class RplP2pMultiTargetRelayTestCase : public TestCase
{
  public:
    RplP2pMultiTargetRelayTestCase();

  private:
    void DoRun() override;
};

RplP2pMultiTargetRelayTestCase::RplP2pMultiTargetRelayTestCase()
    : TestCase("A relay re-broadcasts every RPL Target option, not just the primary one")
{
}

void
RplP2pMultiTargetRelayTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(3); // 0 = base root, 1 = relay under test, 2 = the Target

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    ipv6.AssignWithoutAddress(devices);

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    Simulator::Stop(Seconds(10));
    Simulator::Run();

    Ptr<Node> relayNode = nodes.Get(1);
    Ptr<RplRoutingProtocol> relay = relayNode->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> targ = nodes.Get(2)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(relay->IsJoined(), true, "The base DODAG did not reach node 1");
    NS_TEST_ASSERT_MSG_EQ(targ->IsJoined(), true, "The base DODAG did not reach node 2");

    Ipv6Address origin("2001:9::1");         // no real node owns this address
    Ipv6Address primaryTarget("2001:9::99"); // unrelated to both node 1 and node 2
    Ipv6Address neighbour("fe80::a");
    static constexpr uint8_t INSTANCE = 0x81;

    RplDioHeader dio;
    dio.SetInstanceId(INSTANCE);
    dio.SetVersionNumber(0);
    dio.SetRank(RPL_MIN_HOPRANKINC);
    dio.SetMop(RPL_MOP_P2P_ROUTE_DISCOVERY);
    dio.SetGrounded(true);
    dio.SetDodagId(origin);
    dio.SetDtsn(0);
    dio.SetDagConfiguration(4, 6, 0, 0, RPL_MIN_HOPRANKINC, RPL_OCP_OF0, RPL_DEFAULT_LIFETIME,
                            RPL_DEFAULT_LIFETIME_UNIT);
    P2pRdoOption rdo;
    rdo.reply = true;
    rdo.hopByHop = false;
    rdo.numRoutes = 0;
    rdo.lifetime = 2; // 16 seconds
    rdo.maxRankOrNh = 3;
    rdo.target = primaryTarget; // neither node 1 nor node 2
    rdo.addressVector = {};
    dio.SetP2pRdo(rdo);

    RplDioHeader::TargetOption targetOption;
    targetOption.target = targ->GetGlobalAddress();
    dio.AddTarget(targetOption);

    DeliverRawRplMessage<RplDioHeader>(relayNode,
                                       1,
                                       dio,
                                       static_cast<uint8_t>(RPL_CODE_DIO),
                                       neighbour,
                                       Ipv6Address(RPL_ALL_NODES_MULTICAST));

    NS_TEST_ASSERT_MSG_EQ(relay->IsP2pTarget(INSTANCE, origin),
                          false,
                          "node 1 should not consider itself a Target here");

    // node1's own Trickle has to actually fire and reach node2 over the
    // real channel -- Imin is 64 ms per the DagConfiguration above, so 1 s
    // leaves a comfortable margin for at least one firing plus propagation.
    Simulator::Stop(Seconds(1));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(targ->IsP2pTarget(INSTANCE, origin),
                          true,
                          "node2 never recognised itself as the Target: node1's own "
                          "re-broadcast must have dropped the RPL Target option naming it");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A Target matched only through an RPL Target option, with no other
 *        Target left outstanding, sets the Stop flag and treats a repeat
 *        DIO as the ordinary single-Target repeat case does.
 *
 * design-constraints.md sections 41.3/45: RFC 6997 section 9.5's own Stop-
 * eligibility wording ("a unicast address of the router as the TargetAddr
 * inside the P2P-RDO with no additional Targets specified via RPL Target
 * options") and its "MUST NOT forward...if no other Targets are to be
 * discovered" condition are both worded around the primary-TargetAddr
 * case; read completely literally, neither could ever be satisfied for a
 * Target matched only via a Target option, since additionalTargets never
 * filters out this node's own matched entry (RplP2pMultiTargetTestCase's
 * own scenario, but that one always keeps a second, genuinely different
 * Target option outstanding, so it never exercises this specific edge).
 * HasOtherP2pTargets() is the more permissive reading this module settles
 * on instead: "is there a Target *other than me* still outstanding".
 *
 * Same two-node, one-way-blacklisted construction as
 * RplP2pMultiTargetTestCase, but with a single RPL Target option naming
 * only this node, and the same DIO delivered twice to also confirm the
 * repeat guard now short-circuits (rather than reprocessing indefinitely
 * for as long as the membership exists, the way it did before this
 * change, @see design-constraints.md section 41.2's droSequence overflow).
 */
class RplP2pSoleTargetViaOptionStopsTestCase : public TestCase
{
  public:
    RplP2pSoleTargetViaOptionStopsTestCase();

  private:
    void DoRun() override;

    /// @brief Count a P2P-DRO seen at the monitor, capturing the first.
    /// @param socket the monitoring socket
    void CaptureDro(Ptr<Socket> socket);

    uint32_t m_droCount{0};     //!< P2P-DROs seen at the monitor
    RplP2pDroHeader m_captured; //!< the first one seen
};

RplP2pSoleTargetViaOptionStopsTestCase::RplP2pSoleTargetViaOptionStopsTestCase()
    : TestCase("A Target matched only via an RPL Target option, with none other outstanding, "
               "sets Stop and treats a repeat as already-answered")
{
}

void
RplP2pSoleTargetViaOptionStopsTestCase::CaptureDro(Ptr<Socket> socket)
{
    Address sender;
    Ptr<Packet> packet = socket->RecvFrom(sender);
    if (!packet)
    {
        return;
    }
    Ipv6Header ipv6Header;
    packet->RemoveHeader(ipv6Header);
    Icmpv6Header icmpv6Header;
    packet->RemoveHeader(icmpv6Header);
    if (icmpv6Header.GetType() != ICMPV6_RPL || icmpv6Header.GetCode() != RPL_CODE_P2P_DRO)
    {
        return;
    }
    if (m_droCount == 0)
    {
        packet->RemoveHeader(m_captured);
    }
    m_droCount++;
}

void
RplP2pSoleTargetViaOptionStopsTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    ipv6.AssignWithoutAddress(devices);

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    Simulator::Stop(Seconds(10));
    Simulator::Run();

    Ptr<Node> node = nodes.Get(1);
    Ptr<RplRoutingProtocol> rpl = node->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(rpl->IsJoined(), true, "The base DODAG did not reach node 1");

    Ptr<SimpleNetDevice> dev0 = DynamicCast<SimpleNetDevice>(devices.Get(0));
    Ptr<SimpleNetDevice> dev1 = DynamicCast<SimpleNetDevice>(devices.Get(1));
    channel->BlackList(dev0, dev1);

    Ptr<Socket> monitor = Socket::CreateSocket(nodes.Get(0), Ipv6RawSocketFactory::GetTypeId());
    monitor->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    monitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    monitor->BindToNetDevice(nodes.Get(0)->GetObject<Ipv6L3Protocol>()->GetNetDevice(1));
    monitor->SetRecvCallback(
        MakeCallback(&RplP2pSoleTargetViaOptionStopsTestCase::CaptureDro, this));

    Ipv6Address origin("2001:9::1");         // no real node owns this address
    Ipv6Address primaryTarget("2001:9::99"); // unrelated to node 1
    Ipv6Address neighbour("fe80::a");
    static constexpr uint8_t INSTANCE = 0x81;

    RplDioHeader dio;
    dio.SetInstanceId(INSTANCE);
    dio.SetVersionNumber(0);
    dio.SetRank(RPL_MIN_HOPRANKINC);
    dio.SetMop(RPL_MOP_P2P_ROUTE_DISCOVERY);
    dio.SetGrounded(true);
    dio.SetDodagId(origin);
    dio.SetDtsn(0);
    dio.SetDagConfiguration(4,
                            6,
                            0,
                            0,
                            RPL_MIN_HOPRANKINC,
                            RPL_OCP_OF0,
                            RPL_DEFAULT_LIFETIME,
                            RPL_DEFAULT_LIFETIME_UNIT);
    P2pRdoOption rdo;
    rdo.reply = true;
    rdo.hopByHop = false;
    rdo.numRoutes = 0;
    rdo.lifetime = 2;
    rdo.maxRankOrNh = 3;
    rdo.target = primaryTarget; // not node 1 -- only the Target option below is
    rdo.addressVector = {};
    dio.SetP2pRdo(rdo);

    RplDioHeader::TargetOption ownTarget;
    ownTarget.target = rpl->GetGlobalAddress();
    dio.AddTarget(ownTarget); // the only Target option: nothing else outstanding

    DeliverRawRplMessage<RplDioHeader>(node,
                                       1,
                                       dio,
                                       static_cast<uint8_t>(RPL_CODE_DIO),
                                       neighbour,
                                       Ipv6Address(RPL_ALL_NODES_MULTICAST));

    NS_TEST_ASSERT_MSG_EQ(rpl->IsP2pTarget(INSTANCE, origin),
                          true,
                          "The node did not recognise itself as a Target via the RPL Target "
                          "option");

    // SendP2pDro()'s multicast is scheduled onto the channel, not delivered
    // synchronously (@see RplP2pDroAckWrongSequenceTestCase's own comment).
    Simulator::Stop(MilliSeconds(10));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(m_droCount, 1, "No P2P-DRO was ever sent");
    NS_TEST_ASSERT_MSG_EQ(m_captured.GetStop(),
                          true,
                          "'S' should have been set: this node is the only Target outstanding, "
                          "even though it was named only via an RPL Target option rather than "
                          "the P2P-RDO's own primary TargetAddr");

    // The same DIO again: RFC 6997 section 9.5's "MUST NOT forward...if no
    // other Targets are to be discovered" should now bite the same way it
    // already does for a Target named via the primary TargetAddr, so this
    // must be silently ignored as an already-answered repeat, not
    // reprocessed into a second P2P-DRO.
    DeliverRawRplMessage<RplDioHeader>(node,
                                       1,
                                       dio,
                                       static_cast<uint8_t>(RPL_CODE_DIO),
                                       neighbour,
                                       Ipv6Address(RPL_ALL_NODES_MULTICAST));
    Simulator::Stop(MilliSeconds(10));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(m_droCount,
                          1,
                          "A repeat DIO for the same sole Target-option match produced a second "
                          "P2P-DRO: the repeat guard should have short-circuited it");

    monitor->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A P2P-DRO-ACK for the wrong sequence is ignored, not mistaken for
 *        the one actually outstanding.
 *
 * RFC 6997 section 10: "Various fields in a P2P-DRO-ACK message MUST have
 * the same values as the corresponding fields in the P2P-DRO message" --
 * HandleP2pDroAck() checks Seq against dodag.p2p.droSequence before
 * cancelling the retry timer, but nothing so far had actually delivered a
 * mismatched one to confirm the check bites. Same two-node construction as
 * RplP2pDroRetryTestCase (@see its own doc comment for why a single
 * self-rooted node hangs), but this time a P2P-DRO-ACK naming the wrong
 * Seq is delivered directly (DeliverRawRplMessage()) to node 1 in between
 * the original P2P-DRO and the point its retry would otherwise fire.
 */
class RplP2pDroAckWrongSequenceTestCase : public TestCase
{
  public:
    RplP2pDroAckWrongSequenceTestCase();

  private:
    void DoRun() override;

    /// @brief Count each P2P-DRO seen at the monitor.
    /// @param socket the monitoring socket
    void CaptureDro(Ptr<Socket> socket);

    uint32_t m_droCount{0}; //!< how many times node 1 has sent a P2P-DRO
};

RplP2pDroAckWrongSequenceTestCase::RplP2pDroAckWrongSequenceTestCase()
    : TestCase("A P2P-DRO-ACK for the wrong sequence does not cancel the retry")
{
}

void
RplP2pDroAckWrongSequenceTestCase::CaptureDro(Ptr<Socket> socket)
{
    Address sender;
    Ptr<Packet> packet = socket->RecvFrom(sender);
    if (!packet)
    {
        return;
    }
    Ipv6Header ipv6Header;
    packet->RemoveHeader(ipv6Header);
    Icmpv6Header icmpv6Header;
    packet->RemoveHeader(icmpv6Header);
    if (icmpv6Header.GetType() != ICMPV6_RPL || icmpv6Header.GetCode() != RPL_CODE_P2P_DRO)
    {
        return;
    }
    m_droCount++;
}

void
RplP2pDroAckWrongSequenceTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    rplHelper.Set("P2pDroAckWaitTime", TimeValue(MilliSeconds(100)));
    rplHelper.Set("P2pDroMaxRetransmissions", UintegerValue(2));
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    ipv6.AssignWithoutAddress(devices);

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    // Same margin as RplP2pDroRetryTestCase: base RPL's DioIntervalMin
    // default (4.096 s) means the root's first DIO can take that long.
    Simulator::Stop(Seconds(10));
    Simulator::Run();

    Ptr<Node> node = nodes.Get(1);
    Ptr<RplRoutingProtocol> rpl = node->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(rpl->IsJoined(), true, "The base DODAG did not reach node 1");

    Ptr<SimpleNetDevice> dev0 = DynamicCast<SimpleNetDevice>(devices.Get(0));
    Ptr<SimpleNetDevice> dev1 = DynamicCast<SimpleNetDevice>(devices.Get(1));
    channel->BlackList(dev0, dev1);

    Ptr<Socket> monitor =
        Socket::CreateSocket(nodes.Get(0), Ipv6RawSocketFactory::GetTypeId());
    monitor->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    monitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    monitor->BindToNetDevice(nodes.Get(0)->GetObject<Ipv6L3Protocol>()->GetNetDevice(1));
    monitor->SetRecvCallback(MakeCallback(&RplP2pDroAckWrongSequenceTestCase::CaptureDro, this));

    Ipv6Address origin("2001:9::1"); // no real node owns this address
    Ipv6Address neighbour("fe80::a");
    static constexpr uint8_t INSTANCE = 0x81;

    RplDioHeader dio;
    dio.SetInstanceId(INSTANCE);
    dio.SetVersionNumber(0);
    dio.SetRank(RPL_MIN_HOPRANKINC);
    dio.SetMop(RPL_MOP_P2P_ROUTE_DISCOVERY);
    dio.SetGrounded(true);
    dio.SetDodagId(origin);
    dio.SetDtsn(0);
    // @see RplP2pDroRetryTestCase's own comment: without this,
    // dodag.dioIntervalMin stays at zero and Trickle livelocks.
    dio.SetDagConfiguration(4, 6, 0, 0, RPL_MIN_HOPRANKINC, RPL_OCP_OF0, RPL_DEFAULT_LIFETIME,
                            RPL_DEFAULT_LIFETIME_UNIT);
    P2pRdoOption rdo;
    rdo.reply = true;
    rdo.hopByHop = false;
    rdo.numRoutes = 0;
    rdo.lifetime = 2; // 16 seconds, comfortably past this test's own window
    rdo.maxRankOrNh = 3;
    rdo.target = rpl->GetGlobalAddress(); // node 1 is the Target
    rdo.addressVector = {};
    dio.SetP2pRdo(rdo);

    DeliverRawRplMessage<RplDioHeader>(node,
                                       1,
                                       dio,
                                       static_cast<uint8_t>(RPL_CODE_DIO),
                                       neighbour,
                                       Ipv6Address(RPL_ALL_NODES_MULTICAST));

    NS_TEST_ASSERT_MSG_EQ(rpl->IsP2pTarget(INSTANCE, origin),
                          true,
                          "The node did not recognise itself as the Target");

    // SendP2pDro()'s multicast is scheduled onto the channel
    // (SimpleChannel::Send() uses Simulator::ScheduleWithContext()), not
    // delivered synchronously, so it needs a short run before the monitor
    // actually sees it.
    Simulator::Stop(MilliSeconds(10));
    Simulator::Run();
    NS_TEST_ASSERT_MSG_EQ(m_droCount, 1, "The first P2P-DRO was not sent");

    // A P2P-DRO-ACK for Seq 2, when the outstanding one is Seq 1 (the first
    // and, so far, only cycle HandleP2pRdo() has started): must not be
    // mistaken for the real one.
    RplP2pDroAckHeader wrongAck;
    wrongAck.SetInstanceId(INSTANCE);
    wrongAck.SetSequence(2);
    wrongAck.SetDodagId(origin);
    DeliverRawRplMessage<RplP2pDroAckHeader>(node,
                                             1,
                                             wrongAck,
                                             static_cast<uint8_t>(RPL_CODE_P2P_DRO_ACK),
                                             neighbour,
                                             rpl->GetGlobalAddress());

    // Long enough for both retries P2pDroMaxRetransmissions=2 allows to
    // fire (P2pDroAckWaitTime is 100 ms here, so ~100 ms and ~200 ms after
    // the original) if the wrong-sequence ack had (incorrectly) cancelled
    // the cycle, none would.
    Simulator::Stop(Seconds(0.5));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(m_droCount,
                          3,
                          "The wrong-sequence P2P-DRO-ACK cancelled the retry cycle: the "
                          "Target should have retried both times by now (the original plus "
                          "P2pDroMaxRetransmissions=2), exactly as if no ack had arrived at "
                          "all");

    monitor->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A P2P-RPL discovery completes end to end: the P2P-DRO relays back
 *        along the trimmed Address Vector, the Origin stores an
 *        Origin-outward route from it, and the route carries data.
 *
 * The increment 5/6 counterpart of RplAodvAsymmetricRouteCompletesTestCase,
 * on the same four-node line:
 *
 *     orig(0) ---- relay1(1) ---- relay2(2) ---- targ(3)
 *
 * The Target answers with a P2P-DRO carrying [relay1, relay2] (its own
 * trailing entry already trimmed, RplP2pDroGeneratedTestCase's own
 * concern); each relay named at the Address Vector's current NH position
 * decrements NH and re-multicasts without recording anything, since H=0
 * keeps no per-hop state; the Origin recognises its own address in the
 * P2P-DRO's DODAGID field and stores the vector as a route, appending the
 * Target -- no reversal needed, unlike AODV-RPL's asymmetric RREP-Instance,
 * because the P2P-DRO's vector is a fixed snapshot rather than something
 * accumulated hop by hop during the relay back.
 *
 * What this pins down beyond the bookkeeping is that the route works: a UDP
 * datagram sent to the Target has to traverse both relays, which only
 * happens if RouteOutput() picked the discovered route, if
 * PrepareOutgoingPacket() turned it into a Routing Header, and if
 * RplIpv6ExtensionSourceRouting::Process() walked it hop by hop.
 */
class RplP2pRouteCompletesTestCase : public TestCase
{
  public:
    RplP2pRouteCompletesTestCase();

  private:
    void DoRun() override;

    /// @brief Count a datagram delivered at the Target.
    /// @param socket the receiving socket
    void CountDelivery(Ptr<Socket> socket);

    /// @brief Send one datagram, as a named method Simulator::Schedule() can
    ///        resolve (Socket::Send is overloaded).
    /// @param socket the sending socket
    void SendOne(Ptr<Socket> socket);

    /// @brief Count each P2P-DRO seen at the monitor that came from the
    ///        Target itself (not a relay's own re-transmission of it) --
    ///        proves the P2P-DRO-ACK this scenario's default
    ///        P2pDroAckRequested=true actually reaches the Target and
    ///        P2pDroRetry() has nothing to retry, the one thing this
    ///        class's own end-to-end setup had never checked.
    /// @param socket the monitoring socket
    void CaptureDro(Ptr<Socket> socket);

    uint32_t m_delivered{0}; //!< datagrams that reached the Target
    int m_sendResult{0};     //!< what Socket::Send() returned, -1 on refusal
    Ipv6Address m_targLinkLocal; //!< set before Simulator::Run(), filters CaptureDro()
    uint32_t m_droCount{0};      //!< how many times the Target has sent a P2P-DRO
};

RplP2pRouteCompletesTestCase::RplP2pRouteCompletesTestCase()
    : TestCase("A P2P-RPL P2P-DRO returns a source route that carries data end to end")
{
}

void
RplP2pRouteCompletesTestCase::CaptureDro(Ptr<Socket> socket)
{
    Address sender;
    Ptr<Packet> packet = socket->RecvFrom(sender);
    if (!packet)
    {
        return;
    }
    Ipv6Header ipv6Header;
    packet->RemoveHeader(ipv6Header);
    if (ipv6Header.GetSource() != m_targLinkLocal)
    {
        // relay2 relays every P2P-DRO it receives onward (NH decremented),
        // the same reason RplP2pDroRetryTestCase's own CaptureDro() filters
        // by source.
        return;
    }
    Icmpv6Header icmpv6Header;
    packet->RemoveHeader(icmpv6Header);
    if (icmpv6Header.GetType() != ICMPV6_RPL || icmpv6Header.GetCode() != RPL_CODE_P2P_DRO)
    {
        return;
    }
    m_droCount++;
}

void
RplP2pRouteCompletesTestCase::CountDelivery(Ptr<Socket> socket)
{
    Ptr<Packet> packet = socket->Recv();
    while (packet)
    {
        m_delivered++;
        packet = socket->Recv();
    }
}

void
RplP2pRouteCompletesTestCase::SendOne(Ptr<Socket> socket)
{
    m_sendResult = socket->Send(Create<Packet>(64));
}

void
RplP2pRouteCompletesTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(4); // 0 = Origin and base root, 1 and 2 = relays, 3 = Target

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    auto blacklist = [&](uint32_t a, uint32_t b) {
        Ptr<SimpleNetDevice> devA = DynamicCast<SimpleNetDevice>(devices.Get(a));
        Ptr<SimpleNetDevice> devB = DynamicCast<SimpleNetDevice>(devices.Get(b));
        channel->BlackList(devA, devB);
        channel->BlackList(devB, devA);
    };
    blacklist(0, 2);
    blacklist(0, 3);
    blacklist(1, 3);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(250));
    Simulator::Run();

    Ptr<RplRoutingProtocol> orig = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay1 = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay2 = nodes.Get(2)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> targ = nodes.Get(3)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(targ->IsJoined(), true, "The base DODAG did not reach the far end");

    Ipv6Address relay1Address = relay1->GetGlobalAddress();
    Ipv6Address relay2Address = relay2->GetGlobalAddress();
    Ipv6Address targAddress = targ->GetGlobalAddress();

    NS_TEST_ASSERT_MSG_EQ(orig->GetP2pRouteCount(), 0, "A route exists before any discovery");

    // Watching from relay2, the same vantage RplP2pDroGeneratedTestCase and
    // RplP2pDroRetryTestCase use, filtered to P2P-DROs that came from the
    // Target itself.
    m_targLinkLocal = nodes.Get(3)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ptr<Socket> droMonitor =
        Socket::CreateSocket(nodes.Get(2), Ipv6RawSocketFactory::GetTypeId());
    droMonitor->SetAttribute("Protocol",
                             UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    droMonitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    droMonitor->BindToNetDevice(nodes.Get(2)->GetObject<Ipv6L3Protocol>()->GetNetDevice(1));
    droMonitor->SetRecvCallback(MakeCallback(&RplP2pRouteCompletesTestCase::CaptureDro, this));

    RplRoutingProtocol::DodagKey key = orig->DiscoverP2pRoute(targAddress);
    NS_TEST_ASSERT_MSG_NE(key.dodagId, Ipv6Address::GetAny(), "The discovery did not start");

    Simulator::Stop(Seconds(10));
    Simulator::Run();

    std::vector<Ipv6Address> hops;
    NS_TEST_ASSERT_MSG_EQ(orig->GetP2pRoute(targAddress, hops),
                          true,
                          "The P2P-DRO never produced a route at the Origin");
    NS_TEST_ASSERT_MSG_EQ(hops.size(), 3, "The discovered route has the wrong length");
    NS_TEST_ASSERT_MSG_EQ(hops[0],
                          relay1Address,
                          "The route starts at the wrong end: relay1 is the Origin's own "
                          "neighbour, so it has to come first");
    NS_TEST_ASSERT_MSG_EQ(hops[1], relay2Address, "Wrong second hop");
    NS_TEST_ASSERT_MSG_EQ(hops[2], targAddress, "The route does not end at the Target");
    NS_TEST_ASSERT_MSG_EQ(orig->GetP2pRouteCount(), 1, "Wrong number of routes");

    // The Origin's P2pDroAckRequested default is true, so getting this far
    // (the route above is only recorded once the Origin processes the
    // P2P-DRO) already means it should have generated and unicast a
    // P2P-DRO-ACK -- confirmed by there being exactly one P2P-DRO from the
    // Target, not the up-to-four (1 + P2pDroMaxRetransmissions) an
    // unacknowledged one would produce (@see RplP2pDroRetryTestCase). Run
    // well past P2pDroAckWaitTime's 1 s default to be sure a retry was not
    // simply still pending.
    NS_TEST_ASSERT_MSG_EQ(m_droCount,
                          1,
                          "The Target retried its P2P-DRO, meaning the P2P-DRO-ACK never "
                          "arrived or was not recognised");
    Simulator::Stop(Seconds(2));
    Simulator::Run();
    NS_TEST_ASSERT_MSG_EQ(m_droCount,
                          1,
                          "A P2P-DRO retry appeared after the fact: the ack did not actually "
                          "cancel P2pDroRetry()'s timer");
    droMonitor->Close();

    // Source routing keeps no per-hop state.
    NS_TEST_ASSERT_MSG_EQ(relay1->GetP2pRouteCount(), 0, "relay1 recorded a route it should not");
    NS_TEST_ASSERT_MSG_EQ(relay2->GetP2pRouteCount(), 0, "relay2 recorded a route it should not");

    // And it works. A route stored backwards would still have three entries
    // and still look like a path; only actually sending over it tells the
    // difference.
    uint16_t port = 4243;
    Ptr<Socket> receiver = Socket::CreateSocket(nodes.Get(3), UdpSocketFactory::GetTypeId());
    receiver->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), port));
    receiver->SetRecvCallback(MakeCallback(&RplP2pRouteCompletesTestCase::CountDelivery, this));

    Ptr<Socket> sender = Socket::CreateSocket(nodes.Get(0), UdpSocketFactory::GetTypeId());
    sender->Connect(Inet6SocketAddress(targAddress, port));
    Simulator::Schedule(Seconds(1), &RplP2pRouteCompletesTestCase::SendOne, this, sender);

    Simulator::Stop(Seconds(5));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_GT(m_sendResult, 0, "Socket::Send() refused the datagram outright");
    NS_TEST_ASSERT_MSG_EQ(m_delivered,
                          1,
                          "The datagram never reached the Target over the P2P-RPL route");

    receiver->Close();
    sender->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A P2P-RPL Hop-by-hop Route (H=1) carries data end to end, each
 *        relay holding only its own next hop rather than the whole path.
 *
 * RplP2pRouteCompletesTestCase's own four-node line and channel
 * blacklisting:
 *
 *     orig(0) ---- relay1(1) ---- relay2(2) ---- targ(3)
 *
 * but with DiscoverP2pRoute()'s hopByHop parameter set, so the Target's
 * P2P-DRO carries H=1 and each relay stores a next-hop entry (RFC 6997
 * section 9.6) instead of the Origin recording the whole path (section
 * 9.7). GetP2pRouteCount() staying 0 throughout, at every node, is what
 * tells this apart from the H=0 case actually running instead of the H=1
 * one asked for.
 */
class RplP2pHopByHopRouteCompletesTestCase : public TestCase
{
  public:
    RplP2pHopByHopRouteCompletesTestCase();

  private:
    void DoRun() override;

    /// @brief Count a datagram delivered at the Target.
    /// @param socket the receiving socket
    void CountDelivery(Ptr<Socket> socket);

    /// @brief Send one datagram, as a named method Simulator::Schedule() can
    ///        resolve (Socket::Send is overloaded).
    /// @param socket the sending socket
    void SendOne(Ptr<Socket> socket);

    uint32_t m_delivered{0}; //!< datagrams that reached the Target
    int m_sendResult{0};     //!< what Socket::Send() returned, -1 on refusal
};

RplP2pHopByHopRouteCompletesTestCase::RplP2pHopByHopRouteCompletesTestCase()
    : TestCase("A P2P-RPL Hop-by-hop Route (H=1) carries data end to end")
{
}

void
RplP2pHopByHopRouteCompletesTestCase::CountDelivery(Ptr<Socket> socket)
{
    Ptr<Packet> packet = socket->Recv();
    while (packet)
    {
        m_delivered++;
        packet = socket->Recv();
    }
}

void
RplP2pHopByHopRouteCompletesTestCase::SendOne(Ptr<Socket> socket)
{
    m_sendResult = socket->Send(Create<Packet>(64));
}

void
RplP2pHopByHopRouteCompletesTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(4); // 0 = Origin and base root, 1 and 2 = relays, 3 = Target

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    auto blacklist = [&](uint32_t a, uint32_t b) {
        Ptr<SimpleNetDevice> devA = DynamicCast<SimpleNetDevice>(devices.Get(a));
        Ptr<SimpleNetDevice> devB = DynamicCast<SimpleNetDevice>(devices.Get(b));
        channel->BlackList(devA, devB);
        channel->BlackList(devB, devA);
    };
    blacklist(0, 2);
    blacklist(0, 3);
    blacklist(1, 3);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(250));
    Simulator::Run();

    Ptr<RplRoutingProtocol> orig = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay1 = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay2 = nodes.Get(2)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> targ = nodes.Get(3)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(targ->IsJoined(), true, "The base DODAG did not reach the far end");

    Ipv6Address relay1Address = relay1->GetGlobalAddress();
    Ipv6Address relay2Address = relay2->GetGlobalAddress();
    Ipv6Address targAddress = targ->GetGlobalAddress();

    RplRoutingProtocol::DodagKey key = orig->DiscoverP2pRoute(targAddress, true);
    NS_TEST_ASSERT_MSG_NE(key.dodagId, Ipv6Address::GetAny(), "The discovery did not start");

    Simulator::Stop(Seconds(10));
    Simulator::Run();

    // H=1: no whole-path route recorded anywhere, unlike
    // RplP2pRouteCompletesTestCase's own H=0 scenario.
    NS_TEST_ASSERT_MSG_EQ(orig->GetP2pRouteCount(),
                          0,
                          "A Source Route was recorded for what should have been a Hop-by-hop "
                          "Route discovery");

    // Each hop holds only its own next hop (RFC 6997 section 9.6/9.7),
    // and each one is the next hop actually on the path to the Target,
    // not merely present.
    Ipv6Address nextHop;
    uint8_t hopInstanceId = 0;
    NS_TEST_ASSERT_MSG_EQ(orig->GetHopByHopRoute(targAddress, nextHop, key.instanceId),
                          true,
                          "The Origin never recorded a Hop-by-hop Route");
    NS_TEST_ASSERT_MSG_EQ(nextHop, relay1Address, "The Origin's own next hop is wrong");
    NS_TEST_ASSERT_MSG_EQ(relay1->GetHopByHopRoute(targAddress, nextHop, hopInstanceId),
                          true,
                          "relay1 never recorded a Hop-by-hop Route");
    NS_TEST_ASSERT_MSG_EQ(nextHop, relay2Address, "relay1's own next hop is wrong");
    NS_TEST_ASSERT_MSG_EQ(relay2->GetHopByHopRoute(targAddress, nextHop, hopInstanceId),
                          true,
                          "relay2 never recorded a Hop-by-hop Route");
    NS_TEST_ASSERT_MSG_EQ(nextHop, targAddress, "relay2's own next hop is wrong");

    // And it works: a datagram sent from the Origin, addressed to the
    // Target, has to actually cross relay1 and relay2's own independent
    // next-hop lookups to arrive -- not a Routing Header carrying the
    // whole path, since none was ever attached.
    uint16_t port = 4244;
    Ptr<Socket> receiver = Socket::CreateSocket(nodes.Get(3), UdpSocketFactory::GetTypeId());
    receiver->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), port));
    receiver->SetRecvCallback(
        MakeCallback(&RplP2pHopByHopRouteCompletesTestCase::CountDelivery, this));

    Ptr<Socket> sender = Socket::CreateSocket(nodes.Get(0), UdpSocketFactory::GetTypeId());
    sender->Connect(Inet6SocketAddress(targAddress, port));
    Simulator::Schedule(Seconds(1), &RplP2pHopByHopRouteCompletesTestCase::SendOne, this, sender);

    Simulator::Stop(Seconds(5));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_GT(m_sendResult, 0, "Socket::Send() refused the datagram outright");
    NS_TEST_ASSERT_MSG_EQ(m_delivered,
                          1,
                          "The datagram never reached the Target over the Hop-by-hop Route");

    receiver->Close();
    sender->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A P2P-RPL Hop-by-hop Route (H=1) keeps carrying data after the
 *        temporary DAG that discovered it has left, at every hop.
 *
 * RFC 6997 section 7 has a router unconditionally leave the temporary DAG
 * at its own 'L' deadline, well before the Hop-by-hop Route's own,
 * typically much longer Default Lifetime/Lifetime Unit expires. The same
 * three-hop scenario as RplP2pHopByHopRouteCompletesTestCase, but data is
 * sent only after every node's own temporary DAG membership has already
 * expired -- proving the route itself (GetHopByHopRoute()/
 * HasHopByHopRoute()) genuinely outlives it and RouteOutput()/RouteInput()
 * still forward correctly with no live membership behind rpi.GetInstanceId()
 * at any hop.
 *
 * This does not, on its own, prove RplIpv6OptionRpl::Process()'s own
 * HasHopByHopRoute() early return load-bearing: this module's isDropped
 * only traces a confirmed rank inconsistency rather than enforcing it
 * (@see design-constraints.md), so this test still passes with that early
 * return removed -- what it prevents instead is a live, unrelated DODAG
 * elsewhere reusing the same instanceId misreading the rewritten
 * SenderRank as a genuine inconsistency (@see that early return's own
 * comment). Kept here anyway as the direct, positive demonstration of the
 * property actually promised (data keeps flowing after the temporary DAG
 * is gone), which is the part worth a dedicated test regardless.
 */
class RplP2pHopByHopRouteOutlivesTemporaryDagTestCase : public TestCase
{
  public:
    RplP2pHopByHopRouteOutlivesTemporaryDagTestCase();

  private:
    void DoRun() override;

    /// @brief Count a datagram delivered at the Target.
    /// @param socket the receiving socket
    void CountDelivery(Ptr<Socket> socket);

    /// @brief Send one datagram, as a named method Simulator::Schedule() can
    ///        resolve (Socket::Send is overloaded).
    /// @param socket the sending socket
    void SendOne(Ptr<Socket> socket);

    uint32_t m_delivered{0}; //!< datagrams that reached the Target
    int m_sendResult{0};     //!< what Socket::Send() returned, -1 on refusal
};

RplP2pHopByHopRouteOutlivesTemporaryDagTestCase::RplP2pHopByHopRouteOutlivesTemporaryDagTestCase()
    : TestCase("A P2P-RPL Hop-by-hop Route keeps working after its temporary DAG has expired")
{
}

void
RplP2pHopByHopRouteOutlivesTemporaryDagTestCase::CountDelivery(Ptr<Socket> socket)
{
    Ptr<Packet> packet = socket->Recv();
    while (packet)
    {
        m_delivered++;
        packet = socket->Recv();
    }
}

void
RplP2pHopByHopRouteOutlivesTemporaryDagTestCase::SendOne(Ptr<Socket> socket)
{
    m_sendResult = socket->Send(Create<Packet>(64));
}

void
RplP2pHopByHopRouteOutlivesTemporaryDagTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(4); // 0 = Origin and base root, 1 and 2 = relays, 3 = Target

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    auto blacklist = [&](uint32_t a, uint32_t b) {
        Ptr<SimpleNetDevice> devA = DynamicCast<SimpleNetDevice>(devices.Get(a));
        Ptr<SimpleNetDevice> devB = DynamicCast<SimpleNetDevice>(devices.Get(b));
        channel->BlackList(devA, devB);
        channel->BlackList(devB, devA);
    };
    blacklist(0, 2);
    blacklist(0, 3);
    blacklist(1, 3);

    RplHelper rplHelper;
    // Encoding 1 (4 s, @see RplP2pLifetimeSeconds()), not the default 2
    // (16 s): fast enough that waiting well past it does not make this
    // test slow, but with enough margin over the few hundred milliseconds
    // the discovery itself takes (each hop's own 'L' deadline re-arms on
    // every DIO/P2P-DRO it processes, @see ArmP2pExpiry(), so what matters
    // is headroom between consecutive messages, not the discovery's total
    // duration) that a slow Trickle draw does not fail the discovery
    // outright before this test ever gets to the point under test.
    rplHelper.Set("P2pLifetime", UintegerValue(1));
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(250));
    Simulator::Run();

    Ptr<RplRoutingProtocol> orig = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay1 = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> relay2 = nodes.Get(2)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> targ = nodes.Get(3)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(targ->IsJoined(), true, "The base DODAG did not reach the far end");

    Ipv6Address targAddress = targ->GetGlobalAddress();

    RplRoutingProtocol::DodagKey key = orig->DiscoverP2pRoute(targAddress, true);
    NS_TEST_ASSERT_MSG_NE(key.dodagId, Ipv6Address::GetAny(), "The discovery did not start");

    Simulator::Stop(Seconds(10));
    Simulator::Run();

    Ipv6Address nextHop;
    NS_TEST_ASSERT_MSG_EQ(orig->GetHopByHopRoute(targAddress, nextHop, key.instanceId),
                          true,
                          "The Origin never recorded a Hop-by-hop Route");

    // Comfortably past P2pLifetime encoding 1's own 4 s
    // (RplP2pLifetimeSeconds()) for every node's temporary DAG membership
    // to have left on its own, each measured from the last DIO/P2P-DRO it
    // saw rather than from discovery start (@see ArmP2pExpiry()).
    Simulator::Stop(Seconds(15));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(orig->IsJoinedTo(key.instanceId, key.dodagId),
                          false,
                          "The Origin's own temporary DAG should have expired by now");
    NS_TEST_ASSERT_MSG_EQ(relay1->IsJoinedTo(key.instanceId, key.dodagId),
                          false,
                          "relay1's own temporary DAG membership should have expired by now");
    NS_TEST_ASSERT_MSG_EQ(relay2->IsJoinedTo(key.instanceId, key.dodagId),
                          false,
                          "relay2's own temporary DAG membership should have expired by now");

    // The Hop-by-hop Route itself must still be there at every hop --
    // P2pLifetime bounds the temporary DAG only, not the route it found
    // (RFC 6997's Default Lifetime/Lifetime Unit, this module's own
    // m_pathLifetime/m_lifetimeUnit, are independent attributes, at their
    // own generous defaults here).
    NS_TEST_ASSERT_MSG_EQ(orig->GetHopByHopRoute(targAddress, nextHop, key.instanceId),
                          true,
                          "The Origin's own Hop-by-hop Route did not outlive its temporary DAG");
    NS_TEST_ASSERT_MSG_EQ(relay1->HasHopByHopRoute(key.instanceId, targAddress),
                          true,
                          "relay1's own Hop-by-hop Route did not outlive its temporary DAG");
    NS_TEST_ASSERT_MSG_EQ(relay2->HasHopByHopRoute(key.instanceId, targAddress),
                          true,
                          "relay2's own Hop-by-hop Route did not outlive its temporary DAG");

    // And data still gets through -- the real point of this test.
    // RplIpv6OptionRpl::Process()'s rank-consistency check would otherwise
    // see an instanceId with no membership behind it at every one of
    // these now-expired nodes (GetRankForInstance() answering
    // RPL_INFINITE_RANK) and drop the packet as rank inconsistent well
    // before it ever reached the Target.
    uint16_t port = 4245;
    Ptr<Socket> receiver = Socket::CreateSocket(nodes.Get(3), UdpSocketFactory::GetTypeId());
    receiver->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), port));
    receiver->SetRecvCallback(
        MakeCallback(&RplP2pHopByHopRouteOutlivesTemporaryDagTestCase::CountDelivery, this));

    Ptr<Socket> sender = Socket::CreateSocket(nodes.Get(0), UdpSocketFactory::GetTypeId());
    sender->Connect(Inet6SocketAddress(targAddress, port));
    Simulator::Schedule(Seconds(1),
                        &RplP2pHopByHopRouteOutlivesTemporaryDagTestCase::SendOne,
                        this,
                        sender);

    Simulator::Stop(Seconds(5));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_GT(m_sendResult, 0, "Socket::Send() refused the datagram outright");
    NS_TEST_ASSERT_MSG_EQ(m_delivered,
                          1,
                          "The datagram never reached the Target: the Hop-by-hop Route did not "
                          "survive its temporary DAG's own expiry the way it is supposed to");

    receiver->Close();
    sender->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A P2P-DRO is relayed only by the router named at the Address
 *        Vector's current NH position, and not at all if that would be a
 *        loop.
 *
 * RplP2pRouteCompletesTestCase's four-node line, with its channel
 * blacklisting, never lets more than one router hear a given P2P-DRO
 * transmission at a time, so it cannot tell the NH-position gate and the
 * loop check in HandleP2pDro() apart from "this instance simply is not
 * named anywhere nearby" -- confirmed by probing both checks away in turn
 * and finding that test still passes either way. This drives fabricated
 * P2P-DROs straight at one node instead (DeliverRawRplMessage(), bypassing
 * the channel for input only -- a relay this node actually sends still
 * goes out for real, caught by a monitor socket on a second, real
 * neighbour, the same pattern RplP2pDroGeneratedTestCase uses).
 */
class RplP2pDroRelayTestCase : public TestCase
{
  public:
    RplP2pDroRelayTestCase();

  private:
    void DoRun() override;

    /// @brief Capture a relayed P2P-DRO seen at the monitor.
    /// @param socket the monitoring socket
    void CaptureDro(Ptr<Socket> socket);

    /**
     * @brief Join the node under test as an ordinary relay of a fresh
     *        fabricated temporary DAG, then deliver one fabricated P2P-DRO
     *        to it and report whether it relayed.
     *
     * @param node the node under test
     * @param ownIndices which 0-based Address Vector positions should hold
     *                   this node's own address (empty for none, one entry
     *                   for the ordinary case, two for the loop case)
     * @param nh the P2P-DRO's own NH field
     * @return true if a relayed copy was captured at the monitor
     */
    bool TryRelay(Ptr<Node> node, const std::vector<uint32_t>& ownIndices, uint8_t nh);

    bool m_seenRelay{false}; //!< a relayed P2P-DRO was captured
    uint8_t m_seenNh{0};     //!< its own NH field
};

RplP2pDroRelayTestCase::RplP2pDroRelayTestCase()
    : TestCase("A P2P-DRO is relayed only by the router at the current NH position, once")
{
}

void
RplP2pDroRelayTestCase::CaptureDro(Ptr<Socket> socket)
{
    Address sender;
    Ptr<Packet> packet = socket->RecvFrom(sender);
    if (!packet)
    {
        return;
    }
    Ipv6Header ipv6Header;
    packet->RemoveHeader(ipv6Header);
    Icmpv6Header icmpv6Header;
    packet->RemoveHeader(icmpv6Header);
    if (icmpv6Header.GetType() != ICMPV6_RPL || icmpv6Header.GetCode() != RPL_CODE_P2P_DRO)
    {
        return;
    }
    m_seenRelay = true;
    RplP2pDroHeader relayed;
    packet->RemoveHeader(relayed);
    m_seenNh = relayed.GetP2pRdo().maxRankOrNh;
}

bool
RplP2pDroRelayTestCase::TryRelay(Ptr<Node> node,
                                 const std::vector<uint32_t>& ownIndices,
                                 uint8_t nh)
{
    static uint16_t sequence = 0;
    sequence++;
    // A fresh Origin address per call: distinct each time so no earlier
    // sub-case's membership can interfere with this one's.
    std::ostringstream originSuffix;
    originSuffix << "2001:9::" << sequence << ":1";
    Ipv6Address origin(originSuffix.str().c_str());
    Ipv6Address neighbour("fe80::a");

    static constexpr uint8_t INSTANCE = 0x81;

    Ptr<RplRoutingProtocol> rpl = node->GetObject<RplRoutingProtocol>();

    // A P2P-DRO is only ever acted on if a matching temporary DAG
    // membership already exists (RFC 6997 sections 9.6/9.7), so join one
    // first, as an ordinary relay (the fabricated Target is never this
    // node).
    RplDioHeader joinDio;
    joinDio.SetInstanceId(INSTANCE);
    joinDio.SetVersionNumber(0);
    joinDio.SetRank(RPL_MIN_HOPRANKINC);
    joinDio.SetMop(RPL_MOP_P2P_ROUTE_DISCOVERY);
    joinDio.SetGrounded(true);
    joinDio.SetDodagId(origin);
    joinDio.SetDtsn(0);
    // Without a DODAG Configuration option, JoinDodag() leaves
    // dodag.dioIntervalMin at its raw default-constructed zero rather than
    // RFC 6997 section 6.1's own stated default DODAG Configuration Option
    // (64 ms) -- a real DIO from this module always attaches one
    // (SendDio() does so unconditionally), so this never comes up in
    // practice, but a fixture built by hand has to supply it explicitly or
    // the resulting Trickle timer schedules itself at Imin 0 and spins.
    joinDio.SetDagConfiguration(4, 6, 0, 0, RPL_MIN_HOPRANKINC, RPL_OCP_OF0, 0xFF, 0xFFFF);
    P2pRdoOption joinRdo;
    joinRdo.reply = true;
    joinRdo.hopByHop = false;
    joinRdo.maxRankOrNh = 0; // no limit
    joinRdo.target = Ipv6Address("2001:9::dead:1"); // never this node
    joinDio.SetP2pRdo(joinRdo);
    DeliverRawRplMessage<RplDioHeader>(node,
                                       1,
                                       joinDio,
                                       static_cast<uint8_t>(RPL_CODE_DIO),
                                       neighbour,
                                       Ipv6Address(RPL_ALL_NODES_MULTICAST));
    NS_ASSERT_MSG(rpl->IsJoinedTo(INSTANCE, origin), "Failed to set up this sub-case's fixture");

    // The P2P-DRO under test: a 3-entry Address Vector, with this node's
    // own address substituted in at the requested positions and arbitrary
    // fabricated addresses elsewhere.
    RplP2pDroHeader dro;
    dro.SetInstanceId(INSTANCE);
    dro.SetDodagId(origin);
    P2pRdoOption rdo;
    rdo.reply = false;
    rdo.hopByHop = false;
    rdo.target = Ipv6Address("2001:9::dead:2"); // the fabricated Target
    for (uint32_t i = 0; i < 3; i++)
    {
        if (std::find(ownIndices.begin(), ownIndices.end(), i) != ownIndices.end())
        {
            rdo.addressVector.push_back(rpl->GetGlobalAddress());
        }
        else
        {
            std::ostringstream hopSuffix;
            hopSuffix << "2001:9::" << sequence << ":" << (10 + i);
            rdo.addressVector.push_back(Ipv6Address(hopSuffix.str().c_str()));
        }
    }
    rdo.maxRankOrNh = nh;
    dro.SetP2pRdo(rdo);

    m_seenRelay = false;
    DeliverRawRplMessage<RplP2pDroHeader>(node,
                                          1,
                                          dro,
                                          static_cast<uint8_t>(RPL_CODE_P2P_DRO),
                                          neighbour,
                                          Ipv6Address(RPL_ALL_NODES_MULTICAST));

    // DeliverRawRplMessage() delivers synchronously, but a relay this node
    // decides to send goes out through SimpleChannel::Send(), which
    // schedules delivery via Simulator::ScheduleWithContext() rather than
    // calling the receiving device directly -- so it needs a further
    // Simulator::Run() to actually reach the monitor.
    Simulator::Stop(Seconds(1));
    Simulator::Run();

    return m_seenRelay;
}

void
RplP2pDroRelayTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2); // 0 = the router under test, 1 = a real neighbour to monitor from

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    ipv6.AssignWithoutAddress(devices);

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    Simulator::Stop(Seconds(2));
    Simulator::Run();

    Ptr<Node> node = nodes.Get(0);

    Ptr<Socket> monitor = Socket::CreateSocket(nodes.Get(1), Ipv6RawSocketFactory::GetTypeId());
    monitor->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    monitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    monitor->BindToNetDevice(nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetNetDevice(1));
    monitor->SetRecvCallback(MakeCallback(&RplP2pDroRelayTestCase::CaptureDro, this));

    // Named at NH (index 1, 0-based, i.e. Address[2] 1-indexed): relays,
    // NH decremented to 1.
    //
    // The result of each TryRelay() call is captured into a local first
    // rather than passed to NS_TEST_ASSERT_MSG_EQ() directly:
    // NS_TEST_ASSERT_MSG_EQ() re-evaluates its "actual" argument a second
    // time to build the failure message when the assertion does not hold
    // (src/core/model/test.h), and TryRelay() is not idempotent -- it
    // delivers a fresh fabricated P2P-DRO and may cause a real relay
    // transmission -- so evaluating it twice on a failing sub-case would
    // run the fixture-and-delivery sequence again under a new sequence
    // number, corrupting the very failure this assertion is trying to
    // report. Found by that exact symptom: an early draft of this test
    // passed TryRelay(...) straight to the macro and, on the first
    // sub-case's failure, silently ran a second, differently-numbered
    // delivery that (successfully) relayed, leaving m_captured holding
    // that second delivery's content instead of the first's.
    bool relayedAtNh = TryRelay(node, {1}, 2);
    NS_TEST_ASSERT_MSG_EQ(relayedAtNh, true, "The router named at the current NH position did not relay");
    NS_TEST_ASSERT_MSG_EQ(m_seenNh, 1, "NH was not decremented correctly");

    // Not named at NH (present in the vector, but at a different position
    // than NH names): not this node's turn, must not relay.
    bool relayedWrongPosition = TryRelay(node, {0}, 2);
    NS_TEST_ASSERT_MSG_EQ(relayedWrongPosition,
                          false,
                          "A router not named at the current NH position relayed anyway");

    // Not in the vector at all: nothing to do.
    bool relayedAbsent = TryRelay(node, {}, 2);
    NS_TEST_ASSERT_MSG_EQ(relayedAbsent, false, "A router absent from the Address Vector relayed anyway");

    // Named at NH, but also present a second time elsewhere: RFC 6997
    // section 9.6's loop check, "the Address vector...includes multiple
    // IPv6 addresses assigned to the router's interfaces."
    bool relayedWithLoop = TryRelay(node, {0, 1}, 2);
    NS_TEST_ASSERT_MSG_EQ(relayedWithLoop,
                          false,
                          "A router named at the current NH position, but also present a second "
                          "time elsewhere in the Address Vector, relayed anyway");

    monitor->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A Hop-by-hop Route (H=1) whose stored next hop conflicts with a
 *        later P2P-DRO's own is discarded and not relayed, but a repeat
 *        naming the very same next hop is not mistaken for a conflict, and
 *        a different RPLInstanceID/DODAGID to the same destination is a
 *        different, unrelated route rather than a conflict at all.
 *
 * RFC 6997 section 9.6: "If the router already maintains a Hop-by-hop
 * state listing the Target as the destination and carrying the same
 * RPLInstanceID and DODAGID fields as the received P2P-DRO, and the
 * next-hop information in the state does not match the next hop indicated
 * in the received P2P-DRO, the router MUST discard the P2P-DRO message
 * with no further processing" -- design-constraints.md section 46
 * implemented this (StoreHopByHopRoute()) alongside the end-to-end
 * delivery increment but left it without a dedicated test of its own,
 * since RplP2pHopByHopRouteCompletesTestCase's own three-node line never
 * gives one router two different candidate next hops for the same route
 * to begin with.
 *
 * One router under test, joined to a single fabricated temporary DAG, fed
 * a sequence of hand-built P2P-DROs naming it at the Address Vector's
 * current NH position -- RplP2pDroRelayTestCase's own two-node
 * (monitor) infrastructure, but state deliberately kept across sub-cases
 * this time (unlike that test's own "fresh Origin per call" isolation),
 * since what is under test here only exists across more than one
 * delivery.
 */
class RplP2pHopByHopRouteConflictTestCase : public TestCase
{
  public:
    RplP2pHopByHopRouteConflictTestCase();

  private:
    void DoRun() override;

    /// @brief Count a relayed P2P-DRO seen at the monitor.
    /// @param socket the monitoring socket
    void CaptureDro(Ptr<Socket> socket);

    /**
     * @brief Deliver one fabricated H=1 P2P-DRO naming the node under test
     *        at the Address Vector's current NH position, and report
     *        whether it relayed.
     *
     * @param node the node under test
     * @param origin the temporary DAG's own DODAGID
     * @param target the Target this Hop-by-hop Route leads to
     * @param beforeSelf addresses of convenience placed before the node's
     *                    own entry in the Address Vector
     * @param afterSelf addresses of convenience placed after the node's
     *                   own entry -- the first of these (if any) is what
     *                   Address[NH+1] resolves the next hop to
     * @return true if a relayed copy was captured at the monitor
     */
    bool TryDeliver(Ptr<Node> node,
                    Ipv6Address origin,
                    Ipv6Address target,
                    const std::vector<Ipv6Address>& beforeSelf,
                    const std::vector<Ipv6Address>& afterSelf);

    bool m_seenRelay{false}; //!< a relayed P2P-DRO was captured
};

RplP2pHopByHopRouteConflictTestCase::RplP2pHopByHopRouteConflictTestCase()
    : TestCase("A conflicting next hop for an existing Hop-by-hop Route is discarded, a "
               "repeat of the same one is not, and a different Instance is a different route")
{
}

void
RplP2pHopByHopRouteConflictTestCase::CaptureDro(Ptr<Socket> socket)
{
    Address sender;
    Ptr<Packet> packet = socket->RecvFrom(sender);
    if (!packet)
    {
        return;
    }
    Ipv6Header ipv6Header;
    packet->RemoveHeader(ipv6Header);
    Icmpv6Header icmpv6Header;
    packet->RemoveHeader(icmpv6Header);
    if (icmpv6Header.GetType() != ICMPV6_RPL || icmpv6Header.GetCode() != RPL_CODE_P2P_DRO)
    {
        return;
    }
    m_seenRelay = true;
}

bool
RplP2pHopByHopRouteConflictTestCase::TryDeliver(Ptr<Node> node,
                                                Ipv6Address origin,
                                                Ipv6Address target,
                                                const std::vector<Ipv6Address>& beforeSelf,
                                                const std::vector<Ipv6Address>& afterSelf)
{
    Ptr<RplRoutingProtocol> rpl = node->GetObject<RplRoutingProtocol>();
    Ipv6Address neighbour("fe80::a");
    static constexpr uint8_t INSTANCE = 0x81;

    RplP2pDroHeader dro;
    dro.SetInstanceId(INSTANCE);
    dro.SetDodagId(origin);
    P2pRdoOption rdo;
    rdo.reply = false;
    rdo.hopByHop = true;
    rdo.target = target;
    for (const auto& hop : beforeSelf)
    {
        rdo.addressVector.push_back(hop);
    }
    rdo.addressVector.push_back(rpl->GetGlobalAddress());
    for (const auto& hop : afterSelf)
    {
        rdo.addressVector.push_back(hop);
    }
    // 1-indexed "Address[NH]" naming this node's own, just-appended entry.
    rdo.maxRankOrNh = static_cast<uint8_t>(beforeSelf.size() + 1);
    dro.SetP2pRdo(rdo);

    m_seenRelay = false;
    DeliverRawRplMessage<RplP2pDroHeader>(node,
                                          1,
                                          dro,
                                          static_cast<uint8_t>(RPL_CODE_P2P_DRO),
                                          neighbour,
                                          Ipv6Address(RPL_ALL_NODES_MULTICAST));

    // DeliverRawRplMessage() delivers synchronously, but a relay this node
    // decides to send goes out through SimpleChannel::Send(), which
    // schedules delivery via Simulator::ScheduleWithContext() rather than
    // calling the receiving device directly -- so it needs a further
    // Simulator::Run() to actually reach the monitor (@see
    // RplP2pDroRelayTestCase's own TryRelay(), the same recipe). Stop()
    // takes a delay *relative to now*, not an absolute time -- an earlier
    // draft passed Simulator::Now() + Seconds(1) here, which (being
    // itself relative) compounded on every call across this test's own
    // several sequential deliveries into the same membership, each
    // successive gap between deliveries roughly doubling and eventually
    // running well past every relevant Trickle/staleness margin. Plain
    // Seconds(1), the same as RplP2pDroRelayTestCase's own TryRelay(),
    // is correct.
    Simulator::Stop(Seconds(1));
    Simulator::Run();

    return m_seenRelay;
}

void
RplP2pHopByHopRouteConflictTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2); // 0 = the router under test, 1 = a real neighbour to monitor from

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    ipv6.AssignWithoutAddress(devices);

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    Simulator::Stop(Seconds(2));
    Simulator::Run();

    Ptr<Node> node = nodes.Get(0);
    Ptr<RplRoutingProtocol> rpl = node->GetObject<RplRoutingProtocol>();

    Ptr<Socket> monitor = Socket::CreateSocket(nodes.Get(1), Ipv6RawSocketFactory::GetTypeId());
    monitor->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    monitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    monitor->BindToNetDevice(nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetNetDevice(1));
    monitor->SetRecvCallback(
        MakeCallback(&RplP2pHopByHopRouteConflictTestCase::CaptureDro, this));

    static constexpr uint8_t INSTANCE = 0x81;
    Ipv6Address origin("2001:9::1");
    Ipv6Address otherOrigin("2001:9::9");
    Ipv6Address target("2001:9::dead:2");
    Ipv6Address hopA("2001:9::a0");
    Ipv6Address hopB("2001:9::b0");
    Ipv6Address hopC("2001:9::c0");

    // A P2P-DRO is only ever acted on if a matching temporary DAG
    // membership already exists (RFC 6997 sections 9.6/9.7), so join one
    // first, as an ordinary relay (the fabricated Target is never this
    // node) -- the same fixture RplP2pDroRelayTestCase's own TryRelay()
    // uses, joined once here rather than per delivery, since this test's
    // whole point is state persisting across more than one.
    RplDioHeader joinDio;
    joinDio.SetInstanceId(INSTANCE);
    joinDio.SetVersionNumber(0);
    joinDio.SetRank(RPL_MIN_HOPRANKINC);
    joinDio.SetMop(RPL_MOP_P2P_ROUTE_DISCOVERY);
    joinDio.SetGrounded(true);
    joinDio.SetDodagId(origin);
    joinDio.SetDtsn(0);
    joinDio.SetDagConfiguration(4, 6, 0, 0, RPL_MIN_HOPRANKINC, RPL_OCP_OF0, 0xFF, 0xFFFF);
    P2pRdoOption joinRdo;
    joinRdo.reply = true;
    joinRdo.hopByHop = true;
    joinRdo.maxRankOrNh = 0; // no limit
    joinRdo.lifetime = 3;    // 64 s (@see RplP2pLifetimeSeconds()), ample margin
    joinRdo.target = Ipv6Address("2001:9::dead:1"); // never this node
    joinDio.SetP2pRdo(joinRdo);
    RplDioHeader otherJoinDio = joinDio;
    otherJoinDio.SetDodagId(otherOrigin);

    // Delivered from a one-shot fabricated neighbour ("fe80::a", never a
    // real node), which goes stale and drops out of this node's own
    // dodag.parents for either membership after about 2 s (2 x Imax,
    // Imax = Imin x 2^doublings = 64 ms x 2^4 from the DagConfiguration
    // above) -- SelectPreferredParent() then loses the last parent and
    // poisons the membership out from under this test, exactly the
    // design-constraints.md section 42.3 hazard, here newly reachable
    // because this test (unlike RplP2pDroRelayTestCase's own TryRelay(),
    // which joins fresh and delivers within under a second every single
    // call) keeps one membership alive across several deliveries in a
    // row. Re-delivered every 100 ms, for both DODAGIDs, for the whole
    // test's duration, to keep "fe80::a" looking alive throughout.
    for (uint32_t i = 0; i < 50; i++)
    {
        Simulator::Schedule(MilliSeconds(100 * i),
                            &DeliverRawRplMessage<RplDioHeader>,
                            node,
                            1,
                            joinDio,
                            static_cast<uint8_t>(RPL_CODE_DIO),
                            Ipv6Address("fe80::a"),
                            Ipv6Address(RPL_ALL_NODES_MULTICAST));
        Simulator::Schedule(MilliSeconds(100 * i),
                            &DeliverRawRplMessage<RplDioHeader>,
                            node,
                            1,
                            otherJoinDio,
                            static_cast<uint8_t>(RPL_CODE_DIO),
                            Ipv6Address("fe80::a"),
                            Ipv6Address(RPL_ALL_NODES_MULTICAST));
    }
    Simulator::Stop(MilliSeconds(50));
    Simulator::Run();
    NS_ASSERT_MSG(rpl->IsJoinedTo(INSTANCE, origin), "Failed to set up this test's fixture");
    NS_ASSERT_MSG(rpl->IsJoinedTo(INSTANCE, otherOrigin),
                 "Failed to set up this test's second fixture");

    // First delivery: establishes the Hop-by-hop Route, next hop hopB
    // (Address[NH+1]). Nothing stored yet to conflict with, so this
    // relays.
    bool firstRelayed = TryDeliver(node, origin, target, {hopA}, {hopB});
    NS_TEST_ASSERT_MSG_EQ(firstRelayed, true, "The first delivery, with nothing to conflict "
                                              "against yet, was not relayed");
    Ipv6Address nextHop;
    uint8_t hopInstanceId = 0;
    NS_TEST_ASSERT_MSG_EQ(rpl->HasHopByHopRoute(INSTANCE, target),
                          true,
                          "The first delivery did not establish a Hop-by-hop Route");
    NS_TEST_ASSERT_MSG_EQ(rpl->GetHopByHopRoute(target, nextHop, hopInstanceId),
                          true,
                          "The first delivery did not establish a Hop-by-hop Route");
    NS_TEST_ASSERT_MSG_EQ(nextHop, hopB, "Wrong next hop recorded from the first delivery");

    // Second delivery: same Instance/DODAGID/Target, but a different
    // Address Vector around this node's own entry, so Address[NH+1]
    // resolves to hopC instead of hopB -- a genuine conflict. RFC 6997
    // section 9.6: MUST discard with no further processing, so this must
    // not relay, and the originally stored next hop (hopB) must survive
    // untouched.
    bool conflictingRelayed = TryDeliver(node, origin, target, {hopB}, {hopC});
    NS_TEST_ASSERT_MSG_EQ(conflictingRelayed,
                          false,
                          "A P2P-DRO conflicting with an already-established Hop-by-hop Route "
                          "was relayed instead of discarded");
    NS_TEST_ASSERT_MSG_EQ(rpl->GetHopByHopRoute(target, nextHop, hopInstanceId),
                          true,
                          "The Hop-by-hop Route disappeared after the conflicting delivery");
    NS_TEST_ASSERT_MSG_EQ(nextHop,
                          hopB,
                          "The conflicting delivery overwrote the original next hop instead of "
                          "being discarded");

    // Third delivery: the exact same Address Vector as the first
    // (next hop still hopB) -- an ordinary retransmission, not a
    // conflict, since the stored and incoming next hop agree. Must relay
    // normally and leave the route exactly as it was.
    bool repeatRelayed = TryDeliver(node, origin, target, {hopA}, {hopB});
    NS_TEST_ASSERT_MSG_EQ(repeatRelayed,
                          true,
                          "A repeat delivery naming the very same next hop was mistaken for a "
                          "conflict and discarded instead of relayed");
    NS_TEST_ASSERT_MSG_EQ(rpl->GetHopByHopRoute(target, nextHop, hopInstanceId),
                          true,
                          "The Hop-by-hop Route disappeared after the repeat delivery");
    NS_TEST_ASSERT_MSG_EQ(nextHop, hopB, "The repeat delivery changed the stored next hop");

    // Fourth delivery: a different DODAGID (a different, unrelated
    // Origin, already joined by the keep-alive loop above) naming the
    // very same Target, with yet another next hop (hopC). RFC 6997
    // section 9.6's own conflict rule is scoped to "the same
    // RPLInstanceID and DODAGID fields" -- a different DODAGID is a
    // different route to the same destination, not a conflict, the same
    // "last one wins" rule this module's own m_p2pRoutes/m_aodvRoutes
    // already apply for their own H=0 routes (@see design-constraints.md
    // section 46.6's own note on this). Must relay, and must replace what
    // was stored under the destination.
    bool otherInstanceRelayed = TryDeliver(node, otherOrigin, target, {hopA}, {hopC});
    NS_TEST_ASSERT_MSG_EQ(otherInstanceRelayed,
                          true,
                          "A Hop-by-hop Route to the same destination under a different Instance "
                          "was treated as a conflict instead of a different, unrelated route");
    NS_TEST_ASSERT_MSG_EQ(rpl->GetHopByHopRoute(target, nextHop, hopInstanceId),
                          true,
                          "The Hop-by-hop Route to the shared destination disappeared");
    NS_TEST_ASSERT_MSG_EQ(nextHop,
                          hopC,
                          "The different-Instance delivery to the same destination did not "
                          "replace the stored route the way an unrelated route should");

    monitor->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A router leaves rather than joins a temporary DAG whose P2P mode
 *        DIO Address Vector already has no room left for its own entry.
 *
 * The P2P-RPL counterpart of RplAodvRrepInstanceAddressVectorFullTestCase:
 * HandleP2pRdo() already guards against joining with an Address Vector
 * that has no room left for this router's own entry, but nothing exercised
 * that boundary specifically for P2P-RPL -- RplP2pFloodTestCase's own
 * four-node line never gets anywhere near
 * RPL_P2P_ADDRESS_VECTOR_MAX_ENTRIES (14) hops. Without the guard, a
 * vector already at that wire limit would grow to 15 on append and hit
 * P2pRdoSerializedSize()/P2pRdoSerialize()'s own arithmetic assuming no
 * more than 14 (RPL_P2P_ADDRESS_VECTOR_MAX_ENTRIES), the same shape of
 * failure the AODV-RPL RREP-Instance test guards against for its own,
 * differently-sized, limit.
 */
class RplP2pAddressVectorFullTestCase : public TestCase
{
  public:
    RplP2pAddressVectorFullTestCase();

  private:
    void DoRun() override;

    /**
     * @brief Feed one fabricated P2P mode DIO, with an Address Vector of
     *        the given length, and report whether the temporary DAG was
     *        joined.
     *
     * @param node the node under test
     * @param vectorEntries how many fabricated hops to put in the P2P-RDO's
     *                      Address Vector before delivery
     * @return true if the node ended up joined to the temporary DAG
     */
    bool TryJoin(Ptr<Node> node, uint8_t vectorEntries);
};

RplP2pAddressVectorFullTestCase::RplP2pAddressVectorFullTestCase()
    : TestCase("A temporary DAG whose Address Vector is already full is left, not joined")
{
}

bool
RplP2pAddressVectorFullTestCase::TryJoin(Ptr<Node> node, uint8_t vectorEntries)
{
    static uint16_t sequence = 0;
    sequence++;
    // A fresh Origin address per call: distinct each time so no earlier
    // sub-case's membership interferes with this one's.
    std::ostringstream originSuffix;
    originSuffix << "2001:a::" << sequence << ":1";
    Ipv6Address origin(originSuffix.str().c_str());
    Ipv6Address neighbour("fe80::a");

    static constexpr uint8_t INSTANCE = 0x81;

    Ptr<RplRoutingProtocol> rpl = node->GetObject<RplRoutingProtocol>();

    RplDioHeader dio;
    dio.SetInstanceId(INSTANCE);
    dio.SetVersionNumber(0);
    dio.SetRank(RPL_MIN_HOPRANKINC);
    dio.SetMop(RPL_MOP_P2P_ROUTE_DISCOVERY);
    dio.SetGrounded(true);
    dio.SetDodagId(origin);
    dio.SetDtsn(0);

    P2pRdoOption rdo;
    rdo.reply = true;
    rdo.hopByHop = false;
    rdo.numRoutes = 0;
    rdo.lifetime = 0;
    rdo.maxRankOrNh = RPL_P2P_MAX_RANK_INFINITE; // out of the way: this test is about the AV
    rdo.target = Ipv6Address("2001:a::dead:1");  // never this node: an ordinary relay throughout
    for (uint8_t i = 0; i < vectorEntries; i++)
    {
        std::ostringstream hopSuffix;
        hopSuffix << "2001:a::" << sequence << ":" << +i;
        rdo.addressVector.push_back(Ipv6Address(hopSuffix.str().c_str()));
    }
    dio.SetP2pRdo(rdo);

    DeliverRawRplMessage<RplDioHeader>(node,
                                       1,
                                       dio,
                                       static_cast<uint8_t>(RPL_CODE_DIO),
                                       neighbour,
                                       Ipv6Address(RPL_ALL_NODES_MULTICAST));

    return rpl->IsJoinedTo(INSTANCE, origin);
}

void
RplP2pAddressVectorFullTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(1);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    ipv6.AssignWithoutAddress(devices);

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    Simulator::Stop(Seconds(2));
    Simulator::Run();

    Ptr<Node> node = nodes.Get(0);

    NS_TEST_ASSERT_MSG_EQ(
        TryJoin(node, RPL_P2P_ADDRESS_VECTOR_MAX_ENTRIES - 1),
        true,
        "A relay was refused a temporary DAG whose Address Vector still had room for its own "
        "entry");
    NS_TEST_ASSERT_MSG_EQ(
        TryJoin(node, RPL_P2P_ADDRESS_VECTOR_MAX_ENTRIES),
        false,
        "A relay joined a temporary DAG whose Address Vector was already full, with no room "
        "left to append its own entry");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check which DIOs RplRoutingProtocol::HandleDio() acts on and which
 *        it turns away: a mode of operation it does not implement, another
 *        RPL instance or DODAG, a stale DODAG version, and the infinite
 *        rank RFC 6550 section 8.2.2.5 uses to poison a sub-DODAG.
 *
 * Driven the same way RplMrhofSelectionTestCase is: one node under test,
 * fed hand-built DIOs sourced from a second real node that need not run RPL
 * itself.
 */
class RplDioRejectionTestCase : public TestCase
{
  public:
    RplDioRejectionTestCase();

  private:
    void DoRun() override;
};

RplDioRejectionTestCase::RplDioRejectionTestCase()
    : TestCase("DIOs HandleDio() must turn away")
{
}

void
RplDioRejectionTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2); // 0 = node under test, 1 = the peer sending the DIOs

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }
    rplHelper.AssignStreams(nodes, 1);

    Ptr<RplRoutingProtocol> node = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ipv6Address dodagId("2001:1::1");
    Ipv6Address nodeLinkLocal =
        nodes.Get(0)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address peerLinkLocal =
        nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    auto buildDio = [](Ipv6Address id, uint8_t version, uint16_t rank, uint8_t mop) {
        RplDioHeader dio;
        dio.SetInstanceId(RPL_DEFAULT_INSTANCE);
        dio.SetVersionNumber(version);
        dio.SetRank(rank);
        dio.SetMop(mop);
        dio.SetDodagId(id);
        dio.SetDagConfiguration(RPL_DIO_INTERVAL_DOUBLINGS,
                                RPL_DIO_INTERVAL_MIN,
                                RPL_DIO_REDUNDANCY,
                                RPL_MAX_RANKINC,
                                RPL_MIN_HOPRANKINC,
                                RPL_OCP_OF0,
                                RPL_DEFAULT_LIFETIME,
                                RPL_DEFAULT_LIFETIME_UNIT);
        return dio;
    };

    auto send = [&](const RplDioHeader& dio) {
        Simulator::Schedule(Seconds(0),
                            &SendRawRplMessage<RplDioHeader>,
                            nodes.Get(1),
                            1,
                            dio,
                            static_cast<uint8_t>(RPL_CODE_DIO),
                            peerLinkLocal,
                            nodeLinkLocal);
        Simulator::Stop(MilliSeconds(10));
        Simulator::Run();
    };

    // Storing mode with multicast (MOP 3): not implemented here (only MOP 2,
    // storing without multicast, is -- @see RplStoringModeDownwardRouteTestCase),
    // so nothing about this DIO may be acted on, not even to join the DODAG
    // it advertises.
    send(buildDio(dodagId, 1, RPL_MIN_HOPRANKINC, RPL_MOP_STORING_MULTICAST));
    NS_TEST_ASSERT_MSG_EQ(node->IsJoined(),
                          false,
                          "A DIO advertising storing mode with multicast was joined anyway");

    // Likewise a mode of operation with no downward routes at all.
    send(buildDio(dodagId, 1, RPL_MIN_HOPRANKINC, RPL_MOP_NO_DOWNWARD_ROUTES));
    NS_TEST_ASSERT_MSG_EQ(node->IsJoined(), false, "A DIO with MOP 0 was joined anyway");

    // An infinite rank poisons a sub-DODAG (RFC 6550 section 8.2.2.5): a
    // node that has not joined anything has nothing to poison, and must not
    // treat it as an invitation either.
    send(buildDio(dodagId, 1, RPL_INFINITE_RANK, RPL_MOP_NON_STORING));
    NS_TEST_ASSERT_MSG_EQ(node->IsJoined(),
                          false,
                          "A DIO advertising an infinite rank was joined");

    // A well-formed non-storing DIO: this one is joined.
    send(buildDio(dodagId, 5, RPL_MIN_HOPRANKINC, RPL_MOP_NON_STORING));
    NS_TEST_ASSERT_MSG_EQ(node->IsJoined(), true, "A valid DIO did not bootstrap a DODAG");
    NS_TEST_ASSERT_MSG_EQ(node->GetDodagId(), dodagId, "Joined the wrong DODAG");
    NS_TEST_ASSERT_MSG_EQ(node->GetPreferredParent(), peerLinkLocal, "Wrong preferred parent");
    NS_TEST_ASSERT_MSG_EQ(node->GetRank(), 2 * RPL_MIN_HOPRANKINC, "Wrong rank one hop out");

    // A DIO for another DODAG entirely is no longer turned away: a node can
    // belong to more than one DODAG at once (@see RplMultiDodagTestCase),
    // so this is deliberately not covered by this rejection-focused test.

    // A stale version of the DODAG this node is in: ignored.
    send(buildDio(dodagId, 4, 1, RPL_MOP_NON_STORING));
    NS_TEST_ASSERT_MSG_EQ(node->GetRank(),
                          2 * RPL_MIN_HOPRANKINC,
                          "A DIO for a stale DODAG version changed the rank");

    // A newer version: the node leaves and rejoins on it.
    send(buildDio(dodagId, 6, RPL_MIN_HOPRANKINC, RPL_MOP_NON_STORING));
    NS_TEST_ASSERT_MSG_EQ(node->IsJoined(), true, "The node did not rejoin on the new version");
    NS_TEST_ASSERT_MSG_EQ(node->GetDodagId(), dodagId, "The DODAG changed on a version bump");
    NS_TEST_ASSERT_MSG_EQ(node->GetPreferredParent(),
                          peerLinkLocal,
                          "The parent was not picked up again after the version bump");

    // The only parent poisons itself: with nothing left to attach to, the
    // node leaves the DODAG and goes back to soliciting.
    send(buildDio(dodagId, 6, RPL_INFINITE_RANK, RPL_MOP_NON_STORING));
    NS_TEST_ASSERT_MSG_EQ(node->GetPreferredParent(),
                          Ipv6Address::GetAny(),
                          "A poisoned parent stayed selected");
    NS_TEST_ASSERT_MSG_EQ(node->GetRank(), RPL_INFINITE_RANK, "The rank was not invalidated");
    NS_TEST_ASSERT_MSG_EQ(node->IsJoined(), false, "The node stayed in a DODAG it cannot reach");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Follow a node all the way around the state machine: joined, then
 *        cut off from its only parent until it gives up on the DODAG, then
 *        reconnected and joined again.
 *
 * The interesting half is the middle one. Every other path into
 * SelectPreferredParent() is driven by an incoming DIO, so a node whose
 * only neighbour goes silent has nothing to trigger the staleness check
 * that is supposed to notice -- unless something the node runs on its own
 * clock does the triggering. Losing the last parent has to take the node
 * out of the DODAG (RFC 6550 section 8.2.2.1: a node with no parent has an
 * infinite rank) and back to soliciting, rather than leave it advertising
 * a rank it can no longer reach the root with.
 */
class RplParentLossRejoinTestCase : public TestCase
{
  public:
    RplParentLossRejoinTestCase();

  private:
    void DoRun() override;
};

RplParentLossRejoinTestCase::RplParentLossRejoinTestCase()
    : TestCase("Losing the last parent and rejoining")
{
}

void
RplParentLossRejoinTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    // A short Imin with two doublings puts Imax at about a second, so the
    // two missed announcements that make a neighbour stale take a couple of
    // seconds rather than the best part of an hour.
    rplHelper.Set("DioIntervalMin", TimeValue(MilliSeconds(256)));
    rplHelper.Set("DioIntervalDoublings", UintegerValue(2));
    rplHelper.Set("DisInterval", TimeValue(Seconds(2)));

    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Ptr<RplRoutingProtocol> root = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> child = nodes.Get(1)->GetObject<RplRoutingProtocol>();

    // Joined: the ordinary sequence, DIS to DIO to parent selection to DAO.
    Simulator::Stop(Seconds(10));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(child->IsJoined(), true, "The child never joined the DODAG");
    NS_TEST_ASSERT_MSG_EQ(child->GetRank(), 2 * RPL_MIN_HOPRANKINC, "The child is one hop out");
    Ipv6Address parent = child->GetPreferredParent();
    NS_TEST_ASSERT_MSG_NE(parent, Ipv6Address::GetAny(), "The child has no preferred parent");
    NS_TEST_ASSERT_MSG_EQ(root->GetTopologySize(), 1, "The root never heard the child's DAO");

    // Cut the child off from the root's DIOs. Nothing else is on this link,
    // so no DIO reaches the child at all from here on.
    Ptr<SimpleNetDevice> rootDevice = DynamicCast<SimpleNetDevice>(devices.Get(0));
    Ptr<SimpleNetDevice> childDevice = DynamicCast<SimpleNetDevice>(devices.Get(1));
    channel->BlackList(rootDevice, childDevice);

    // Well past the two maximum Trickle intervals that make a neighbour
    // stale, plus room for the child's own Trickle to fire after that.
    Simulator::Stop(Seconds(15));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(child->GetPreferredParent(),
                          Ipv6Address::GetAny(),
                          "A parent that stopped sending DIOs stayed selected");
    NS_TEST_ASSERT_MSG_EQ(child->GetRank(),
                          RPL_INFINITE_RANK,
                          "A node with no parent kept a finite rank");
    NS_TEST_ASSERT_MSG_EQ(child->IsJoined(),
                          false,
                          "A node with no way to the root stayed in the DODAG");

    // Reconnect: the DIS the child is sending again finds the root, and the
    // whole join sequence runs a second time.
    channel->UnBlackList(rootDevice, childDevice);

    Simulator::Stop(Seconds(15));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(child->IsJoined(), true, "The child did not rejoin once reconnected");
    NS_TEST_ASSERT_MSG_EQ(child->GetPreferredParent(),
                          parent,
                          "The child rejoined on a different parent than the only one there is");
    NS_TEST_ASSERT_MSG_EQ(child->GetRank(),
                          2 * RPL_MIN_HOPRANKINC,
                          "The rank was not restored on rejoining");
    NS_TEST_ASSERT_MSG_EQ(child->GetDodagId(),
                          root->GetDodagId(),
                          "The child rejoined a different DODAG");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Take a joined node's interface down and back up, and check it
 *        unwinds and rebuilds its RPL state around that.
 *
 * A different route out of the DODAG than losing a parent to silence
 * (@see RplParentLossRejoinTestCase): here it is StopInterface() that has
 * to drop the neighbours reachable through that interface, close the
 * socket and hand what is left to the parent selection, and
 * StartInterface() that has to bring the socket and the multicast
 * subscription back once the interface returns.
 */
class RplInterfaceRestartTestCase : public TestCase
{
  public:
    RplInterfaceRestartTestCase();

  private:
    void DoRun() override;
};

RplInterfaceRestartTestCase::RplInterfaceRestartTestCase()
    : TestCase("An interface going down and coming back up")
{
}

void
RplInterfaceRestartTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    rplHelper.Set("DioIntervalMin", TimeValue(MilliSeconds(256)));
    rplHelper.Set("DioIntervalDoublings", UintegerValue(2));
    rplHelper.Set("DisInterval", TimeValue(Seconds(2)));

    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Ptr<RplRoutingProtocol> child = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<Ipv6L3Protocol> childIpv6 = nodes.Get(1)->GetObject<Ipv6L3Protocol>();

    Simulator::Stop(Seconds(10));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(child->IsJoined(), true, "The child never joined the DODAG");
    Ipv6Address parent = child->GetPreferredParent();
    NS_TEST_ASSERT_MSG_NE(parent, Ipv6Address::GetAny(), "The child has no preferred parent");

    // Down: the only neighbour was reachable through this interface, so
    // dropping it leaves no parent and takes the node out of the DODAG.
    childIpv6->SetDown(1);
    Simulator::Stop(Seconds(1));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(child->GetPreferredParent(),
                          Ipv6Address::GetAny(),
                          "A parent reachable only through a downed interface stayed selected");
    NS_TEST_ASSERT_MSG_EQ(child->GetRank(),
                          RPL_INFINITE_RANK,
                          "A node with no usable interface kept a finite rank");
    NS_TEST_ASSERT_MSG_EQ(child->IsJoined(),
                          false,
                          "A node with no usable interface stayed in the DODAG");

    // Up again: the socket and the all-RPL-nodes subscription come back,
    // and the ordinary join sequence runs a second time.
    childIpv6->SetUp(1);
    Simulator::Stop(Seconds(15));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(child->IsJoined(),
                          true,
                          "The child did not rejoin after its interface came back");
    NS_TEST_ASSERT_MSG_EQ(child->GetRank(),
                          2 * RPL_MIN_HOPRANKINC,
                          "The rank was not restored after the interface came back");
    NS_TEST_ASSERT_MSG_NE(child->GetPreferredParent(),
                          Ipv6Address::GetAny(),
                          "No parent was picked up after the interface came back");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check that a second Duplicate Address Detection success on the
 *        root does not restart the DODAG it is already running.
 *
 * HandleDadSuccess() is what starts the root's DODAG, on the trace that
 * fires when its own SLAAC address clears DAD (RFC 4862). That trace can
 * fire again later -- any further global address on the root goes through
 * DAD too -- and RFC 6550 section 8.2.2.2 has the DODAGID be one specific
 * address of the root's, not whichever one most recently finished DAD:
 * changing it mid-flight would orphan every node that joined on the old
 * one and invalidate every downward path already computed.
 */
class RplRootReaddressTestCase : public TestCase
{
  public:
    RplRootReaddressTestCase();

  private:
    void DoRun() override;
};

RplRootReaddressTestCase::RplRootReaddressTestCase()
    : TestCase("A second address on the root does not restart the DODAG")
{
}

void
RplRootReaddressTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    rplHelper.Set("DioIntervalMin", TimeValue(MilliSeconds(256)));
    rplHelper.Set("DioIntervalDoublings", UintegerValue(2));

    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(10));
    Simulator::Run();

    Ptr<RplRoutingProtocol> root = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> child = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ipv6Address dodagId = root->GetDodagId();
    NS_TEST_ASSERT_MSG_NE(dodagId, Ipv6Address::GetAny(), "The root never started a DODAG");
    NS_TEST_ASSERT_MSG_EQ(root->GetTopologySize(), 1, "The root never heard the child's DAO");
    NS_TEST_ASSERT_MSG_EQ(child->GetDodagId(), dodagId, "The child joined another DODAG");

    // A second global address on the root, on an unrelated prefix: it goes
    // through DAD and fires the same trace the DODAG was started on.
    Ptr<Ipv6L3Protocol> rootIpv6 = nodes.Get(0)->GetObject<Ipv6L3Protocol>();
    Ipv6InterfaceAddress extra(Ipv6Address("2001:db8::1"), Ipv6Prefix(64));
    extra.SetScope(Ipv6InterfaceAddress::GLOBAL);
    rootIpv6->AddAddress(1, extra);

    Simulator::Stop(Seconds(10));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(root->GetDodagId(),
                          dodagId,
                          "A later DAD success moved the DODAGID to the new address");
    NS_TEST_ASSERT_MSG_EQ(root->GetRank(),
                          RPL_MIN_HOPRANKINC,
                          "The root's rank changed on a later DAD success");
    NS_TEST_ASSERT_MSG_EQ(root->GetTopologySize(),
                          1,
                          "The topology learnt from the DAOs was thrown away");
    NS_TEST_ASSERT_MSG_EQ(child->GetDodagId(),
                          dodagId,
                          "The child was moved to a different DODAG under it");
    NS_TEST_ASSERT_MSG_EQ(child->GetRank(),
                          2 * RPL_MIN_HOPRANKINC,
                          "The child's rank changed for a reason of the root's own");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check what the root's downward path computation does with a
 *        topology that does not lead anywhere: an entry whose reported
 *        parents form a cycle, one whose lifetime has run out, and a
 *        destination it never heard of at all.
 *
 * The DAOs that build these are hand-made (@see SendRawRplMessage): a node
 * running this implementation only ever reports its real preferred parent,
 * so none of these shapes can arise from one.
 */
class RplComputeSourceRouteFailureTestCase : public TestCase
{
  public:
    RplComputeSourceRouteFailureTestCase();

  private:
    void DoRun() override;
};

RplComputeSourceRouteFailureTestCase::RplComputeSourceRouteFailureTestCase()
    : TestCase("Downward path computation over an unusable topology")
{
}

void
RplComputeSourceRouteFailureTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(60));
    Simulator::Run();

    Ptr<RplRoutingProtocol> root = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ipv6Address rootAddress = root->GetGlobalAddress();
    Ptr<RplRoutingProtocol> child = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ipv6Address childAddress = child->GetGlobalAddress();
    NS_TEST_ASSERT_MSG_EQ(root->GetTopologySize(), 1, "The root did not learn the child's DAO");

    std::vector<Ipv6Address> hops;

    // A destination no DAO ever mentioned.
    NS_TEST_ASSERT_MSG_EQ(root->ComputeSourceRoute(Ipv6Address("2001:1::dead"), hops),
                          false,
                          "The root invented a path to a node it never heard of");
    NS_TEST_ASSERT_MSG_EQ(hops.size(), 0, "A failed path computation left hops behind");

    // Two nodes reporting each other as their parent: the walk up the
    // parents never reaches the root, and must terminate rather than spin.
    Ipv6Address cycleA("2001:1::ff:fe00:aa");
    Ipv6Address cycleB("2001:1::ff:fe00:bb");

    auto sendDao = [&](Ipv6Address target, Ipv6Address parent, uint8_t lifetime) {
        RplDaoHeader dao;
        dao.SetInstanceId(RPL_DEFAULT_INSTANCE);
        dao.SetSequence(1);
        dao.SetTarget(target);
        dao.SetTransitInformation(parent, 1, lifetime);
        Simulator::Schedule(Seconds(0),
                            &SendRawRplMessage<RplDaoHeader>,
                            nodes.Get(1),
                            1,
                            dao,
                            static_cast<uint8_t>(RPL_CODE_DAO),
                            childAddress,
                            rootAddress);
        Simulator::Stop(MilliSeconds(10));
        Simulator::Run();
    };

    sendDao(cycleA, cycleB, RPL_DEFAULT_LIFETIME);
    sendDao(cycleB, cycleA, RPL_DEFAULT_LIFETIME);
    NS_TEST_ASSERT_MSG_EQ(root->GetTopologySize(), 3, "The hand-built DAOs were not recorded");

    NS_TEST_ASSERT_MSG_EQ(root->ComputeSourceRoute(cycleA, hops),
                          false,
                          "A cycle in the reported parents produced a path anyway");
    NS_TEST_ASSERT_MSG_EQ(hops.size(), 0, "A failed path computation left hops behind");

    // A parent chain that simply stops at a node the root has no entry for.
    Ipv6Address orphan("2001:1::ff:fe00:cc");
    sendDao(orphan, Ipv6Address("2001:1::ff:fe00:dd"), RPL_DEFAULT_LIFETIME);
    NS_TEST_ASSERT_MSG_EQ(root->ComputeSourceRoute(orphan, hops),
                          false,
                          "A parent chain that never reaches the root produced a path");

    // The real child is still reachable throughout: none of the broken
    // entries above may take the working one down with them.
    NS_TEST_ASSERT_MSG_EQ(root->ComputeSourceRoute(childAddress, hops),
                          true,
                          "The one usable entry was lost among the broken ones");
    NS_TEST_ASSERT_MSG_EQ(hops.size(), 1, "A direct child is one hop: itself");

    // An entry whose lifetime has run out is no longer a path, even before
    // anything purges it from the table. PathLifetime 1 with the default
    // lifetime unit of 60 s expires a minute out.
    Ipv6Address expiring("2001:1::ff:fe00:ee");
    sendDao(expiring, rootAddress, 1);
    NS_TEST_ASSERT_MSG_EQ(root->ComputeSourceRoute(expiring, hops),
                          true,
                          "A freshly advertised entry was not usable");

    Simulator::Stop(Seconds(61));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(root->ComputeSourceRoute(expiring, hops),
                          false,
                          "An expired entry was still used to build a path");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Exercise RplIpv6ExtensionSourceRouting::Process() directly, at the
 *        boundary and error paths RFC 6554 section 4.1 specifies: a
 *        malformed Segments Left, a multicast address in the path, hop limit
 *        exhaustion, and the two ways a hop can finish (relay onward, or
 *        recognise itself as the real destination).
 *
 * These do not depend on a live multi-hop delivery, so a single node with RPL
 * installed is enough: what is under test is the header parsing and the
 * outcome flags Process() reports back to Ipv6L3Protocol::LocalDeliver(), not
 * the routing decision that follows.
 */
class RplSourceRoutingProcessTestCase : public TestCase
{
  public:
    RplSourceRoutingProcessTestCase();

  private:
    void DoRun() override;
};

RplSourceRoutingProcessTestCase::RplSourceRoutingProcessTestCase()
    : TestCase("Source routing header processing, boundary and error paths")
{
}

void
RplSourceRoutingProcessTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(1);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    ipv6.AssignWithoutAddress(devices);

    // Nothing here needs simulated time to pass, only DoInitialize() to have
    // run, which is what registers RplIpv6ExtensionSourceRouting.
    Simulator::Stop(Seconds(0));
    Simulator::Run();

    Ptr<Node> node = nodes.Get(0);
    Ptr<Ipv6L3Protocol> nodeIpv6 = node->GetObject<Ipv6L3Protocol>();
    Ptr<Ipv6ExtensionRoutingDemux> demux = node->GetObject<Ipv6ExtensionRoutingDemux>();
    NS_TEST_ASSERT_MSG_EQ(demux != nullptr, true, "No routing extension demux on the node");

    Ptr<Ipv6ExtensionRouting> extension =
        demux->GetExtensionRouting(RplIpv6ExtensionSourceRouting::TYPE_ROUTING);
    NS_TEST_ASSERT_MSG_EQ(extension != nullptr,
                          true,
                          "RplIpv6ExtensionSourceRouting was not registered");

    Ipv6Address linkLocal = nodeIpv6->GetAddress(1, 0).GetAddress();

    // Segments Left greater than the number of addresses: malformed, dropped.
    {
        RplSourceRoutingHeader srh;
        srh.SetNextHeader(59); // No Next Header
        srh.SetSegmentsLeft(5);
        srh.SetAddresses({Ipv6Address("fe80::2")});

        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(srh);

        Ipv6Header ipv6Header;
        ipv6Header.SetSource(Ipv6Address("fe80::3"));
        ipv6Header.SetDestination(linkLocal);
        ipv6Header.SetHopLimit(64);

        bool stopProcessing = false;
        bool isDropped = false;
        Ipv6L3Protocol::DropReason dropReason;
        extension->Process(packet,
                           0,
                           ipv6Header,
                           linkLocal,
                           nullptr,
                           stopProcessing,
                           isDropped,
                           dropReason);

        NS_TEST_ASSERT_MSG_EQ(isDropped, true, "A malformed header was not dropped");
        NS_TEST_ASSERT_MSG_EQ(stopProcessing,
                              true,
                              "Processing was not stopped for a malformed header");
        NS_TEST_ASSERT_MSG_EQ(dropReason,
                              Ipv6L3Protocol::DROP_MALFORMED_HEADER,
                              "Wrong drop reason for a malformed header");
    }

    // A multicast address in the path: RFC 6554 section 4.1 forbids it.
    {
        RplSourceRoutingHeader srh;
        srh.SetNextHeader(59);
        srh.SetSegmentsLeft(1);
        srh.SetAddresses({Ipv6Address("ff02::1a")});

        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(srh);

        Ipv6Header ipv6Header;
        ipv6Header.SetSource(Ipv6Address("fe80::3"));
        ipv6Header.SetDestination(linkLocal);
        ipv6Header.SetHopLimit(64);

        bool stopProcessing = false;
        bool isDropped = false;
        Ipv6L3Protocol::DropReason dropReason;
        extension->Process(packet,
                           0,
                           ipv6Header,
                           linkLocal,
                           nullptr,
                           stopProcessing,
                           isDropped,
                           dropReason);

        NS_TEST_ASSERT_MSG_EQ(isDropped, true, "A multicast next hop was not dropped");
        NS_TEST_ASSERT_MSG_EQ(stopProcessing,
                              true,
                              "Processing was not stopped for a multicast next hop");
    }

    // Hop limit already at 1: one more hop would make it 0, so RFC 8200 has
    // this dropped instead, with a Time Exceeded sent back.
    {
        RplSourceRoutingHeader srh;
        srh.SetNextHeader(59);
        srh.SetSegmentsLeft(1);
        srh.SetAddresses({Ipv6Address("fe80::4")});

        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(srh);

        Ipv6Header ipv6Header;
        ipv6Header.SetSource(Ipv6Address("fe80::3"));
        ipv6Header.SetDestination(linkLocal);
        ipv6Header.SetHopLimit(1);

        bool stopProcessing = false;
        bool isDropped = false;
        Ipv6L3Protocol::DropReason dropReason;
        extension->Process(packet,
                           0,
                           ipv6Header,
                           linkLocal,
                           nullptr,
                           stopProcessing,
                           isDropped,
                           dropReason);

        NS_TEST_ASSERT_MSG_EQ(isDropped, true, "A hop limit of 1 did not drop the packet");
        NS_TEST_ASSERT_MSG_EQ(stopProcessing,
                              true,
                              "Processing was not stopped for hop limit exhaustion");
    }

    // A relay hop (Segments Left still nonzero, otherwise valid) always stops
    // the caller's receive loop, whether or not a route to the next hop
    // exists: this is the regression test for the bug where a relay hop both
    // resent the packet on its own and let the original fall through to
    // local delivery too, corrupting whatever was listening on this node.
    // fe80::4 was never heard from, but on a node with a single RPL
    // interface RouteToNeighbour() finds a route anyway (see its own
    // comment on InterfaceForNeighbour()'s single-interface fallback): the
    // root, not this hop, already decided fe80::4 is one radio hop away, so
    // this is a normal relay, not the RFC 6554 section 4.2 on-link failure
    // (that is covered separately below, on a node with no RPL interface at
    // all to send through).
    {
        RplSourceRoutingHeader srh;
        srh.SetNextHeader(59);
        srh.SetSegmentsLeft(1);
        srh.SetAddresses({Ipv6Address("fe80::4")});

        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(srh);

        Ipv6Header ipv6Header;
        ipv6Header.SetSource(Ipv6Address("fe80::3"));
        ipv6Header.SetDestination(linkLocal);
        ipv6Header.SetHopLimit(64);

        bool stopProcessing = false;
        bool isDropped = false;
        Ipv6L3Protocol::DropReason dropReason;
        extension->Process(packet,
                           0,
                           ipv6Header,
                           linkLocal,
                           nullptr,
                           stopProcessing,
                           isDropped,
                           dropReason);

        NS_TEST_ASSERT_MSG_EQ(isDropped, true, "A relay hop did not mark the packet as handled");
        NS_TEST_ASSERT_MSG_EQ(stopProcessing,
                              true,
                              "A relay hop did not stop the caller's receive loop");
    }

    // RFC 6554 section 4.2's on-link failure: neither RouteToNeighbour() nor
    // the routing lookup can find a way to reach the next hop. A node with
    // no RPL interface at all is what actually triggers this (see the
    // comment in RplIpv6ExtensionSourceRouting::Process() on why a started
    // interface's fallback absorbs every other case): a second node here,
    // with no NetDevice installed at all, so RplRoutingProtocol's
    // DoInitialize() still registers the extension but starts no interface.
    {
        NodeContainer isolated;
        isolated.Create(1);
        RplHelper isolatedRplHelper;
        InternetStackHelper isolatedInternetv6;
        isolatedInternetv6.SetRoutingHelper(isolatedRplHelper);
        isolatedInternetv6.Install(isolated);

        Simulator::Stop(Seconds(0));
        Simulator::Run();

        Ptr<Ipv6ExtensionRoutingDemux> isolatedDemux =
            isolated.Get(0)->GetObject<Ipv6ExtensionRoutingDemux>();
        Ptr<Ipv6ExtensionRouting> isolatedExtension =
            isolatedDemux->GetExtensionRouting(RplIpv6ExtensionSourceRouting::TYPE_ROUTING);
        NS_TEST_ASSERT_MSG_EQ(isolatedExtension != nullptr,
                              true,
                              "RplIpv6ExtensionSourceRouting was not registered on a node with "
                              "no interface");

        RplSourceRoutingHeader srh;
        srh.SetNextHeader(59);
        srh.SetSegmentsLeft(1);
        srh.SetAddresses({Ipv6Address("fe80::4")});

        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(srh);

        Ipv6Header ipv6Header;
        ipv6Header.SetSource(Ipv6Address("fe80::3"));
        ipv6Header.SetDestination(Ipv6Address("fe80::9"));
        ipv6Header.SetHopLimit(64);

        bool stopProcessing = false;
        bool isDropped = false;
        Ipv6L3Protocol::DropReason dropReason;
        isolatedExtension->Process(packet,
                                   0,
                                   ipv6Header,
                                   Ipv6Address("fe80::9"),
                                   nullptr,
                                   stopProcessing,
                                   isDropped,
                                   dropReason);

        NS_TEST_ASSERT_MSG_EQ(isDropped, true, "An on-link failure was not dropped");
        NS_TEST_ASSERT_MSG_EQ(stopProcessing,
                              true,
                              "Processing was not stopped for an on-link failure");
        NS_TEST_ASSERT_MSG_EQ(dropReason,
                              Ipv6L3Protocol::DROP_NO_ROUTE,
                              "Wrong drop reason for an on-link failure");
    }

    // A routing loop (RFC 6554 section 4.2): this router's own link-local
    // address appears twice in the Routing Header, other than the entry
    // Segments Left points at, with a different address in between. The
    // root's non-storing path computation (ComputeSourceRoute()) never
    // produces this on its own; it takes a stale or tampered header.
    {
        RplSourceRoutingHeader srh;
        srh.SetNextHeader(59);
        srh.SetSegmentsLeft(1);
        srh.SetAddresses(
            {linkLocal, Ipv6Address("fe80::5"), linkLocal, Ipv6Address("fe80::6")});

        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(srh);

        Ipv6Header ipv6Header;
        ipv6Header.SetSource(Ipv6Address("fe80::3"));
        ipv6Header.SetDestination(linkLocal);
        ipv6Header.SetHopLimit(64);

        bool stopProcessing = false;
        bool isDropped = false;
        Ipv6L3Protocol::DropReason dropReason;
        extension->Process(packet,
                           0,
                           ipv6Header,
                           linkLocal,
                           nullptr,
                           stopProcessing,
                           isDropped,
                           dropReason);

        NS_TEST_ASSERT_MSG_EQ(isDropped, true, "A routing loop was not dropped");
        NS_TEST_ASSERT_MSG_EQ(stopProcessing,
                              true,
                              "Processing was not stopped for a routing loop");
        NS_TEST_ASSERT_MSG_EQ(dropReason,
                              Ipv6L3Protocol::DROP_ROUTE_ERROR,
                              "Wrong drop reason for a routing loop");
    }

    // Segments Left already zero: this node is the real destination, so
    // nothing is touched and the rest of the receive chain takes over.
    {
        RplSourceRoutingHeader srh;
        srh.SetNextHeader(58); // ICMPv6, a plausible inner protocol
        srh.SetSegmentsLeft(0);
        srh.SetAddresses({Ipv6Address("fe80::4")});

        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(srh);

        Ipv6Header ipv6Header;
        ipv6Header.SetSource(Ipv6Address("fe80::3"));
        ipv6Header.SetDestination(linkLocal);
        ipv6Header.SetHopLimit(64);

        bool stopProcessing = false;
        bool isDropped = false;
        uint8_t nextHeader = 0;
        Ipv6L3Protocol::DropReason dropReason;
        uint8_t processed = extension->Process(packet,
                                               0,
                                               ipv6Header,
                                               linkLocal,
                                               &nextHeader,
                                               stopProcessing,
                                               isDropped,
                                               dropReason);

        NS_TEST_ASSERT_MSG_EQ(isDropped, false, "A fully-arrived packet was dropped");
        NS_TEST_ASSERT_MSG_EQ(stopProcessing,
                              false,
                              "A fully-arrived packet stopped the rest of the receive chain");
        NS_TEST_ASSERT_MSG_EQ(nextHeader, 58, "The inner next header was not reported");
        // fe80::4 is link-local and the lone (so CmprE-governed) address:
        // compressed to 8 bytes rather than carried in full.
        NS_TEST_ASSERT_MSG_EQ(processed, 8 + 8, "Wrong number of bytes reported consumed");
    }

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check that RplRoutingProtocol::PrepareOutgoingPacket() leaves a
 *        packet untouched when the route it is given does not actually
 *        leave on an interface RPL runs on -- e.g. RPL composed with
 *        another routing protocol under Ipv6ListRouting, which offers this
 *        hook to every member regardless of whose route is in use.
 */
class RplPrepareOutgoingPacketNonRplInterfaceTestCase : public TestCase
{
  public:
    RplPrepareOutgoingPacketNonRplInterfaceTestCase();

  private:
    void DoRun() override;
};

RplPrepareOutgoingPacketNonRplInterfaceTestCase::RplPrepareOutgoingPacketNonRplInterfaceTestCase()
    : TestCase("PrepareOutgoingPacket ignores a route leaving on a non-RPL interface")
{
}

void
RplPrepareOutgoingPacketNonRplInterfaceTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(1);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    ipv6.AssignWithoutAddress(devices);

    // Nothing here needs simulated time to pass, only DoInitialize() to have
    // run, which is what registers RplRoutingProtocol on the interface.
    Simulator::Stop(Seconds(0));
    Simulator::Run();

    Ptr<Node> node = nodes.Get(0);
    Ptr<RplRoutingProtocol> rpl = node->GetObject<RplRoutingProtocol>();

    // A device this node's Ipv6 has no interface index for at all -- attached
    // to a different node entirely -- stands in for "an interface RPL does
    // not run on": Ipv6::GetInterfaceForDevice() returns -1 for it exactly
    // the way it would for a second, non-RPL interface on this same node.
    Ptr<Node> otherNode = CreateObject<Node>();
    NetDeviceContainer otherDevice = simpleNetDevice.Install(otherNode, channel);

    Ptr<Ipv6Route> route = Create<Ipv6Route>();
    route->SetOutputDevice(otherDevice.Get(0));

    Ipv6Header header;
    header.SetDestination(Ipv6Address("2001:db8::1")); // global: not the
                                                        // multicast/link-local
                                                        // early return
    header.SetNextHeader(59);                          // No Next Header

    Ptr<Packet> packet = Create<Packet>();
    uint32_t originalSize = packet->GetSize();

    rpl->PrepareOutgoingPacket(packet, header, route);

    NS_TEST_ASSERT_MSG_EQ(
        packet->GetSize(),
        originalSize,
        "A packet leaving on a non-RPL interface must not gain an RPL Option");
    NS_TEST_ASSERT_MSG_EQ(header.GetNextHeader(),
                          59,
                          "Next Header must not be rewritten for a non-RPL interface");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check the RSSI -> Link Quality Level mapping (RFC 6551 section 4.6):
 *        the built-in default table, and that SetRssiToLqlMapping()
 *        genuinely replaces it rather than merely supplementing it.
 *
 * RFC 6551 leaves how a raw signal reading becomes an LQL "implementation
 * specific", which is exactly why this is a plain, user-replaceable
 * callback rather than a fixed table baked into the protocol -- this test
 * exists to hold that configurability itself to a contract, independently
 * of whatever radio a scenario happens to use. No node or topology is
 * needed: RssiToLql() and SetRssiToLqlMapping() touch nothing but the
 * mapping itself.
 */
class RplLqlMappingTestCase : public TestCase
{
  public:
    RplLqlMappingTestCase();

  private:
    void DoRun() override;
};

RplLqlMappingTestCase::RplLqlMappingTestCase()
    : TestCase("RSSI to LQL mapping, default and user-replaced")
{
}

void
RplLqlMappingTestCase::DoRun()
{
    Ptr<RplRoutingProtocol> protocol = CreateObject<RplRoutingProtocol>();

    // The default table: 1 is the best determined quality, 7 the worst,
    // never 0 (undetermined) for an actual reading.
    NS_TEST_ASSERT_MSG_EQ(+protocol->RssiToLql(-40.0), 1, "Strong signal should be the best LQL");
    NS_TEST_ASSERT_MSG_EQ(+protocol->RssiToLql(-75.0), 1, "Wrong LQL at the -75 dBm threshold");
    NS_TEST_ASSERT_MSG_EQ(+protocol->RssiToLql(-75.1),
                          2,
                          "Wrong LQL just past the -75 dBm threshold");
    NS_TEST_ASSERT_MSG_EQ(+protocol->RssiToLql(-103.0), 6, "Wrong LQL at the -103 dBm threshold");
    NS_TEST_ASSERT_MSG_EQ(+protocol->RssiToLql(-120.0), 7, "Weak signal should be the worst LQL");

    // A caller-supplied mapping replaces the default outright, not
    // alongside it: a threshold the default table would call "1" has to
    // come back however the new mapping says, here always 7 except right
    // at 0 dBm.
    protocol->SetRssiToLqlMapping(
        [](double rssiDbm) -> uint8_t { return rssiDbm >= 0.0 ? 1 : 7; });
    NS_TEST_ASSERT_MSG_EQ(+protocol->RssiToLql(-40.0), 7, "The custom mapping was not used");
    NS_TEST_ASSERT_MSG_EQ(+protocol->RssiToLql(0.0), 1, "The custom mapping was not used");
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check that a No-Path DAO (RFC 6550 section 6.4.3, path lifetime
 *        zero) removes the target from the root's topology.
 *
 * This exercises HandleDao()'s receiving side on its own, with a hand-built
 * message (SendRawRplMessage()) standing in for one from another
 * implementation sharing the DODAG, or one this node sent itself
 * (SendNoPathDao(), @see RplNoPathDaoSentOnParentLossTestCase) that arrived
 * out of order relative to the rest of this test's setup.
 */
class RplNoPathDaoTestCase : public TestCase
{
  public:
    RplNoPathDaoTestCase();

  private:
    void DoRun() override;
};

RplNoPathDaoTestCase::RplNoPathDaoTestCase()
    : TestCase("No-Path DAO removes a topology entry")
{
}

void
RplNoPathDaoTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(60));
    Simulator::Run();

    Ptr<RplRoutingProtocol> root = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> child = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ipv6Address childAddress = child->GetGlobalAddress();
    Ipv6Address rootAddress = root->GetGlobalAddress();
    NS_TEST_ASSERT_MSG_EQ(root->GetTopologySize(), 1, "The root did not learn the child's DAO");

    std::vector<Ipv6Address> hops;
    NS_TEST_ASSERT_MSG_EQ(root->ComputeSourceRoute(childAddress, hops),
                          true,
                          "The root cannot reach the child before the No-Path");

    RplDaoHeader noPath;
    noPath.SetInstanceId(RPL_DEFAULT_INSTANCE);
    noPath.SetSequence(99);
    noPath.SetTarget(childAddress);
    noPath.SetTransitInformation(Ipv6Address("2001:1::9"), 1, 0); // lifetime 0: No-Path

    Simulator::Schedule(Seconds(0),
                       &SendRawRplMessage<RplDaoHeader>,
                       nodes.Get(1),
                       1,
                       noPath,
                       static_cast<uint8_t>(RPL_CODE_DAO),
                       childAddress,
                       rootAddress);

    Simulator::Stop(Seconds(1));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(root->GetTopologySize(), 0, "The No-Path DAO did not remove the entry");
    NS_TEST_ASSERT_MSG_EQ(root->ComputeSourceRoute(childAddress, hops),
                          false,
                          "The root can still reach the child after the No-Path");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check that a node about to leave the DODAG for lack of a parent
 *        withdraws itself first: SendNoPathDao(), RFC 6550 section 6.4.3.
 *
 * Same setup as RplParentLossRejoinTestCase (a parent that stops sending
 * DIOs, detected as stale once the Trickle timer notices), but with a raw
 * socket on the root recording every DAO that arrives so the withdrawal
 * itself -- not just its effect on the root's topology, which
 * RplNoPathDaoTestCase already covers from a hand-built message -- can be
 * confirmed. Only the root-to-child direction is blacklisted, so the
 * withdrawal, travelling child to root, still gets through.
 */
class RplNoPathDaoSentOnParentLossTestCase : public TestCase
{
  public:
    RplNoPathDaoSentOnParentLossTestCase();

  private:
    void DoRun() override;

    /**
     * @brief Record a DAO's target and path lifetime.
     * @param socket the monitoring socket
     */
    void RecordDao(Ptr<Socket> socket);

    std::vector<std::pair<Ipv6Address, uint8_t>> m_daos; //!< (target, path lifetime) of every DAO seen
};

RplNoPathDaoSentOnParentLossTestCase::RplNoPathDaoSentOnParentLossTestCase()
    : TestCase("A node withdraws itself with a No-Path DAO before leaving the DODAG")
{
}

void
RplNoPathDaoSentOnParentLossTestCase::RecordDao(Ptr<Socket> socket)
{
    Address sender;
    Ptr<Packet> packet = socket->RecvFrom(sender);
    if (!packet)
    {
        return;
    }

    Ipv6Header ipv6Header;
    packet->RemoveHeader(ipv6Header);
    Icmpv6Header icmpv6Header;
    packet->RemoveHeader(icmpv6Header);

    if (icmpv6Header.GetType() == ICMPV6_RPL && icmpv6Header.GetCode() == RPL_CODE_DAO)
    {
        RplDaoHeader dao;
        packet->RemoveHeader(dao);
        m_daos.emplace_back(dao.GetTarget(), dao.GetPathLifetime());
    }
}

void
RplNoPathDaoSentOnParentLossTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    rplHelper.Set("DioIntervalMin", TimeValue(MilliSeconds(256)));
    rplHelper.Set("DioIntervalDoublings", UintegerValue(2));
    rplHelper.Set("DisInterval", TimeValue(Seconds(2)));

    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Ptr<Node> rootNode = nodes.Get(0);
    Ptr<Socket> monitor = Socket::CreateSocket(rootNode, Ipv6RawSocketFactory::GetTypeId());
    monitor->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    monitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    monitor->BindToNetDevice(rootNode->GetObject<Ipv6L3Protocol>()->GetNetDevice(1));
    monitor->SetRecvCallback(MakeCallback(&RplNoPathDaoSentOnParentLossTestCase::RecordDao, this));

    Ptr<RplRoutingProtocol> root = rootNode->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> child = nodes.Get(1)->GetObject<RplRoutingProtocol>();

    Simulator::Stop(Seconds(10));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(child->IsJoined(), true, "The child never joined the DODAG");
    Ipv6Address childAddress = child->GetGlobalAddress();
    NS_TEST_ASSERT_MSG_EQ(root->GetTopologySize(), 1, "The root never heard the child's first DAO");

    long normalDaos =
        std::count_if(m_daos.begin(), m_daos.end(), [](const auto& dao) { return dao.second != 0; });
    NS_TEST_ASSERT_MSG_GT_OR_EQ(normalDaos, 1, "The child's ordinary advertisement never arrived");

    Ptr<SimpleNetDevice> rootDevice = DynamicCast<SimpleNetDevice>(devices.Get(0));
    Ptr<SimpleNetDevice> childDevice = DynamicCast<SimpleNetDevice>(devices.Get(1));
    channel->BlackList(rootDevice, childDevice);

    Simulator::Stop(Seconds(15));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(child->IsJoined(),
                          false,
                          "The child never noticed its parent had gone quiet");

    bool withdrew = std::any_of(m_daos.begin(), m_daos.end(), [&](const auto& dao) {
        return dao.first == childAddress && dao.second == 0;
    });
    NS_TEST_ASSERT_MSG_EQ(withdrew,
                          true,
                          "No No-Path DAO for the child's own address arrived at the root");

    // The root acts on it exactly as it would one from another
    // implementation (RplNoPathDaoTestCase): the topology entry is gone.
    NS_TEST_ASSERT_MSG_EQ(root->GetTopologySize(),
                          0,
                          "The root's topology still lists the child after its withdrawal");

    monitor->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check that a node poisoned by its only parent (RFC 6550 section
 *        8.2.2.5, an infinite rank) also withdraws itself, the same as one
 *        that loses its parent to silence.
 *
 * HandleDio() has its own m_parents.erase(from), separate from the
 * staleness sweep RplNoPathDaoSentOnParentLossTestCase exercises, so this
 * is not the same code path even though both end up at
 * SelectPreferredParent()'s best.IsAny() case. The link itself is very
 * much alive here (that is how the poisoning DIO arrived at all), so
 * unlike an interface going down (StopInterface(), which closes the
 * socket before it ever gets a chance to withdraw anything, and has
 * nothing left to send on by the time it would) there is no reason the
 * withdrawal should not get through.
 */
class RplNoPathDaoSentOnPoisonTestCase : public TestCase
{
  public:
    RplNoPathDaoSentOnPoisonTestCase();

  private:
    void DoRun() override;

    /**
     * @brief Record a DAO's target and path lifetime.
     * @param socket the monitoring socket
     */
    void RecordDao(Ptr<Socket> socket);

    std::vector<std::pair<Ipv6Address, uint8_t>> m_daos; //!< (target, path lifetime) of every DAO seen
};

RplNoPathDaoSentOnPoisonTestCase::RplNoPathDaoSentOnPoisonTestCase()
    : TestCase("A node withdraws itself with a No-Path DAO when poisoned")
{
}

void
RplNoPathDaoSentOnPoisonTestCase::RecordDao(Ptr<Socket> socket)
{
    Address sender;
    Ptr<Packet> packet = socket->RecvFrom(sender);
    if (!packet)
    {
        return;
    }

    Ipv6Header ipv6Header;
    packet->RemoveHeader(ipv6Header);
    Icmpv6Header icmpv6Header;
    packet->RemoveHeader(icmpv6Header);

    if (icmpv6Header.GetType() == ICMPV6_RPL && icmpv6Header.GetCode() == RPL_CODE_DAO)
    {
        RplDaoHeader dao;
        packet->RemoveHeader(dao);
        m_daos.emplace_back(dao.GetTarget(), dao.GetPathLifetime());
    }
}

void
RplNoPathDaoSentOnPoisonTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Ptr<Node> rootNode = nodes.Get(0);
    Ptr<Socket> monitor = Socket::CreateSocket(rootNode, Ipv6RawSocketFactory::GetTypeId());
    monitor->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    monitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    monitor->BindToNetDevice(rootNode->GetObject<Ipv6L3Protocol>()->GetNetDevice(1));
    monitor->SetRecvCallback(MakeCallback(&RplNoPathDaoSentOnPoisonTestCase::RecordDao, this));

    Ptr<RplRoutingProtocol> root = rootNode->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> child = nodes.Get(1)->GetObject<RplRoutingProtocol>();

    Simulator::Stop(Seconds(10));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(child->IsJoined(), true, "The child never joined the DODAG");
    Ipv6Address childAddress = child->GetGlobalAddress();
    NS_TEST_ASSERT_MSG_EQ(root->GetTopologySize(), 1, "The root never heard the child's first DAO");

    Ipv6Address rootLinkLocal =
        rootNode->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address childLinkLocal =
        nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    // A DIO advertising an infinite rank, from the root's own link-local
    // address -- the child's one and only parent -- but hand-built rather
    // than anything the real root would ever send: RplRoutingProtocol
    // never poisons its own sub-DODAG this way, so this is standing in for
    // a different implementation, or a compromised node, doing so.
    RplDioHeader poison;
    poison.SetInstanceId(RPL_DEFAULT_INSTANCE);
    poison.SetVersionNumber(0); // the root's version at DoInitialize(), never bumped here
    poison.SetRank(RPL_INFINITE_RANK);
    poison.SetMop(RPL_MOP_NON_STORING);
    poison.SetDodagId(root->GetDodagId());

    Simulator::Schedule(Seconds(0),
                        &SendRawRplMessage<RplDioHeader>,
                        rootNode,
                        1,
                        poison,
                        static_cast<uint8_t>(RPL_CODE_DIO),
                        rootLinkLocal,
                        childLinkLocal);
    Simulator::Stop(Seconds(1));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(child->IsJoined(), false, "The child stayed joined despite the poison");
    NS_TEST_ASSERT_MSG_EQ(child->GetPreferredParent(),
                          Ipv6Address::GetAny(),
                          "The poisoned parent stayed selected");

    bool withdrew = std::any_of(m_daos.begin(), m_daos.end(), [&](const auto& dao) {
        return dao.first == childAddress && dao.second == 0;
    });
    NS_TEST_ASSERT_MSG_EQ(withdrew,
                          true,
                          "No No-Path DAO for the child's own address arrived at the root after "
                          "being poisoned, even though the link it would have travelled on was "
                          "never taken down");

    monitor->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check that a node detaching from the middle of a line poisons its
 *        sub-DODAG on the way out (RFC 6550 section 8.2.2.5) instead of
 *        going quiet and looping with its own former child.
 *
 * Three nodes in a line, root - middle - leaf. Cutting the root's DIOs off
 * from the middle leaves the middle with no parent, so it detaches. The
 * leaf, meanwhile, is still perfectly able to hear the middle and has no
 * reason of its own to stop sending DIOs at it.
 *
 * Without the poisoning DIO, the leaf never learns any of that: it keeps
 * announcing itself, and the middle -- unjoined, so with no rank of its
 * own left for SelectPreferredParent()'s loop avoidance to compare
 * against -- takes the first DIO back as its new parent, which is the leaf
 * that is still pointing at the middle. The two route through each other
 * and a packet bounces between them until the Hop Limit runs out (in a
 * debug build, until PacketMetadata's bookkeeping trips an assertion
 * first). RFC 6550 section 8.2.2.6 is what says the detaching node has to
 * speak up here, and section 8.2.2.5 what the sub-DODAG does about it:
 * a former parent advertising INFINITE_RANK "cannot act as a parent any
 * longer and is removed from the parent set".
 */
class RplPoisonOnDetachTestCase : public TestCase
{
  public:
    RplPoisonOnDetachTestCase();

  private:
    void DoRun() override;

    /**
     * @brief Record a DAO's target and path lifetime.
     * @param socket the monitoring socket
     */
    void RecordDao(Ptr<Socket> socket);

    std::vector<std::pair<Ipv6Address, uint8_t>> m_daos; //!< (target, path lifetime) of every DAO seen
};

RplPoisonOnDetachTestCase::RplPoisonOnDetachTestCase()
    : TestCase("A detaching node poisons its sub-DODAG instead of looping with it")
{
}

void
RplPoisonOnDetachTestCase::RecordDao(Ptr<Socket> socket)
{
    Address sender;
    Ptr<Packet> packet = socket->RecvFrom(sender);
    if (!packet)
    {
        return;
    }
    Ipv6Header ipv6Header;
    packet->RemoveHeader(ipv6Header);
    Icmpv6Header icmpv6Header;
    packet->RemoveHeader(icmpv6Header);
    if (icmpv6Header.GetType() == ICMPV6_RPL && icmpv6Header.GetCode() == RPL_CODE_DAO)
    {
        RplDaoHeader dao;
        packet->RemoveHeader(dao);
        m_daos.emplace_back(dao.GetTarget(), dao.GetPathLifetime());
    }
}

void
RplPoisonOnDetachTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(3); // 0 = root, 1 = middle, 2 = leaf

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    // Line topology: the two ends cannot hear each other.
    Ptr<SimpleNetDevice> first = DynamicCast<SimpleNetDevice>(devices.Get(0));
    Ptr<SimpleNetDevice> last = DynamicCast<SimpleNetDevice>(devices.Get(2));
    channel->BlackList(first, last);
    channel->BlackList(last, first);

    RplHelper rplHelper;
    rplHelper.Set("DioIntervalMin", TimeValue(MilliSeconds(256)));
    rplHelper.Set("DioIntervalDoublings", UintegerValue(2));
    rplHelper.Set("DisInterval", TimeValue(Seconds(2)));

    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Ptr<Node> rootNode = nodes.Get(0);
    Ptr<Socket> monitor = Socket::CreateSocket(rootNode, Ipv6RawSocketFactory::GetTypeId());
    monitor->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    monitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    monitor->BindToNetDevice(rootNode->GetObject<Ipv6L3Protocol>()->GetNetDevice(1));
    monitor->SetRecvCallback(MakeCallback(&RplPoisonOnDetachTestCase::RecordDao, this));

    Ptr<RplRoutingProtocol> root = rootNode->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> middle = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> leaf = nodes.Get(2)->GetObject<RplRoutingProtocol>();

    Simulator::Stop(Seconds(15));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(middle->IsJoined(), true, "The middle node never joined");
    NS_TEST_ASSERT_MSG_EQ(leaf->IsJoined(), true, "The leaf never joined");
    NS_TEST_ASSERT_MSG_EQ(root->GetTopologySize(), 2, "The root did not hear both DAOs");
    Ipv6Address middleAddress = middle->GetGlobalAddress();
    Ipv6Address middleLinkLocal =
        nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address leafLinkLocal =
        nodes.Get(2)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    NS_TEST_ASSERT_MSG_EQ(leaf->GetPreferredParent(),
                          middleLinkLocal,
                          "The leaf is not hanging off the middle node");

    // Cut the root's DIOs off from the middle node. The leaf can still hear
    // the middle perfectly well, and goes on announcing itself to it.
    Ptr<SimpleNetDevice> rootDevice = DynamicCast<SimpleNetDevice>(devices.Get(0));
    Ptr<SimpleNetDevice> middleDevice = DynamicCast<SimpleNetDevice>(devices.Get(1));
    channel->BlackList(rootDevice, middleDevice);

    Simulator::Stop(Seconds(20));
    Simulator::Run();

    // The middle node has nothing left to reach the root through, so it
    // detaches -- and so, once the poisoning DIO reaches it, does the leaf,
    // whose only way up was the middle.
    NS_TEST_ASSERT_MSG_EQ(middle->IsJoined(),
                          false,
                          "The middle node stayed in a DODAG it cannot reach");
    NS_TEST_ASSERT_MSG_EQ(leaf->IsJoined(),
                          false,
                          "The leaf kept a parent that had already detached, which means the "
                          "poisoning DIO never reached it");

    // The heart of it: neither may end up pointing at the other. Before the
    // poisoning DIO existed, this is exactly what happened -- the middle
    // took the leaf as its parent while the leaf still had the middle as
    // its own, and traffic looped between them.
    NS_TEST_ASSERT_MSG_NE(middle->GetPreferredParent(),
                          leafLinkLocal,
                          "The middle node adopted its own former child as a parent");
    NS_TEST_ASSERT_MSG_NE(leaf->GetPreferredParent(),
                          middleLinkLocal,
                          "The leaf kept the detached middle node as its parent");

    // The middle node was still able to reach the root when it detached, so
    // its own withdrawal got through. The leaf's cannot: its only route to
    // the root ran through the middle node, which by then had detached too,
    // so that entry is left for the root's PurgeTopology() to age out.
    bool middleWithdrew = std::any_of(m_daos.begin(), m_daos.end(), [&](const auto& dao) {
        return dao.first == middleAddress && dao.second == 0;
    });
    NS_TEST_ASSERT_MSG_EQ(middleWithdrew,
                          true,
                          "The middle node never withdrew itself from the root");

    monitor->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check RFC 6719 section 3.2.2 rule 4: with no preferred parent,
 *        cur_min_path_cost (m_pathEtx) is MAX_PATH_COST, not 0.
 *
 * The only DIO a node with no parent ever sends is the poisoning one
 * (LeaveDodag(true)), whose INFINITE_RANK already gets it dropped from
 * every listener's parent set before the Metric Container would matter
 * (RFC 6550 section 8.2.2.5) -- so this checks the value on the wire
 * directly rather than through any behavioural side effect, which is the
 * whole reason 25.6/26 in design-constraints.md calls the bug harmless
 * rather than unobservable.
 */
class RplPathCostOnDetachTestCase : public TestCase
{
  public:
    RplPathCostOnDetachTestCase();

  private:
    void DoRun() override;

    /**
     * @brief Record a poisoning DIO's path ETX.
     * @param socket the monitoring socket
     */
    void RecordDio(Ptr<Socket> socket);

    std::vector<uint16_t> m_poisonPathEtx; //!< path ETX of every INFINITE_RANK DIO seen
};

RplPathCostOnDetachTestCase::RplPathCostOnDetachTestCase()
    : TestCase("A detaching node advertises MAX_PATH_COST, not 0, under MRHOF")
{
}

void
RplPathCostOnDetachTestCase::RecordDio(Ptr<Socket> socket)
{
    Address sender;
    Ptr<Packet> packet = socket->RecvFrom(sender);
    if (!packet)
    {
        return;
    }
    Ipv6Header ipv6Header;
    packet->RemoveHeader(ipv6Header);
    Icmpv6Header icmpv6Header;
    packet->RemoveHeader(icmpv6Header);
    if (icmpv6Header.GetType() != ICMPV6_RPL || icmpv6Header.GetCode() != RPL_CODE_DIO)
    {
        return;
    }
    RplDioHeader dio;
    packet->RemoveHeader(dio);
    if (dio.GetRank() == RPL_INFINITE_RANK && dio.HasMetricContainer())
    {
        m_poisonPathEtx.push_back(dio.GetPathEtx());
    }
}

void
RplPathCostOnDetachTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    rplHelper.Set("Ocp", UintegerValue(RPL_OCP_MRHOF));
    rplHelper.Set("DioIntervalMin", TimeValue(MilliSeconds(256)));
    rplHelper.Set("DioIntervalDoublings", UintegerValue(2));
    rplHelper.Set("DisInterval", TimeValue(Seconds(2)));

    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Ptr<Node> rootNode = nodes.Get(0);
    Ptr<Node> childNode = nodes.Get(1);
    // On the root, not the child: a node's own multicast transmissions are
    // never delivered back to a socket on that same node, so a monitor on
    // the child would never see the child's own poisoning DIO (@see
    // .claude/skills/ns3-debug-pitfalls).
    Ptr<Socket> dioMonitor = Socket::CreateSocket(rootNode, Ipv6RawSocketFactory::GetTypeId());
    dioMonitor->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    dioMonitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    dioMonitor->BindToNetDevice(rootNode->GetObject<Ipv6L3Protocol>()->GetNetDevice(1));
    dioMonitor->SetRecvCallback(MakeCallback(&RplPathCostOnDetachTestCase::RecordDio, this));

    Ptr<RplRoutingProtocol> root = rootNode->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> child = childNode->GetObject<RplRoutingProtocol>();

    Simulator::Stop(Seconds(10));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(child->IsJoined(), true, "The child never joined the DODAG");
    NS_TEST_ASSERT_MSG_LT(child->GetPathEtx(),
                          static_cast<uint16_t>(RPL_MRHOF_MAX_PATH_COST),
                          "The path ETX while still joined via the root is already at the "
                          "ceiling, so a later MAX_PATH_COST reading would not be distinguishable "
                          "from this baseline");

    // Cut the root's DIOs off from the child (one direction only, same as
    // RplPoisonOnDetachTestCase): the child loses its last parent and
    // detaches, poisoning as it goes (LeaveDodag(true)). The reverse
    // direction stays up, which is what lets the poisoning DIO -- still a
    // multicast, addressed to the whole link -- reach the monitor on the
    // root.
    Ptr<SimpleNetDevice> rootDevice = DynamicCast<SimpleNetDevice>(devices.Get(0));
    Ptr<SimpleNetDevice> childDevice = DynamicCast<SimpleNetDevice>(devices.Get(1));
    channel->BlackList(rootDevice, childDevice);

    Simulator::Stop(Seconds(15));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(child->IsJoined(), false, "The child never detached");
    NS_TEST_ASSERT_MSG_GT_OR_EQ(m_poisonPathEtx.size(),
                                1,
                                "No poisoning DIO with a Metric Container was ever heard");
    for (uint16_t pathEtx : m_poisonPathEtx)
    {
        NS_TEST_ASSERT_MSG_EQ(pathEtx,
                              static_cast<uint16_t>(RPL_MRHOF_MAX_PATH_COST),
                              "The poisoning DIO advertised the wrong path ETX -- MAX_PATH_COST "
                              "expected, not 0");
    }

    dioMonitor->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check that an unacknowledged DAO is retried DaoRetries times at
 *        DaoAckTimeout, then given up on until the next periodic DAO.
 *
 * A raw socket installed on the root, alongside RPL's own, counts DAO
 * arrivals without touching any of RplRoutingProtocol's private retry state:
 * one for the DAO that follows joining the DODAG, which gets acknowledged
 * normally, then, once the return path is cut, one for the next periodic DAO
 * plus DaoRetries retries, none of which do.
 */
class RplDaoAckRetryTestCase : public TestCase
{
  public:
    RplDaoAckRetryTestCase();

  private:
    void DoRun() override;

    /**
     * @brief Record the arrival of a DAO at the monitoring socket.
     * @param socket the monitoring socket
     */
    void RecordDao(Ptr<Socket> socket);

    std::vector<Time> m_daoArrivals; //!< when a DAO reached the monitoring socket
};

RplDaoAckRetryTestCase::RplDaoAckRetryTestCase()
    : TestCase("DAO-ACK timeout retries the DAO, then gives up")
{
}

void
RplDaoAckRetryTestCase::RecordDao(Ptr<Socket> socket)
{
    Address sender;
    Ptr<Packet> packet = socket->RecvFrom(sender);
    if (!packet)
    {
        return;
    }

    Ipv6Header ipv6Header;
    packet->RemoveHeader(ipv6Header);
    Icmpv6Header icmpv6Header;
    packet->RemoveHeader(icmpv6Header);

    if (icmpv6Header.GetType() == ICMPV6_RPL && icmpv6Header.GetCode() == RPL_CODE_DAO)
    {
        m_daoArrivals.push_back(Simulator::Now());
    }
}

void
RplDaoAckRetryTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    // A short, exact Imin gets the DODAG up quickly and predictably, so the
    // margins below do not depend on how long that takes.
    rplHelper.Set("DioIntervalMin", TimeValue(MilliSeconds(256)));
    rplHelper.Set("DaoInterval", TimeValue(Seconds(4)));
    rplHelper.Set("DaoAckTimeout", TimeValue(Seconds(1)));
    rplHelper.Set("DaoRetries", UintegerValue(2));

    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Ptr<Node> rootNode = nodes.Get(0);
    Ptr<Socket> monitor = Socket::CreateSocket(rootNode, Ipv6RawSocketFactory::GetTypeId());
    monitor->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    monitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    monitor->BindToNetDevice(rootNode->GetObject<Ipv6L3Protocol>()->GetNetDevice(1));
    monitor->SetRecvCallback(MakeCallback(&RplDaoAckRetryTestCase::RecordDao, this));

    // The DAO that follows joining the DODAG, well before the first periodic
    // refresh at DaoInterval later, gets acknowledged normally.
    Simulator::Stop(Seconds(2));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(m_daoArrivals.size(), 1, "The first DAO did not arrive as expected");
    Ptr<RplRoutingProtocol> root = rootNode->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(root->GetTopologySize(), 1, "The root did not learn the child's DAO");

    // Cut the return path: the child's next DAO still reaches the root (so it
    // still counts here), but the DAO-ACK the root sends back never does.
    Ptr<SimpleNetDevice> rootDevice = DynamicCast<SimpleNetDevice>(devices.Get(0));
    Ptr<SimpleNetDevice> childDevice = DynamicCast<SimpleNetDevice>(devices.Get(1));
    channel->BlackList(rootDevice, childDevice);

    // DaoTimerExpire() reschedules the next periodic DAO unconditionally,
    // whether or not the previous one was acknowledged, so the window below
    // has to end well inside one DaoInterval to see only one such cycle. With
    // the streams AssignStreams() fixes above, the periodic DAO and its two
    // retries land at 3.71, 4.71 and 5.71 s after the blacklist, and the next
    // periodic DAO at 7.71 s; 6.2 s comfortably separates the two.
    Simulator::Stop(Seconds(6.2));
    Simulator::Run();

    // 1 (initial, already counted) + 1 (periodic, unacknowledged) +
    // DaoRetries (2, also unacknowledged), and no more within this window.
    NS_TEST_ASSERT_MSG_EQ(m_daoArrivals.size(),
                          4,
                          "Wrong number of DAO transmissions across the periodic "
                          "refresh and its retries");

    monitor->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check the three answers a DIS can get (RFC 6550 section 8.3): a
 *        unicast one is answered with a unicast DIO, a multicast one resets
 *        the Trickle timer instead, and a node that has not joined a DODAG
 *        answers neither.
 *
 * A monitoring raw socket on the soliciting node counts the DIOs; Imin is
 * long enough that the Trickle timer's own transmissions are easy to tell
 * apart from an answer, and the multicast case is read off the timing --
 * a reset puts the next transmission back inside one Imin, where the
 * grown-up interval would have taken seconds.
 */
class RplDisHandlingTestCase : public TestCase
{
  public:
    RplDisHandlingTestCase();

  private:
    void DoRun() override;

    /**
     * @brief Record the arrival of a DIO at the monitoring socket.
     * @param socket the monitoring socket
     */
    void RecordDio(Ptr<Socket> socket);

    std::vector<Time> m_dioArrivals; //!< when a DIO reached the monitoring socket
};

RplDisHandlingTestCase::RplDisHandlingTestCase()
    : TestCase("DIS answered, ignored, or turned into a Trickle reset")
{
}

void
RplDisHandlingTestCase::RecordDio(Ptr<Socket> socket)
{
    Address sender;
    Ptr<Packet> packet = socket->RecvFrom(sender);
    if (!packet)
    {
        return;
    }

    Ipv6Header ipv6Header;
    packet->RemoveHeader(ipv6Header);
    Icmpv6Header icmpv6Header;
    packet->RemoveHeader(icmpv6Header);

    if (icmpv6Header.GetType() == ICMPV6_RPL && icmpv6Header.GetCode() == RPL_CODE_DIO)
    {
        m_dioArrivals.push_back(Simulator::Now());
    }
}

void
RplDisHandlingTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(3); // 0 = root, 1 = the soliciting node, 2 = never joins

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    // Node 2 never hears a DIO from anyone -- neither the root's own, nor
    // one relayed by node 1 once it joins and starts advertising its own
    // rank -- so it stays outside the DODAG and can stand in for
    // "solicited but not joined".
    Ptr<SimpleNetDevice> rootDevice = DynamicCast<SimpleNetDevice>(devices.Get(0));
    Ptr<SimpleNetDevice> proberDevice = DynamicCast<SimpleNetDevice>(devices.Get(1));
    Ptr<SimpleNetDevice> outsiderDevice = DynamicCast<SimpleNetDevice>(devices.Get(2));
    channel->BlackList(rootDevice, outsiderDevice);
    channel->BlackList(outsiderDevice, rootDevice);
    channel->BlackList(proberDevice, outsiderDevice);
    channel->BlackList(outsiderDevice, proberDevice);

    RplHelper rplHelper;
    // Imin of a second with four doublings: Imax is 16 s, far enough from
    // Imin that a reset back to Imin is unmistakable in the arrival times.
    rplHelper.Set("DioIntervalMin", TimeValue(Seconds(1)));
    rplHelper.Set("DioIntervalDoublings", UintegerValue(4));
    // Nothing here needs the soliciting node's own periodic DIS.
    rplHelper.Set("DisInterval", TimeValue(Seconds(1000)));

    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Ptr<Node> prober = nodes.Get(1);
    Ptr<Socket> monitor = Socket::CreateSocket(prober, Ipv6RawSocketFactory::GetTypeId());
    monitor->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    monitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    monitor->BindToNetDevice(prober->GetObject<Ipv6L3Protocol>()->GetNetDevice(1));
    monitor->SetRecvCallback(MakeCallback(&RplDisHandlingTestCase::RecordDio, this));

    // Let the DODAG settle and the root's Trickle interval grow to Imax.
    Simulator::Stop(Seconds(80));
    Simulator::Run();

    Ptr<RplRoutingProtocol> root = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> outsider = nodes.Get(2)->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(root->IsJoined(), true, "The root never started its DODAG");
    NS_TEST_ASSERT_MSG_EQ(outsider->IsJoined(),
                          false,
                          "The node cut off from the root joined a DODAG anyway");

    Ipv6Address proberLinkLocal =
        prober->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address rootLinkLocal =
        nodes.Get(0)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address outsiderLinkLocal =
        nodes.Get(2)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    // A unicast DIS to the root: answered with a DIO addressed back, well
    // inside the seconds the grown-up Trickle interval would have taken.
    m_dioArrivals.clear();
    RplDisHeader dis;
    Simulator::Schedule(Seconds(0),
                        &SendRawRplMessage<RplDisHeader>,
                        prober,
                        1,
                        dis,
                        static_cast<uint8_t>(RPL_CODE_DIS),
                        proberLinkLocal,
                        rootLinkLocal);
    Simulator::Stop(MilliSeconds(100));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(m_dioArrivals.size(), 1, "A unicast DIS was not answered with one DIO");

    // A unicast DIS to a node that has not joined anything: it has nothing
    // to advertise, so it stays quiet.
    m_dioArrivals.clear();
    Simulator::Schedule(Seconds(0),
                        &SendRawRplMessage<RplDisHeader>,
                        prober,
                        1,
                        dis,
                        static_cast<uint8_t>(RPL_CODE_DIS),
                        proberLinkLocal,
                        outsiderLinkLocal);
    Simulator::Stop(MilliSeconds(100));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(m_dioArrivals.size(),
                          0,
                          "A node outside any DODAG answered a DIS anyway");

    // A multicast DIS is an inconsistency (RFC 6550 section 8.3): rather
    // than answer it directly, the root resets its Trickle timer, which
    // puts the next multicast DIO within one Imin instead of the up to
    // Imax it was heading for.
    m_dioArrivals.clear();
    Simulator::Schedule(Seconds(0),
                        &SendRawRplMessage<RplDisHeader>,
                        prober,
                        1,
                        dis,
                        static_cast<uint8_t>(RPL_CODE_DIS),
                        proberLinkLocal,
                        Ipv6Address(RPL_ALL_NODES_MULTICAST));
    Time before = Simulator::Now();
    Simulator::Stop(Seconds(1));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_GT_OR_EQ(m_dioArrivals.size(),
                                1,
                                "A multicast DIS did not reset the root's Trickle timer");
    NS_TEST_ASSERT_MSG_LT(m_dioArrivals.front() - before,
                          Seconds(1),
                          "The DIO after a multicast DIS came no sooner than the un-reset "
                          "interval would have produced");

    monitor->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check which DAO-ACKs stop a node retrying its DAO and which do
 *        not: the wrong sequence number, a rejection status, and the one
 *        that actually matches. Plus the DAO a node that is not the root
 *        must not act on.
 *
 * RFC 6550 section 6.5's DAO-ACK carries back the sequence it answers, so
 * a node has to check it: acting on an acknowledgement for an earlier DAO
 * would clear the pending state of the one still in flight and lose the
 * retry that was meant to get it through.
 */
class RplDaoAckSequenceTestCase : public TestCase
{
  public:
    RplDaoAckSequenceTestCase();

  private:
    void DoRun() override;

    /**
     * @brief Record a DAO, and the sequence it carries.
     * @param socket the monitoring socket
     */
    void RecordDao(Ptr<Socket> socket);

    std::vector<uint8_t> m_daoSequences; //!< sequence of every DAO seen
};

RplDaoAckSequenceTestCase::RplDaoAckSequenceTestCase()
    : TestCase("DAO-ACKs a node must not accept")
{
}

void
RplDaoAckSequenceTestCase::RecordDao(Ptr<Socket> socket)
{
    Address sender;
    Ptr<Packet> packet = socket->RecvFrom(sender);
    if (!packet)
    {
        return;
    }

    Ipv6Header ipv6Header;
    packet->RemoveHeader(ipv6Header);
    Icmpv6Header icmpv6Header;
    packet->RemoveHeader(icmpv6Header);

    if (icmpv6Header.GetType() == ICMPV6_RPL && icmpv6Header.GetCode() == RPL_CODE_DAO)
    {
        RplDaoHeader dao;
        packet->RemoveHeader(dao);
        m_daoSequences.push_back(dao.GetSequence());
    }
}

void
RplDaoAckSequenceTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    rplHelper.Set("DioIntervalMin", TimeValue(MilliSeconds(256)));
    // The child's very first DAO gets acknowledged for real, before the
    // blacklist below is even applied, so what that blacklist leaves
    // unacknowledged is the next one -- the periodic refresh, DaoInterval
    // later. Long enough that it cannot recur a second time before every
    // check below is done (SendDao() unconditionally hands the
    // acknowledgement-tracking state to whatever sequence it just sent, so
    // a second refresh landing mid-test would silently retarget the
    // retries this test is watching), short enough that the whole test
    // still finishes well inside Icmpv6L4Protocol's default 30 s
    // ReachableTime -- the child's Neighbour Discovery cache entry for the
    // root, as its gateway, is confirmed once during the join above and
    // never again once the blacklist is up, and past ReachableTime a
    // genuinely unreachable entry drops packets before they ever reach the
    // channel, which would stop the DAOs themselves, not just their
    // acknowledgement.
    rplHelper.Set("DaoInterval", TimeValue(Seconds(20)));
    rplHelper.Set("DaoAckTimeout", TimeValue(Seconds(1)));
    rplHelper.Set("DaoRetries", UintegerValue(30));

    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Ptr<Node> rootNode = nodes.Get(0);
    Ptr<Socket> monitor = Socket::CreateSocket(rootNode, Ipv6RawSocketFactory::GetTypeId());
    monitor->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    monitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    monitor->BindToNetDevice(rootNode->GetObject<Ipv6L3Protocol>()->GetNetDevice(1));
    monitor->SetRecvCallback(MakeCallback(&RplDaoAckSequenceTestCase::RecordDao, this));

    // Let the child join and send its first DAO normally, so this exercises
    // a real DAO-ACK sequence being interrupted, not a join that never
    // happened in the first place. That first DAO gets acknowledged before
    // the blacklist below takes effect. The bystander is never a candidate
    // parent (RPL_MOP_NON_STORING is the only mode implemented and every
    // node here runs it, but the bystander joining the same DODAG one hop
    // out from the child would only complicate the topology for nothing
    // this test needs); it just needs a working address of its own,
    // established here alongside everything else.
    Simulator::Stop(Seconds(5));
    Simulator::Run();

    Ptr<RplRoutingProtocol> root = rootNode->GetObject<RplRoutingProtocol>();
    Ptr<Node> childNode = nodes.Get(1);
    Ptr<RplRoutingProtocol> child = childNode->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(child->IsJoined(), true, "The child never joined the DODAG");
    NS_TEST_ASSERT_MSG_GT_OR_EQ(m_daoSequences.size(),
                                1,
                                "The child's first DAO did not arrive");

    // A DAO addressed to a node that is not the root, while root-to-child is
    // still open: non-storing mode has the root, and only the root, keep
    // the topology (RFC 6550 section 9.2), so this must not be recorded
    // anywhere on the child.
    Ipv6Address childAddress = child->GetGlobalAddress();
    Ipv6Address rootAddress = root->GetGlobalAddress();
    NS_TEST_ASSERT_MSG_EQ(child->GetTopologySize(), 0, "A non-root node kept a topology");
    RplDaoHeader stray;
    stray.SetInstanceId(RPL_DEFAULT_INSTANCE);
    stray.SetSequence(1);
    stray.SetTarget(Ipv6Address("2001:1::ff:fe00:99"));
    stray.SetTransitInformation(rootAddress, 1, RPL_DEFAULT_LIFETIME);
    Simulator::Schedule(Seconds(0),
                        &SendRawRplMessage<RplDaoHeader>,
                        rootNode,
                        1,
                        stray,
                        static_cast<uint8_t>(RPL_CODE_DAO),
                        rootAddress,
                        childAddress);
    Simulator::Stop(Seconds(1));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(child->GetTopologySize(),
                          0,
                          "A node that is not the root acted on a DAO");

    // Now cut the root's replies off: the root's own DAO-ACK never reaches
    // the child from here on, so the only acknowledgements it sees are the
    // hand-built ones below (sent from the bystander instead, see the note
    // on sendAck()), and the retry timer keeps the DAO coming.
    Ptr<SimpleNetDevice> rootDevice = DynamicCast<SimpleNetDevice>(devices.Get(0));
    Ptr<SimpleNetDevice> childDevice = DynamicCast<SimpleNetDevice>(devices.Get(1));
    channel->BlackList(rootDevice, childDevice);

    // The next periodic DAO (DaoInterval after the child joined) finds
    // nothing to acknowledge it: DaoAckTimeout's retries follow.
    Simulator::Stop(Seconds(20));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_GT_OR_EQ(m_daoSequences.size(),
                                2,
                                "The child's DAO was not retried while unacknowledged");
    uint8_t pending = m_daoSequences.back();

    auto countOf = [this](uint8_t sequence) {
        return std::count(m_daoSequences.begin(), m_daoSequences.end(), sequence);
    };

    // RplRoutingProtocol::HandleDaoAck() never checks who a DAO-ACK actually
    // came from -- only which DODAG it names, plus its sequence and status
    // (@see RplMultiDodagDaoAckIsolationTestCase for the key resolution
    // itself; here there is only ever the one membership for it to
    // resolve to) -- and DeliverRawRplMessage()
    // hands it straight to the child's Ipv6L3Protocol::Receive() -- no
    // channel involved, so the blacklist above cannot swallow it, and
    // nothing about a real send (routing, Neighbour Discovery) has to
    // succeed first for it to arrive. An earlier version of this test sent
    // these the same way SendRawRplMessage() does, from the root itself,
    // which meant lifting that same blacklist for the moment the packet was
    // on the wire; that just as easily let the root's own genuine,
    // correctly-sequenced acknowledgement -- sent automatically in response
    // to whichever retry happened to land inside that same window -- slip
    // through too, silently ending the very sequence this test exists to
    // drive by hand.
    auto sendAck = [&](uint8_t sequence, uint8_t status) {
        RplDaoAckHeader ack;
        ack.SetInstanceId(RPL_DEFAULT_INSTANCE);
        ack.SetDodagId(root->GetDodagId());
        ack.SetSequence(sequence);
        ack.SetStatus(status);
        Simulator::Schedule(Seconds(0),
                            &DeliverRawRplMessage<RplDaoAckHeader>,
                            childNode,
                            1,
                            ack,
                            static_cast<uint8_t>(RPL_CODE_DAO_ACK),
                            rootAddress,
                            childAddress);
    };

    // A DAO-ACK for an earlier sequence: not the one in flight, so the
    // retries have to keep going.
    long countBefore = countOf(pending);
    sendAck(static_cast<uint8_t>(pending - 1), 0);
    Simulator::Stop(Seconds(3));
    Simulator::Run();
    NS_TEST_ASSERT_MSG_GT(countOf(pending),
                          countBefore,
                          "A DAO-ACK for an earlier sequence stopped the retries");

    // The right sequence, but a rejection status: RFC 6550 section 6.5's
    // Status is not "accepted", so the DAO is not confirmed either.
    countBefore = countOf(pending);
    sendAck(pending, 1);
    Simulator::Stop(Seconds(3));
    Simulator::Run();
    NS_TEST_ASSERT_MSG_GT(countOf(pending),
                          countBefore,
                          "A rejected DAO was treated as acknowledged");

    // The matching sequence, accepted: the retries stop.
    sendAck(pending, 0);
    Simulator::Stop(Seconds(1));
    Simulator::Run();

    countBefore = countOf(pending);
    Simulator::Stop(Seconds(3));
    Simulator::Run();
    NS_TEST_ASSERT_MSG_EQ(countOf(pending),
                          countBefore,
                          "The DAO kept being retried after it was acknowledged");

    // A duplicate of that same acknowledgement changes nothing.
    sendAck(pending, 0);
    Simulator::Stop(Seconds(3));
    Simulator::Run();
    NS_TEST_ASSERT_MSG_EQ(countOf(pending),
                          countBefore,
                          "A duplicate DAO-ACK restarted something");

    monitor->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check RFC 6550 section 9.6: a node that hears its DAO parent
 *        increment its DTSN refreshes its own DAO (rule 1) and bumps its
 *        own DTSN in turn (rule 2, non-storing mode).
 *
 * The parent's DTSN bump is a hand-built DIO (SendRawRplMessage()), since
 * nothing in this implementation increments its own DTSN on its own --
 * the whole point under test is what a node does on the *receiving* end of
 * one. Two monitors, both on the root: a raw socket counts DAO arrivals
 * (rule 1), and a second one, filtered to the child's link-local source
 * address, reads back the DTSN the child itself puts in its next DIO
 * (rule 2). Both have to sit on the root, not the child: a node's own
 * multicast transmissions are never delivered back to a socket on that
 * same node, so a monitor on the child would only ever see the root's
 * DIOs, never the child's own.
 */
class RplDtsnRefreshTestCase : public TestCase
{
  public:
    RplDtsnRefreshTestCase();

  private:
    void DoRun() override;

    /**
     * @brief Record the arrival of a DAO.
     * @param socket the monitoring socket
     */
    void RecordDao(Ptr<Socket> socket);

    /**
     * @brief Record a DIO's DTSN, if it came from the child.
     * @param socket the monitoring socket
     */
    void RecordDio(Ptr<Socket> socket);

    uint32_t m_daoCount{0};             //!< number of DAOs seen at the root
    Ipv6Address m_childLinkLocal;       //!< the child's address, to filter DIOs by sender
    std::vector<uint8_t> m_childDtsns; //!< DTSN of every DIO the child itself sent
};

RplDtsnRefreshTestCase::RplDtsnRefreshTestCase()
    : TestCase("A DTSN increment from the DAO parent refreshes the DAO and the DTSN")
{
}

void
RplDtsnRefreshTestCase::RecordDao(Ptr<Socket> socket)
{
    Address sender;
    Ptr<Packet> packet = socket->RecvFrom(sender);
    if (!packet)
    {
        return;
    }
    Ipv6Header ipv6Header;
    packet->RemoveHeader(ipv6Header);
    Icmpv6Header icmpv6Header;
    packet->RemoveHeader(icmpv6Header);
    if (icmpv6Header.GetType() == ICMPV6_RPL && icmpv6Header.GetCode() == RPL_CODE_DAO)
    {
        m_daoCount++;
    }
}

void
RplDtsnRefreshTestCase::RecordDio(Ptr<Socket> socket)
{
    Address sender;
    Ptr<Packet> packet = socket->RecvFrom(sender);
    if (!packet)
    {
        return;
    }
    Ipv6Header ipv6Header;
    packet->RemoveHeader(ipv6Header);
    if (ipv6Header.GetSource() != m_childLinkLocal)
    {
        // A node's own multicast transmissions are not delivered back to a
        // socket on that same node, so this monitor never actually sees
        // the root's own DIOs -- but filtering by source is what makes
        // that guaranteed rather than incidental.
        return;
    }
    Icmpv6Header icmpv6Header;
    packet->RemoveHeader(icmpv6Header);
    if (icmpv6Header.GetType() == ICMPV6_RPL && icmpv6Header.GetCode() == RPL_CODE_DIO)
    {
        RplDioHeader dio;
        packet->RemoveHeader(dio);
        m_childDtsns.push_back(dio.GetDtsn());
    }
}

void
RplDtsnRefreshTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    rplHelper.Set("DioIntervalMin", TimeValue(MilliSeconds(256)));
    rplHelper.Set("DioIntervalDoublings", UintegerValue(2));

    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Ptr<Node> rootNode = nodes.Get(0);
    Ptr<Node> childNode = nodes.Get(1);

    Ptr<Socket> daoMonitor = Socket::CreateSocket(rootNode, Ipv6RawSocketFactory::GetTypeId());
    daoMonitor->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    daoMonitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    daoMonitor->BindToNetDevice(rootNode->GetObject<Ipv6L3Protocol>()->GetNetDevice(1));
    daoMonitor->SetRecvCallback(MakeCallback(&RplDtsnRefreshTestCase::RecordDao, this));

    Ptr<RplRoutingProtocol> root = rootNode->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> child = childNode->GetObject<RplRoutingProtocol>();

    Simulator::Stop(Seconds(10));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(child->IsJoined(), true, "The child never joined the DODAG");
    NS_TEST_ASSERT_MSG_GT_OR_EQ(m_daoCount, 1, "The child's initial DAO never arrived");

    Ipv6Address rootLinkLocal =
        rootNode->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address childLinkLocal =
        childNode->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    NS_TEST_ASSERT_MSG_EQ(child->GetPreferredParent(),
                          rootLinkLocal,
                          "The child's preferred parent is not the root");

    // The DIO monitor goes on the root, not the child: a node's own
    // multicast transmissions are never delivered back to a socket on that
    // same node, so this is set up only once the child's link-local
    // address (used to filter it to the child's own DIOs, @see
    // RecordDio()) is known, and only now, after the join settled, so the
    // first DIO it captures is a real one to read the starting DTSN off
    // of rather than racing the join sequence.
    m_childLinkLocal = childLinkLocal;
    Ptr<Socket> dioMonitor = Socket::CreateSocket(rootNode, Ipv6RawSocketFactory::GetTypeId());
    dioMonitor->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    dioMonitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    dioMonitor->BindToNetDevice(rootNode->GetObject<Ipv6L3Protocol>()->GetNetDevice(1));
    dioMonitor->SetRecvCallback(MakeCallback(&RplDtsnRefreshTestCase::RecordDio, this));

    // Imax is Imin << doublings = 256ms << 2 = ~1s, but the monitor's setup
    // and the Trickle timer's current interval are not synchronised: in the
    // worst case (just missed a transmission near the end of the current
    // interval) it takes the rest of that interval plus a whole one more
    // to see the next DIO, up to 2 * Imax. Waited out with margin rather
    // than exactly, so this is not sensitive to exactly where in the
    // interval the monitor happened to be set up.
    Simulator::Stop(Seconds(3));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_GT_OR_EQ(m_childDtsns.size(), 1, "The child never sent a DIO of its own");
    NS_TEST_ASSERT_MSG_EQ(m_childDtsns.back(), 0, "The child's DTSN did not start at 0");

    uint32_t daoCountBeforeBump = m_daoCount;

    // A hand-built DIO, from the root's own link-local address -- the
    // child's one and only DAO parent -- with the DTSN incremented from
    // the 0 every real DIO in this test has carried so far. RplRoutingProtocol
    // never increments its own DTSN unprompted, so nothing short of this
    // can put rule 1/2 to the test.
    RplDioHeader bump;
    bump.SetInstanceId(RPL_DEFAULT_INSTANCE);
    bump.SetVersionNumber(0);
    bump.SetRank(RPL_MIN_HOPRANKINC); // the root's own, fixed rank
    bump.SetMop(RPL_MOP_NON_STORING);
    bump.SetDodagId(root->GetDodagId());
    bump.SetDtsn(1);

    Simulator::Schedule(Seconds(0),
                        &SendRawRplMessage<RplDioHeader>,
                        rootNode,
                        1,
                        bump,
                        static_cast<uint8_t>(RPL_CODE_DIO),
                        rootLinkLocal,
                        childLinkLocal);
    Simulator::Stop(Seconds(1));
    Simulator::Run();

    // Rule 1: a DAO went out to refresh the root's downward state.
    NS_TEST_ASSERT_MSG_GT(m_daoCount,
                          daoCountBeforeBump,
                          "The DTSN bump from the DAO parent did not trigger a DAO");

    // Rule 2: the child's own DTSN followed. Confirmed the same way the
    // baseline was: reading it back out of the child's next real DIO,
    // rather than reaching into RplRoutingProtocol's private state.
    Simulator::Stop(Seconds(5));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(m_childDtsns.back(),
                          1,
                          "The child's own DTSN did not follow its DAO parent's increment");

    daoMonitor->Close();
    dioMonitor->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief RFC 6550 section 7.2 rule 2's circular-region wrap (127 -> 0, not
 *        128) applies to DTSN's own increment (rule 2's "this node's own
 *        DTSN follows its parent's up"), the same as Path Sequence
 *        (design-constraints.md section 58).
 */
class RplDtsnOwnIncrementWrapTestCase : public TestCase
{
  public:
    RplDtsnOwnIncrementWrapTestCase();

  private:
    void DoRun() override;

    /// @brief Record a DIO's DTSN, if it came from the child.
    /// @param socket the monitoring socket
    void RecordDio(Ptr<Socket> socket);

    Ipv6Address m_childLinkLocal;      //!< the child's address, to filter DIOs by sender
    std::vector<uint8_t> m_childDtsns; //!< DTSN of every DIO the child itself sent
};

RplDtsnOwnIncrementWrapTestCase::RplDtsnOwnIncrementWrapTestCase()
    : TestCase("The DTSN a node advertises wraps from 127 to 0, not into the linear region at "
              "128")
{
}

void
RplDtsnOwnIncrementWrapTestCase::RecordDio(Ptr<Socket> socket)
{
    Address sender;
    Ptr<Packet> packet = socket->RecvFrom(sender);
    if (!packet)
    {
        return;
    }
    Ipv6Header ipv6Header;
    packet->RemoveHeader(ipv6Header);
    if (ipv6Header.GetSource() != m_childLinkLocal)
    {
        return;
    }
    Icmpv6Header icmpv6Header;
    packet->RemoveHeader(icmpv6Header);
    if (icmpv6Header.GetType() == ICMPV6_RPL && icmpv6Header.GetCode() == RPL_CODE_DIO)
    {
        RplDioHeader dio;
        packet->RemoveHeader(dio);
        m_childDtsns.push_back(dio.GetDtsn());
    }
}

void
RplDtsnOwnIncrementWrapTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    rplHelper.Set("DioIntervalMin", TimeValue(MilliSeconds(256)));
    rplHelper.Set("DioIntervalDoublings", UintegerValue(2));

    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Ptr<Node> rootNode = nodes.Get(0);
    Ptr<Node> childNode = nodes.Get(1);

    Simulator::Stop(Seconds(10));
    Simulator::Run();

    Ptr<RplRoutingProtocol> root = rootNode->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> child = childNode->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(child->IsJoined(), true, "The child never joined the DODAG");

    Ipv6Address rootLinkLocal =
        rootNode->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address childLinkLocal =
        childNode->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    m_childLinkLocal = childLinkLocal;
    Ptr<Socket> dioMonitor = Socket::CreateSocket(rootNode, Ipv6RawSocketFactory::GetTypeId());
    dioMonitor->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    dioMonitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    dioMonitor->BindToNetDevice(rootNode->GetObject<Ipv6L3Protocol>()->GetNetDevice(1));
    dioMonitor->SetRecvCallback(MakeCallback(&RplDtsnOwnIncrementWrapTestCase::RecordDio, this));

    // 128 successive hand-built DIOs from the root, DTSN 1 through 128 --
    // each one step "newer" than the last per RplSequenceNewer(), so every
    // one triggers rule 2's "this node's own DTSN follows its parent's up"
    // (@see RplDtsnRefreshTestCase for the same mechanism, one bump at a
    // time). The 127th bump takes the child's own DTSN to 127; the 128th
    // is what section 7.2 rule 2 says must wrap it back to 0, not carry it
    // on to 128. 1 ms apart is enough: each SendRawRplMessage()'s own
    // HandleDio() call runs to completion (updating the cached parent DTSN
    // rule 2 compares the next one against) before the next one fires,
    // ns-3's event loop being single-threaded.
    //
    // This shares dodag->parents[rootLinkLocal].dtsn -- the same cache slot
    // rule 2's own comparison reads -- with whatever real DIOs the actual
    // root node keeps sending on its own Trickle schedule throughout this
    // whole 128 ms window: a real DIO landing here would carry its own
    // (unrelated, always-0) DTSN and could desynchronize the count. Not
    // guarded against explicitly, but not observed to collide either: with
    // this test's DioIntervalMin/Doublings, the root's real DIOs land with
    // enough margin on both sides of the window across every AssignStreams()
    // seed tried during this test's own development.
    for (uint16_t dtsn = 1; dtsn <= 128; dtsn++)
    {
        RplDioHeader bump;
        bump.SetInstanceId(RPL_DEFAULT_INSTANCE);
        bump.SetVersionNumber(0);
        bump.SetRank(RPL_MIN_HOPRANKINC);
        bump.SetMop(RPL_MOP_NON_STORING);
        bump.SetDodagId(root->GetDodagId());
        bump.SetDtsn(static_cast<uint8_t>(dtsn));

        Simulator::Schedule(MilliSeconds(dtsn),
                            &SendRawRplMessage<RplDioHeader>,
                            rootNode,
                            1,
                            bump,
                            static_cast<uint8_t>(RPL_CODE_DIO),
                            rootLinkLocal,
                            childLinkLocal);
    }
    Simulator::Stop(Seconds(1));
    Simulator::Run();

    // The same 2 * Imax margin RplDtsnRefreshTestCase waits for its own
    // single bump, for the child's own next real DIO to arrive and be
    // read back.
    Simulator::Stop(Seconds(3));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_GT_OR_EQ(m_childDtsns.size(), 1, "The child never sent a DIO of its own");
    NS_TEST_ASSERT_MSG_EQ(m_childDtsns.back(),
                          0,
                          "The child's DTSN wrapped past 127 into the linear region instead of "
                          "back to 0");

    dioMonitor->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A DAO parent that increments its DTSN faster than the DelayDAO
 *        jitter window (RFC 6550 section 9.6 rules 1-2 impose no rate
 *        limit of their own) must not be able to perpetually defer this
 *        node's own DAO refresh by repeatedly cancelling and re-arming it
 *        -- the refresh has to coalesce into one send instead.
 */
class RplDtsnRapidBumpCoalescedTestCase : public TestCase
{
  public:
    RplDtsnRapidBumpCoalescedTestCase();

  private:
    void DoRun() override;

    /**
     * @brief Count a DAO delivered to the monitoring socket.
     * @param socket the monitoring socket
     */
    void RecordDao(Ptr<Socket> socket);

    uint32_t m_daoCount{0}; //!< DAOs observed at the root
};

RplDtsnRapidBumpCoalescedTestCase::RplDtsnRapidBumpCoalescedTestCase()
    : TestCase("Rapid DTSN increments from a DAO parent coalesce into one DAO refresh, not one "
              "per increment and not none at all")
{
}

void
RplDtsnRapidBumpCoalescedTestCase::RecordDao(Ptr<Socket> socket)
{
    Ptr<Packet> packet = socket->Recv();
    while (packet)
    {
        Ipv6Header ipv6Header;
        if (packet->RemoveHeader(ipv6Header) != 0)
        {
            Icmpv6Header icmpv6Header;
            if (packet->RemoveHeader(icmpv6Header) != 0 &&
                icmpv6Header.GetType() == ICMPV6_RPL && icmpv6Header.GetCode() == RPL_CODE_DAO)
            {
                m_daoCount++;
            }
        }
        packet = socket->Recv();
    }
}

void
RplDtsnRapidBumpCoalescedTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2); // 0 = root (the DAO parent), 1 = child

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    rplHelper.Set("DioIntervalMin", TimeValue(MilliSeconds(256)));
    rplHelper.Set("DioIntervalDoublings", UintegerValue(2));

    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Ptr<Node> rootNode = nodes.Get(0);
    Ptr<Node> childNode = nodes.Get(1);

    Ptr<Socket> daoMonitor = Socket::CreateSocket(rootNode, Ipv6RawSocketFactory::GetTypeId());
    daoMonitor->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    daoMonitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    daoMonitor->BindToNetDevice(rootNode->GetObject<Ipv6L3Protocol>()->GetNetDevice(1));
    daoMonitor->SetRecvCallback(MakeCallback(&RplDtsnRapidBumpCoalescedTestCase::RecordDao, this));

    Simulator::Stop(Seconds(10));
    Simulator::Run();

    Ptr<RplRoutingProtocol> root = rootNode->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> child = childNode->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(child->IsJoined(), true, "The child never joined the DODAG");

    Ipv6Address rootLinkLocal =
        rootNode->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address childLinkLocal =
        childNode->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    uint32_t daoCountBeforeBumps = m_daoCount;

    // 150 hand-built DIOs from the root, DTSN 1 through 150, 20 ms apart (3
    // s of continuous bumping) -- standing in for a misbehaving or actively
    // adversarial DAO parent, since RFC 6550 imposes no rate limit of its
    // own on how often a legitimate one may increment its DTSN. Each one
    // individually satisfies rule 2's "hears... increment its DTSN", and
    // would, pre-fix, unconditionally cancel and re-arm dodag->daoEvent
    // every time.
    //
    // Counter-intuitively, the bug this guards against makes the DAO
    // refresh fire LESS often under a rapid burst, not more: with an
    // unconditional cancel-and-rearm, a pending send only ever survives to
    // actually fire if that particular jitter draw happens to be shorter
    // than the gap before the next bump cancels it again -- a narrow
    // window each time, so most of a long burst's individual arm attempts
    // are wasted. The fix does not depend on any one draw being short: the
    // first bump in a pending cycle arms it once, every later bump in the
    // same cycle is a no-op (gated by daoRefreshPending), and the pending
    // send always gets to actually fire on its own schedule regardless of
    // how many more bumps arrive while it waits -- so the number of
    // completed refreshes over one fixed-length burst is governed by the
    // burst's own duration divided by the average jitter draw, not by how
    // often cancellation gets a chance to interrupt one. For this stream
    // (AssignStreams(nodes, 1), reproducible run to run) that difference
    // was empirically 7 fixed-code sends against 3 with the fix reverted
    // for this exact burst. The threshold below is not the midpoint of
    // that gap, though: the burst's own ~4.48 s effective window (first
    // bump at +20 ms to the +4.5 s stop) divided by the maximum possible
    // single jitter draw (Seconds(0,1), i.e. < 1 s) gives a provable floor
    // of floor(4.48 / 1.0) = 4 completed cycles for genuinely-fixed code
    // even under an adversarial draw sequence that always lands at the
    // jitter ceiling -- so 4, not something picked to merely clear this
    // one run's observed 7, is the threshold that cannot spuriously fail a
    // correctly-fixed run regardless of which draws this shared m_jitter
    // stream happens to produce (shared with dioTrickle/DIS/other
    // jittered sends elsewhere in the same run, so not fully isolated to
    // this test's own Schedule() calls).
    for (uint16_t dtsn = 1; dtsn <= 150; dtsn++)
    {
        RplDioHeader bump;
        bump.SetInstanceId(RPL_DEFAULT_INSTANCE);
        bump.SetVersionNumber(0);
        bump.SetRank(RPL_MIN_HOPRANKINC);
        bump.SetMop(RPL_MOP_NON_STORING);
        bump.SetDodagId(root->GetDodagId());
        bump.SetDtsn(static_cast<uint8_t>(dtsn));

        Simulator::Schedule(MilliSeconds(20 * dtsn),
                            &SendRawRplMessage<RplDioHeader>,
                            rootNode,
                            1,
                            bump,
                            static_cast<uint8_t>(RPL_CODE_DIO),
                            rootLinkLocal,
                            childLinkLocal);
    }
    // The injection window itself (3 s) plus the up-to-1-s jitter the last
    // coalesced send could still be waiting out when the injection ends.
    Simulator::Stop(Seconds(4.5));
    Simulator::Run();

    uint32_t daoCountDuringBumps = m_daoCount - daoCountBeforeBumps;
    NS_TEST_ASSERT_MSG_GT_OR_EQ(daoCountDuringBumps,
                               4,
                               "150 rapid DTSN increments produced only " << daoCountDuringBumps
                                                                         << " DAO refreshes -- "
                                                                            "consistent with the "
                                                                            "unconditional "
                                                                            "cancel-and-rearm bug "
                                                                            "starving most of "
                                                                            "them");

    daoMonitor->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A single already-adjacent neighbour forcing repeated preferred
 *        parent switches (RFC 6550 imposes no rate limit on how often a
 *        node's preferred parent may change, and this module's default
 *        OF0 objective function applies no rank hysteresis at all) must
 *        not be able to perpetually defer this node's own DAO refresh by
 *        repeatedly cancelling and re-arming it -- the same
 *        daoRefreshPending coalescing HandleDio()'s own DTSN trigger uses
 *        (@see RplDtsnRapidBumpCoalescedTestCase) has to also cover
 *        SelectPreferredParent()'s own separate trigger on the identical
 *        Timer.
 */
class RplParentSwitchRapidBumpCoalescedTestCase : public TestCase
{
  public:
    RplParentSwitchRapidBumpCoalescedTestCase();

  private:
    void DoRun() override;

    /**
     * @brief Count a DAO delivered to the monitoring socket.
     * @param socket the monitoring socket
     */
    void RecordDao(Ptr<Socket> socket);

    uint32_t m_daoCount{0}; //!< DAOs observed at the root
};

RplParentSwitchRapidBumpCoalescedTestCase::RplParentSwitchRapidBumpCoalescedTestCase()
    : TestCase("Rapid forced preferred parent switches coalesce into a bounded number of DAO "
              "refreshes, not one per switch and not none at all")
{
}

void
RplParentSwitchRapidBumpCoalescedTestCase::RecordDao(Ptr<Socket> socket)
{
    Ptr<Packet> packet = socket->Recv();
    while (packet)
    {
        Ipv6Header ipv6Header;
        if (packet->RemoveHeader(ipv6Header) != 0)
        {
            Icmpv6Header icmpv6Header;
            if (packet->RemoveHeader(icmpv6Header) != 0 &&
                icmpv6Header.GetType() == ICMPV6_RPL && icmpv6Header.GetCode() == RPL_CODE_DAO)
            {
                // SelectPreferredParent()'s own SendNoPathDao() call (Path
                // Lifetime 0) is deliberately left unguarded by
                // daoRefreshPending -- it is owed to each specific
                // transition's own old preferred parent, not something
                // later switches may coalesce away -- so it fires on every
                // one of the burst's forced switches below regardless of
                // whether the coalescing fix under test is even present.
                // Counting it here would pass this test on that volume
                // alone, independent of the guard. Only the coalesced
                // self-advertisement (SendDao() via daoEvent, a nonzero
                // Path Lifetime) is what daoRefreshPending actually gates,
                // so that is the only one this test counts.
                RplDaoHeader dao;
                if (packet->RemoveHeader(dao) != 0 && dao.GetPathLifetime() != 0)
                {
                    m_daoCount++;
                }
            }
        }
        packet = socket->Recv();
    }
}

void
RplParentSwitchRapidBumpCoalescedTestCase::DoRun()
{
    NodeContainer nodes;
    // 0 = root (the DAO destination), 1 and 2 = altA/altB (real, properly
    // joined second-hop relays the child is forced to alternate between),
    // 3 = child (the victim). altA/altB have to be real nodes, not
    // fabricated addresses with nobody behind them: RouteOutput() (@see its
    // own comment, "everyone else sends everything to its preferred
    // parent") makes dodag.preferredParent the gateway of every route this
    // node's own self-advertisement DAO takes, so a preferred parent with
    // no real device on the channel leaves that DAO permanently
    // undeliverable at the link layer -- SendDao() itself still runs and
    // reports success, but nothing ever reaches the root to prove it. An
    // earlier version of this test used two addresses nobody owned
    // ("fe80::...:aa"/"...:bb") for exactly that reason (a single attacker
    // can trivially operate two identities) and every coalesced
    // self-advertisement silently vanished, which read as the exact same
    // symptom the unfixed livelock produces (daoCountDuringSwitches == 0)
    // for a completely different, uninteresting reason -- @see
    // design-constraints.md's own account of this fix.
    nodes.Create(4);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    rplHelper.Set("DioIntervalMin", TimeValue(MilliSeconds(256)));
    rplHelper.Set("DioIntervalDoublings", UintegerValue(2));

    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Ptr<Node> rootNode = nodes.Get(0);
    Ptr<Node> altANode = nodes.Get(1);
    Ptr<Node> altBNode = nodes.Get(2);
    Ptr<Node> childNode = nodes.Get(3);

    Ptr<Socket> daoMonitor = Socket::CreateSocket(rootNode, Ipv6RawSocketFactory::GetTypeId());
    daoMonitor->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    daoMonitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    daoMonitor->BindToNetDevice(rootNode->GetObject<Ipv6L3Protocol>()->GetNetDevice(1));
    daoMonitor->SetRecvCallback(
        MakeCallback(&RplParentSwitchRapidBumpCoalescedTestCase::RecordDao, this));

    Simulator::Stop(Seconds(10));
    Simulator::Run();

    Ptr<RplRoutingProtocol> root = rootNode->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> child = childNode->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(child->IsJoined(), true, "The child never joined the DODAG");
    NS_TEST_ASSERT_MSG_EQ(altANode->GetObject<RplRoutingProtocol>()->IsJoined(),
                          true,
                          "altA never joined the DODAG");
    NS_TEST_ASSERT_MSG_EQ(altBNode->GetObject<RplRoutingProtocol>()->IsJoined(),
                          true,
                          "altB never joined the DODAG");

    Ipv6Address rootLinkLocal =
        rootNode->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address childLinkLocal =
        childNode->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    // altA/altB's own real link-local addresses: DeliverRawRplMessage()
    // spoofs the DIOs' claimed Rank below, not their identity, so the
    // resulting preferred-parent switches land on genuine, L2-reachable
    // neighbours that can actually relay the child's own DAO onward.
    Ipv6Address altALinkLocal =
        altANode->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address altBLinkLocal =
        altBNode->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address dodagId = root->GetDodagId();

    auto buildDio = [&dodagId](uint16_t rank) {
        RplDioHeader dio;
        dio.SetInstanceId(RPL_DEFAULT_INSTANCE);
        dio.SetVersionNumber(0);
        dio.SetRank(rank);
        dio.SetMop(RPL_MOP_NON_STORING);
        dio.SetDodagId(dodagId);
        return dio;
    };

    // Warm both alternates up to RPL_FRESHNESS_TARGET first, at a rank far
    // worse than the real root's, so the freshness gate does not exclude
    // either of them from the burst below -- otherwise a "new" candidate
    // heard only once or twice would lose to the real, already-established
    // root regardless of claimed rank (@see RplParentFreshnessTestCase),
    // masking the very switching this test means to force. Delivered
    // straight to childNode's own Receive() (DeliverRawRplMessage(), not
    // SendRawRplMessage()): the child already heard altA/altB's own
    // genuine, unmanipulated DIOs during formation above (both real
    // second-hop relays, @see the node-count comment), so this only
    // overwrites the claimed Rank of an already-known neighbour, not its
    // identity.
    for (uint8_t heard = 0; heard < RPL_FRESHNESS_TARGET; heard++)
    {
        Simulator::Schedule(Seconds(0),
                            &DeliverRawRplMessage<RplDioHeader>,
                            childNode,
                            1,
                            buildDio(5000),
                            static_cast<uint8_t>(RPL_CODE_DIO),
                            altALinkLocal,
                            childLinkLocal);
        Simulator::Schedule(Seconds(0),
                            &DeliverRawRplMessage<RplDioHeader>,
                            childNode,
                            1,
                            buildDio(5000),
                            static_cast<uint8_t>(RPL_CODE_DIO),
                            altBLinkLocal,
                            childLinkLocal);
        Simulator::Stop(MilliSeconds(10));
        Simulator::Run();
    }
    NS_TEST_ASSERT_MSG_EQ(child->GetPreferredParent(),
                          rootLinkLocal,
                          "The warmup's own rank 5000 for both alternates was not actually worse "
                          "than the real root's -- it took over prematurely, invalidating the "
                          "burst's own baseline");

    uint32_t daoCountBeforeSwitches = m_daoCount;

    // 100 forced switches, alternating altA/altB, 20 ms apart (2 s of
    // continuous churn). RankViaParent() computes the resulting rank as the
    // candidate's own claimed rank plus dodag.minHopRankIncrease (RFC 6550
    // section 6.7.6's own default, RPL_MIN_HOPRANKINC = 128 here, unchanged
    // since none of these DIOs carry a DAG Configuration option of their
    // own): with the real root's own rank fixed at RPL_MIN_HOPRANKINC too,
    // root's own offer (128 + 128 = 256) is a competing candidate on every
    // single one of SelectPreferredParent()'s calls during this burst,
    // since root keeps re-advertising on its own Trickle schedule
    // throughout, and so is each alternate's own genuine, unmanipulated
    // rank (also 256, a real single hop via root) whenever its own Trickle
    // timer happens to fire during the burst. A claimed rank has to stay
    // below 128 for its own resulting rank to ever beat both, which leaves
    // only 127 distinct positive integers to spend across the whole burst
    // if each step is to keep strictly outdoing not just those but the
    // previous step's own winning claim too -- 100, comfortably inside that
    // ceiling, is what an earlier version of this test got wrong: claimed
    // ranks of 1000 or more, strictly decreasing only relative to each
    // other, never once beat root's fixed 256, so SelectPreferredParent()
    // never actually switched away from it and this test passed for the
    // wrong reason (@see design-constraints.md's own account of this fix).
    // Pre-fix, each of these switches unconditionally cancelled and
    // re-armed dodag.daoEvent the same way an unfixed DTSN bump did.
    // step's own winning claim too -- 100, comfortably inside that ceiling,
    // is what an earlier version of this test got wrong: claimed ranks of
    // 1000 or more, strictly decreasing only relative to each other, never
    for (uint16_t step = 1; step <= 100; step++)
    {
        Ipv6Address from = (step % 2 == 0) ? altALinkLocal : altBLinkLocal;
        uint16_t rank = static_cast<uint16_t>(101 - step);
        Simulator::Schedule(MilliSeconds(20 * step),
                            &DeliverRawRplMessage<RplDioHeader>,
                            childNode,
                            1,
                            buildDio(rank),
                            static_cast<uint8_t>(RPL_CODE_DIO),
                            from,
                            childLinkLocal);
    }
    // The injection window itself (2 s) plus the up-to-1-s jitter the last
    // coalesced send could still be waiting out when the injection ends,
    // plus the same margin RplDtsnRapidBumpCoalescedTestCase's own burst
    // leaves: unchanged at 4.5 s despite the shorter injection window above,
    // so the "first bump to stop" effective window -- and the provable
    // floor derived from it just below -- stays identical to that test's.
    Simulator::Stop(Seconds(4.5));
    Simulator::Run();

    uint32_t daoCountDuringSwitches = m_daoCount - daoCountBeforeSwitches;
    // Same reasoning and the same provable floor as
    // RplDtsnRapidBumpCoalescedTestCase's own threshold: this burst's
    // effective window and jitter ceiling are identical, so the same
    // floor(4.48 / 1.0) = 4 completed cycles applies to genuinely-fixed
    // code regardless of this run's own actual jitter draws.
    NS_TEST_ASSERT_MSG_GT_OR_EQ(daoCountDuringSwitches,
                               4,
                               "100 rapid forced parent switches produced only "
                                   << daoCountDuringSwitches
                                   << " DAO refreshes -- consistent with the unconditional "
                                      "cancel-and-rearm bug starving most of them");

    daoMonitor->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A join via a DIO that omits the (RFC 6550 section 6.7.6, optional
 *        on every individual DIO) DAG Configuration option still leaves
 *        this node's own Trickle interval at a sane, positive value, not
 *        stuck at zero.
 *
 * DodagMembership::dioIntervalMin had no default member initializer, unlike
 * its sibling fields (ocp, minHopRankIncrease, dioIntervalDoublings,
 * dioRedundancy), so it silently stayed at Time(0) whenever JoinDodag() ran
 * on a DIO without a Configuration option -- a real possibility, since the
 * option is only recommended periodically, not required on every DIO
 * (RFC 6550 section 8.2 lets a node fall back to its own locally configured
 * defaults when nothing has been learned yet, which is exactly what this
 * fix does; the bug was that nothing filled that role at all).
 * RplTrickleTimer::IntervalEvent()'s own doubling (interval + interval) has
 * 0 as a fixed point, so an Imin of 0 never grows past it: every firing
 * reschedules the same zero-delay event forever, an infinite loop that
 * freezes the whole simulator rather than a merely-wrong DIO cadence. This
 * was first found by RplParentSwitchRapidBumpCoalescedTestCase's own
 * warmup, before that test was redesigned to no longer take the code path
 * that reached it; this test exercises the same underlying gap directly and
 * deterministically instead of as a side effect of another scenario's own
 * timing.
 */
class RplJoinWithoutDagConfigurationTestCase : public TestCase
{
  public:
    RplJoinWithoutDagConfigurationTestCase();

  private:
    void DoRun() override;

    /**
     * @brief Count a DIO sent by the child.
     * @param socket the monitoring socket
     */
    void RecordDio(Ptr<Socket> socket);

    uint32_t m_dioCount{0}; //!< DIOs observed from the child
};

RplJoinWithoutDagConfigurationTestCase::RplJoinWithoutDagConfigurationTestCase()
    : TestCase("Joining via a DIO without a DAG Configuration option leaves the Trickle "
              "interval at a sane default, not stuck at zero")
{
}

void
RplJoinWithoutDagConfigurationTestCase::RecordDio(Ptr<Socket> socket)
{
    Ptr<Packet> packet = socket->Recv();
    while (packet)
    {
        Ipv6Header ipv6Header;
        if (packet->RemoveHeader(ipv6Header) != 0)
        {
            Icmpv6Header icmpv6Header;
            if (packet->RemoveHeader(icmpv6Header) != 0 &&
                icmpv6Header.GetType() == ICMPV6_RPL && icmpv6Header.GetCode() == RPL_CODE_DIO)
            {
                m_dioCount++;
            }
        }
        packet = socket->Recv();
    }
}

void
RplJoinWithoutDagConfigurationTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2); // 0 = root (unused past supplying a DODAGID), 1 = child

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    Ipv6Address dodagId("2001:1::1");
    Ptr<Node> rootNode = nodes.Get(0);
    Ptr<Node> childNode = nodes.Get(1);
    Ipv6Address rootLinkLocal =
        rootNode->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address childLinkLocal =
        childNode->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    Ptr<Socket> dioMonitor = Socket::CreateSocket(rootNode, Ipv6RawSocketFactory::GetTypeId());
    dioMonitor->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    dioMonitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    dioMonitor->BindToNetDevice(rootNode->GetObject<Ipv6L3Protocol>()->GetNetDevice(1));
    dioMonitor->SetRecvCallback(
        MakeCallback(&RplJoinWithoutDagConfigurationTestCase::RecordDio, this));

    // Lets DAD/interface-up settle before the injection below, the same as
    // every other test that delivers a fabricated DIO straight to a node
    // that never went through ordinary root-driven formation first (@see
    // RplRankInconsistencyPerInstanceTestCase's own such delivery).
    Simulator::Stop(Seconds(1));
    Simulator::Run();

    // No DagConfiguration option at all: JoinDodag() has to fall back to
    // this node's own locally configured Imin, not the option's absent
    // one, the same way it already does for ocp/minHopRankIncrease/
    // dioIntervalDoublings/dioRedundancy (@see the class's own doc
    // comment).
    RplDioHeader dio;
    dio.SetInstanceId(RPL_DEFAULT_INSTANCE);
    dio.SetVersionNumber(0);
    dio.SetRank(RPL_MIN_HOPRANKINC);
    dio.SetMop(RPL_MOP_NON_STORING);
    dio.SetDodagId(dodagId);
    DeliverRawRplMessage(childNode, 1, dio, static_cast<uint8_t>(RPL_CODE_DIO), rootLinkLocal,
                        childLinkLocal);

    Ptr<RplRoutingProtocol> child = childNode->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(child->IsJoined(),
                          true,
                          "The child never joined the DODAG-Configuration-less DIO");

    // A genuinely-fixed Trickle interval (RPL_DIO_INTERVAL_MIN's own
    // default, 2^12 ms = 4.096 s, times up to 2^RPL_DIO_INTERVAL_DOUBLINGS
    // for Imax) sends at most a small handful of DIOs in 5 simulated
    // seconds. An Imin stuck at 0 does not merely send more of them: its
    // IntervalEvent() reschedules the same zero-delay event forever, an
    // infinite loop that never reaches this Stop() boundary at all -- so
    // this test does not fail with a large observed count if the bug is
    // reintroduced, it hangs, the same unmistakable signal the full-suite
    // load-bearing run for this fix relied on.
    Simulator::Stop(Seconds(5));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_LT_OR_EQ(m_dioCount,
                                5,
                                "The child sent " << m_dioCount << " DIOs in 5 s -- consistent "
                                                   << "with a Trickle interval far below its own "
                                                      "configured Imin");

    dioMonitor->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief A DAG Configuration option's DIOIntervalMin/DIOIntervalDoublings
 *        (RFC 6550 section 6.7.6, each an unconstrained wire byte) do not
 *        crash or hang the simulator when a joining/rejoining DIO carries
 *        an out-of-range value.
 *
 * `JoinDodag()` fed both fields, unclamped, straight into
 * `int64_t(1) << exponent` -- undefined behaviour for an exponent >= 64,
 * and even an in-range-looking exponent of exactly 63 (shifting a 1 into
 * a signed 64-bit type's own sign bit) deterministically produces a
 * negative `Time` on real (two's complement) hardware. Confirmed by this
 * fix's own load-bearing check: reverting the clamp and delivering a DIO
 * with DIOIntervalMin = DIOIntervalDoublings = 63 hung the whole
 * simulator (100% CPU, never returning) rather than cleanly asserting --
 * a single malformed or adversarial DIO's DAG Configuration option is
 * therefore enough to lock up the process, no timing race required,
 * needing a hard kill to recover. (An exponent >= 64, e.g. 100, is
 * genuinely unpredictable rather than reliably bad: on this toolchain
 * the shift amount is masked modulo 64, so 100 behaves as 36 and stays
 * harmless -- 63 is the value that actually exercises the failure.)
 */
class RplDagConfigurationExponentOverflowTestCase : public TestCase
{
  public:
    RplDagConfigurationExponentOverflowTestCase();

  private:
    void DoRun() override;

    /**
     * @brief Count a DIO sent by the child.
     * @param socket the monitoring socket
     */
    void RecordDio(Ptr<Socket> socket);

    uint32_t m_dioCount{0}; //!< DIOs observed from the child
};

RplDagConfigurationExponentOverflowTestCase::RplDagConfigurationExponentOverflowTestCase()
    : TestCase("A DAG Configuration option's out-of-range DIOIntervalMin or DIOIntervalDoublings "
              "does not crash or hang the simulator")
{
}

void
RplDagConfigurationExponentOverflowTestCase::RecordDio(Ptr<Socket> socket)
{
    Ptr<Packet> packet = socket->Recv();
    while (packet)
    {
        Ipv6Header ipv6Header;
        if (packet->RemoveHeader(ipv6Header) != 0)
        {
            Icmpv6Header icmpv6Header;
            if (packet->RemoveHeader(icmpv6Header) != 0 &&
                icmpv6Header.GetType() == ICMPV6_RPL && icmpv6Header.GetCode() == RPL_CODE_DIO)
            {
                m_dioCount++;
            }
        }
        packet = socket->Recv();
    }
}

void
RplDagConfigurationExponentOverflowTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2); // 0 = root (unused past supplying a DODAGID), 1 = child

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    Ipv6Address dodagId("2001:1::1");
    Ptr<Node> rootNode = nodes.Get(0);
    Ptr<Node> childNode = nodes.Get(1);
    Ipv6Address rootLinkLocal =
        rootNode->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address childLinkLocal =
        childNode->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    Ptr<Socket> dioMonitor = Socket::CreateSocket(rootNode, Ipv6RawSocketFactory::GetTypeId());
    dioMonitor->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    dioMonitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    dioMonitor->BindToNetDevice(rootNode->GetObject<Ipv6L3Protocol>()->GetNetDevice(1));
    dioMonitor->SetRecvCallback(
        MakeCallback(&RplDagConfigurationExponentOverflowTestCase::RecordDio, this));

    Simulator::Stop(Seconds(1));
    Simulator::Run();

    // 63, not some larger out-of-range value: shifting a 1 into a signed
    // 64-bit type's own sign bit (exponent 63) deterministically produces
    // INT64_MIN on real (two's complement) hardware, i.e. a negative Time
    // -- an exponent >= 64 is instead genuinely unpredictable (some
    // toolchains mask the shift amount modulo 64, e.g. 100 -> effectively
    // 36, which stays positive and would not exercise the failure this
    // test means to catch at all).
    RplDioHeader dio;
    dio.SetInstanceId(RPL_DEFAULT_INSTANCE);
    dio.SetVersionNumber(0);
    dio.SetRank(RPL_MIN_HOPRANKINC);
    dio.SetMop(RPL_MOP_NON_STORING);
    dio.SetDodagId(dodagId);
    dio.SetDagConfiguration(63,
                            63,
                            RPL_DIO_REDUNDANCY,
                            RPL_MAX_RANKINC,
                            RPL_MIN_HOPRANKINC,
                            RPL_OCP_OF0,
                            RPL_DEFAULT_LIFETIME,
                            RPL_DEFAULT_LIFETIME_UNIT);
    DeliverRawRplMessage(childNode, 1, dio, static_cast<uint8_t>(RPL_CODE_DIO), rootLinkLocal,
                        childLinkLocal);

    Ptr<RplRoutingProtocol> child = childNode->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(child->IsJoined(),
                          true,
                          "The child never joined via the out-of-range DAG Configuration DIO");

    // Reaching this Stop()/Run() at all -- rather than hanging the way the
    // unclamped code genuinely does for this exact input, confirmed above
    // -- is most of what this test checks. The clamp
    // (RPL_DIO_INTERVAL_EXPONENT_MAX = 20) still leaves a very long Imin,
    // so no more than a couple of DIOs are expected in 5 s -- the same
    // style of bound RplJoinWithoutDagConfigurationTestCase uses.
    Simulator::Stop(Seconds(5));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_LT_OR_EQ(m_dioCount,
                                5,
                                "The child sent " << m_dioCount << " DIOs in 5 s after joining "
                                                   << "via an out-of-range DAG Configuration -- "
                                                      "consistent with the clamp not actually "
                                                      "engaging");

    dioMonitor->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check the neighbour freshness rule: a neighbour heard once is a
 *        candidate parent only while nothing better-established is
 *        available, and stops being one as soon as another neighbour has
 *        been heard RPL_FRESHNESS_TARGET times.
 *
 * A radio link that delivered exactly one packet may well be a lucky long
 * shot rather than a usable link, and RFC 6550 leaves how a candidate
 * becomes a parent to the implementation (section 3.2.5, "the details of
 * this process are out of scope"). This mirrors Contiki-NG's link
 * statistics: everything counts until something is established, then only
 * the established ones do -- otherwise a node deep in a DODAG could never
 * bootstrap at all.
 */
class RplParentFreshnessTestCase : public TestCase
{
  public:
    RplParentFreshnessTestCase();

  private:
    void DoRun() override;
};

RplParentFreshnessTestCase::RplParentFreshnessTestCase()
    : TestCase("A neighbour heard once loses to one heard often")
{
}

void
RplParentFreshnessTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(3); // 0 = node under test, 1 = the lucky shot, 2 = the steady one

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }
    rplHelper.AssignStreams(nodes, 1);

    Ptr<RplRoutingProtocol> node = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ipv6Address dodagId("2001:1::1");
    Ipv6Address nodeLinkLocal =
        nodes.Get(0)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address luckyLinkLocal =
        nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address steadyLinkLocal =
        nodes.Get(2)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    auto buildDio = [&dodagId](uint16_t rank) {
        RplDioHeader dio;
        dio.SetInstanceId(RPL_DEFAULT_INSTANCE);
        dio.SetVersionNumber(1);
        dio.SetRank(rank);
        dio.SetMop(RPL_MOP_NON_STORING);
        dio.SetDodagId(dodagId);
        dio.SetDagConfiguration(RPL_DIO_INTERVAL_DOUBLINGS,
                                RPL_DIO_INTERVAL_MIN,
                                RPL_DIO_REDUNDANCY,
                                RPL_MAX_RANKINC,
                                RPL_MIN_HOPRANKINC,
                                RPL_OCP_OF0,
                                RPL_DEFAULT_LIFETIME,
                                RPL_DEFAULT_LIFETIME_UNIT);
        return dio;
    };

    auto send = [&](Ptr<Node> from, Ipv6Address fromAddress, const RplDioHeader& dio) {
        Simulator::Schedule(Seconds(0),
                            &SendRawRplMessage<RplDioHeader>,
                            from,
                            1,
                            dio,
                            static_cast<uint8_t>(RPL_CODE_DIO),
                            fromAddress,
                            nodeLinkLocal);
        Simulator::Stop(MilliSeconds(10));
        Simulator::Run();
    };

    // The lucky shot, heard exactly once, at the best rank there is. With
    // nothing established to compare against, it is taken: a node has to
    // be able to bootstrap on the first DIO it ever hears.
    RplDioHeader luckyDio = buildDio(RPL_MIN_HOPRANKINC);
    send(nodes.Get(1), luckyLinkLocal, luckyDio);

    NS_TEST_ASSERT_MSG_EQ(node->IsJoined(), true, "The first DIO did not bootstrap a DODAG");
    NS_TEST_ASSERT_MSG_EQ(node->GetPreferredParent(),
                          luckyLinkLocal,
                          "The only neighbour there was did not become the parent");
    NS_TEST_ASSERT_MSG_EQ(node->GetRank(), 2 * RPL_MIN_HOPRANKINC, "Wrong rank via the lucky shot");

    // The steady one, at a worse rank, heard up to one short of the
    // freshness target: still not established, so the better rank of the
    // lucky shot keeps winning.
    //
    // Its rank is one MinHopRankIncrease worse than the lucky shot's, which
    // is to say the same as this node's own -- deliberately not two, which
    // is what a child of this node would advertise and which the loop
    // avoidance in SelectPreferredParent() refuses outright, freshness or
    // no freshness. What is under test here is the freshness rule, so the
    // candidate has to be one that rule alone decides.
    RplDioHeader steadyDio = buildDio(2 * RPL_MIN_HOPRANKINC);
    for (uint8_t heard = 1; heard < RPL_FRESHNESS_TARGET; heard++)
    {
        send(nodes.Get(2), steadyLinkLocal, steadyDio);
        NS_TEST_ASSERT_MSG_EQ(node->GetPreferredParent(),
                              luckyLinkLocal,
                              "A neighbour heard " << +heard << " times, still short of the "
                                                   << "freshness target, took over anyway");
    }

    // The one that reaches the target: from here on the lucky shot, heard
    // once, is no longer a candidate, and the established neighbour takes
    // over despite advertising a worse rank.
    send(nodes.Get(2), steadyLinkLocal, steadyDio);

    NS_TEST_ASSERT_MSG_EQ(node->GetPreferredParent(),
                          steadyLinkLocal,
                          "A neighbour heard once kept beating one heard the full "
                          "freshness target of times");
    NS_TEST_ASSERT_MSG_EQ(node->GetRank(),
                          3 * RPL_MIN_HOPRANKINC,
                          "Wrong rank via the established neighbour");
    NS_TEST_ASSERT_MSG_EQ(node->IsJoined(),
                          true,
                          "Switching to the established neighbour dropped the DODAG");

    // And once the lucky shot is heard often enough to be established
    // itself, its better rank counts again.
    for (uint8_t heard = 1; heard < RPL_FRESHNESS_TARGET; heard++)
    {
        send(nodes.Get(1), luckyLinkLocal, luckyDio);
    }

    NS_TEST_ASSERT_MSG_EQ(node->GetPreferredParent(),
                          luckyLinkLocal,
                          "A neighbour that became established was not reconsidered");
    NS_TEST_ASSERT_MSG_EQ(node->GetRank(),
                          2 * RPL_MIN_HOPRANKINC,
                          "Wrong rank after moving back up");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check that the RPL Option (RPI, RFC 6553) survives a serialize and
 *        deserialize round trip, flags included.
 */
class RplPacketInfoHeaderTestCase : public TestCase
{
  public:
    RplPacketInfoHeaderTestCase();

  private:
    void DoRun() override;
};

RplPacketInfoHeaderTestCase::RplPacketInfoHeaderTestCase()
    : TestCase("RPL Option (RPI) header serialization")
{
}

void
RplPacketInfoHeaderTestCase::DoRun()
{
    RplPacketInfoHeader rpi;
    rpi.SetDown(true);
    rpi.SetInstanceId(7);
    rpi.SetSenderRank(384);

    NS_TEST_ASSERT_MSG_EQ(rpi.GetSerializedSize(), 6, "The RPI option is 6 bytes");

    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(rpi);
    NS_TEST_ASSERT_MSG_EQ(packet->GetSize(), 6, "Unexpected packet size");

    RplPacketInfoHeader received;
    NS_TEST_ASSERT_MSG_EQ(packet->RemoveHeader(received), 6, "Unexpected deserialized size");
    NS_TEST_ASSERT_MSG_EQ(received.GetDown(), true, "The 'O' flag did not survive");
    NS_TEST_ASSERT_MSG_EQ(received.GetRankError(), false, "The 'R' flag leaked");
    NS_TEST_ASSERT_MSG_EQ(received.GetForwardingError(), false, "The 'F' flag leaked");
    NS_TEST_ASSERT_MSG_EQ(received.GetInstanceId(), 7, "Wrong RPLInstanceID");
    NS_TEST_ASSERT_MSG_EQ(received.GetSenderRank(), 384, "Wrong SenderRank");
    NS_TEST_ASSERT_MSG_EQ(packet->GetSize(), 0, "The header did not consume the whole packet");

    // All three flags share one byte: check none of them clobbers another.
    RplPacketInfoHeader allFlags;
    allFlags.SetDown(true);
    allFlags.SetRankError(true);
    allFlags.SetForwardingError(true);
    packet = Create<Packet>();
    packet->AddHeader(allFlags);
    packet->RemoveHeader(received);
    NS_TEST_ASSERT_MSG_EQ(received.GetDown(), true, "The 'O' flag was lost among the others");
    NS_TEST_ASSERT_MSG_EQ(received.GetRankError(), true, "The 'R' flag was lost among the others");
    NS_TEST_ASSERT_MSG_EQ(received.GetForwardingError(),
                          true,
                          "The 'F' flag was lost among the others");
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check that the RPL Option carries sub-TLVs through unchanged.
 *
 * RFC 6553 section 3: "The RPL Option Data Length is variable", and "A RPL
 * device MUST skip over any unrecognized sub-TLVs and attempt to process any
 * additional sub-TLVs that may appear after." This implementation defines no
 * sub-TLV of its own, so the whole of that requirement is: read past them,
 * do not eat them, and put them back on the wire byte for byte.
 */
class RplPacketInfoSubTlvTestCase : public TestCase
{
  public:
    RplPacketInfoSubTlvTestCase();

  private:
    void DoRun() override;
};

RplPacketInfoSubTlvTestCase::RplPacketInfoSubTlvTestCase()
    : TestCase("RPL Option sub-TLVs survive parsing and reserialization")
{
}

void
RplPacketInfoSubTlvTestCase::DoRun()
{
    // Option Type, Opt Data Len 8 (the four base octets plus a four-octet
    // sub-TLV), flags, RPLInstanceID, SenderRank, then the sub-TLV.
    const uint8_t raw[10] =
        {RPL_HBH_OPTION_TYPE, 8, RPL_HDR_OPT_DOWN, 7, 0x01, 0x80, 0xde, 0xad, 0xbe, 0xef};
    Ptr<Packet> packet = Create<Packet>(raw, sizeof(raw));

    RplPacketInfoHeader received;
    NS_TEST_ASSERT_MSG_EQ(packet->RemoveHeader(received),
                          10,
                          "A sub-TLV-carrying option did not report its full length");
    NS_TEST_ASSERT_MSG_EQ(received.IsMalformed(), false, "A well-formed option was rejected");
    NS_TEST_ASSERT_MSG_EQ(received.GetDown(), true, "The 'O' flag was lost");
    NS_TEST_ASSERT_MSG_EQ(received.GetInstanceId(), 7, "Wrong RPLInstanceID");
    NS_TEST_ASSERT_MSG_EQ(received.GetSenderRank(), 384, "Wrong SenderRank");
    NS_TEST_ASSERT_MSG_EQ(received.GetSubTlvs().size(), 4, "Wrong number of sub-TLV bytes kept");
    NS_TEST_ASSERT_MSG_EQ(received.GetSerializedSize(),
                          10,
                          "GetSerializedSize() does not account for the sub-TLV");

    // Back onto a packet: the sub-TLV has to come out exactly as it went in.
    Ptr<Packet> rebuilt = Create<Packet>();
    rebuilt->AddHeader(received);
    NS_TEST_ASSERT_MSG_EQ(rebuilt->GetSize(), 10, "The reserialized option changed size");

    uint8_t out[10] = {0};
    rebuilt->CopyData(out, sizeof(out));
    for (uint32_t i = 0; i < sizeof(raw); i++)
    {
        NS_TEST_ASSERT_MSG_EQ(+out[i],
                              +raw[i],
                              "Byte " << i << " of the option changed across a round trip");
    }

    // The plain four-octet option has no sub-TLV at all.
    RplPacketInfoHeader plain;
    plain.SetSenderRank(128);
    NS_TEST_ASSERT_MSG_EQ(plain.GetSubTlvs().size(), 0, "A bare option invented a sub-TLV");
    NS_TEST_ASSERT_MSG_EQ(plain.GetSerializedSize(),
                          RplPacketInfoHeader::RPI_BASE_SIZE,
                          "A bare option is six octets");
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check that an RPL Option whose Opt Data Len cannot be trusted is
 *        rejected rather than acted on.
 *
 * RFC 6553 section 3's Opt Data Len is whatever the sender wrote. Too short
 * for the four mandatory base octets, or longer than the packet actually
 * carries, and there is nothing to parse; either way the value must not be
 * reported back to ns3::Ipv6Extension::ProcessOptions(), which advances its
 * walk of the option list by exactly that much -- and, since
 * Ipv6Option::Process() returns a uint8_t, an Opt Data Len of 254 reports
 * 256, i.e. 0, which advances it not at all.
 */
class RplPacketInfoMalformedTestCase : public TestCase
{
  public:
    RplPacketInfoMalformedTestCase();

  private:
    void DoRun() override;
};

RplPacketInfoMalformedTestCase::RplPacketInfoMalformedTestCase()
    : TestCase("RPL Option with an untrustworthy Opt Data Len")
{
}

void
RplPacketInfoMalformedTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(1);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    ipv6.AssignWithoutAddress(devices);
    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);

    Simulator::Stop(Seconds(2));
    Simulator::Run();

    Ptr<Ipv6OptionDemux> demux = nodes.Get(0)->GetObject<Ipv6OptionDemux>();
    Ptr<Ipv6Option> option = demux->GetOption(RPL_HBH_OPTION_TYPE);
    NS_TEST_ASSERT_MSG_EQ(option != nullptr, true, "RplIpv6OptionRpl was not registered");

    Ipv6Header ipv6Header;
    ipv6Header.SetSource(Ipv6Address("fe80::9"));
    ipv6Header.SetDestination(Ipv6Address("2001:1::ff:fe00:1"));
    ipv6Header.SetHopLimit(64);

    // Six octets are all that is really present in each of these, whatever
    // the length field claims: 0-3 cannot hold the base octets at all, and
    // 5 upwards claims bytes past the end of the packet. 254 is the one
    // that used to report 0 and stall ProcessOptions()' walk outright.
    for (uint8_t declared : {0, 1, 2, 3, 5, 10, 100, 253, 254, 255})
    {
        uint8_t raw[6] = {RPL_HBH_OPTION_TYPE, declared, 0, 0, 0xff, 0xff};
        Ptr<Packet> packet = Create<Packet>(raw, sizeof(raw));

        RplPacketInfoHeader parsed;
        NS_TEST_ASSERT_MSG_EQ(packet->PeekHeader(parsed),
                              2,
                              "Opt Data Len " << +declared
                                              << " was parsed as if the bytes were there");
        NS_TEST_ASSERT_MSG_EQ(parsed.IsMalformed(),
                              true,
                              "Opt Data Len " << +declared << " was not flagged as malformed");

        bool isDropped = false;
        uint8_t processed = option->Process(packet, 0, ipv6Header, isDropped);
        NS_TEST_ASSERT_MSG_EQ(isDropped,
                              true,
                              "Opt Data Len " << +declared << " was not dropped");
        NS_TEST_ASSERT_MSG_EQ(+processed,
                              2,
                              "Opt Data Len " << +declared
                                              << " reported more consumed than was read");
        NS_TEST_ASSERT_MSG_GT(+processed,
                              0,
                              "Opt Data Len " << +declared
                                              << " reported no progress, stalling the option walk");
        NS_TEST_ASSERT_MSG_EQ(packet->GetSize(),
                              sizeof(raw),
                              "Opt Data Len " << +declared << " grew the packet");
    }

    // The other side of the boundary: an Opt Data Len of 4 with the bytes
    // actually present is the ordinary option and must be processed.
    {
        uint8_t raw[6] = {RPL_HBH_OPTION_TYPE, 4, 0, 0, 0x02, 0x00};
        Ptr<Packet> packet = Create<Packet>(raw, sizeof(raw));

        RplPacketInfoHeader parsed;
        NS_TEST_ASSERT_MSG_EQ(packet->PeekHeader(parsed), 6, "A bare option was not parsed");
        NS_TEST_ASSERT_MSG_EQ(parsed.IsMalformed(), false, "A bare option was called malformed");

        bool isDropped = false;
        uint8_t processed = option->Process(packet, 0, ipv6Header, isDropped);
        NS_TEST_ASSERT_MSG_EQ(isDropped, false, "A well-formed option was dropped");
        NS_TEST_ASSERT_MSG_EQ(+processed, 6, "Wrong number of bytes reported consumed");
    }

    // 253 is the longest Opt Data Len ns-3 can report back through
    // Ipv6Option::Process()' eight-bit return value (253 + 2 = 255): with
    // the bytes really there it parses, one octet more and it cannot.
    {
        std::vector<uint8_t> raw(255, 0xa5);
        raw[0] = RPL_HBH_OPTION_TYPE;
        raw[1] = 253;
        raw[2] = 0;
        raw[3] = 0;
        raw[4] = 0x01;
        raw[5] = 0x00;
        Ptr<Packet> packet = Create<Packet>(raw.data(), raw.size());

        RplPacketInfoHeader parsed;
        NS_TEST_ASSERT_MSG_EQ(packet->PeekHeader(parsed),
                              255,
                              "The longest representable option was not parsed");
        NS_TEST_ASSERT_MSG_EQ(parsed.IsMalformed(), false, "It was called malformed");
        NS_TEST_ASSERT_MSG_EQ(parsed.GetSubTlvs().size(), 249, "Wrong sub-TLV length");

        bool isDropped = false;
        uint8_t processed = option->Process(packet, 0, ipv6Header, isDropped);
        NS_TEST_ASSERT_MSG_EQ(isDropped, false, "The longest representable option was dropped");
        NS_TEST_ASSERT_MSG_EQ(+processed, 255, "Wrong number of bytes reported consumed");
    }

    {
        std::vector<uint8_t> raw(256, 0xa5);
        raw[0] = RPL_HBH_OPTION_TYPE;
        raw[1] = 254;
        raw[2] = 0;
        raw[3] = 0;
        raw[4] = 0x01;
        raw[5] = 0x00;
        Ptr<Packet> packet = Create<Packet>(raw.data(), raw.size());

        RplPacketInfoHeader parsed;
        NS_TEST_ASSERT_MSG_EQ(packet->PeekHeader(parsed),
                              2,
                              "An option ns-3 cannot report the length of was parsed anyway");
        NS_TEST_ASSERT_MSG_EQ(parsed.IsMalformed(), true, "It was not flagged as malformed");
    }

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check RplIpv6OptionRpl::Process(): the rank consistency check in
 *        both directions, the once-then-confirmed inconsistency sequence of
 *        RFC 6550 section 11.2, and that processing the same packet twice
 *        only acts on it once.
 */
class RplPacketInfoProcessTestCase : public TestCase
{
  public:
    RplPacketInfoProcessTestCase();

  private:
    void DoRun() override;
};

RplPacketInfoProcessTestCase::RplPacketInfoProcessTestCase()
    : TestCase("RPL Option processing: rank consistency and idempotency")
{
}

void
RplPacketInfoProcessTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(1);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    ipv6.AssignWithoutAddress(devices);

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);

    // The root only settles at a fixed, known rank once its own SLAAC
    // address has cleared DAD (RFC 4862's DadTimeout defaults to 1 s) and
    // HandleDadSuccess() starts the DODAG; RplIpv6OptionRpl is registered
    // earlier, at DoInitialize(), but there is nothing to gain from
    // separating the two waits here.
    Simulator::Stop(Seconds(2));
    Simulator::Run();

    Ptr<Node> node = nodes.Get(0);
    Ptr<RplRoutingProtocol> rpl = node->GetObject<RplRoutingProtocol>();
    uint16_t ownRank = rpl->GetRank();
    NS_TEST_ASSERT_MSG_EQ(ownRank, RPL_MIN_HOPRANKINC, "The root is not at a fixed, known rank");

    Ptr<Ipv6OptionDemux> demux = node->GetObject<Ipv6OptionDemux>();
    Ptr<Ipv6Option> option = demux->GetOption(RPL_HBH_OPTION_TYPE);
    NS_TEST_ASSERT_MSG_EQ(option != nullptr, true, "RplIpv6OptionRpl was not registered");

    Ipv6Header ipv6Header;
    ipv6Header.SetSource(Ipv6Address("fe80::9"));
    ipv6Header.SetDestination(Ipv6Address("2001:1::ff:fe00:1"));
    ipv6Header.SetHopLimit(64);

    // A consistent upward packet: the sender is further from the root (a
    // higher rank) than this node, so this checks out; SenderRank is
    // rewritten to this node's own rank for the next hop to check against.
    {
        RplPacketInfoHeader rpi;
        rpi.SetDown(false);
        rpi.SetSenderRank(ownRank + RPL_MIN_HOPRANKINC);

        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(rpi);

        bool isDropped = false;
        uint8_t processed = option->Process(packet, 0, ipv6Header, isDropped);
        NS_TEST_ASSERT_MSG_EQ(isDropped, false, "A consistent packet was dropped");
        NS_TEST_ASSERT_MSG_EQ(processed, 6, "Wrong number of bytes reported consumed");

        RplPacketInfoHeader received;
        packet->RemoveHeader(received);
        NS_TEST_ASSERT_MSG_EQ(received.GetRankError(),
                              false,
                              "The 'R' flag was set for a consistent packet");
        NS_TEST_ASSERT_MSG_EQ(received.GetSenderRank(),
                              ownRank,
                              "SenderRank was not rewritten to this node's own rank");
    }

    // An inconsistent upward packet: the sender claims to be no further from
    // the root than this node, which moving up should never see. Flagged
    // once, not (yet) treated as a confirmed loop.
    {
        RplPacketInfoHeader rpi;
        rpi.SetDown(false);
        rpi.SetSenderRank(ownRank);

        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(rpi);

        bool isDropped = false;
        option->Process(packet, 0, ipv6Header, isDropped);
        NS_TEST_ASSERT_MSG_EQ(isDropped,
                              false,
                              "The first inconsistency was already treated as confirmed");

        RplPacketInfoHeader received;
        packet->RemoveHeader(received);
        NS_TEST_ASSERT_MSG_EQ(received.GetRankError(),
                              true,
                              "The 'R' flag was not set on the first inconsistency");
    }

    // A packet that arrives with the Rank-Error bit already set -- flagged
    // by an earlier hop, per RFC 6550 section 11.2's "A host or RPL leaf
    // node MUST set the 'R' bit to 0", every packet starts at R=0, so this
    // can only be a hop further back on the same packet's path -- and hits
    // another inconsistency here is section 11.2.2.2's confirmed loop:
    // traced as dropped, even though Ipv6Option::Process() has no way to
    // actually stop the packet here (see design-constraints.md). What
    // decides "confirmed" is the bit carried on the packet, not anything
    // this node remembers between packets, so this is a fresh packet built
    // with the bit already on rather than a second call reusing the one
    // above.
    {
        RplPacketInfoHeader rpi;
        rpi.SetDown(false);
        rpi.SetSenderRank(ownRank);
        rpi.SetRankError(true);

        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(rpi);

        bool isDropped = false;
        option->Process(packet, 0, ipv6Header, isDropped);
        NS_TEST_ASSERT_MSG_EQ(isDropped, true, "A confirmed inconsistency was not traced as dropped");
    }

    // The same check the other way round (RFC 6550 section 11.2): a packet
    // moving down should come from a sender closer to the root, i.e. of
    // lower rank. Both sides of the boundary, plus the boundary itself --
    // an equal rank is an inconsistency in either direction, since a hop
    // has to change the distance to the root one way or the other.
    struct
    {
        bool down;             //!< the 'O' flag under test
        int senderRankOffset;  //!< the sender's rank, relative to this node's
        bool expectRankError;  //!< whether the 'R' flag should come back set
        const char* what;      //!< what the case is, for the failure message
    } directionCases[] = {
        {false, +1, false, "a sender one step further from the root, moving up"},
        {false, 0, true, "a sender of equal rank, moving up"},
        {false, -1, true, "a sender closer to the root, moving up"},
        {true, -1, false, "a sender one step closer to the root, moving down"},
        {true, 0, true, "a sender of equal rank, moving down"},
        {true, +1, true, "a sender further from the root, moving down"},
    };

    for (const auto& testCase : directionCases)
    {
        RplPacketInfoHeader rpi;
        rpi.SetDown(testCase.down);
        rpi.SetSenderRank(
            static_cast<uint16_t>(ownRank + testCase.senderRankOffset * RPL_MIN_HOPRANKINC));

        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(rpi);

        bool isDropped = false;
        option->Process(packet, 0, ipv6Header, isDropped);
        NS_TEST_ASSERT_MSG_EQ(isDropped,
                              false,
                              "A first inconsistency was treated as confirmed for "
                                  << testCase.what);

        RplPacketInfoHeader received;
        packet->RemoveHeader(received);
        NS_TEST_ASSERT_MSG_EQ(received.GetRankError(),
                              testCase.expectRankError,
                              "Wrong 'R' flag for " << testCase.what);
        NS_TEST_ASSERT_MSG_EQ(received.GetDown(),
                              testCase.down,
                              "The 'O' flag was rewritten for " << testCase.what);
        NS_TEST_ASSERT_MSG_EQ(received.GetSenderRank(),
                              ownRank,
                              "SenderRank was not rewritten for " << testCase.what);
    }

    // Ipv6L3Protocol::Receive() walks the Hop-by-Hop chain twice for a
    // locally-destined packet; the second call must be a no-op rather than
    // re-checking the SenderRank this same call already rewrote to this
    // node's own.
    Ptr<Packet> repeated = Create<Packet>();
    {
        RplPacketInfoHeader rpi;
        rpi.SetDown(false);
        rpi.SetSenderRank(ownRank + RPL_MIN_HOPRANKINC);
        repeated->AddHeader(rpi);

        bool isDropped = false;
        option->Process(repeated, 0, ipv6Header, isDropped);
        NS_TEST_ASSERT_MSG_EQ(isDropped, false, "The first call of the pair was dropped");

        uint8_t processedAgain = option->Process(repeated, 0, ipv6Header, isDropped);
        NS_TEST_ASSERT_MSG_EQ(isDropped, false, "The second call of the pair acted on the packet");
        NS_TEST_ASSERT_MSG_EQ(processedAgain,
                              6,
                              "Wrong number of bytes reported consumed on the repeat call");
    }

    // That suppression is keyed on the Uid *and* the time, not the Uid
    // alone: RPL's own forwarding keeps a packet's Uid across every hop
    // (RplIpv6ExtensionSourceRouting::Process() rebuilds it with
    // CreateFragment()), so the same Uid coming back at a later time is a
    // loop -- exactly what the rank check exists to catch -- and must be
    // checked rather than waved through as the second half of a
    // Receive()/LocalDeliver() pair. The packet above already carries this
    // node's own rank, so a genuine recheck finds it inconsistent.
    {
        Simulator::Stop(Seconds(1));
        Simulator::Run();

        bool isDropped = false;
        option->Process(repeated, 0, ipv6Header, isDropped);

        RplPacketInfoHeader received;
        repeated->RemoveHeader(received);
        NS_TEST_ASSERT_MSG_EQ(received.GetRankError(),
                              true,
                              "The same packet arriving later was suppressed as a duplicate "
                              "instead of being checked as the loop it is");
    }

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check that a DAO parent's DTSN wrapping past its maximum still
 *        reads as the increment it is.
 *
 * RFC 6550 section 9.6 rule 2: "If a node hears one of its DAO parents
 * increment its DTSN, the node MUST increment its own DTSN." The DTSN is not
 * one of the three counters section 7.1 names, but it is an 8-bit RPL
 * sequence counter that wraps the same way, and read with a plain `>` the
 * wrap from 255 to 0 is the one increment in every 256 that is missed --
 * along with the DAO refresh rule 1 asks for, throughout the sub-DODAG at
 * once, leaving the root's downward routes to expire.
 *
 * The DIOs come from an address no node on the channel owns, handed straight
 * to the node under test. That is what makes the two steps below the only
 * DTSNs its DAO parent is ever heard with: a real neighbour would keep
 * transmitting its own DTSN in between and overwrite the state under test.
 */
class RplDtsnWrapTestCase : public TestCase
{
  public:
    RplDtsnWrapTestCase();

  private:
    void DoRun() override;

    /**
     * @brief Record a DIO's DTSN, if it came from the node under test.
     * @param socket the monitoring socket
     */
    void RecordDio(Ptr<Socket> socket);

    Ipv6Address m_nodeLinkLocal;   //!< the node under test, to filter DIOs by sender
    std::vector<uint8_t> m_dtsns; //!< DTSN of every DIO the node under test sent
};

RplDtsnWrapTestCase::RplDtsnWrapTestCase()
    : TestCase("A DAO parent's DTSN wrapping past its maximum")
{
}

void
RplDtsnWrapTestCase::RecordDio(Ptr<Socket> socket)
{
    Address sender;
    Ptr<Packet> packet = socket->RecvFrom(sender);
    if (!packet)
    {
        return;
    }
    Ipv6Header ipv6Header;
    packet->RemoveHeader(ipv6Header);
    if (ipv6Header.GetSource() != m_nodeLinkLocal)
    {
        return;
    }
    Icmpv6Header icmpv6Header;
    packet->RemoveHeader(icmpv6Header);
    if (icmpv6Header.GetType() == ICMPV6_RPL && icmpv6Header.GetCode() == RPL_CODE_DIO)
    {
        RplDioHeader dio;
        packet->RemoveHeader(dio);
        m_dtsns.push_back(dio.GetDtsn());
    }
}

void
RplDtsnWrapTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2); // 0 = node under test, 1 = the DIO monitor

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }
    rplHelper.AssignStreams(nodes, 1);

    Ptr<Node> node = nodes.Get(0);
    Ptr<RplRoutingProtocol> rpl = node->GetObject<RplRoutingProtocol>();

    Simulator::Stop(Seconds(2));
    Simulator::Run();

    m_nodeLinkLocal = node->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    // The monitor goes on the other node: a node's own multicast is never
    // delivered back to a socket on that same node, so nothing on the node
    // under test could read the DIOs it sends itself.
    Ptr<Socket> dioMonitor = Socket::CreateSocket(nodes.Get(1), Ipv6RawSocketFactory::GetTypeId());
    dioMonitor->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    dioMonitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    dioMonitor->BindToNetDevice(nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetNetDevice(1));
    dioMonitor->SetRecvCallback(MakeCallback(&RplDtsnWrapTestCase::RecordDio, this));

    // An address on this link that belongs to no node.
    Ipv6Address phantom("fe80::200:ff:fe00:99");
    Ipv6Address dodagId("2001:1::1");

    auto buildDio = [&dodagId](uint8_t dtsn) {
        RplDioHeader dio;
        dio.SetInstanceId(RPL_DEFAULT_INSTANCE);
        dio.SetVersionNumber(0);
        dio.SetRank(RPL_MIN_HOPRANKINC);
        dio.SetMop(RPL_MOP_NON_STORING);
        dio.SetDodagId(dodagId);
        dio.SetDtsn(dtsn);
        // Imin 2^8 ms = 256 ms with two doublings, so the node under test
        // emits DIOs of its own often enough to be read below, and its DAO
        // parent is not dropped as stale (2 * Imax = ~2 s) before then.
        dio.SetDagConfiguration(2,
                                8,
                                RPL_DIO_REDUNDANCY,
                                RPL_MAX_RANKINC,
                                RPL_MIN_HOPRANKINC,
                                RPL_OCP_OF0,
                                RPL_DEFAULT_LIFETIME,
                                RPL_DEFAULT_LIFETIME_UNIT);
        return dio;
    };

    // The first DIO from a neighbour only creates its Parent record; there is
    // no previous DTSN to have incremented past, so this one cannot be read
    // as a bump under any comparison. That is what leaves 255 recorded as the
    // DAO parent's DTSN with the node's own still at 0, and makes the step
    // below the only thing that can move it.
    DeliverRawRplMessage(node,
                         1,
                         buildDio(255),
                         static_cast<uint8_t>(RPL_CODE_DIO),
                         phantom,
                         m_nodeLinkLocal);
    Simulator::Stop(MilliSeconds(10));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(rpl->IsJoined(), true, "The injected DIO did not bootstrap a DODAG");
    NS_TEST_ASSERT_MSG_EQ(rpl->GetPreferredParent(),
                          phantom,
                          "The only neighbour there was did not become the DAO parent");

    // The wrap: RFC 6550 section 7.2 rule 3.1 with A = 255 and B = 0 gives
    // (256 + 0 - 255) = 1, at most SEQUENCE_WINDOW, so 0 is greater than 255.
    DeliverRawRplMessage(node,
                         1,
                         buildDio(0),
                         static_cast<uint8_t>(RPL_CODE_DIO),
                         phantom,
                         m_nodeLinkLocal);

    // Long enough for several of the node's own DIOs at Imin 256 ms, and
    // short of the ~2 s of silence that would have it drop the phantom as
    // stale and leave the DODAG.
    Simulator::Stop(MilliSeconds(1500));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_GT_OR_EQ(m_dtsns.size(), 1, "The node under test never sent a DIO");
    // Widened out of uint8_t, which the test macros would otherwise render as
    // the character of that code point in the failure message.
    NS_TEST_ASSERT_MSG_EQ(static_cast<uint32_t>(m_dtsns.back()),
                          1,
                          "The node did not follow its DAO parent's DTSN across the wrap, so "
                          "neither it nor its sub-DODAG would have refreshed their DAOs");

    dioMonitor->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check the lollipop comparison of RFC 6550 section 7.2 against the
 *        worked examples the RFC states for it.
 *
 * Section 7.2 rule 3 opens with "When comparing two sequence counters, the
 * following rules MUST be applied", so this is not a detail an implementation
 * gets to pick a simpler rule for: a plain integer comparison disagrees with
 * it on exactly the wrap-around cases the lollipop encoding exists to get
 * right.
 */
class RplSequenceCounterTestCase : public TestCase
{
  public:
    RplSequenceCounterTestCase();

  private:
    void DoRun() override;
};

RplSequenceCounterTestCase::RplSequenceCounterTestCase()
    : TestCase("Lollipop sequence counter comparison")
{
}

void
RplSequenceCounterTestCase::DoRun()
{
    // Compared by name rather than by value: RplSequenceOrder is an enum
    // class, which the test macros cannot stream into a failure message, and
    // "LESS, expected GREATER" says more there than "0, expected 2" would.
    auto order = [](uint8_t a, uint8_t b) {
        switch (RplSequenceCompare(a, b))
        {
        case RplSequenceOrder::LESS:
            return std::string("LESS");
        case RplSequenceOrder::EQUAL:
            return std::string("EQUAL");
        case RplSequenceOrder::GREATER:
            return std::string("GREATER");
        case RplSequenceOrder::NOT_COMPARABLE:
            return std::string("NOT_COMPARABLE");
        }
        return std::string("UNKNOWN");
    };

    // The two examples RFC 6550 section 7.2 rule 3.1 spells out itself.
    // "if A is 240, and B is 5, then (256 + 5 - 240) is 21. 21 is greater
    // than SEQUENCE_WINDOW (16); thus, 240 is greater than 5."
    NS_TEST_ASSERT_MSG_EQ(order(240, 5),
                          "GREATER",
                          "240 should be greater than 5 (the RFC's own example)");
    NS_TEST_ASSERT_MSG_EQ(order(5, 240),
                          "LESS",
                          "the comparison should be antisymmetric");

    // "if A is 250 and B is 5, then (256 + 5 - 250) is 11. 11 is less than
    // SEQUENCE_WINDOW (16); thus, 250 is less than 5."
    NS_TEST_ASSERT_MSG_EQ(order(250, 5),
                          "LESS",
                          "250 should be less than 5 (the RFC's own example)");
    NS_TEST_ASSERT_MSG_EQ(order(5, 250),
                          "GREATER",
                          "the comparison should be antisymmetric");

    // Rule 2: "When a sequence counter increment would cause the sequence
    // counter to increment beyond its maximum value, the sequence counter
    // MUST wrap back to zero." A counter in the linear region tops out at
    // 255 and wraps to 0, which the comparison then has to read as an
    // increment, not a 255-step drop.
    NS_TEST_ASSERT_MSG_EQ(order(0, 255),
                          "GREATER",
                          "the wrap from the linear region into the circular one was not "
                          "recognised as an increment");
    NS_TEST_ASSERT_MSG_EQ(order(255, 0),
                          "LESS",
                          "a counter that has not wrapped yet was taken for the newer one");

    NS_TEST_ASSERT_MSG_EQ(RplSequenceNewer(0, 255),
                          true,
                          "RplSequenceNewer() disagrees with RplSequenceCompare() on the wrap");
    NS_TEST_ASSERT_MSG_EQ(RplSequenceNewer(255, 0),
                          false,
                          "RplSequenceNewer() accepted the pre-wrap value as newer");

    // Rule 2 again: a counter that is already in the circular region wraps
    // at 127, not at 255.
    NS_TEST_ASSERT_MSG_EQ(order(0, 127),
                          "GREATER",
                          "the wrap inside the circular region was not recognised");

    // Rule 3.2: inside one region, RFC 1982 ordering applies while the two
    // are within SEQUENCE_WINDOW of each other.
    NS_TEST_ASSERT_MSG_EQ(order(11, 10),
                          "GREATER",
                          "an ordinary increment in the circular region compared wrong");
    NS_TEST_ASSERT_MSG_EQ(order(10, 10),
                          "EQUAL",
                          "a counter did not compare equal to itself");
    NS_TEST_ASSERT_MSG_EQ(order(241, 240),
                          "GREATER",
                          "an ordinary increment in the linear region compared wrong");

    // Rule 3.2.2: "If the absolute magnitude of difference of the two
    // sequence counters is greater than SEQUENCE_WINDOW, then a
    // desynchronization has occurred and the two sequence numbers are not
    // comparable."
    NS_TEST_ASSERT_MSG_EQ(order(100, 10),
                          "NOT_COMPARABLE",
                          "two counters a desynchronisation apart compared anyway");
    NS_TEST_ASSERT_MSG_EQ(order(240, 200),
                          "NOT_COMPARABLE",
                          "two counters a desynchronisation apart compared anyway");

    // Exactly SEQUENCE_WINDOW apart is still comparable: rule 3.2.1 is
    // "less than or equal to SEQUENCE_WINDOW".
    NS_TEST_ASSERT_MSG_EQ(order(26, 10),
                          "GREATER",
                          "a difference of exactly SEQUENCE_WINDOW was called incomparable");

    // Rule 4: a node "should consider the comparison as if it has evaluated
    // in such a way so as to minimize the resulting changes to its own
    // state", i.e. an incomparable counter is not newer.
    NS_TEST_ASSERT_MSG_EQ(RplSequenceNewer(100, 10),
                          false,
                          "an incomparable counter was treated as newer, changing state on "
                          "information that cannot be ordered");
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief RplSequenceIncrement() wraps a lollipop sequence counter at the
 *        boundary RFC 6550 section 7.2 rule 2 actually specifies for
 *        whichever region it is currently in -- 127 for the circular
 *        region, 255 for the linear one -- rather than a plain `uint8_t`
 *        increment's single wrap at 255 for both.
 *
 * Found by an independent /protocol-test-matrix audit (@see
 * design-constraints.md section 57.2 item 6's own sibling finding, and
 * section 58): every Path Sequence increment in this module used a plain
 * `++` before this, which happens to still compare correctly for a single
 * adjacent step at any boundary (@see design-constraints.md section 37.6),
 * but permanently mis-files a value that should have wrapped back into the
 * circular region as a linear-region ("just restarted") one instead --
 * section 7.2 rule 3.1 treats the two regions asymmetrically, so this is
 * not a cosmetic difference.
 */
class RplSequenceIncrementTestCase : public TestCase
{
  public:
    RplSequenceIncrementTestCase();

  private:
    void DoRun() override;
};

RplSequenceIncrementTestCase::RplSequenceIncrementTestCase()
    : TestCase("Lollipop sequence counter increment wraps within its own region")
{
}

void
RplSequenceIncrementTestCase::DoRun()
{
    // An ordinary step, nowhere near either boundary, in each region.
    NS_TEST_ASSERT_MSG_EQ(+RplSequenceIncrement(10), 11, "an ordinary circular-region step");
    NS_TEST_ASSERT_MSG_EQ(+RplSequenceIncrement(200), 201, "an ordinary linear-region step");

    // Rule 2: "When incrementing a sequence counter less than 128, the
    // maximum value is 127" -- the circular region wraps to 0 one step
    // early, at 127, not at 255 the way a plain uint8_t increment would.
    NS_TEST_ASSERT_MSG_EQ(+RplSequenceIncrement(126),
                          127,
                          "the last ordinary step before the circular region's own boundary");
    NS_TEST_ASSERT_MSG_EQ(+RplSequenceIncrement(127),
                          0,
                          "the circular region did not wrap back to 0 at its own boundary (127), "
                          "instead carrying through into the linear region at 128");

    // Rule 2: "When incrementing a sequence counter greater than or equal
    // to 128, the maximum value is 255" -- unaffected by the fix, since a
    // plain increment already wraps 255 back to 0 correctly on its own.
    NS_TEST_ASSERT_MSG_EQ(+RplSequenceIncrement(254), 255, "the last step in the linear region");
    NS_TEST_ASSERT_MSG_EQ(+RplSequenceIncrement(255), 0, "the linear region's own boundary wrap");

    // The consequence the wrong wrap point produces: a node whose Path
    // Sequence has been incrementing normally for a while (starting below
    // 127, long enough to approach it) must still compare as *more
    // circular-region* Path Sequences arrive, not suddenly read as if it
    // had just restarted. Simulates 10 ordinary increments starting at
    // 120 -- correctly wrapping once through 127 -- and confirms the
    // result still lands in the circular region, comparing correctly
    // against a stale value from before the run.
    uint8_t value = 120;
    for (int i = 0; i < 10; i++)
    {
        value = RplSequenceIncrement(value);
    }
    NS_TEST_ASSERT_MSG_EQ(+value,
                          2,
                          "10 increments from 120, wrapping once at 127, should land on 2");
    NS_TEST_ASSERT_MSG_EQ(RplSequenceNewer(value, 120),
                          true,
                          "10 real increments away was not recognised as newer than the "
                          "original value -- had these used a plain ++ instead, the result "
                          "(130) would have permanently misrepresented this node as having "
                          "just restarted (RFC 6550 section 7.2 rule 3.1's own linear-region "
                          "semantics), rather than remaining an ordinary circular-region value");
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check that a DODAG Version Number wrapping past its maximum is read
 *        as the increment it is, and that a genuinely older one is still
 *        rejected.
 *
 * RFC 6550 section 7.1: the DODAGVersionNumber "is monotonically incremented
 * by the root each time the root decides to form a new Version of the DODAG
 * in order to revalidate the integrity and allow a global repair to occur".
 * Section 7.2 rule 2 has that counter wrap back to zero once it passes 255.
 * A plain `>` comparison reads that wrap as a 255-step decrease and rejects
 * the new Version -- and since the root never goes back, every node in the
 * DODAG rejects every DIO from then on: global repair stops working for good,
 * not just for one round.
 *
 * Driven entirely from hand-built DIOs of a DODAG that has no real root on
 * the channel, so that nothing else transmits a Version number to race the
 * one under test.
 */
class RplVersionWrapTestCase : public TestCase
{
  public:
    RplVersionWrapTestCase();

  private:
    void DoRun() override;
};

RplVersionWrapTestCase::RplVersionWrapTestCase()
    : TestCase("A DODAG Version Number wrapping past its maximum")
{
}

void
RplVersionWrapTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2); // 0 = node under test, 1 = the only neighbour it ever hears

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }
    rplHelper.AssignStreams(nodes, 1);

    Ptr<RplRoutingProtocol> node = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ipv6Address dodagId("2001:1::1");
    Ipv6Address nodeLinkLocal =
        nodes.Get(0)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ipv6Address neighbourLinkLocal =
        nodes.Get(1)->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();

    auto buildDio = [&dodagId](uint8_t version, uint16_t rank) {
        RplDioHeader dio;
        dio.SetInstanceId(RPL_DEFAULT_INSTANCE);
        dio.SetVersionNumber(version);
        dio.SetRank(rank);
        dio.SetMop(RPL_MOP_NON_STORING);
        dio.SetDodagId(dodagId);
        dio.SetDagConfiguration(RPL_DIO_INTERVAL_DOUBLINGS,
                                RPL_DIO_INTERVAL_MIN,
                                RPL_DIO_REDUNDANCY,
                                RPL_MAX_RANKINC,
                                RPL_MIN_HOPRANKINC,
                                RPL_OCP_OF0,
                                RPL_DEFAULT_LIFETIME,
                                RPL_DEFAULT_LIFETIME_UNIT);
        return dio;
    };

    auto send = [&](const RplDioHeader& dio) {
        Simulator::Schedule(Seconds(0),
                            &SendRawRplMessage<RplDioHeader>,
                            nodes.Get(1),
                            1,
                            dio,
                            static_cast<uint8_t>(RPL_CODE_DIO),
                            neighbourLinkLocal,
                            nodeLinkLocal);
        Simulator::Stop(MilliSeconds(10));
        Simulator::Run();
    };

    // Join at the top of the linear region, one increment short of the wrap.
    // The rank advertised is what tells the Versions apart below: on
    // migrating, the node drops its parent set and recomputes its own rank
    // from whatever DIO carried it into the new Version.
    send(buildDio(255, RPL_MIN_HOPRANKINC));
    NS_TEST_ASSERT_MSG_EQ(node->IsJoined(), true, "The first DIO did not bootstrap a DODAG");
    NS_TEST_ASSERT_MSG_EQ(node->GetRank(),
                          2 * RPL_MIN_HOPRANKINC,
                          "Wrong rank on joining DODAG Version 255");

    // The wrap. RFC 6550 section 7.2 rule 3.1: with A = 255 and B = 0,
    // (256 + 0 - 255) is 1, which is at most SEQUENCE_WINDOW (16), so 0 is
    // greater than 255 -- a new DODAG Version, and the node has to migrate
    // into it.
    send(buildDio(0, 3 * RPL_MIN_HOPRANKINC));
    NS_TEST_ASSERT_MSG_EQ(node->GetRank(),
                          4 * RPL_MIN_HOPRANKINC,
                          "The node did not migrate into the DODAG Version the counter wrapped "
                          "into, so a global repair after the wrap would never reach it");

    // And the other direction still has to be refused, or the fix would just
    // be "accept anything that differs": with A = 255 and B = 0 again, 255
    // is the lesser of the two, so a DIO still advertising it is stale.
    send(buildDio(255, RPL_MIN_HOPRANKINC));
    NS_TEST_ASSERT_MSG_EQ(node->GetRank(),
                          4 * RPL_MIN_HOPRANKINC,
                          "The node migrated backwards into the DODAG Version it had already "
                          "left");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief RFC 6550 section 7.2 rule 2's circular-region wrap (127 -> 0, not
 *        128) applies to the DODAG Version Number's own increment
 *        (GlobalRepairFire(), RFC 6550 section 3.2.2), the same as Path
 *        Sequence (design-constraints.md section 58) and DTSN. Unlike
 *        RplVersionWrapTestCase above (the receiving/comparison side, the
 *        already-correct linear-region 255 -> 0 wrap), this is the sending
 *        side: does a root that repairs its way up to 127 actually wrap the
 *        value it advertises next back to 0, rather than carrying it on into
 *        the linear region at 128.
 */
class RplGlobalRepairVersionWrapTestCase : public TestCase
{
  public:
    RplGlobalRepairVersionWrapTestCase();

  private:
    void DoRun() override;

    /// @brief Record a DIO's version number, if it came from the root.
    /// @param socket the monitoring socket
    void RecordDio(Ptr<Socket> socket);

    Ipv6Address m_rootLinkLocal;         //!< the root's address, to filter DIOs by sender
    std::vector<uint8_t> m_rootVersions; //!< version of every DIO the root itself sent
};

RplGlobalRepairVersionWrapTestCase::RplGlobalRepairVersionWrapTestCase()
    : TestCase("The DODAG Version Number a root advertises wraps from 127 to 0, not into the "
              "linear region at 128, across repeated global repairs")
{
}

void
RplGlobalRepairVersionWrapTestCase::RecordDio(Ptr<Socket> socket)
{
    Ptr<Packet> packet = socket->Recv();
    while (packet)
    {
        Ipv6Header ipv6Header;
        if (packet->RemoveHeader(ipv6Header) != 0 && ipv6Header.GetSource() == m_rootLinkLocal)
        {
            Icmpv6Header icmpv6Header;
            if (packet->RemoveHeader(icmpv6Header) != 0 &&
                icmpv6Header.GetType() == ICMPV6_RPL && icmpv6Header.GetCode() == RPL_CODE_DIO)
            {
                RplDioHeader dio;
                packet->RemoveHeader(dio);
                m_rootVersions.push_back(dio.GetVersionNumber());
            }
        }
        packet = socket->Recv();
    }
}

void
RplGlobalRepairVersionWrapTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2); // 0 = root, 1 = child

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    rplHelper.Set("DioIntervalMin", TimeValue(MilliSeconds(256)));
    rplHelper.Set("DioIntervalDoublings", UintegerValue(2));
    // Short enough that the whole circular region (128 repairs) fits in a
    // practical test duration; dioTrickle.Reset() on every repair
    // (GlobalRepairFire()'s own doc comment) means no DIO actually escapes
    // until repairs stop resetting it, so this need not be anywhere near
    // DioIntervalMin.
    rplHelper.Set("GlobalRepairInterval", TimeValue(MilliSeconds(10)));
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Ptr<Node> rootNode = nodes.Get(0);
    Ptr<Node> childNode = nodes.Get(1);

    m_rootLinkLocal = rootNode->GetObject<Ipv6L3Protocol>()->GetAddress(1, 0).GetAddress();
    Ptr<Socket> monitor = Socket::CreateSocket(childNode, Ipv6RawSocketFactory::GetTypeId());
    monitor->SetAttribute("Protocol", UintegerValue(Icmpv6L4Protocol::GetStaticProtocolNumber()));
    monitor->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    monitor->SetRecvCallback(MakeCallback(&RplGlobalRepairVersionWrapTestCase::RecordDio, this));

    // Left running free rather than timed to stop at exactly the 128th
    // repair: the first repair does not fire until close to Imax after the
    // DODAG forms (observed ~1 s with the DioIntervalMin/Doublings below,
    // Trickle's own settling time before GlobalRepairFire() was first
    // scheduled), so pinning an absolute time to "the 128th repair" is
    // fragile. 6 s at a 10 ms repair interval is enough for several hundred
    // repairs -- multiple full trips around the circular region -- so
    // instead of checking one specific wrap, every version this DIO
    // monitor records over the whole run is checked below: none may ever
    // reach the linear region (128), and 127 must be followed by 0
    // somewhere, proving an actual wrap happened and was handled instead of
    // the boundary simply never being reached.
    Simulator::Stop(Seconds(6));
    Simulator::Run();

    Ptr<RplRoutingProtocol> child = childNode->GetObject<RplRoutingProtocol>();
    NS_TEST_ASSERT_MSG_EQ(child->IsJoined(), true, "The child never joined the DODAG");

    bool sawLinearRegionValue = false;
    bool sawWrapTo0After127 = false;
    bool have127 = false;
    for (auto version : m_rootVersions)
    {
        if (version >= 128)
        {
            sawLinearRegionValue = true;
        }
        if (version == 127)
        {
            have127 = true;
        }
        else if (version == 0 && have127)
        {
            sawWrapTo0After127 = true;
        }
    }
    NS_TEST_ASSERT_MSG_GT_OR_EQ(m_rootVersions.size(), 1, "The root never sent a DIO of its own");
    NS_TEST_ASSERT_MSG_EQ(sawLinearRegionValue,
                          false,
                          "The DODAG version wrapped past 127 into the linear region (128) "
                          "instead of back to 0");
    NS_TEST_ASSERT_MSG_EQ(sawWrapTo0After127,
                          true,
                          "Never observed the version actually wrap from 127 back to 0 -- the "
                          "boundary was not reached within this run");

    monitor->Close();
    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check that the root orders DAOs for one target by their Path
 *        Sequence, so a stale one -- a No-Path in particular -- cannot undo a
 *        newer one that overtook it.
 *
 * RFC 6550 section 7.1 on the Path Sequence: "An older (lesser) value
 * received from an originating router indicates that the originating router
 * holds stale routing states and the originating router should not be
 * considered anymore as a potential next hop for the target." Section 9.2.1
 * makes the counter advance on exactly the two events that produce the race:
 * "the Path Lifetime is to be updated (e.g., a refresh or a no-Path)" and
 * "the DODAG Parent Address subfield list is to be changed".
 *
 * The race is not hypothetical in this implementation: a node that loses its
 * preferred parent withdraws through that same parent (SendNoPathDao()) and
 * then advertises through the new one, so the two DAOs travel up disjoint
 * paths of unrelated length and can arrive in either order.
 */
class RplStaleDaoTestCase : public TestCase
{
  public:
    RplStaleDaoTestCase();

  private:
    void DoRun() override;
};

RplStaleDaoTestCase::RplStaleDaoTestCase()
    : TestCase("A DAO overtaken by a newer one for the same target")
{
}

void
RplStaleDaoTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(60));
    Simulator::Run();

    Ptr<RplRoutingProtocol> root = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ipv6Address rootAddress = root->GetGlobalAddress();
    Ptr<RplRoutingProtocol> child = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ipv6Address childAddress = child->GetGlobalAddress();
    NS_TEST_ASSERT_MSG_EQ(root->GetTopologySize(), 1, "The root did not learn the child's DAO");

    auto sendDao = [&](Ipv6Address target,
                       Ipv6Address parent,
                       uint8_t pathSequence,
                       uint8_t lifetime) {
        RplDaoHeader dao;
        dao.SetInstanceId(RPL_DEFAULT_INSTANCE);
        dao.SetSequence(pathSequence);
        dao.SetTarget(target);
        dao.SetTransitInformation(parent, pathSequence, lifetime);
        Simulator::Schedule(Seconds(0),
                            &SendRawRplMessage<RplDaoHeader>,
                            nodes.Get(1),
                            1,
                            dao,
                            static_cast<uint8_t>(RPL_CODE_DAO),
                            childAddress,
                            rootAddress);
        Simulator::Stop(MilliSeconds(10));
        Simulator::Run();
    };

    // A target sitting under the real child, so the parent chain the root
    // walks actually reaches it and a route can be computed.
    Ipv6Address target("2001:1::ff:fe00:aa");
    // ...and a parent that leads nowhere, which is what the stale DAOs below
    // claim instead: if one of them is taken, the route computation stops
    // finding a path, which is what makes the difference observable.
    Ipv6Address nowhere("2001:1::ff:fe00:bb");
    std::vector<Ipv6Address> hops;

    sendDao(target, childAddress, 20, RPL_DEFAULT_LIFETIME);
    NS_TEST_ASSERT_MSG_EQ(root->GetTopologySize(), 2, "The first DAO was not recorded");
    NS_TEST_ASSERT_MSG_EQ(root->ComputeSourceRoute(target, hops),
                          true,
                          "A freshly advertised target was not routable");

    // A DAO the network reordered: it left before the one above (lower Path
    // Sequence) but arrived after it. Taking it would move the target under
    // a parent it has already left.
    sendDao(target, nowhere, 19, RPL_DEFAULT_LIFETIME);
    NS_TEST_ASSERT_MSG_EQ(root->ComputeSourceRoute(target, hops),
                          true,
                          "A DAO with an older Path Sequence overwrote the newer entry it was "
                          "overtaken by");

    // The same for a No-Path, which is the case that actually happens here:
    // it is sent through the parent being abandoned, so it travels a
    // different and possibly slower path than the DAO that replaced it.
    // Acting on it drops the target from the topology altogether, leaving it
    // unreachable until its next periodic refresh.
    sendDao(target, nowhere, 19, 0);
    NS_TEST_ASSERT_MSG_EQ(root->GetTopologySize(),
                          2,
                          "A No-Path with an older Path Sequence withdrew a route that had "
                          "already been re-advertised through a different parent");
    NS_TEST_ASSERT_MSG_EQ(root->ComputeSourceRoute(target, hops),
                          true,
                          "A stale No-Path left the target unroutable");

    // A No-Path that really is the newest word on the target still has to
    // take it down, or the ordering check would just be a way to ignore
    // withdrawals.
    sendDao(target, childAddress, 21, 0);
    NS_TEST_ASSERT_MSG_EQ(root->GetTopologySize(),
                          1,
                          "An up-to-date No-Path did not withdraw the route");
    NS_TEST_ASSERT_MSG_EQ(root->ComputeSourceRoute(target, hops),
                          false,
                          "A withdrawn target was still routable");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check that a Path Lifetime of 0xFF means the route never expires.
 *
 * RFC 6550 section 6.7.8 on the Transit Information option's Path Lifetime:
 * "The length of time in Lifetime Units (obtained from the Configuration
 * option) that the prefix is valid for route determination. ... A value of
 * all one bits (0xFF) represents infinity." Read as a plain multiplier
 * instead, 0xFF is the *shortest* lifetime a node can ask for beyond the
 * ordinary range rather than an unlimited one, and the root drops the route
 * 255 lifetime units in.
 */
class RplInfiniteLifetimeDaoTestCase : public TestCase
{
  public:
    RplInfiniteLifetimeDaoTestCase();

  private:
    void DoRun() override;
};

RplInfiniteLifetimeDaoTestCase::RplInfiniteLifetimeDaoTestCase()
    : TestCase("A DAO asking for an infinite path lifetime")
{
}

void
RplInfiniteLifetimeDaoTestCase::DoRun()
{
    NodeContainer nodes;
    nodes.Create(2);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(60));
    Simulator::Run();

    Ptr<RplRoutingProtocol> root = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ipv6Address rootAddress = root->GetGlobalAddress();
    Ptr<RplRoutingProtocol> child = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ipv6Address childAddress = child->GetGlobalAddress();

    Ipv6Address target("2001:1::ff:fe00:aa");
    RplDaoHeader dao;
    dao.SetInstanceId(RPL_DEFAULT_INSTANCE);
    dao.SetSequence(1);
    dao.SetTarget(target);
    dao.SetTransitInformation(childAddress, 1, RPL_INFINITE_LIFETIME);
    Simulator::Schedule(Seconds(0),
                        &SendRawRplMessage<RplDaoHeader>,
                        nodes.Get(1),
                        1,
                        dao,
                        static_cast<uint8_t>(RPL_CODE_DAO),
                        childAddress,
                        rootAddress);
    Simulator::Stop(MilliSeconds(10));
    Simulator::Run();

    std::vector<Ipv6Address> hops;
    NS_TEST_ASSERT_MSG_EQ(root->ComputeSourceRoute(target, hops),
                          true,
                          "A freshly advertised target was not routable");

    // Well past the 255 lifetime units a plain multiplication would have
    // given the entry, and past the point where the periodic purge in
    // RouteOutput() would have had every chance to run.
    Simulator::Stop(Seconds(RPL_INFINITE_LIFETIME * RPL_DEFAULT_LIFETIME_UNIT + 600));
    Simulator::Run();

    NS_TEST_ASSERT_MSG_EQ(root->ComputeSourceRoute(target, hops),
                          true,
                          "A route advertised with the infinite path lifetime expired anyway");

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief Check RplRoutingProtocol::PrintRoutingTableJson(), in particular
 *        that it reports the same keys whatever the node's configuration.
 *
 * The point of the JSON emitter over the human-readable one next to it is
 * that a program can index into its output without first working out which
 * of several shapes it got, so what is worth testing is exactly that: the
 * keys that PrintRoutingTable() omits under OF0, without LQL, or on a node
 * that never joined are present here too, carrying a null.
 */
class RplPrintRoutingTableJsonTestCase : public TestCase
{
  public:
    RplPrintRoutingTableJsonTestCase();

  private:
    void DoRun() override;

    /**
     * @brief Capture one node's JSON snapshot.
     * @param rpl the routing protocol to dump
     * @return the line it wrote, newline stripped
     */
    std::string Dump(Ptr<RplRoutingProtocol> rpl) const;
};

RplPrintRoutingTableJsonTestCase::RplPrintRoutingTableJsonTestCase()
    : TestCase("The JSON form of the routing table")
{
}

std::string
RplPrintRoutingTableJsonTestCase::Dump(Ptr<RplRoutingProtocol> rpl) const
{
    std::ostringstream captured;
    Ptr<OutputStreamWrapper> stream = Create<OutputStreamWrapper>(&captured);
    rpl->PrintRoutingTableJson(stream);
    std::string line = captured.str();
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
    {
        line.pop_back();
    }
    return line;
}

void
RplPrintRoutingTableJsonTestCase::DoRun()
{
    // Every key the emitter is contracted to produce, checked for by name
    // rather than by parsing: a missing one is exactly the failure this
    // guards against, and spotting it does not need a JSON reader.
    const std::vector<std::string> requiredKeys = {"\"node\":",
                                                   "\"time\":",
                                                   "\"role\":",
                                                   "\"joined\":",
                                                   "\"dodagId\":",
                                                   "\"instance\":",
                                                   "\"version\":",
                                                   "\"ocp\":",
                                                   "\"rank\":",
                                                   "\"pathEtx\":",
                                                   "\"preferredParent\":",
                                                   "\"parents\":",
                                                   "\"topology\":",
                                                   "\"p2pRoutes\":"};

    auto checkKeys = [&](const std::string& line, const std::string& what) {
        for (const auto& key : requiredKeys)
        {
            NS_TEST_ASSERT_MSG_EQ(line.find(key) != std::string::npos,
                                  true,
                                  "The snapshot of " << what << " is missing " << key << ": "
                                                     << line);
        }
        NS_TEST_ASSERT_MSG_EQ(line.find('\n'),
                             std::string::npos,
                             "A snapshot of " << what << " spans more than the one line a "
                                              << "line-oriented consumer expects");
    };

    NodeContainer nodes;
    nodes.Create(3);

    Ptr<SimpleChannel> channel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices = simpleNetDevice.Install(nodes, channel);

    RplHelper rplHelper;
    rplHelper.Set("Ocp", UintegerValue(RPL_OCP_MRHOF));
    rplHelper.Set("EnableLql", BooleanValue(true));

    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    Ptr<RplRoutingProtocol> root = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> child = nodes.Get(1)->GetObject<RplRoutingProtocol>();

    // Before anything runs, nothing has joined: the "not joined" shape.
    std::string beforeJoin = Dump(child);
    checkKeys(beforeJoin, "a node that has not joined");
    NS_TEST_ASSERT_MSG_EQ(beforeJoin.find("\"joined\":false") != std::string::npos,
                          true,
                          "A node that has not joined did not say so: " << beforeJoin);
    NS_TEST_ASSERT_MSG_EQ(beforeJoin.find("\"dodagId\":null") != std::string::npos,
                          true,
                          "A node that has not joined reported a DODAGID: " << beforeJoin);
    NS_TEST_ASSERT_MSG_EQ(beforeJoin.find("\"parents\":[]") != std::string::npos,
                          true,
                          "A node that has not joined reported candidate parents: "
                              << beforeJoin);

    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(60));
    Simulator::Run();

    // The root: the only node that reports a topology in non-storing mode.
    std::string rootLine = Dump(root);
    checkKeys(rootLine, "the root");
    NS_TEST_ASSERT_MSG_EQ(rootLine.find("\"role\":\"root\"") != std::string::npos,
                          true,
                          "The root did not report itself as one: " << rootLine);
    NS_TEST_ASSERT_MSG_EQ(rootLine.find("\"ocp\":\"mrhof\"") != std::string::npos,
                          true,
                          "The objective function in use was not reported: " << rootLine);
    NS_TEST_ASSERT_MSG_EQ(rootLine.find("\"target\":") != std::string::npos,
                          true,
                          "The root reported no topology despite holding DAOs: " << rootLine);
    NS_TEST_ASSERT_MSG_EQ(rootLine.find("\"expiresIn\":") != std::string::npos,
                          true,
                          "A topology entry carried no expiry: " << rootLine);

    // A router: a topology of its own would be wrong, candidate parents
    // would not be.
    std::string childLine = Dump(child);
    checkKeys(childLine, "a router");
    NS_TEST_ASSERT_MSG_EQ(childLine.find("\"role\":\"router\"") != std::string::npos,
                          true,
                          "A non-root node reported itself as the root: " << childLine);
    NS_TEST_ASSERT_MSG_EQ(childLine.find("\"topology\":[]") != std::string::npos,
                          true,
                          "A non-root node reported a topology: " << childLine);
    NS_TEST_ASSERT_MSG_EQ(childLine.find("\"address\":") != std::string::npos,
                          true,
                          "A joined router reported no candidate parents: " << childLine);
    // MRHOF and LQL are both on above, so these carry numbers here. The
    // configurations that null them out are checked below.
    NS_TEST_ASSERT_MSG_EQ(childLine.find("\"linkEtx\":null") == std::string::npos,
                          true,
                          "MRHOF is in use, but the link ETX was reported as null: "
                              << childLine);
    NS_TEST_ASSERT_MSG_EQ(childLine.find("\"lql\":null") == std::string::npos,
                          true,
                          "LQL is enabled, but it was reported as null: " << childLine);

    Simulator::Destroy();

    // The same DODAG under OF0 and with LQL off, the configuration whose
    // columns PrintRoutingTable() drops from its output altogether.
    NodeContainer plainNodes;
    plainNodes.Create(2);

    Ptr<SimpleChannel> plainChannel = CreateObject<SimpleChannel>();
    SimpleNetDeviceHelper plainNetDevice;
    NetDeviceContainer plainDevices = plainNetDevice.Install(plainNodes, plainChannel);

    RplHelper plainHelper;
    InternetStackHelper plainInternet;
    plainInternet.SetRoutingHelper(plainHelper);
    plainInternet.Install(plainNodes);

    Ipv6AddressHelper plainIpv6;
    Ipv6InterfaceContainer plainInterfaces = plainIpv6.AssignWithoutAddress(plainDevices);
    for (uint32_t i = 0; i < plainNodes.GetN(); i++)
    {
        plainInterfaces.SetForwarding(i, true);
    }

    plainHelper.SetRoot(plainNodes.Get(0), Ipv6Address("2001:1::"), 64);
    plainHelper.AssignStreams(plainNodes, 1);

    Simulator::Stop(Seconds(60));
    Simulator::Run();

    std::string of0Line = Dump(plainNodes.Get(1)->GetObject<RplRoutingProtocol>());
    checkKeys(of0Line, "a router running OF0 without LQL");
    NS_TEST_ASSERT_MSG_EQ(of0Line.find("\"ocp\":\"of0\"") != std::string::npos,
                          true,
                          "OF0 was not reported as the objective function: " << of0Line);
    NS_TEST_ASSERT_MSG_EQ(of0Line.find("\"pathEtx\":null") != std::string::npos,
                          true,
                          "OF0 derives no path cost, but one was reported anyway: " << of0Line);
    NS_TEST_ASSERT_MSG_EQ(of0Line.find("\"linkEtx\":null") != std::string::npos,
                          true,
                          "The per-parent link ETX was not nulled out under OF0: " << of0Line);
    NS_TEST_ASSERT_MSG_EQ(of0Line.find("\"lql\":null") != std::string::npos,
                          true,
                          "LQL is disabled, but a value was reported for it: " << of0Line);

    Simulator::Destroy();
}

/**
 * @ingroup rpl
 * @ingroup tests
 *
 * @brief The RPL test suite.
 */
class RplTestSuite : public TestSuite
{
  public:
    RplTestSuite();
};

RplTestSuite::RplTestSuite()
    : TestSuite("rpl", Type::UNIT)
{
    AddTestCase(new RplDisHeaderTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplDioHeaderTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplAodvComprMixedAddressVectorTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplDioBoundaryTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplDioUnknownOptionTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplDioTruncatedOptionTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplDioUnknownMetricTypeTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplDioOptionEdgeTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplDioTargetOptionTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplDioMultiArtTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplDaoHeaderTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplDaoMultiTargetHeaderTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplDaoGroupedTargetTransitTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplP2pDroHeaderTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplP2pDroAckHeaderTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplDaoBoundaryTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplSourceRoutingHeaderTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplSourceRoutingCompressionTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplSourceRoutingBoundaryTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplSourceRoutingTruncatedTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplSourceRoutingProcessTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplPrepareOutgoingPacketNonRplInterfaceTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplTrickleTimerTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplDodagFormationTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplStoringModeDownwardRouteTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplStoringModeStaleDaoAndNoPathTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplStoringModeDaoRetryTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplStoringModeDaoRetryContentTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplStoringModeInputValidationTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplStoringModeInfiniteLifetimeRelayedTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplStoringModeAggregatedRefreshTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplStoringModeBogusPrimaryTargetTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplDaoDuplicateTargetDedupedTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplHandleDaoAggregatesSimultaneousChangesTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplStoringModeOrdinarySwitchNoPathTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplStoringModeStaleAfterExpiryTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplStoringModeRootPurgeTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplMultiDodagTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplCreateLocalDodagTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplCreateLocalDodagClearsDFlagTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplMultiDodagVersionIsolationTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplMultiDodagDtsnIsolationTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplMultiDodagPathSequenceIsolationTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplMultiDodagDaoAckIsolationTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplNonBaseDodagRelayTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplLocalDodagRootWithoutSetAsRootTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplRankInconsistencyPerInstanceTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplNonBaseRootDownwardPacketTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplReadRpiInstanceIdRejectsWrongOptionTypeTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplAodvMopAcceptedTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplAodvAddressVectorFollowsParentTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplAodvHopByHopStaleSeqNoRejectedTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplAodvAsymmetricHopByHopRouteFollowsParentTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplAodvRreqFloodTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplAodvMultiArtIntersectionTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplAodvMultiArtTwoTargetsAnsweredTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplAodvMultiArtTargNodeRelaysToFartherTargetTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplAodvMultiArtWorseRankIgnoredTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplAodvMultiArtStopsWhenExhaustedTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplAodvForcedAsymmetricSBitTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplAodvAsymmetricRrepInstanceTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplAodvAsymmetricRrepFloodTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplAodvAsymmetricRouteCompletesTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplAodvAsymmetricHopByHopRouteCompletesTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplAodvRrepCompletesTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplAodvHopByHopRouteCompletesTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplAodvHopByHopRouteDirectNeighbourTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplAodvHopByHopRouteOutlivesRreqInstanceTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplAodvGratuitousRrepTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplAodvGratuitousRrepFreshnessBoundaryTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplAodvGratuitousRrepThenRealRrepTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplRootJoinsForeignRreqInstanceParentLossTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplAodvRrepInstanceRankLimitTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplAodvRrepInstanceAddressVectorFullTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplAodvRrepDuplicateRelayedOnceTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplAodvRoutesInPrintedTablesTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplP2pRoutesInPrintedTablesTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplP2pDiscoverRouteTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplP2pFloodTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplP2pMaxRankTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplP2pTrickleRuleSuppressionTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplP2pDroGeneratedTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplP2pDroRetryTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplP2pMultiTargetTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplP2pMultiTargetRelayTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplP2pSoleTargetViaOptionStopsTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplP2pDroAckWrongSequenceTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplP2pRouteCompletesTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplP2pHopByHopRouteCompletesTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplP2pHopByHopRouteOutlivesTemporaryDagTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplP2pDroRelayTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplP2pHopByHopRouteConflictTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplP2pAddressVectorFullTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplDioRejectionTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplParentLossRejoinTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplInterfaceRestartTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplRootReaddressTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplParentFreshnessTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplDisHandlingTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplDaoAckSequenceTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplDtsnRefreshTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplDtsnOwnIncrementWrapTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplDtsnRapidBumpCoalescedTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplParentSwitchRapidBumpCoalescedTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplJoinWithoutDagConfigurationTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplDagConfigurationExponentOverflowTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplComputeSourceRouteFailureTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplMrhofSelectionTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplMrhofHysteresisBoundaryTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplMrhofLinkMetricBoundaryTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplLqlMappingTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplNoPathDaoTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplNoPathDaoSentOnParentLossTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplNoPathDaoSentOnPoisonTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplPoisonOnDetachTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplPathCostOnDetachTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplDaoAckRetryTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplPacketInfoHeaderTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplPacketInfoSubTlvTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplPacketInfoMalformedTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplPacketInfoProcessTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplSequenceCounterTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplSequenceIncrementTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplVersionWrapTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplGlobalRepairVersionWrapTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplStaleDaoTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplInfiniteLifetimeDaoTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplDtsnWrapTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplPrintRoutingTableJsonTestCase, TestCase::Duration::QUICK);
}

/// Static variable for test initialization.
static RplTestSuite g_rplTestSuite;
