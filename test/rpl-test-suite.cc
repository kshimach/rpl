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

    // Storing mode: not implemented here, so nothing about this DIO may be
    // acted on, not even to join the DODAG it advertises.
    send(buildDio(dodagId, 1, RPL_MIN_HOPRANKINC, RPL_MOP_STORING_NO_MULTICAST));
    NS_TEST_ASSERT_MSG_EQ(node->IsJoined(),
                          false,
                          "A DIO advertising storing mode was joined anyway");

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
                                                   "\"topology\":"};

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
    AddTestCase(new RplDaoHeaderTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplDaoBoundaryTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplSourceRoutingHeaderTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplSourceRoutingCompressionTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplSourceRoutingBoundaryTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplSourceRoutingTruncatedTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplSourceRoutingProcessTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplPrepareOutgoingPacketNonRplInterfaceTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplTrickleTimerTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplDodagFormationTestCase, TestCase::Duration::QUICK);
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
    AddTestCase(new RplAodvRreqFloodTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplAodvForcedAsymmetricSBitTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplAodvAsymmetricRrepInstanceTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplAodvAsymmetricRrepFloodTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplAodvRrepCompletesTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplRootJoinsForeignRreqInstanceParentLossTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplAodvRrepDuplicateRelayedOnceTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplAodvRoutesInPrintedTablesTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplDioRejectionTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplParentLossRejoinTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplInterfaceRestartTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplRootReaddressTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplParentFreshnessTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplDisHandlingTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplDaoAckSequenceTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplDtsnRefreshTestCase, TestCase::Duration::QUICK);
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
    AddTestCase(new RplVersionWrapTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplStaleDaoTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplInfiniteLifetimeDaoTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplDtsnWrapTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplPrintRoutingTableJsonTestCase, TestCase::Duration::QUICK);
}

/// Static variable for test initialization.
static RplTestSuite g_rplTestSuite;
