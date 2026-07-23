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
#include "ns3/test.h"
#include "ns3/uinteger.h"

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

    // Eight bytes of RH3 and one uncompressed address per entry.
    NS_TEST_ASSERT_MSG_EQ(srh.GetSerializedSize(), 8 + 2 * 16, "Unexpected header size");

    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(srh);
    NS_TEST_ASSERT_MSG_EQ(packet->GetSize(), 8 + 2 * 16, "Unexpected packet size");

    RplSourceRoutingHeader received;
    NS_TEST_ASSERT_MSG_EQ(packet->RemoveHeader(received), 8 + 2 * 16, "Unexpected deserialized size");
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
    ipv6.SetBase(Ipv6Address("2001:1::"), Ipv6Prefix(64));
    Ipv6InterfaceContainer interfaces = ipv6.Assign(devices);

    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0));
    rplHelper.AssignStreams(nodes, 1);

    // Imin is 4.096 s and the Trickle interval doubles every time, so the
    // second hop needs a couple of minutes to settle.
    Simulator::Stop(Seconds(200));
    Simulator::Run();

    Ptr<RplRoutingProtocol> root = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> middle = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> leaf = nodes.Get(2)->GetObject<RplRoutingProtocol>();

    Ipv6Address dodagId = interfaces.GetAddress(0, 1);
    Ipv6Address middleAddress = interfaces.GetAddress(1, 1);
    Ipv6Address leafAddress = interfaces.GetAddress(2, 1);

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
    ipv6.SetBase(Ipv6Address("2001:1::"), Ipv6Prefix(64));
    Ipv6InterfaceContainer interfaces = ipv6.Assign(devices);
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
    ipv6.SetBase(Ipv6Address("2001:1::"), Ipv6Prefix(64));
    ipv6.Assign(devices);

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
    {
        RplSourceRoutingHeader srh;
        srh.SetNextHeader(59);
        srh.SetSegmentsLeft(1);
        srh.SetAddresses({Ipv6Address("fe80::4")}); // heard from nobody: no route

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
        NS_TEST_ASSERT_MSG_EQ(processed, 8 + 16, "Wrong number of bytes reported consumed");
    }

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
 * Nothing in this implementation sends a No-Path DAO yet (see
 * doc/design-constraints.md section 10): a node's downward route is only ever
 * dropped by PurgeTopology() once its lifetime runs out. HandleDao() does
 * know what to do with one, though, e.g. from another implementation sharing
 * the DODAG, so this builds one by hand with SendRawRplMessage() and checks
 * that path.
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
    ipv6.SetBase(Ipv6Address("2001:1::"), Ipv6Prefix(64));
    Ipv6InterfaceContainer interfaces = ipv6.Assign(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0));
    rplHelper.AssignStreams(nodes, 1);

    Simulator::Stop(Seconds(60));
    Simulator::Run();

    Ptr<RplRoutingProtocol> root = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ipv6Address childAddress = interfaces.GetAddress(1, 1);
    Ipv6Address rootAddress = interfaces.GetAddress(0, 1);
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
    ipv6.SetBase(Ipv6Address("2001:1::"), Ipv6Prefix(64));
    Ipv6InterfaceContainer interfaces = ipv6.Assign(devices);
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0));
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
    // retries land at 4.71, 5.71 and 6.71 s after the blacklist, and the next
    // periodic DAO at 8.71 s; 5.5 s comfortably separates the two.
    Simulator::Stop(Seconds(5.5));
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
    ipv6.SetBase(Ipv6Address("2001:1::"), Ipv6Prefix(64));
    ipv6.Assign(devices);

    rplHelper.SetRoot(nodes.Get(0));

    // Only needs DoInitialize() to have run, which is what registers
    // RplIpv6OptionRpl and puts the root at a fixed, known rank.
    Simulator::Stop(Seconds(0));
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

    // A second inconsistency right after the first is RFC 6550 section
    // 11.2's confirmed loop: traced as dropped, even though
    // Ipv6Option::Process() has no way to actually stop the packet here (see
    // design-constraints.md).
    {
        RplPacketInfoHeader rpi;
        rpi.SetDown(false);
        rpi.SetSenderRank(ownRank);

        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(rpi);

        bool isDropped = false;
        option->Process(packet, 0, ipv6Header, isDropped);
        NS_TEST_ASSERT_MSG_EQ(isDropped, true, "A confirmed inconsistency was not traced as dropped");
    }

    // Ipv6L3Protocol::Receive() walks the Hop-by-Hop chain twice for a
    // locally-destined packet; the second call must be a no-op rather than
    // re-checking the SenderRank this same call already rewrote to this
    // node's own.
    {
        RplPacketInfoHeader rpi;
        rpi.SetDown(false);
        rpi.SetSenderRank(ownRank + RPL_MIN_HOPRANKINC);

        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(rpi);

        bool isDropped = false;
        option->Process(packet, 0, ipv6Header, isDropped);
        NS_TEST_ASSERT_MSG_EQ(isDropped, false, "The first call of the pair was dropped");

        uint8_t processedAgain = option->Process(packet, 0, ipv6Header, isDropped);
        NS_TEST_ASSERT_MSG_EQ(isDropped, false, "The second call of the pair acted on the packet");
        NS_TEST_ASSERT_MSG_EQ(processedAgain,
                              6,
                              "Wrong number of bytes reported consumed on the repeat call");
    }

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
    AddTestCase(new RplDioUnknownOptionTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplDioUnknownMetricTypeTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplDaoHeaderTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplSourceRoutingHeaderTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplSourceRoutingProcessTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplTrickleTimerTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplDodagFormationTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplMrhofSelectionTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplLqlMappingTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplNoPathDaoTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplDaoAckRetryTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplPacketInfoHeaderTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplPacketInfoProcessTestCase, TestCase::Duration::QUICK);
}

/// Static variable for test initialization.
static RplTestSuite g_rplTestSuite;
