/*
 * Copyright (c) 2026 ns-3 RPL module contributors
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "ns3/boolean.h"
#include "ns3/internet-stack-helper.h"
#include "ns3/ipv6-address-helper.h"
#include "ns3/ipv6-l3-protocol.h"
#include "ns3/ipv6-route.h"
#include "ns3/node-container.h"
#include "ns3/packet.h"
#include "ns3/rpl-header.h"
#include "ns3/rpl-helper.h"
#include "ns3/rpl-routing-protocol.h"
#include "ns3/rpl-trickle-timer.h"
#include "ns3/simple-net-device-helper.h"
#include "ns3/simulator.h"
#include "ns3/test.h"

using namespace ns3;
using namespace ns3::rpl;

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
 * Each hop is its own SimpleNetDevice channel, so a node only ever hears its
 * neighbours and the line cannot collapse into a single hop.
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

    // One channel per hop: node 0 and node 2 are two hops apart.
    SimpleNetDeviceHelper simpleNetDevice;
    NetDeviceContainer devices01 =
        simpleNetDevice.Install(NodeContainer(nodes.Get(0), nodes.Get(1)));
    NetDeviceContainer devices12 =
        simpleNetDevice.Install(NodeContainer(nodes.Get(1), nodes.Get(2)));

    RplHelper rplHelper;
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);

    Ipv6AddressHelper ipv6;
    ipv6.SetBase(Ipv6Address("2001:1::"), Ipv6Prefix(64));
    Ipv6InterfaceContainer interfaces01 = ipv6.Assign(devices01);
    ipv6.SetBase(Ipv6Address("2001:2::"), Ipv6Prefix(64));
    Ipv6InterfaceContainer interfaces12 = ipv6.Assign(devices12);

    interfaces01.SetForwarding(0, true);
    interfaces01.SetForwarding(1, true);
    interfaces12.SetForwarding(0, true);
    interfaces12.SetForwarding(1, true);

    rplHelper.SetRoot(nodes.Get(0));
    rplHelper.AssignStreams(nodes, 1);

    // Imin is 4.096 s and the Trickle interval doubles every time, so the
    // second hop needs a couple of minutes to settle.
    Simulator::Stop(Seconds(200));
    Simulator::Run();

    Ptr<RplRoutingProtocol> root = nodes.Get(0)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> middle = nodes.Get(1)->GetObject<RplRoutingProtocol>();
    Ptr<RplRoutingProtocol> leaf = nodes.Get(2)->GetObject<RplRoutingProtocol>();

    Ipv6Address dodagId = interfaces01.GetAddress(0, 1);

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
                          middleIpv6->GetAddress(2, 0).GetAddress(),
                          "Node 2 did not pick node 1 as its parent");

    // An upward route exists and points at the preferred parent.
    Ipv6Header header;
    header.SetDestination(dodagId);
    Socket::SocketErrno sockerr;
    Ptr<Ipv6Route> route =
        leaf->RouteOutput(Create<Packet>(), header, nullptr, sockerr);
    NS_TEST_ASSERT_MSG_NE(route, nullptr, "Node 2 has no route to the root");
    NS_TEST_ASSERT_MSG_EQ(route->GetGateway(),
                          leaf->GetPreferredParent(),
                          "The route to the root does not go through the preferred parent");

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
    AddTestCase(new RplTrickleTimerTestCase, TestCase::Duration::QUICK);
    AddTestCase(new RplDodagFormationTestCase, TestCase::Duration::QUICK);
}

/// Static variable for test initialization.
static RplTestSuite g_rplTestSuite;
