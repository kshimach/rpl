/*
 * Copyright (c) 2026 ns-3 RPL module contributors
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/**
 * A line of 802.15.4 nodes running RPL over 6LoWPAN in route-over mode.
 *
 *   n0 (root) ---- n1 ---- n2 ---- ...
 *
 * The nodes are spaced so that only neighbours hear each other, which forces a
 * multi-hop DODAG. Once the DODAG has converged the last node pings the root
 * and the root answers, which exercises both directions: the request climbs to
 * the root through the preferred parents, and the reply comes back down the
 * path the root put together out of the DAOs it collected.
 */

#include "ns3/core-module.h"
#include "ns3/internet-apps-module.h"
#include "ns3/internet-module.h"
#include "ns3/lr-wpan-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/propagation-module.h"
#include "ns3/rpl-module.h"
#include "ns3/sixlowpan-module.h"
#include "ns3/spectrum-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("RplSixLowPanSimple");

/**
 * Print the DODAG each node ended up in.
 *
 * @param nodes the nodes running RPL
 */
static void
PrintDodag(NodeContainer nodes)
{
    Ptr<OutputStreamWrapper> stream = Create<OutputStreamWrapper>(&std::cout);
    for (auto i = nodes.Begin(); i != nodes.End(); i++)
    {
        Ptr<rpl::RplRoutingProtocol> rpl = (*i)->GetObject<rpl::RplRoutingProtocol>();
        rpl->PrintRoutingTable(stream);
    }
}

int
main(int argc, char** argv)
{
    uint32_t nNodes = 3;
    uint32_t nPackets = 5;
    double distance = 60.0;
    double stopTime = 300.0;
    bool verbose = false;
    bool pcap = false;
    bool mrhof = false;
    int64_t streamNumber = 1;

    CommandLine cmd(__FILE__);
    cmd.AddValue("nNodes", "number of nodes in the line", nNodes);
    cmd.AddValue("nPackets", "number of echo requests the last node sends to the root", nPackets);
    cmd.AddValue("distance", "spacing between neighbouring nodes, in metres", distance);
    cmd.AddValue("stopTime", "simulation duration, in seconds", stopTime);
    cmd.AddValue("verbose", "turn on RPL logging", verbose);
    cmd.AddValue("pcap", "write pcap traces", pcap);
    cmd.AddValue("mrhof",
                "use MRHOF (RFC 6719, ETX) instead of the default OF0 (RFC 6552, hop count)",
                mrhof);
    cmd.Parse(argc, argv);

    if (verbose)
    {
        LogComponentEnable("RplRoutingProtocol",
                           LogLevel(LOG_LEVEL_INFO | LOG_PREFIX_TIME | LOG_PREFIX_NODE));
    }

    NodeContainer nodes;
    nodes.Create(nNodes);

    MobilityHelper mobility;
    Ptr<ListPositionAllocator> positions = CreateObject<ListPositionAllocator>();
    for (uint32_t i = 0; i < nNodes; i++)
    {
        positions->Add(Vector(distance * i, 0.0, 0.0));
    }
    mobility.SetPositionAllocator(positions);
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(nodes);

    LrWpanHelper lrWpanHelper;
    lrWpanHelper.SetPropagationDelayModel("ns3::ConstantSpeedPropagationDelayModel");
    lrWpanHelper.AddPropagationLossModel("ns3::LogDistancePropagationLossModel");
    NetDeviceContainer lrwpanDevices = lrWpanHelper.Install(nodes);
    streamNumber += lrWpanHelper.AssignStreams(lrwpanDevices, streamNumber);
    lrWpanHelper.CreateAssociatedPan(lrwpanDevices, 1);

    // Without an error model the PHY never touches the LQI it tags every
    // received frame with (it stays pinned at the "perfect" default), which
    // would make MRHOF's ETX indistinguishable from OF0's hop count. One
    // shared LrWpanErrorModel, driven by the SINR the spectrum channel
    // already computes from the distances above, is what gives every hop a
    // real, and different, link quality to measure.
    Ptr<lrwpan::LrWpanErrorModel> errorModel = CreateObject<lrwpan::LrWpanErrorModel>();
    for (auto i = lrwpanDevices.Begin(); i != lrwpanDevices.End(); i++)
    {
        DynamicCast<lrwpan::LrWpanNetDevice>(*i)->GetPhy()->SetErrorModel(errorModel);
    }

    RplHelper rplHelper;
    if (mrhof)
    {
        rplHelper.Set("Ocp", UintegerValue(rpl::RPL_OCP_MRHOF));
    }
    InternetStackHelper internetv6;
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(nodes);
    streamNumber += internetv6.AssignStreams(nodes, streamNumber);

    // Route-over: the IPv6 interfaces sit on the 6LoWPAN devices, which is
    // where RPL runs. UseMeshUnder stays false (the default).
    SixLowPanHelper sixlowpan;
    NetDeviceContainer devices = sixlowpan.Install(lrwpanDevices);
    streamNumber += sixlowpan.AssignStreams(devices, streamNumber);

    // Not the 2001:db8::/32 documentation prefix: Ipv6L3Protocol::IpForward()
    // drops anything addressed to it, so a multi-hop route would never work.
    Ipv6AddressHelper ipv6;
    ipv6.SetBase(Ipv6Address("2001:1::"), Ipv6Prefix(64));
    Ipv6InterfaceContainer interfaces = ipv6.Assign(devices);

    // Every node forwards: in a DODAG the nodes in the middle are routers.
    for (uint32_t i = 0; i < nNodes; i++)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(nodes.Get(0));
    streamNumber += rplHelper.AssignStreams(nodes, streamNumber);

    // The DODAG needs a few Trickle intervals to reach the far end of the line,
    // and the DAOs another moment to get back to the root, so the traffic only
    // starts in the second half of the run. A ping needs both directions to
    // work, which is the point of the exercise.
    PingHelper ping(interfaces.GetAddress(0, 1));
    ping.SetAttribute("Count", UintegerValue(nPackets));
    ping.SetAttribute("Interval", TimeValue(Seconds(2)));
    ApplicationContainer pingApp = ping.Install(nodes.Get(nNodes - 1));
    pingApp.Start(Seconds(stopTime / 2));
    pingApp.Stop(Seconds(stopTime));

    if (pcap)
    {
        lrWpanHelper.EnablePcapAll("rpl-6lowpan-simple", true);
    }

    Simulator::Schedule(Seconds(stopTime - 1), &PrintDodag, nodes);

    Simulator::Stop(Seconds(stopTime));
    Simulator::Run();
    Simulator::Destroy();

    return 0;
}
