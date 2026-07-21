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
 * multi-hop DODAG. Once the DODAG has converged the last node sends UDP packets
 * to the root, which exercises the upward routes: every hop forwards them to
 * its preferred parent. The traffic only flows that way, because the downward
 * routes of the non-storing mode need the DAOs and the source routing header,
 * which are not implemented yet.
 */

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
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
    int64_t streamNumber = 1;

    CommandLine cmd(__FILE__);
    cmd.AddValue("nNodes", "number of nodes in the line", nNodes);
    cmd.AddValue("nPackets", "number of packets the last node sends to the root", nPackets);
    cmd.AddValue("distance", "spacing between neighbouring nodes, in metres", distance);
    cmd.AddValue("stopTime", "simulation duration, in seconds", stopTime);
    cmd.AddValue("verbose", "turn on RPL logging", verbose);
    cmd.AddValue("pcap", "write pcap traces", pcap);
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

    RplHelper rplHelper;
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
    // so the traffic only starts in the second half of the run.
    uint16_t port = 9;
    UdpServerHelper server(port);
    ApplicationContainer serverApp = server.Install(nodes.Get(0));
    serverApp.Start(Seconds(0));
    serverApp.Stop(Seconds(stopTime));

    UdpClientHelper client(interfaces.GetAddress(0, 1), port);
    client.SetAttribute("MaxPackets", UintegerValue(nPackets));
    client.SetAttribute("Interval", TimeValue(Seconds(2)));
    client.SetAttribute("PacketSize", UintegerValue(32));
    ApplicationContainer clientApp = client.Install(nodes.Get(nNodes - 1));
    clientApp.Start(Seconds(stopTime / 2));
    clientApp.Stop(Seconds(stopTime));

    if (pcap)
    {
        lrWpanHelper.EnablePcapAll("rpl-6lowpan-simple", true);
    }

    Simulator::Schedule(Seconds(stopTime - 1), &PrintDodag, nodes);

    Simulator::Stop(Seconds(stopTime));
    Simulator::Run();

    uint64_t received = DynamicCast<UdpServer>(serverApp.Get(0))->GetReceived();
    std::cout << "Root received " << received << " of the " << nPackets
              << " packets sent by node " << nNodes - 1 << std::endl;

    Simulator::Destroy();

    return 0;
}
