/*
 * Copyright (c) 2026 kawashy
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/**
 * A line of 802.15.4 nodes running RPL over 6LoWPAN in route-over mode.
 *
 *   n0 (root) ---- n1 ---- n2 ---- ...
 *
 * The nodes are spaced so that only neighbours hear each other, which forces a
 * multi-hop DODAG. No node's global address is assigned by this script: the
 * root owns a GUA/ULA prefix (RplHelper::SetRoot()) and disseminates it over
 * the DODAG via the DIO's Prefix Information option (RFC 6550 section
 * 6.7.10), and every node builds its own address on it through the same
 * SLAAC + Duplicate Address Detection (RFC 4862) machinery a real deployment
 * would use. Once the DODAG has converged and every node has settled an
 * address, the last node pings the root and the root answers, which
 * exercises both directions: the request climbs to the root through the
 * preferred parents, and the reply comes back down the path the root put
 * together out of the DAOs it collected.
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

/**
 * Ping the root from the last node in the line.
 *
 * Scheduled rather than set up ahead of time because the root's address
 * only exists once SLAAC has settled it -- there is nothing to point
 * PingHelper at before the simulation actually runs.
 *
 * @param nodes the nodes running RPL, root first
 * @param nPackets number of echo requests to send
 * @param remainingTime how much longer the simulation has left to run
 */
static void
StartPing(NodeContainer nodes, uint32_t nPackets, double remainingTime)
{
    Ptr<rpl::RplRoutingProtocol> rootRpl = nodes.Get(0)->GetObject<rpl::RplRoutingProtocol>();
    Ipv6Address rootAddress = rootRpl->GetDodagId();
    NS_ABORT_MSG_IF(rootAddress.IsAny(),
                    "The root has not settled its SLAAC address yet; "
                    "give the DODAG more time to converge before pinging");

    PingHelper ping(rootAddress);
    ping.SetAttribute("Count", UintegerValue(nPackets));
    ping.SetAttribute("Interval", TimeValue(Seconds(2)));
    ApplicationContainer pingApp = ping.Install(nodes.Get(nodes.GetN() - 1));
    // Mid-simulation Install(): Application::DoInitialize() schedules the
    // start relative to *now*, so Start(0) means "next event", not "at
    // t=0" the way it would if this ran before Simulator::Run().
    pingApp.Start(Seconds(0));
    pingApp.Stop(Seconds(remainingTime));
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
    bool lql = false;
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
    cmd.AddValue("lql",
                "also derive and advertise a Link Quality Level from RSSI (RFC 6551 "
                "section 4.6)",
                lql);
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
    if (mrhof)
    {
        rplHelper.Set("Ocp", UintegerValue(rpl::RPL_OCP_MRHOF));

        // Without an error model the PHY never touches the LQI it tags every
        // received frame with (it stays pinned at the "perfect" default),
        // which would make MRHOF's ETX indistinguishable from OF0's hop
        // count. One shared LrWpanErrorModel, driven by the SINR the
        // spectrum channel already computes from the distances above, is
        // what gives every hop a real, and different, link quality to
        // measure. Only wired in for --mrhof: RSSI (and so LQL) already
        // varies with distance without it, and leaving the default run
        // (neither flag set) loss-free keeps it a plain reachability demo.
        Ptr<lrwpan::LrWpanErrorModel> errorModel = CreateObject<lrwpan::LrWpanErrorModel>();
        for (auto i = lrwpanDevices.Begin(); i != lrwpanDevices.End(); i++)
        {
            DynamicCast<lrwpan::LrWpanNetDevice>(*i)->GetPhy()->SetErrorModel(errorModel);
        }
    }
    if (lql)
    {
        rplHelper.Set("EnableLql", BooleanValue(true));
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

    // Ipv6AddressHelper::AssignWithoutAddress() still has to run once: it is
    // what actually creates the Ipv6Interface for each SixLowPanNetDevice
    // (Ipv6::AddInterface(), brings it up, wires up traffic control) --
    // SLAAC (below) only ever adds an address to an interface that already
    // exists, it does not create one. No global address comes out of this
    // call, only the interfaces and their link-local addresses.
    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);

    // Every node forwards: in a DODAG the nodes in the middle are routers.
    for (uint32_t i = 0; i < nNodes; i++)
    {
        interfaces.SetForwarding(i, true);
    }

    // Not the 2001:db8::/32 documentation prefix: Ipv6L3Protocol::IpForward()
    // drops anything addressed to it, so a multi-hop route would never work.
    // The root builds its own address on this prefix the same way SLAAC
    // would (RplRoutingProtocol's RootPrefix/RootPrefixLength attributes,
    // set here through the helper) and disseminates it to every other node
    // over the DODAG (RFC 6550 section 6.7.10's Prefix Information option),
    // which is what lets them SLAAC their own addresses on it in turn.
    rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
    streamNumber += rplHelper.AssignStreams(nodes, streamNumber);

    // The DODAG needs a few Trickle intervals to reach the far end of the
    // line, the DAOs another moment to get back to the root, and SLAAC (the
    // DIO's Prefix Information option, once it arrives) a Duplicate Address
    // Detection round on top of that, so the traffic only starts in the
    // second half of the run. A ping needs both directions to work, which is
    // the point of the exercise.
    Simulator::Schedule(Seconds(stopTime / 2), &StartPing, nodes, nPackets, stopTime / 2);

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
