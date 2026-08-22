/*
 * Copyright (c) 2026 ns-3 RPL module contributors
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/**
 * Evaluation harness modelled on Zhao, Kumar, Chong and Lu, "A comprehensive
 * study of RPL and P2P-RPL routing protocols: Implementation, challenges and
 * opportunities", Peer-to-Peer Netw. Appl. (2016), section 5.
 *
 * The paper evaluates two things over a unit-disk-graph-model (UDGM) lossy
 * channel: (a) DODAG initialization performance as network size grows
 * (section 5.3), and (b) traffic-pattern performance -- MP2P/P2P/P2MP -- as
 * the channel gets lossier (section 5.4). This program reproduces both
 * shapes of experiment against this module's Storing mode Base RPL (RFC
 * 6550 section 9.8), P2P-RPL (RFC 6997) and AODV-RPL (RFC 9854) -- the paper
 * itself only covers the first two, AODV-RPL is this run's own extension of
 * its methodology to a protocol the paper does not discuss.
 *
 * Deliberate departures from the paper's own setup, all one-shot decisions
 * made once here rather than re-litigated per run:
 *
 *  - L2/PHY: the paper uses IEEE 802.11. This program uses ns3::SimpleNetDevice
 *    over a custom UdgmChannel (below) instead, the same stack this module's
 *    own test suite builds every synthetic topology on. That keeps the
 *    experiment on the one L2 this RPL implementation has actually been
 *    exercised against, at the cost of not modelling 802.11's own MAC
 *    contention or link-layer retransmission (Table 4's "Retransmission
 *    limit: 4" has no counterpart here).
 *  - UDGM itself: reproduced directly from the paper's own description
 *    (section 5.1) -- loss probability proportional to the square of the
 *    Euclidean distance between two nodes, zero loss at distance 0, the
 *    configured EdgeSuccessRate at the communication range, and certain loss
 *    beyond it -- rather than by calibrating a physical propagation/error
 *    model to approximate the same curve indirectly.
 *  - Objective function: OF0 (hop count) only. This module's MRHOF
 *    implementation derives its ETX sample from the lr-wpan LQI tag
 *    (RplRoutingProtocol::LinkEtxFromPacket()); SimpleNetDevice carries no
 *    such tag, so MRHOF would silently degenerate to OF0's own ranking on
 *    this L2, making the comparison meaningless here.
 *  - Root position, node count, iteration count and the EdgeSuccessRate grid
 *    are all reduced from the paper's own sweep (10 iterations, 80..240
 *    nodes, 0.1..0.7 in steps of 0.2, corner vs. centre) to a smaller grid
 *    that still shows the same trends inside a practical runtime -- see the
 *    driver script this program is invoked from for the exact grid used.
 *
 * Two run patterns, selected by --pattern:
 *
 *  "init" -- DODAG initialization only (paper section 5.3, Fig. 14).
 *  Reports convergence time, average/maximum rank, and the network-wide RPL
 *  control byte rate observed over the observation window.
 *
 *  "p2p" -- point-to-point traffic (paper section 5.4.2, Fig. 16/17).
 *  --protocol picks how each flow's route is found: "base" leaves it to
 *  ordinary Storing mode (up to a common ancestor, back down); "p2prpl" and
 *  "aodvrpl" call DiscoverP2pRoute()/DiscoverRoute() on the source first.
 *  Reports PDR, average end-to-end delay and average hop count, plus the
 *  RPL control bytes spent between the discovery trigger and the traffic
 *  start. Traffic uses ns3::UdpClient/UdpServer (not FlowMonitor: every
 *  data packet carries an RPI Hop-by-Hop option, RFC 6553, and
 *  Ipv6FlowClassifier::Classify() reads the IPv6 header's own NextHeader
 *  field directly without walking past extension headers, so it would
 *  silently misclassify -- and drop -- every single packet this module
 *  sends). PDR/delay/hop count are instead read off ns3::Ipv6L3Protocol's
 *  own "LocalDeliver" trace at the destination, which fires after
 *  extension-header processing (the NextHeader it reports is already the
 *  real L4 protocol) but before the packet is handed up to the socket: the
 *  UdpClient-stamped SeqTsHeader gives the send timestamp, and the IPv6
 *  header's remaining Hop Limit (subtracted from the default 64) gives the
 *  hop count.
 *
 * Every run appends exactly one CSV row (header written once, on first
 * creation of the file) so a driver script can sweep parameters by
 * repeated invocation.
 */

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/rpl-module.h"

#include <fstream>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("RplPaperEvaluation");

/**
 * @brief The paper's own UDGM loss model (section 5.1), reproduced directly.
 *
 * Within CommRange, the per-packet delivery probability decreases from 1 at
 * distance 0 to EdgeSuccessRate at distance CommRange, quadratically in
 * distance (the paper: "the packet loss probability is proportional to the
 * square of the Euclidean distance between two nodes"). Beyond CommRange,
 * delivery probability is 0.
 *
 * Subclasses ns3::SimpleChannel (rather than ns3::Channel directly) because
 * ns3::SimpleNetDevice::SetChannel() only accepts a Ptr<SimpleChannel>; the
 * device list itself stays in the (private) base class and is walked
 * through the inherited, still-virtual GetNDevices()/GetDevice().
 */
class UdgmChannel : public SimpleChannel
{
  public:
    UdgmChannel()
        : m_rng(CreateObject<UniformRandomVariable>())
    {
    }

    /**
     * @brief Configure the loss model's two parameters.
     * @param rangeMeters CommRange: beyond this, delivery probability is 0
     * @param edgeSuccessRate delivery probability exactly at rangeMeters
     */
    void SetParameters(double rangeMeters, double edgeSuccessRate)
    {
        m_range = rangeMeters;
        m_edgeSuccessRate = edgeSuccessRate;
    }

    void Send(Ptr<Packet> p,
             uint16_t protocol,
             Mac48Address to,
             Mac48Address from,
             Ptr<SimpleNetDevice> sender) override
    {
        for (std::size_t i = 0; i < GetNDevices(); ++i)
        {
            Ptr<SimpleNetDevice> receiver = DynamicCast<SimpleNetDevice>(GetDevice(i));
            if (!receiver || receiver == sender)
            {
                continue;
            }
            Ptr<MobilityModel> txMobility = sender->GetNode()->GetObject<MobilityModel>();
            Ptr<MobilityModel> rxMobility = receiver->GetNode()->GetObject<MobilityModel>();
            double distance = txMobility->GetDistanceFrom(rxMobility);
            if (distance > m_range)
            {
                continue;
            }
            double edgeFraction = (m_range > 0.0) ? (distance / m_range) : 0.0;
            double deliveryProbability = 1.0 - (1.0 - m_edgeSuccessRate) * edgeFraction * edgeFraction;
            if (m_rng->GetValue(0.0, 1.0) > deliveryProbability)
            {
                continue;
            }
            Simulator::ScheduleWithContext(receiver->GetNode()->GetId(),
                                           Seconds(0),
                                           &SimpleNetDevice::Receive,
                                           receiver,
                                           p->Copy(),
                                           protocol,
                                           to,
                                           from);
        }
    }

  private:
    double m_range{35.0};          //!< CommRange, metres
    double m_edgeSuccessRate{0.5}; //!< delivery probability at CommRange
    Ptr<UniformRandomVariable> m_rng;
};

// --- RPL control-traffic byte counter (paper's "routing control overhead") ---
//
// Every RPL control message -- DIS/DIO/DAO/DAO-ACK, and this module's
// P2P-DRO/DRO-ACK and AODV-RPL RREQ/RREP-DIO, which reuse the DIO wire
// format -- is an ICMPv6 packet of type rpl::ICMPV6_RPL (RFC 6550 section
// 6, confirmed against model/rpl-conf.h). Ipv6L3Protocol's Tx trace fires
// once per node per hop (both for locally originated and forwarded
// packets, see Ipv6L3Protocol::SendRealOut()/CallTxTrace()), with the IPv6
// header already reattached -- so summing packet sizes there gives the
// same "total bytes of control messages" the paper measures, at the IP
// layer, network-wide.
static uint64_t g_controlBytes = 0;

static void
OnIpv6Tx(Ptr<const Packet> packet, Ptr<Ipv6> ipv6, uint32_t interface)
{
    Ptr<Packet> copy = packet->Copy();
    Ipv6Header ipHeader;
    copy->RemoveHeader(ipHeader);
    if (ipHeader.GetNextHeader() != Icmpv6L4Protocol::GetStaticProtocolNumber())
    {
        return;
    }
    Icmpv6Header icmpHeader;
    copy->PeekHeader(icmpHeader);
    if (icmpHeader.GetType() != rpl::ICMPV6_RPL)
    {
        return;
    }
    g_controlBytes += packet->GetSize();
}

// --- Data-plane PDR/delay/hop-count, read off Ipv6L3Protocol's LocalDeliver ---
//
// @see the file-level comment for why FlowMonitor is not used instead.
static uint64_t g_rxPackets = 0;
static uint64_t g_sumDelayUs = 0;
static uint64_t g_sumHopCount = 0;
static uint16_t g_trafficPort = 9;
static const uint8_t kDefaultHopLimit = 64; // Ipv6L3Protocol's own "DefaultTtl" default

static void
OnLocalDeliver(const Ipv6Header& header, Ptr<const Packet> packet, uint32_t interface)
{
    if (header.GetNextHeader() != UdpL4Protocol::PROT_NUMBER)
    {
        return;
    }
    Ptr<Packet> copy = packet->Copy();
    UdpHeader udpHeader;
    copy->RemoveHeader(udpHeader);
    if (udpHeader.GetDestinationPort() != g_trafficPort)
    {
        return;
    }
    SeqTsHeader seqTs;
    copy->PeekHeader(seqTs);
    int64_t delayUs = (Simulator::Now() - seqTs.GetTs()).GetMicroSeconds();
    if (delayUs < 0)
    {
        return; // not one of our tagged packets, or a clock oddity: skip rather than pollute the average
    }
    g_rxPackets++;
    g_sumDelayUs += static_cast<uint64_t>(delayUs);
    g_sumHopCount += (kDefaultHopLimit - header.GetHopLimit()) + 1;
}

// --- Convergence tracking: last time any node's joined-state or rank changed ---
static NodeContainer g_nodes;
static double g_lastChangeTime = 0.0;
static std::vector<bool> g_lastJoined;
static std::vector<uint16_t> g_lastRank;

static void
CheckConvergence(double windowEnd)
{
    bool changed = false;
    for (uint32_t i = 0; i < g_nodes.GetN(); ++i)
    {
        Ptr<rpl::RplRoutingProtocol> rpl = g_nodes.Get(i)->GetObject<rpl::RplRoutingProtocol>();
        bool joined = rpl->IsJoined();
        uint16_t rank = rpl->GetRank();
        if (joined != g_lastJoined[i] || rank != g_lastRank[i])
        {
            changed = true;
            g_lastJoined[i] = joined;
            g_lastRank[i] = rank;
        }
    }
    if (changed)
    {
        g_lastChangeTime = Simulator::Now().GetSeconds();
    }
    if (Simulator::Now().GetSeconds() < windowEnd)
    {
        Simulator::Schedule(MilliSeconds(200), &CheckConvergence, windowEnd);
    }
}

/**
 * @brief Trigger a P2P-RPL or AODV-RPL discovery, or do nothing for "base".
 * @param srcIndex index into g_nodes of the flow's source
 * @param destAddr the flow's destination global address
 * @param protocol "base", "p2prpl" or "aodvrpl"
 */
static void
TriggerDiscovery(uint32_t srcIndex, Ipv6Address destAddr, std::string protocol)
{
    Ptr<rpl::RplRoutingProtocol> rpl = g_nodes.Get(srcIndex)->GetObject<rpl::RplRoutingProtocol>();
    if (protocol == "p2prpl")
    {
        rpl->DiscoverP2pRoute(destAddr);
    }
    else if (protocol == "aodvrpl")
    {
        rpl->DiscoverRoute(destAddr);
    }
    // "base": nothing to do, RouteOutput() falls back to the Storing mode
    // route through a common ancestor once traffic starts.
}

int
main(int argc, char** argv)
{
    uint32_t nNodes = 60;
    double areaSide = 300.0;
    std::string rootPlacement = "center";
    double commRange = 35.0;
    double edgeSuccessRate = 0.5;
    std::string pattern = "p2p";
    std::string protocol = "base";
    uint32_t nFlows = 15;
    double trafficDuration = 200.0;
    double settleTime = 80.0;
    double discoveryWait = 30.0;
    double initWindow = 150.0;
    uint32_t dioIntervalMinMs = 50;
    uint32_t dioIntervalDoublings = 7;
    double globalRepairIntervalS = 0.0; // 0 = disabled (RplRoutingProtocol's own default, Time::Max())
    std::string csvPath = "rpl-paper-evaluation.csv";
    bool verbose = false;

    CommandLine cmd(__FILE__);
    cmd.AddValue("nNodes", "number of nodes, root included", nNodes);
    cmd.AddValue("areaSide", "side of the square deployment area, metres", areaSide);
    cmd.AddValue("rootPlacement", "center, corner or random", rootPlacement);
    cmd.AddValue("commRange", "UDGM CommRange, metres", commRange);
    cmd.AddValue("edgeSuccessRate", "UDGM delivery probability at CommRange", edgeSuccessRate);
    cmd.AddValue("pattern", "init (DODAG formation only) or p2p (traffic scenario)", pattern);
    cmd.AddValue("protocol", "base, p2prpl or aodvrpl (pattern=p2p only)", protocol);
    cmd.AddValue("nFlows", "number of concurrent P2P flows (pattern=p2p only)", nFlows);
    cmd.AddValue("trafficDuration", "seconds each flow sends for (pattern=p2p only)", trafficDuration);
    cmd.AddValue("settleTime", "seconds allowed for the base DODAG to converge before anything else", settleTime);
    cmd.AddValue("discoveryWait",
                "seconds allowed for P2P-RPL/AODV-RPL discovery to complete before traffic starts "
                "(pattern=p2p only)",
                discoveryWait);
    cmd.AddValue("initWindow", "observation window for convergence/control overhead (pattern=init only)", initWindow);
    cmd.AddValue("dioIntervalMinMs", "base DODAG's DioIntervalMin, milliseconds", dioIntervalMinMs);
    cmd.AddValue("dioIntervalDoublings", "base DODAG's DioIntervalDoublings", dioIntervalDoublings);
    cmd.AddValue("globalRepairIntervalS",
                "root's GlobalRepairInterval, seconds; 0 (default) leaves it disabled "
                "(design-constraints.md section 37)",
                globalRepairIntervalS);
    cmd.AddValue("csv", "path to append one result row to", csvPath);
    cmd.AddValue("verbose", "turn on RPL logging", verbose);
    cmd.Parse(argc, argv);

    if (verbose)
    {
        LogComponentEnable("RplRoutingProtocol",
                           LogLevel(LOG_LEVEL_INFO | LOG_PREFIX_TIME | LOG_PREFIX_NODE));
    }

    g_nodes.Create(nNodes);

    // --- Positions: root per --rootPlacement, everyone else uniform random ---
    MobilityHelper mobility;
    Ptr<ListPositionAllocator> positions = CreateObject<ListPositionAllocator>();
    if (rootPlacement == "corner")
    {
        positions->Add(Vector(0.0, 0.0, 0.0));
    }
    else if (rootPlacement == "random")
    {
        Ptr<UniformRandomVariable> rx = CreateObject<UniformRandomVariable>();
        Ptr<UniformRandomVariable> ry = CreateObject<UniformRandomVariable>();
        rx->SetAttribute("Max", DoubleValue(areaSide));
        ry->SetAttribute("Max", DoubleValue(areaSide));
        positions->Add(Vector(rx->GetValue(), ry->GetValue(), 0.0));
    }
    else
    {
        positions->Add(Vector(areaSide / 2.0, areaSide / 2.0, 0.0));
    }
    Ptr<UniformRandomVariable> ux = CreateObject<UniformRandomVariable>();
    Ptr<UniformRandomVariable> uy = CreateObject<UniformRandomVariable>();
    ux->SetAttribute("Max", DoubleValue(areaSide));
    uy->SetAttribute("Max", DoubleValue(areaSide));
    for (uint32_t i = 1; i < nNodes; ++i)
    {
        positions->Add(Vector(ux->GetValue(), uy->GetValue(), 0.0));
    }
    mobility.SetPositionAllocator(positions);
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(g_nodes);

    // --- L2: SimpleNetDevice over the UDGM channel above ---
    Ptr<UdgmChannel> channel = CreateObject<UdgmChannel>();
    channel->SetParameters(commRange, edgeSuccessRate);
    NetDeviceContainer devices;
    for (uint32_t i = 0; i < nNodes; ++i)
    {
        Ptr<SimpleNetDevice> dev = CreateObject<SimpleNetDevice>();
        dev->SetAddress(Mac48Address::Allocate());
        g_nodes.Get(i)->AddDevice(dev);
        dev->SetChannel(channel);
        devices.Add(dev);
    }

    // --- L3: RPL Storing mode, OF0 (@see the file-level comment for why) ---
    RplHelper rplHelper;
    rplHelper.Set("Mop", UintegerValue(rpl::RPL_MOP_STORING_NO_MULTICAST));
    rplHelper.Set("DioIntervalMin", TimeValue(MilliSeconds(dioIntervalMinMs)));
    rplHelper.Set("DioIntervalDoublings", UintegerValue(dioIntervalDoublings));
    if (globalRepairIntervalS > 0.0)
    {
        rplHelper.Set("GlobalRepairInterval", TimeValue(Seconds(globalRepairIntervalS)));
    }
    InternetStackHelper internetv6;
    internetv6.SetIpv4StackInstall(false);
    internetv6.SetRoutingHelper(rplHelper);
    internetv6.Install(g_nodes);

    Ipv6AddressHelper ipv6;
    Ipv6InterfaceContainer interfaces = ipv6.AssignWithoutAddress(devices);
    for (uint32_t i = 0; i < nNodes; ++i)
    {
        interfaces.SetForwarding(i, true);
    }

    rplHelper.SetRoot(g_nodes.Get(0), Ipv6Address("2001:1::"), 64);

    // --- Control-overhead instrumentation ---
    Config::ConnectWithoutContext("/NodeList/*/$ns3::Ipv6L3Protocol/Tx", MakeCallback(&OnIpv6Tx));

    // --- Convergence tracking ---
    g_lastJoined.assign(nNodes, false);
    g_lastRank.assign(nNodes, 0);
    double convergenceWindowEnd = (pattern == "init") ? initWindow : settleTime;
    Simulator::Schedule(MilliSeconds(200), &CheckConvergence, convergenceWindowEnd);

    std::vector<std::pair<uint32_t, uint32_t>> flowEndpoints; // (srcIndex, destIndex)
    uint32_t successfulFlows = 0;
    double simDuration = settleTime + 10.0;
    uint32_t packetsPerFlow = static_cast<uint32_t>(trafficDuration); // 1 pkt/s (Table 4)

    if (pattern == "p2p")
    {
        Config::ConnectWithoutContext("/NodeList/*/$ns3::Ipv6L3Protocol/LocalDeliver",
                                      MakeCallback(&OnLocalDeliver));

        // Pick nFlows distinct, non-root (source, destination) pairs.
        Ptr<UniformRandomVariable> pick = CreateObject<UniformRandomVariable>();
        pick->SetAttribute("Min", DoubleValue(1));
        pick->SetAttribute("Max", DoubleValue(nNodes - 1));
        for (uint32_t f = 0; f < nFlows && nNodes > 2; ++f)
        {
            uint32_t src = static_cast<uint32_t>(pick->GetValue());
            uint32_t dst;
            do
            {
                dst = static_cast<uint32_t>(pick->GetValue());
            } while (dst == src);
            flowEndpoints.emplace_back(src, dst);
        }

        ApplicationContainer sinks;
        for (uint32_t i = 1; i < nNodes; ++i)
        {
            UdpServerHelper server(g_trafficPort);
            ApplicationContainer app = server.Install(g_nodes.Get(i));
            app.Start(Seconds(0));
            app.Stop(Seconds(settleTime + discoveryWait + trafficDuration + 5.0));
            sinks.Add(app);
        }

        double discoveryStart = settleTime;
        double trafficStart = settleTime + discoveryWait;
        // The destination's SLAAC address only exists once the sim starts
        // running, so the discovery trigger (which needs that address) and
        // the traffic start are both scheduled from a single deferred setup
        // step instead of computed ahead of time.
        Simulator::Schedule(
            Seconds(discoveryStart),
            [&flowEndpoints, &successfulFlows, protocol, trafficStart, packetsPerFlow]() {
                for (const auto& flow : flowEndpoints)
                {
                    Ptr<rpl::RplRoutingProtocol> destRpl =
                        g_nodes.Get(flow.second)->GetObject<rpl::RplRoutingProtocol>();
                    Ipv6Address destAddr = destRpl->GetGlobalAddress();
                    if (destAddr.IsAny())
                    {
                        continue;
                    }
                    TriggerDiscovery(flow.first, destAddr, protocol);
                    successfulFlows++;

                    UdpClientHelper client(destAddr, g_trafficPort);
                    client.SetAttribute("Interval", TimeValue(Seconds(1)));
                    client.SetAttribute("PacketSize", UintegerValue(512));
                    client.SetAttribute("MaxPackets", UintegerValue(packetsPerFlow));
                    ApplicationContainer app = client.Install(g_nodes.Get(flow.first));
                    double startOffset = trafficStart - Simulator::Now().GetSeconds();
                    app.Start(Seconds(startOffset));
                    app.Stop(Seconds(startOffset + packetsPerFlow + 1));
                }
            });

        simDuration = settleTime + discoveryWait + trafficDuration + 10.0;
    }
    else
    {
        simDuration = initWindow + 10.0;
    }

    uint64_t controlBytesAtDiscoveryStart = 0;
    if (pattern == "p2p")
    {
        Simulator::Schedule(Seconds(settleTime),
                            [&controlBytesAtDiscoveryStart]() {
                                controlBytesAtDiscoveryStart = g_controlBytes;
                            });
    }

    Simulator::Stop(Seconds(simDuration));
    Simulator::Run();

    // --- Gather and emit results ---
    //
    // A node's rank can get stuck at RPL_INFINITE_RANK for a reason
    // unrelated to P2P-RPL/AODV-RPL: RFC 6550 section 8.2.2.4 rule 3 makes
    // a node advertise INFINITE_RANK once its own rank exceeds
    // lowestRankThisVersion + DAGMaxRankIncrease (repeated parent
    // switching climbing it past the ceiling), and recovering from that
    // needs a DODAG Version increment that this implementation's global
    // repair does not reliably deliver at the node counts/link-loss rates
    // used here (design-constraints.md section 37 -- confirmed, by
    // instrumenting this same harness, to reproduce identically whether
    // any P2P-RPL/AODV-RPL discovery ever runs or not). Included as its
    // own explicit fraction rather than silently folded into avgRank/
    // maxRank, which an INFINITE_RANK outlier would otherwise dominate.
    double convergenceTime = g_lastChangeTime;
    uint32_t sumRank = 0;
    uint16_t maxRank = 0;
    uint32_t reachableCount = 0;
    uint32_t infiniteRankCount = 0;
    for (uint32_t i = 0; i < nNodes; ++i)
    {
        uint16_t rank = g_nodes.Get(i)->GetObject<rpl::RplRoutingProtocol>()->GetRank();
        if (rank == rpl::RPL_INFINITE_RANK)
        {
            infiniteRankCount++;
            continue;
        }
        sumRank += rank;
        maxRank = std::max(maxRank, rank);
        reachableCount++;
    }
    double avgRank = (reachableCount > 0) ? (static_cast<double>(sumRank) / reachableCount) : -1.0;
    double infiniteRankFraction = static_cast<double>(infiniteRankCount) / nNodes;
    double controlBytesPerSec = g_controlBytes / initWindow;

    double pdr = -1.0;
    double avgDelayMs = -1.0;
    double avgHopCount = -1.0;
    uint64_t discoveryControlBytes = 0;
    uint64_t txPackets = 0;
    uint64_t rxPackets = 0;

    if (pattern == "p2p")
    {
        txPackets = static_cast<uint64_t>(successfulFlows) * packetsPerFlow;
        rxPackets = g_rxPackets;
        pdr = (txPackets > 0) ? (static_cast<double>(rxPackets) / txPackets) : -1.0;
        avgDelayMs = (rxPackets > 0) ? (g_sumDelayUs / 1000.0 / rxPackets) : -1.0;
        avgHopCount = (rxPackets > 0) ? (static_cast<double>(g_sumHopCount) / rxPackets) : -1.0;
        discoveryControlBytes = g_controlBytes - controlBytesAtDiscoveryStart;
    }

    bool writeHeader = false;
    {
        std::ifstream probe(csvPath);
        writeHeader = !probe.good();
    }
    std::ofstream csv(csvPath, std::ios::app);
    if (writeHeader)
    {
        csv << "pattern,protocol,nNodes,areaSide,rootPlacement,commRange,edgeSuccessRate,nFlows,"
              "rngRun,convergenceTime,avgRank,maxRank,infiniteRankFraction,controlBytesPerSec,pdr,"
              "avgDelayMs,avgHopCount,discoveryControlBytes,txPackets,rxPackets\n";
    }
    csv << pattern << "," << protocol << "," << nNodes << "," << areaSide << "," << rootPlacement
        << "," << commRange << "," << edgeSuccessRate << "," << nFlows << ","
        << RngSeedManager::GetRun() << "," << convergenceTime << "," << avgRank << "," << maxRank
        << "," << infiniteRankFraction << "," << controlBytesPerSec << "," << pdr << ","
        << avgDelayMs << "," << avgHopCount << "," << discoveryControlBytes << "," << txPackets
        << "," << rxPackets << "\n";
    csv.close();

    std::cout << "pattern=" << pattern << " protocol=" << protocol << " nNodes=" << nNodes
              << " edgeSuccessRate=" << edgeSuccessRate << " run=" << RngSeedManager::GetRun()
              << " convergence=" << convergenceTime << "s avgRank=" << avgRank
              << " infiniteRankFraction=" << infiniteRankFraction << " pdr=" << pdr
              << " delay=" << avgDelayMs << "ms hops=" << avgHopCount << std::endl;

    Simulator::Destroy();
    return 0;
}
