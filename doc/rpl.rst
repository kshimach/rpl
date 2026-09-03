RPL: IPv6 Routing Protocol for Low-Power and Lossy Networks
=============================================================

.. heading hierarchy:
   ============= Module Name
   ------------- Section (#.#)
   ~~~~~~~~~~~~~ Subsection (#.#.#)

This chapter describes ``contrib/rpl``, an implementation of RPL (RFC 6550),
the IPv6 Routing Protocol for Low-Power and Lossy Networks, for |ns3|. The
implementation supports both non-storing mode (MOP 1) and storing mode without
multicast (MOP 2):

* DODAG formation and maintenance from DIS/DIO exchanges paced by the Trickle
  algorithm (RFC 6206).
* Rank and path cost computation by either Objective Function Zero (RFC 6552,
  hop count, the compiled-in default) or MRHOF (RFC 6719) over the ETX routing
  metric (RFC 6551), optionally accompanied by a recorded-only Link Quality
  Level (LQL) metric (RFC 6551 section 4.6).
* Non-storing mode (MOP 1) downward routing: destination advertisement through
  DAOs sent to the DODAG root, with the root attaching a real RFC 6554 Type 3
  Source Routing Header (SRH) with optional CmprI/CmprE prefix compression.
* Storing mode (MOP 2) downward routing: hop-by-hop downward routing tables
  populated at every intermediate router, DAO aggregation, No-Path DAOs, route
  purging on expiration, and DAO inconsistency loop recovery with Forwarding-Error
  ('F') bit bouncing (RFC 6550 section 11.2.2.3).
* Strict RFC 6550 section 7.2 lollipop sequence counter arithmetic (comparison
  and increment) across the linear [128..255] and circular [0..127] regions for
  DODAGVersionNumber, DTSN, DAOSequence, and Path Sequence.
* Data-plane rank consistency and loop detection via a real RFC 6553 RPL Option
  (RPI) carried in an IPv6 Hop-by-Hop header.
* Reactive on-demand point-to-point route discovery via P2P-RPL (RFC 6997) and
  AODV-RPL (RFC 9854), supporting both source-routed (H=0) and hop-by-hop (H=1)
  discovered routes.
* Support for multiple concurrent DODAG instances and dynamic local DODAG
  creation.

The protocol is designed to run over 6LoWPAN in route-over mode, i.e. installed
on the IPv6 interfaces that sit on ``SixLowPanNetDevice``, not directly on the
link-layer device underneath. This architecture matches the RPL profile
standardized by Wi-SUN FAN 1.1 (non-storing, MRHOF, ETX).

The source code lives in ``contrib/rpl/``.

Scope and Limitations
----------------------

What the model does:
~~~~~~~~~~~~~~~~~~~~

* **DODAG Formation and Upward Routing**: Solicits DODAG discovery via multicast
  DIS, advertises configuration and rank via Trickle-paced DIOs (RFC 6206),
  computes rank using OF0 (RFC 6552) or MRHOF (RFC 6719), and selects preferred
  parents with a freshness gate against spurious long-range PHY reception.
* **MRHOF and Link Metrics (RFC 6551, RFC 6719)**: Under MRHOF, derives the ETX
  routing metric from lr-wpan's per-frame LQI (EWMA-smoothed), selects preferred
  parents by additive path cost, and prevents parent flapping using RFC 6719's
  hysteresis threshold (``PARENT_SWITCH_THRESHOLD``).
* **Link Quality Level (RFC 6551 section 4.6)**: Optionally derives an LQL value
  from lr-wpan's per-frame RSSI and advertises it in a Metric Container. Per the
  RFC, LQL is recorded-only and does not influence parent selection or rank.
  The RSSI-to-LQL mapping is user-configurable via a callback.
* **Non-Storing Downward Routing (RFC 6550 MOP 1, RFC 6554)**: Nodes send unicast
  DAOs to the root reporting their parent set. The root maintains the complete
  topology map and attaches an RFC 6554 Type 3 Source Routing Header (SRH) to
  downward packets. Supports CmprI and CmprE prefix elision for 64-bit link-local
  addresses. Intermediate routers process the SRH, decrement Segments Left, swap
  destination addresses, and re-inject packets into the forwarding pipeline.
* **Storing Downward Routing (RFC 6550 MOP 2)**: Non-root routers maintain
  downward routing tables (``downwardRoutes``) from DAOs received from child
  nodes. Nodes aggregate DAO advertisements toward their parent, transmit
  No-Path DAOs (lifetime 0) upon parent change or departure, and purge expired
  routes. Implements RFC 6550 section 11.2.2.3 DAO inconsistency detection and
  recovery by bouncing downward packets back up to the parent with the
  Forwarding-Error ('F') bit set.
* **Lollipop Sequence Counter Arithmetic (RFC 6550 section 7.2)**: Implements
  the full lollipop sequence rules (Rules 1-4) for DODAGVersionNumber, DTSN,
  DAOSequence, and Path Sequence, correctly handling transitions between the
  linear [128..255] and circular [0..127] spaces, wrap-around, and desynchronization
  detection within ``SEQUENCE_WINDOW`` (16).
* **Loop Avoidance and Data-Plane Validation (RFC 6550 section 11.2, RFC 6553)**:
  Attaches an RFC 6553 RPL Option (RPI) in a Hop-by-Hop header to originated
  packets. Intermediate routers verify rank consistency against the packet's
  direction ('O' bit). A first inconsistency sets the Rank-Error ('R') bit; a
  second inconsistency confirms the loop, flags the packet for drop, and resets
  the DODAG's Trickle timer.
* **Loop Prevention (RFC 6550 section 8.2.2.4 Rule 3)**: Tracks
  ``lowestRankThisVersion`` to prevent a node from joining parents that would
  increase its rank beyond ``DAGMaxRankIncrease``. Nodes that cannot find an
  acceptable parent poison their route by advertising ``RPL_INFINITE_RANK``.
* **Global Repair**: The root can periodically initiate Global Repair by
  incrementing the ``DODAGVersionNumber`` (governed by ``GlobalRepairInterval``),
  allowing nodes stuck at infinite rank to reform a loop-free DODAG.
* **Reactive Peer-to-Peer Route Discovery (P2P-RPL, RFC 6997)**: Origin nodes
  can initiate on-demand discovery by creating a temporary DAG carrying a
  P2P Route Discovery Option (P2P-RDO) in DIOs. Discovered routes are confirmed
  via P2P Discovery Reply Objects (P2P-DRO) with optional P2P-DRO-ACK
  acknowledgments. Supports both source-routed (H=0) and hop-by-hop (H=1)
  discovered routes, candidate route diversity, and multi-route discovery ('N' field).
* **Reactive Route Discovery (AODV-RPL, RFC 9854)**: Supports reactive route
  discovery using RREQ-DIO, RREP-DIO, and Address Registration Option (ART)
  options. Supports symmetric routes (S=1 via unicast RREP), asymmetric routes
  (S=0 via flooded RREP-Instance), Gratuitous RREP from intermediate caches,
  RankLimit boundaries, and both H=0 and H=1 forwarding modes.
* **Multiple DODAG Instances**: Supports concurrent participation in multiple
  DODAG instances identified by ``(RPLInstanceID, DODAGID)``. Local instances can
  be dynamically established via ``CreateLocalDodag()``.
* **ICMPv6 Handling**: Receives ICMPv6 type 155 RPL control messages using
  dedicated per-interface ``Ipv6RawSocket`` instances bound to
  ``Ipv6Address::GetAny()``, bypassing core limitations without modifying
  ``Icmpv6L4Protocol``.

What it does not do (Limitations):
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* **Storing Mode with Multicast (MOP 3)**: MOP 3 is not implemented. Only
  Non-Storing (MOP 1) and Storing without multicast (MOP 2) are supported.
* **Floating DODAGs**: Floating DODAGs (Grounded flag G=0) are not supported;
  all DODAGs are grounded (G=1).
* **RPL Cryptographic Security**: The cryptographic security modes defined in
  RFC 6550 section 10 (Secure DIS/DIO/DAO) are not implemented. Link-layer
  security (e.g. IEEE 802.15.4 MAC-layer encryption) is assumed.
* **IPv6-in-IPv6 Tunneling**: RFC 6553 and RFC 6554 specify encapsulating
  packets in IPv6-in-IPv6 tunnels when inserting RPL Option or Routing Headers
  on mid-path relays. In this implementation, headers are added directly to the
  packet without tunneling encapsulation.
* **Confirmed Rank Inconsistency Packet Drop**: A confirmed rank inconsistency
  (RFC 6550 section 11.2) traces and flags the drop, resetting the Trickle timer,
  but |ns3|'s ``Ipv6Option::Process()`` API lacks a mechanism to forcibly halt
  packet delivery. See ``contrib/rpl/doc/design-constraints.md`` section 12.3.
* **Other Routing Metrics**: Only ETX and LQL (RFC 6551 sections 4.3 and 4.6)
  are implemented. Node Energy, Hop Count metric object, Link Throughput, Link
  Latency, and Link Color are not supported.

Design
------

RplRoutingProtocol
~~~~~~~~~~~~~~~~~~~

``rpl::RplRoutingProtocol`` implements ``ns3::Ipv6RoutingProtocol``.

* **Routing Output (``RouteOutput()``)**: Resolves outgoing next hops with the
  following priority:
  1. AODV-RPL / P2P-RPL source routes (H=0).
  2. AODV-RPL / P2P-RPL hop-by-hop routes (H=1).
  3. Storing mode downward routes (MOP 2, looking up ``downwardRoutes``).
  4. Non-storing mode downward source routes (MOP 1, root topology map lookup).
  5. Target DODAG's preferred parent (for DAOs addressed to a non-base DODAGID).
  6. Base DODAG's preferred parent (upward default routing).
* **Routing Input (``RouteInput()``)**: Forwards in-transit packets:
  1. Hop-by-hop routes (H=1) for P2P-RPL or AODV-RPL.
  2. Storing mode downward forwarding; if downward route is missing on a downward
     packet, bounces the packet to the preferred parent with Forwarding-Error ('F') set.
  3. Upward forwarding toward the preferred parent of the matching RPL instance.
* **Packet Preparation (``PrepareOutgoingPacket()``)**: Invoked by
  ``Ipv6L3Protocol::Send()`` before frame dispatch. For Non-storing downward
  routes at the root, attaches an ``RplSourceRoutingHeader`` (RFC 6554). For all
  traffic on RPL-enabled interfaces (except single-hop multicast/link-local and
  H=0 reactive routes), attaches an ``RplPacketInfoHeader`` (RFC 6553 RPI) with
  the sender's current rank and direction ('O' bit).

Control Message Headers
~~~~~~~~~~~~~~~~~~~~~~~~

All control messages inherit from ``ns3::Header`` and represent RFC wire formats:

* ``RplDisHeader``: Solicitation base object (RFC 6550 section 6.2).
* ``RplDioHeader``: Information object (section 6.3), carrying optional DAG
  Configuration, Metric Container (ETX / LQL), Prefix Information, Target,
  P2P-RDO (RFC 6997), and AODV-RPL (RFC 9854) options.
* ``RplDaoHeader``: Destination advertisement object (section 6.4), carrying
  Target and Transit Information options.
* ``RplDaoAckHeader``: DAO acknowledgment object (section 6.5).
* ``RplP2pDroHeader`` and ``RplP2pDroAckHeader``: P2P route reply and ACK (RFC 6997).

Source Routing and Address Compression (RFC 6554)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``RplSourceRoutingHeader`` (``rpl-header.h``) implements RFC 6554 Type 3 Routing
Headers. ``RplIpv6ExtensionSourceRouting`` is registered on
``Ipv6ExtensionRoutingDemux``:
* Validates ``SegmentsLeft <= nbAddress`` (sends ICMP Parameter Problem on error).
* Checks for routing loops (detecting if any local address appears more than once
  separated by other nodes).
* Swaps the next hop address into ``DestinationAddress`` and decrements ``HopLimit``.
* Supports prefix compression: ``CmprI`` and ``CmprE`` elide the common 8-byte
  prefix (e.g. ``fe80::/64``) when all listed hops share it with the destination.

RPL Option and Data-Path Validation (RFC 6553)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``RplPacketInfoHeader`` and ``RplIpv6OptionRpl`` implement the RFC 6553 Hop-by-Hop
option (option type ``0x63``).
* Tracks ``(Packet::GetUid(), Simulator::Now())`` to avoid re-processing on
  ``LocalDeliver()`` duplicate invocations.
* Inspects Down ('O') bit:
  * Downward: Sender rank must be strictly less than own rank (towards leaf).
  * Upward: Sender rank must be strictly greater than own rank (towards root).
* Flags rank inconsistency ('R' bit); on a confirmed repeated inconsistency,
  notifies the routing protocol to reset Trickle timers.
* Handles Forwarding-Error ('F') bit bounces in Storing mode, clearing invalid
  downward routes upon receipt.

Reactive Discovery: P2P-RPL and AODV-RPL
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* **P2P-RPL (RFC 6997)**: Discovers direct peer-to-peer routes without passing
  traffic through the root. Origin nodes create a temporary DODAG (MOP 4) and
  flood P2P mode DIOs carrying P2P-RDO. Targets reply with unicast or multicast
  P2P-DRO. Intermediate nodes can maintain candidate routes for path diversity.
* **AODV-RPL (RFC 9854)**: Provides reactive AODV-style discovery on top of RPL.
  Supports symmetric (S=1, unicast RREP) and asymmetric (S=0, flooded RREP-Instance)
  paths. Intermediate routers with valid routes can respond with Gratuitous RREPs (G=1).

Usage
-----

Install RPL as the IPv6 routing protocol using ``RplHelper`` before configuring
the internet stack on nodes:

::

  RplHelper rplHelper;
  // To configure Storing mode instead of Non-Storing:
  // rplHelper.Set("Mop", UintegerValue(RPL_MOP_STORING_NO_MULTICAST));

  InternetStackHelper internetv6;
  internetv6.SetRoutingHelper(rplHelper);
  internetv6.Install(nodes);

  // Configure IPv6 addresses (or let SLAAC configure them)
  rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
  rplHelper.AssignStreams(nodes, 1);

Attributes
~~~~~~~~~~

All attributes are registered on ``ns3::rpl::RplRoutingProtocol``:

General and DODAG Attributes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* ``DisInterval``: Period of unsolicited multicast DIS while unjoined (default: 30s).
* ``DioIntervalMin``: Trickle Imin for DIOs on the root (default: 4.096s, $2^{12}$ ms).
* ``DioIntervalDoublings``: Number of Trickle doublings between Imin and Imax (default: 8).
* ``DioRedundancy``: Trickle redundancy constant k (default: 10; 0 disables suppression).
* ``MinHopRankIncrease``: Minimum rank increase per hop, and rank of root (default: 256).
* ``Ocp``: Objective Code Point advertised by root: ``RPL_OCP_OF0`` (0, default) or
  ``RPL_OCP_MRHOF`` (1).
* ``Mop``: Mode of Operation advertised by root: ``RPL_MOP_NON_STORING`` (1, default)
  or ``RPL_MOP_STORING_NO_MULTICAST`` (2).
* ``EnableLql``: Whether to derive and advertise Link Quality Level from RSSI (default: false).
* ``RootPrefix``: IPv6 prefix advertised by root in Prefix Information Option for SLAAC.
* ``RootPrefixLength``: Prefix length in bits for ``RootPrefix`` (default: 64).
* ``GlobalRepairInterval``: Interval for root to trigger periodic Global Repair via
  DODAGVersionNumber increment (default: disabled / ``Time::Max()``).

DAO Attributes
^^^^^^^^^^^^^^

* ``DaoInterval``: Periodic interval for nodes to repeat DAO advertisements (default: 60s).
* ``DaoAckTimeout``: Timeout waiting for DAO-ACK before retry (default: 5s).
* ``DaoRetries``: Maximum retries for unacknowledged DAOs (default: 3).
* ``PathLifetime``: Lifetime of downward routes in lifetime units (default: 30).

AODV-RPL Attributes (RFC 9854)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* ``AodvDioIntervalMin``: Trickle Imin for RREQ-DIOs (default: 128ms).
* ``AodvDioIntervalDoublings``: Trickle doublings for RREQ-DIOs (default: 4).
* ``AodvRankLimit``: Maximum DAGRank allowed to join RREQ discovery; 0 for unlimited (default: 8).
* ``AodvLifetime``: RREQ-Instance lifetime: 0 (unlimited), 1 (16s, default), 2 (64s), 3 (256s).
* ``AodvRejoinReenable``: Time to refuse rejoining an expired RREQ-Instance (default: 15 min).
* ``AodvForceAsymmetric``: Clear 'S' bit on RREQ-DIOs, forcing asymmetric RREP-Instance flooding (default: false).

P2P-RPL Attributes (RFC 6997)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* ``P2pDioIntervalMin``: Trickle Imin for P2P mode DIOs (default: 64ms).
* ``P2pDioIntervalDoublings``: Trickle doublings for P2P mode DIOs (default: 4).
* ``P2pDioRedundancy``: Trickle redundancy constant k for P2P mode (default: 1).
* ``P2pMaxRank``: Maximum DAGRank allowed to join temporary DAG; 0 for unlimited (default: 8).
* ``P2pLifetime``: Temporary DAG lifetime: 0 (1s), 1 (4s), 2 (16s, default), 3 (64s).
* ``P2pNumRoutes``: Number of additional routes requested ('N' field; default: 0).
* ``P2pDroCollectWindow``: Window to collect alternate routes when N > 0 (default: 256ms).
* ``P2pDroAckRequested``: Request P2P-DRO-ACK for P2P-DRO replies (default: true).
* ``P2pDroAckWaitTime``: Timeout before retransmitting P2P-DRO (default: 1s).
* ``P2pDroMaxRetransmissions``: Retries for unacknowledged P2P-DRO (default: 3).

Traces
~~~~~~

The module does not currently define protocol-specific trace sources. Standard
``Ipv6L3Protocol`` Tx/Rx/Drop traces capture RPL packet flow.

Examples and Tests
-------------------

Examples
~~~~~~~~

* ``rpl-6lowpan-simple.cc``: Multi-hop IEEE 802.15.4 linear network running RPL
  over 6LoWPAN in route-over mode. Exercises upward and downward traffic (ping
  to/from root). Supports command-line switches ``--mrhof``, ``--lql``, and
  ``--verbose``.
* ``rpl-paper-evaluation.cc``: Topology evaluation script benchmarking convergence
  time, packet delivery ratio, and control overhead under varying network densities
  and error models.

Tests
~~~~~

The comprehensive test suite (``test/rpl-test-suite.cc``) comprises **144 test cases**:

* Serialization and deserialization round trips for all control messages, options,
  SRH, RPI, P2P-RDO, DRO, DRO-ACK, and AODV-RPL options.
* Boundary conditions, malformed header parsing, truncated options, and unknown option handling.
* RFC 6206 Trickle timer mechanics (interval expansion, [I/2, I) distribution, suppression, reset).
* RFC 6550 section 7.2 lollipop sequence counter comparison, wrap-around, and increments.
* Data-plane source routing (RFC 6554) error processing: segments left bounds, multicast
  destination check, loop detection with multiple local addresses, and hop limit expiry.
* Data-plane RPL Option (RFC 6553) rank inconsistency detection, duplicate suppression,
  and Trickle reset triggers.
* Multi-hop DODAG convergence, SLAAC address allocation, parent selection (OF0 and MRHOF
  with hysteresis), and upward/downward packet delivery.
* Storing mode (MOP 2) downward table population, No-Path DAO route removal, and
  Forwarding-Error ('F') bit bouncing.
* P2P-RPL (RFC 6997) route discovery, DRO retransmissions, ACK handling, and H=0/H=1 routing.
* AODV-RPL (RFC 9854) RREQ flooding, symmetric/asymmetric RREP replies, Gratuitous RREPs,
  and RankLimit boundary checks.

Validation
----------

The test suite is formally verified via ``./test.py -s rpl`` (all 144 unit test cases
executing cleanly). Multi-hop topologies with full IEEE 802.15.4 and 6LoWPAN stacks
demonstrate 100% end-to-end bidirectional ping delivery, correct ETX accumulation, and
stable operation across lossy radio channels.

References
----------

[`1 <https://www.rfc-editor.org/rfc/rfc6550>`_] T. Winter, Ed., et al.,
"RPL: IPv6 Routing Protocol for Low-Power and Lossy Networks," RFC 6550,
March 2012.

[`2 <https://www.rfc-editor.org/rfc/rfc6552>`_] T. Thubert, Ed., "Objective
Function Zero for the Routing Protocol for Low-Power and Lossy Networks
(RPL)," RFC 6552, March 2012.

[`3 <https://www.rfc-editor.org/rfc/rfc6206>`_] P. Levis et al., "The
Trickle Algorithm," RFC 6206, March 2011.

[`4 <https://www.rfc-editor.org/rfc/rfc6554>`_] J. Hui, J. Vasseur, D.
Culler, and V. Manral, "An IPv6 Routing Header for Source Routes with the
Routing Protocol for Low-Power and Lossy Networks (RPL)," RFC 6554, March
2012.

[`5 <https://www.rfc-editor.org/rfc/rfc6553>`_] J. Hui and JP. Vasseur,
"The Routing Protocol for Low-Power and Lossy Networks (RPL) Option for
Carrying RPL Information in Data-Plane Datagrams," RFC 6553, March 2012.

[`6 <https://www.rfc-editor.org/rfc/rfc6551>`_] JP. Vasseur, Ed., et al.,
"Routing Metrics Used for Path Calculation in Low-Power and Lossy
Networks," RFC 6551, March 2012.

[`7 <https://www.rfc-editor.org/rfc/rfc6719>`_] O. Gnawali and P. Levis,
"The Minimum Rank with Hysteresis Objective Function," RFC 6719, September
2012.

[`8 <https://www.rfc-editor.org/rfc/rfc6997>`_] M. Goyal, Ed., et al.,
"Reactive Discovery of Point-to-Point Routes in Low-Power and Lossy
Networks," RFC 6997, August 2013.

[`9 <https://www.rfc-editor.org/rfc/rfc9854>`_] M. Goyal, Ed., et al.,
"AODV-RPL: Reactive Route Discovery with RPL," RFC 9854, December 2024.
