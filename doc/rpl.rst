RPL: IPv6 Routing Protocol for Low-Power and Lossy Networks
=============================================================

.. heading hierarchy:
   ============= Module Name
   ------------- Section (#.#)
   ~~~~~~~~~~~~~ Subsection (#.#.#)

This chapter describes ``contrib/rpl``, an implementation of RPL (RFC 6550),
the IPv6 Routing Protocol for Low-Power and Lossy Networks, for ns-3. The
implementation covers non-storing mode (MOP 1) only: DODAG formation from
DIS/DIO exchanges paced by a Trickle timer (RFC 6206), rank computed by
either Objective Function Zero (RFC 6552, hop count, the default) or MRHOF
(RFC 6719) over the ETX routing metric (RFC 6551), downward routes built
from the DAOs every node sends to the root and delivered with a real RFC
6554 Source Routing Header, and per-hop rank consistency checking with a
real RFC 6553 RPL Option in a Hop-by-Hop header. The protocol is designed to
run over 6LoWPAN in route-over mode, i.e. installed on the IPv6 interfaces
that sit on ``SixLowPanNetDevice``, not directly on the link-layer device
underneath. This is also the profile Wi-SUN FAN 1.1 builds its RPL usage on
(non-storing, MRHOF, ETX); see design-constraints.md section 13.1 for what
of that profile is, and is not, verifiable from public sources.

The source code lives in ``contrib/rpl/``.

Scope and Limitations
----------------------

What the model does:

* Builds and maintains a DODAG: DIS solicitation, Trickle-paced DIO
  advertisement, rank computation with OF0 or MRHOF, parent selection with a
  freshness gate against spurious long-range PHY reception, and DODAG
  version changes.
* Under MRHOF, derives the ETX routing metric from lr-wpan's per-frame LQI
  (an EWMA-smoothed approximation of the bidirectional link quality Wi-SUN
  FAN measures through Neighbor Discovery), and picks the preferred parent
  by path cost with RFC 6719's hysteresis against flapping between parents
  of near-identical quality.
* Builds downward routes the way non-storing mode does: every node tells the
  root, with a DAO, which parent it sits under; only the root keeps a picture
  of the whole topology, and it computes and attaches a source route to every
  packet it sends down.
* Attaches that source route as a real IPv6 Routing Header (RFC 6554, Type
  3), inserted at the node that originates the packet and processed hop by
  hop by every router along the way, the same way ``Ipv6ExtensionLooseRouting``
  processes RFC 2460's Type 0 Routing Header elsewhere in |ns3|.
* Attaches a real RFC 6553 RPL Option to the same Hop-by-Hop header on every
  packet a node originates, carrying its own rank and the direction (up or
  down) the packet is expected to move in; every router the packet crosses
  checks the two against its own rank and updates the option for the next
  hop, flagging, and after a second inconsistency in a row treating as
  confirmed, a possible loop or stale route (RFC 6550 section 11.2).
* Receives its ICMPv6 type 155 control messages through an ``Ipv6RawSocket``
  per interface, since |ns3|'s ``Icmpv6L4Protocol`` silently discards ICMPv6
  types it does not know about.

What it does not do:

* Storing mode (MOP 2/3) is not implemented. This is a deliberate scope
  decision, not a missing feature: see
  ``contrib/rpl/doc/design-constraints.md`` section 1.
* RH3 address compression (CmprI/CmprE, RFC 6554 section 3) is not
  implemented; every address in a Routing Header is carried in full.
* A confirmed rank inconsistency (RFC 6550 section 11.2) is flagged and
  traced but not actually dropped: |ns3|'s ``Ipv6Option::Process()`` has no
  way to stop a packet the way ``Ipv6Extension::Process()`` can. See
  ``contrib/rpl/doc/design-constraints.md`` section 12.3.
* Wi-SUN FAN 1.1's own numeric tuning (Trickle intervals, hysteresis
  threshold, etc.) is not publicly documented, so MRHOF uses RFC 6719's own
  published defaults instead. See design-constraints.md section 13.1.
* Only the ETX metric (RFC 6551 section 4.3) is implemented; LQL and
  carrying more than one Routing Metric/Constraint object in the same DIO
  are not.
* No security modes (RFC 6550 section 10): every control message is sent
  unsecured.
* No P2P-RPL (RFC 6997) and no support for multiple concurrent RPL
  instances or DODAGs on the same node.
* The DODAG version number and the DAO path sequence are compared as plain
  integers, not with the lollipop comparison of RFC 6550 section 7.2, so a
  sequence number wrapping around past 255 is not detected. In practice this
  needs 256 DODAG version changes, or 256 parent changes by the same node, to
  matter, and a node that misreads a wrapped sequence as stale converges
  again on the next DIO or DAO regardless.
* A No-Path DAO (RFC 6550 section 6.4.3) is understood on receipt, but this
  implementation never sends one: a downward route is only ever dropped once
  its lifetime runs out. A node leaving a DODAG is consequently visible to
  the root only after that lifetime expires, not immediately.
* Every design decision forced by an |ns3| constraint, e.g. why the Routing
  Header needed a small core change to attach at the origin, is written up
  in ``contrib/rpl/doc/design-constraints.md`` alongside the ns-3 core bugs
  that surfaced while getting there. That document is the detailed
  companion to this overview.

Design
------

RplRoutingProtocol
~~~~~~~~~~~~~~~~~~~

``rpl::RplRoutingProtocol`` implements ``Ipv6RoutingProtocol``. Beside
``RouteOutput()``/``RouteInput()``, the notable override is
``PrepareOutgoingPacket()``, called by ``Ipv6L3Protocol::Send()`` right
before a packet reaches the device: on the root, for a global destination
more than one hop away, it computes the source route and attaches a
``RplSourceRoutingHeader``. Every other node, and every packet that does
not need one, leaves it untouched.

A node's own state (rank, preferred parent, DODAG identity, Trickle
parameters) lives directly on the ``RplRoutingProtocol`` instance. The root
additionally keeps a topology map, one entry per node in the DODAG, built
from the target and parent that node's DAOs report; everyone else keeps
none, which is what makes the mode non-storing.

Control message headers
~~~~~~~~~~~~~~~~~~~~~~~~

``RplDisHeader``, ``RplDioHeader``, ``RplDaoHeader`` and ``RplDaoAckHeader``
(``rpl-header.h``) are the RPL message bodies of RFC 6550 section 6, each a
plain ``Header``. The ICMPv6 type/code/checksum envelope around them is a
separate, composed ``Icmpv6Header`` rather than a base class every message
header inherits from; see design-constraints.md section 2 for why.

Source routing
~~~~~~~~~~~~~~

``RplSourceRoutingHeader`` (``rpl-header.h``) is an
``Ipv6ExtensionRoutingHeader`` subclass carrying the RFC 6554 wire format.
``RplIpv6ExtensionSourceRouting`` (``rpl-source-routing-extension.h``) is an
``Ipv6ExtensionRouting`` subclass, registered on every node's
``Ipv6ExtensionRoutingDemux``, that processes it: swap the current
destination into the address list, read the next one out, and re-inject the
packet through ``RouteOutput()``, the same algorithm
``Ipv6ExtensionLooseRouting`` already runs for RFC 2460's RH0. Since a node
processing this header is always addressed to itself at that point, every
address the header carries, including the final destination, is link-local.

RPL Option (data-path validation)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``RplPacketInfoHeader`` (``rpl-header.h``) is an ``Ipv6OptionHeader``
subclass carrying the RFC 6553 wire format. ``RplIpv6OptionRpl``
(``rpl-packet-info-option.h``) is an ``Ipv6Option`` subclass, registered on
every node's ``Ipv6OptionDemux``, that processes it. Unlike the Routing
Header, a Hop-by-Hop option is examined at every hop regardless of whether
the packet is addressed to that node, and ``Ipv6L3Protocol::Receive()``
happens to run the Hop-by-Hop chain twice for a packet that is: once itself
and once more inside ``LocalDeliver()``. ``RplIpv6OptionRpl`` tracks the
``Packet::GetUid()`` of the last packet it actually acted on so the second
call is a no-op rather than re-checking a rank it just rewrote to its own.

Routing metric (ETX, MRHOF)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``RplDioHeader`` optionally carries a DAG Metric Container (RFC 6550 section
6.7.8) holding an ETX object (RFC 6551 section 4.3), the cumulative path ETX
in the same fixed-point scale (``ETX * 128``) the wire format itself uses.
``RplRoutingProtocol`` reads lr-wpan's per-frame LQI
(``ns3::lrwpan::LrWpanLqiTag``) off a received DIO to estimate the
instantaneous ETX of that link, EWMA-smooths it into a per-neighbour
estimate, and, under MRHOF (``Ocp`` attribute set to ``RPL_OCP_MRHOF``),
uses it in place of a plain hop count for both the rank (RFC 6719 section
3.3) and preferred parent selection, including the hysteresis against
flapping between near-identical parents. The tag is read by its registered
``TypeId`` name through the generic ``PacketTagIterator`` rather than a
direct dependency on the lr-wpan module, so ``librpl`` keeps building and
running over any link layer, falling back to a neutral ETX (i.e. behaving
like plain hop count) where the tag is absent. See design-constraints.md
section 13 for the full design rationale, including what of Wi-SUN FAN
1.1's RPL profile could and could not be verified from public sources.

OF0 remains the compiled-in default; MRHOF is an explicit opt-in on the
root, the same way every other DODAG-wide parameter propagates from the
root's DIOs to the rest of the DODAG.

Trickle timer
~~~~~~~~~~~~~

``RplTrickleTimer`` (``rpl-trickle-timer.h``) is a small, self-contained
implementation of RFC 6206, independent of the rest of the module, used to
pace DIO transmission.

Usage
-----

A node running RPL needs ``RplHelper`` passed to
``InternetStackHelper::SetRoutingHelper()`` before the stack is installed,
one node marked as the DODAG root after its global address exists, and, for
route-over operation, the IPv6 interfaces installed on
``SixLowPanNetDevice`` rather than directly on the link layer. See
``contrib/rpl/examples/rpl-6lowpan-simple.cc`` for a complete example.

Helpers
~~~~~~~

::

  RplHelper rplHelper;
  InternetStackHelper internetv6;
  internetv6.SetRoutingHelper(rplHelper);
  internetv6.Install(nodes);

  // ... assign IPv6 addresses ...

  rplHelper.SetRoot(nodes.Get(0));       // after global addresses exist
  rplHelper.AssignStreams(nodes, 1);
  rplHelper.Set("DaoInterval", TimeValue(Seconds(30)));  // before Install(),
                                                          // to reach every node

Attributes
~~~~~~~~~~

All attributes are on ``ns3::rpl::RplRoutingProtocol``:

* ``DisInterval``: period of the unsolicited multicast DIS a node sends
  while it has not joined a DODAG.
* ``DioIntervalMin``: Trickle Imin for DIOs. Only the root's value matters;
  every other node takes it from the DODAG Configuration option of the DIO
  it joins on.
* ``DioIntervalDoublings``: number of Trickle doublings between Imin and
  Imax.
* ``DioRedundancy``: the Trickle redundancy constant k; 0 disables
  suppression.
* ``MinHopRankIncrease``: MinHopRankIncrease, which is also the rank of the
  root.
* ``Ocp``: Objective Code Point the root advertises, ``RPL_OCP_OF0`` (hop
  count, the default) or ``RPL_OCP_MRHOF`` (RFC 6719, ETX). Only meaningful
  on the root; every other node adopts whatever OCP the DIO it joins on
  advertises.
* ``DaoInterval``: how often a node repeats the DAO telling the root where
  it sits.
* ``DaoAckTimeout``: how long a node waits for a DAO-ACK before resending
  the DAO.
* ``DaoRetries``: how many times an unacknowledged DAO is resent before a
  node gives up until the next periodic refresh.
* ``PathLifetime``: lifetime of the downward route a node advertises, in
  lifetime units.

Traces
~~~~~~

Not applicable: the module does not currently define any trace sources of
its own. ``Ipv6L3Protocol``'s own Tx/Rx/Drop traces apply to RPL traffic
like any other IPv6 traffic.

Examples and Tests
-------------------

Examples
~~~~~~~~

``rpl-6lowpan-simple.cc`` builds a line of IEEE 802.15.4 nodes running RPL
over 6LoWPAN in route-over mode, spaced so that only neighbours hear each
other, forcing a multi-hop DODAG. Once it has converged, the last node
pings the root and the root answers, exercising both the upward route (the
request climbing through preferred parents) and the downward one (the
reply following the source route the root computed from the DAOs it
collected). The ``--mrhof`` command-line argument switches the DODAG from
OF0 to MRHOF; combined with ``--verbose`` and a large enough ``--distance``
to put a real ``LrWpanErrorModel`` into a lossy regime, the log shows each
hop's link ETX and the cumulative path ETX every node ends up advertising.

Tests
~~~~~

The ``rpl`` test suite (``test/rpl-test-suite.cc``) is a unit suite covering:

* Serialization round trips of every control message header, the source
  routing header, and the RPL Option.
* ``RplIpv6ExtensionSourceRouting::Process()``'s boundary and error paths:
  a malformed Segments Left, a multicast address in the path, hop limit
  exhaustion, a relay hop correctly stopping the receive chain instead of
  also delivering the packet locally, and a hop recognising itself as the
  real destination.
* ``RplIpv6OptionRpl::Process()``: the rank consistency check in both
  directions, the RFC 6550 section 11.2 once-then-confirmed inconsistency
  sequence, and that processing the same packet twice, the way
  ``Ipv6L3Protocol::Receive()`` does for one addressed to this node, only
  acts on it once.
* The Trickle timer of RFC 6206: interval doubling up to Imax, transmission
  within [I/2, I), a reset returning to Imin, and redundancy suppression.
* DODAG formation over a line of three nodes: rank progression, preferred
  parent selection, the resulting upward route, and the downward route and
  Routing Header the root builds for each of a direct child and a
  grandchild.
* A No-Path DAO removing a topology entry at the root.
* An unacknowledged DAO being retried the configured number of times at the
  configured timeout, then given up on until the next periodic refresh.
* MRHOF parent selection: choosing the lower path-cost candidate between two
  otherwise-equal neighbours, and the RFC 6719 hysteresis keeping the
  current preferred parent over a candidate whose improvement does not
  exceed ``PARENT_SWITCH_THRESHOLD``.

Validation
----------

The test suite above is the formal validation; it is run with
``./test.py -s rpl``. Beyond the unit level, ``rpl-6lowpan-simple`` has been
run over topologies of 3 to 6 nodes with the full IEEE 802.15.4/6LoWPAN
stack, confirming 100% ping delivery in both directions, including with the
Routing Header and the RPL Option actually on the wire together (i.e.
without |ns3| core's IPHC compression silently corrupting the former, or
either header getting lost in the process of the latter riding along on
every hop of a source routed packet's relay: two of the four |ns3| core and
module bugs this development surfaced; see design-constraints.md section
11).

The same example, run with ``--mrhof`` at a distance long enough to put the
link in a lossy regime, confirmed that ``LrWpanLqiTag`` survives the full
receive path (PHY through ``SixLowPanNetDevice`` decompression up to
``RplRoutingProtocol``) with real, non-neutral ETX values, and that the
path ETX MRHOF advertises accumulates additively across hops exactly as RFC
6551 section 4.3 defines it, with ping still succeeding end to end. See
design-constraints.md section 13.6.

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
