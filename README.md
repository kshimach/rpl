# RPL for ns-3

An implementation of RPL, the IPv6 Routing Protocol for Low-Power and Lossy
Networks, together with its two reactive point-to-point extensions, as a
single [ns-3](https://www.nsnam.org/) contrib module.

* **RPL** — [RFC 6550](https://www.rfc-editor.org/rfc/rfc6550): DODAG
  formation over Trickle-paced DIS/DIO/DAO exchanges, Non-Storing (MOP 1)
  and Storing-without-multicast (MOP 2) downward routing, OF0
  ([RFC 6552](https://www.rfc-editor.org/rfc/rfc6552)) and MRHOF
  ([RFC 6719](https://www.rfc-editor.org/rfc/rfc6719)) objective functions,
  and data-plane loop detection via the RPL Option
  ([RFC 6553](https://www.rfc-editor.org/rfc/rfc6553)).
* **P2P-RPL** — [RFC 6997](https://www.rfc-editor.org/rfc/rfc6997): on-demand
  discovery of a direct route between two nodes without detouring through
  the DODAG root.
* **AODV-RPL** — [RFC 9854](https://www.rfc-editor.org/rfc/rfc9854): a newer,
  AODV-style reactive discovery protocol built on the same DIO framework,
  supporting both symmetric and asymmetric routes.

The three protocols are implemented together because they share a wire
format, a DODAG/DIO framework, and — in this module — a single state model
(see [`DESIGN_CONSTRAINTS.md`](DESIGN_CONSTRAINTS.md)), which makes it
possible to run them standalone or mixed on the same network and compare
them under identical conditions.

## Status

144 unit test cases (`./test.py -s rpl`), all passing. Multi-hop scenarios
with a full IEEE 802.15.4 + 6LoWPAN stack (`rpl-6lowpan-simple`) and a
100-node system-test harness (`rpl-large-scale-system-test`, in `scratch/`
of the parent tree) are used for end-to-end validation; see
[`doc/rpl.rst`](doc/rpl.rst) for the full test/validation summary.

## Getting started

This module is a `contrib/` directory of an ns-3 source tree, not a
standalone build. From the root of the ns-3 tree:

```bash
./ns3 configure --enable-examples --enable-tests
./ns3 build
./test.py -s rpl
./ns3 run "rpl-6lowpan-simple --mrhof --lql --verbose"
```

Minimal setup in your own scenario:

```cpp
RplHelper rplHelper;
// Storing mode instead of the default Non-Storing:
// rplHelper.Set("Mop", UintegerValue(RPL_MOP_STORING_NO_MULTICAST));

InternetStackHelper internetv6;
internetv6.SetRoutingHelper(rplHelper);
internetv6.Install(nodes);

rplHelper.SetRoot(nodes.Get(0), Ipv6Address("2001:1::"), 64);
rplHelper.AssignStreams(nodes, 1);
```

RPL is designed to sit on top of 6LoWPAN in route-over mode (i.e. installed
on the IPv6 interface above a `SixLowPanNetDevice`), matching the profile
Wi-SUN FAN 1.1 standardizes (Non-Storing, MRHOF, ETX).

## Documentation

* [`doc/rpl.rst`](doc/rpl.rst) — the full Sphinx model document: supported
  features, explicit scope/limitations, class design, every attribute, and
  the test/validation summary.
* [`DESIGN_CONSTRAINTS.md`](DESIGN_CONSTRAINTS.md) — an English summary of
  the ns-3-core-level constraints this module works around (and the four
  independent ns-3 core bugs it uncovered along the way).
* [`doc/design-constraints.md`](doc/design-constraints.md) — the full,
  ongoing design-decision record (Japanese), the source the summary above
  is drawn from.

## Known limitations

The short version (see `doc/rpl.rst` for the complete list):

* MOP 3 (Storing with multicast), RPL's cryptographic security modes
  (RFC 6550 section 10), and IPv6-in-IPv6 tunneling for mid-path header
  insertion are not implemented.
* A confirmed rank inconsistency ([RFC 6550](https://www.rfc-editor.org/rfc/rfc6550)
  section 11.2) is traced and flagged, and resets the DODAG's Trickle timer,
  but is not actually dropped: ns-3's `Ipv6Option::Process()` has no
  mechanism to halt packet delivery the way `Ipv6Extension::Process()`
  does. See `DESIGN_CONSTRAINTS.md`.
* Only the ETX and LQL routing metrics (RFC 6551 sections 4.3/4.6) are
  implemented; Node Energy, Hop Count, Link Throughput, Link Latency, and
  Link Color are not.

## License

GPLv2, matching the rest of ns-3 (see [`LICENSE`](LICENSE)).

## References

1. T. Winter, Ed., et al., "RPL: IPv6 Routing Protocol for Low-Power and
   Lossy Networks," [RFC 6550](https://www.rfc-editor.org/rfc/rfc6550), 2012.
2. T. Thubert, Ed., "Objective Function Zero for RPL,"
   [RFC 6552](https://www.rfc-editor.org/rfc/rfc6552), 2012.
3. P. Levis et al., "The Trickle Algorithm,"
   [RFC 6206](https://www.rfc-editor.org/rfc/rfc6206), 2011.
4. J. Hui et al., "An IPv6 Routing Header for Source Routes with RPL,"
   [RFC 6554](https://www.rfc-editor.org/rfc/rfc6554), 2012.
5. J. Hui and JP. Vasseur, "The RPL Option for Carrying RPL Information in
   Data-Plane Datagrams," [RFC 6553](https://www.rfc-editor.org/rfc/rfc6553), 2012.
6. JP. Vasseur, Ed., et al., "Routing Metrics Used for Path Calculation in
   LLNs," [RFC 6551](https://www.rfc-editor.org/rfc/rfc6551), 2012.
7. O. Gnawali and P. Levis, "The Minimum Rank with Hysteresis Objective
   Function," [RFC 6719](https://www.rfc-editor.org/rfc/rfc6719), 2012.
8. M. Goyal, Ed., et al., "Reactive Discovery of Point-to-Point Routes in
   LLNs," [RFC 6997](https://www.rfc-editor.org/rfc/rfc6997), 2013.
9. M. Goyal, Ed., et al., "AODV-RPL: Reactive Route Discovery with RPL,"
   [RFC 9854](https://www.rfc-editor.org/rfc/rfc9854), 2024.
