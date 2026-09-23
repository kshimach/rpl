# RPL Module — Design Constraints (English Summary)

This is a condensed English summary of the current ns-3-core-level
constraints this module works around, and the reasoning behind each
workaround. The full record — a much longer, chronological Japanese design
log covering every fix made during development — lives in
[`doc/design-constraints.md`](doc/design-constraints.md); this file draws
only the constraints that are still true today, states them as current
facts, and leaves the development history out. Section numbers below are
this file's own and do not match the Japanese original.

The module's own policy throughout has been: **do not modify ns-3 core**
unless there is no other way to meet a hard requirement (an accurate wire
format, a correct protocol behaviour). Sections 2 and 15 are the two places
that policy was overridden, each behind a minimal, generically-useful core
hook rather than an RPL-specific change.

## 1. Scope

Both Non-Storing mode (MOP 1, RFC 6550) and Storing mode without multicast
(MOP 2) are supported; MOP 3 (Storing with multicast) is not. See
`doc/rpl.rst` for the full supported/unsupported feature list.

## 2. Inserting a real extension header at the source (core hook)

**Constraint:** `Ipv6L3Protocol::Send()` fixes and truncates the payload
length around the `RouteOutput()` call, so a routing protocol has no
opportunity to add an IPv6 extension header (e.g. a Type 3 Routing Header)
to a packet at its source.

**Workaround:** a non-pure-virtual `Ipv6RoutingProtocol::PrepareOutgoingPacket
(packet, header, route)` hook was added to ns-3 core (default: empty), called
from all three send paths in `Ipv6L3Protocol::Send()` immediately before
`SendRealOut()`, with `header.SetPayloadLength()` recomputed afterwards. No
other routing protocol overrides it, so this has no effect elsewhere.
`RplRoutingProtocol::PrepareOutgoingPacket()` uses it, at the root only, to
add a real `RplSourceRoutingHeader` (RFC 6554) via `packet->AddHeader()`.
The receive side registers `RplIpv6ExtensionSourceRouting` on the existing
`Ipv6ExtensionRoutingDemux` — the same generic "process the header addressed
to me, rewrite the destination, resend via `RouteOutput()`" framework RFC
2460's RH0 already uses, so no further core change was needed beyond one
`friend` declaration matching RH0's own.

An earlier version avoided the core change entirely by carrying the RH3
wire format as out-of-band `PacketTag` bytes instead of a real header (a
technique also used, for a different header, by a prior RPL-for-ns-3 thesis
implementation). That approach was abandoned in favour of the core hook once
"pack real SRH bytes into every hop's frame, not just metadata" became a
hard requirement.

## 3. Receiving ICMPv6 type 155 without subclassing `Icmpv6L4Protocol`

**Constraint:** adding a new ICMPv6 message type by subclassing
`Icmpv6L4Protocol` requires a core change.

**Workaround:** an `Ipv6RawSocketImpl` bound to `Ipv6Address::GetAny()` (not
a specific address — binding to a link-local address causes multicast RPL
traffic to `ff02::1a` to be dropped) with `BindToNetDevice()` restricting it
to one interface. `RecvRpl()` checks the ICMPv6 type field manually.
`Icmpv6FilterSetPass()` is unavailable through the public raw-socket API, so
there is no kernel-level filter — only the manual type check.

## 4. Two IPv6-forwarding pitfalls that only bite in simulation

* `Ipv6L3Protocol::IpForward()` refuses to forward to the RFC 3849
  documentation prefix (`2001:db8::/32`); examples must use a different
  prefix (this module's examples use `2001:1::/64`).
* `RouteOutput()`'s default on-link heuristic ("same /64 as my DODAG ⇒
  reachable in one hop") is wrong in a multi-hop LLN. The module never
  treats a global-unicast destination as on-link; everything not multicast
  or link-local routes through the DODAG (upward) or a Source Routing
  Header (downward).

## 5. A freshness gate against spurious long-range PHY reception

ns-3's radio PHY models occasionally deliver a frame across a distance that
would not succeed in practice. A node that locks onto a distant, one-off DIO
as its preferred parent can break multi-hop connectivity. A Contiki-NG-style
freshness counter (`RPL_FRESHNESS_MAX=16`, `RPL_FRESHNESS_TARGET=4`) requires
a run of stable receptions before a candidate parent is trusted; a preferred
parent that goes stale has its inherited rank discarded too.

## 6. `Timer`, not a raw `EventId`

`Timer::Schedule()` aborts with `NS_FATAL_ERROR` if called while an event is
already pending; a raw `EventId` re-assigned without cancelling silently
leaks the old event. Every periodic send (DIS, DAO, DAO retry, both Trickle
timer events) uses `Timer` (following `src/olsr`'s convention) and always
calls `Cancel()` before `Schedule()`.

## 7. One multicast path, one unicast path

A single loop over all interfaces in the message-send routine caused
duplicate unicast messages (DAO, DAO-ACK) on multi-interface nodes.
`SendRplMessageMulticast()` (DIS/DIO, every interface) and
`SendRplMessageUnicast()` (DAO/DAO-ACK, the one relevant interface) are now
separate.

## 8. Lazy topology-table cleanup

The root's `PurgeTopology()` runs from `RouteOutput()`'s root branch
(immediately before `ComputeSourceRoute()`), not from a dedicated timer —
the same lazy-cleanup-on-use pattern `src/aodv`'s `RoutingTable::Purge()`
follows. The topology only needs to be current at the moment it is actually
consulted.

## 9. A single-interface assumption in the test topology

Giving every hop its own `SimpleNetDevice`/`SimpleChannel` in a test breaks
`GlobalAddressOf()`'s "one node, one interface, one prefix" assumption. RPL
targets LLNs, where a node normally has exactly one multi-hop radio
interface; the test suite represents multi-hop topologies with `BlackList()`
on a single shared `SimpleChannel` instead.

## 10. Four ns-3 core bugs found along the way

Switching to a real RH3 implementation and a real RFC 6553 RPL Option
exercised IPv6 extension-header code paths that had, in practice, never run
before. Three of the four are not RPL-specific — they reproduce with plain
RFC 2460 RH0 routing headers over 6LoWPAN, or after any Hop-by-Hop header —
and were fixed in `src/sixlowpan` / `src/internet`, not in this module.

1. **6LoWPAN NHC compression corrupts Routing Header addresses.**
   `SixLowPanNetDevice::CompressLowPanNhc()`/`DecompressLowPanNhc()` read and
   write through the `Ipv6ExtensionRoutingHeader` *base class*, whose
   `GetSerializedSize()` returns a fixed 4 bytes and knows nothing about
   RH0/RH3's actual CmprI/CmprE/Pad fields or address list — even though
   `Ipv6ExtensionRoutingDemux::GetExtensionRoutingHeaderPtr()`, which returns
   the correct concrete header type, already existed and was simply never
   called from this path. Fix: `IPV6_EXT_ROUTING` was removed from
   `SixLowPanNetDevice::CanCompressLowPanNhc()`'s compressible set, falling
   back to the existing uncompressed path. Routing Headers now travel
   uncompressed over 6LoWPAN; this module does not implement RH3 address
   compression as a way around the bug (compression is simply not attempted
   over 6LoWPAN at all).
2. **A relay double-delivers to the ICMPv6 layer.**
   `RplIpv6ExtensionSourceRouting::Process()` (modelled on RH0's
   `Ipv6ExtensionLooseRouting::Process()`) resent a relayed packet and set
   `isDropped = true`, but never set `stopProcessing`. The caller,
   `Ipv6L3Protocol::LocalDeliver()`, only checks `stopProcessing`, so it
   delivered the same payload to ICMPv6 a second time. **The same bug exists
   in ns-3's own RH0 implementation**, unexercised there for the same
   reason: fixing it in `Ipv6ExtensionLooseRouting` was out of this module's
   scope, so only `RplIpv6ExtensionSourceRouting::Process()` was corrected.
3. **`Ipv6ExtensionRouting::Process()` ignores its own offset.** It builds
   `p = packet->Copy(); p->RemoveAtStart(offset)` and then reads the next 4
   bytes from `packet` (offset 0) instead of `p` — dead code that happened
   to be harmless as long as a Routing Header was always the first
   extension header (offset always 0). Adding the RPI Hop-by-Hop header in
   front of it exposed the bug: the Routing Header's Routing Type byte was
   misread from stale RPI bytes, taken for an unregistered type, and the
   packet was dropped as malformed. One-line fix.
4. **This module's own relay code discarded the Hop-by-Hop header on
   relay.** Once the Hop-by-Hop header (RPI) sat in front of the Routing
   Header, `RplIpv6ExtensionSourceRouting::Process()`'s
   `p = packet->Copy(); p->RemoveAtStart(offset)` silently dropped
   everything before the Routing Header — RPI included — on every relay,
   without updating the IPv6 header's Next Header field to match. Fixed by
   preserving the discarded prefix (`packet->CreateFragment(0, offset)`) and
   re-attaching it after the Routing Header rewrite.

## 11. Hop-by-Hop option double dispatch

**Registering an `Ipv6Option`:** `ipv6-option-demux.h` was missing from
`src/internet`'s public header list even though its `Insert()` API is
public; one line added to `CMakeLists.txt`'s `HEADER_FILES` fixed it. No
`friend` declaration was needed.

**The double-dispatch problem:** `Ipv6L3Protocol::Receive()` processes
Hop-by-Hop options once itself and, if the packet is addressed locally, a
second time inside `LocalDeliver()`. This is harmless for options that never
mutate anything (Pad1, PadN, Jumbogram, RouterAlert) but not for RPI, which
rewrites the sender's rank: the second pass re-validates against the value
the first pass just wrote. A `PacketTag` marker was rejected (nothing
guarantees the tag survives to the packet's next hop, since that depends on
the NetDevice/Channel implementation). Instead, `RplIpv6OptionRpl` keeps the
last `Packet::GetUid()` it processed per node; a repeat is treated as the
second, redundant dispatch and skipped.

`Packet::GetUid()` alone is not sufficient, however: a packet relayed by
`RplIpv6ExtensionSourceRouting::Process()`'s `CreateFragment()` keeps its Uid
across hops (fragmenting copies `PacketMetadata` rather than minting a new
Uid). A genuine forwarding loop back to the same node would then be
misdiagnosed as the harmless double-dispatch and silently skipped — defeating
RFC 6550 section 11.2's own loop-detection mechanism in exactly the case it
exists to catch. The fix tracks `(Uid, Simulator::Now())` together: the two
same-packet dispatches always happen within the same simulation event
(identical timestamp), while a packet that returns after a real loop arrives
at a different time and is correctly reprocessed.

## 12. Confirmed loops are traced, not dropped

RFC 6550 section 11.2.2.2's rule is precise: a Rank inconsistency detected
once is not fatal and the packet continues; the **same packet** detected
inconsistent a **second time**, anywhere along its path, MUST be dropped.
The rule is carried by a bit on the packet itself (the RPI's Rank-Error
bit), not by any per-node counter — every packet starts with this bit
clear, since hosts and leaves are required to send it that way.

This module correctly reads the Rank-Error bit carried by the packet
(`RplPacketInfoHeader::GetRankError()`), sets `isDropped` and resets the
Trickle timer only on the confirmed (second) detection, and leaves the bit
untouched afterwards (RFC 6550 defines no clearing rule).

It cannot, however, actually stop the packet: `Ipv6Extension::Process()`
has a `stopProcessing` output parameter that tells its caller "do nothing
further with this packet," but the sibling API for Hop-by-Hop *options*,
`Ipv6Option::Process(Ptr<Packet> packet, uint8_t offset, const Ipv6Header&
header, bool& isDropped)`, has no equivalent. `isDropped` exists, but
`Ipv6Extension::ProcessOptions()` never translates it into
`stopProcessing`, so `isDropped = true` only fires the drop trace — the
packet is delivered and forwarded exactly as if no inconsistency had been
confirmed. Two fixes were considered: (a) add a `stopProcessing`-equivalent
to `Ipv6Option::Process()` — a breaking-signature change to every
`Ipv6Option` subclass registered with `Ipv6OptionDemux`, with a blast radius
this module cannot fully assess; (b) corrupt the packet in place to force a
later stage to fail — a plausible new crash of the same shape as the bugs in
section 10. Neither has been made; a genuinely confirmed loop is a rare
event, and the RFC's early-recovery intent (a Trickle reset triggering fresh
DIOs) is already achieved the moment the second detection fires.

**This is the module's one open, upstream-worthy ns-3 core gap.** A patch
adding a real `stopProcessing` output to `Ipv6Option::Process()` would need
review and testing across every existing `Ipv6Option` subclass before it
could be proposed to the ns-3 project.

## 13. `PrepareOutgoingPacket()` must stay scoped to RPL's own interfaces

The `route` argument this hook receives was initially ignored. On a node
that runs RPL alongside another routing protocol via `Ipv6ListRouting` and
also owns an interface RPL does not manage, every list-routing member
receives this hook regardless of whose route is actually in use — so
unrelated global traffic leaving through the other interface was getting an
SRH/RPI attached unconditionally. Since RPL Option's high two type bits mean
"if unrecognised, ICMP error and drop the whole packet," a receiver that
does not speak RPL would silently drop that traffic. Fix: resolve
`route->GetOutputDevice()` to an interface index and return immediately if
that interface is not one RPL actually started (`m_ifcToSocket`).

## 14. Source-routed downward traffic: link-local next hop, global destination

Root-originated downward traffic (e.g. an ICMPv6 Echo Request root sends
itself) failed past the first hop: `ComputeSourceRoute()` builds its address
list entirely in link-local addresses, including the final destination. With
that address on the wire, `Icmpv6L4Protocol::HandleEchoRequest()` — which
echoes the request's own destination address as the reply's source — sends
its reply from a link-local address, which RFC 4291 scoping rules confine to
one hop; `Ipv6L3Protocol::IpForward()` silently drops it beyond that. Every
prior test only exercised the opposite direction (leaf pings root), whose
downward reply always carries the root's real global address, so the bug
was never triggered.

An initial fix (route the final hop through a new public
`RplRoutingProtocol::RouteToNeighbour()`, bypassing `RouteOutput()`'s
on-link restriction just for SRH) passed small tests but destabilized rank
in a 10-node random topology once a global address reached
`Ipv6Route::SetGateway()` and confused neighbour-discovery/local-delivery
logic further down the stack. The change that stuck keeps the Routing
Header's final address global, while `RouteToNeighbour()` itself normalizes
its `Gateway` — the address actually used for link-layer transmission — to
link-local (`neighbour.IsLinkLocal() ? neighbour : LinkLocalOf(neighbour)`)
regardless of what address it was asked to route toward. The next-hop
resolution this module's other neighbour lookups already rely on (link-local,
one radio hop) stays intact, while the IPv6 destination itself, and hence
the reply's source address, remains globally scoped.

## 15. No link-time dependency on `lr-wpan`

`librpl` links only `libinternet` and `libsixlowpan`. Reading lr-wpan's
per-frame `LrWpanLqiTag` (for ETX) and a new `LrWpanRssiTag` (added to
`src/lr-wpan`, for LQL — RSSI was computed in `LrWpanPhy` but never attached
to a packet before) is done through `TypeId::LookupByNameFailSafe()` plus
`PacketTagIterator`, using a local stand-in tag whose `GetInstanceTypeId()`
is resolved at runtime to the real one — matching the wire format without
an `#include` or a link dependency on `liblr-wpan`. This follows an existing
precedent: `sixlowpan` itself does not link `liblr-wpan` from its main
library, only from its examples. When `liblr-wpan` is absent (as in this
module's own `rpl-test` binary), the lookup fails safely and link metrics
fall back to a neutral value (ETX 1.0).

## 16. DODAG startup waits for address assignment, not initialization

The root derives its own address from `RootPrefix` via
`Ipv6Address::MakeAutoconfiguredAddress()` in `DoInitialize()`, but does not
start the DODAG (join Trickle, fix the DODAGID) there. `AddAddress()`
schedules Duplicate Address Detection automatically; the root instead starts
on `Icmpv6L4Protocol`'s `"DadSuccess"` trace source, once the address is
confirmed unique. Non-root nodes autoconfigure via the Prefix Information
Option carried in DIOs (`Ipv6L3Protocol::AddAutoconfiguredAddress()`) and
begin routing immediately — ns-3's own `Ipv6InterfaceAddress` defaults to
`TENTATIVE_OPTIMISTIC` (RFC 4429 Optimistic DAD), a core-wide policy of
using an address before DAD completes; only the root's own identity (its
DODAGID) is held to the stricter, DAD-confirmed standard, since once
advertised it propagates to the whole DODAG.

## Current known limitations

* **MOP 3** (Storing mode with multicast) is not implemented.
* **RPL's cryptographic security modes** (RFC 6550 section 10) are not
  implemented; link-layer security (e.g. IEEE 802.15.4 MAC encryption) is
  assumed instead.
* **IPv6-in-IPv6 tunneling** for mid-path header insertion (as RFC 6553/6554
  specify) is not implemented; headers are added to the packet directly.
* **A confirmed rank inconsistency is not actually dropped** — see section 12.
* **Only ETX and LQL are implemented** among RFC 6551's routing metrics;
  Node Energy, Hop Count metric object, Link Throughput, Link Latency, and
  Link Color are not.
* **Unbounded rank growth under dense topologies.** Root's periodic Global
  Repair (`GlobalRepairInterval`, DODAGVersionNumber increment) exists, but
  a node that has hit `DAGMaxRankIncrease` and gone infinite-rank can fail
  to recover under some dense-topology conditions; not fully root-caused.
