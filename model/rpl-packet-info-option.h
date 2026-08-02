/*
 * Copyright (c) 2026 ns-3 RPL module contributors
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Processing of the RFC 6553 RPL Option (RPI), registered on the node's
 * Ipv6OptionDemux the way the built-in options (Pad1, PadN, ...) are.
 */

#ifndef RPL_PACKET_INFO_OPTION_H
#define RPL_PACKET_INFO_OPTION_H

#include "ns3/ipv6-option.h"
#include "ns3/nstime.h"

namespace ns3
{
namespace rpl
{

/**
 * @ingroup rpl
 *
 * @brief IPv6 Option: the RPL Option (RPI), RFC 6553.
 *
 * Registered on a node's Ipv6OptionDemux, this is invoked by the core's
 * generic Hop-by-Hop option loop at every hop a packet carrying one crosses,
 * whether or not the packet is addressed to this node: RFC 6553 requires the
 * rank consistency check to run everywhere along the path, not just at the
 * final destination.
 *
 * Ipv6L3Protocol::Receive() runs the Hop-by-Hop chain twice for a packet
 * addressed to this node: once itself, before the destination is even
 * checked, and once more inside LocalDeliver(). Process() only acts on the
 * first of the two, tracked by the packet's Uid rather than anything carried
 * on the packet itself, since nothing guarantees the second call sees the
 * same packet object once this node forwards it onward. The Uid alone is not
 * enough to tell that pair apart from a genuinely later packet, though:
 * fragments and copies taken along RPL's own forwarding path (e.g.
 * RplIpv6ExtensionSourceRouting::Process()'s CreateFragment()-based rebuild)
 * keep the original packet's Uid, so a packet that loops back to a node it
 * already crossed carries the same Uid it had the first time. The two
 * Receive()/LocalDeliver() calls for one packet happen back to back in the
 * same simulation event, so pairing the Uid with Simulator::Now() tells that
 * case apart from a real repeat: same Uid, later time, processed again.
 *
 * @internal
 * A confirmed rank inconsistency, RFC 6550 section 11.2's second one in a
 * row, is traced as dropped (isDropped is set) but not actually stopped:
 * unlike Ipv6Extension::Process(), Ipv6Option::Process() has no
 * stopProcessing output, and Ipv6Extension::ProcessOptions() never derives
 * one from an option's isDropped, so the packet is still delivered or
 * forwarded regardless. What this implementation can enforce is the
 * repair-triggering side of RFC 6550 section 11.2: the 'R' flag gets set and
 * RplRoutingProtocol::NotifyRankInconsistency() resets the Trickle timer, so
 * an up to date DIO goes out sooner. Actually discarding the packet would
 * need either a core change to Ipv6Option::Process()'s signature, or
 * destroying enough of the packet here to make delivery fail on its own,
 * which risks the same kind of crash a malformed packet causes elsewhere in
 * ns-3, for a case, a confirmed loop, that is already rare in a working
 * network.
 * @endinternal
 */
class RplIpv6OptionRpl : public Ipv6Option
{
  public:
    /**
     * @brief Get the type ID.
     * @return the object TypeId
     */
    static TypeId GetTypeId();

    RplIpv6OptionRpl();
    ~RplIpv6OptionRpl() override;

    /**
     * @brief Set the node.
     *
     * Ipv6Option::SetNode() has no matching public getter, so this keeps its
     * own copy alongside calling the base class, since Process() needs to
     * look RplRoutingProtocol up on every call.
     *
     * @param node the node to set
     */
    void SetNode(Ptr<Node> node);

    uint8_t GetOptionNumber() const override;

    uint8_t Process(Ptr<Packet> packet,
                    uint8_t offset,
                    const Ipv6Header& ipv6Header,
                    bool& isDropped) override;

  private:
    Ptr<Node> m_node;            //!< the node this option processor runs on
    uint64_t m_lastProcessedUid; //!< Uid of the last packet actually processed
    Time m_lastProcessedTime;    //!< simulation time of m_lastProcessedUid, so a
                                  //!< later packet reusing that Uid (e.g. the same
                                  //!< packet object come back around a loop) is not
                                  //!< mistaken for the same Receive()/LocalDeliver()
                                  //!< pair and skipped
    bool m_rankErrorSignaled;    //!< true once an inconsistency was flagged, until a
                                  //!< consistent packet is seen again
};

} // namespace rpl
} // namespace ns3

#endif /* RPL_PACKET_INFO_OPTION_H */
