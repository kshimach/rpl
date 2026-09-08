/*
 * Copyright (c) 2026 kawashy
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * The protocol constants below follow RFC 6550/6551/6552/6719 and are kept
 * numerically identical to the Contiki-NG rpl-lite defaults so that ns-3 and
 * Cooja runs are directly comparable.
 * Reference: contiki-ng/os/net/routing/rpl-lite/{rpl-const.h,rpl-conf.h}
 * (Copyright (c) 2010, Swedish Institute of Computer Science, 3-clause BSD)
 */

#ifndef RPL_CONF_H
#define RPL_CONF_H

#include <cstdint>

namespace ns3
{
namespace rpl
{

/// ICMPv6 type carrying every RPL control message (RFC 6550, section 6).
constexpr uint8_t ICMPV6_RPL = 155;

/// ICMPv6 codes identifying the RPL control message (RFC 6550, section 6).
enum RplMessageCode : uint8_t
{
    RPL_CODE_DIS = 0x00,     //!< DODAG Information Solicitation
    RPL_CODE_DIO = 0x01,     //!< DODAG Information Object
    RPL_CODE_DAO = 0x02,     //!< Destination Advertisement Object
    RPL_CODE_DAO_ACK = 0x03, //!< DAO Acknowledgement
    RPL_CODE_P2P_DRO = 0x04, //!< P2P Discovery Reply Object (RFC 6997, section 8)
    RPL_CODE_P2P_DRO_ACK = 0x05, //!< P2P-DRO Acknowledgement (RFC 6997, section 10)
    RPL_CODE_SEC_DIS = 0x80, //!< Secure DIS (not implemented)
    RPL_CODE_SEC_DIO = 0x81, //!< Secure DIO (not implemented)
    RPL_CODE_SEC_DAO = 0x82, //!< Secure DAO (not implemented)
    RPL_CODE_SEC_DAO_ACK = 0x83, //!< Secure DAO-ACK (not implemented)
};

/// RPL control message option types (RFC 6550, section 6.7).
enum RplOptionType : uint8_t
{
    RPL_OPTION_PAD1 = 0,
    RPL_OPTION_PADN = 1,
    RPL_OPTION_DAG_METRIC_CONTAINER = 2,
    RPL_OPTION_ROUTE_INFO = 3,
    RPL_OPTION_DAG_CONF = 4,
    RPL_OPTION_TARGET = 5,
    RPL_OPTION_TRANSIT = 6,
    RPL_OPTION_SOLICITED_INFO = 7,
    RPL_OPTION_PREFIX_INFO = 8,
    RPL_OPTION_TARGET_DESC = 9,
    RPL_OPTION_P2P_RDO = 0x0A,   //!< P2P Route Discovery Option (RFC 6997, section 7)
    RPL_OPTION_AODV_RREQ = 0x0B, //!< AODV-RPL Route Request (RFC 9854, section 4.1)
    RPL_OPTION_AODV_RREP = 0x0C, //!< AODV-RPL Route Reply (RFC 9854, section 4.2)
    RPL_OPTION_AODV_ART = 0x0D,  //!< AODV-RPL Target (RFC 9854, section 4.3)
};

/// Mode of Operation (RFC 6550, section 20.14). NON_STORING is what core RPL
/// runs here; P2P_ROUTE_DISCOVERY is AODV-RPL's (RFC 9854, section 9, which
/// reuses the value RFC 6997 registered for P2P-RPL).
enum RplMop : uint8_t
{
    RPL_MOP_NO_DOWNWARD_ROUTES = 0,
    RPL_MOP_NON_STORING = 1,
    RPL_MOP_STORING_NO_MULTICAST = 2,
    RPL_MOP_STORING_MULTICAST = 3,
    RPL_MOP_P2P_ROUTE_DISCOVERY = 4,
};

/// Objective Code Points (RFC 6552, RFC 6719).
enum RplOcp : uint16_t
{
    RPL_OCP_OF0 = 0,
    RPL_OCP_MRHOF = 1,
};

/// Objective Function bit positions inside the DIO "G/MOP/Prf" byte.
constexpr uint8_t RPL_DIO_GROUNDED = 0x80;
constexpr uint8_t RPL_DIO_MOP_SHIFT = 3;
constexpr uint8_t RPL_DIO_MOP_MASK = 0x38;
constexpr uint8_t RPL_DIO_PREFERENCE_MASK = 0x07;

/// DAO base flags (RFC 6550, section 6.4).
constexpr uint8_t RPL_DAO_K_FLAG = 0x80; //!< DAO-ACK requested
constexpr uint8_t RPL_DAO_D_FLAG = 0x40; //!< DODAGID present

/// Rank values (RFC 6550, section 17).
constexpr uint16_t RPL_INFINITE_RANK = 0xFFFF;
constexpr uint8_t RPL_INFINITE_LIFETIME = 0xFF;

/// Lollipop sequence counters (RFC 6550, section 7.2). Values of 128 and
/// greater form a linear region used to bootstrap the counter after a
/// restart; values of 127 and below form a circular region of size 128.
constexpr uint8_t RPL_SEQUENCE_WINDOW = 16;         //!< SEQUENCE_WINDOW, 2^4
constexpr uint8_t RPL_SEQUENCE_LINEAR_REGION = 128; //!< first value of the linear region
constexpr uint8_t RPL_SEQUENCE_CIRCULAR_SIZE = 128; //!< size of the circular region

/// How two lollipop sequence counters relate (RFC 6550, section 7.2, rule 3).
enum class RplSequenceOrder
{
    LESS,           //!< the first counter is the older one
    EQUAL,          //!< the two counters are the same
    GREATER,        //!< the first counter is the newer one
    NOT_COMPARABLE, //!< too far apart to order: a desynchronisation
};

/**
 * @brief Order two lollipop sequence counters, RFC 6550 section 7.2 rule 3.
 *
 * Rule 3 opens with "When comparing two sequence counters, the following
 * rules MUST be applied", and the rules disagree with a plain integer
 * comparison on exactly the wrap-around the lollipop encoding exists to
 * express: 0 follows 255, so it is the newer of the two, and a `>` reads
 * that as a 255-step decrease instead.
 *
 * @internal
 * Two readings of rule 3.2 are possible, since it measures "the absolute
 * magnitude of difference between the two sequence counters" without saying
 * whether the measurement goes around the region or across it. Taken across,
 * rule 3.2.1's reference to RFC 1982 would be redundant -- inside a window of
 * 16, RFC 1982 and a plain comparison never disagree -- so this takes it as
 * going around, which is also what Contiki-NG's rpl_lollipop_greater_than()
 * does. That only applies to the circular region: rule 2 has a counter in the
 * linear region wrap "back to zero", i.e. into the circular region, so 255 is
 * never one step short of 128 and the linear region is not circular.
 *
 * The one deliberate difference from Contiki-NG is the boundary: rule 3.2.1
 * is "less than or equal to SEQUENCE_WINDOW", where Contiki-NG's comparison
 * is strict, so counters exactly SEQUENCE_WINDOW apart are ordered here and
 * incomparable there.
 * @endinternal
 *
 * @param a the first counter
 * @param b the second counter
 * @return how a relates to b
 */
inline RplSequenceOrder
RplSequenceCompare(uint8_t a, uint8_t b)
{
    if (a == b)
    {
        return RplSequenceOrder::EQUAL;
    }

    const bool aLinear = a >= RPL_SEQUENCE_LINEAR_REGION;
    const bool bLinear = b >= RPL_SEQUENCE_LINEAR_REGION;

    if (aLinear != bLinear)
    {
        // Rule 3.1, with A the counter in [128..255] and B the one in
        // [0..127]: "If (256 + B - A) is less than or equal to
        // SEQUENCE_WINDOW, then B is greater than A".
        const uint16_t linear = aLinear ? a : b;
        const uint16_t circular = aLinear ? b : a;
        const bool circularIsGreater = (256 + circular - linear) <= RPL_SEQUENCE_WINDOW;
        if (circularIsGreater)
        {
            return aLinear ? RplSequenceOrder::LESS : RplSequenceOrder::GREATER;
        }
        return aLinear ? RplSequenceOrder::GREATER : RplSequenceOrder::LESS;
    }

    if (aLinear)
    {
        // Rule 3.2 in the linear region, which does not wrap within itself.
        const uint16_t magnitude = (a > b) ? (a - b) : (b - a);
        if (magnitude > RPL_SEQUENCE_WINDOW)
        {
            return RplSequenceOrder::NOT_COMPARABLE;
        }
        return (a > b) ? RplSequenceOrder::GREATER : RplSequenceOrder::LESS;
    }

    // Rule 3.2 in the circular region: how far b has to advance to reach a.
    const uint8_t forward = static_cast<uint8_t>(a - b) % RPL_SEQUENCE_CIRCULAR_SIZE;
    if (forward <= RPL_SEQUENCE_WINDOW)
    {
        return RplSequenceOrder::GREATER;
    }
    if (RPL_SEQUENCE_CIRCULAR_SIZE - forward <= RPL_SEQUENCE_WINDOW)
    {
        return RplSequenceOrder::LESS;
    }
    return RplSequenceOrder::NOT_COMPARABLE;
}

/**
 * @brief Whether a lollipop sequence counter carries newer information than
 *        the one already held.
 *
 * RFC 6550 section 7.2 rule 4 on the counters that cannot be ordered at all:
 * failing any record of which one incremented most recently, "the node should
 * consider the comparison as if it has evaluated in such a way so as to
 * minimize the resulting changes to its own state" -- so an incomparable
 * counter is not newer, and nothing is updated on the strength of it.
 *
 * @param candidate the counter that just arrived
 * @param held the counter already recorded
 * @return true if the arriving counter supersedes the recorded one
 */
inline bool
RplSequenceNewer(uint8_t candidate, uint8_t held)
{
    return RplSequenceCompare(candidate, held) == RplSequenceOrder::GREATER;
}

/**
 * @brief Increment a lollipop sequence counter, RFC 6550 section 7.2 rule 2.
 *
 * "When a sequence counter increment would cause the sequence counter to
 * increment beyond its maximum value, the sequence counter MUST wrap back
 * to zero. When incrementing a sequence counter greater than or equal to
 * 128, the maximum value is 255. When incrementing a sequence counter less
 * than 128, the maximum value is 127." A plain `uint8_t` increment already
 * gets the linear region's own wrap right (255 -> 0 is exactly what
 * unsigned overflow does), but would instead carry 127 across into the
 * linear region at 128 -- not the "circular sequence number space of size
 * 128" section 7.2 itself describes the region below 128 as.
 *
 * A single-step increment lands on a value RplSequenceCompare() still
 * judges "newer" than what it replaced at every boundary regardless of
 * which of the two wrap rules applies (traced in design-constraints.md
 * section 37.6/37.7), which is why a plain, unwrapped `++` gets away with
 * it for as long as a counter's own updates stay single-step. It stops
 * holding once a real gap can open between two increments of the *same*
 * counter -- a relay outage, or a burst of parent flapping -- and the next
 * comparison has to relate two values on opposite sides of the boundary
 * rather than two adjacent ones; whichever counter that comparison
 * actually happens against needs the true RFC wrap to stay correctly
 * ordered across it. This module applies this function to every locally
 * incremented sequence counter RFC 6550 section 7 names as governed by
 * this scheme -- the DODAG Version Number, DAOSequence, and Path Sequence
 * -- plus DTSN, which section 7.1 does not name but which this module
 * still treats the same way (design-constraints.md sections 58 and 61
 * cover Path Sequence and DTSN/Version respectively). DAOSequence's own
 * comparisons (design-constraints.md section 33) are all by exact
 * equality (DAO-ACK correlation) rather than through
 * RplSequenceCompare()/RplSequenceNewer(), so which side of either wrap
 * boundary it lands on has no observable effect either way -- applied
 * here anyway, for the same reason the DODAG Version Number's own
 * "practically harmless" pre-fix argument (section 61) was not treated as
 * a reason to leave it non-conformant.
 *
 * @param value the counter's current value
 * @return the counter's value after one RFC-correct increment
 */
inline uint8_t
RplSequenceIncrement(uint8_t value)
{
    return value == RPL_SEQUENCE_LINEAR_REGION - 1 ? 0 : static_cast<uint8_t>(value + 1);
}

/// Routing Header type 3 (RFC 6554).
constexpr uint8_t RPL_RH_TYPE_SRH = 3;

/// RPL Option in a Hop-by-Hop header (RFC 6553).
constexpr uint8_t RPL_HBH_OPTION_TYPE = 0x63;
constexpr uint8_t RPL_HDR_OPT_DOWN = 0x80;     //!< 'O' flag
constexpr uint8_t RPL_HDR_OPT_RANK_ERR = 0x40; //!< 'R' flag
constexpr uint8_t RPL_HDR_OPT_FWD_ERR = 0x20;  //!< 'F' flag

/// Trickle and timer defaults, matching Contiki-NG rpl-conf.h.
constexpr uint8_t RPL_DIO_INTERVAL_MIN = 12;      //!< Imin = 2^12 ms = 4.096 s
constexpr uint8_t RPL_DIO_INTERVAL_DOUBLINGS = 8; //!< Imax = Imin << 8 ~= 17.5 min
constexpr uint8_t RPL_DIO_REDUNDANCY = 0;         //!< k = 0 disables suppression

/// DIOIntervalMin and DIOIntervalDoublings (RFC 6550 section 6.7.6) are each
/// an unconstrained wire byte (0-255), consumed as the shift-exponent
/// operand of `int64_t(1) << exponent` when converting to a Time -- a
/// shift by >= 64 is undefined behaviour, and even a shift comfortably
/// under 64 can overflow once the result is also multiplied by
/// MilliSeconds()'s own ~1e6 (2^20) nanosecond scale and, for
/// DIOIntervalDoublings specifically, multiplied again by the DODAG's
/// already-computed Imin. Clamping each exponent to this bound keeps their
/// *sum* (the worst case, Imax) safely under 63 bits even after that
/// double scaling, while still permitting an Imin or Imax far longer than
/// any real deployment would use (2^20 ms is already about 12.4 days).
constexpr uint8_t RPL_DIO_INTERVAL_EXPONENT_MAX = 20;
constexpr uint16_t RPL_MIN_HOPRANKINC = 128;
constexpr uint16_t RPL_MAX_RANKINC = 8 * RPL_MIN_HOPRANKINC;
constexpr uint16_t RPL_SIGNIFICANT_CHANGE_THRESHOLD = 4 * RPL_MIN_HOPRANKINC;
constexpr uint8_t RPL_DEFAULT_INSTANCE = 0;

/// RPLInstanceID field sub-bits for a Local instance (RFC 6550 section 5.1,
/// "|1|D|ID|"): set on the top bit to mark the field as Local rather than a
/// 7-bit Global instance number, cleared for a Global one.
constexpr uint8_t RPL_LOCAL_INSTANCE_FLAG = 0x80;
/// The Local RPLInstanceID's own 'D' flag (the second-highest bit): "always
/// set to 0 in RPL control messages" (RFC 6550 section 5.1). Only ever
/// meaningful together with RPL_LOCAL_INSTANCE_FLAG -- for a Global
/// instance this same bit is simply part of its 7-bit ID space (0..127).
constexpr uint8_t RPL_LOCAL_INSTANCE_D_FLAG = 0x40;

/// AODV-RPL (RFC 9854) RREQ/RREP option bit positions, in the first of the two
/// octets that follow Option Type and Opt Data Len. The 'L' field straddles
/// those two octets (bits 23-24 of the row in RFC 9854 sections 4.1 and 4.2),
/// so it has no single mask here -- @see RplDioHeader::Serialize().
constexpr uint8_t RPL_AODV_S_FLAG = 0x80;      //!< RREQ 'S': the route so far is symmetric
constexpr uint8_t RPL_AODV_G_FLAG = 0x80;      //!< RREP 'G': Gratuitous RREP (never set here)
constexpr uint8_t RPL_AODV_H_FLAG = 0x40;      //!< 'H': 1 hop-by-hop, 0 source routed
constexpr uint8_t RPL_AODV_COMPR_MASK = 0x1E;  //!< 'Compr', 4 bits
constexpr uint8_t RPL_AODV_COMPR_SHIFT = 1;

/// The 'RankLimit' field of the RREQ/RREP options. RFC 9854 sections 4.1 and
/// 4.2 call it "8-bit" in prose, but their own figures leave it only bits
/// 25-31 once S/G, H, X, Compr and L have taken bits 16-24 -- the prose
/// reading would make the row 33 bits wide. The figure is the only
/// dimensionally consistent reading, so seven bits it is; harmless in
/// practice, since this is compared against DAGRank() (rank divided by
/// MinHopRankIncrease), which tops out at 511 for the 16-bit ranks and
/// default MinHopRankIncrease of 128 used here and is far below 127 for any
/// realistic hop count. @see design-constraints.md.
constexpr uint8_t RPL_AODV_RANK_LIMIT_MASK = 0x7F;
/// Zero means "no limit" (RFC 9854 sections 4.1, 4.2).
constexpr uint8_t RPL_AODV_RANK_LIMIT_INFINITE = 0;

/// The 'Delta' field of the RREP option (RFC 9854 section 4.2): six bits,
/// added to the RREQ-InstanceID to obtain the RREP-InstanceID (section 6.3.3).
constexpr uint8_t RPL_AODV_DELTA_MASK = 0xFC;
constexpr uint8_t RPL_AODV_DELTA_SHIFT = 2;

/// The ART option's 'Prefix Length' field (RFC 9854 section 4.3): seven bits,
/// the top bit of that octet being the reserved 'X'. Zero means the Target
/// Prefix / Address field carries a full 128-bit address rather than a prefix.
constexpr uint8_t RPL_AODV_PREFIX_LENGTH_MASK = 0x7F;

/// The 'L' field of the RREQ/RREP options (RFC 9854 section 4.1): how long a
/// node may stay in the RREQ-Instance. Zero imposes no limit at all.
constexpr uint8_t RPL_AODV_LIFETIME_MASK = 0x03;
constexpr uint8_t RPL_AODV_LIFETIME_UNLIMITED = 0;

/**
 * @brief How long the 'L' field of an RREQ/RREP option lets a node stay in
 *        the RREQ-Instance, in seconds.
 *
 * RFC 9854 section 4.1 tabulates the two-bit field as 0x00 "no time limit
 * imposed", 0x01 16 seconds, 0x02 64 seconds, 0x03 256 seconds. Expressed in
 * seconds rather than an ns3::Time so this stays a pure-constant header.
 *
 * @param lifetimeField the 'L' field, only its low two bits are read
 * @return the duration in seconds, 0 for the "no limit" encoding
 */
constexpr uint32_t
RplAodvLifetimeSeconds(uint8_t lifetimeField)
{
    switch (lifetimeField & RPL_AODV_LIFETIME_MASK)
    {
    case 1:
        return 16;
    case 2:
        return 64;
    case 3:
        return 256;
    default:
        return 0;
    }
}

/// The P2P Route Discovery Option's (P2P-RDO, RFC 6997 section 7) flag
/// octet, the byte right after Option Length: 'R' (Reply), 'H' (Hop-by-hop),
/// 'N' (Number of Routes, 2 bits) and 'Compr' (4 bits), in that bit order --
/// unlike the AODV-RPL RREQ/RREP options, this byte has no reserved bit and
/// none of its fields straddle a byte boundary, confirmed against the RFC's
/// own bit ruler (@see design-constraints.md).
constexpr uint8_t RPL_P2P_R_FLAG = 0x80;
constexpr uint8_t RPL_P2P_H_FLAG = 0x40;
constexpr uint8_t RPL_P2P_N_MASK = 0x30;
constexpr uint8_t RPL_P2P_N_SHIFT = 4;
constexpr uint8_t RPL_P2P_COMPR_MASK = 0x0F;

/// The byte after the flag octet: 'L' (Lifetime, 2 bits) then 'MaxRank/NH'
/// (6 bits) -- the field means MaxRank inside a P2P mode DIO's P2P-RDO and
/// the Address Vector's next-hop index inside a P2P-DRO's (RFC 6997
/// sections 7, 8.2).
constexpr uint8_t RPL_P2P_LIFETIME_MASK = 0xC0;
constexpr uint8_t RPL_P2P_LIFETIME_SHIFT = 6;
constexpr uint8_t RPL_P2P_MAX_RANK_MASK = 0x3F;
/// Zero means "MaxRank is infinity" (RFC 6997 section 7).
constexpr uint8_t RPL_P2P_MAX_RANK_INFINITE = 0;

/**
 * @brief How many Address Vector entries a P2P-RDO can carry at a given
 *        Compr.
 *
 * Not a policy choice, and not a single number: it falls out of the wire
 * format, which is Compr-dependent. RFC 6997 section 7 lays the option out
 * as a 2-byte flags/L-MaxRank part followed by TargetAddr and every Address
 * Vector entry, each of them (16 - Compr) octets after prefix elision, all
 * of it counted by an eight-bit Opt Data Len. So
 * `2 + (1 + n) * (16 - Compr) <= 255`, i.e. `n <= 253 / (16 - Compr) - 1`.
 *
 * A second, independent ceiling applies on top: a P2P-DRO carries the
 * vector's own entry count in the NH field ("the NH field is set to
 * n = (Option Length - 2 - (16 - Compr)) / (16 - Compr)", section 8.2),
 * which shares its six bits with MaxRank. Past Compr 12 the length stops
 * being what binds and NH's 63 does.
 *
 * Concretely: 14 entries at Compr 0, 30 at Compr 8, 63 from Compr 13 up.
 * Applying the Compr 0 figure everywhere -- which this module did until the
 * /protocol-test-matrix audit derived this, @see design-constraints.md
 * section 79 -- truncates discoveries less than halfway into the space the
 * wire format actually offers, since P2pElidedPrefixLength() returns 8 for
 * any network sharing one /64.
 *
 * @param compr the P2P-RDO's Compr field, 0..15
 * @return the largest Address Vector entry count that fits
 */
constexpr uint8_t
RplP2pMaxAddressVectorEntries(uint8_t compr)
{
    uint32_t entrySize = 16u - (compr & RPL_P2P_COMPR_MASK);
    uint32_t blocks = 253u / entrySize; // TargetAddr plus the vector entries
    uint32_t entries = blocks > 0 ? blocks - 1 : 0;
    return static_cast<uint8_t>(entries < RPL_P2P_MAX_RANK_MASK ? entries
                                                                : RPL_P2P_MAX_RANK_MASK);
}

/// The Compr 0 figure, which is the smallest RplP2pMaxAddressVectorEntries()
/// ever returns -- what a check has to use when the Compr that will apply is
/// not yet known.
constexpr uint8_t RPL_P2P_ADDRESS_VECTOR_MAX_ENTRIES = RplP2pMaxAddressVectorEntries(0);

/// How many tied-rank routes a router keeps for RFC 6997 section 9.4's own
/// diversity ("an Intermediate Router SHOULD keep track of multiple routes").
/// The RFC puts no bound on it at all, so this one is this module's: the set
/// is filled straight from received DIOs and would otherwise grow with the
/// number of neighbours advertising a tied rank. Unrelated to how long an
/// Address Vector may be, though it once borrowed that constant because the
/// two numbers happened to coincide.
constexpr uint8_t RPL_P2P_MAX_CANDIDATE_ROUTES = 14;

/**
 * @brief How long the 'L' field of a P2P-RDO lets a node stay in the
 *        temporary DAG, in seconds.
 *
 * RFC 6997 section 7 tabulates this two-bit field as 0x00 1 second, 0x01 4
 * seconds, 0x02 16 seconds, 0x03 64 seconds -- a different mapping (and no
 * "unlimited" encoding) from the AODV-RPL RREQ/RREP options' own 'L' field,
 * @see RplAodvLifetimeSeconds().
 *
 * @param lifetimeField the 'L' field, only its low two bits are read
 * @return the duration in seconds
 */
constexpr uint32_t
RplP2pLifetimeSeconds(uint8_t lifetimeField)
{
    switch (lifetimeField & 0x03)
    {
    case 1:
        return 4;
    case 2:
        return 16;
    case 3:
        return 64;
    default:
        return 1;
    }
}

/// The P2P Discovery Reply Object's (P2P-DRO, RFC 6997 section 8) third
/// octet: 'S' (Stop), 'A' (Ack Required) and 'Seq' (2 bits), the rest of
/// that octet and the whole octet after it being Reserved.
constexpr uint8_t RPL_P2P_DRO_S_FLAG = 0x80;
constexpr uint8_t RPL_P2P_DRO_A_FLAG = 0x40;
constexpr uint8_t RPL_P2P_DRO_SEQ_MASK = 0x30;
constexpr uint8_t RPL_P2P_DRO_SEQ_SHIFT = 4;

/// The P2P-DRO Acknowledgement's (P2P-DRO-ACK, RFC 6997 section 10) third
/// octet: no 'S'/'A' here (there is nothing left to stop or to ask an ack
/// for), so 'Seq' sits where those two flags would otherwise be -- the top
/// 2 bits, not RPL_P2P_DRO_SEQ_MASK's position -- verified against the raw
/// RFC text by column-counting the same way as the P2P-DRO's own bit width
/// (@see design-constraints.md).
constexpr uint8_t RPL_P2P_DRO_ACK_SEQ_MASK = 0xC0;
constexpr uint8_t RPL_P2P_DRO_ACK_SEQ_SHIFT = 6;

/// Routing Metric/Constraint object types (RFC 6551, section 4).
constexpr uint8_t RPL_DAG_MC_LQL = 6;
constexpr uint8_t RPL_DAG_MC_ETX = 7;

/// Link Quality Level (LQL) range, RFC 6551 section 4.6: 0 means undetermined,
/// 1 is the best determined quality, 7 the worst.
constexpr uint8_t RPL_LQL_UNDETERMINED = 0;
constexpr uint8_t RPL_LQL_WORST = 7;

/// MRHOF (RFC 6719) defaults, in the same fixed-point scale as the wire
/// encoding of ETX (ETX * 128, RFC 6551 section 4.3).
constexpr uint16_t RPL_ETX_FIXED_POINT = 128;                //!< ETX * 128
constexpr uint16_t RPL_MRHOF_MAX_LINK_METRIC = 512;          //!< ETX 4.0
constexpr uint32_t RPL_MRHOF_MAX_PATH_COST = 32768;          //!< ETX 256.0
constexpr uint16_t RPL_MRHOF_PARENT_SWITCH_THRESHOLD = 192;  //!< ETX 1.5

/// Neighbour freshness, mirroring the link statistics of Contiki-NG
/// (os/net/link-stats.h). A neighbour heard only once may well be an
/// unreliable long shot, so it is not a parent until it has been heard
/// RPL_FRESHNESS_TARGET times.
constexpr uint8_t RPL_FRESHNESS_MAX = 16;
constexpr uint8_t RPL_FRESHNESS_TARGET = 4;

constexpr uint8_t RPL_DEFAULT_LIFETIME = 30;
constexpr uint16_t RPL_DEFAULT_LIFETIME_UNIT = 60;

/// Defaults for the Prefix Information option (RFC 6550 section 6.7.10),
/// matching the common Router Advertisement defaults (e.g. radvd's).
constexpr uint32_t RPL_PREFIX_VALID_LIFETIME = 86400;     //!< 1 day
constexpr uint32_t RPL_PREFIX_PREFERRED_LIFETIME = 14400; //!< 4 hours

/// All-RPL-nodes link-local multicast address (RFC 6550, section 6).
constexpr const char* RPL_ALL_NODES_MULTICAST = "ff02::1a";

/// ICMPv6 Destination Unreachable code for a Source Route Header naming a
/// next hop this router cannot forward to, either because it is not on-link
/// (RFC 6554 section 4.2) or because the header names this router's own
/// address twice with something else in between, a routing loop (also
/// section 4.2). ns-3 core has no named constant for this RFC 6554-defined
/// code.
constexpr uint8_t RPL_ICMPV6_SRH_ERROR = 7;

} // namespace rpl
} // namespace ns3

#endif /* RPL_CONF_H */
