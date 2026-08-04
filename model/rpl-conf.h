/*
 * Copyright (c) 2026 ns-3 RPL module contributors
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
};

/// Mode of Operation (RFC 6550, section 20.14). Only NON_STORING is implemented.
enum RplMop : uint8_t
{
    RPL_MOP_NO_DOWNWARD_ROUTES = 0,
    RPL_MOP_NON_STORING = 1,
    RPL_MOP_STORING_NO_MULTICAST = 2,
    RPL_MOP_STORING_MULTICAST = 3,
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
constexpr uint16_t RPL_MIN_HOPRANKINC = 128;
constexpr uint16_t RPL_MAX_RANKINC = 8 * RPL_MIN_HOPRANKINC;
constexpr uint16_t RPL_SIGNIFICANT_CHANGE_THRESHOLD = 4 * RPL_MIN_HOPRANKINC;
constexpr uint8_t RPL_DEFAULT_INSTANCE = 0;

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
