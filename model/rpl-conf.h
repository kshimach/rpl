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
constexpr uint8_t RPL_DAG_MC_ETX = 7;

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

/// All-RPL-nodes link-local multicast address (RFC 6550, section 6).
constexpr const char* RPL_ALL_NODES_MULTICAST = "ff02::1a";

} // namespace rpl
} // namespace ns3

#endif /* RPL_CONF_H */
