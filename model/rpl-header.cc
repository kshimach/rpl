/*
 * Copyright (c) 2026 ns-3 RPL module contributors
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "rpl-header.h"

#include "ns3/log.h"

#include <algorithm>
#include <limits>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("RplHeader");

namespace rpl
{

NS_OBJECT_ENSURE_REGISTERED(RplDisHeader);

RplDisHeader::RplDisHeader()
{
}

TypeId
RplDisHeader::GetTypeId()
{
    static TypeId tid = TypeId("ns3::rpl::RplDisHeader")
                            .SetParent<Header>()
                            .SetGroupName("Rpl")
                            .AddConstructor<RplDisHeader>();
    return tid;
}

TypeId
RplDisHeader::GetInstanceTypeId() const
{
    return GetTypeId();
}

void
RplDisHeader::Print(std::ostream& os) const
{
    os << "DIS";
}

uint32_t
RplDisHeader::GetSerializedSize() const
{
    return 2;
}

void
RplDisHeader::Serialize(Buffer::Iterator start) const
{
    start.WriteU8(0); // Flags
    start.WriteU8(0); // Reserved
}

uint32_t
RplDisHeader::Deserialize(Buffer::Iterator start)
{
    Buffer::Iterator i = start;
    i.ReadU8();
    i.ReadU8();
    return i.GetDistanceFrom(start);
}

namespace
{

/**
 * @brief How many leading octets a P2P-RDO's TargetAddr and Address Vector
 *        can elide, RFC 6997 section 7's Compr field.
 *
 * Mirrors RplDioHeader::ElidedPrefixLength()'s 0-or-8 heuristic (@see
 * design-constraints.md), extended to also require TargetAddr itself to
 * share the prefix: unlike the AODV-RPL RREQ/RREP options, whose ART option
 * carries the target address separately and always in full, RFC 6997
 * section 7 elides Compr octets "from the Target field and the Address
 * vector" alike.
 *
 * @param target the option's TargetAddr
 * @param addressVector the option's Address Vector
 * @param dodagId the DODAGID of the enclosing message
 * @return 8 if target and every addressVector entry share their first 8
 *         octets with dodagId, 0 otherwise
 */
uint8_t
P2pElidedPrefixLength(Ipv6Address target,
                      const std::vector<Ipv6Address>& addressVector,
                      Ipv6Address dodagId)
{
    uint8_t dodagIdBuf[16];
    dodagId.Serialize(dodagIdBuf);

    uint8_t targetBuf[16];
    target.Serialize(targetBuf);
    if (!std::equal(dodagIdBuf, dodagIdBuf + 8, targetBuf))
    {
        return 0;
    }
    for (const auto& address : addressVector)
    {
        uint8_t addressBuf[16];
        address.Serialize(addressBuf);
        if (!std::equal(dodagIdBuf, dodagIdBuf + 8, addressBuf))
        {
            return 0;
        }
    }
    return 8;
}

} // namespace

uint32_t
P2pRdoSerializedSize(const P2pRdoOption& rdo, Ipv6Address dodagId)
{
    uint8_t compr = P2pElidedPrefixLength(rdo.target, rdo.addressVector, dodagId);
    uint8_t entrySize = static_cast<uint8_t>(16 - compr);
    // Type + Length (2) + flags + L/MaxRank (2) + TargetAddr and each
    // Address Vector entry, all entrySize octets after Compr elision.
    return 4 + (1 + rdo.addressVector.size()) * entrySize;
}

void
P2pRdoSerialize(Buffer::Iterator& i, const P2pRdoOption& rdo, Ipv6Address dodagId)
{
    uint8_t compr = P2pElidedPrefixLength(rdo.target, rdo.addressVector, dodagId);
    uint8_t entrySize = static_cast<uint8_t>(16 - compr);
    uint8_t length =
        static_cast<uint8_t>(2 + (1 + rdo.addressVector.size()) * entrySize);

    i.WriteU8(RPL_OPTION_P2P_RDO);
    i.WriteU8(length);
    i.WriteU8(static_cast<uint8_t>(
        (rdo.reply ? RPL_P2P_R_FLAG : 0) | (rdo.hopByHop ? RPL_P2P_H_FLAG : 0) |
        ((rdo.numRoutes << RPL_P2P_N_SHIFT) & RPL_P2P_N_MASK) | (compr & RPL_P2P_COMPR_MASK)));
    i.WriteU8(static_cast<uint8_t>(
        ((rdo.lifetime << RPL_P2P_LIFETIME_SHIFT) & RPL_P2P_LIFETIME_MASK) |
        (rdo.maxRankOrNh & RPL_P2P_MAX_RANK_MASK)));

    uint8_t targetBuf[16];
    rdo.target.Serialize(targetBuf);
    i.Write(targetBuf + compr, entrySize);

    for (const auto& address : rdo.addressVector)
    {
        uint8_t addressBuf[16];
        address.Serialize(addressBuf);
        i.Write(addressBuf + compr, entrySize);
    }
}

bool
P2pRdoDeserialize(Buffer::Iterator& i, uint8_t length, Ipv6Address dodagId, P2pRdoOption& rdo)
{
    if (length < 2)
    {
        // Not even the flags/L-MaxRank bytes fit; nothing of the declared
        // span has been consumed yet, so consume it all now for the caller.
        i.Next(length);
        return false;
    }
    uint8_t flags = i.ReadU8();
    uint8_t limits = i.ReadU8();
    uint8_t compr = flags & RPL_P2P_COMPR_MASK;
    uint8_t entrySize = static_cast<uint8_t>(16 - compr);
    uint8_t remaining = static_cast<uint8_t>(length - 2);
    uint8_t blocks = static_cast<uint8_t>(remaining / entrySize);
    if (remaining % entrySize != 0 || blocks < 1 ||
        static_cast<uint8_t>(blocks - 1) > RPL_P2P_ADDRESS_VECTOR_MAX_ENTRIES)
    {
        NS_LOG_LOGIC("Skipping a malformed P2P-RDO (Compr " << +compr << ", length " << +length
                                                             << ")");
        // flags/limits (2 bytes) already consumed of length's total.
        i.Next(static_cast<uint8_t>(length - 2));
        return false;
    }
    uint8_t entries = static_cast<uint8_t>(blocks - 1);

    rdo.reply = (flags & RPL_P2P_R_FLAG) != 0;
    rdo.hopByHop = (flags & RPL_P2P_H_FLAG) != 0;
    rdo.numRoutes = (flags & RPL_P2P_N_MASK) >> RPL_P2P_N_SHIFT;
    rdo.compr = compr;
    rdo.lifetime = (limits & RPL_P2P_LIFETIME_MASK) >> RPL_P2P_LIFETIME_SHIFT;
    rdo.maxRankOrNh = limits & RPL_P2P_MAX_RANK_MASK;

    uint8_t dodagIdBuf[16];
    dodagId.Serialize(dodagIdBuf);

    uint8_t targetBuf[16] = {0};
    std::copy(dodagIdBuf, dodagIdBuf + compr, targetBuf);
    i.Read(targetBuf + compr, entrySize);
    rdo.target = Ipv6Address::Deserialize(targetBuf);

    rdo.addressVector.clear();
    for (uint8_t entry = 0; entry < entries; entry++)
    {
        uint8_t addressBuf[16] = {0};
        std::copy(dodagIdBuf, dodagIdBuf + compr, addressBuf);
        i.Read(addressBuf + compr, entrySize);
        rdo.addressVector.push_back(Ipv6Address::Deserialize(addressBuf));
    }
    return true;
}

NS_OBJECT_ENSURE_REGISTERED(RplDioHeader);

RplDioHeader::RplDioHeader()
    : m_instanceId(RPL_DEFAULT_INSTANCE),
      m_versionNumber(0),
      m_rank(RPL_INFINITE_RANK),
      m_grounded(false),
      m_mop(RPL_MOP_NON_STORING),
      m_preference(0),
      m_dtsn(0),
      m_dodagId(Ipv6Address::GetAny()),
      m_hasDagConf(false),
      m_dagConfFlags(0),
      m_intervalDoublings(RPL_DIO_INTERVAL_DOUBLINGS),
      m_intervalMin(RPL_DIO_INTERVAL_MIN),
      m_redundancy(RPL_DIO_REDUNDANCY),
      m_maxRankIncrease(RPL_MAX_RANKINC),
      m_minHopRankIncrease(RPL_MIN_HOPRANKINC),
      m_ocp(RPL_OCP_OF0),
      m_defaultLifetime(RPL_DEFAULT_LIFETIME),
      m_lifetimeUnit(RPL_DEFAULT_LIFETIME_UNIT),
      m_hasMetricContainer(false),
      m_pathEtx(0),
      m_hasLql(false),
      m_lql(0),
      m_hasPrefixInfo(false),
      m_prefix(Ipv6Address::GetAny()),
      m_prefixLength(0),
      m_prefixOnLink(false),
      m_prefixAutonomous(false),
      m_prefixValidLifetime(0),
      m_prefixPreferredLifetime(0),
      m_hasRreq(false),
      m_hasRrep(false),
      m_hasP2pRdo(false)
{
}

TypeId
RplDioHeader::GetTypeId()
{
    static TypeId tid = TypeId("ns3::rpl::RplDioHeader")
                            .SetParent<Header>()
                            .SetGroupName("Rpl")
                            .AddConstructor<RplDioHeader>();
    return tid;
}

TypeId
RplDioHeader::GetInstanceTypeId() const
{
    return GetTypeId();
}

void
RplDioHeader::Print(std::ostream& os) const
{
    os << "DIO instance " << +m_instanceId << " DODAGID " << m_dodagId << " version "
       << +m_versionNumber << " rank " << m_rank << " MOP " << +m_mop << " DTSN " << +m_dtsn;
    if (m_grounded)
    {
        os << " grounded";
    }
    if (m_hasDagConf)
    {
        os << " OCP " << m_ocp << " MinHopRankIncrease " << m_minHopRankIncrease;
    }
    if (m_hasMetricContainer)
    {
        os << " pathETX " << (static_cast<double>(m_pathEtx) / RPL_ETX_FIXED_POINT);
    }
    if (m_hasLql)
    {
        os << " LQL " << +m_lql;
    }
    if (m_hasPrefixInfo)
    {
        os << " prefix " << m_prefix << "/" << +m_prefixLength;
    }
    if (m_hasRreq)
    {
        os << " RREQ" << (m_rreq.symmetric ? " S" : "") << (m_rreq.hopByHop ? " H" : "")
           << " OrigSeqNo " << +m_rreq.origSeqNo << " RankLimit " << +m_rreq.rankLimit
           << " AV " << m_rreq.addressVector.size();
    }
    if (m_hasRrep)
    {
        os << " RREP" << (m_rrep.gratuitous ? " G" : "") << (m_rrep.hopByHop ? " H" : "")
           << " Delta " << +m_rrep.delta << " RankLimit " << +m_rrep.rankLimit
           << " AV " << m_rrep.addressVector.size();
    }
    for (const auto& art : m_arts)
    {
        os << " ART " << art.target << "/" << +art.prefixLength << " DestSeqNo "
           << +art.destSeqNo;
    }
    if (m_hasP2pRdo)
    {
        os << " P2P-RDO" << (m_p2pRdo.reply ? " R" : "") << (m_p2pRdo.hopByHop ? " H" : "")
           << " Target " << m_p2pRdo.target << " MaxRank " << +m_p2pRdo.maxRankOrNh << " AV "
           << m_p2pRdo.addressVector.size();
    }
    if (!m_targets.empty())
    {
        os << " +" << m_targets.size() << " Target option(s)";
    }
}

uint8_t
RplDioHeader::ElidedPrefixLength(const std::vector<Ipv6Address>& addressVector) const
{
    if (addressVector.empty())
    {
        return 0;
    }
    uint8_t dodagIdBuf[16];
    m_dodagId.Serialize(dodagIdBuf);
    for (const auto& address : addressVector)
    {
        uint8_t addressBuf[16];
        address.Serialize(addressBuf);
        if (!std::equal(dodagIdBuf, dodagIdBuf + 8, addressBuf))
        {
            return 0;
        }
    }
    return 8;
}

uint32_t
RplDioHeader::GetSerializedSize() const
{
    return 24 + (m_hasDagConf ? DAG_CONF_OPTION_SIZE : 0) +
           (m_hasMetricContainer ? METRIC_CONTAINER_OPTION_SIZE : 0) +
           (m_hasLql ? LQL_OPTION_SIZE : 0) +
           (m_hasPrefixInfo ? PREFIX_INFO_OPTION_SIZE : 0) +
           (m_hasRreq ? 2 + AODV_RREQ_OPTION_BASE_LENGTH +
                            m_rreq.addressVector.size() *
                                (AODV_ADDRESS_VECTOR_ENTRY_SIZE -
                                 ElidedPrefixLength(m_rreq.addressVector))
                      : 0) +
           (m_hasRrep ? 2 + AODV_RREP_OPTION_BASE_LENGTH +
                            m_rrep.addressVector.size() *
                                (AODV_ADDRESS_VECTOR_ENTRY_SIZE -
                                 ElidedPrefixLength(m_rrep.addressVector))
                      : 0) +
           m_arts.size() * AODV_ART_OPTION_SIZE +
           (m_hasP2pRdo ? P2pRdoSerializedSize(m_p2pRdo, m_dodagId) : 0) +
           m_targets.size() * TARGET_OPTION_SIZE;
}

void
RplDioHeader::Serialize(Buffer::Iterator start) const
{
    start.WriteU8(m_instanceId);
    start.WriteU8(m_versionNumber);
    start.WriteHtonU16(m_rank);

    uint8_t flags = (m_grounded ? RPL_DIO_GROUNDED : 0);
    flags |= (m_mop << RPL_DIO_MOP_SHIFT) & RPL_DIO_MOP_MASK;
    flags |= m_preference & RPL_DIO_PREFERENCE_MASK;
    start.WriteU8(flags);

    start.WriteU8(m_dtsn);
    start.WriteU8(0); // Flags
    start.WriteU8(0); // Reserved

    uint8_t buf[16];
    m_dodagId.Serialize(buf);
    start.Write(buf, 16);

    if (m_hasDagConf)
    {
        start.WriteU8(RPL_OPTION_DAG_CONF);
        start.WriteU8(DAG_CONF_OPTION_LENGTH);
        start.WriteU8(m_dagConfFlags);
        start.WriteU8(m_intervalDoublings);
        start.WriteU8(m_intervalMin);
        start.WriteU8(m_redundancy);
        start.WriteHtonU16(m_maxRankIncrease);
        start.WriteHtonU16(m_minHopRankIncrease);
        start.WriteHtonU16(m_ocp);
        start.WriteU8(0); // Reserved
        start.WriteU8(m_defaultLifetime);
        start.WriteHtonU16(m_lifetimeUnit);
    }

    if (m_hasMetricContainer)
    {
        start.WriteU8(RPL_OPTION_DAG_METRIC_CONTAINER);
        start.WriteU8(METRIC_CONTAINER_OPTION_LENGTH);
        start.WriteU8(RPL_DAG_MC_ETX);
        start.WriteU8(0); // Res+P+C+O+R, RFC 6551 section 2.1: a plain metric,
                          // not a constraint, that could be recorded
        start.WriteU8(0); // A+Prec: A=0 (additive, RFC 6551 section 3), no
                          // precedence
        start.WriteU8(2); // Object body length: the 16-bit ETX value below
        start.WriteHtonU16(m_pathEtx);
    }

    if (m_hasLql)
    {
        start.WriteU8(RPL_OPTION_DAG_METRIC_CONTAINER);
        start.WriteU8(LQL_OPTION_LENGTH);
        start.WriteU8(RPL_DAG_MC_LQL);
        start.WriteU8(0); // Res+P+C+O+R: a plain, recorded-only link metric
        start.WriteU8(0); // A+Prec: not aggregated path-wise, no precedence
        start.WriteU8(2); // Object body length: Res octet + one LQL sub-object
        start.WriteU8(0); // Res (RFC 6551 section 4.6)
        // LQL Type 1 sub-object: Val (this link's LQL) in the high nibble,
        // Counter in the low nibble. This implementation always reports
        // exactly one sample (its own link to its preferred parent), never a
        // multi-hop histogram, so Counter is always 1.
        start.WriteU8(static_cast<uint8_t>((m_lql << 4) | 0x1));
    }

    if (m_hasPrefixInfo)
    {
        start.WriteU8(RPL_OPTION_PREFIX_INFO);
        start.WriteU8(PREFIX_INFO_OPTION_LENGTH);
        start.WriteU8(m_prefixLength);
        uint8_t prefixFlags = (m_prefixOnLink ? PREFIX_INFO_L_FLAG : 0) |
                              (m_prefixAutonomous ? PREFIX_INFO_A_FLAG : 0);
        start.WriteU8(prefixFlags); // Reserved1 in the low 6 bits, always 0
        start.WriteHtonU32(m_prefixValidLifetime);
        start.WriteHtonU32(m_prefixPreferredLifetime);
        uint8_t prefixBuf[16];
        m_prefix.Serialize(prefixBuf);
        start.Write(prefixBuf, 16);
    }

    // The AODV-RPL options (RFC 9854) come last, after every RFC 6550 option
    // above, purely so adding them left the byte offsets of the existing
    // ones alone. Nothing in the RFCs orders the option list.
    //
    // 'L' straddles the two flag octets in both the RREQ and the RREP option
    // (bits 23-24 of their rows in RFC 9854 sections 4.1 and 4.2): its high
    // bit is the last bit of the first octet, its low bit the top bit of the
    // second, which is why neither can be written with a single mask.
    if (m_hasRreq)
    {
        uint8_t rreqCompr = ElidedPrefixLength(m_rreq.addressVector);
        start.WriteU8(RPL_OPTION_AODV_RREQ);
        start.WriteU8(static_cast<uint8_t>(
            AODV_RREQ_OPTION_BASE_LENGTH +
            m_rreq.addressVector.size() * (AODV_ADDRESS_VECTOR_ENTRY_SIZE - rreqCompr)));
        start.WriteU8(static_cast<uint8_t>((m_rreq.symmetric ? RPL_AODV_S_FLAG : 0) |
                                           (m_rreq.hopByHop ? RPL_AODV_H_FLAG : 0) |
                                           ((rreqCompr << RPL_AODV_COMPR_SHIFT) &
                                            RPL_AODV_COMPR_MASK) |
                                           ((m_rreq.lifetime >> 1) & AODV_LIFETIME_HIGH_BIT)));
        start.WriteU8(static_cast<uint8_t>(((m_rreq.lifetime & 0x01) ? AODV_LIFETIME_LOW_BIT : 0) |
                                           (m_rreq.rankLimit & RPL_AODV_RANK_LIMIT_MASK)));
        start.WriteU8(m_rreq.origSeqNo);
        for (const auto& address : m_rreq.addressVector)
        {
            uint8_t addressBuf[16];
            address.Serialize(addressBuf);
            start.Write(addressBuf + rreqCompr, 16 - rreqCompr);
        }
    }

    if (m_hasRrep)
    {
        uint8_t rrepCompr = ElidedPrefixLength(m_rrep.addressVector);
        start.WriteU8(RPL_OPTION_AODV_RREP);
        start.WriteU8(static_cast<uint8_t>(
            AODV_RREP_OPTION_BASE_LENGTH +
            m_rrep.addressVector.size() * (AODV_ADDRESS_VECTOR_ENTRY_SIZE - rrepCompr)));
        start.WriteU8(static_cast<uint8_t>((m_rrep.gratuitous ? RPL_AODV_G_FLAG : 0) |
                                           (m_rrep.hopByHop ? RPL_AODV_H_FLAG : 0) |
                                           ((rrepCompr << RPL_AODV_COMPR_SHIFT) &
                                            RPL_AODV_COMPR_MASK) |
                                           ((m_rrep.lifetime >> 1) & AODV_LIFETIME_HIGH_BIT)));
        start.WriteU8(static_cast<uint8_t>(((m_rrep.lifetime & 0x01) ? AODV_LIFETIME_LOW_BIT : 0) |
                                           (m_rrep.rankLimit & RPL_AODV_RANK_LIMIT_MASK)));
        // Delta occupies the top six bits, the low two being reserved.
        start.WriteU8(static_cast<uint8_t>((m_rrep.delta << RPL_AODV_DELTA_SHIFT) &
                                           RPL_AODV_DELTA_MASK));
        for (const auto& address : m_rrep.addressVector)
        {
            uint8_t addressBuf[16];
            address.Serialize(addressBuf);
            start.Write(addressBuf + rrepCompr, 16 - rrepCompr);
        }
    }

    // RFC 9854 section 6.1: "The OrigNode can initiate the route discovery
    // process for multiple targets simultaneously by including multiple ART
    // options" -- any number, one per TargNode being sought.
    for (const auto& art : m_arts)
    {
        start.WriteU8(RPL_OPTION_AODV_ART);
        start.WriteU8(AODV_ART_OPTION_LENGTH);
        start.WriteU8(art.destSeqNo);
        // The top bit of this octet is the reserved 'X', always zero.
        start.WriteU8(static_cast<uint8_t>(art.prefixLength & RPL_AODV_PREFIX_LENGTH_MASK));
        uint8_t targetBuf[16];
        art.target.Serialize(targetBuf);
        start.Write(targetBuf, 16);
    }

    if (m_hasP2pRdo)
    {
        P2pRdoSerialize(start, m_p2pRdo, m_dodagId);
    }

    // RFC 6997's own reuse of RFC 6550 section 6.7.7: any number of these,
    // one per additional Target beyond the P2P-RDO's own primary one.
    for (const auto& targetOption : m_targets)
    {
        start.WriteU8(RPL_OPTION_TARGET);
        start.WriteU8(TARGET_OPTION_LENGTH);
        start.WriteU8(0); // Flags, reserved
        start.WriteU8(targetOption.prefixLength);
        uint8_t targetOptionBuf[16];
        targetOption.target.Serialize(targetOptionBuf);
        start.Write(targetOptionBuf, 16);
    }
}

uint32_t
RplDioHeader::Deserialize(Buffer::Iterator start)
{
    Buffer::Iterator i = start;

    m_instanceId = i.ReadU8();
    m_versionNumber = i.ReadU8();
    m_rank = i.ReadNtohU16();

    uint8_t flags = i.ReadU8();
    m_grounded = (flags & RPL_DIO_GROUNDED) != 0;
    m_mop = (flags & RPL_DIO_MOP_MASK) >> RPL_DIO_MOP_SHIFT;
    m_preference = flags & RPL_DIO_PREFERENCE_MASK;

    m_dtsn = i.ReadU8();
    i.ReadU8(); // Flags
    i.ReadU8(); // Reserved

    uint8_t buf[16];
    i.Read(buf, 16);
    m_dodagId = Ipv6Address::Deserialize(buf);

    // The DIO is the last thing in the packet, so the end of the buffer is the
    // end of the option list.
    m_hasDagConf = false;
    m_hasMetricContainer = false;
    m_hasLql = false;
    m_hasPrefixInfo = false;
    m_hasRreq = false;
    m_hasRrep = false;
    m_hasP2pRdo = false;
    m_arts.clear();
    m_targets.clear();
    while (!i.IsEnd())
    {
        uint8_t type = i.ReadU8();
        if (type == RPL_OPTION_PAD1)
        {
            continue;
        }
        if (i.IsEnd())
        {
            NS_LOG_WARN("Truncated RPL option " << +type << ", stopping");
            break;
        }
        uint8_t length = i.ReadU8();

        // length is the attacker-controlled Option Length field: every branch
        // below trusts it (directly, or indirectly via the *_OPTION_LENGTH
        // equality checks) to read that many bytes. Buffer::Iterator has no
        // bounds checking of its own in an optimized build (PeekU8()'s range
        // check is an NS_ASSERT, compiled out there), so a declared length
        // longer than what is actually left in a truncated or malformed
        // packet would read (and, for the option types below, use as field
        // values) memory past the buffer's end instead of stopping cleanly
        // the way a debug build's assertion failure would.
        if (i.GetRemainingSize() < length)
        {
            NS_LOG_WARN("Truncated RPL option "
                        << +type << " (declared length " << +length << ", only "
                        << i.GetRemainingSize() << " bytes remain), stopping");
            break;
        }

        if (type == RPL_OPTION_DAG_CONF && length == DAG_CONF_OPTION_LENGTH)
        {
            m_hasDagConf = true;
            m_dagConfFlags = i.ReadU8();
            m_intervalDoublings = i.ReadU8();
            m_intervalMin = i.ReadU8();
            m_redundancy = i.ReadU8();
            m_maxRankIncrease = i.ReadNtohU16();
            m_minHopRankIncrease = i.ReadNtohU16();
            m_ocp = i.ReadNtohU16();
            i.ReadU8(); // Reserved
            m_defaultLifetime = i.ReadU8();
            m_lifetimeUnit = i.ReadNtohU16();
        }
        else if (type == RPL_OPTION_DAG_METRIC_CONTAINER &&
                 length == METRIC_CONTAINER_OPTION_LENGTH)
        {
            uint8_t mcType = i.ReadU8();
            i.ReadU8();          // Res+P+C+O+R, not checked: this implementation
                                 // only ever sends the plain additive metric it
                                 // expects back
            i.ReadU8();          // A+Prec, likewise not checked
            uint8_t objLength = i.ReadU8();
            if (mcType == RPL_DAG_MC_ETX && objLength == 2)
            {
                m_hasMetricContainer = true;
                m_pathEtx = i.ReadNtohU16();
            }
            else if (mcType == RPL_DAG_MC_LQL && objLength == 2)
            {
                i.ReadU8(); // Res (RFC 6551 section 4.6), not checked
                uint8_t subObject = i.ReadU8();
                m_hasLql = true;
                // Val, the high nibble; Counter (low nibble) not checked,
                // always 1 here. Clamped to keep GetLql()'s documented
                // 0-7 range even if a peer sends a Val above RPL_LQL_WORST.
                m_lql = std::min<uint8_t>(subObject >> 4, RPL_LQL_WORST);
            }
            else
            {
                NS_LOG_LOGIC("Skipping a Routing Metric/Constraint object of "
                            << "unsupported type " << +mcType);
                // objLength is attacker-controlled and must not drive the
                // seek: the option's total size was already validated above
                // (length == METRIC_CONTAINER_OPTION_LENGTH), so skip only
                // the bytes that are actually left in it (4 header bytes --
                // mcType, Res+P+C+O+R, A+Prec, objLength -- already consumed).
                i.Next(METRIC_CONTAINER_OPTION_LENGTH - 4);
            }
        }
        else if (type == RPL_OPTION_PREFIX_INFO && length == PREFIX_INFO_OPTION_LENGTH)
        {
            m_hasPrefixInfo = true;
            m_prefixLength = i.ReadU8();
            uint8_t prefixFlags = i.ReadU8();
            m_prefixOnLink = (prefixFlags & PREFIX_INFO_L_FLAG) != 0;
            m_prefixAutonomous = (prefixFlags & PREFIX_INFO_A_FLAG) != 0;
            m_prefixValidLifetime = i.ReadNtohU32();
            m_prefixPreferredLifetime = i.ReadNtohU32();
            uint8_t prefixBuf[16];
            i.Read(prefixBuf, 16);
            m_prefix = Ipv6Address::Deserialize(prefixBuf);
        }
        // The AODV-RPL RREQ/RREP options (RFC 9854 sections 4.1, 4.2) are the
        // only variable-length options here, so they cannot use the exact
        // `length == <X>_OPTION_LENGTH` guard every option above does. It is
        // still the option's own declared length that is being checked
        // rather than trusted -- the loop already refused a length longer
        // than the packet, and no arithmetic below reads past what this
        // check accounts for.
        //
        // The shape check itself needs Compr, which is inside the option's
        // own content rather than in type/length -- unlike every guard
        // above, this cannot be decided before reading part of the option,
        // so the length/entry-count check moves inside the branch instead,
        // with the same "declared length trusted, but validated, then
        // skipped over if it does not check out" recovery the metric
        // container option above uses for its own sub-validation.
        else if (type == RPL_OPTION_AODV_RREQ && length >= AODV_RREQ_OPTION_BASE_LENGTH)
        {
            uint8_t flags = i.ReadU8();
            uint8_t limits = i.ReadU8();
            uint8_t compr = (flags & RPL_AODV_COMPR_MASK) >> RPL_AODV_COMPR_SHIFT;
            uint8_t entrySize = static_cast<uint8_t>(AODV_ADDRESS_VECTOR_ENTRY_SIZE - compr);
            uint8_t remaining = static_cast<uint8_t>(length - AODV_RREQ_OPTION_BASE_LENGTH);
            uint8_t entries = static_cast<uint8_t>(remaining / entrySize);
            if (remaining % entrySize != 0 || entries > AODV_ADDRESS_VECTOR_MAX_ENTRIES)
            {
                NS_LOG_LOGIC("Skipping a malformed AODV-RPL RREQ option (Compr "
                            << +compr << ", length " << +length << ")");
                // flags and limits (2 bytes) already read of length's total;
                // Orig SeqNo has not been, unlike remaining above (which
                // subtracts the full 3-byte base for the entries math).
                i.Next(static_cast<uint8_t>(length - 2));
                continue;
            }
            m_hasRreq = true;
            m_rreq.symmetric = (flags & RPL_AODV_S_FLAG) != 0;
            m_rreq.hopByHop = (flags & RPL_AODV_H_FLAG) != 0;
            m_rreq.compr = compr;
            m_rreq.lifetime = static_cast<uint8_t>(((flags & AODV_LIFETIME_HIGH_BIT) << 1) |
                                                   ((limits & AODV_LIFETIME_LOW_BIT) ? 1 : 0));
            m_rreq.rankLimit = limits & RPL_AODV_RANK_LIMIT_MASK;
            m_rreq.origSeqNo = i.ReadU8();
            m_rreq.addressVector.clear();
            // RFC 9854 section 4.1: the elided octets are shared with the
            // DODAGID, already deserialized above (the DIO's fixed fields
            // precede its options on the wire).
            uint8_t dodagIdBuf[16];
            m_dodagId.Serialize(dodagIdBuf);
            for (uint8_t entry = 0; entry < entries; entry++)
            {
                uint8_t addressBuf[16] = {0};
                std::copy(dodagIdBuf, dodagIdBuf + compr, addressBuf);
                i.Read(addressBuf + compr, entrySize);
                m_rreq.addressVector.push_back(Ipv6Address::Deserialize(addressBuf));
            }
        }
        else if (type == RPL_OPTION_AODV_RREP && length >= AODV_RREP_OPTION_BASE_LENGTH)
        {
            uint8_t flags = i.ReadU8();
            uint8_t limits = i.ReadU8();
            uint8_t compr = (flags & RPL_AODV_COMPR_MASK) >> RPL_AODV_COMPR_SHIFT;
            uint8_t entrySize = static_cast<uint8_t>(AODV_ADDRESS_VECTOR_ENTRY_SIZE - compr);
            uint8_t remaining = static_cast<uint8_t>(length - AODV_RREP_OPTION_BASE_LENGTH);
            uint8_t entries = static_cast<uint8_t>(remaining / entrySize);
            if (remaining % entrySize != 0 || entries > AODV_ADDRESS_VECTOR_MAX_ENTRIES)
            {
                NS_LOG_LOGIC("Skipping a malformed AODV-RPL RREP option (Compr "
                            << +compr << ", length " << +length << ")");
                // flags and limits (2 bytes) already read of length's total;
                // Delta has not been, unlike remaining above (which
                // subtracts the full 3-byte base for the entries math).
                i.Next(static_cast<uint8_t>(length - 2));
                continue;
            }
            m_hasRrep = true;
            m_rrep.gratuitous = (flags & RPL_AODV_G_FLAG) != 0;
            m_rrep.hopByHop = (flags & RPL_AODV_H_FLAG) != 0;
            m_rrep.compr = compr;
            m_rrep.lifetime = static_cast<uint8_t>(((flags & AODV_LIFETIME_HIGH_BIT) << 1) |
                                                   ((limits & AODV_LIFETIME_LOW_BIT) ? 1 : 0));
            m_rrep.rankLimit = limits & RPL_AODV_RANK_LIMIT_MASK;
            m_rrep.delta = (i.ReadU8() & RPL_AODV_DELTA_MASK) >> RPL_AODV_DELTA_SHIFT;
            m_rrep.addressVector.clear();
            uint8_t dodagIdBuf[16];
            m_dodagId.Serialize(dodagIdBuf);
            for (uint8_t entry = 0; entry < entries; entry++)
            {
                uint8_t addressBuf[16] = {0};
                std::copy(dodagIdBuf, dodagIdBuf + compr, addressBuf);
                i.Read(addressBuf + compr, entrySize);
                m_rrep.addressVector.push_back(Ipv6Address::Deserialize(addressBuf));
            }
        }
        else if (type == RPL_OPTION_AODV_ART && length == AODV_ART_OPTION_LENGTH)
        {
            // May appear any number of times (RFC 9854 section 6.1), unlike
            // RREQ/RREP/P2P-RDO above, which a DIO carries at most one of.
            ArtOption art;
            art.destSeqNo = i.ReadU8();
            // The top bit is the reserved 'X', ignored on receipt per RFC
            // 9854 section 4.3.
            art.prefixLength = i.ReadU8() & RPL_AODV_PREFIX_LENGTH_MASK;
            uint8_t targetBuf[16];
            i.Read(targetBuf, 16);
            art.target = Ipv6Address::Deserialize(targetBuf);
            m_arts.push_back(art);
        }
        else if (type == RPL_OPTION_P2P_RDO)
        {
            // P2pRdoDeserialize() itself validates length against Compr and
            // the Address Vector entry count, and always leaves i exactly
            // length bytes further along, success or not -- the same
            // "declared length trusted, but validated" contract the AODV-RPL
            // RREQ/RREP branches above follow.
            m_hasP2pRdo = P2pRdoDeserialize(i, length, m_dodagId, m_p2pRdo);
        }
        else if (type == RPL_OPTION_TARGET && length == TARGET_OPTION_LENGTH)
        {
            // May appear any number of times (RFC 6997's own reuse of RFC
            // 6550 section 6.7.7), unlike every other option above, which a
            // P2P mode DIO carries at most one of.
            TargetOption targetOption;
            i.ReadU8(); // Flags, reserved
            targetOption.prefixLength = i.ReadU8();
            uint8_t targetOptionBuf[16];
            i.Read(targetOptionBuf, 16);
            targetOption.target = Ipv6Address::Deserialize(targetOptionBuf);
            m_targets.push_back(targetOption);
        }
        else
        {
            NS_LOG_LOGIC("Skipping RPL option " << +type << " of length " << +length);
            i.Next(length);
        }
    }

    return i.GetDistanceFrom(start);
}

void
RplDioHeader::SetInstanceId(uint8_t instanceId)
{
    m_instanceId = instanceId;
}

uint8_t
RplDioHeader::GetInstanceId() const
{
    return m_instanceId;
}

void
RplDioHeader::SetVersionNumber(uint8_t version)
{
    m_versionNumber = version;
}

uint8_t
RplDioHeader::GetVersionNumber() const
{
    return m_versionNumber;
}

void
RplDioHeader::SetRank(uint16_t rank)
{
    m_rank = rank;
}

uint16_t
RplDioHeader::GetRank() const
{
    return m_rank;
}

void
RplDioHeader::SetGrounded(bool grounded)
{
    m_grounded = grounded;
}

bool
RplDioHeader::GetGrounded() const
{
    return m_grounded;
}

void
RplDioHeader::SetMop(uint8_t mop)
{
    // The Mode of Operation is three bits of the DIO's G/MOP/Prf octet (RFC
    // 6550 section 6.3.1); anything wider is silently masked away by
    // Serialize(), turning e.g. 8 into 0, an entirely different mode.
    NS_ASSERT_MSG(mop <= (RPL_DIO_MOP_MASK >> RPL_DIO_MOP_SHIFT),
                  "Mode of operation " << +mop << " does not fit the DIO's three-bit MOP field");
    m_mop = mop;
}

uint8_t
RplDioHeader::GetMop() const
{
    return m_mop;
}

void
RplDioHeader::SetPreference(uint8_t preference)
{
    // Likewise three bits of the same octet, DAGPreference (RFC 6550
    // section 6.3.1).
    NS_ASSERT_MSG(preference <= RPL_DIO_PREFERENCE_MASK,
                  "Preference " << +preference << " does not fit the DIO's three-bit Prf field");
    m_preference = preference;
}

uint8_t
RplDioHeader::GetPreference() const
{
    return m_preference;
}

void
RplDioHeader::SetDtsn(uint8_t dtsn)
{
    m_dtsn = dtsn;
}

uint8_t
RplDioHeader::GetDtsn() const
{
    return m_dtsn;
}

void
RplDioHeader::SetDodagId(Ipv6Address dodagId)
{
    m_dodagId = dodagId;
}

Ipv6Address
RplDioHeader::GetDodagId() const
{
    return m_dodagId;
}

bool
RplDioHeader::HasDagConfiguration() const
{
    return m_hasDagConf;
}

void
RplDioHeader::SetDagConfiguration(uint8_t intervalDoublings,
                                  uint8_t intervalMin,
                                  uint8_t redundancy,
                                  uint16_t maxRankIncrease,
                                  uint16_t minHopRankIncrease,
                                  uint16_t ocp,
                                  uint8_t defaultLifetime,
                                  uint16_t lifetimeUnit)
{
    m_hasDagConf = true;
    m_intervalDoublings = intervalDoublings;
    m_intervalMin = intervalMin;
    m_redundancy = redundancy;
    m_maxRankIncrease = maxRankIncrease;
    m_minHopRankIncrease = minHopRankIncrease;
    m_ocp = ocp;
    m_defaultLifetime = defaultLifetime;
    m_lifetimeUnit = lifetimeUnit;
}

uint8_t
RplDioHeader::GetIntervalDoublings() const
{
    return m_intervalDoublings;
}

uint8_t
RplDioHeader::GetIntervalMin() const
{
    return m_intervalMin;
}

uint8_t
RplDioHeader::GetRedundancy() const
{
    return m_redundancy;
}

uint16_t
RplDioHeader::GetMaxRankIncrease() const
{
    return m_maxRankIncrease;
}

uint16_t
RplDioHeader::GetMinHopRankIncrease() const
{
    return m_minHopRankIncrease;
}

uint16_t
RplDioHeader::GetOcp() const
{
    return m_ocp;
}

uint8_t
RplDioHeader::GetDefaultLifetime() const
{
    return m_defaultLifetime;
}

uint16_t
RplDioHeader::GetLifetimeUnit() const
{
    return m_lifetimeUnit;
}

bool
RplDioHeader::HasMetricContainer() const
{
    return m_hasMetricContainer;
}

void
RplDioHeader::SetMetricContainer(uint16_t pathEtx)
{
    m_hasMetricContainer = true;
    m_pathEtx = pathEtx;
}

uint16_t
RplDioHeader::GetPathEtx() const
{
    return m_pathEtx;
}

bool
RplDioHeader::HasLql() const
{
    return m_hasLql;
}

void
RplDioHeader::SetLql(uint8_t lql)
{
    m_hasLql = true;
    // The wire format's Val sub-field is 4 bits (RFC 6551 section 4.6), and
    // RPL_LQL_WORST (7) is the worst defined value on top of that; clamp so
    // a caller passing an out-of-range value (e.g. an unclamped RSSI-to-LQL
    // mapping) cannot silently truncate on the shift in Serialize().
    m_lql = std::min(lql, RPL_LQL_WORST);
}

uint8_t
RplDioHeader::GetLql() const
{
    return m_lql;
}

bool
RplDioHeader::HasPrefixInfo() const
{
    return m_hasPrefixInfo;
}

void
RplDioHeader::SetPrefixInfo(Ipv6Address prefix,
                            uint8_t prefixLength,
                            bool onLink,
                            bool autonomous,
                            uint32_t validLifetime,
                            uint32_t preferredLifetime)
{
    m_hasPrefixInfo = true;
    m_prefix = prefix;
    m_prefixLength = prefixLength;
    m_prefixOnLink = onLink;
    m_prefixAutonomous = autonomous;
    m_prefixValidLifetime = validLifetime;
    m_prefixPreferredLifetime = preferredLifetime;
}

Ipv6Address
RplDioHeader::GetPrefix() const
{
    return m_prefix;
}

uint8_t
RplDioHeader::GetPrefixLength() const
{
    return m_prefixLength;
}

bool
RplDioHeader::GetPrefixOnLink() const
{
    return m_prefixOnLink;
}

bool
RplDioHeader::GetPrefixAutonomous() const
{
    return m_prefixAutonomous;
}

uint32_t
RplDioHeader::GetPrefixValidLifetime() const
{
    return m_prefixValidLifetime;
}

uint32_t
RplDioHeader::GetPrefixPreferredLifetime() const
{
    return m_prefixPreferredLifetime;
}

bool
RplDioHeader::HasRreq() const
{
    return m_hasRreq;
}

void
RplDioHeader::SetRreq(const RreqOption& rreq)
{
    // Asserted rather than clamped, the same way SetMop() treats a Mode of
    // Operation too wide for its field: a caller that built one of these out
    // of range has a bug of its own, and silently narrowing the value would
    // put a different DODAG's worth of meaning on the wire.
    NS_ASSERT_MSG(rreq.addressVector.size() <= AODV_ADDRESS_VECTOR_MAX_ENTRIES,
                  "The Address Vector does not fit the RREQ option's 8-bit Opt Data Len");
    NS_ASSERT_MSG(rreq.compr <= (RPL_AODV_COMPR_MASK >> RPL_AODV_COMPR_SHIFT),
                  "Compr does not fit its 4-bit field");
    NS_ASSERT_MSG(rreq.lifetime <= RPL_AODV_LIFETIME_MASK, "L does not fit its 2-bit field");
    NS_ASSERT_MSG(rreq.rankLimit <= RPL_AODV_RANK_LIMIT_MASK,
                  "RankLimit does not fit its 7-bit field");
    m_hasRreq = true;
    m_rreq = rreq;
}

const RplDioHeader::RreqOption&
RplDioHeader::GetRreq() const
{
    return m_rreq;
}

bool
RplDioHeader::HasRrep() const
{
    return m_hasRrep;
}

void
RplDioHeader::SetRrep(const RrepOption& rrep)
{
    NS_ASSERT_MSG(rrep.addressVector.size() <= AODV_ADDRESS_VECTOR_MAX_ENTRIES,
                  "The Address Vector does not fit the RREP option's 8-bit Opt Data Len");
    NS_ASSERT_MSG(rrep.compr <= (RPL_AODV_COMPR_MASK >> RPL_AODV_COMPR_SHIFT),
                  "Compr does not fit its 4-bit field");
    NS_ASSERT_MSG(rrep.lifetime <= RPL_AODV_LIFETIME_MASK, "L does not fit its 2-bit field");
    NS_ASSERT_MSG(rrep.rankLimit <= RPL_AODV_RANK_LIMIT_MASK,
                  "RankLimit does not fit its 7-bit field");
    NS_ASSERT_MSG(rrep.delta <= (RPL_AODV_DELTA_MASK >> RPL_AODV_DELTA_SHIFT),
                  "Delta does not fit its 6-bit field");
    m_hasRrep = true;
    m_rrep = rrep;
}

const RplDioHeader::RrepOption&
RplDioHeader::GetRrep() const
{
    return m_rrep;
}

bool
RplDioHeader::HasArt() const
{
    return !m_arts.empty();
}

void
RplDioHeader::SetArt(const ArtOption& art)
{
    NS_ASSERT_MSG(art.prefixLength <= RPL_AODV_PREFIX_LENGTH_MASK,
                  "Prefix Length does not fit the ART option's 7-bit field");
    m_arts.assign(1, art);
}

const RplDioHeader::ArtOption&
RplDioHeader::GetArt() const
{
    static const ArtOption empty;
    return m_arts.empty() ? empty : m_arts.front();
}

void
RplDioHeader::AddArt(const ArtOption& art)
{
    NS_ASSERT_MSG(art.prefixLength <= RPL_AODV_PREFIX_LENGTH_MASK,
                  "Prefix Length does not fit the ART option's 7-bit field");
    m_arts.push_back(art);
}

const std::vector<RplDioHeader::ArtOption>&
RplDioHeader::GetArts() const
{
    return m_arts;
}

bool
RplDioHeader::HasP2pRdo() const
{
    return m_hasP2pRdo;
}

void
RplDioHeader::SetP2pRdo(const P2pRdoOption& rdo)
{
    NS_ASSERT_MSG(rdo.addressVector.size() <= RPL_P2P_ADDRESS_VECTOR_MAX_ENTRIES,
                  "The Address Vector does not fit the P2P-RDO's 8-bit Opt Data Len");
    NS_ASSERT_MSG(rdo.numRoutes <= (RPL_P2P_N_MASK >> RPL_P2P_N_SHIFT),
                  "N does not fit its 2-bit field");
    NS_ASSERT_MSG(rdo.lifetime <= (RPL_P2P_LIFETIME_MASK >> RPL_P2P_LIFETIME_SHIFT),
                  "L does not fit its 2-bit field");
    NS_ASSERT_MSG(rdo.maxRankOrNh <= RPL_P2P_MAX_RANK_MASK,
                  "MaxRank/NH does not fit its 6-bit field");
    m_hasP2pRdo = true;
    m_p2pRdo = rdo;
}

const P2pRdoOption&
RplDioHeader::GetP2pRdo() const
{
    return m_p2pRdo;
}

const std::vector<RplDioHeader::TargetOption>&
RplDioHeader::GetTargets() const
{
    return m_targets;
}

void
RplDioHeader::AddTarget(const TargetOption& target)
{
    m_targets.push_back(target);
}

NS_OBJECT_ENSURE_REGISTERED(RplP2pDroHeader);

RplP2pDroHeader::RplP2pDroHeader()
    : m_instanceId(RPL_DEFAULT_INSTANCE),
      m_stop(false),
      m_ackRequested(false),
      m_sequence(0),
      m_dodagId(Ipv6Address::GetAny()),
      m_hasP2pRdo(false)
{
}

TypeId
RplP2pDroHeader::GetTypeId()
{
    static TypeId tid = TypeId("ns3::rpl::RplP2pDroHeader")
                            .SetParent<Header>()
                            .SetGroupName("Rpl")
                            .AddConstructor<RplP2pDroHeader>();
    return tid;
}

TypeId
RplP2pDroHeader::GetInstanceTypeId() const
{
    return GetTypeId();
}

void
RplP2pDroHeader::Print(std::ostream& os) const
{
    os << "P2P-DRO instance " << +m_instanceId << " DODAGID " << m_dodagId;
    if (m_stop)
    {
        os << " stop";
    }
    if (m_ackRequested)
    {
        os << " ackRequested Seq " << +m_sequence;
    }
    if (m_hasP2pRdo)
    {
        os << " P2P-RDO" << (m_p2pRdo.reply ? " R" : "") << (m_p2pRdo.hopByHop ? " H" : "")
           << " Target " << m_p2pRdo.target << " AV " << m_p2pRdo.addressVector.size();
    }
}

uint32_t
RplP2pDroHeader::GetSerializedSize() const
{
    return 20 + (m_hasP2pRdo ? P2pRdoSerializedSize(m_p2pRdo, m_dodagId) : 0);
}

void
RplP2pDroHeader::Serialize(Buffer::Iterator start) const
{
    start.WriteU8(m_instanceId);
    start.WriteU8(0); // Version, RFC 6997 section 8: always zero

    uint8_t flags = static_cast<uint8_t>((m_stop ? RPL_P2P_DRO_S_FLAG : 0) |
                                         (m_ackRequested ? RPL_P2P_DRO_A_FLAG : 0) |
                                         ((m_sequence << RPL_P2P_DRO_SEQ_SHIFT) &
                                          RPL_P2P_DRO_SEQ_MASK));
    start.WriteU8(flags);
    start.WriteU8(0); // Reserved

    uint8_t buf[16];
    m_dodagId.Serialize(buf);
    start.Write(buf, 16);

    if (m_hasP2pRdo)
    {
        P2pRdoSerialize(start, m_p2pRdo, m_dodagId);
    }
}

uint32_t
RplP2pDroHeader::Deserialize(Buffer::Iterator start)
{
    Buffer::Iterator i = start;

    // The fixed base object has no length field of its own to validate a
    // received packet against -- unlike an option, whose declared length
    // the loop below checks before trusting -- so a packet shorter than it
    // has to be caught explicitly, before any of it is read: nothing here
    // has bounds-checked reads of its own in an optimized build (@see
    // design-constraints.md), and this class's own fields are left exactly
    // as this header already held them (a fresh one's constructor
    // defaults) rather than partially overwritten.
    if (i.GetRemainingSize() < BASE_SIZE)
    {
        NS_LOG_WARN("Truncated P2P-DRO (" << i.GetRemainingSize() << " bytes, need at least "
                                          << +BASE_SIZE << ")");
        return 0;
    }

    m_instanceId = i.ReadU8();
    i.ReadU8(); // Version, always zero, not checked on receipt

    uint8_t flags = i.ReadU8();
    m_stop = (flags & RPL_P2P_DRO_S_FLAG) != 0;
    m_ackRequested = (flags & RPL_P2P_DRO_A_FLAG) != 0;
    m_sequence = (flags & RPL_P2P_DRO_SEQ_MASK) >> RPL_P2P_DRO_SEQ_SHIFT;
    i.ReadU8(); // Reserved

    uint8_t buf[16];
    i.Read(buf, 16);
    m_dodagId = Ipv6Address::Deserialize(buf);

    // A P2P-DRO is the last thing in the packet, same as a DIO, so the end
    // of the buffer is the end of the option list.
    m_hasP2pRdo = false;
    while (!i.IsEnd())
    {
        uint8_t type = i.ReadU8();
        if (type == RPL_OPTION_PAD1)
        {
            continue;
        }
        if (i.IsEnd())
        {
            NS_LOG_WARN("Truncated RPL option " << +type << ", stopping");
            break;
        }
        uint8_t length = i.ReadU8();
        if (i.GetRemainingSize() < length)
        {
            NS_LOG_WARN("Truncated RPL option "
                        << +type << " (declared length " << +length << ", only "
                        << i.GetRemainingSize() << " bytes remain), stopping");
            break;
        }

        if (type == RPL_OPTION_P2P_RDO)
        {
            m_hasP2pRdo = P2pRdoDeserialize(i, length, m_dodagId, m_p2pRdo);
        }
        else
        {
            NS_LOG_LOGIC("Skipping RPL option " << +type << " of length " << +length);
            i.Next(length);
        }
    }

    return i.GetDistanceFrom(start);
}

void
RplP2pDroHeader::SetInstanceId(uint8_t instanceId)
{
    m_instanceId = instanceId;
}

uint8_t
RplP2pDroHeader::GetInstanceId() const
{
    return m_instanceId;
}

void
RplP2pDroHeader::SetStop(bool stop)
{
    m_stop = stop;
}

bool
RplP2pDroHeader::GetStop() const
{
    return m_stop;
}

void
RplP2pDroHeader::SetAckRequested(bool ackRequested)
{
    m_ackRequested = ackRequested;
}

bool
RplP2pDroHeader::GetAckRequested() const
{
    return m_ackRequested;
}

void
RplP2pDroHeader::SetSequence(uint8_t sequence)
{
    NS_ASSERT_MSG(sequence <= (RPL_P2P_DRO_SEQ_MASK >> RPL_P2P_DRO_SEQ_SHIFT),
                  "Seq does not fit its 2-bit field");
    m_sequence = sequence;
}

uint8_t
RplP2pDroHeader::GetSequence() const
{
    return m_sequence;
}

void
RplP2pDroHeader::SetDodagId(Ipv6Address dodagId)
{
    m_dodagId = dodagId;
}

Ipv6Address
RplP2pDroHeader::GetDodagId() const
{
    return m_dodagId;
}

bool
RplP2pDroHeader::HasP2pRdo() const
{
    return m_hasP2pRdo;
}

void
RplP2pDroHeader::SetP2pRdo(const P2pRdoOption& rdo)
{
    NS_ASSERT_MSG(rdo.addressVector.size() <= RPL_P2P_ADDRESS_VECTOR_MAX_ENTRIES,
                  "The Address Vector does not fit the P2P-RDO's 8-bit Opt Data Len");
    NS_ASSERT_MSG(rdo.numRoutes <= (RPL_P2P_N_MASK >> RPL_P2P_N_SHIFT),
                  "N does not fit its 2-bit field");
    NS_ASSERT_MSG(rdo.lifetime <= (RPL_P2P_LIFETIME_MASK >> RPL_P2P_LIFETIME_SHIFT),
                  "L does not fit its 2-bit field");
    NS_ASSERT_MSG(rdo.maxRankOrNh <= RPL_P2P_MAX_RANK_MASK,
                  "MaxRank/NH does not fit its 6-bit field");
    m_hasP2pRdo = true;
    m_p2pRdo = rdo;
}

const P2pRdoOption&
RplP2pDroHeader::GetP2pRdo() const
{
    return m_p2pRdo;
}

NS_OBJECT_ENSURE_REGISTERED(RplP2pDroAckHeader);

RplP2pDroAckHeader::RplP2pDroAckHeader()
    : m_instanceId(RPL_DEFAULT_INSTANCE),
      m_sequence(0),
      m_dodagId(Ipv6Address::GetAny())
{
}

TypeId
RplP2pDroAckHeader::GetTypeId()
{
    static TypeId tid = TypeId("ns3::rpl::RplP2pDroAckHeader")
                            .SetParent<Header>()
                            .SetGroupName("Rpl")
                            .AddConstructor<RplP2pDroAckHeader>();
    return tid;
}

TypeId
RplP2pDroAckHeader::GetInstanceTypeId() const
{
    return GetTypeId();
}

void
RplP2pDroAckHeader::Print(std::ostream& os) const
{
    os << "P2P-DRO-ACK instance " << +m_instanceId << " DODAGID " << m_dodagId << " Seq "
       << +m_sequence;
}

uint32_t
RplP2pDroAckHeader::GetSerializedSize() const
{
    return SIZE;
}

void
RplP2pDroAckHeader::Serialize(Buffer::Iterator start) const
{
    start.WriteU8(m_instanceId);
    start.WriteU8(0); // Version, RFC 6997 section 8: always zero

    uint8_t flags = static_cast<uint8_t>((m_sequence << RPL_P2P_DRO_ACK_SEQ_SHIFT) &
                                         RPL_P2P_DRO_ACK_SEQ_MASK);
    start.WriteU8(flags);
    start.WriteU8(0); // Reserved

    uint8_t buf[16];
    m_dodagId.Serialize(buf);
    start.Write(buf, 16);
}

uint32_t
RplP2pDroAckHeader::Deserialize(Buffer::Iterator start)
{
    Buffer::Iterator i = start;

    // No length field of its own, same reason RplP2pDroHeader::Deserialize()
    // checks its own BASE_SIZE before reading anything.
    if (i.GetRemainingSize() < SIZE)
    {
        NS_LOG_WARN("Truncated P2P-DRO-ACK (" << i.GetRemainingSize() << " bytes, need "
                                              << +SIZE << ")");
        return 0;
    }

    m_instanceId = i.ReadU8();
    i.ReadU8(); // Version, always zero, not checked on receipt

    uint8_t flags = i.ReadU8();
    m_sequence = (flags & RPL_P2P_DRO_ACK_SEQ_MASK) >> RPL_P2P_DRO_ACK_SEQ_SHIFT;
    i.ReadU8(); // Reserved

    uint8_t buf[16];
    i.Read(buf, 16);
    m_dodagId = Ipv6Address::Deserialize(buf);

    return i.GetDistanceFrom(start);
}

void
RplP2pDroAckHeader::SetInstanceId(uint8_t instanceId)
{
    m_instanceId = instanceId;
}

uint8_t
RplP2pDroAckHeader::GetInstanceId() const
{
    return m_instanceId;
}

void
RplP2pDroAckHeader::SetSequence(uint8_t sequence)
{
    m_sequence = sequence;
}

uint8_t
RplP2pDroAckHeader::GetSequence() const
{
    return m_sequence;
}

void
RplP2pDroAckHeader::SetDodagId(Ipv6Address dodagId)
{
    m_dodagId = dodagId;
}

Ipv6Address
RplP2pDroAckHeader::GetDodagId() const
{
    return m_dodagId;
}

NS_OBJECT_ENSURE_REGISTERED(RplDaoHeader);

RplDaoHeader::RplDaoHeader()
    : m_instanceId(RPL_DEFAULT_INSTANCE),
      m_ackRequested(false),
      m_sequence(0),
      m_dodagId(Ipv6Address::GetAny()),
      m_target(Ipv6Address::GetAny()),
      m_targetPrefixLen(128),
      m_parent(Ipv6Address::GetAny()),
      m_pathSequence(0),
      m_pathLifetime(RPL_DEFAULT_LIFETIME)
{
}

TypeId
RplDaoHeader::GetTypeId()
{
    static TypeId tid = TypeId("ns3::rpl::RplDaoHeader")
                            .SetParent<Header>()
                            .SetGroupName("Rpl")
                            .AddConstructor<RplDaoHeader>();
    return tid;
}

TypeId
RplDaoHeader::GetInstanceTypeId() const
{
    return GetTypeId();
}

void
RplDaoHeader::Print(std::ostream& os) const
{
    os << "DAO instance " << +m_instanceId << " sequence " << +m_sequence << " target " << m_target
       << "/" << +m_targetPrefixLen << " via " << m_parent << " lifetime " << +m_pathLifetime;
    if (m_ackRequested)
    {
        os << " ack requested";
    }
    if (!m_additionalTargets.empty())
    {
        os << " (+" << m_additionalTargets.size() << " more target(s))";
    }
}

uint32_t
RplDaoHeader::GetSerializedSize() const
{
    uint32_t size = 4;
    if (!m_dodagId.IsAny())
    {
        size += 16;
    }
    size += TARGET_OPTION_SIZE + TRANSIT_OPTION_SIZE;
    size += static_cast<uint32_t>(m_additionalTargets.size()) *
           (TARGET_OPTION_SIZE + TRANSIT_OPTION_SIZE);
    return size;
}

void
RplDaoHeader::Serialize(Buffer::Iterator start) const
{
    uint8_t buf[16];

    start.WriteU8(m_instanceId);

    uint8_t flags = m_ackRequested ? RPL_DAO_K_FLAG : 0;
    if (!m_dodagId.IsAny())
    {
        flags |= RPL_DAO_D_FLAG;
    }
    start.WriteU8(flags);

    start.WriteU8(0); // Reserved
    start.WriteU8(m_sequence);

    if (!m_dodagId.IsAny())
    {
        m_dodagId.Serialize(buf);
        start.Write(buf, 16);
    }

    // Target option, RFC 6550 section 6.7.7.
    start.WriteU8(RPL_OPTION_TARGET);
    start.WriteU8(TARGET_OPTION_LENGTH);
    start.WriteU8(0); // Flags
    start.WriteU8(m_targetPrefixLen);
    m_target.Serialize(buf);
    start.Write(buf, 16);

    // Transit Information option, RFC 6550 section 6.7.8.
    start.WriteU8(RPL_OPTION_TRANSIT);
    start.WriteU8(TRANSIT_OPTION_LENGTH);
    start.WriteU8(0); // E flag and flags
    start.WriteU8(0); // Path Control
    start.WriteU8(m_pathSequence);
    start.WriteU8(m_pathLifetime);
    m_parent.Serialize(buf);
    start.Write(buf, 16);

    // Every additional Target + Transit Information pair, RFC 6550 section
    // 9.4 rule 3: each is its own complete group, sharing this message's
    // own Transit Information parent field (m_parent) the same way the
    // primary one does -- @see AddTarget()'s own doc comment for why.
    for (const auto& additional : m_additionalTargets)
    {
        start.WriteU8(RPL_OPTION_TARGET);
        start.WriteU8(TARGET_OPTION_LENGTH);
        start.WriteU8(0); // Flags
        start.WriteU8(additional.targetPrefixLength);
        additional.target.Serialize(buf);
        start.Write(buf, 16);

        start.WriteU8(RPL_OPTION_TRANSIT);
        start.WriteU8(TRANSIT_OPTION_LENGTH);
        start.WriteU8(0); // E flag and flags
        start.WriteU8(0); // Path Control
        start.WriteU8(additional.pathSequence);
        start.WriteU8(additional.pathLifetime);
        m_parent.Serialize(buf);
        start.Write(buf, 16);
    }
}

uint32_t
RplDaoHeader::Deserialize(Buffer::Iterator start)
{
    Buffer::Iterator i = start;
    uint8_t buf[16];

    m_instanceId = i.ReadU8();

    uint8_t flags = i.ReadU8();
    m_ackRequested = (flags & RPL_DAO_K_FLAG) != 0;
    bool hasDodagId = (flags & RPL_DAO_D_FLAG) != 0;

    i.ReadU8(); // Reserved
    m_sequence = i.ReadU8();

    if (hasDodagId)
    {
        i.Read(buf, 16);
        m_dodagId = Ipv6Address::Deserialize(buf);
    }
    else
    {
        m_dodagId = Ipv6Address::GetAny();
    }

    m_target = Ipv6Address::GetAny();
    m_parent = Ipv6Address::GetAny();
    m_additionalTargets.clear();

    // Pairs each Target option with the Transit Information option that
    // follows it (RFC 6550 section 9.4 rule 3): this module's own send
    // side only ever generates the simplest form of the general grouping
    // rule -- exactly one Transit Information option per Target option --
    // so that pairing is done here purely sequentially rather than
    // implementing the fully general "one or more Target options followed
    // by one or more Transit Information options, applying to the whole
    // group" rule. The first complete pair found becomes this message's
    // own primary target (m_target/m_parent/m_pathSequence/m_pathLifetime,
    // preserving every existing single-target caller's own behaviour
    // unchanged); every complete pair after that is appended to
    // m_additionalTargets instead. A Target option with no Transit
    // Information option ever following it (or a second Target option
    // before the first is paired) cannot come from this module's own
    // SendDaoMessage() and is simply dropped, the same "does not follow
    // the rules, discard" allowance RFC 6550 section 9.4 rule 6 gives.
    //
    // The DAO is the last thing in the packet, so the end of the buffer is
    // the end of the option list.
    bool havePendingTarget = false;
    Ipv6Address pendingTarget;
    uint8_t pendingPrefixLength = 128;
    bool haveAnyPair = false;

    while (!i.IsEnd())
    {
        uint8_t type = i.ReadU8();
        if (type == RPL_OPTION_PAD1)
        {
            continue;
        }
        if (i.IsEnd())
        {
            NS_LOG_WARN("Truncated RPL option " << +type << ", stopping");
            break;
        }
        uint8_t length = i.ReadU8();

        // length is the attacker-controlled Option Length field: every branch
        // below trusts it (directly, or indirectly via the *_OPTION_LENGTH
        // equality checks) to read that many bytes. Buffer::Iterator has no
        // bounds checking of its own in an optimized build (PeekU8()'s range
        // check is an NS_ASSERT, compiled out there), so a declared length
        // longer than what is actually left in a truncated or malformed
        // packet would read (and, for the option types below, use as field
        // values) memory past the buffer's end instead of stopping cleanly
        // the way a debug build's assertion failure would.
        if (i.GetRemainingSize() < length)
        {
            NS_LOG_WARN("Truncated RPL option "
                        << +type << " (declared length " << +length << ", only "
                        << i.GetRemainingSize() << " bytes remain), stopping");
            break;
        }

        if (type == RPL_OPTION_TARGET && length == TARGET_OPTION_LENGTH)
        {
            i.ReadU8(); // Flags
            pendingPrefixLength = i.ReadU8();
            i.Read(buf, 16);
            pendingTarget = Ipv6Address::Deserialize(buf);
            havePendingTarget = true;
        }
        else if (type == RPL_OPTION_TRANSIT && length == TRANSIT_OPTION_LENGTH)
        {
            i.ReadU8(); // E flag and flags
            i.ReadU8(); // Path Control
            uint8_t pathSequence = i.ReadU8();
            uint8_t pathLifetime = i.ReadU8();
            i.Read(buf, 16);
            Ipv6Address parent = Ipv6Address::Deserialize(buf);

            if (havePendingTarget)
            {
                if (!haveAnyPair)
                {
                    m_target = pendingTarget;
                    m_targetPrefixLen = pendingPrefixLength;
                    m_parent = parent;
                    m_pathSequence = pathSequence;
                    m_pathLifetime = pathLifetime;
                    haveAnyPair = true;
                }
                else
                {
                    AdditionalTarget additional;
                    additional.target = pendingTarget;
                    additional.targetPrefixLength = pendingPrefixLength;
                    additional.pathSequence = pathSequence;
                    additional.pathLifetime = pathLifetime;
                    m_additionalTargets.push_back(additional);
                }
                havePendingTarget = false;
            }
        }
        else
        {
            NS_LOG_LOGIC("Skipping RPL option " << +type << " of length " << +length);
            i.Next(length);
        }
    }

    return i.GetDistanceFrom(start);
}

void
RplDaoHeader::AddTarget(const AdditionalTarget& additionalTarget)
{
    m_additionalTargets.push_back(additionalTarget);
}

const std::vector<RplDaoHeader::AdditionalTarget>&
RplDaoHeader::GetAdditionalTargets() const
{
    return m_additionalTargets;
}

void
RplDaoHeader::SetInstanceId(uint8_t instanceId)
{
    m_instanceId = instanceId;
}

uint8_t
RplDaoHeader::GetInstanceId() const
{
    return m_instanceId;
}

void
RplDaoHeader::SetAckRequested(bool ackRequested)
{
    m_ackRequested = ackRequested;
}

bool
RplDaoHeader::GetAckRequested() const
{
    return m_ackRequested;
}

void
RplDaoHeader::SetSequence(uint8_t sequence)
{
    m_sequence = sequence;
}

uint8_t
RplDaoHeader::GetSequence() const
{
    return m_sequence;
}

void
RplDaoHeader::SetDodagId(Ipv6Address dodagId)
{
    m_dodagId = dodagId;
}

Ipv6Address
RplDaoHeader::GetDodagId() const
{
    return m_dodagId;
}

void
RplDaoHeader::SetTarget(Ipv6Address target, uint8_t prefixLength)
{
    m_target = target;
    m_targetPrefixLen = prefixLength;
}

Ipv6Address
RplDaoHeader::GetTarget() const
{
    return m_target;
}

uint8_t
RplDaoHeader::GetTargetPrefixLength() const
{
    return m_targetPrefixLen;
}

void
RplDaoHeader::SetTransitInformation(Ipv6Address parent,
                                    uint8_t pathSequence,
                                    uint8_t pathLifetime)
{
    m_parent = parent;
    m_pathSequence = pathSequence;
    m_pathLifetime = pathLifetime;
}

Ipv6Address
RplDaoHeader::GetParent() const
{
    return m_parent;
}

uint8_t
RplDaoHeader::GetPathSequence() const
{
    return m_pathSequence;
}

uint8_t
RplDaoHeader::GetPathLifetime() const
{
    return m_pathLifetime;
}

NS_OBJECT_ENSURE_REGISTERED(RplDaoAckHeader);

RplDaoAckHeader::RplDaoAckHeader()
    : m_instanceId(RPL_DEFAULT_INSTANCE),
      m_sequence(0),
      m_status(0),
      m_dodagId(Ipv6Address::GetAny())
{
}

TypeId
RplDaoAckHeader::GetTypeId()
{
    static TypeId tid = TypeId("ns3::rpl::RplDaoAckHeader")
                            .SetParent<Header>()
                            .SetGroupName("Rpl")
                            .AddConstructor<RplDaoAckHeader>();
    return tid;
}

TypeId
RplDaoAckHeader::GetInstanceTypeId() const
{
    return GetTypeId();
}

void
RplDaoAckHeader::Print(std::ostream& os) const
{
    os << "DAO-ACK instance " << +m_instanceId << " sequence " << +m_sequence << " status "
       << +m_status;
}

uint32_t
RplDaoAckHeader::GetSerializedSize() const
{
    return m_dodagId.IsAny() ? 4 : 20;
}

void
RplDaoAckHeader::Serialize(Buffer::Iterator start) const
{
    start.WriteU8(m_instanceId);
    start.WriteU8(m_dodagId.IsAny() ? 0 : RPL_DAO_D_FLAG);
    start.WriteU8(m_sequence);
    start.WriteU8(m_status);

    if (!m_dodagId.IsAny())
    {
        uint8_t buf[16];
        m_dodagId.Serialize(buf);
        start.Write(buf, 16);
    }
}

uint32_t
RplDaoAckHeader::Deserialize(Buffer::Iterator start)
{
    Buffer::Iterator i = start;

    m_instanceId = i.ReadU8();
    bool hasDodagId = (i.ReadU8() & RPL_DAO_D_FLAG) != 0;
    m_sequence = i.ReadU8();
    m_status = i.ReadU8();

    if (hasDodagId)
    {
        uint8_t buf[16];
        i.Read(buf, 16);
        m_dodagId = Ipv6Address::Deserialize(buf);
    }
    else
    {
        m_dodagId = Ipv6Address::GetAny();
    }

    return i.GetDistanceFrom(start);
}

void
RplDaoAckHeader::SetInstanceId(uint8_t instanceId)
{
    m_instanceId = instanceId;
}

uint8_t
RplDaoAckHeader::GetInstanceId() const
{
    return m_instanceId;
}

void
RplDaoAckHeader::SetSequence(uint8_t sequence)
{
    m_sequence = sequence;
}

uint8_t
RplDaoAckHeader::GetSequence() const
{
    return m_sequence;
}

void
RplDaoAckHeader::SetStatus(uint8_t status)
{
    m_status = status;
}

uint8_t
RplDaoAckHeader::GetStatus() const
{
    return m_status;
}

void
RplDaoAckHeader::SetDodagId(Ipv6Address dodagId)
{
    m_dodagId = dodagId;
}

Ipv6Address
RplDaoAckHeader::GetDodagId() const
{
    return m_dodagId;
}

NS_OBJECT_ENSURE_REGISTERED(RplSourceRoutingHeader);

RplSourceRoutingHeader::RplSourceRoutingHeader()
{
    SetTypeRouting(RPL_RH_TYPE_SRH);
}

TypeId
RplSourceRoutingHeader::GetTypeId()
{
    static TypeId tid = TypeId("ns3::rpl::RplSourceRoutingHeader")
                            .SetParent<Ipv6ExtensionRoutingHeader>()
                            .SetGroupName("Rpl")
                            .AddConstructor<RplSourceRoutingHeader>();
    return tid;
}

TypeId
RplSourceRoutingHeader::GetInstanceTypeId() const
{
    return GetTypeId();
}

void
RplSourceRoutingHeader::Print(std::ostream& os) const
{
    os << "SRH segments left " << +GetSegmentsLeft() << " addresses";
    for (const auto& address : m_addresses)
    {
        os << " " << address;
    }
}

uint8_t
RplSourceRoutingHeader::Cmpri() const
{
    if (m_addresses.size() < 2)
    {
        return 0;
    }
    for (size_t index = 0; index + 1 < m_addresses.size(); index++)
    {
        if (!m_addresses[index].IsLinkLocal())
        {
            return 0;
        }
    }
    return 8;
}

uint8_t
RplSourceRoutingHeader::Cmpre() const
{
    return (!m_addresses.empty() && m_addresses.back().IsLinkLocal()) ? 8 : 0;
}

uint32_t
RplSourceRoutingHeader::GetSerializedSize() const
{
    // Next Header, Hdr Ext Len, Routing Type and Segments Left, then CmprI,
    // CmprE, Pad and the reserved bits, then the addresses, each entry but
    // the last (16 - CmprI) octets and the last (16 - CmprE) (see the class
    // docs for why CmprI/CmprE only ever come out as 0 or 8 here, which is
    // also why this is always a multiple of 8 on its own, no Pad needed).
    if (m_addresses.empty())
    {
        return 8;
    }
    return 8 + (m_addresses.size() - 1) * (16 - Cmpri()) + (16 - Cmpre());
}

void
RplSourceRoutingHeader::Serialize(Buffer::Iterator start) const
{
    Buffer::Iterator i = start;
    uint8_t cmprI = Cmpri();
    uint8_t cmprE = Cmpre();

    // Hdr Ext Len is eight bits (RFC 8200 section 4.4), so a longer header
    // than this cannot say how long it is: the cast below would wrap and the
    // receiver would reconstruct a different, shorter address list without
    // anything on the wire saying so. @see SetAddresses().
    NS_ASSERT_MSG(GetSerializedSize() <= MAX_SERIALIZED_SIZE,
                  "A Routing Header of " << GetSerializedSize()
                                         << " bytes does not fit an 8-bit Hdr Ext Len");

    i.WriteU8(GetNextHeader());
    // Hdr Ext Len counts 8-byte units after the first eight bytes.
    i.WriteU8(static_cast<uint8_t>((GetSerializedSize() - 8) / 8));
    i.WriteU8(GetTypeRouting());
    i.WriteU8(GetSegmentsLeft());

    i.WriteU8(static_cast<uint8_t>((cmprI << 4) | cmprE));
    i.WriteU8(0); // Pad (always 0 here) and the top of the reserved field
    i.WriteU16(0);

    uint8_t buf[16];
    for (size_t index = 0; index < m_addresses.size(); index++)
    {
        uint8_t elided = (index + 1 == m_addresses.size()) ? cmprE : cmprI;
        m_addresses[index].Serialize(buf);
        i.Write(buf + elided, 16 - elided);
    }
}

uint32_t
RplSourceRoutingHeader::Deserialize(Buffer::Iterator start)
{
    Buffer::Iterator i = start;

    SetNextHeader(i.ReadU8());
    uint8_t hdrExtLen = i.ReadU8();
    SetTypeRouting(i.ReadU8());
    SetSegmentsLeft(i.ReadU8());

    uint8_t cmprByte = i.ReadU8();
    uint8_t cmprI = cmprByte >> 4;
    uint8_t cmprE = cmprByte & 0x0f;
    uint8_t pad = i.ReadU8() >> 4; // top nibble is Pad, the rest is reserved
    i.ReadU16();                  // the rest of the reserved field

    m_addresses.clear();

    // Hdr Ext Len is whatever the sender wrote, and everything below reads
    // against it. Buffer::Iterator does no bounds checking of its own in an
    // optimized build (@see RplDioHeader::Deserialize()'s note on the same
    // hazard), so a header claiming more eight-octet units than the packet
    // actually carries -- which this implementation never sends, but a
    // truncated or hand-built one does -- would read past the buffer's end,
    // once per address it thinks is there. Clamp the claim to what is
    // really left instead, and report that same clamped total as the size
    // consumed so the caller does not trim more of the packet than existed.
    uint32_t declaredSize = uint32_t(hdrExtLen + 1) * 8;
    uint32_t availableSize = 8 + i.GetRemainingSize();
    if (declaredSize > availableSize)
    {
        NS_LOG_WARN("Truncated RPL Source Routing Header (Hdr Ext Len "
                    << +hdrExtLen << " claims " << declaredSize << " bytes, only " << availableSize
                    << " are present)");
        declaredSize = availableSize;
    }

    // RFC 6554 section 4.2's n, adapted to bytes already past the fixed
    // 8-octet part: this header's payload, after Pad, holds (n-1) entries
    // of (16-CmprI) octets and one of (16-CmprE).
    uint32_t addressBytes = declaredSize - 8;
    addressBytes = (addressBytes > pad) ? addressBytes - pad : 0;
    if (addressBytes >= uint32_t(16 - cmprE))
    {
        uint32_t n = (addressBytes - (16 - cmprE)) / (16 - cmprI) + 1;
        // fe80::/64 is the only prefix this implementation ever elides (see
        // the class docs); clamped to 8 octets so a header claiming to
        // elide more than that -- which this implementation never sends,
        // but a malformed or hand-built one might -- cannot read past the
        // constant.
        static const uint8_t linkLocalPrefix[8] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0};
        for (uint32_t index = 0; index < n; index++)
        {
            uint8_t elided = (index + 1 == n) ? cmprE : cmprI;
            uint8_t fromConstant = std::min<uint8_t>(elided, 8);
            uint8_t buf[16] = {0};
            std::copy(linkLocalPrefix, linkLocalPrefix + fromConstant, buf);
            i.Read(buf + elided, 16 - elided);
            m_addresses.push_back(Ipv6Address::Deserialize(buf));
        }
    }

    // The wire's own Hdr Ext Len, clamped above to what the packet really
    // holds, is authoritative for how many bytes this header occupies,
    // independent of what GetSerializedSize() would recompute from the
    // addresses just reconstructed: a header this implementation did not
    // itself produce need not round-trip through Cmpri()/Cmpre() the same
    // way (e.g. a CmprI other than 0 or 8, which this implementation never
    // sends but a hand-built packet might).
    return declaredSize;
}

void
RplSourceRoutingHeader::SetAddresses(const std::vector<Ipv6Address>& addresses)
{
    m_addresses = addresses;
}

const std::vector<Ipv6Address>&
RplSourceRoutingHeader::GetAddresses() const
{
    return m_addresses;
}

void
RplSourceRoutingHeader::SetAddress(uint8_t index, Ipv6Address address)
{
    m_addresses.at(index) = address;
}

Ipv6Address
RplSourceRoutingHeader::GetAddress(uint8_t index) const
{
    return m_addresses.at(index);
}

NS_OBJECT_ENSURE_REGISTERED(RplPacketInfoHeader);

RplPacketInfoHeader::RplPacketInfoHeader()
    : m_flags(0),
      m_instanceId(RPL_DEFAULT_INSTANCE),
      m_senderRank(0),
      m_malformed(false)
{
    SetType(RPL_HBH_OPTION_TYPE);
    SetLength(RPI_BASE_LENGTH); // Flags, RPLInstanceID, SenderRank
}

TypeId
RplPacketInfoHeader::GetTypeId()
{
    static TypeId tid = TypeId("ns3::rpl::RplPacketInfoHeader")
                            .SetParent<Ipv6OptionHeader>()
                            .SetGroupName("Rpl")
                            .AddConstructor<RplPacketInfoHeader>();
    return tid;
}

TypeId
RplPacketInfoHeader::GetInstanceTypeId() const
{
    return GetTypeId();
}

void
RplPacketInfoHeader::Print(std::ostream& os) const
{
    os << "RPI down " << GetDown() << " rankError " << GetRankError() << " forwardingError "
       << GetForwardingError() << " instance " << +m_instanceId << " senderRank " << m_senderRank;
}

uint32_t
RplPacketInfoHeader::GetSerializedSize() const
{
    // Derived from what is actually held rather than from the Opt Data Len
    // field on its own: the two must not be able to disagree, or a forged
    // length would decide how many bytes Serialize() is given while
    // Serialize() itself only ever writes the base octets, leaving the rest
    // of that space filled with whatever the buffer happened to hold.
    return RPI_BASE_SIZE + m_subTlvs.size();
}

void
RplPacketInfoHeader::Serialize(Buffer::Iterator start) const
{
    Buffer::Iterator i = start;

    i.WriteU8(GetType());
    i.WriteU8(static_cast<uint8_t>(RPI_BASE_LENGTH + m_subTlvs.size()));
    i.WriteU8(m_flags);
    i.WriteU8(m_instanceId);
    i.WriteHtonU16(m_senderRank);
    if (!m_subTlvs.empty())
    {
        i.Write(m_subTlvs.data(), m_subTlvs.size());
    }
}

uint32_t
RplPacketInfoHeader::Deserialize(Buffer::Iterator start)
{
    Buffer::Iterator i = start;

    SetType(i.ReadU8());
    uint8_t length = i.ReadU8();

    m_subTlvs.clear();
    m_malformed = false;

    // length is RFC 6553 section 3's Opt Data Len, straight off the wire.
    // Everything below reads against it, and the enclosing Hop-by-Hop
    // header's option walk (ns3::Ipv6Extension::ProcessOptions()) advances
    // by whatever this option reports it consumed, so a length that either
    // cannot hold the mandatory base octets or claims bytes the packet does
    // not carry has to stop here rather than be acted on:
    //
    //   - Buffer::Iterator does no bounds checking of its own in an
    //     optimized build (PeekU8()'s range check is an NS_ASSERT, compiled
    //     out there), so reading the base octets of an option cut short
    //     would read past the buffer's end.
    //   - Reporting a length the packet does not have back to
    //     ProcessOptions() makes it walk past the real end of the option
    //     list, and, since Ipv6Option::Process()'s return value is a
    //     uint8_t, an Opt Data Len of 254 reports 256, i.e. 0, which never
    //     advances that walk at all.
    //
    // Two octets is all that was really read, so that is what is reported;
    // m_malformed is what tells RplIpv6OptionRpl::Process() to drop the
    // packet rather than let a partly-parsed option through.
    if (length < RPI_BASE_LENGTH || i.GetRemainingSize() < length ||
        uint32_t(length) + 2 > std::numeric_limits<uint8_t>::max())
    {
        NS_LOG_WARN("Malformed RPL Option: Opt Data Len " << +length << " with "
                                                          << i.GetRemainingSize()
                                                          << " bytes left in the packet");
        m_malformed = true;
        SetLength(RPI_BASE_LENGTH);
        m_flags = 0;
        m_instanceId = RPL_DEFAULT_INSTANCE;
        m_senderRank = 0;
        return 2;
    }

    SetLength(length);
    m_flags = i.ReadU8();
    m_instanceId = i.ReadU8();
    m_senderRank = i.ReadNtohU16();

    // RFC 6553 section 3: whatever follows the base octets is a sub-TLV,
    // none of which this implementation defines. Carried verbatim so
    // Serialize() can put it back unchanged for the next hop.
    if (length > RPI_BASE_LENGTH)
    {
        m_subTlvs.resize(length - RPI_BASE_LENGTH);
        i.Read(m_subTlvs.data(), m_subTlvs.size());
    }

    return GetSerializedSize();
}

bool
RplPacketInfoHeader::IsMalformed() const
{
    return m_malformed;
}

const std::vector<uint8_t>&
RplPacketInfoHeader::GetSubTlvs() const
{
    return m_subTlvs;
}

void
RplPacketInfoHeader::SetDown(bool down)
{
    if (down)
    {
        m_flags |= RPL_HDR_OPT_DOWN;
    }
    else
    {
        m_flags &= ~RPL_HDR_OPT_DOWN;
    }
}

bool
RplPacketInfoHeader::GetDown() const
{
    return (m_flags & RPL_HDR_OPT_DOWN) != 0;
}

void
RplPacketInfoHeader::SetRankError(bool rankError)
{
    if (rankError)
    {
        m_flags |= RPL_HDR_OPT_RANK_ERR;
    }
    else
    {
        m_flags &= ~RPL_HDR_OPT_RANK_ERR;
    }
}

bool
RplPacketInfoHeader::GetRankError() const
{
    return (m_flags & RPL_HDR_OPT_RANK_ERR) != 0;
}

void
RplPacketInfoHeader::SetForwardingError(bool forwardingError)
{
    if (forwardingError)
    {
        m_flags |= RPL_HDR_OPT_FWD_ERR;
    }
    else
    {
        m_flags &= ~RPL_HDR_OPT_FWD_ERR;
    }
}

bool
RplPacketInfoHeader::GetForwardingError() const
{
    return (m_flags & RPL_HDR_OPT_FWD_ERR) != 0;
}

void
RplPacketInfoHeader::SetInstanceId(uint8_t instanceId)
{
    m_instanceId = instanceId;
}

uint8_t
RplPacketInfoHeader::GetInstanceId() const
{
    return m_instanceId;
}

void
RplPacketInfoHeader::SetSenderRank(uint16_t rank)
{
    m_senderRank = rank;
}

uint16_t
RplPacketInfoHeader::GetSenderRank() const
{
    return m_senderRank;
}

} // namespace rpl
} // namespace ns3
