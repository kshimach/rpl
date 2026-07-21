/*
 * Copyright (c) 2026 ns-3 RPL module contributors
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "rpl-header.h"

#include "ns3/log.h"

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
      m_lifetimeUnit(RPL_DEFAULT_LIFETIME_UNIT)
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
}

uint32_t
RplDioHeader::GetSerializedSize() const
{
    return 24 + (m_hasDagConf ? DAG_CONF_OPTION_SIZE : 0);
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

} // namespace rpl
} // namespace ns3
