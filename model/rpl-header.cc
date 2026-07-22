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
}

uint32_t
RplDaoHeader::GetSerializedSize() const
{
    uint32_t size = 4;
    if (!m_dodagId.IsAny())
    {
        size += 16;
    }
    return size + TARGET_OPTION_SIZE + TRANSIT_OPTION_SIZE;
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

    // The DAO is the last thing in the packet, so the end of the buffer is the
    // end of the option list.
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

        if (type == RPL_OPTION_TARGET && length == TARGET_OPTION_LENGTH)
        {
            i.ReadU8(); // Flags
            m_targetPrefixLen = i.ReadU8();
            i.Read(buf, 16);
            m_target = Ipv6Address::Deserialize(buf);
        }
        else if (type == RPL_OPTION_TRANSIT && length == TRANSIT_OPTION_LENGTH)
        {
            i.ReadU8(); // E flag and flags
            i.ReadU8(); // Path Control
            m_pathSequence = i.ReadU8();
            m_pathLifetime = i.ReadU8();
            i.Read(buf, 16);
            m_parent = Ipv6Address::Deserialize(buf);
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

uint32_t
RplSourceRoutingHeader::GetSerializedSize() const
{
    // Next Header, Hdr Ext Len, Routing Type and Segments Left, then CmprI,
    // CmprE, Pad and the reserved bits, then the uncompressed addresses.
    return 8 + 16 * m_addresses.size();
}

void
RplSourceRoutingHeader::Serialize(Buffer::Iterator start) const
{
    Buffer::Iterator i = start;

    i.WriteU8(GetNextHeader());
    // Hdr Ext Len counts 8-byte units after the first eight bytes.
    i.WriteU8(static_cast<uint8_t>(2 * m_addresses.size()));
    i.WriteU8(GetTypeRouting());
    i.WriteU8(GetSegmentsLeft());

    i.WriteU8(0); // CmprI and CmprE, both zero: no compression
    i.WriteU8(0); // Pad and the top of the reserved field
    i.WriteU16(0);

    uint8_t buf[16];
    for (const auto& address : m_addresses)
    {
        address.Serialize(buf);
        i.Write(buf, 16);
    }
}

uint32_t
RplSourceRoutingHeader::Deserialize(Buffer::Iterator start)
{
    Buffer::Iterator i = start;

    SetNextHeader(i.ReadU8());
    uint8_t extensionLength = i.ReadU8();
    SetTypeRouting(i.ReadU8());
    SetSegmentsLeft(i.ReadU8());

    i.ReadU8(); // CmprI and CmprE, assumed zero: no compression support
    i.ReadU8(); // Pad and the top of the reserved field
    i.ReadU16();

    m_addresses.clear();
    uint8_t buf[16];
    for (uint8_t index = 0; index < extensionLength / 2; index++)
    {
        i.Read(buf, 16);
        m_addresses.push_back(Ipv6Address::Deserialize(buf));
    }

    return GetSerializedSize();
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
      m_senderRank(0)
{
    SetType(RPL_HBH_OPTION_TYPE);
    SetLength(4); // Flags, RPLInstanceID, SenderRank
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
    return GetLength() + 2;
}

void
RplPacketInfoHeader::Serialize(Buffer::Iterator start) const
{
    Buffer::Iterator i = start;

    i.WriteU8(GetType());
    i.WriteU8(GetLength());
    i.WriteU8(m_flags);
    i.WriteU8(m_instanceId);
    i.WriteHtonU16(m_senderRank);
}

uint32_t
RplPacketInfoHeader::Deserialize(Buffer::Iterator start)
{
    Buffer::Iterator i = start;

    SetType(i.ReadU8());
    SetLength(i.ReadU8());
    m_flags = i.ReadU8();
    m_instanceId = i.ReadU8();
    m_senderRank = i.ReadNtohU16();

    return GetSerializedSize();
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
