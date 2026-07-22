/*
 * Copyright (c) 2026 ns-3 RPL module contributors
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * RPL control message formats (RFC 6550, section 6).
 */

#ifndef RPL_HEADER_H
#define RPL_HEADER_H

#include "rpl-conf.h"

#include "ns3/header.h"
#include "ns3/ipv6-address.h"
#include "ns3/ipv6-extension-header.h"
#include "ns3/ipv6-option-header.h"

#include <vector>

namespace ns3
{
namespace rpl
{

/**
 * @ingroup rpl
 *
 * @brief DODAG Information Solicitation, RFC 6550 section 6.2.
 *
 * The base object is two reserved bytes; the Solicited Information option is
 * not generated, and any option found on reception is skipped.
 */
class RplDisHeader : public Header
{
  public:
    /**
     * @brief Get the type ID.
     * @return the object TypeId
     */
    static TypeId GetTypeId();

    RplDisHeader();

    TypeId GetInstanceTypeId() const override;
    void Print(std::ostream& os) const override;
    uint32_t GetSerializedSize() const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;
};

/**
 * @ingroup rpl
 *
 * @brief DODAG Information Object, RFC 6550 section 6.3.
 *
 * Carries the 24-byte base object and, optionally, the DODAG Configuration
 * option (RFC 6550 section 6.7.6) which propagates the Trickle parameters and
 * the objective code point through the DODAG. Options that are not understood
 * are skipped on reception, so a DIO from another implementation still parses.
 */
class RplDioHeader : public Header
{
  public:
    /**
     * @brief Get the type ID.
     * @return the object TypeId
     */
    static TypeId GetTypeId();

    RplDioHeader();

    TypeId GetInstanceTypeId() const override;
    void Print(std::ostream& os) const override;
    uint32_t GetSerializedSize() const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;

    /**
     * @brief Set the RPL instance this DODAG belongs to.
     * @param instanceId the RPLInstanceID
     */
    void SetInstanceId(uint8_t instanceId);
    /**
     * @brief Get the RPL instance this DODAG belongs to.
     * @return the RPLInstanceID
     */
    uint8_t GetInstanceId() const;

    /**
     * @brief Set the DODAG version number.
     * @param version the version number
     */
    void SetVersionNumber(uint8_t version);
    /**
     * @brief Get the DODAG version number.
     * @return the version number
     */
    uint8_t GetVersionNumber() const;

    /**
     * @brief Set the rank of the sender.
     * @param rank the rank
     */
    void SetRank(uint16_t rank);
    /**
     * @brief Get the rank of the sender.
     * @return the rank
     */
    uint16_t GetRank() const;

    /**
     * @brief Set the Grounded flag, i.e. whether the DODAG reaches a goal.
     * @param grounded true if grounded
     */
    void SetGrounded(bool grounded);
    /**
     * @brief Get the Grounded flag.
     * @return true if the DODAG is grounded
     */
    bool GetGrounded() const;

    /**
     * @brief Set the Mode of Operation.
     * @param mop the mode of operation
     */
    void SetMop(uint8_t mop);
    /**
     * @brief Get the Mode of Operation.
     * @return the mode of operation
     */
    uint8_t GetMop() const;

    /**
     * @brief Set the DODAG preference, 0 being the least preferred.
     * @param preference the preference
     */
    void SetPreference(uint8_t preference);
    /**
     * @brief Get the DODAG preference.
     * @return the preference
     */
    uint8_t GetPreference() const;

    /**
     * @brief Set the Destination Advertisement Trigger Sequence Number.
     * @param dtsn the DTSN
     */
    void SetDtsn(uint8_t dtsn);
    /**
     * @brief Get the Destination Advertisement Trigger Sequence Number.
     * @return the DTSN
     */
    uint8_t GetDtsn() const;

    /**
     * @brief Set the DODAGID, the global address of the root.
     * @param dodagId the DODAGID
     */
    void SetDodagId(Ipv6Address dodagId);
    /**
     * @brief Get the DODAGID.
     * @return the DODAGID
     */
    Ipv6Address GetDodagId() const;

    /**
     * @brief Whether the DODAG Configuration option is present.
     * @return true if the option is present
     */
    bool HasDagConfiguration() const;

    /**
     * @brief Attach a DODAG Configuration option, RFC 6550 section 6.7.6.
     *
     * @param intervalDoublings DIOIntervalDoublings, i.e. Imax = Imin << this
     * @param intervalMin DIOIntervalMin, i.e. Imin = 2^this milliseconds
     * @param redundancy DIORedundancyConstant, the Trickle k
     * @param maxRankIncrease MaxRankIncrease
     * @param minHopRankIncrease MinHopRankIncrease
     * @param ocp the objective code point
     * @param defaultLifetime the default lifetime of downward routes
     * @param lifetimeUnit the unit, in seconds, of the default lifetime
     */
    void SetDagConfiguration(uint8_t intervalDoublings,
                             uint8_t intervalMin,
                             uint8_t redundancy,
                             uint16_t maxRankIncrease,
                             uint16_t minHopRankIncrease,
                             uint16_t ocp,
                             uint8_t defaultLifetime,
                             uint16_t lifetimeUnit);

    /**
     * @brief Get DIOIntervalDoublings from the DODAG Configuration option.
     * @return the number of doublings between Imin and Imax
     */
    uint8_t GetIntervalDoublings() const;
    /**
     * @brief Get DIOIntervalMin from the DODAG Configuration option.
     * @return Imin, as a power of two in milliseconds
     */
    uint8_t GetIntervalMin() const;
    /**
     * @brief Get DIORedundancyConstant from the DODAG Configuration option.
     * @return the Trickle redundancy constant
     */
    uint8_t GetRedundancy() const;
    /**
     * @brief Get MaxRankIncrease from the DODAG Configuration option.
     * @return the maximum rank increase allowed within a version
     */
    uint16_t GetMaxRankIncrease() const;
    /**
     * @brief Get MinHopRankIncrease from the DODAG Configuration option.
     * @return the minimum rank increase per hop
     */
    uint16_t GetMinHopRankIncrease() const;
    /**
     * @brief Get the objective code point from the DODAG Configuration option.
     * @return the objective code point
     */
    uint16_t GetOcp() const;
    /**
     * @brief Get the default lifetime from the DODAG Configuration option.
     * @return the default lifetime, in lifetime units
     */
    uint8_t GetDefaultLifetime() const;
    /**
     * @brief Get the lifetime unit from the DODAG Configuration option.
     * @return the lifetime unit, in seconds
     */
    uint16_t GetLifetimeUnit() const;

  private:
    /// Serialized size of the DODAG Configuration option, type and length byte
    /// included (RFC 6550, section 6.7.6).
    static constexpr uint8_t DAG_CONF_OPTION_SIZE = 16;
    /// Value of the length field of the DODAG Configuration option.
    static constexpr uint8_t DAG_CONF_OPTION_LENGTH = DAG_CONF_OPTION_SIZE - 2;

    uint8_t m_instanceId;    //!< RPLInstanceID
    uint8_t m_versionNumber; //!< DODAG version number
    uint16_t m_rank;         //!< rank of the sender
    bool m_grounded;         //!< Grounded flag
    uint8_t m_mop;           //!< Mode of Operation
    uint8_t m_preference;    //!< DODAG preference
    uint8_t m_dtsn;          //!< Destination Advertisement Trigger Sequence Number
    Ipv6Address m_dodagId;   //!< DODAGID

    bool m_hasDagConf;             //!< true if the DODAG Configuration option is present
    uint8_t m_dagConfFlags;        //!< flags, Authentication and PCS of the option
    uint8_t m_intervalDoublings;   //!< DIOIntervalDoublings
    uint8_t m_intervalMin;         //!< DIOIntervalMin
    uint8_t m_redundancy;          //!< DIORedundancyConstant
    uint16_t m_maxRankIncrease;    //!< MaxRankIncrease
    uint16_t m_minHopRankIncrease; //!< MinHopRankIncrease
    uint16_t m_ocp;                //!< objective code point
    uint8_t m_defaultLifetime;     //!< default lifetime of downward routes
    uint16_t m_lifetimeUnit;       //!< lifetime unit, in seconds
};

/**
 * @ingroup rpl
 *
 * @brief Destination Advertisement Object, RFC 6550 section 6.4.
 *
 * A DAO advertises one target, i.e. one address that can be reached through
 * the sender, and the Transit Information option that says through which
 * parent and for how long. RFC 6550 allows several targets to share one
 * Transit Information option; this implementation sends one target per DAO,
 * which costs a message per destination but keeps the parsing straightforward.
 *
 * In non-storing mode the Transit Information option carries the address of
 * the parent, which is what lets the root reassemble the whole topology out of
 * the target and parent pairs it collects.
 */
class RplDaoHeader : public Header
{
  public:
    /**
     * @brief Get the type ID.
     * @return the object TypeId
     */
    static TypeId GetTypeId();

    RplDaoHeader();

    TypeId GetInstanceTypeId() const override;
    void Print(std::ostream& os) const override;
    uint32_t GetSerializedSize() const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;

    /**
     * @brief Set the RPL instance this DAO belongs to.
     * @param instanceId the RPLInstanceID
     */
    void SetInstanceId(uint8_t instanceId);
    /**
     * @brief Get the RPL instance this DAO belongs to.
     * @return the RPLInstanceID
     */
    uint8_t GetInstanceId() const;

    /**
     * @brief Ask for a DAO-ACK, i.e. set the 'K' flag.
     * @param ackRequested true to request a DAO-ACK
     */
    void SetAckRequested(bool ackRequested);
    /**
     * @brief Whether a DAO-ACK was asked for.
     * @return true if the 'K' flag is set
     */
    bool GetAckRequested() const;

    /**
     * @brief Set the DAO sequence, which pairs a DAO with its DAO-ACK.
     * @param sequence the DAO sequence
     */
    void SetSequence(uint8_t sequence);
    /**
     * @brief Get the DAO sequence.
     * @return the DAO sequence
     */
    uint8_t GetSequence() const;

    /**
     * @brief Set the DODAGID, which also sets the 'D' flag.
     * @param dodagId the DODAGID
     */
    void SetDodagId(Ipv6Address dodagId);
    /**
     * @brief Get the DODAGID.
     * @return the DODAGID, :: if the 'D' flag was clear
     */
    Ipv6Address GetDodagId() const;

    /**
     * @brief Set the advertised target, RFC 6550 section 6.7.7.
     * @param target the address that can be reached through the sender
     * @param prefixLength the significant bits of the target, 128 for a host
     */
    void SetTarget(Ipv6Address target, uint8_t prefixLength = 128);
    /**
     * @brief Get the advertised target.
     * @return the target address
     */
    Ipv6Address GetTarget() const;
    /**
     * @brief Get the prefix length of the advertised target.
     * @return the prefix length
     */
    uint8_t GetTargetPrefixLength() const;

    /**
     * @brief Set the Transit Information option, RFC 6550 section 6.7.8.
     * @param parent the address of the parent the target is reached through
     * @param pathSequence the path sequence, which orders successive DAOs
     * @param pathLifetime the lifetime, in lifetime units, 0 for a No-Path
     */
    void SetTransitInformation(Ipv6Address parent, uint8_t pathSequence, uint8_t pathLifetime);
    /**
     * @brief Get the parent address of the Transit Information option.
     * @return the parent the target is reached through
     */
    Ipv6Address GetParent() const;
    /**
     * @brief Get the path sequence of the Transit Information option.
     * @return the path sequence
     */
    uint8_t GetPathSequence() const;
    /**
     * @brief Get the path lifetime of the Transit Information option.
     * @return the path lifetime, in lifetime units, 0 for a No-Path
     */
    uint8_t GetPathLifetime() const;

  private:
    /// Serialized size of the Target option for a full address, type and
    /// length byte included (RFC 6550, section 6.7.7).
    static constexpr uint8_t TARGET_OPTION_SIZE = 20;
    /// Value of the length field of the Target option.
    static constexpr uint8_t TARGET_OPTION_LENGTH = TARGET_OPTION_SIZE - 2;
    /// Serialized size of the Transit Information option in non-storing mode,
    /// i.e. with the parent address, type and length byte included (RFC 6550,
    /// section 6.7.8).
    static constexpr uint8_t TRANSIT_OPTION_SIZE = 22;
    /// Value of the length field of the Transit Information option.
    static constexpr uint8_t TRANSIT_OPTION_LENGTH = TRANSIT_OPTION_SIZE - 2;

    uint8_t m_instanceId;  //!< RPLInstanceID
    bool m_ackRequested;   //!< 'K' flag, a DAO-ACK is expected
    uint8_t m_sequence;    //!< DAO sequence
    Ipv6Address m_dodagId; //!< DODAGID, :: when the 'D' flag is clear

    Ipv6Address m_target;      //!< the advertised target
    uint8_t m_targetPrefixLen; //!< significant bits of the target
    Ipv6Address m_parent;      //!< the parent the target is reached through
    uint8_t m_pathSequence;    //!< path sequence of the Transit Information option
    uint8_t m_pathLifetime;    //!< path lifetime, 0 for a No-Path
};

/**
 * @ingroup rpl
 *
 * @brief Destination Advertisement Object Acknowledgement, RFC 6550 section 6.5.
 */
class RplDaoAckHeader : public Header
{
  public:
    /**
     * @brief Get the type ID.
     * @return the object TypeId
     */
    static TypeId GetTypeId();

    RplDaoAckHeader();

    TypeId GetInstanceTypeId() const override;
    void Print(std::ostream& os) const override;
    uint32_t GetSerializedSize() const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;

    /**
     * @brief Set the RPL instance this DAO-ACK belongs to.
     * @param instanceId the RPLInstanceID
     */
    void SetInstanceId(uint8_t instanceId);
    /**
     * @brief Get the RPL instance this DAO-ACK belongs to.
     * @return the RPLInstanceID
     */
    uint8_t GetInstanceId() const;

    /**
     * @brief Set the sequence of the DAO being acknowledged.
     * @param sequence the DAO sequence
     */
    void SetSequence(uint8_t sequence);
    /**
     * @brief Get the sequence of the DAO being acknowledged.
     * @return the DAO sequence
     */
    uint8_t GetSequence() const;

    /**
     * @brief Set the status, 0 meaning unqualified acceptance.
     * @param status the status
     */
    void SetStatus(uint8_t status);
    /**
     * @brief Get the status.
     * @return the status
     */
    uint8_t GetStatus() const;

    /**
     * @brief Set the DODAGID, which also sets the 'D' flag.
     * @param dodagId the DODAGID
     */
    void SetDodagId(Ipv6Address dodagId);
    /**
     * @brief Get the DODAGID.
     * @return the DODAGID, :: if the 'D' flag was clear
     */
    Ipv6Address GetDodagId() const;

  private:
    uint8_t m_instanceId;  //!< RPLInstanceID
    uint8_t m_sequence;    //!< sequence of the DAO being acknowledged
    uint8_t m_status;      //!< status, 0 on acceptance
    Ipv6Address m_dodagId; //!< DODAGID, :: when the 'D' flag is clear
};

/**
 * @ingroup rpl
 *
 * @brief The source routing header of RFC 6554, which carries the downward
 *        route the root computed for a packet.
 *
 * The wire format is the RH3 of RFC 6554 with CmprI, CmprE and Pad always
 * zero, i.e. every address is carried in full rather than compressed against
 * a common prefix; compressing addresses, which is what makes an RH3 cheap in
 * a real LLN, is not implemented. This is a genuine IPv6 extension header,
 * inserted at the node that originates the packet by
 * Ipv6RoutingProtocol::PrepareOutgoingPacket() and processed hop by hop by
 * RplIpv6ExtensionSourceRouting, the way RFC 6554 prescribes: nothing about
 * the downward path is carried out of band.
 */
class RplSourceRoutingHeader : public Ipv6ExtensionRoutingHeader
{
  public:
    /**
     * @brief Get the type ID.
     * @return the object TypeId
     */
    static TypeId GetTypeId();

    RplSourceRoutingHeader();

    TypeId GetInstanceTypeId() const override;
    void Print(std::ostream& os) const override;
    uint32_t GetSerializedSize() const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;

    /**
     * @brief Set the addresses of RFC 6554 section 3, in order.
     *
     * The last address is the packet's real final destination; the IPv6
     * header carries the address of the first hop instead, which is why it is
     * not repeated here.
     *
     * @param addresses the addresses to visit, in order
     */
    void SetAddresses(const std::vector<Ipv6Address>& addresses);

    /**
     * @brief Get the addresses of RFC 6554 section 3.
     * @return the addresses to visit, in order
     */
    const std::vector<Ipv6Address>& GetAddresses() const;

    /**
     * @brief Set one address of the list.
     * @param index the index of the address
     * @param address the new value
     */
    void SetAddress(uint8_t index, Ipv6Address address);

    /**
     * @brief Get one address of the list.
     * @param index the index of the address
     * @return the address at that index
     */
    Ipv6Address GetAddress(uint8_t index) const;

  private:
    std::vector<Ipv6Address> m_addresses; //!< addresses of RFC 6554 section 3, in order
};

/**
 * @ingroup rpl
 *
 * @brief The RPL Option (RPI), RFC 6553, carried in an IPv6 Hop-by-Hop header.
 *
 * Every data packet that travels along a DODAG carries one of these, giving
 * each router on the path the rank and direction (the 'O' flag: up towards
 * the root, or down away from it) the sender expected the packet to move in.
 * A router that finds the direction and the relative rank of the sender
 * inconsistent, e.g. a packet claiming to move up arriving from a sender of
 * lower rank, has a loop, or a stale downward route, on its hands: RFC 6550
 * section 11.2 has it flag the inconsistency once, with the 'R' flag, and
 * treat a second one in a row as confirmed. @see RplIpv6OptionRpl for what
 * this implementation can and cannot actually do about a confirmed one.
 *
 * The 'F' flag (Forwarding-Error, set by a storing-mode router unable to find
 * a downward route to relay the packet through) is defined for completeness
 * but never set by this implementation: non-storing mode's only forwarding
 * decision for downward traffic is the one the Routing Header already makes.
 */
class RplPacketInfoHeader : public Ipv6OptionHeader
{
  public:
    /**
     * @brief Get the type ID.
     * @return the object TypeId
     */
    static TypeId GetTypeId();

    RplPacketInfoHeader();

    TypeId GetInstanceTypeId() const override;
    void Print(std::ostream& os) const override;
    uint32_t GetSerializedSize() const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;

    /**
     * @brief Set the 'O' flag: true if the packet is moving down, away from
     *        the root; false if it is moving up, towards it.
     * @param down true for a downward packet
     */
    void SetDown(bool down);
    /**
     * @brief Get the 'O' flag.
     * @return true if the packet is moving down
     */
    bool GetDown() const;

    /**
     * @brief Set the 'R' flag: a rank inconsistency was already flagged once.
     * @param rankError true if a router already found the rank inconsistent
     */
    void SetRankError(bool rankError);
    /**
     * @brief Get the 'R' flag.
     * @return true if a rank inconsistency was already flagged
     */
    bool GetRankError() const;

    /**
     * @brief Set the 'F' flag. Never set by this implementation; see class docs.
     * @param forwardingError true if a router could not forward the packet
     */
    void SetForwardingError(bool forwardingError);
    /**
     * @brief Get the 'F' flag.
     * @return true if a router could not forward the packet
     */
    bool GetForwardingError() const;

    /**
     * @brief Set the RPL instance this packet's DODAG belongs to.
     * @param instanceId the RPLInstanceID
     */
    void SetInstanceId(uint8_t instanceId);
    /**
     * @brief Get the RPL instance this packet's DODAG belongs to.
     * @return the RPLInstanceID
     */
    uint8_t GetInstanceId() const;

    /**
     * @brief Set the rank of the router that last touched this field.
     * @param rank the sender's rank
     */
    void SetSenderRank(uint16_t rank);
    /**
     * @brief Get the rank of the router that last touched this field.
     * @return the sender's rank
     */
    uint16_t GetSenderRank() const;

  private:
    uint8_t m_flags;      //!< O, R and F flags in the top three bits
    uint8_t m_instanceId; //!< RPLInstanceID
    uint16_t m_senderRank; //!< rank of the router that last touched this field
};

} // namespace rpl
} // namespace ns3

#endif /* RPL_HEADER_H */
