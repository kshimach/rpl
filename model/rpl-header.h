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

    /**
     * @brief Whether the DAG Metric Container option is present.
     * @return true if the option is present
     */
    bool HasMetricContainer() const;

    /**
     * @brief Attach a DAG Metric Container option carrying an ETX Routing
     *        Metric object, RFC 6550 section 6.7.4 and RFC 6551 section 4.3.
     *
     * Only the ETX object is supported: this implementation has no other
     * metric to put in the container, so it does not carry more than one.
     *
     * @param pathEtx the path ETX to advertise, fixed-point as ETX * 128
     */
    void SetMetricContainer(uint16_t pathEtx);

    /**
     * @brief Get the path ETX from the DAG Metric Container option.
     * @return the path ETX, fixed-point as ETX * 128
     */
    uint16_t GetPathEtx() const;

    /**
     * @brief Whether a DAG Metric Container option carrying a Link Quality
     *        Level (LQL) object is present.
     * @return true if the option is present
     */
    bool HasLql() const;

    /**
     * @brief Attach a DAG Metric Container option carrying a Link Quality
     *        Level Routing Metric object, RFC 6550 section 6.7.4 and RFC
     *        6551 section 4.6.
     *
     * Carried alongside, not instead of, the ETX object set with
     * SetMetricContainer(): RFC 6551 allows more than one
     * Routing-MC-Type object in the same DIO, and LQL is a "recorded
     * only" link metric (RFC 6551 section 3.4), not something this
     * implementation's Objective Functions compute a rank from, so it
     * does not replace ETX as MRHOF's input.
     *
     * @param lql the Link Quality Level to advertise, 0 (undetermined) to
     *            7 (worst determined), 1 being the best
     */
    void SetLql(uint8_t lql);

    /**
     * @brief Get the Link Quality Level from the DAG Metric Container option.
     * @return the LQL, 0 (undetermined) to 7 (worst determined)
     */
    uint8_t GetLql() const;

    /**
     * @brief Whether the Prefix Information option is present.
     * @return true if the option is present
     */
    bool HasPrefixInfo() const;

    /**
     * @brief Attach a Prefix Information option, RFC 6550 section 6.7.10.
     *
     * This is how the root disseminates the prefix a node should build its
     * global address on: every node that joins copies this option onto its
     * own outgoing DIOs unchanged, the same way the DODAG Configuration
     * option propagates.
     *
     * @param prefix the prefix
     * @param prefixLength the prefix length in bits
     * @param onLink the 'L' flag: the prefix can be used for on-link
     *               determination
     * @param autonomous the 'A' flag: the prefix can be used for stateless
     *                   address autoconfiguration (RFC 4862)
     * @param validLifetime the 'Valid Lifetime', in seconds
     * @param preferredLifetime the 'Preferred Lifetime', in seconds
     */
    void SetPrefixInfo(Ipv6Address prefix,
                       uint8_t prefixLength,
                       bool onLink,
                       bool autonomous,
                       uint32_t validLifetime,
                       uint32_t preferredLifetime);

    /**
     * @brief Get the advertised prefix.
     * @return the prefix
     */
    Ipv6Address GetPrefix() const;
    /**
     * @brief Get the advertised prefix length.
     * @return the prefix length in bits
     */
    uint8_t GetPrefixLength() const;
    /**
     * @brief Get the 'L' (on-link) flag of the Prefix Information option.
     * @return true if the prefix can be used for on-link determination
     */
    bool GetPrefixOnLink() const;
    /**
     * @brief Get the 'A' (autonomous) flag of the Prefix Information option.
     * @return true if the prefix can be used for SLAAC
     */
    bool GetPrefixAutonomous() const;
    /**
     * @brief Get the Valid Lifetime of the Prefix Information option.
     * @return the valid lifetime, in seconds
     */
    uint32_t GetPrefixValidLifetime() const;
    /**
     * @brief Get the Preferred Lifetime of the Prefix Information option.
     * @return the preferred lifetime, in seconds
     */
    uint32_t GetPrefixPreferredLifetime() const;

    /**
     * @brief The AODV-RPL Route Request option (RFC 9854, section 4.1).
     *
     * Grouped into a struct rather than spread across loose members the way
     * this class's four RFC 6550 options are: these carry six scalars and a
     * variable-length vector each, and three such sets of loose members
     * would be considerably harder to read than the existing four options
     * are. @see design-constraints.md for the deviation.
     *
     * The Address Vector accumulates, hop by hop on the way out, the route
     * the RREQ-DIO has taken (RFC 9854 section 6.2.5), OrigNode-side first.
     * Its entries are full 128-bit addresses: this implementation always
     * sends Compr == 0, so no prefix octets are ever elided.
     */
    struct RreqOption
    {
        bool symmetric{true};   //!< 'S': the route so far is symmetric (section 5)
        bool hopByHop{false};   //!< 'H': 1 hop-by-hop, 0 source routed
        uint8_t compr{0};       //!< 'Compr', 4 bits: elided prefix octets
        uint8_t lifetime{0};    //!< 'L', 2 bits: @see RplAodvLifetimeSeconds()
        uint8_t rankLimit{0};   //!< 'RankLimit', 7 bits, 0 meaning no limit
        uint8_t origSeqNo{0};   //!< 'Orig SeqNo': the OrigNode's Sequence Number
        std::vector<Ipv6Address> addressVector; //!< the route accumulated so far
    };

    /**
     * @brief The AODV-RPL Route Reply option (RFC 9854, section 4.2).
     *
     * The same shape as RreqOption, with 'S' replaced by 'G' (Gratuitous
     * RREP, section 7, which this implementation never sets) and 'Orig
     * SeqNo' by 'Delta' (section 6.3.3's RPLInstanceID pairing).
     */
    struct RrepOption
    {
        bool gratuitous{false}; //!< 'G': a Gratuitous RREP (section 7)
        bool hopByHop{false};   //!< 'H', matching the RREQ's own
        uint8_t compr{0};       //!< 'Compr', 4 bits
        uint8_t lifetime{0};    //!< 'L', 2 bits
        uint8_t rankLimit{0};   //!< 'RankLimit', 7 bits, 0 meaning no limit
        uint8_t delta{0};       //!< 'Delta', 6 bits: RREP-InstanceID - RREQ-InstanceID
        std::vector<Ipv6Address> addressVector; //!< the route back to the OrigNode
    };

    /**
     * @brief The AODV-RPL Target (ART) option (RFC 9854, section 4.3).
     *
     * RFC 6550's own Target option with the Flags field replaced by the
     * TargNode's Destination Sequence Number and Prefix Length narrowed to
     * seven bits. This implementation only ever sends prefixLength 0, which
     * RFC 9854 section 4.3 defines as "the value in the Target Prefix /
     * Address field represents an IPv6 address, not a prefix" -- so the
     * field is always a full 16 bytes and the option a fixed 20 bytes, the
     * same size as RFC 6550's Target option.
     */
    struct ArtOption
    {
        uint8_t destSeqNo{0};    //!< 'Dest SeqNo', 0 when nothing is known
        uint8_t prefixLength{0}; //!< 'Prefix Length', 7 bits; 0 means an address
        Ipv6Address target;      //!< 'Target Prefix / Address'
    };

    /**
     * @brief Whether the AODV-RPL RREQ option is present.
     * @return true if the option is present
     */
    bool HasRreq() const;
    /**
     * @brief Attach an AODV-RPL RREQ option (RFC 9854, section 4.1).
     * @param rreq the option; its Address Vector must hold at most
     *             AODV_ADDRESS_VECTOR_MAX_ENTRIES entries
     */
    void SetRreq(const RreqOption& rreq);
    /**
     * @brief Get the AODV-RPL RREQ option.
     * @return the option, default-constructed if none is present
     */
    const RreqOption& GetRreq() const;

    /**
     * @brief Whether the AODV-RPL RREP option is present.
     * @return true if the option is present
     */
    bool HasRrep() const;
    /**
     * @brief Attach an AODV-RPL RREP option (RFC 9854, section 4.2).
     * @param rrep the option; its Address Vector must hold at most
     *             AODV_ADDRESS_VECTOR_MAX_ENTRIES entries
     */
    void SetRrep(const RrepOption& rrep);
    /**
     * @brief Get the AODV-RPL RREP option.
     * @return the option, default-constructed if none is present
     */
    const RrepOption& GetRrep() const;

    /**
     * @brief Whether the AODV-RPL Target (ART) option is present.
     * @return true if the option is present
     */
    bool HasArt() const;
    /**
     * @brief Attach an AODV-RPL Target (ART) option (RFC 9854, section 4.3).
     *
     * At most one, unlike the RFC, which lets an RREQ-DIO carry several to
     * look for several targets at once -- @see design-constraints.md for why
     * multiple targets are out of scope. A second call replaces the first.
     *
     * @param art the option
     */
    void SetArt(const ArtOption& art);
    /**
     * @brief Get the AODV-RPL Target (ART) option.
     * @return the option, default-constructed if none is present
     */
    const ArtOption& GetArt() const;

    /// How many Address Vector entries an RREQ/RREP option can carry. Not a
    /// policy choice: the option's own Opt Data Len is eight bits, so with a
    /// 3-byte fixed part and 16 bytes per entry (Compr is always 0 here) the
    /// wire format itself stops at 15, since 3 + 16 * 16 = 259 > 255.
    static constexpr uint8_t AODV_ADDRESS_VECTOR_MAX_ENTRIES = 15;

  private:
    /// Serialized size of the DODAG Configuration option, type and length byte
    /// included (RFC 6550, section 6.7.6).
    static constexpr uint8_t DAG_CONF_OPTION_SIZE = 16;
    /// Value of the length field of the DODAG Configuration option.
    static constexpr uint8_t DAG_CONF_OPTION_LENGTH = DAG_CONF_OPTION_SIZE - 2;
    /// Serialized size of the DAG Metric Container option carrying a single
    /// ETX object: RPL option type and length (2 bytes), the RFC 6551
    /// Routing Metric/Constraint object's own common header (4 bytes), and
    /// the 16-bit ETX object body (2 bytes).
    static constexpr uint8_t METRIC_CONTAINER_OPTION_SIZE = 8;
    /// Value of the length field of the DAG Metric Container option.
    static constexpr uint8_t METRIC_CONTAINER_OPTION_LENGTH = METRIC_CONTAINER_OPTION_SIZE - 2;
    /// Serialized size of the DAG Metric Container option carrying a single
    /// LQL object: RPL option type and length (2 bytes), the RFC 6551
    /// Routing Metric/Constraint object's own common header (4 bytes), and
    /// the 2-byte LQL object body (a reserved octet plus one LQL sub-object,
    /// RFC 6551 section 4.6).
    static constexpr uint8_t LQL_OPTION_SIZE = 8;
    /// Value of the length field of the LQL DAG Metric Container option.
    static constexpr uint8_t LQL_OPTION_LENGTH = LQL_OPTION_SIZE - 2;
    /// Serialized size of the Prefix Information option, type and length
    /// byte included (RFC 6550, section 6.7.10): Type+Length (2), Prefix
    /// Length (1), L/A/Reserved1 (1), Valid Lifetime (4), Preferred
    /// Lifetime (4), and the 16-byte Prefix -- unlike RFC 4861's Neighbor
    /// Discovery PIO (32 bytes), this option has no 4-byte Reserved2 field
    /// between Preferred Lifetime and Prefix.
    static constexpr uint8_t PREFIX_INFO_OPTION_SIZE = 28;
    /// Value of the length field of the Prefix Information option.
    static constexpr uint8_t PREFIX_INFO_OPTION_LENGTH = PREFIX_INFO_OPTION_SIZE - 2;
    static constexpr uint8_t PREFIX_INFO_L_FLAG = 0x80; //!< 'L' (on-link) flag
    static constexpr uint8_t PREFIX_INFO_A_FLAG = 0x40; //!< 'A' (autonomous) flag
    /// Bytes one Address Vector entry takes on the wire. Sixteen, not
    /// 16 - Compr: this implementation always sends Compr == 0 (@see
    /// RreqOption) and refuses to parse a nonzero one.
    static constexpr uint8_t AODV_ADDRESS_VECTOR_ENTRY_SIZE = 16;
    /// The part of the RREQ option's length field that is there whatever the
    /// Address Vector holds: the two octets carrying S/H/X/Compr/L/RankLimit,
    /// plus Orig SeqNo (RFC 9854, section 4.1).
    static constexpr uint8_t AODV_RREQ_OPTION_BASE_LENGTH = 3;
    /// The same for the RREP option, whose third octet is Delta/reserved
    /// rather than Orig SeqNo (RFC 9854, section 4.2).
    static constexpr uint8_t AODV_RREP_OPTION_BASE_LENGTH = 3;
    /// Serialized size of the ART option carrying a full address (Prefix
    /// Length 0): Type+Length (2), Dest SeqNo (1), X/Prefix Length (1) and
    /// the 16-byte address.
    static constexpr uint8_t AODV_ART_OPTION_SIZE = 20;
    /// Value of the length field of the ART option.
    static constexpr uint8_t AODV_ART_OPTION_LENGTH = AODV_ART_OPTION_SIZE - 2;
    /// Mask of the 'L' field's high bit, which sits in the last bit of the
    /// RREQ/RREP option's first flag octet (bit 23 of the row); its low bit
    /// is the top bit of the octet after (bit 24). @see rpl-conf.h.
    static constexpr uint8_t AODV_LIFETIME_HIGH_BIT = 0x01;
    /// Mask of the 'L' field's low bit in the second octet.
    static constexpr uint8_t AODV_LIFETIME_LOW_BIT = 0x80;

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

    bool m_hasMetricContainer; //!< true if the ETX DAG Metric Container option is present
    uint16_t m_pathEtx;        //!< path ETX advertised by the option, as ETX * 128

    bool m_hasLql; //!< true if the LQL DAG Metric Container option is present
    uint8_t m_lql; //!< LQL advertised by the option, 0 (undetermined) to 7

    bool m_hasPrefixInfo;         //!< true if the Prefix Information option is present
    Ipv6Address m_prefix;         //!< the advertised prefix
    uint8_t m_prefixLength;       //!< the advertised prefix length, in bits
    bool m_prefixOnLink;          //!< 'L' flag
    bool m_prefixAutonomous;      //!< 'A' flag
    uint32_t m_prefixValidLifetime;     //!< Valid Lifetime, in seconds
    uint32_t m_prefixPreferredLifetime; //!< Preferred Lifetime, in seconds

    bool m_hasRreq;    //!< true if the AODV-RPL RREQ option is present
    RreqOption m_rreq; //!< the AODV-RPL RREQ option
    bool m_hasRrep;    //!< true if the AODV-RPL RREP option is present
    RrepOption m_rrep; //!< the AODV-RPL RREP option
    bool m_hasArt;     //!< true if the AODV-RPL Target (ART) option is present
    ArtOption m_art;   //!< the AODV-RPL Target (ART) option
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
 * The wire format is the RH3 of RFC 6554, with CmprI and CmprE (the number
 * of shared prefix octets elided from, respectively, every address but the
 * last, and the last address) chosen per header, address by address: an
 * address is compressed exactly when it is link-local, eliding its
 * (implementation-independent, RFC 4291) fe80::/64 prefix; anything else
 * (a global address, e.g. the real final destination -- see
 * RplRoutingProtocol::PrepareOutgoingPacket()'s own comment on why that one
 * address is deliberately global rather than link-local) is carried in
 * full. Every entry but the last is always link-local in this
 * implementation (RplRoutingProtocol::ComputeSourceRoute() only ever
 * collects link-local next-hop identifiers, and
 * RplIpv6ExtensionSourceRouting::Process() only ever rewrites a visited
 * entry with the relaying router's own link-local address), so this
 * compresses every hop but the last in practice. Since a compressed entry
 * always elides a whole, fixed, 8-octet prefix, CmprI and CmprE only ever
 * take the values 0 or 8, and the header's size is always a multiple of 8
 * octets on its own, so Pad is always 0.
 *
 * Because the elided prefix is this fixed constant rather than something
 * carried on the wire, decompression needs no other context (in particular
 * not the enclosing IPv6 header's Destination Address, which the general
 * RFC 6554 mechanism uses and Serialize()/Deserialize() have no access to
 * anyway) -- it is still what RFC 6554-compliant decompression would
 * recover: at the point in RplIpv6ExtensionSourceRouting::Process() where
 * any compressed entry is read, the packet's actual Destination Address is
 * always link-local with the same elided prefix, so a generic RFC 6554
 * implementation reading these packets would decompress them the same way.
 *
 * This is a genuine IPv6 extension header, inserted at the node that
 * originates the packet by Ipv6RoutingProtocol::PrepareOutgoingPacket() and
 * processed hop by hop by RplIpv6ExtensionSourceRouting, the way RFC 6554
 * prescribes: nothing about the downward path is carried out of band.
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

    /// The largest this header can be on the wire: RFC 8200 section 4.4's
    /// Hdr Ext Len counts eight-octet units past the first eight, in eight
    /// bits, so (255 + 1) * 8. A path long enough to need more than this
    /// cannot be expressed as one Routing Header at all.
    static constexpr uint32_t MAX_SERIALIZED_SIZE = 2048;

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
     * The resulting header has to fit MAX_SERIALIZED_SIZE, which how much of
     * each address compresses away decides (@see Cmpri()): between 127
     * addresses if none of them do and 255 if they all do. Serialize()
     * asserts on a list that does not fit; callers building one from a path
     * of their own should check GetSerializedSize() first.
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
    /**
     * @brief The CmprI this header would serialize as: how many octets are
     *        elided from every address but the last.
     * @return 8 if there is at least one non-last address and all of them
     *         are link-local, 0 otherwise
     */
    uint8_t Cmpri() const;

    /**
     * @brief The CmprE this header would serialize as: how many octets are
     *        elided from the last address.
     * @return 8 if the last address is link-local, 0 otherwise (including
     *         when there is no address at all)
     */
    uint8_t Cmpre() const;

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
    /// Opt Data Len of an option carrying nothing but the mandatory base
    /// octets of RFC 6553 section 3: Flags, RPLInstanceID and SenderRank.
    static constexpr uint8_t RPI_BASE_LENGTH = 4;

    /// What an option of RPI_BASE_LENGTH occupies on the wire, Option Type
    /// and Opt Data Len included.
    static constexpr uint8_t RPI_BASE_SIZE = RPI_BASE_LENGTH + 2;

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

    /**
     * @brief Whether the last Deserialize() found the option unusable.
     *
     * RFC 6553 section 3's Opt Data Len is whatever the sender wrote: it can
     * be shorter than the four mandatory base octets, or claim more bytes
     * than the packet actually carries. Neither can be parsed, and neither
     * can be trusted to say how far the enclosing Hop-by-Hop header's option
     * walk should advance, so Deserialize() reports only the two octets it
     * really read and raises this instead. @see RplIpv6OptionRpl::Process(),
     * which turns it into a drop.
     *
     * @return true if the option as received could not be parsed
     */
    bool IsMalformed() const;

    /**
     * @brief The bytes past the four mandatory base octets, if any.
     *
     * RFC 6553 section 3: "A RPL device MUST skip over any unrecognized
     * sub-TLVs and attempt to process any additional sub-TLVs that may
     * appear after." This implementation defines no sub-TLV of its own, so
     * they are kept verbatim and written back out unchanged by Serialize()
     * rather than interpreted -- a router that dropped them would be
     * rewriting an option it does not understand.
     *
     * @return the sub-TLV bytes, empty for the plain four-octet option
     */
    const std::vector<uint8_t>& GetSubTlvs() const;

  private:
    uint8_t m_flags;       //!< O, R and F flags in the top three bits
    uint8_t m_instanceId;  //!< RPLInstanceID
    uint16_t m_senderRank; //!< rank of the router that last touched this field
    std::vector<uint8_t> m_subTlvs; //!< opaque bytes past the four base octets
    bool m_malformed;               //!< set by Deserialize() on an unparseable option
};

} // namespace rpl
} // namespace ns3

#endif /* RPL_HEADER_H */
