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
 * @brief The P2P Route Discovery Option (P2P-RDO), RFC 6997 section 7.
 *
 * Unlike the AODV-RPL RREQ/RREP/ART options, which only ever appear inside a
 * DIO, a P2P-RDO is carried by two different messages: a P2P mode DIO
 * (RplDioHeader, RFC 6997 section 6) and a P2P-DRO (RplP2pDroHeader, RFC 6997
 * section 8) -- "A P2P mode DIO and a P2P-DRO message MUST carry exactly one
 * P2P-RDO" (section 7). It is therefore a free-standing struct with its own
 * P2pRdoSerializedSize()/P2pRdoSerialize()/P2pRdoDeserialize() rather than a
 * private nested type of either message class: duplicating the Compr and
 * Address Vector length arithmetic into two classes would risk exactly the
 * kind of declared-length-vs-actual-content mismatch bugs found elsewhere in
 * this module (@see design-constraints.md).
 *
 * addressVector, like the AODV-RPL options' own, always holds full 128-bit
 * addresses regardless of what came off (or goes onto) the wire --
 * P2pRdoSerialize() computes its own Compr fresh from target, addressVector
 * and the caller's dodagId, and P2pRdoDeserialize() reconstructs full
 * addresses before returning.
 */
struct P2pRdoOption
{
    bool reply{true};      //!< 'R': the Target(s) may send P2P-DRO messages back
    bool hopByHop{false};  //!< 'H': 1 for a Hop-by-hop Route, 0 for a Source Route
    /// 'N', 2 bits: one plus this many Source Routes are requested per
    /// Target. Always sent as 0 (exactly one route) and ignored on receipt;
    /// @see design-constraints.md for why more are out of scope.
    uint8_t numRoutes{0};
    /// 'Compr', 4 bits: elided prefix octets, shared by TargetAddr and every
    /// Address Vector entry alike (RFC 6997 section 7). Read from the wire on
    /// P2pRdoDeserialize(); P2pRdoSerialize() ignores this and computes its
    /// own, so setting it before calling has no effect on what is sent.
    uint8_t compr{0};
    uint8_t lifetime{0}; //!< 'L', 2 bits: @see RplP2pLifetimeSeconds()
    /// 'MaxRank/NH', 6 bits: MaxRank inside a P2P mode DIO (0 meaning no
    /// limit), or the Address Vector's next-hop index inside a P2P-DRO.
    uint8_t maxRankOrNh{0};
    Ipv6Address target;                     //!< 'TargetAddr'
    std::vector<Ipv6Address> addressVector; //!< 'Address[1..n]'
};

/**
 * @brief Serialized size of a P2pRdoOption, type and length bytes included.
 * @param rdo the option
 * @param dodagId the DODAGID of the enclosing message, against which Compr
 *                elision is computed
 * @return the size in octets
 */
uint32_t P2pRdoSerializedSize(const P2pRdoOption& rdo, Ipv6Address dodagId);

/**
 * @brief Serialize a P2pRdoOption, type and length bytes included.
 * @param i where to write; advanced past the option on return
 * @param rdo the option
 * @param dodagId the DODAGID of the enclosing message, against which Compr
 *                elision is computed
 */
void P2pRdoSerialize(Buffer::Iterator& i, const P2pRdoOption& rdo, Ipv6Address dodagId);

/**
 * @brief Deserialize a P2pRdoOption whose type byte has already been read.
 *
 * Same "declared length trusted, but validated before being acted on"
 * contract as RplDioHeader::Deserialize()'s own AODV-RPL option branches: on
 * a malformed option (length too short for the Compr it declares, or an
 * Address Vector entry count the length cannot evenly hold), this leaves i
 * exactly length bytes past the type/length pair and returns false without
 * touching rdo, so the caller's own option loop can skip past it unharmed.
 *
 * @param i positioned right after the option's length byte; advanced past
 *          the option's declared length on return, success or not
 * @param length the option's declared length (Option Length field)
 * @param dodagId the DODAGID of the enclosing message, against which Compr
 *                elision is resolved
 * @param rdo the option, populated on success
 * @return true if the option was well-formed
 */
bool P2pRdoDeserialize(Buffer::Iterator& i, uint8_t length, Ipv6Address dodagId, P2pRdoOption& rdo);

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
     * addressVector here always holds full 128-bit addresses regardless of
     * what came off (or goes onto) the wire: Serialize() computes its own
     * Compr fresh from the addresses and the DODAGID (@see
     * RplDioHeader::ElidedPrefixLength()) and Deserialize() reconstructs
     * full addresses before this struct is ever populated, the same
     * "compressed only on the wire" contract RplSourceRoutingHeader's
     * Cmpri()/Cmpre() keep for the Routing Header's own addresses.
     */
    struct RreqOption
    {
        bool symmetric{true};   //!< 'S': the route so far is symmetric (section 5)
        bool hopByHop{false};   //!< 'H': 1 hop-by-hop, 0 source routed
        /// 'Compr', 4 bits: elided prefix octets. Read from the wire on
        /// Deserialize(); Serialize() ignores this and computes its own,
        /// so setting it before calling SetRreq() has no effect on what is
        /// sent (@see RplDioHeader::ElidedPrefixLength()).
        uint8_t compr{0};
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
        /// 'Compr', 4 bits. Same Serialize()-computes-its-own-value
        /// contract as RreqOption::compr.
        uint8_t compr{0};
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
     * @brief Whether at least one AODV-RPL Target (ART) option is present.
     * @return true if the option is present
     */
    bool HasArt() const;
    /**
     * @brief Attach a single AODV-RPL Target (ART) option (RFC 9854,
     *        section 4.3), replacing every ART option already attached.
     *
     * The RREP-DIO case: RFC 9854 section 4.3 has it carry exactly one.
     * For an RREQ-DIO, which MAY carry several (section 6.1's own multiple
     * targets), @see AddArt() instead.
     *
     * @param art the option
     */
    void SetArt(const ArtOption& art);
    /**
     * @brief Get the first AODV-RPL Target (ART) option.
     *
     * For an RREQ-DIO carrying more than one, @see GetArts() for the rest.
     *
     * @return the option, default-constructed if none is present
     */
    const ArtOption& GetArt() const;
    /**
     * @brief Append an AODV-RPL Target (ART) option (RFC 9854, section
     *        4.3), for an RREQ-DIO naming more than one TargNode at once
     *        (section 6.1: "The OrigNode can initiate the route discovery
     *        process for multiple targets simultaneously by including
     *        multiple ART options").
     *
     * Unlike SetArt(), this adds rather than replaces.
     *
     * @param art the option
     */
    void AddArt(const ArtOption& art);
    /**
     * @brief Get every AODV-RPL Target (ART) option.
     * @return the list, in the order attached; empty if none are present
     */
    const std::vector<ArtOption>& GetArts() const;

    /**
     * @brief Whether the P2P Route Discovery Option (P2P-RDO) is present.
     * @return true if the option is present
     */
    bool HasP2pRdo() const;
    /**
     * @brief RFC 6550's own RPL Target option (section 6.7.7), reused
     *        inside a P2P mode DIO (RFC 6997) to name an additional
     *        Target beyond the P2P-RDO's own primary TargetAddr.
     *
     * This implementation only ever sends/accepts prefixLength 0 (a full
     * unicast address), the same simplification the DAO side already
     * makes (@see RplDaoHeader::TARGET_OPTION_LENGTH) -- multicast Targets
     * and prefixes are out of scope.
     */
    struct TargetOption
    {
        uint8_t prefixLength{0}; //!< 'Prefix Length'; only 0 (a full address) is supported
        Ipv6Address target;      //!< 'Target Prefix'
    };

    /**
     * @brief Get every additional Target named by an RPL Target option.
     * @return the list, empty if none are present
     */
    const std::vector<TargetOption>& GetTargets() const;
    /**
     * @brief Append an additional Target, carried as its own RPL Target
     *        option (RFC 6550 section 6.7.7, RFC 6997's own reuse of it).
     *
     * Unlike SetP2pRdo()/SetRreq()/etc., this adds rather than replaces:
     * a P2P mode DIO MAY carry any number of these.
     *
     * @param target the option
     */
    void AddTarget(const TargetOption& target);

    /**
     * @brief Attach a P2P-RDO (RFC 6997 section 7).
     *
     * A P2P mode DIO MUST carry exactly one; a second call replaces the
     * first.
     *
     * @param rdo the option; its Address Vector must hold at most
     *            RPL_P2P_ADDRESS_VECTOR_MAX_ENTRIES entries
     */
    void SetP2pRdo(const P2pRdoOption& rdo);
    /**
     * @brief Get the P2P-RDO.
     * @return the option, default-constructed if none is present
     */
    const P2pRdoOption& GetP2pRdo() const;

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
    /// An uncompressed Address Vector entry's size on the wire; an actual
    /// entry, after Compr elision, is this minus ElidedPrefixLength()'s
    /// result. Also AODV_ADDRESS_VECTOR_MAX_ENTRIES' own unit.
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
    /// Serialized size of the RPL Target option carrying a full address
    /// (Prefix Length 0): Type+Length (2), Flags (1), Prefix Length (1)
    /// and the 16-byte address -- the same fixed shape
    /// RplDaoHeader::TARGET_OPTION_SIZE has, duplicated rather than shared
    /// since the two classes have no other Target-related logic in common
    /// (unlike P2pRdoOption, carried by two message classes with real
    /// shared Compr arithmetic).
    static constexpr uint8_t TARGET_OPTION_SIZE = 20;
    /// Value of the length field of the RPL Target option.
    static constexpr uint8_t TARGET_OPTION_LENGTH = TARGET_OPTION_SIZE - 2;
    /// Mask of the 'L' field's high bit, which sits in the last bit of the
    /// RREQ/RREP option's first flag octet (bit 23 of the row); its low bit
    /// is the top bit of the octet after (bit 24). @see rpl-conf.h.
    static constexpr uint8_t AODV_LIFETIME_HIGH_BIT = 0x01;
    /// Mask of the 'L' field's low bit in the second octet.
    static constexpr uint8_t AODV_LIFETIME_LOW_BIT = 0x80;

    /**
     * @brief How many leading octets an RREQ/RREP Address Vector can elide.
     *
     * RFC 9854 sections 4.1/4.2: "the octets elided are shared with the
     * IPv6 address in the DODAGID". Mirrors RplSourceRoutingHeader::
     * Cmpri()/Cmpre() (@see design-constraints.md section 16): computed
     * fresh from the current addresses on every call rather than cached,
     * and a plain 0-or-8 choice -- an Address Vector entry and m_dodagId
     * are always global addresses under this simulation's one shared
     * prefix, so either every entry shares its first 8 octets with
     * m_dodagId or none usefully do.
     *
     * @param addressVector the Address Vector about to be serialized
     * @return 8 if every entry shares its first 8 octets with m_dodagId, 0
     *         otherwise (including when addressVector is empty)
     */
    uint8_t ElidedPrefixLength(const std::vector<Ipv6Address>& addressVector) const;

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
    /// Every AODV-RPL Target (ART) option attached: RFC 9854 section 6.1
    /// lets an RREQ-DIO carry more than one, though section 4.3 requires
    /// exactly one on an RREP-DIO. SetArt()/GetArt() operate on the first
    /// entry only; AddArt()/GetArts() see the whole list.
    std::vector<ArtOption> m_arts;

    bool m_hasP2pRdo;    //!< true if the P2P Route Discovery Option is present
    P2pRdoOption m_p2pRdo; //!< the P2P Route Discovery Option

    /// Additional Targets named by RPL Target options (RFC 6997's own
    /// reuse of RFC 6550 section 6.7.7), beyond the P2P-RDO's own primary
    /// TargetAddr. Empty on a DIO that names none.
    std::vector<TargetOption> m_targets;
};

/**
 * @ingroup rpl
 *
 * @brief P2P Discovery Reply Object (P2P-DRO), RFC 6997 section 8.
 *
 * Unlike a DIO, DAO or DAO-ACK, a P2P-DRO is a message type of its own
 * (ICMPv6 code 0x04) rather than a variant of an existing one: a Target
 * sends it, over link-local multicast, to carry a discovered route back to
 * the Origin -- identified by this message's own DODAGID field, copied from
 * the P2P mode DIO (RplDioHeader) that found the route. It MUST carry
 * exactly one P2P-RDO (@see P2pRdoOption), the same option a P2P mode DIO
 * carries, which is why P2pRdoOption's own (de)serialization is shared
 * between the two classes rather than duplicated here.
 *
 * The Version field is always zero (RFC 6997 section 8: "a temporary DAG
 * always has value zero for the Version") and so is not exposed as a
 * settable field; Serialize() always writes it as zero and Deserialize()
 * reads and discards it, the same treatment RplDioHeader gives the DIO base
 * object's own always-zero Flags/Reserved bytes.
 */
class RplP2pDroHeader : public Header
{
  public:
    /**
     * @brief Get the type ID.
     * @return the object TypeId
     */
    static TypeId GetTypeId();

    RplP2pDroHeader();

    TypeId GetInstanceTypeId() const override;
    void Print(std::ostream& os) const override;
    uint32_t GetSerializedSize() const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;

    /**
     * @brief Set the RPLInstanceID of the temporary DAG used for discovery.
     * @param instanceId the RPLInstanceID
     */
    void SetInstanceId(uint8_t instanceId);
    /**
     * @brief Get the RPLInstanceID of the temporary DAG used for discovery.
     * @return the RPLInstanceID
     */
    uint8_t GetInstanceId() const;

    /**
     * @brief Set the 'Stop' flag.
     *
     * RFC 6997 section 8: a Target sets this to say the P2P-RPL route
     * discovery is over, so routers should stop generating or processing
     * DIOs for this temporary DAG (but keep processing P2P-DRO messages).
     *
     * @param stop true to set the flag
     */
    void SetStop(bool stop);
    /**
     * @brief Get the 'Stop' flag.
     * @return true if set
     */
    bool GetStop() const;

    /**
     * @brief Set the 'Ack Required' (A) flag: ask the Origin to reply with a
     *        P2P-DRO-ACK.
     * @param ackRequested true to set the flag
     */
    void SetAckRequested(bool ackRequested);
    /**
     * @brief Get the 'Ack Required' (A) flag.
     * @return true if set
     */
    bool GetAckRequested() const;

    /**
     * @brief Set the sequence number that pairs this P2P-DRO with the
     *        P2P-DRO-ACK sent in response.
     * @param sequence the 'Seq' field, 2 bits
     */
    void SetSequence(uint8_t sequence);
    /**
     * @brief Get the sequence number.
     * @return the 'Seq' field
     */
    uint8_t GetSequence() const;

    /**
     * @brief Set the DODAGID: the temporary DAG's root, the Origin.
     * @param dodagId the DODAGID
     */
    void SetDodagId(Ipv6Address dodagId);
    /**
     * @brief Get the DODAGID.
     * @return the DODAGID
     */
    Ipv6Address GetDodagId() const;

    /**
     * @brief Whether the P2P-RDO is present.
     *
     * RFC 6997 section 8: "A received P2P-DRO message MUST be discarded if
     * it does not contain exactly one P2P-RDO" -- tracked rather than
     * assumed, the same way HasArt() lets HandleAodvRrep() check for an RREP
     * missing its own required option.
     *
     * @return true if the option is present
     */
    bool HasP2pRdo() const;
    /**
     * @brief Attach the P2P-RDO.
     * @param rdo the option; its Address Vector must hold at most
     *            RPL_P2P_ADDRESS_VECTOR_MAX_ENTRIES entries
     */
    void SetP2pRdo(const P2pRdoOption& rdo);
    /**
     * @brief Get the P2P-RDO.
     * @return the option, default-constructed if none is present
     */
    const P2pRdoOption& GetP2pRdo() const;

  private:
    /// Serialized size of the fixed base object -- RPLInstanceID, Version,
    /// flags, Reserved, DODAGID -- before any options (RFC 6997 section 8,
    /// Figure 2). Unlike an option, this has no length field of its own to
    /// validate a received packet against, so Deserialize() checks a
    /// received packet's remaining size against this directly before
    /// reading any of it.
    static constexpr uint8_t BASE_SIZE = 20;

    uint8_t m_instanceId;  //!< RPLInstanceID
    bool m_stop;           //!< 'S' flag
    bool m_ackRequested;   //!< 'A' flag
    uint8_t m_sequence;    //!< 'Seq', 2 bits
    Ipv6Address m_dodagId; //!< DODAGID

    bool m_hasP2pRdo;    //!< true if the P2P-RDO is present
    P2pRdoOption m_p2pRdo; //!< the P2P-RDO
};

/**
 * @ingroup rpl
 *
 * @brief P2P Discovery Reply Object Acknowledgement, RFC 6997 section 10.
 *
 * Unlike the P2P-DRO, this carries no options at all -- the base object,
 * unconditionally 20 bytes, is the entire message. Sent by the Origin to
 * the Target, as a unicast, when a received P2P-DRO's 'A' flag asked for
 * one; instanceId/dodagId/sequence are copied straight from that P2P-DRO
 * (RFC 6997 section 10: "Various fields...MUST have the same values as
 * the corresponding fields in the P2P-DRO message").
 */
class RplP2pDroAckHeader : public Header
{
  public:
    /**
     * @brief Get the type ID.
     * @return the object TypeId
     */
    static TypeId GetTypeId();

    RplP2pDroAckHeader();

    TypeId GetInstanceTypeId() const override;
    void Print(std::ostream& os) const override;
    uint32_t GetSerializedSize() const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;

    /**
     * @brief Set the RPLInstanceID of the temporary DAG this acknowledges.
     * @param instanceId the RPLInstanceID
     */
    void SetInstanceId(uint8_t instanceId);
    /**
     * @brief Get the RPLInstanceID of the temporary DAG this acknowledges.
     * @return the RPLInstanceID
     */
    uint8_t GetInstanceId() const;

    /**
     * @brief Set the sequence number of the P2P-DRO being acknowledged.
     * @param sequence the 'Seq' field, 2 bits
     */
    void SetSequence(uint8_t sequence);
    /**
     * @brief Get the sequence number of the P2P-DRO being acknowledged.
     * @return the 'Seq' field
     */
    uint8_t GetSequence() const;

    /**
     * @brief Set the DODAGID: the temporary DAG's root, the Origin.
     * @param dodagId the DODAGID
     */
    void SetDodagId(Ipv6Address dodagId);
    /**
     * @brief Get the DODAGID.
     * @return the DODAGID
     */
    Ipv6Address GetDodagId() const;

  private:
    /// Serialized size of this header -- fixed, since it carries no
    /// options. Checked by Deserialize() against a received packet's
    /// remaining size before reading any of it, the same reason
    /// RplP2pDroHeader::BASE_SIZE exists.
    static constexpr uint8_t SIZE = 20;

    uint8_t m_instanceId;  //!< RPLInstanceID
    uint8_t m_sequence;    //!< 'Seq', 2 bits
    Ipv6Address m_dodagId; //!< DODAGID
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

    /**
     * @brief One additional Target + Transit Information pair beyond the
     *        primary one (SetTarget()/SetTransitInformation()).
     *
     * RFC 6550 section 9.4: "a DAO message may include several groups of
     * options, where each group consists of one or more Target options
     * followed by one or more Transit Information options." This is that
     * general grouping rule taken to its simplest per-target form -- one
     * Target option immediately followed by its own Transit Information
     * option -- which is all this module ever needs, since it never varies
     * the Transit Information's own parent field across targets in one
     * message (@see AddTarget()'s own doc comment).
     */
    struct AdditionalTarget
    {
        Ipv6Address target;               //!< the additional target address
        uint8_t targetPrefixLength{128};  //!< significant bits of the target
        uint8_t pathSequence{0};          //!< path sequence for this target
        uint8_t pathLifetime{0};          //!< path lifetime for this target, 0 for a No-Path
    };

    /**
     * @brief Append an additional Target + Transit Information pair, letting
     *        one DAO message carry several targets (RFC 6550 section 9.4
     *        rule 3) instead of one message per target.
     *
     * The appended pair's own Transit Information option shares this
     * message's single Transit Information parent field
     * (SetTransitInformation()'s own @p parent) rather than carrying one of
     * its own: this module never has a reason to vary it across targets in
     * one message (Storing mode leaves it empty for every target
     * regardless, RFC 6550 section 9.8 rule 1; Non-Storing mode's own
     * sender has exactly one preferred parent to report, the same for
     * every target it is relaying). A general RFC 6550 sender is free to
     * pair different Target option groups with different Transit
     * Information options of their own; this is the simplification this
     * module's own send side never needs more than.
     *
     * @param additionalTarget the target, prefix length, path sequence and
     *        path lifetime to append
     */
    void AddTarget(const AdditionalTarget& additionalTarget);

    /**
     * @brief Get every additional Target + Transit Information pair beyond
     *        the primary one.
     * @return the additional pairs, in the order they were added (or, after
     *         a Deserialize(), the order they were found on the wire)
     */
    const std::vector<AdditionalTarget>& GetAdditionalTargets() const;

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

    /// Every Target + Transit Information pair beyond the primary one
    /// above, in wire order; @see AddTarget()'s own doc comment for why
    /// they all still share m_parent rather than carrying one of their own.
    std::vector<AdditionalTarget> m_additionalTargets;
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
