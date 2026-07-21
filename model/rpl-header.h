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

} // namespace rpl
} // namespace ns3

#endif /* RPL_HEADER_H */
