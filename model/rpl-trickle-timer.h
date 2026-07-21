/*
 * Copyright (c) 2026 ns-3 RPL module contributors
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * The Trickle algorithm, RFC 6206.
 */

#ifndef RPL_TRICKLE_TIMER_H
#define RPL_TRICKLE_TIMER_H

#include "ns3/callback.h"
#include "ns3/nstime.h"
#include "ns3/ptr.h"
#include "ns3/random-variable-stream.h"
#include "ns3/timer.h"

namespace ns3
{
namespace rpl
{

/**
 * @ingroup rpl
 *
 * @brief The Trickle algorithm of RFC 6206, as used to pace DIOs.
 *
 * An interval I starts at Imin and doubles at the end of every interval up to
 * Imax = Imin << doublings. A transmission is scheduled at a uniformly random
 * point in [I/2, I); it happens only if fewer than k consistent messages have
 * been heard during the interval, so that a dense neighbourhood settles into
 * one transmitter. Following Contiki-NG, k = 0 means suppression is disabled.
 *
 * A detected inconsistency, e.g. a new DODAG version or a rank change, resets
 * the interval to Imin, which is what makes the network converge quickly after
 * a change and stay near-silent when nothing happens.
 */
class RplTrickleTimer
{
  public:
    RplTrickleTimer();
    ~RplTrickleTimer();

    /**
     * @brief Set the Trickle parameters.
     *
     * @param intervalMin Imin, the shortest interval
     * @param doublings the number of doublings between Imin and Imax
     * @param redundancy the redundancy constant k, 0 to never suppress
     */
    void SetParameters(Time intervalMin, uint8_t doublings, uint8_t redundancy);

    /**
     * @brief Set the function called when the timer decides to transmit.
     * @param callback the transmission callback
     */
    void SetFunction(Callback<void> callback);

    /**
     * @brief Start the algorithm with I = Imin.
     *
     * RFC 6206 allows the first interval to be picked anywhere in [Imin, Imax];
     * starting at Imin is what Contiki-NG does and gets a DODAG up quickly.
     */
    void Start();

    /**
     * @brief Stop the algorithm and cancel the pending events.
     */
    void Stop();

    /**
     * @brief Whether the algorithm is running.
     * @return true if running
     */
    bool IsRunning() const;

    /**
     * @brief Reset the interval to Imin, as done on an inconsistency.
     *
     * Per RFC 6206 section 4.2 this is a no-op when the interval is already
     * Imin, so a burst of inconsistencies cannot keep restarting the interval.
     */
    void Reset();

    /**
     * @brief Record a consistent message, i.e. increment the Trickle counter.
     */
    void ConsistencyHit();

    /**
     * @brief Get the current interval length.
     * @return the current I
     */
    Time GetInterval() const;

    /**
     * @brief Assign a fixed stream number to the random variable used here.
     * @param stream the stream index to use
     * @return the number of stream indices assigned
     */
    int64_t AssignStreams(int64_t stream);

  private:
    /**
     * @brief Start a new interval: reset the counter and schedule the events.
     */
    void NewInterval();

    /**
     * @brief Transmit unless the interval was found redundant.
     */
    void TransmitEvent();

    /**
     * @brief Double the interval, up to Imax, and start the next one.
     */
    void IntervalEvent();

    Time m_intervalMin;     //!< Imin
    Time m_intervalMax;     //!< Imax
    Time m_interval;        //!< the current interval I
    uint8_t m_redundancy;   //!< the redundancy constant k
    uint16_t m_counter;     //!< consistent messages heard during this interval
    bool m_running;         //!< true between Start() and Stop()
    Timer m_transmitTimer; //!< fires at t inside the interval
    Timer m_intervalTimer; //!< fires at the end of the interval
    Callback<void> m_callback;       //!< called on transmission
    Ptr<UniformRandomVariable> m_rng; //!< picks t inside [I/2, I)
};

} // namespace rpl
} // namespace ns3

#endif /* RPL_TRICKLE_TIMER_H */
