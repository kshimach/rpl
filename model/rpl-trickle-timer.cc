/*
 * Copyright (c) 2026 ns-3 RPL module contributors
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "rpl-trickle-timer.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("RplTrickleTimer");

namespace rpl
{

RplTrickleTimer::RplTrickleTimer()
    : m_intervalMin(Seconds(1)),
      m_intervalMax(Seconds(1)),
      m_interval(Seconds(1)),
      m_redundancy(0),
      m_counter(0),
      m_running(false),
      m_transmitTimer(Timer::CANCEL_ON_DESTROY),
      m_intervalTimer(Timer::CANCEL_ON_DESTROY)
{
    m_rng = CreateObject<UniformRandomVariable>();
    m_transmitTimer.SetFunction(&RplTrickleTimer::TransmitEvent, this);
    m_intervalTimer.SetFunction(&RplTrickleTimer::IntervalEvent, this);
}

RplTrickleTimer::~RplTrickleTimer()
{
    Stop();
}

void
RplTrickleTimer::SetParameters(Time intervalMin, uint8_t doublings, uint8_t redundancy)
{
    NS_LOG_FUNCTION(this << intervalMin << +doublings << +redundancy);
    m_intervalMin = intervalMin;
    m_intervalMax = intervalMin * (int64_t(1) << doublings);
    m_redundancy = redundancy;
}

void
RplTrickleTimer::SetFunction(Callback<void> callback)
{
    m_callback = callback;
}

void
RplTrickleTimer::Start()
{
    NS_LOG_FUNCTION(this);
    m_running = true;
    m_interval = m_intervalMin;
    NewInterval();
}

void
RplTrickleTimer::Stop()
{
    NS_LOG_FUNCTION(this);
    m_running = false;
    m_transmitTimer.Cancel();
    m_intervalTimer.Cancel();
}

bool
RplTrickleTimer::IsRunning() const
{
    return m_running;
}

void
RplTrickleTimer::Reset()
{
    NS_LOG_FUNCTION(this);
    if (!m_running || m_interval == m_intervalMin)
    {
        return;
    }
    m_interval = m_intervalMin;
    NewInterval(); // cancels and reschedules both timers
}

void
RplTrickleTimer::ConsistencyHit()
{
    m_counter++;
}

Time
RplTrickleTimer::GetInterval() const
{
    return m_interval;
}

void
RplTrickleTimer::NewInterval()
{
    NS_LOG_FUNCTION(this << m_interval);

    m_counter = 0;

    // RFC 6206, section 4.2: t is picked in [I/2, I).
    double half = m_interval.GetSeconds() / 2.0;
    Time t = Seconds(m_rng->GetValue(half, m_interval.GetSeconds()));

    // Timer::Schedule() asserts if an event is still pending, unlike a raw
    // EventId reassignment, which would silently leak the old one; the
    // Cancel() here is a no-op once a timer has already fired (as
    // m_transmitTimer always has by the time IntervalEvent() calls back into
    // here), and is what makes Reset() safe to call mid-interval, when both
    // timers can still be pending.
    m_transmitTimer.Cancel();
    m_transmitTimer.Schedule(t);
    m_intervalTimer.Cancel();
    m_intervalTimer.Schedule(m_interval);
}

void
RplTrickleTimer::TransmitEvent()
{
    NS_LOG_FUNCTION(this << m_counter << +m_redundancy);

    // k = 0 disables suppression, following Contiki-NG rpl-conf.h.
    if (m_redundancy == 0 || m_counter < m_redundancy)
    {
        if (!m_callback.IsNull())
        {
            m_callback();
        }
    }
    else
    {
        NS_LOG_LOGIC("Suppressed: heard " << m_counter << " consistent messages");
    }
}

void
RplTrickleTimer::IntervalEvent()
{
    NS_LOG_FUNCTION(this);

    m_interval = std::min(m_interval + m_interval, m_intervalMax);
    NewInterval();
}

int64_t
RplTrickleTimer::AssignStreams(int64_t stream)
{
    m_rng->SetStream(stream);
    return 1;
}

} // namespace rpl
} // namespace ns3
