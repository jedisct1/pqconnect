from random import choice
from time import monotonic

MINCWND = 8192
INITCWND = 24576

BBR_STARTUP = 1
BBR_DRAIN = 2
BBR_PROBEBANDWIDTH = 3
BBR_PROBERTT = 4

bbr_pacing_gain_cycle = (1.25, 0.75, 1, 1, 1, 1, 1, 1)


class WindowedMaxSample:
    def __init__(self, t: float, v: float) -> None:
        self.t: float = t
        self.v: float = v


class WindowedMax:
    """
    ----- windowed max
    basically the linux windowed minmax code, modulo data types
    skip windowedmin: user can negate input
    """

    def __init__(self) -> None:
        self.s: list = [WindowedMaxSample(0, 0) for i in range(3)]

    def get(self) -> float:
        return self.s[0].v

    def reset(self, t: float, v: float) -> None:
        self.s[2].t = self.s[1].t = self.s[0].t = t
        self.s[2].v = self.s[1].v = self.s[0].v = v

    def subwin_update(self, window: float, t: float, v: float) -> None:
        dt = t - self.s[0].t
        if dt > window:
            self.s.pop(0)
            self.s.append(WindowedMaxSample(t, v))

            if (t - self.s[0].t) > window:
                self.s.pop(0)
                self.s.append(WindowedMaxSample(t, v))

        elif (self.s[1].t == self.s[0].t) and (dt > (window / 4)):
            self.s[2].t = self.s[1].t = t
            self.s[2].v = self.s[1].v = v

        elif (self.s[2].t == self.s[1].t) and (dt > (window / 2)):
            self.s[2].t = t
            self.s[2].v = v

    def running_max(self, window: float, t: float, v: float) -> None:
        if v >= self.s[0].v or t - (self.s[2].t) > window:
            self.reset(t, v)
            return

        if v >= self.s[1].v:
            self.s[2].t = self.s[1].t = t
            self.s[2].v = self.s[1].v = v

        elif v >= self.s[2].v:
            self.s[2].t = t
            self.s[2].v = v

        self.subwin_update(window, t, v)


class PacingPacket:
    def __init__(self, numbytes: int) -> None:
        self.len: int = numbytes
        self.transmissions: float = 0
        self.acknowledged: float = 0
        self.transmissiontime: float = 0

        self.save_netbytesdelivered: int
        self.save_netbytesdelivered_time: float
        self.first_sent_time: float


class PacingConnection:
    def __init__(self) -> None:
        self._now: float = 0
        self._lastsending: float = (
            0  # time of most recent transmission or retransmission
        )

        self._bytesinflight: int = (
            0  # packets transmitted and not yet acknowledged
        )
        self._packetssent: int = 0
        self._packetsreceived: int = 0

        # at pacing_when, would have been comfortable sending pacing_netbytes
        self._pacing_when: float = 0
        self._pacing_netbytes: int = 0

        # setting retransmission timeout:
        self._rtt_measured: int = (
            0  # 1 if pacing_newrtt() has ever been called
        )
        self._rtt_smoothed: float = 0  # "srtt"; smoothing of rtt measurements
        self._rtt_variance: float = 0  # "rttvar"; estimate of rtt variance
        self._rtt_nextdecrease: float = (
            0  # time for next possible decrease of rtt_variance
        )
        self._rtt_mdev: float = 0  # smoothing of deviation from rtt_smoothed
        self._rtt_mdev_max: float = (
            0  # maximum of rtt_mdev since last possible decrease
        )
        self._rto: float = 1  # retransmission timeout

        # BBR delivery-rate variables:
        self._bbrinit_happened: int = 0

        self.now_update()

        self._netbytesdelivered: int = 0
        self._netbytesdelivered_time: float = 0
        self._first_sent_time: float = 0

        self._bbr_state: int = 0
        self._bbr_cycle_index: int = 0
        self._bbr_cycle_stamp: float = 0

        self._bbr_bandwidthfilter: WindowedMax = WindowedMax()
        self._bbr_rtprop: float = 0
        self._bbr_rtprop_stamp: float = 0
        self._bbr_rtprop_expired: int = 0
        self._bbr_probe_rtt_done_stamp: float = 0
        self._bbr_probe_rtt_round_done: int = 0
        self._bbr_packet_conservation: int = 0
        self._bbr_prior_cwnd: int = 0
        self._bbr_idle_restart: int = 0

        self._bbr_next_round_delivered: int = 0
        self._bbr_round_start: int = 0
        self._bbr_round_count: int = 0

        self._bbr_filled_pipe: int = 0
        self._bbr_full_bandwidth: int = 0
        self._bbr_full_bandwidth_count: int = 0

        self._bbr_cwnd: int = 0

        self._bbr_nominal_bandwidth: int = 0
        self._bbr_bandwidth: int = 0
        self._bbr_pacing_gain: float = 0
        self._bbr_cwnd_gain: float = 0

        self._bbr_pacing_rate: float = 0
        self._bbr_cwnd_rate: float = 0
        self._bbr_rate: float = 0

        self._bbr_rateinv: float = 0  # 1 / bbr_rate

        self._bbr_target_cwnd: int = 0
        self._bbr_bytes_lost: int = 0
        self._bbr_prior_inflight: int = 0
        self._bbr_now_inflight: int = 0
        self._bbr_prior_delivered: int = 0
        self._bbr_prior_time: float = 0
        self._bbr_send_elapsed: float = 0
        self._bbr_ack_elapsed: float = 0
        self._bbr_interval: float = 0
        self._bbr_delivered: int = 0
        self._bbr_delivery_rate: int = 0

    def _setrto(self, rtt: float) -> None:
        if rtt <= 0:
            return

        if self._rtt_measured == 0:
            self._rtt_measured = 1
            self._rtt_smoothed = rtt
            self._rtt_variance = 0.5 * rtt
            self._rtt_mdev = 0
            self._rtt_mdev_max = 0
            self._rtt_nextdecrease = self._now + 2 * rtt
            if self._packetssent > 1:
                self._rto = 3  # rfc 6298 paragraph 5.7
            return

        diff = rtt
        diff -= self._rtt_smoothed
        self._rtt_smoothed += 0.125 * diff

        if diff > 0:
            diff -= self._rtt_mdev
        else:
            diff = -diff
            diff -= self._rtt_mdev

            # slow down increase of mdev when rtt seems to be decreasing
            if diff > 0:
                diff *= 0.125

        self._rtt_mdev += 0.25 * diff
        if self._rtt_mdev > self._rtt_mdev_max:
            self._rtt_mdev_max = self._rtt_mdev
            if self._rtt_mdev > self._rtt_variance:
                self._rtt_variance = self._rtt_mdev

        self._rto = self._rtt_smoothed + 4 * self._rtt_variance + 0.000001

        if self._now >= self._rtt_nextdecrease:
            if self._rtt_mdev_max < self._rtt_variance:
                self._rtt_variance -= 0.25 * (
                    self._rtt_variance - self._rtt_mdev_max
                )
            self._rtt_mdev_max = 0
            self._rtt_nextdecrease = self._now + self._rtt_smoothed

        # rfc 6298 says "should be rounded up to 1 second" but linux normally rounds
        # up to 0.2 seconds
        self._rto = max(self._rto, 0.2)

    # #### BBR congestion control #### #

    def _bbr_enterprobertt(self) -> None:
        self._bbr_state = BBR_PROBERTT
        self._bbr_pacing_gain = 1
        self._bbr_cwnd_gain = 1

    def _bbr_enterstartup(self) -> None:
        self._bbr_state = BBR_STARTUP
        self._bbr_pacing_gain = 2.88539
        self._bbr_cwnd_gain = 2.88539

    def _bbr_enterdrain(self) -> None:
        self._bbr_state = BBR_DRAIN
        self._bbr_pacing_gain = 0.34657359
        self._bbr_cwnd_gain = 2.88539

    def _bbr_advancecyclephase(self) -> None:
        self._bbr_cycle_stamp = self._now
        self._bbr_cycle_index = (self._bbr_cycle_index + 1) & 7
        self._bbr_pacing_gain = bbr_pacing_gain_cycle[self._bbr_cycle_index]

    def _bbr_enterprobebandwidth(self) -> None:
        self._bbr_state = BBR_PROBEBANDWIDTH
        self._bbr_pacing_gain = 1
        self._bbr_cwnd_gain = 2
        self._bbr_cycle_index = choice(range(1, 8))
        self._bbr_advancecyclephase()

    def _bbrinit(self) -> None:
        if self._bbrinit_happened:
            return

        self._bbrinit_happened = 1
        self._bbr_bandwidthfilter.reset(0, 0)
        self._bbr_rtprop = self._rtt_smoothed

        if self._rtt_smoothed == 0:
            self._bbr_rtprop = 86400

        self._bbr_rtprop_stamp = self._now
        self._bbr_probe_rtt_done_stamp = 0
        self._bbr_probe_rtt_round_done = 0
        self._bbr_packet_conservation = 0
        self._bbr_prior_cwnd = 0
        self._bbr_idle_restart = 0

        self._bbr_next_round_delivered = 0
        self._bbr_round_start = 0
        self._bbr_round_count = 0

        self._bbr_filled_pipe = 0
        self._bbr_full_bandwidth = 0
        self._bbr_full_bandwidth_count = 0

        self._bbr_cwnd = INITCWND

        if self._rtt_smoothed:
            self._bbr_nominal_bandwidth = int(INITCWND / self._rtt_smoothed)
        else:
            self._bbr_nominal_bandwidth = int(INITCWND / 0.001)

        self._bbr_enterstartup()

        self._bbr_pacing_rate = (
            self._bbr_pacing_gain * self._bbr_nominal_bandwidth
        )
        self._bbr_cwnd_rate = self._bbr_cwnd / self._rtt_smoothed
        self._bbr_rate = self._bbr_cwnd_rate
        if self._bbr_rate > self._bbr_pacing_rate:
            self._bbr_rate = self._bbr_pacing_rate
        self._bbr_rateinv = 1 / self._bbr_rate

    def _bbrinflight(self, gain: float) -> float:
        if self._bbr_rtprop == 86400:
            return INITCWND

        return 0.99 * gain * self._bbr_bandwidth * self._bbr_rtprop + 4096

    def _bbr_checkcyclephase(self) -> None:
        if self._bbr_state != BBR_PROBEBANDWIDTH:
            return

        is_full_length: bool = (
            self._now - self._bbr_cycle_stamp
        ) > self._bbr_rtprop

        if self._bbr_pacing_gain == 1:
            if not is_full_length:
                return
        elif self._bbr_pacing_gain > 1:
            if not is_full_length:
                return
            if self._bbr_bytes_lost == 0:
                if self._bbr_prior_inflight < self._bbrinflight(
                    self._bbr_pacing_gain
                ):
                    return
        else:
            if not is_full_length:
                if self._bbr_prior_inflight > self._bbrinflight(1):
                    return
        self._bbr_advancecyclephase()

    def _bbr_checkfullpipe(self) -> None:
        if not self._bbr_filled_pipe:
            return

        if not self._bbr_round_start:
            return

        if self._bbr_bandwidth >= self._bbr_full_bandwidth * 1.25:
            self._bbr_full_bandwidth = self._bbr_bandwidth
            self._bbr_full_bandwidth_count = 0
            return

        self._bbr_full_bandwidth_count += 1
        if self._bbr_full_bandwidth_count >= 3:
            self._bbr_filled_pipe = 1

    # ### BBR delivery-rate estimation ### #

    def _bbrack(self, p: PacingPacket, packetrtt: float) -> None:
        bytes_delivered: int = p.len

        self._bbrinit()

        self._bbr_bytes_lost = (
            0  # XXX: see above regarding negative acknowledgments
        )
        self._bbr_prior_inflight = self._bytesinflight
        self._bbr_now_inflight = self._bbr_prior_inflight - bytes_delivered

        self._netbytesdelivered += bytes_delivered
        self._netbytesdelivered_time = self._now

        if p.save_netbytesdelivered > self._bbr_prior_delivered:
            self._bbr_prior_delivered = p.save_netbytesdelivered
            self._bbr_prior_time = p.save_netbytesdelivered_time
            self._bbr_send_elapsed = p.transmissiontime - p.first_sent_time
            self._bbr_ack_elapsed = (
                self._netbytesdelivered_time - self._bbr_prior_time
            )
            self._first_sent_time = p.transmissiontime

        if self._bbr_prior_time != 0:
            self._bbr_interval = self._bbr_send_elapsed

            if self._bbr_ack_elapsed > self._bbr_interval:
                self._bbr_interval = self._bbr_ack_elapsed

            self._bbr_delivered = (
                self._netbytesdelivered - self._bbr_prior_delivered
            )

            if (
                self._bbr_interval < self._rtt_smoothed
            ):  # /* XXX: replace with bbr_minrtt */
                self._bbr_interval = -1
            elif self._bbr_interval > 0:
                self._bbr_delivery_rate = int(
                    self._bbr_delivered / self._bbr_interval
                )

        self._bbr_delivered += bytes_delivered

        if p.save_netbytesdelivered >= self._bbr_next_round_delivered:
            self._bbr_next_round_delivered = self._bbr_delivered
            self._bbr_round_count += 1
            self._bbr_round_start = 1
        else:
            self._bbr_round_start = 0

        if self._bbr_delivery_rate >= self._bbr_bandwidth:
            self._bbr_bandwidthfilter.running_max(
                10, self._bbr_round_count, self._bbr_delivery_rate
            )
            self._bbr_bandwidth = int(self._bbr_bandwidthfilter.get())

        self._bbr_checkcyclephase()
        self._bbr_checkfullpipe()

        if self._bbr_state == BBR_STARTUP and self._bbr_filled_pipe:
            self._bbr_enterdrain()

        if (
            self._bbr_state == BBR_DRAIN
            and self._bbr_now_inflight <= self._bbrinflight(1)
        ):
            self._bbr_enterprobebandwidth()

        self._bbr_rtprop_expired = self._now > self._bbr_rtprop_stamp + 10

        if packetrtt >= 0:
            if packetrtt <= self._bbr_rtprop or self._bbr_rtprop_expired:
                self._bbr_rtprop = packetrtt
                self._bbr_rtprop_stamp = self._now

        if self._bbr_state != BBR_PROBERTT:
            if self._bbr_rtprop_expired:
                if not self._bbr_idle_restart:
                    self._bbr_enterprobertt()
                    # XXX: do this only if not in lossrecovery
                    self._bbr_prior_cwnd = self._bbr_cwnd
                    self._bbr_probe_rtt_done_stamp = 0

        if self._bbr_state == BBR_PROBERTT:
            if (
                self._bbr_probe_rtt_done_stamp == 0
                and self._bbr_now_inflight <= MINCWND
            ):
                self._bbr_probe_rtt_done_stamp = self._now + 0.2
                self._bbr_probe_rtt_round_done = 0
                self._bbr_next_round_delivered = self._bbr_delivered
            elif self._bbr_probe_rtt_done_stamp:
                if self._bbr_round_start:
                    self._bbr_probe_rtt_round_done = 1
                if self._bbr_probe_rtt_round_done:
                    if self._now > self._bbr_probe_rtt_done_stamp:
                        self._bbr_rtprop_stamp = self._now
                        if self._bbr_cwnd < self._bbr_prior_cwnd:
                            self._bbr_cwnd = self._bbr_prior_cwnd

                        if self._bbr_filled_pipe:
                            self._bbr_enterprobebandwidth()
                        else:
                            self._bbr_enterstartup()

        self._bbr_idle_restart = 0

        rate = self._bbr_pacing_gain * self._bbr_bandwidth
        if self._bbr_filled_pipe or rate > self._bbr_pacing_rate:
            self._bbr_pacing_rate = rate

        self._bbr_target_cwnd = int(self._bbrinflight(self._bbr_cwnd_gain))

        if self._bbr_bytes_lost > 0:
            self._bbr_cwnd -= self._bbr_bytes_lost
            self._bbr_cwnd = max(self._bbr_cwnd, 1600)

        if not self._bbr_packet_conservation:
            if self._bbr_cwnd < self._bbr_now_inflight + bytes_delivered:
                self._bbr_cwnd = self._bbr_now_inflight + bytes_delivered
            if self._bbr_filled_pipe:
                self._bbr_cwnd += bytes_delivered
                if self._bbr_cwnd > self._bbr_target_cwnd:
                    self._bbr_cwnd = self._bbr_target_cwnd
            elif (
                self._bbr_cwnd < self._bbr_target_cwnd
                or self._bbr_delivered < INITCWND
            ):
                self._bbr_cwnd += bytes_delivered
            self._bbr_cwnd = max(self._bbr_cwnd, MINCWND)

        if self._bbr_state == BBR_PROBERTT:
            self._bbr_cwnd = max(self._bbr_cwnd, MINCWND)

        self._bbr_cwnd_rate = self._bbr_cwnd / self._rtt_smoothed
        self._bbr_rate = self._bbr_cwnd_rate
        if self._bbr_rate > self._bbr_pacing_rate:
            self._bbr_rate = self._bbr_pacing_rate
        self._bbr_rateinv = 1 / self._bbr_rate

    # #### pacing #### #

    def _pacing_rememberpacket(self, numbytes: int) -> None:
        if not self._pacing_when or (
            self._now - self._pacing_when > 0.5 * self._rtt_smoothed
        ):
            self._pacing_when = self._now
            self._pacing_netbytes = 0
            return

        self._pacing_netbytes += int(
            self._bbr_rate * (self._now - self._pacing_when)
        )

        self._pacing_when = self._now

        self._pacing_netbytes -= numbytes

    # #### something happened with a packet #### #

    def now_update(self) -> None:
        self._now = monotonic()

    def transmitted(self, p: PacingPacket) -> None:
        firsttransmission = p.transmissions == 0

        p.transmissions += 1
        p.transmissiontime = self._now

        if self._packetssent == 0 or self._now - self._lastsending > 1:
            # XXX: consider more serious reset of state
            self._netbytesdelivered_time = self._now
            self._first_sent_time = self._now

        p.save_netbytesdelivered = self._netbytesdelivered
        p.save_netbytesdelivered_time = self._netbytesdelivered_time
        p.first_sent_time = self._first_sent_time

        self._packetssent += 1
        self._lastsending = self._now

        self._pacing_rememberpacket(p.len)

        if firsttransmission:
            self._bytesinflight += p.len
        else:
            self._rto *= 2  # rfc 6298 paragraph 5.5
            self._rto = min(self._rto, 120)

    def acknowledged(self, p: PacingPacket) -> None:
        if p.acknowledged:
            return

        p.acknowledged = 1

        self._packetsreceived += 1

        # karn's algorithm: ignore RTT for retransmitted packets
        # XXX: transport protocol that can figure out ack for retransmission can reset transmissions, transmissiontime
        if p.transmissions == 1:
            rtt = self._now - p.transmissiontime
            self._setrto(rtt)
            self._bbrack(p, rtt)

        self._bytesinflight -= p.len

    def whendecongested(self, numbytes: int) -> float:
        decongest: float
        if not self._packetsreceived:
            if not self._packetssent:
                return 0  # our very first packet; send immediately
            return (
                self._lastsending + 0.5 * self._packetssent - self._now
            )  # XXX: randomize a bit?

        if self._bytesinflight >= self._bbr_cwnd:
            return self._lastsending + self._rto - self._now

        if self._bbr_rate * self._rtt_smoothed < numbytes:
            decongest = self._lastsending + self._rtt_smoothed
        else:
            numbytes -= self._pacing_netbytes
            decongest = self._pacing_when + numbytes * self._bbr_rateinv

            if decongest > self._lastsending + self._rtt_smoothed:
                decongest = self._lastsending + self._rtt_smoothed

        return decongest - self._now

    def whenrto(self, p: PacingPacket) -> float:
        if p.transmissions:
            return p.transmissiontime + self._rto - self._now

        return 0
