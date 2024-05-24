use std::time::{Duration, Instant};

use log::{info, warn};

use crate::state::Context;

pub struct Monitor {
    ctx: Context,
    last_now: Instant,
    last_sent: u32,
    last_rcvd: u32,
    last_drop: u32,
    last_failures: u32,
}

impl Monitor {
    const UPDATE_INTERVAL: u64 = 1;

    pub fn new(ctx: Context) -> Self {
        Self {
            ctx,
            last_now: Instant::now(),
            last_sent: 0,
            last_rcvd: 0,
            last_drop: 0,
            last_failures: 0,
        }
    }

    pub fn run(&mut self) {
        loop {
            let zsend_complete = self.ctx.sender_state.lock().unwrap().complete;
            let zrecv_complete = self.ctx.receiver_state.lock().unwrap().complete;
            if zsend_complete && zrecv_complete {
                break;
            }

            self.update();
            std::thread::sleep(std::time::Duration::from_secs(Monitor::UPDATE_INTERVAL));
        }
    }

    fn update(&mut self) {
        let zsend = self.ctx.sender_state.lock().unwrap();
        let zsend_complete = zsend.complete;
        let zsend_start = zsend.start;
        let zsend_finish = zsend.finish;
        let zsend_sent = zsend.sent;
        let zsend_sendto_failures = zsend.sendto_failures;
        let zsend_targets = zsend.targets;
        drop(zsend);

        let zrecv = self.ctx.receiver_state.lock().unwrap();
        let zrecv_success_unique = zrecv.success_unique;
        let zrecv_pcap_drop = zrecv.pcap_drop;
        let zrecv_pcap_ifdrop = zrecv.pcap_ifdrop;
        drop(zrecv);

        let age = Instant::now() - zsend_start;
        let age_f64 = age.as_secs_f64();
        let delta = Instant::now() - self.last_now;
        let delta_f64 = delta.as_secs_f64();
        let remaining_secs = self.compute_remaining_time(
            zsend_complete,
            zsend_finish,
            zsend_targets,
            zsend_sent,
            zrecv_success_unique,
            age,
        );
        let percent_complete = 100.0 * (age_f64 / (age_f64 + remaining_secs.as_secs_f64()));

        let send_rate = ((zsend_sent - self.last_sent) as f64 / delta_f64);
        let send_avg = (zsend_sent as f64) / age_f64;
        let recv_rate = (zrecv_success_unique - self.last_rcvd) as f64 / delta_f64;
        let recv_avg = (zrecv_success_unique as f64) / age_f64;
        let pcap_drop_rate =
            (zrecv_pcap_drop + zrecv_pcap_ifdrop - self.last_drop) as f64 / delta_f64;
        let pcap_drop_rate_avg = (zrecv_pcap_drop + zrecv_pcap_ifdrop) as f64 / age_f64;

        if pcap_drop_rate > (((zrecv_success_unique - self.last_rcvd) as f64) / delta_f64) / 20f64 {
            warn!(
                "Dropped {:.0} in the last second, {} total dropped (pcap: {} + iface: {})",
                pcap_drop_rate,
                zrecv_pcap_drop + zrecv_pcap_ifdrop,
                zrecv_pcap_drop,
                zrecv_pcap_ifdrop
            );
        }

        let fail_rate = ((zsend_sendto_failures - self.last_failures) as f64) / delta_f64;
        if fail_rate > ((zsend_sent as f64) / age_f64) / 100.0 {
            warn!(
                "Failed to send {:.0} packets/sec ({} total failures)",
                fail_rate, zsend_sendto_failures
            );
        }

        if !zsend_complete {
            info!(
                "{:.0?} {:.2}% ({:.0?}); send: {} {:.0} p/s ({:.0} p/s avg); recv {} {:.0} p/s ({:.0} p/s avg); drops {:.0} p/s ({:.0} p/s avg); hits: {:.2}%",
                age,
                percent_complete,
                remaining_secs,
                zsend_sent,
                send_rate,
                send_avg,
                zrecv_success_unique,
                recv_rate,
                recv_avg,
                pcap_drop_rate,
                pcap_drop_rate_avg,
                ((zrecv_success_unique as f64) * 100.0) / (zsend_sent as f64),
            );
        } else {
            let send_avg = (zsend_sent as f64 / (zsend_finish - zsend_start).as_secs_f64());
            info!(
                "{:.0?} {:.2}% ({:.0?}); send: {} done ({:.0} p/s avg); recv {} {:.0} p/s ({:.0} p/s avg); drops {:.0} p/s ({:.0} p/s avg); hits: {:.2}%",
                age,
                percent_complete,
                remaining_secs,
                zsend_sent,
                send_avg,
                zrecv_success_unique,
                recv_rate,
                recv_avg,
                pcap_drop_rate,
                pcap_drop_rate_avg,
                ((zrecv_success_unique as f64) * 100.0) / (zsend_sent as f64)
            );
        }

        self.last_now = Instant::now();
        self.last_sent = zsend_sent;
        self.last_rcvd = zrecv_success_unique;
        self.last_drop = zrecv_pcap_drop + zrecv_pcap_ifdrop;
        self.last_failures = zsend_sendto_failures;
    }

    fn compute_remaining_time(
        &self,
        zsend_complete: bool,
        zsend_finish: Instant,
        zsend_targets: u32,
        zsend_sent: u32,
        zrecv_success_unique: u32,
        age: Duration,
    ) -> Duration {
        let age_f64 = age.as_secs_f64();
        if !zsend_complete {
            let mut target_duration = f64::INFINITY;
            let mut runtime_duration = f64::INFINITY;
            let mut results_duration = f64::INFINITY;

            if zsend_targets > 0 {
                let done = (zsend_sent as f64) / (zsend_targets as f64);
                target_duration =
                    (1.0 - done) * (age_f64 / done) + self.ctx.config.cooldown_secs.as_secs_f64();
            }

            if self.ctx.config.max_runtime > 0 {
                runtime_duration = (self.ctx.config.max_runtime as f64 - age_f64)
                    + self.ctx.config.cooldown_secs.as_secs_f64();
            }

            if self.ctx.config.max_results > 0 {
                let done = (zrecv_success_unique as f64) / (self.ctx.config.max_results as f64);
                results_duration = (1. - done) * (age_f64 / done);
            }

            let min = target_duration.min(runtime_duration).min(results_duration);
            if min == f64::INFINITY {
                return Duration::from_secs(0);
            }
            return Duration::from_secs_f64(min);
        }

        return self.ctx.config.cooldown_secs - (Instant::now() - zsend_finish);
    }
}
