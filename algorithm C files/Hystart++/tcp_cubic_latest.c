// SPDX-License-Identifier: GPL-2.0-only
/*
 * TCP CUBIC: Binary Increase Congestion control for TCP v2.3 with HyStart++ (RFC 9406)
 */

 #include <linux/mm.h>
 #include <linux/btf.h>
 #include <linux/btf_ids.h>
 #include <linux/module.h>
 #include <linux/math64.h>
 #include <net/tcp.h>
 
 #define BICTCP_BETA_SCALE    1024
 #define BICTCP_HZ               10
 
 /* Two methods of standard HyStart */
 #define HYSTART_ACK_TRAIN       0x1
 #define HYSTART_DELAY           0x2
 #define HYSTART_MIN_SAMPLES     8
 #define HYSTART_DELAY_MIN       (4000U)
 #define HYSTART_DELAY_MAX       (16000U)
 #define HYSTART_DELAY_THRESH(x) clamp(x, HYSTART_DELAY_MIN, HYSTART_DELAY_MAX)
 
 /* HyStart++ Parameters {RFC 9406} */
 #define HSPP_MIN_RTT_THRESH     (4000U)  /* 4 ms */
 #define HSPP_MAX_RTT_THRESH     (16000U) /* 16 ms */
 #define HSPP_CSS_MIN_RTT_DIV    3        /* RTT / 8 */
 #define HSPP_N_RTT_SAMPLE       8        /* Minimum samples to evaluate RTT */
 #define HSPP_CSS_GROWTH_DIV     4        /* CSS growth denominator */
 #define HSPP_CSS_ROUNDS         5        /* Maximum rounds in CSS */
 
 #define HSPP_DEACTIVE           0
 #define HSPP_IN_SS              1
 #define HSPP_IN_CSS             2
 #define HSPP_RTT_THRESH(x)      clamp(x, HSPP_MIN_RTT_THRESH, HSPP_MAX_RTT_THRESH)
 
 static int fast_convergence __read_mostly = 1;
 static int beta __read_mostly = 717;
 static int initial_ssthresh __read_mostly;
 static int bic_scale __read_mostly = 41;
 static int tcp_friendliness __read_mostly = 1;
 
 static int hystart __read_mostly = 1;
 static int hystart_detect __read_mostly = HYSTART_ACK_TRAIN | HYSTART_DELAY;
 static int hystart_low_window __read_mostly = 16;
 static int hystart_ack_delta_us __read_mostly = 2000;
 
 static u32 cube_rtt_scale __read_mostly;
 static u32 beta_scale __read_mostly;
 static u64 cube_factor __read_mostly;
 
 module_param(fast_convergence, int, 0644);
 MODULE_PARM_DESC(fast_convergence, "turn on/off fast convergence");
 module_param(beta, int, 0644);
 MODULE_PARM_DESC(beta, "beta for multiplicative increase");
 module_param(initial_ssthresh, int, 0644);
 MODULE_PARM_DESC(initial_ssthresh, "initial value of slow start threshold");
 module_param(bic_scale, int, 0444);
 MODULE_PARM_DESC(bic_scale, "scale value for bic function");
 module_param(tcp_friendliness, int, 0644);
 MODULE_PARM_DESC(tcp_friendliness, "turn on/off tcp friendliness");
 module_param(hystart, int, 0644);
 MODULE_PARM_DESC(hystart, "turn on/off hybrid slow start algorithm");
 module_param(hystart_detect, int, 0644);
 MODULE_PARM_DESC(hystart_detect, "hybrid slow start detection mechanisms");
 module_param(hystart_low_window, int, 0644);
 MODULE_PARM_DESC(hystart_low_window, "lower bound cwnd for hybrid slow start");
 module_param(hystart_ack_delta_us, int, 0644);
 MODULE_PARM_DESC(hystart_ack_delta_us, "spacing between ack's indicating train (usecs)");
 
 static int hystartpp = 1;
 module_param(hystartpp, int, 0644);
 MODULE_PARM_DESC(hystartpp, "turn on/off hystart++ algorithm");
 
 static int hystartpp_source_port = 5201;
 module_param(hystartpp_source_port, int, 0644);
 MODULE_PARM_DESC(hystartpp_source_port, "Port to monitor and log for HyStart++");
 
 /* BIC TCP Parameters */
 struct bictcp {
         u32     cnt;
         u32     last_max_cwnd;
         u32     last_cwnd;
         u32     last_time;
         u32     bic_origin_point;
         u32     bic_K;
         u32     delay_min;
         u32     epoch_start;
         u32     ack_cnt;
         u32     tcp_cwnd;
         u16     unused;
         u8      sample_cnt;
         u8      found;
         u32     round_start;
         u32     end_seq;
         u32     last_ack;
         u32     curr_rtt;
 
         /* HyStart++ (RFC 9406) state */
         u8      hspp_flag;
         u8      hspp_rttsample_counter;
         u32     hspp_last_round_minrtt;
         u32     hspp_current_round_minrtt;
         u8      hspp_round_counter;
         u8      hspp_entered_css_at_round;
         u32     hspp_css_baseline_minrtt;
         u32     hspp_end_seq;
         u32     hspp_last_round_cwnd;
 };
 
 static inline void bictcp_reset(struct bictcp *ca)
 {
         memset(ca, 0, offsetof(struct bictcp, unused));
         ca->found = 0;
 }
 
 static inline u32 bictcp_clock_us(const struct sock *sk)
 {
         return tcp_sk(sk)->tcp_mstamp;
 }
 
 static inline bool hspp_should_log(const struct sock *sk)
 {
         struct tcp_sock *tp = tcp_sk(sk);
         return (ntohs(inet_sk(sk)->inet_sport) == hystartpp_source_port ||
                  ntohs(inet_sk(sk)->inet_dport) == hystartpp_source_port);
 }
 
 static const char *hspp_stage_str(u8 stage)
 {
         switch (stage) {
         case HSPP_IN_SS:
                 return "SLOW_START";
         case HSPP_IN_CSS:
                 return "CSS";
         case HSPP_DEACTIVE:
                 return "CONGESTION_AVOIDANCE";
         default:
                 return "UNKNOWN";
         }
 }
 
 static inline void bictcp_hystart_reset(struct sock *sk)
 {
         struct tcp_sock *tp = tcp_sk(sk);
         struct bictcp *ca = inet_csk_ca(sk);
 
         ca->round_start = ca->last_ack = bictcp_clock_us(sk);
         ca->end_seq = tp->snd_nxt;
         ca->curr_rtt = ~0U;
         ca->sample_cnt = 0;
 }
 
 static inline void hystartpp_reset(struct sock *sk)
 {
         struct tcp_sock *tp = tcp_sk(sk);
         struct bictcp *ca = inet_csk_ca(sk);
 
         ca->hspp_last_round_minrtt = ca->hspp_current_round_minrtt;
         ca->hspp_current_round_minrtt = ~0U;
         ca->hspp_rttsample_counter = 0;
         ca->hspp_end_seq = tp->snd_nxt;
 }
 
 __bpf_kfunc static void cubictcp_init(struct sock *sk)
 {
         struct bictcp *ca = inet_csk_ca(sk);
 
         bictcp_reset(ca);
 
         if (hystartpp) {
                 ca->hspp_round_counter = 0;
                 ca->hspp_flag = HSPP_IN_SS;
                 ca->hspp_last_round_minrtt = ~0U;
                 ca->hspp_current_round_minrtt = ~0U;
                 ca->hspp_last_round_cwnd = tcp_snd_cwnd(tcp_sk(sk));
                 hystartpp_reset(sk);
                 if (hspp_should_log(sk))
                         pr_info("[HyStart++] [sk: %p] INIT -> SLOW_START | cwnd: %u, ssthresh: %u, mss: %u\n",
                                 sk, tcp_snd_cwnd(tcp_sk(sk)), tcp_sk(sk)->snd_ssthresh, tcp_sk(sk)->mss_cache);
                 return;
         }
 
         if (hystart)
                 bictcp_hystart_reset(sk);
 
         if (!hystart && initial_ssthresh)
                 tcp_sk(sk)->snd_ssthresh = initial_ssthresh;
 }
 
 __bpf_kfunc static void cubictcp_cwnd_event(struct sock *sk, enum tcp_ca_event event)
 {
         if (event == CA_EVENT_TX_START) {
                 struct bictcp *ca = inet_csk_ca(sk);
                 u32 now = tcp_jiffies32;
                 s32 delta = now - tcp_sk(sk)->lsndtime;
 
                 if (ca->epoch_start && delta > 0) {
                         ca->epoch_start += delta;
                         if (after(ca->epoch_start, now))
                                 ca->epoch_start = now;
                 }
                 return;
         }
 }
 
 static u32 cubic_root(u64 a)
 {
         u32 x, b, shift;
         static const u8 v[] = {
                 0,   54,  54,  54,  118, 118, 118, 118,
                 123, 129, 134, 138, 143, 147, 151, 156,
                 157, 161, 164, 168, 170, 173, 176, 179,
                 181, 185, 187, 190, 192, 194, 197, 199,
                 200, 202, 204, 206, 209, 211, 213, 215,
                 217, 219, 221, 222, 224, 225, 227, 229,
                 231, 232, 234, 236, 237, 239, 240, 242,
                 244, 245, 246, 248, 250, 251, 252, 254,
         };
 
         b = fls64(a);
         if (b < 7)
                 return ((u32)v[(u32)a] + 35) >> 6;
 
         b = ((b * 84) >> 8) - 1;
         shift = (a >> (b * 3));
         x = ((u32)(((u32)v[shift] + 10) << b)) >> 6;
         x = (2 * x + (u32)div64_u64(a, (u64)x * (u64)(x - 1)));
         x = ((x * 341) >> 10);
         return x;
 }
 
 static inline void bictcp_update(struct bictcp *ca, u32 cwnd, u32 acked)
 {
         u32 delta, bic_target, max_cnt;
         u64 offs, t;
 
         ca->ack_cnt += acked;
 
         if (ca->last_cwnd == cwnd &&
             (s32)(tcp_jiffies32 - ca->last_time) <= HZ / 32)
                 return;
 
         if (ca->epoch_start && tcp_jiffies32 == ca->last_time)
                 goto tcp_friendliness;
 
         ca->last_cwnd = cwnd;
         ca->last_time = tcp_jiffies32;
 
         if (ca->epoch_start == 0) {
                 ca->epoch_start = tcp_jiffies32;
                 ca->ack_cnt = acked;
                 ca->tcp_cwnd = cwnd;
 
                 if (ca->last_max_cwnd <= cwnd) {
                         ca->bic_K = 0;
                         ca->bic_origin_point = cwnd;
                 } else {
                         ca->bic_K = cubic_root(cube_factor * (ca->last_max_cwnd - cwnd));
                         ca->bic_origin_point = ca->last_max_cwnd;
                 }
         }
 
         t = (s32)(tcp_jiffies32 - ca->epoch_start);
         t += usecs_to_jiffies(ca->delay_min);
         t <<= BICTCP_HZ;
         do_div(t, HZ);
 
         if (t < ca->bic_K)
                 offs = ca->bic_K - t;
         else
                 offs = t - ca->bic_K;
 
         delta = (cube_rtt_scale * offs * offs * offs) >> (10+3*BICTCP_HZ);
         if (t < ca->bic_K)
                 bic_target = ca->bic_origin_point - delta;
         else
                 bic_target = ca->bic_origin_point + delta;
 
         if (bic_target > cwnd)
                 ca->cnt = cwnd / (bic_target - cwnd);
         else
                 ca->cnt = 100 * cwnd;
 
         if (ca->last_max_cwnd == 0 && ca->cnt > 20)
                 ca->cnt = 20;
 
 tcp_friendliness:
         if (tcp_friendliness) {
                 u32 scale = beta_scale;
 
                 delta = (cwnd * scale) >> 3;
                 while (ca->ack_cnt > delta) {
                         ca->ack_cnt -= delta;
                         ca->tcp_cwnd++;
                 }
 
                 if (ca->tcp_cwnd > cwnd) {
                         delta = ca->tcp_cwnd - cwnd;
                         max_cnt = cwnd / delta;
                         if (ca->cnt > max_cnt)
                                 ca->cnt = max_cnt;
                 }
         }
 
         ca->cnt = max(ca->cnt, 2U);
 }
 
 static void hystartpp_adjust_cwnd(struct sock *sk, u32 acked)
 {
         struct tcp_sock *tp = tcp_sk(sk);
         struct bictcp *ca = inet_csk_ca(sk);
 
         if (ca->hspp_flag == HSPP_IN_SS) {
                 tcp_slow_start(tp, acked);
         } else if (ca->hspp_flag == HSPP_IN_CSS) {
                 /* RFC 9406: CSS window increases by cwnd / HSPP_CSS_GROWTH_DIV per RTT */
                 tcp_cong_avoid_ai(tp, HSPP_CSS_GROWTH_DIV, acked);
         }
 
         if (tcp_snd_cwnd(tp) >= tp->snd_ssthresh) {
                 if (hspp_should_log(sk))
                         pr_info("[HyStart++] [sk: %p] STAGE: %s -> CONGESTION_AVOIDANCE (Hit ssthresh) | cwnd: %u, ssthresh: %u\n",
                                 sk, hspp_stage_str(ca->hspp_flag), tcp_snd_cwnd(tp), tp->snd_ssthresh);
                 ca->hspp_flag = HSPP_DEACTIVE;
         }
 }
 
 __bpf_kfunc static void cubictcp_cong_avoid(struct sock *sk, u32 ack, u32 acked)
 {
         struct tcp_sock *tp = tcp_sk(sk);
         struct bictcp *ca = inet_csk_ca(sk);
         u32 old_cwnd;
 
         if (tcp_in_slow_start(tp)) {
                 if (hystartpp && (ca->hspp_flag != HSPP_DEACTIVE)) {
                         hystartpp_adjust_cwnd(sk, acked);
                         return;
                 }
 
                 acked = tcp_slow_start(tp, acked);
                 if (!acked)
                         return;
         }
 
         if (!tcp_is_cwnd_limited(sk))
                 return;
 
         old_cwnd = tcp_snd_cwnd(tp);
 
         bictcp_update(ca, tcp_snd_cwnd(tp), acked);
         tcp_cong_avoid_ai(tp, ca->cnt, acked);
 
         if (hspp_should_log(sk) && ca->hspp_flag == HSPP_DEACTIVE) {
                 u32 new_cwnd = tcp_snd_cwnd(tp);
 
                 if (new_cwnd != old_cwnd) { 
                         pr_info("[HyStart++] [sk: %p] cwnd: %u, ssthresh: %u\n",
                                 sk, new_cwnd, tp->snd_ssthresh);
                 }
         }
 
 }
 
 __bpf_kfunc static u32 cubictcp_recalc_ssthresh(struct sock *sk)
 {
         const struct tcp_sock *tp = tcp_sk(sk);
         struct bictcp *ca = inet_csk_ca(sk);
 
         ca->epoch_start = 0;
 
         if (tcp_snd_cwnd(tp) < ca->last_max_cwnd && fast_convergence)
                 ca->last_max_cwnd = (tcp_snd_cwnd(tp) * (BICTCP_BETA_SCALE + beta))
                                     / (2 * BICTCP_BETA_SCALE);
         else
                 ca->last_max_cwnd = tcp_snd_cwnd(tp);
 
         return max((tcp_snd_cwnd(tp) * beta) / BICTCP_BETA_SCALE, 2U);
 }
 
 __bpf_kfunc static void cubictcp_state(struct sock *sk, u8 new_state)
 {
         struct bictcp *ca = inet_csk_ca(sk);
         const char *reason = NULL;
         const char *destination = NULL;
 
         if (new_state == TCP_CA_Loss) {
                 reason = "TCP_CA_LOSS";
                 destination = "LOSS";
         } else if (new_state == TCP_CA_Recovery) {
                 reason = "TCP_CA_RECOVERY";
                 destination = "RECOVERY";
         } else if (new_state == TCP_CA_CWR) {
                 reason = "TCP_CA_CWR";
                 destination = "CWR";
         }
 
         if (hystartpp && (ca->hspp_flag != HSPP_DEACTIVE) && reason) {
                 if (hspp_should_log(sk))
                         pr_info("[HyStart++] [sk: %p] STAGE: %s -> %s (%s) | cwnd: %u\n",
                                 sk, hspp_stage_str(ca->hspp_flag), destination, reason, tcp_sk(sk)->snd_cwnd);
                 ca->hspp_flag = HSPP_DEACTIVE;
         }
 
         if (new_state == TCP_CA_Loss) {
                 bictcp_reset(inet_csk_ca(sk));
                 
                 if (hystartpp) {
                         /* Reset HyStart++ tracking on hard loss */
                         ca->hspp_round_counter = 0;
                         ca->hspp_last_round_cwnd = tcp_snd_cwnd(tcp_sk(sk));
                         hystartpp_reset(sk);
                 } else if (hystart) {
                         bictcp_hystart_reset(sk);
                 }
         }
 }
 
 /* NEW: This explicitly hooks into the TCP Undo event */
 __bpf_kfunc static u32 cubictcp_undo_cwnd(struct sock *sk)
 {
         struct tcp_sock *tp = tcp_sk(sk);
         struct bictcp *ca = inet_csk_ca(sk);
 
         /* Standard CUBIC functionality: reset the epoch curve */
         ca->epoch_start = 0; 
 
         if (hystart && ca->found) {
                 /* Spurious loss recovered. Turn standard HyStart back on. */
                 ca->found = 0;
                 bictcp_hystart_reset(sk);
         }
 
         /* Continue processing default TCP Reno undo logic */
         return tcp_reno_undo_cwnd(sk);
 }
 
 static u32 hystart_ack_delay(const struct sock *sk)
 {
         unsigned long rate = READ_ONCE(sk->sk_pacing_rate);
         if (!rate)
                 return 0;
         return min_t(u64, USEC_PER_MSEC,
                      div64_ul((u64)sk->sk_gso_max_size * 4 * USEC_PER_SEC, rate));
 }
 
 static void hystartpp_new_round(struct sock *sk)
 {
         struct tcp_sock *tp = tcp_sk(sk);
         struct bictcp *ca = inet_csk_ca(sk);
         u32 curr_cwnd = tcp_snd_cwnd(tp);
         u32 prev_cwnd = ca->hspp_last_round_cwnd ? ca->hspp_last_round_cwnd : curr_cwnd;
         s32 diff = (s32)curr_cwnd - (s32)prev_cwnd;
         s32 pct = prev_cwnd ? (diff * 100) / (s32)prev_cwnd : 0;
         u32 rtt = (ca->hspp_current_round_minrtt != ~0U) ? ca->hspp_current_round_minrtt : (tp->srtt_us >> 3);
 
         if (hspp_should_log(sk))
                 pr_info("[HyStart++] [sk: %p] [ ROUND %u | stage: %s, cwnd: %u, mss: %u, min_rtt: %u us, growth: %+d pkts (%+d%%) ]\n",
                         sk, ca->hspp_round_counter, hspp_stage_str(ca->hspp_flag), curr_cwnd, tp->mss_cache, rtt, diff, pct);
 
         ca->hspp_last_round_cwnd = curr_cwnd;
         hystartpp_reset(sk);
         ca->hspp_round_counter++;
 
         if ((ca->hspp_flag == HSPP_IN_CSS) &&
             ((ca->hspp_round_counter - ca->hspp_entered_css_at_round) >= HSPP_CSS_ROUNDS)) {
                 tp->snd_ssthresh = tcp_snd_cwnd(tp);
                 ca->hspp_flag = HSPP_DEACTIVE;
                 if (hspp_should_log(sk))
                         pr_info("[HyStart++] [sk: %p] STAGE: CSS -> CONGESTION_AVOIDANCE (CSS 5-round limit) | cwnd: %u, ssthresh: %u\n",
                                 sk, tcp_snd_cwnd(tp), tp->snd_ssthresh);
         }
 }
 
 static void hystartpp_adjust_params(struct sock *sk, u32 rtt)
 {
         struct tcp_sock *tp = tcp_sk(sk);
         struct bictcp *ca = inet_csk_ca(sk);
         u32 rtt_thresh;
 
         /* RFC 9406 Section 4.2: Check for delay increase to enter CSS */
         if ((ca->hspp_flag == HSPP_IN_SS) &&
             (ca->hspp_rttsample_counter >= HSPP_N_RTT_SAMPLE) &&
             (ca->hspp_current_round_minrtt != ~0U) &&
             (ca->hspp_last_round_minrtt != ~0U)) {
                 rtt_thresh = ca->hspp_last_round_minrtt >> HSPP_CSS_MIN_RTT_DIV;
                 rtt_thresh = HSPP_RTT_THRESH(rtt_thresh);
 
                 if (ca->hspp_current_round_minrtt >= (ca->hspp_last_round_minrtt + rtt_thresh)) {
                         ca->hspp_css_baseline_minrtt = ca->hspp_current_round_minrtt;
                         ca->hspp_entered_css_at_round = ca->hspp_round_counter;
                         ca->hspp_flag = HSPP_IN_CSS;
                         if (hspp_should_log(sk))
                                 pr_info("[HyStart++] [sk: %p] STAGE: SLOW_START -> CSS | cwnd: %u, min_rtt: %u us, thresh: %u us\n",
                                         sk, tcp_snd_cwnd(tp), ca->hspp_current_round_minrtt, rtt_thresh);
                 }
         } else if ((ca->hspp_flag == HSPP_IN_CSS) &&
                    (ca->hspp_rttsample_counter >= HSPP_N_RTT_SAMPLE)) {
                 /* RFC 9406 Section 4.3: Premature exit check */
                 if (ca->hspp_current_round_minrtt < ca->hspp_css_baseline_minrtt) {
                         if (hspp_should_log(sk))
                                 pr_info("[HyStart++] [sk: %p] STAGE: CSS -> SLOW_START (Premature exit: RTT dropped) | cwnd: %u, rtt: %u us < baseline: %u us\n",
                                         sk, tcp_snd_cwnd(tp), ca->hspp_current_round_minrtt, ca->hspp_css_baseline_minrtt);
                         ca->hspp_css_baseline_minrtt = ~0U;
                         ca->hspp_flag = HSPP_IN_SS;
                 }
         }
 }
 
 static void hystart_update(struct sock *sk, u32 delay)
 {
         struct tcp_sock *tp = tcp_sk(sk);
         struct bictcp *ca = inet_csk_ca(sk);
         u32 threshold;
 
         if (after(tp->snd_una, ca->end_seq))
                 bictcp_hystart_reset(sk);
 
         if (tcp_snd_cwnd(tp) < hystart_low_window)
                 return;
 
         if (hystart_detect & HYSTART_ACK_TRAIN) {
                 u32 now = bictcp_clock_us(sk);
 
                 if ((s32)(now - ca->last_ack) <= hystart_ack_delta_us) {
                         ca->last_ack = now;
                         threshold = ca->delay_min + hystart_ack_delay(sk);
 
                         if (sk->sk_pacing_status == SK_PACING_NONE)
                                 threshold >>= 1;
 
                         if ((s32)(now - ca->round_start) > threshold) {
                                 ca->found = 1;
                                 tp->snd_ssthresh = tcp_snd_cwnd(tp);
                         }
                 }
         }
 
         if (hystart_detect & HYSTART_DELAY) {
                 if (ca->curr_rtt > delay)
                         ca->curr_rtt = delay;
                 if (ca->sample_cnt < HYSTART_MIN_SAMPLES) {
                         ca->sample_cnt++;
                 } else {
                         if (ca->curr_rtt > ca->delay_min +
                             HYSTART_DELAY_THRESH(ca->delay_min >> 3)) {
                                 ca->found = 1;
                                 tp->snd_ssthresh = tcp_snd_cwnd(tp);
                         }
                 }
         }
 }
 
 
__bpf_kfunc static void cubictcp_acked(
        struct sock *sk,
        const struct ack_sample *sample)
    {
        const struct tcp_sock *tp = tcp_sk(sk);
        struct bictcp *ca = inet_csk_ca(sk);
        u32 delay;
    
        /*
         * Log every ACK callback before any early returns.
         *
         * Invalid RTT samples are reported as -1.
         * min_rtt is the previously maintained minimum.
         *
         * Logging does not change congestion-control state.
         */
        if (hspp_should_log(sk)) {
            pr_info("[HyStart++] [sk: %p] EVENT: ACK | "
                    "stage: %s, cwnd: %u, ssthresh: %u, "
                    "mss: %u, rtt_sample: %d us, "
                    "min_rtt: %u us\n",
                    sk,
                    hspp_stage_str(ca->hspp_flag),
                    tcp_snd_cwnd(tp),
                    tp->snd_ssthresh,
                    tp->mss_cache,
                    sample->rtt_us,
                    ca->delay_min);
        }
    
        /*
         * Preserve original RTT validity check.
         */
        if (sample->rtt_us < 0)
            return;
    
        /*
         * Preserve original CUBIC early return.
         * Logging now happens before this condition.
         */
        if (ca->epoch_start &&
            (s32)(tcp_jiffies32 - ca->epoch_start) < HZ)
            return;
    
        delay = sample->rtt_us ? sample->rtt_us : 1;
    
        /*
         * Maintain minimum RTT.
         */
        if (ca->delay_min == 0 || ca->delay_min > delay)
            ca->delay_min = delay;
    
        /*
         * HyStart++ processing.
         */
        if (hystartpp) {
    
            /*
             * Track round boundaries across congestion stages.
             */
            if (after(tp->snd_una, ca->hspp_end_seq))
                hystartpp_new_round(sk);
    
            /*
             * Update current round minimum RTT.
             */
            if (delay < ca->hspp_current_round_minrtt)
                ca->hspp_current_round_minrtt = delay;
    
            ca->hspp_rttsample_counter++;
    
            /*
             * Evaluate HyStart++ parameters only
             * during active Slow Start or CSS.
             */
            if (tcp_in_slow_start(tp) &&
                ca->hspp_flag != HSPP_DEACTIVE) {
                hystartpp_adjust_params(sk, delay);
            }
    
            return;
        }
    
        /*
         * Standard HyStart fallback.
         */
        if (!ca->found && tcp_in_slow_start(tp) && hystart)
            hystart_update(sk, delay);
    }
    
 
 static struct tcp_congestion_ops cubictcp __read_mostly = {
         .init           = cubictcp_init,
         .ssthresh       = cubictcp_recalc_ssthresh,
         .cong_avoid     = cubictcp_cong_avoid,
         .set_state      = cubictcp_state,
         .undo_cwnd      = cubictcp_undo_cwnd, /* CHANGED: Hooked to the custom undo function */
         .cwnd_event     = cubictcp_cwnd_event,
         .pkts_acked     = cubictcp_acked,
         .owner          = THIS_MODULE,
         .name           = "cubic",
 };
 
 BTF_SET8_START(tcp_cubic_check_kfunc_ids)
 #ifdef CONFIG_X86
 #ifdef CONFIG_DYNAMIC_FTRACE
 BTF_ID_FLAGS(func, cubictcp_init)
 BTF_ID_FLAGS(func, cubictcp_recalc_ssthresh)
 BTF_ID_FLAGS(func, cubictcp_cong_avoid)
 BTF_ID_FLAGS(func, cubictcp_state)
 BTF_ID_FLAGS(func, cubictcp_undo_cwnd) /* CHANGED: Added to BTF IDs */
 BTF_ID_FLAGS(func, cubictcp_cwnd_event)
 BTF_ID_FLAGS(func, cubictcp_acked)
 #endif
 #endif
 BTF_SET8_END(tcp_cubic_check_kfunc_ids)
 
 static const struct btf_kfunc_id_set tcp_cubic_kfunc_set = {
         .owner = THIS_MODULE,
         .set   = &tcp_cubic_check_kfunc_ids,
 };
 
 static int __init cubictcp_register(void)
 {
         BUILD_BUG_ON(sizeof(struct bictcp) > ICSK_CA_PRIV_SIZE);
 
         beta_scale = 8 * (BICTCP_BETA_SCALE + beta) / 3 / (BICTCP_BETA_SCALE - beta);
         cube_rtt_scale = (bic_scale * 10);
         cube_factor = 1ull << (10 + 3 * BICTCP_HZ);
         do_div(cube_factor, bic_scale * 10);
 
         register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &tcp_cubic_kfunc_set);
         return tcp_register_congestion_control(&cubictcp);
 }
 
 static void __exit cubictcp_unregister(void)
 {
         tcp_unregister_congestion_control(&cubictcp);
 }
 
 module_init(cubictcp_register);
 module_exit(cubictcp_unregister);
 
 MODULE_AUTHOR("Sangtae Ha, Stephen Hemminger");
 MODULE_LICENSE("GPL");
 MODULE_DESCRIPTION("CUBIC TCP");
 MODULE_VERSION("2.3");
 
