// SPDX-License-Identifier: GPL-2.0-only
/*
 * TCP CUBIC: Binary Increase Congestion control for TCP v2.3 with SEARCH Logging
 */

#include <linux/mm.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/module.h>
#include <linux/math64.h>
#include <net/tcp.h>

#define BICTCP_BETA_SCALE    1024       /* Scale factor beta calculation
                                         * max_cwnd = snd_cwnd * beta
                                         */
#define BICTCP_HZ               10      /* BIC HZ 2^10 = 1024 */

/* Two methods of hybrid slow start */
#define HYSTART_ACK_TRAIN       0x1
#define HYSTART_DELAY           0x2

/* Number of delay samples for detecting the increase of delay */
#define HYSTART_MIN_SAMPLES     8
#define HYSTART_DELAY_MIN       (4000U) /* 4 ms */
#define HYSTART_DELAY_MAX       (16000U)        /* 16 ms */
#define HYSTART_DELAY_THRESH(x) clamp(x, HYSTART_DELAY_MIN, HYSTART_DELAY_MAX)

static int fast_convergence __read_mostly = 1;
static int beta __read_mostly = 717;    /* = 717/1024 (BICTCP_BETA_SCALE) */
static int initial_ssthresh __read_mostly;
static int bic_scale __read_mostly = 41;
static int tcp_friendliness __read_mostly = 1;

static int hystart_detect __read_mostly = HYSTART_ACK_TRAIN | HYSTART_DELAY;
static int hystart_low_window __read_mostly = 16;
static int hystart_ack_delta_us __read_mostly = 2000;

static u32 cube_rtt_scale __read_mostly;
static u32 beta_scale __read_mostly;
static u64 cube_factor __read_mostly;

/* Note parameters that are used for precomputing scale factors are read-only */
module_param(fast_convergence, int, 0644);
MODULE_PARM_DESC(fast_convergence, "turn on/off fast convergence");
module_param(beta, int, 0644);
MODULE_PARM_DESC(beta, "beta for multiplicative increase");
module_param(initial_ssthresh, int, 0644);
MODULE_PARM_DESC(initial_ssthresh, "initial value of slow start threshold");
module_param(bic_scale, int, 0444);
MODULE_PARM_DESC(bic_scale, "scale (scaled by 1024) value for bic function (bic_scale/1024)");
module_param(tcp_friendliness, int, 0644);
MODULE_PARM_DESC(tcp_friendliness, "turn on/off tcp friendliness");
module_param(hystart_detect, int, 0644);
MODULE_PARM_DESC(hystart_detect, "hybrid slow start detection mechanisms"
                 " 1: packet-train 2: delay 3: both packet-train and delay");
module_param(hystart_low_window, int, 0644);
MODULE_PARM_DESC(hystart_low_window, "lower bound cwnd for hybrid slow start");
module_param(hystart_ack_delta_us, int, 0644);
MODULE_PARM_DESC(hystart_ack_delta_us, "spacing between ack's indicating train (usecs)");

//////////////////////// SEARCH ////////////////////////
#define MAX_US_INT 0xffff
#define SEARCH_BINS 10                                                          /* Number of bins in a window */
#define SEARCH_EXTRA_ACKED_BINS 1                                               /* Number of additional bins to calculate delivery window */
#define SEARCH_EXTRA_SENT_BINS 40                                               /* Number of additional bins to cover data after shifting by RTT */
#define SEARCH_ACKED_BINS (SEARCH_BINS + SEARCH_EXTRA_ACKED_BINS)       /* Number of total bins in an acked window */
#define SEARCH_SENT_BINS (SEARCH_BINS + SEARCH_EXTRA_SENT_BINS)         /* Number of total bins in a sent window */
#define SEARCH_DRAIN_ACKEDSEG_THRESH 3                  /* ACKed-segment threshold to permit CWND increase during drain */

#define SEARCH_VERSION 40 /* Just for logging */

/* Define an enum for the slow start mode */
enum {
    SS_LEGACY = 0, /* No slow start algorithm is used */
    SS_SEARCH = 1, /* Enable the SEARCH slow start algorithm */
    SS_HYSTART = 2 /* Enable the HyStart slow start algorithm */
};

enum unset_bin_duration {
    RESET_BIN_DURATION_TRUE,  // Reset bin duration
    RESET_BIN_DURATION_FALSE    // Do not reset bin duration
};

/* Set the default mode */
static int slow_start_mode __read_mostly = SS_SEARCH;
static int search_window_duration_factor __read_mostly = 35;
static int search_thresh __read_mostly = 26;
static int debug_port __read_mostly = 5201;

// Module parameters used by SEARCH
module_param(slow_start_mode, int, 0644);
MODULE_PARM_DESC(slow_start_mode, "0: No Algorithm, 1: SEARCH, 2: HyStart");
module_param(search_window_duration_factor, int, 0644);
MODULE_PARM_DESC(search_window_duration_factor, "Multiply with (initial RTT / 10) to set the window size");
module_param(search_thresh, int, 0644);
MODULE_PARM_DESC(search_thresh, "Threshold for exiting from slow start in percentage");
module_param(debug_port, int, 0644);
MODULE_PARM_DESC(debug_port, "Port to monitor and log for SEARCH");

static inline bool search_should_log(const struct sock *sk)
{
        return (ntohs(inet_sk(sk)->inet_sport) == debug_port ||
                ntohs(inet_sk(sk)->inet_dport) == debug_port);
}

/* BIC TCP Parameters */
struct bictcp {
        u32     cnt;            /* increase cwnd by 1 after ACKs */
        u32     last_max_cwnd;  /* last maximum snd_cwnd */
        u32     last_cwnd;      /* the last snd_cwnd */
        u32     last_time;      /* time when updated last_cwnd */
        u32     bic_origin_point;/* origin point of bic function */
        u32     bic_K;          /* time to origin point from beginning of current epoch */
        u32     delay_min;      /* min delay (usec) */
        u32     epoch_start;    /* beginning of an epoch */
        u32     ack_cnt;        /* number of acks */
        u32     tcp_cwnd;       /* estimated tcp cwnd */

        /* Union of HyStart and SEARCH variables */
        union {
                /* HyStart variables */
                struct {
                        u16     unused;
                        u8      sample_cnt;
                        u8      found;
                        u32     round_start;
                        u32     end_seq;
                        u32     last_ack;
                        u32     curr_rtt;
                }hystart;

                /* SEARCH variables */
                struct {
                        u32     bin_duration_us;
                        s32     curr_idx;
                        u32     bin_end_us;
                        u16     acked_bin[SEARCH_ACKED_BINS];
                        u16     sent_bin[SEARCH_SENT_BINS];
                        u8      scale_factor;
                        u32     search_targeted_cwnd;
                        u8      search_cwnd_reduction_to_target;
                        u32     search_drain_ackedseg;
                        u32     prior_delivered;
                }search;
        };
};

static inline void bictcp_search_reset(struct sock *sk, enum unset_bin_duration flag)
{
        struct bictcp *ca = inet_csk_ca(sk);
        struct tcp_sock *tp = tcp_sk(sk);

        memset(ca->search.sent_bin, 0, sizeof(ca->search.sent_bin));
        memset(ca->search.acked_bin, 0, sizeof(ca->search.acked_bin));
        ca->search.curr_idx = -1;
        ca->search.bin_end_us = 0;
        ca->search.scale_factor = 0;
        ca->search.search_targeted_cwnd = 0;
        ca->search.search_cwnd_reduction_to_target = 0;
        ca->search.search_drain_ackedseg = 0;
        ca->search.prior_delivered = tp->delivered;
        if (flag == RESET_BIN_DURATION_TRUE)
                ca->search.bin_duration_us = 0;
}

static inline void bictcp_reset(struct bictcp *ca)
{
        memset(ca, 0, offsetof(struct bictcp, hystart.unused));
        if (slow_start_mode == SS_HYSTART)
                ca->hystart.found = 0;
}

static inline u32 bictcp_clock_us(const struct sock *sk)
{
        return tcp_sk(sk)->tcp_mstamp;
}

static inline void bictcp_hystart_reset(struct sock *sk)
{
        struct tcp_sock *tp = tcp_sk(sk);
        struct bictcp *ca = inet_csk_ca(sk);

        ca->hystart.round_start = ca->hystart.last_ack = bictcp_clock_us(sk);
        ca->hystart.end_seq = tp->snd_nxt;
        ca->hystart.curr_rtt = ~0U;
        ca->hystart.sample_cnt = 0;
}

__bpf_kfunc static void cubictcp_init(struct sock *sk)
{
        struct bictcp *ca = inet_csk_ca(sk);

        bictcp_reset(ca);

        if (slow_start_mode == SS_SEARCH) {
                bictcp_search_reset(sk, RESET_BIN_DURATION_TRUE);
                if (search_should_log(sk)) {
                        pr_info("[SEARCH] [sk: %p] INIT -> SLOW_START | cwnd: %u, ssthresh: %u, mss: %u\n",
                                sk, tcp_snd_cwnd(tcp_sk(sk)), tcp_sk(sk)->snd_ssthresh, tcp_sk(sk)->mss_cache);
                }
        }

        if (slow_start_mode == SS_HYSTART)
                bictcp_hystart_reset(sk);

        if (slow_start_mode != SS_HYSTART && initial_ssthresh)
                tcp_sk(sk)->snd_ssthresh = initial_ssthresh;
}

__bpf_kfunc static void cubictcp_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
        if (event == CA_EVENT_TX_START) {
                struct bictcp *ca = inet_csk_ca(sk);
                u32 now = tcp_jiffies32;
                s32 delta;

                delta = now - tcp_sk(sk)->lsndtime;
                if (ca->epoch_start && delta > 0) {
                        ca->epoch_start += delta;
                        if (after(ca->epoch_start, now))
                                ca->epoch_start = now;
                }
                return;
        }

        if (event == CA_EVENT_CWND_RESTART) {
                if (slow_start_mode == SS_SEARCH)
                        bictcp_search_reset(sk, RESET_BIN_DURATION_TRUE);
                return;
        }
}

static u32 cubic_root(u64 a)
{
        u32 x, b, shift;
        static const u8 v[] = {
                0,   54,   54,   54,  118,  118,  118,  118,
          123,  129,  134,  138,  143,  147,  151,  156,
          157,  161,  164,  168,  170,  173,  176,  179,
          181,  185,  187,  190,  192,  194,  197,  199,
          200,  202,  204,  206,  209,  211,  213,  215,
          217,  219,  221,  222,  224,  225,  227,  229,
          231,  232,  234,  236,  237,  239,  240,  242,
          244,  245,  246,  248,  250,  251,  252,  254,
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

        if (bic_target > cwnd) {
                ca->cnt = cwnd / (bic_target - cwnd);
        } else {
                ca->cnt = 100 * cwnd;
        }

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

__bpf_kfunc static void cubictcp_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
        struct tcp_sock *tp = tcp_sk(sk);
        struct bictcp *ca = inet_csk_ca(sk);

        if (!tcp_is_cwnd_limited(sk))
                return;

        if (tcp_in_slow_start(tp) && ca->search.search_cwnd_reduction_to_target == 1)
                return;

        if (tcp_in_slow_start(tp)) {
                acked = tcp_slow_start(tp, acked);
                if (!acked)
                        return;
        }
        bictcp_update(ca, tcp_snd_cwnd(tp), acked);
        tcp_cong_avoid_ai(tp, ca->cnt, acked);
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
        struct tcp_sock *tp = tcp_sk(sk);

        if (slow_start_mode == SS_SEARCH && search_should_log(sk)) {
                if (new_state == TCP_CA_Loss) {
                        pr_info("[SEARCH] [sk: %p] STAGE: %s -> LOSS (Forced Exit) | Reason: RTO/Timeout | cwnd: %u, ssthresh: %u, inflight: %u\n",
                                sk, (ca->search.search_cwnd_reduction_to_target == 1) ? "DRAIN" : "SLOW_START", 
                                tcp_snd_cwnd(tp), tp->snd_ssthresh, tcp_packets_in_flight(tp));
                }
        }

        if (new_state == TCP_CA_Loss) {
                bictcp_reset(inet_csk_ca(sk));

                if (slow_start_mode == SS_SEARCH)
                        bictcp_search_reset(sk, RESET_BIN_DURATION_TRUE);

                if (slow_start_mode == SS_HYSTART)
                        bictcp_hystart_reset(sk);
        }
}

static u32 hystart_ack_delay(const struct sock *sk)
{
        unsigned long rate;

        rate = READ_ONCE(sk->sk_pacing_rate);
        if (!rate)
                return 0;
        return min_t(u64, USEC_PER_MSEC,
                     div64_ul((u64)sk->sk_gso_max_size * 4 * USEC_PER_SEC, rate));
}

static void hystart_update(struct sock *sk, u32 delay)
{
        struct tcp_sock *tp = tcp_sk(sk);
        struct bictcp *ca = inet_csk_ca(sk);
        u32 threshold;

        if (after(tp->snd_una, ca->hystart.end_seq))
                bictcp_hystart_reset(sk);

        if (tcp_snd_cwnd(tp) < hystart_low_window)
                return;

        if (hystart_detect & HYSTART_ACK_TRAIN) {
                u32 now = bictcp_clock_us(sk);

                if ((s32)(now - ca->hystart.last_ack) <= hystart_ack_delta_us) {
                        ca->hystart.last_ack = now;
                        threshold = ca->delay_min + hystart_ack_delay(sk);

                        if (sk->sk_pacing_status == SK_PACING_NONE)
                                threshold >>= 1;

                        if ((s32)(now - ca->hystart.round_start) > threshold) {
                                ca->hystart.found = 1;
                                tp->snd_ssthresh = tcp_snd_cwnd(tp);
                        }
                }
        }

        if (hystart_detect & HYSTART_DELAY) {
                if (ca->hystart.curr_rtt > delay)
                        ca->hystart.curr_rtt = delay;
                if (ca->hystart.sample_cnt < HYSTART_MIN_SAMPLES) {
                        ca->hystart.sample_cnt++;
                } else {
                        if (ca->hystart.curr_rtt > ca->delay_min +
                            HYSTART_DELAY_THRESH(ca->delay_min >> 3)) {
                                ca->hystart.found = 1;
                                tp->snd_ssthresh = tcp_snd_cwnd(tp);
                        }
                }
        }
}

static inline u8 search_bit_shifting(struct sock *sk, u64 bin_value)
{
        struct bictcp *ca = inet_csk_ca(sk);
        u8 num_shift = 0;
        u32 i = 0;

        while (bin_value > MAX_US_INT) {
                num_shift += 1;
                bin_value >>= 1;
        }

        if (num_shift == 0)
        return 0;

        for (i = 0; i < SEARCH_ACKED_BINS; i++)
                ca->search.acked_bin[i] >>= num_shift;

        for (i = 0; i < SEARCH_SENT_BINS; i++)
                ca->search.sent_bin[i] >>= num_shift;

        ca->search.scale_factor += num_shift;
        return num_shift;
}

static void search_init_bins(struct sock *sk, u32 now_us, u32 rtt_us)
{
        struct bictcp *ca = inet_csk_ca(sk);
        struct tcp_sock *tp = tcp_sk(sk);
        u8 amount_scaled = 0;
        u64 acked_value = 0;
        u64 sent_value = 0;
        u64 largest_val = 0;

        if (ca->search.bin_duration_us == 0)
                ca->search.bin_duration_us = (rtt_us * search_window_duration_factor) / (SEARCH_BINS * 10);

        if (ca->search.bin_duration_us == 0)
                return;

        ca->search.bin_end_us = now_us + ca->search.bin_duration_us;
        ca->search.curr_idx = 0;

        sent_value = tp->bytes_sent;
        acked_value = tp->bytes_acked;

        if (acked_value > MAX_US_INT || sent_value > MAX_US_INT){
                largest_val = (acked_value > sent_value) ? acked_value : sent_value;
                amount_scaled = search_bit_shifting(sk, largest_val);
                acked_value >>= amount_scaled;
                sent_value >>= amount_scaled;
        }
        ca->search.acked_bin[0] = acked_value;
        ca->search.sent_bin[0] = sent_value;
}

static void search_update_bins(struct sock *sk, u32 now_us, u32 rtt_us)
{
        struct bictcp *ca = inet_csk_ca(sk);
        struct tcp_sock *tp = tcp_sk(sk);
        u32 passed_bins = 0;
        u32 i = 0;
        u64 acked_value = 0;
        u64 sent_value = 0;
        u8 amount_scaled = 0;
        u64 largest_val = 0;

        passed_bins = ((now_us - ca->search.bin_end_us) / ca->search.bin_duration_us) + 1;

        for (i = ca->search.curr_idx + 1; i < ca->search.curr_idx + passed_bins; i++){
                ca->search.acked_bin[i % SEARCH_ACKED_BINS] = ca->search.acked_bin[ca->search.curr_idx % SEARCH_ACKED_BINS];
                ca->search.sent_bin[i % SEARCH_SENT_BINS] = ca->search.sent_bin[ca->search.curr_idx % SEARCH_SENT_BINS];
        }

        ca->search.bin_end_us += passed_bins * ca->search.bin_duration_us;
        ca->search.curr_idx += passed_bins;

        acked_value = tp->bytes_acked >> ca->search.scale_factor;
        sent_value = tp->bytes_sent >> ca->search.scale_factor;

        if (acked_value > MAX_US_INT || sent_value > MAX_US_INT) {
                largest_val = (acked_value > sent_value) ? acked_value : sent_value;
                amount_scaled = search_bit_shifting(sk, largest_val);
                acked_value >>= amount_scaled;
                sent_value  >>= amount_scaled;
        }

        ca->search.acked_bin[ca->search.curr_idx % SEARCH_ACKED_BINS] = acked_value;
        ca->search.sent_bin[ca->search.curr_idx % SEARCH_SENT_BINS] = sent_value;
}

static inline u64 search_compute_delivered_window(struct sock *sk, s32 left, s32 right)
{
        struct bictcp *ca = inet_csk_ca(sk);
        u64 delivered = 0;

        delivered = ca->search.acked_bin[right % SEARCH_ACKED_BINS] - ca->search.acked_bin[left % SEARCH_ACKED_BINS];
        return delivered;
}

static inline u64 search_compute_sent_window(struct sock *sk, s32 left, s32 right, u32 fraction)
{
        struct bictcp *ca = inet_csk_ca(sk);
        u64 sent = 0;

        sent = ca->search.sent_bin[(right - 1) % SEARCH_SENT_BINS] - ca->search.sent_bin[left % SEARCH_SENT_BINS];

        if (left == 0)
                sent += (ca->search.sent_bin[left % SEARCH_SENT_BINS]) * fraction / 100;
        else
                sent += (ca->search.sent_bin[left % SEARCH_SENT_BINS] - ca->search.sent_bin[(left - 1) % SEARCH_SENT_BINS]) * fraction / 100;

        sent += (ca->search.sent_bin[right % SEARCH_SENT_BINS] - ca->search.sent_bin[(right - 1) % SEARCH_SENT_BINS]) * (100 - fraction) / 100;

        return sent;
}

static bool search_compute_target_cwnd(struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct bictcp *ca = inet_csk_ca(sk);
    s32 cong_idx;
    u32 initial_rtt;
    u32 rtt_bins;
    u64 delivered_scaled;
    u64 delivered_bytes;
    u64 target_pkts;

    if (!ca->search.bin_duration_us || search_window_duration_factor <= 0){
        bictcp_search_reset(sk, RESET_BIN_DURATION_TRUE);
        return false;
    }

    initial_rtt = ca->search.bin_duration_us * SEARCH_BINS * 10 / search_window_duration_factor;
    rtt_bins = (initial_rtt + ca->search.bin_duration_us - 1) / ca->search.bin_duration_us;

    if (rtt_bins == 0)
        rtt_bins = 1;

    cong_idx = ca->search.curr_idx - (s32)rtt_bins;

    if (cong_idx < 0 || ca->search.curr_idx - cong_idx > SEARCH_ACKED_BINS - 1)
        return false;

    delivered_scaled = search_compute_delivered_window(sk, cong_idx, ca->search.curr_idx);
    delivered_bytes = delivered_scaled << ca->search.scale_factor;
    target_pkts = div_u64(delivered_bytes, tp->mss_cache);

    ca->search.search_targeted_cwnd = max((u32)target_pkts, (u32)TCP_INIT_CWND);

    return true;
}

static void search_update(struct sock *sk, u32 rtt_us)
{
        struct tcp_sock *tp = tcp_sk(sk);
        struct bictcp *ca = inet_csk_ca(sk);

        s32 prev_idx = 0;
        u64 curr_delv_bytes = 0;
        u64 prev_sent_bytes = 0;
        s64 norm_diff = 0;
        u32 now_us = bictcp_clock_us(sk);
        u32 fraction = 0;
        u32 segs_acked = 0;
        u32 snd_cnt = 0;
        u32 new_cwnd = 0;

        if (unlikely(search_window_duration_factor <= 0)) {
                bictcp_search_reset(sk, RESET_BIN_DURATION_TRUE);
                return;
        }

        if (ca->search.search_cwnd_reduction_to_target == 0) {

                if (ca->search.curr_idx < 0) {
                        search_init_bins(sk, now_us, rtt_us);
                        return;
                }

                if (now_us < ca->search.bin_end_us)
                        return;

                search_update_bins(sk, now_us, rtt_us);

                if (ca->search.bin_duration_us == 0) {
                        bictcp_search_reset(sk, RESET_BIN_DURATION_TRUE);
                        return;
                }

                prev_idx = ca->search.curr_idx - (s32)(rtt_us / ca->search.bin_duration_us);
                if (prev_idx >= SEARCH_BINS && (ca->search.curr_idx - prev_idx) < SEARCH_EXTRA_SENT_BINS - 1) {

                        curr_delv_bytes = search_compute_delivered_window(sk,
                                                                          ca->search.curr_idx - SEARCH_BINS,
                                                                          ca->search.curr_idx);

                        fraction = ((rtt_us % ca->search.bin_duration_us) * 100 / ca->search.bin_duration_us);

                        prev_sent_bytes = search_compute_sent_window(sk,
                                                                  prev_idx - SEARCH_BINS,
                                                                  prev_idx,
                                                                  fraction);

                        if (prev_sent_bytes > 0) {
                                s64 diff = (s64)prev_sent_bytes - (s64)curr_delv_bytes;
                                norm_diff = diff * 100 / (s64)prev_sent_bytes;

                                if (search_should_log(sk)) {
                                        pr_info("[SEARCH] [sk: %p] ROUND EVAL | stage: SLOW_START, cwnd: %u, mss: %u, rtt: %u us, prev_sent: %llu, curr_delv: %llu, norm_diff: %lld%%\n",
                                                sk, tcp_snd_cwnd(tp), tp->mss_cache, rtt_us, prev_sent_bytes, curr_delv_bytes, norm_diff);
                                }

                                if (prev_sent_bytes >= curr_delv_bytes &&
                                    norm_diff >= search_thresh) {

                                        if (search_compute_target_cwnd(sk)) {
                                                u32 current_cwnd = tcp_snd_cwnd(tp);
                                                u32 inflight = tcp_packets_in_flight(tp);
                                                u32 target_cwnd = ca->search.search_targeted_cwnd;

                                                if (target_cwnd >= current_cwnd || inflight <= target_cwnd) {
                                                        tp->snd_ssthresh = current_cwnd;
                                                        if (search_should_log(sk)) {
                                                                pr_info("[SEARCH] [sk: %p] STAGE: SLOW_START -> CONGESTION_AVOIDANCE (Skip Drain) | Reason: %s | cwnd: %u, target_cwnd: %u, inflight: %u\n",
                                                                        sk, 
                                                                        (target_cwnd >= current_cwnd) ? "target >= cwnd" : "inflight <= target",
                                                                        current_cwnd, target_cwnd, inflight);
                                                        }
                                                        bictcp_search_reset(sk, RESET_BIN_DURATION_TRUE);
                                                        return;
                                                }

                                                ca->search.search_cwnd_reduction_to_target = 1;
                                                ca->search.prior_delivered = tp->delivered;
                                                ca->search.search_drain_ackedseg = 0;
                                                if (search_should_log(sk)) {
                                                        pr_info("[SEARCH] [sk: %p] STAGE: SLOW_START -> DRAIN | Reason: norm_diff (%lld%%) >= thresh (%d%%) | cwnd: %u, target_cwnd: %u, inflight: %u\n",
                                                                sk, norm_diff, search_thresh, tcp_snd_cwnd(tp), target_cwnd, tcp_packets_in_flight(tp));
                                                }
                                        }
                                }
                        }
                }
        }
        else {
                if (tcp_snd_cwnd(tp) <= ca->search.search_targeted_cwnd) {
                        tp->snd_ssthresh = min(tp->snd_ssthresh, ca->search.search_targeted_cwnd);
                        if (search_should_log(sk)) {
                                pr_info("[SEARCH] [sk: %p] STAGE: DRAIN -> CONGESTION_AVOIDANCE (Target Met Early) | cwnd: %u, ssthresh: %u\n",
                                        sk, tcp_snd_cwnd(tp), tp->snd_ssthresh);
                        }
                        bictcp_search_reset(sk, RESET_BIN_DURATION_TRUE);
                        return;
                }

                segs_acked = tp->delivered - ca->search.prior_delivered;
                ca->search.prior_delivered = tp->delivered;
                ca->search.search_drain_ackedseg += segs_acked;

                if (ca->search.search_drain_ackedseg >= SEARCH_DRAIN_ACKEDSEG_THRESH) {
                    snd_cnt = ca->search.search_drain_ackedseg / SEARCH_DRAIN_ACKEDSEG_THRESH;
                    ca->search.search_drain_ackedseg %= SEARCH_DRAIN_ACKEDSEG_THRESH;
                }

                new_cwnd = max(tcp_packets_in_flight(tp) + snd_cnt, ca->search.search_targeted_cwnd);
                new_cwnd = min(new_cwnd, tcp_snd_cwnd(tp));

                tcp_snd_cwnd_set(tp, new_cwnd);

                if (new_cwnd == ca->search.search_targeted_cwnd) {
                    tp->snd_ssthresh = min(tp->snd_ssthresh, ca->search.search_targeted_cwnd);
                    if (search_should_log(sk)) {
                            pr_info("[SEARCH] [sk: %p] STAGE: DRAIN -> CONGESTION_AVOIDANCE (Drain Complete) | cwnd: %u, ssthresh: %u\n",
                                    sk, new_cwnd, tp->snd_ssthresh);
                    }
                    bictcp_search_reset(sk, RESET_BIN_DURATION_TRUE);
                } else if (search_should_log(sk) && snd_cnt > 0) {
                        pr_info("[SEARCH] [sk: %p] DRAIN ROUND | cwnd: %u, target_cwnd: %u, inflight: %u\n",
                                sk, new_cwnd, ca->search.search_targeted_cwnd, tcp_packets_in_flight(tp));
                }
        }
}

__bpf_kfunc static void cubictcp_acked(struct sock *sk, const struct ack_sample *sample)
{
        const struct tcp_sock *tp = tcp_sk(sk);
        struct bictcp *ca = inet_csk_ca(sk);
        u32 delay;

        if (sample->rtt_us < 0)
                return;

        if (ca->epoch_start && (s32)(tcp_jiffies32 - ca->epoch_start) < HZ)
                return;

        delay = sample->rtt_us;
        if (delay == 0)
                delay = 1;

        if (ca->delay_min == 0 || ca->delay_min > delay)
                ca->delay_min = delay;

        if (slow_start_mode == SS_SEARCH && search_should_log(sk)) {
                const char *stage_str = "UNKNOWN";
                u8 ca_state = inet_csk(sk)->icsk_ca_state;

                if (ca_state == TCP_CA_Recovery)
                        stage_str = "RECOVERY";
                else if (ca_state == TCP_CA_Loss)
                        stage_str = "LOSS";
                else if (ca_state == TCP_CA_CWR)
                        stage_str = "CWR";
                else if (ca_state == TCP_CA_Disorder)
                        stage_str = "DISORDER";
                else if (tcp_in_slow_start(tp)) {
                        if (ca->search.search_cwnd_reduction_to_target == 1)
                                stage_str = "DRAIN";
                        else
                                stage_str = "SLOW_START";
                } else {
                        stage_str = "CONGESTION_AVOIDANCE";
                }

                pr_info("[SEARCH] [sk: %p] ACK | stage: %s, cwnd: %u, rtt: %u us, inflight: %u\n",
                        sk, stage_str, tcp_snd_cwnd(tp), delay, tcp_packets_in_flight(tp));
        }

        if (tcp_in_slow_start(tp) && inet_csk(sk)->icsk_ca_state == TCP_CA_Open) {
                if (slow_start_mode == SS_SEARCH) {
                        search_update(sk, delay);
                } else if (slow_start_mode == SS_HYSTART && !ca->hystart.found)
                        hystart_update(sk, delay);
        }
}

static struct tcp_congestion_ops cubictcp __read_mostly = {
        .init           = cubictcp_init,
        .ssthresh       = cubictcp_recalc_ssthresh,
        .cong_avoid     = cubictcp_cong_avoid,
        .set_state      = cubictcp_state,
        .undo_cwnd      = tcp_reno_undo_cwnd,
        .cwnd_event     = cubictcp_cwnd_event,
        .pkts_acked     = cubictcp_acked,
        .owner          = THIS_MODULE,
        .name           = "cubic_search",
};

BTF_KFUNCS_START(tcp_cubic_check_kfunc_ids)
BTF_ID_FLAGS(func, cubictcp_init)
BTF_ID_FLAGS(func, cubictcp_recalc_ssthresh)
BTF_ID_FLAGS(func, cubictcp_cong_avoid)
BTF_ID_FLAGS(func, cubictcp_state)
BTF_ID_FLAGS(func, cubictcp_cwnd_event)
BTF_ID_FLAGS(func, cubictcp_acked)
BTF_KFUNCS_END(tcp_cubic_check_kfunc_ids)

static const struct btf_kfunc_id_set tcp_cubic_kfunc_set = {
        .owner = THIS_MODULE,
        .set   = &tcp_cubic_check_kfunc_ids,
};

static int __init cubictcp_register(void)
{
        int ret;

        BUILD_BUG_ON(sizeof(struct bictcp) > ICSK_CA_PRIV_SIZE);

        beta_scale = 8*(BICTCP_BETA_SCALE+beta) / 3 / (BICTCP_BETA_SCALE - beta);
        cube_rtt_scale = (bic_scale * 10);
        cube_factor = 1ull << (10+3*BICTCP_HZ); /* 2^40 */
        do_div(cube_factor, bic_scale * 10);

        ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &tcp_cubic_kfunc_set);
        if (ret < 0)
                return ret;
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
