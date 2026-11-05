// SPDX-License-Identifier: GPL-2.0-only
/*
 * TCP CUBIC: Binary Increase Congestion control for TCP v2.3
 * Home page:
 *      http://netsrv.csc.ncsu.edu/twiki/bin/view/Main/BIC
 * This is from the implementation of CUBIC TCP in
 * Sangtae Ha, Injong Rhee and Lisong Xu,
 *  "CUBIC: A New TCP-Friendly High-Speed TCP Variant"
 *  in ACM SIGOPS Operating System Review, July 2008.
 * Available from:
 *  http://netsrv.csc.ncsu.edu/export/cubic_a_new_tcp_2008.pdf
 *
 * CUBIC integrates a new slow start algorithm, called HyStart.
 * The details of HyStart are presented in
 *  Sangtae Ha and Injong Rhee,
 *  "Taming the Elephants: New TCP Slow Start", NCSU TechReport 2008.
 * Available from:
 *  http://netsrv.csc.ncsu.edu/export/hystart_techreport_2008.pdf
 *
 * All testing results are available from:
 * http://netsrv.csc.ncsu.edu/wiki/index.php/TCP_Testing
 *
 * Unless CUBIC is enabled and congestion window is large
 * this behaves the same as the original Reno.
 */

#include <linux/mm.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/module.h>
#include <linux/math64.h>
#include <net/tcp.h>

#define BICTCP_BETA_SCALE    1024	/* Scale factor beta calculation
					 * max_cwnd = snd_cwnd * beta
					 */
#define	BICTCP_HZ		10	/* BIC HZ 2^10 = 1024 */

/* Two methods of hybrid slow start */
#define HYSTART_ACK_TRAIN	0x1
#define HYSTART_DELAY		0x2

/* Number of delay samples for detecting the increase of delay */
#define HYSTART_MIN_SAMPLES	8
#define HYSTART_DELAY_MIN	(4000U)	/* 4 ms */
#define HYSTART_DELAY_MAX	(16000U)	/* 16 ms */
#define HYSTART_DELAY_THRESH(x)	clamp(x, HYSTART_DELAY_MIN, HYSTART_DELAY_MAX)

static int fast_convergence __read_mostly = 1;
static int beta __read_mostly = 717;	/* = 717/1024 (BICTCP_BETA_SCALE) */
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
/*
 * SEARCH 5.0 = SEARCH 4.1 (bins, delivered/sent windows, 1.25x-BDP drain,
 * app-limited protection) plus two new features:
 *   1. Adaptive exit threshold: exit when the norm stands out from the noise
 *      of the last 6 norm samples, norm / std >= 2.5 (signal-to-noise ratio),
 *      and norm >= SEARCH_THRESH_MIN (search_thresh_mode = 1), or a fixed
 *      threshold (search_thresh_mode = 0).
 *   2. Scaled slow-start growth: growth factor from p = norm / threshold,
 *      3x at p = 0, falling linearly to 1.25x at p = 0.2, then 1.25x up to
 *      p = 1 (search_growth_policy = 1).
 *
 * SEARCH works only in slow start, and only in the Open/Disorder states.
 * Whatever ends slow start also resets SEARCH, so each slow start starts fresh.
 *
 * Where things happen:
 *   cubictcp_acked()      -> search_update(): measure, threshold, growth factor,
 *                            exit slow start or start the drain
 *                            (cwnd < ssthresh, Open/Disorder, not draining)
 *   cubictcp_cong_avoid() -> slow-start growth and the drain; resets SEARCH
 *                            once slow start is over (cwnd >= ssthresh).
 *                            Linux does not call cong_avoid in Recovery/CWR,
 *                            so the drain pauses there.
 *   cubictcp_state()      -> Loss (RTO) resets SEARCH.
 *   cubictcp_cwnd_event() -> restart after idle resets SEARCH.
 */
#define MAX_US_INT 0xffff 
#define SEARCH_BINS 10												/* Number of bins in a window */
#define SEARCH_EXTRA_ACKED_BINS 1  									/* Number of additional bins to calculate delivery window (as this is cumulative, we need one more bin) */
#define SEARCH_EXTRA_SENT_BINS 40									/* Number of additional bins to cover data after shiftting by RTT */
#define SEARCH_ACKED_BINS (SEARCH_BINS + SEARCH_EXTRA_ACKED_BINS)	/* Number of total bins in a acked window */
#define SEARCH_SENT_BINS (SEARCH_BINS + SEARCH_EXTRA_SENT_BINS)		/* Number of total bins in a sent window */
#define SEARCH_DRAIN_ACKEDSEG_THRESH 3        						/* ACKed-segment threshold to permit CWND increase during drain */
#define SEARCH_SNR_MIN 25											/* Exit needs norm / std of the norm history >= 2.5 (scaled by 10) */
#define SEARCH_NORM_HISTORY_MAX 6   								/* Size of rolling window for norm history (last 6 samples) */
#define SEARCH_THRESH_MIN 17        								/* Exit needs norm >= 17 as well (lower clamp of the threshold) */
#define SEARCH_THRESH_MAX 105        								/* Maximum allowed threshold (upper clamp) */
#define SEARCH_EARLY_THRESH 35										/* threshold before enough samples (early phase) */
#define SEARCH_DRAIN_FACTOR 125  									/* 1.25x estimated BDP */
#define SEARCH_GROWTH_MAX 300										/* Growth factor x100 at p = norm / threshold = 0 (3x) */
#define SEARCH_GROWTH_KNEE 125										/* Growth factor x100 at the knee (1.25x) */
#define SEARCH_GROWTH_MIN 125										/* Growth factor x100 at p = 1 (1.25x) */
#define SEARCH_GROWTH_KNEE_P 20										/* Knee position: p = 0.2 (scaled by 100) */

#define SEARCH_VERSION 50 /* Just for logging */

/*
 * SEARCH exit threshold modes (search_thresh_mode):
 *  - SEARCH_THRESH_FIXED (0):   threshold = search_thresh
 *  - SEARCH_THRESH_DYNAMIC (1): exit when norm / std(last 6 norms) >= 2.5
 *                               and norm >= SEARCH_THRESH_MIN, that is
 *                               threshold = clamp(2.5 * std(last 6 norms),
 *                               SEARCH_THRESH_MIN, SEARCH_THRESH_MAX);
 *                               SEARCH_EARLY_THRESH until 6 samples exist
 */
enum {
    SEARCH_THRESH_FIXED = 0,
    SEARCH_THRESH_DYNAMIC = 1,
};

/*
 * search_growth_policy (module parameter):
 *	0: normal TCP slow start growth
 *		sudo sh -c "echo 0 > /sys/module/cubic_s_dynthe/parameters/search_growth_policy"
 *	1: scaled growth
 *		sudo sh -c "echo 1 > /sys/module/cubic_s_dynthe/parameters/search_growth_policy"
 */
enum {
	SEARCH_GROWTH_NORMAL = 0,
	SEARCH_GROWTH_SCALING = 1,
};

/*	enable SEARCH with command:
 		sudo sh -c "echo '1' > /sys/module/your_module_name/parameters/slow_start_mode"
	enable HyStart with command:
 		sudo sh -c "echo '2' > /sys/module/cubic_with_search/parameters/slow_start_mode"  
	disable both SEARCH and HyStart with command:
 		sudo sh -c "echo '0' > /sys/module/cubic_with_search/parameters/slow_start_mode" 
*/
enum {
    SS_LEGACY = 0, /* No slow start algorithm is used */
    SS_SEARCH = 1, /* Enable the SEARCH slow start algorithm */
    SS_HYSTART = 2 /* Enable the HyStart slow start algorithm */
};

/* Set the default mode */
static int slow_start_mode __read_mostly = SS_SEARCH;
static int search_thresh_mode __read_mostly = SEARCH_THRESH_DYNAMIC;
static int search_growth_policy __read_mostly = SEARCH_GROWTH_SCALING;
static int search_enable_drain __read_mostly = 1;
static int search_window_duration_factor __read_mostly = 35;
static int search_thresh __read_mostly = 26;
static int search_app_limited_bin_thresh __read_mostly = 1;
static int debug_port __read_mostly = 5201;


// Module parameters used by SEARCH
module_param(slow_start_mode, int, 0644);
MODULE_PARM_DESC(slow_start_mode, "0: No Algorithm, 1: SEARCH, 2: HyStart");
module_param(search_thresh_mode, int, 0644);
MODULE_PARM_DESC(search_thresh_mode, "0: fixed_threshold, 1: dynamic_threshold");
module_param(search_growth_policy, int, 0644);
MODULE_PARM_DESC(search_growth_policy,"0: normal TCP slow start, 1: adaptive scaling growth");
module_param(search_enable_drain, int, 0644);
MODULE_PARM_DESC(search_enable_drain, "1: enable SEARCH drain before exiting slow start, 0: exit slow start immediately");
module_param(search_window_duration_factor, int, 0644);
MODULE_PARM_DESC(search_window_duration_factor, "Multiply with (initial RTT / 10) to set the window size");
module_param(search_thresh, int, 0644);
MODULE_PARM_DESC(search_thresh, "Threshold for exiting from slow start in percentage");
module_param(search_app_limited_bin_thresh, int, 0644);
MODULE_PARM_DESC(search_app_limited_bin_thresh, "Number of app-limited bins required to block SEARCH exit; 0 disables, range 0-10");
module_param(debug_port, int, 0644);
MODULE_PARM_DESC(debug_port, "Not used by the algorithm (kept for test scripts)");

static inline bool search_should_log(const struct sock *sk)
{
        return (ntohs(inet_sk(sk)->inet_sport) == debug_port ||
                ntohs(inet_sk(sk)->inet_dport) == debug_port);
}

/* BIC TCP Parameters */
struct bictcp {
	u32	cnt;		/* increase cwnd by 1 after ACKs */
	u32	last_max_cwnd;	/* last maximum snd_cwnd */
	u32	last_cwnd;	/* the last snd_cwnd */
	u32	last_time;	/* time when updated last_cwnd */
	u32	bic_origin_point;/* origin point of bic function */
	u32	bic_K;		/* time to origin point
				   from the beginning of the current epoch */
	u32	delay_min;	/* min delay (usec) */
	u32	epoch_start;	/* beginning of an epoch */
	u32	ack_cnt;	/* number of acks */
	u32	tcp_cwnd;	/* estimated tcp cwnd */

	/* Union of HyStart and SEARCH variables */
	union {
		/* HyStart variables */
		struct {
			u16	unused;
			u8	sample_cnt;/* number of samples to decide curr_rtt */
			u8	found;		/* the exit point is found? */
			u32	round_start;	/* beginning of each round */
			u32	end_seq;	/* end_seq of the round */
			u32	last_ack;	/* last time when the ACK spacing is close */
			u32	curr_rtt;	/* the minimum rtt of current round */
		}hystart;

		/* SEARCH variables */
		struct {
			u32	bin_duration_us;					/* duration of each bin in microsecond */
			s32	curr_idx;							/* total number of bins */
			u32	bin_end_us;							/* end time of the latest bin in microsecond */
			u16	acked_bin[SEARCH_ACKED_BINS];		/* array to keep acked bytes for bins */
			u16 sent_bin[SEARCH_SENT_BINS];				/* array to keep sent bytes for bins */
			u8 app_limited_bin[SEARCH_BINS];			/* 1 if the bin had an app-limited ACK */
			u8 current_app_limited;						/* app-limited flag of the bin being filled */
			u8	scale_factor;						/* scale factor to fit the value with bin size */
			u32 search_targeted_cwnd;  				/* BDP estimate from one RTT earlier; used to initiate SEARCH drain */
			u32 search_drain_ackedseg;      	 	/* Accumulates number of segments ACKed during SEARCH drain */
			u32 prior_delivered;					/* Number of packets delivered previously */
			s16 norm_hist[SEARCH_NORM_HISTORY_MAX]; /* Stores the most recent norm_diff values (up to SEARCH_NORM_HISTORY_MAX) */
			u8  norm_hist_count;  					/* Used to determine when enough samples are available to set threshold*/
			u32 search_growth_accum; 				/* accumulator for fractional scaled cwnd increase */
			u32 growth_factor_scaled;  				/* cwnd growth factor scaled by 100 (125=1.25×, 300=3.0×) */
			u8 search_draining;  					/* 1 while SEARCH drains toward its target */
		}search;
	};
};

/*
 * Reset all SEARCH state for a fresh slow start: bins, norm history,
 * target, drain counters and flag, growth factor (back to 2x).
 */
static inline void bictcp_search_reset(struct sock *sk)
{
	struct bictcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	memset(ca->search.sent_bin, 0, sizeof(ca->search.sent_bin));
	memset(ca->search.acked_bin, 0, sizeof(ca->search.acked_bin));
	memset(ca->search.norm_hist, 0, sizeof(ca->search.norm_hist));
	memset(ca->search.app_limited_bin, 0, sizeof(ca->search.app_limited_bin));
	ca->search.current_app_limited = 0;

	ca->search.curr_idx = -1;
	ca->search.bin_end_us = 0;
	ca->search.scale_factor = 0;
	ca->search.search_targeted_cwnd = 0;
	ca->search.search_drain_ackedseg = 0;
	ca->search.prior_delivered = tp->delivered;
	ca->search.norm_hist_count = 0;
	ca->search.growth_factor_scaled = 200;
	ca->search.search_growth_accum = 0;
	ca->search.bin_duration_us = 0;
	ca->search.search_draining = 0;
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

static inline bool search_in_drain(const struct bictcp *ca)
{
	return ca->search.search_draining;
}

static inline u32 search_log_growth_factor(const struct bictcp *ca)
{
	return search_growth_policy == SEARCH_GROWTH_SCALING ?
		ca->search.growth_factor_scaled : 200;
}

/* Leave slow start at @ssthresh and reset SEARCH for the next slow start. */
static inline void search_exit_slow_start(struct sock *sk, u32 ssthresh,
					  const char *reason)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);
	const char *stage = search_in_drain(ca) ? "DRAIN" : "SLOW_START";

	if (search_should_log(sk)) {
		pr_info("[SEARCH] [sk: %p] STAGE: %s -> CONGESTION_AVOIDANCE (%s) | cwnd: %u, ssthresh: %u, target_cwnd: %u, inflight: %u, growth_factor: %u.%02u\n",
			sk, stage, reason, tcp_snd_cwnd(tp), ssthresh,
			ca->search.search_targeted_cwnd, tcp_packets_in_flight(tp),
			search_log_growth_factor(ca) / 100,
			search_log_growth_factor(ca) % 100);
	}

	tp->snd_ssthresh = ssthresh;
	bictcp_search_reset(sk);
}

/*
 * Scaled slow start (new in 5.0). Each ACKed packet adds
 * (growth_factor_scaled - 100) / 100 packets to cwnd, so cwnd grows by
 * growth_factor_scaled / 100 per RTT (1.25x .. 3x). Fractions are carried in
 * search_growth_accum. Growth stops at ssthresh; the ACKs not needed to reach
 * it are returned so CUBIC can use them, as tcp_slow_start() does.
 */
static u32 search_scaled_slow_start(struct sock *sk, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);
	u32 step = clamp_t(u32, ca->search.growth_factor_scaled,
			   SEARCH_GROWTH_MIN, SEARCH_GROWTH_MAX) - 100;
	u32 cwnd = tcp_snd_cwnd(tp);
	u32 room, inc, rem, used;
	u64 total;

	if (cwnd >= tp->snd_ssthresh)
		return acked;

	room = tp->snd_ssthresh - cwnd;
	total = ca->search.search_growth_accum + (u64)acked * step;

	/* Compare in 64 bits, so a large total is never truncated */
	if (total >= (u64)room * 100) {
		/* Reaches ssthresh: stop there, leftover ACKs go to CUBIC.
		 * used <= acked here, since acked * step >= room * 100 - accum. */
		used = div_u64((u64)room * 100 - ca->search.search_growth_accum + step - 1, step);
		tcp_snd_cwnd_set(tp, min(cwnd + room, tp->snd_cwnd_clamp));
		ca->search.search_growth_accum = 0;
		return acked - min(used, acked);
	}

	/* total < room * 100, so inc < room and fits in u32 */
	inc = div_u64_rem(total, 100, &rem);
	tcp_snd_cwnd_set(tp, min(cwnd + inc, tp->snd_cwnd_clamp));
	ca->search.search_growth_accum = rem;
	return 0;
}

/* Slow-start growth with SEARCH: normal (2x per RTT) or scaled. */
static u32 search_slow_start(struct sock *sk, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (!acked)
		return 0;

	if (search_growth_policy == SEARCH_GROWTH_SCALING)
		return search_scaled_slow_start(sk, acked);

	return tcp_slow_start(tp, acked);
}

/*
 * SEARCH drain (same rule as 4.1): keep cwnd at inflight plus one packet per
 * SEARCH_DRAIN_ACKEDSEG_THRESH delivered packets, never above the current
 * cwnd and never below the target. When cwnd reaches the target, leave slow
 * start with ssthresh = target.
 */
static void search_drain(struct sock *sk, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);
	u32 target = ca->search.search_targeted_cwnd;
	u32 cwnd = tcp_snd_cwnd(tp);
	u32 inc = 0;

	if (!acked)
		return;

	if (cwnd <= target) {
		search_exit_slow_start(sk, target, "Target met early");
		return;
	}

	ca->search.search_drain_ackedseg += tp->delivered - ca->search.prior_delivered;
	ca->search.prior_delivered = tp->delivered;
	if (ca->search.search_drain_ackedseg >= SEARCH_DRAIN_ACKEDSEG_THRESH) {
		inc = ca->search.search_drain_ackedseg / SEARCH_DRAIN_ACKEDSEG_THRESH;
		ca->search.search_drain_ackedseg %= SEARCH_DRAIN_ACKEDSEG_THRESH;
	}

	cwnd = min(cwnd, max(tcp_packets_in_flight(tp) + inc, target));
	cwnd = min(cwnd, tp->snd_cwnd_clamp);
	tcp_snd_cwnd_set(tp, cwnd);

	if (cwnd <= target) {
		search_exit_slow_start(sk, target, "Drain complete");
	} else if (search_should_log(sk) && inc > 0) {
		pr_info("[SEARCH] [sk: %p] DRAIN ROUND | cwnd: %u, target_cwnd: %u, inflight: %u, growth_factor: %u.%02u\n",
			sk, cwnd, target, tcp_packets_in_flight(tp),
			search_log_growth_factor(ca) / 100,
			search_log_growth_factor(ca) % 100);
	}
}

__bpf_kfunc static void cubictcp_init(struct sock *sk)
{
	struct bictcp *ca = inet_csk_ca(sk);

	bictcp_reset(ca);

	if (slow_start_mode == SS_SEARCH)
		bictcp_search_reset(sk);

	if (slow_start_mode == SS_HYSTART)
		bictcp_hystart_reset(sk);

	if (slow_start_mode != SS_HYSTART && initial_ssthresh)
		tcp_sk(sk)->snd_ssthresh = initial_ssthresh;

	if (slow_start_mode == SS_SEARCH && search_should_log(sk)) {
		pr_info("[SEARCH] [sk: %p] INIT -> SLOW_START | cwnd: %u, ssthresh: %u, mss: %u, exit_thresh: %d (%s), growth_factor: %u.%02u\n",
			sk, tcp_snd_cwnd(tcp_sk(sk)), tcp_sk(sk)->snd_ssthresh,
			tcp_sk(sk)->mss_cache,
			search_thresh_mode == SEARCH_THRESH_DYNAMIC ?
				SEARCH_EARLY_THRESH : search_thresh,
			search_thresh_mode == SEARCH_THRESH_DYNAMIC ?
				"ADAPTIVE" : "FIXED",
			search_log_growth_factor(ca) / 100,
			search_log_growth_factor(ca) % 100);
	}
}

__bpf_kfunc static void cubictcp_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{

	if (event == CA_EVENT_TX_START) {
		struct bictcp *ca = inet_csk_ca(sk);
		u32 now = tcp_jiffies32;
		s32 delta;

		delta = now - tcp_sk(sk)->lsndtime;

		/* We were application limited (idle) for a while.
		 * Shift epoch_start to keep cwnd growth to cubic curve.
		 */
		if (ca->epoch_start && delta > 0) {
			ca->epoch_start += delta;
			if (after(ca->epoch_start, now))
				ca->epoch_start = now;
		}
		return;
	}

	if (event == CA_EVENT_CWND_RESTART) {
		if (slow_start_mode == SS_SEARCH)
			bictcp_search_reset(sk);
		return;
	}
	return;
}

/* calculate the cubic root of x using a table lookup followed by one
 * Newton-Raphson iteration.
 * Avg err ~= 0.195%
 */
static u32 cubic_root(u64 a)
{
	u32 x, b, shift;
	/*
	 * cbrt(x) MSB values for x MSB values in [0..63].
	 * Precomputed then refined by hand - Willy Tarreau
	 *
	 * For x in [0..63],
	 *   v = cbrt(x << 18) - 1
	 *   cbrt(x) = (v[x] + 10) >> 6
	 */
	static const u8 v[] = {
		/* 0x00 */    0,   54,   54,   54,  118,  118,  118,  118,
		/* 0x08 */  123,  129,  134,  138,  143,  147,  151,  156,
		/* 0x10 */  157,  161,  164,  168,  170,  173,  176,  179,
		/* 0x18 */  181,  185,  187,  190,  192,  194,  197,  199,
		/* 0x20 */  200,  202,  204,  206,  209,  211,  213,  215,
		/* 0x28 */  217,  219,  221,  222,  224,  225,  227,  229,
		/* 0x30 */  231,  232,  234,  236,  237,  239,  240,  242,
		/* 0x38 */  244,  245,  246,  248,  250,  251,  252,  254,
	};

	b = fls64(a);
	if (b < 7) {
		/* a in [0..63] */
		return ((u32)v[(u32)a] + 35) >> 6;
	}

	b = ((b * 84) >> 8) - 1;
	shift = (a >> (b * 3));

	x = ((u32)(((u32)v[shift] + 10) << b)) >> 6;

	/*
	 * Newton-Raphson iteration
	 *                         2
	 * x    = ( 2 * x  +  a / x  ) / 3
	 *  k+1          k         k
	 */
	x = (2 * x + (u32)div64_u64(a, (u64)x * (u64)(x - 1)));
	x = ((x * 341) >> 10);
	return x;
}

/*
 * Compute congestion window to use.
 */
static inline void bictcp_update(struct bictcp *ca, u32 cwnd, u32 acked)
{
	u32 delta, bic_target, max_cnt;
	u64 offs, t;

	ca->ack_cnt += acked;	/* count the number of ACKed packets */

	if (ca->last_cwnd == cwnd &&
	    (s32)(tcp_jiffies32 - ca->last_time) <= HZ / 32)
		return;

	/* The CUBIC function can update ca->cnt at most once per jiffy.
	 * On all cwnd reduction events, ca->epoch_start is set to 0,
	 * which will force a recalculation of ca->cnt.
	 */
	if (ca->epoch_start && tcp_jiffies32 == ca->last_time)
		goto tcp_friendliness;

	ca->last_cwnd = cwnd;
	ca->last_time = tcp_jiffies32;

	if (ca->epoch_start == 0) {
		ca->epoch_start = tcp_jiffies32;	/* record beginning */
		ca->ack_cnt = acked;			/* start counting */
		ca->tcp_cwnd = cwnd;			/* syn with cubic */

		if (ca->last_max_cwnd <= cwnd) {
			ca->bic_K = 0;
			ca->bic_origin_point = cwnd;
		} else {
			/* Compute new K based on
			 * (wmax-cwnd) * (srtt>>3 / HZ) / c * 2^(3*bictcp_HZ)
			 */
			ca->bic_K = cubic_root(cube_factor
					       * (ca->last_max_cwnd - cwnd));
			ca->bic_origin_point = ca->last_max_cwnd;
		}
	}

	/* cubic function - calc*/
	/* calculate c * time^3 / rtt,
	 *  while considering overflow in calculation of time^3
	 * (so time^3 is done by using 64 bit)
	 * and without the support of division of 64bit numbers
	 * (so all divisions are done by using 32 bit)
	 *  also NOTE the unit of those veriables
	 *	  time  = (t - K) / 2^bictcp_HZ
	 *	  c = bic_scale >> 10
	 * rtt  = (srtt >> 3) / HZ
	 * !!! The following code does not have overflow problems,
	 * if the cwnd < 1 million packets !!!
	 */

	t = (s32)(tcp_jiffies32 - ca->epoch_start);
	t += usecs_to_jiffies(ca->delay_min);
	/* change the unit from HZ to bictcp_HZ */
	t <<= BICTCP_HZ;
	do_div(t, HZ);

	if (t < ca->bic_K)		/* t - K */
		offs = ca->bic_K - t;
	else
		offs = t - ca->bic_K;

	/* c/rtt * (t-K)^3 */
	delta = (cube_rtt_scale * offs * offs * offs) >> (10+3*BICTCP_HZ);
	if (t < ca->bic_K)                            /* below origin*/
		bic_target = ca->bic_origin_point - delta;
	else                                          /* above origin*/
		bic_target = ca->bic_origin_point + delta;

	/* cubic function - calc bictcp_cnt*/
	if (bic_target > cwnd) {
		ca->cnt = cwnd / (bic_target - cwnd);
	} else {
		ca->cnt = 100 * cwnd;              /* very small increment*/
	}

	/*
	 * The initial growth of cubic function may be too conservative
	 * when the available bandwidth is still unknown.
	 */
	if (ca->last_max_cwnd == 0 && ca->cnt > 20)
		ca->cnt = 20;	/* increase cwnd 5% per RTT */

tcp_friendliness:
	/* TCP Friendly */
	if (tcp_friendliness) {
		u32 scale = beta_scale;

		delta = (cwnd * scale) >> 3;
		while (ca->ack_cnt > delta) {		/* update tcp cwnd */
			ca->ack_cnt -= delta;
			ca->tcp_cwnd++;
		}

		if (ca->tcp_cwnd > cwnd) {	/* if bic is slower than tcp */
			delta = ca->tcp_cwnd - cwnd;
			max_cnt = cwnd / delta;
			if (ca->cnt > max_cnt)
				ca->cnt = max_cnt;
		}
	}

	/* The maximum rate of cwnd increase CUBIC allows is 1 packet per
	 * 2 packets ACKed, meaning cwnd grows at 1.5x per RTT.
	 */
	ca->cnt = max(ca->cnt, 2U);
}

__bpf_kfunc static void cubictcp_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

	if (slow_start_mode == SS_SEARCH) {
		/* Slow start is over (cwnd >= ssthresh): reset any SEARCH state left */
		if (!tcp_in_slow_start(tp) &&
		    (ca->search.curr_idx >= 0 || search_in_drain(ca))) {
			if (search_should_log(sk)) {
				pr_info("[SEARCH] [sk: %p] STAGE: %s -> CONGESTION_AVOIDANCE (ssthresh reached) | cwnd: %u, ssthresh: %u, inflight: %u, growth_factor: %u.%02u\n",
					sk, search_in_drain(ca) ? "DRAIN" : "SLOW_START",
					tcp_snd_cwnd(tp), tp->snd_ssthresh,
					tcp_packets_in_flight(tp),
					search_log_growth_factor(ca) / 100,
					search_log_growth_factor(ca) % 100);
			}
			bictcp_search_reset(sk);
		}

		/* Draining: lower cwnd whether or not the flow is cwnd-limited */
		if (tcp_in_slow_start(tp) && search_in_drain(ca)) {
			search_drain(sk, acked);
			return;
		}
	}

	if (!tcp_is_cwnd_limited(sk))
		return;

	if (tcp_in_slow_start(tp)) {
		if (slow_start_mode == SS_SEARCH)
			acked = search_slow_start(sk, acked);
		else
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
	u32 new_ssthresh;

	ca->epoch_start = 0;	/* end of epoch */

	/* Wmax and fast convergence */
	if (tcp_snd_cwnd(tp) < ca->last_max_cwnd && fast_convergence)
		ca->last_max_cwnd = (tcp_snd_cwnd(tp) * (BICTCP_BETA_SCALE + beta))
			/ (2 * BICTCP_BETA_SCALE);
	else
		ca->last_max_cwnd = tcp_snd_cwnd(tp);
	
	new_ssthresh = max((tcp_snd_cwnd(tp) * beta) / BICTCP_BETA_SCALE, 2U);
	
	return new_ssthresh;
}

__bpf_kfunc static void cubictcp_state(struct sock *sk, u8 new_state)
{
	if (new_state == TCP_CA_Loss) {
		struct tcp_sock *tp = tcp_sk(sk);
		struct bictcp *ca = inet_csk_ca(sk);

		if (slow_start_mode == SS_SEARCH && search_should_log(sk)) {
			const char *stage = search_in_drain(ca) ? "DRAIN" :
				(tcp_in_slow_start(tp) ? "SLOW_START" :
				 "CONGESTION_AVOIDANCE");

			pr_info("[SEARCH] [sk: %p] STAGE: %s -> LOSS (Forced Exit) | Reason: RTO/Timeout | cwnd: %u, ssthresh: %u, inflight: %u, growth_factor: %u.%02u\n",
				sk, stage, tcp_snd_cwnd(tp), tp->snd_ssthresh,
				tcp_packets_in_flight(tp),
				search_log_growth_factor(ca) / 100,
				search_log_growth_factor(ca) % 100);
		}

		bictcp_reset(ca);

		if (slow_start_mode == SS_SEARCH)
			bictcp_search_reset(sk);

		if (slow_start_mode == SS_HYSTART)
			bictcp_hystart_reset(sk);
	}
}


/* Account for TSO/GRO delays.
 * Otherwise short RTT flows could get too small ssthresh, since during
 * slow start we begin with small TSO packets and ca->delay_min would
 * not account for long aggregation delay when TSO packets get bigger.
 * Ideally even with a very small RTT we would like to have at least one
 * TSO packet being sent and received by GRO, and another one in qdisc layer.
 * We apply another 100% factor because @rate is doubled at this point.
 * We cap the cushion to 1ms.
 */
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

	/* hystart triggers when cwnd is larger than some threshold */
	if (tcp_snd_cwnd(tp) < hystart_low_window)
		return;

	if (hystart_detect & HYSTART_ACK_TRAIN) {
		u32 now = bictcp_clock_us(sk);

		/* first detection parameter - ack-train detection */
		if ((s32)(now - ca->hystart.last_ack) <= hystart_ack_delta_us) {
			ca->hystart.last_ack = now;

			threshold = ca->delay_min + hystart_ack_delay(sk);

			/* Hystart ack train triggers if we get ack past
			 * ca->delay_min/2.
			 * Pacing might have delayed packets up to RTT/2
			 * during slow start.
			 */
			if (sk->sk_pacing_status == SK_PACING_NONE)
				threshold >>= 1;

			if ((s32)(now - ca->hystart.round_start) > threshold) {
				ca->hystart.found = 1;
				pr_debug("hystart_ack_train (%u > %u) delay_min %u (+ ack_delay %u) cwnd %u\n",
					 now - ca->hystart.round_start, threshold,
					 ca->delay_min, hystart_ack_delay(sk), tcp_snd_cwnd(tp));
				NET_INC_STATS(sock_net(sk),
					      LINUX_MIB_TCPHYSTARTTRAINDETECT);
				NET_ADD_STATS(sock_net(sk),
					      LINUX_MIB_TCPHYSTARTTRAINCWND,
					      tcp_snd_cwnd(tp));
				tp->snd_ssthresh = tcp_snd_cwnd(tp);			
			}
		}
	}

	if (hystart_detect & HYSTART_DELAY) {
		/* obtain the minimum delay of more than sampling packets */
		if (ca->hystart.curr_rtt > delay)
			ca->hystart.curr_rtt = delay;
		if (ca->hystart.sample_cnt < HYSTART_MIN_SAMPLES) {
			ca->hystart.sample_cnt++;
		} else {
			if (ca->hystart.curr_rtt > ca->delay_min +
			    HYSTART_DELAY_THRESH(ca->delay_min >> 3)) {
				ca->hystart.found = 1;
				NET_INC_STATS(sock_net(sk),
					      LINUX_MIB_TCPHYSTARTDELAYDETECT);
				NET_ADD_STATS(sock_net(sk),
					      LINUX_MIB_TCPHYSTARTDELAYCWND,
					      tcp_snd_cwnd(tp));
				tp->snd_ssthresh = tcp_snd_cwnd(tp);
			}
		}
	}
}

//////////////////////// SEARCH ////////////////////////

/* Scale bin value to fit bin size, rescale previous bins.
 * Return amount scaled.
 */
static inline u8 search_bit_shifting(struct sock *sk, u64 bin_value) 
{

	struct bictcp *ca = inet_csk_ca(sk);
	u8 num_shift = 0; 
	u32 i = 0;


	/* Adjust bin_value if it's greater than MAX_BIN_VALUE */
	while (bin_value > MAX_US_INT) {
		num_shift += 1;
		bin_value >>= 1;  /* divide bin_value by 2 */
	}

	if (num_shift == 0)
    	return 0;

	/* Adjust all previous acked and sent bins according to the new num_shift */
	for (i = 0; i < SEARCH_ACKED_BINS; i++) 
		ca->search.acked_bin[i] >>= num_shift;

	for (i = 0; i < SEARCH_SENT_BINS; i++)
		ca->search.sent_bin[i] >>= num_shift;

	/* Update the scale factor */
	ca->search.scale_factor += num_shift;

	return num_shift;
}

/*
 * Store the running totals of bytes ACKed and sent (divided by
 * 2^scale_factor) and the app-limited flag in bin @idx. If the totals no
 * longer fit in 16 bits, all bins are rescaled first.
 */
static void search_fill_bin(struct sock *sk, s32 idx, u8 app_limited)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);
	u64 acked = tp->bytes_acked >> ca->search.scale_factor;
	u64 sent = tp->bytes_sent >> ca->search.scale_factor;
	u8 shift;

	if (acked > MAX_US_INT || sent > MAX_US_INT) {
		shift = search_bit_shifting(sk, max(acked, sent));
		acked >>= shift;
		sent >>= shift;
	}

	ca->search.acked_bin[idx % SEARCH_ACKED_BINS] = acked;
	ca->search.sent_bin[idx % SEARCH_SENT_BINS] = sent;
	ca->search.app_limited_bin[idx % SEARCH_BINS] = app_limited;
	ca->search.current_app_limited = 0;
}

/*
 * First ACK of a slow start: set the bin length (one window is
 * search_window_duration_factor / 10 x RTT, split into SEARCH_BINS bins)
 * and fill the first bin.
 */
static void search_init_bins(struct sock *sk, u32 now_us, u32 rtt_us, u8 app_limited)
{
	struct bictcp *ca = inet_csk_ca(sk);

	if (ca->search.bin_duration_us == 0)
		ca->search.bin_duration_us = div_u64((u64)rtt_us * search_window_duration_factor,
						       SEARCH_BINS * 10);

	/* RTT sample is too small to form a valid SEARCH bin */
	if (ca->search.bin_duration_us == 0)
		return;

	ca->search.bin_end_us = now_us + ca->search.bin_duration_us;
	ca->search.curr_idx = 0;
	search_fill_bin(sk, 0, app_limited);
}

/*
 * A bin boundary was reached: move to the bin that contains now. Skipped bins
 * (no ACK in them) keep the last totals. If more than a whole window was
 * skipped, the old bins are useless, so start again from this ACK.
 */
static void search_update_bins(struct sock *sk, u32 now_us, u32 rtt_us, u8 app_limited)
{
	struct bictcp *ca = inet_csk_ca(sk);
	u32 passed_bins, i;

	if (ca->search.bin_duration_us == 0) {
		bictcp_search_reset(sk);
		return;
	}

	/* More than one passed bin means some bins were skipped */
	passed_bins = ((now_us - ca->search.bin_end_us) / ca->search.bin_duration_us) + 1;

	if (passed_bins > SEARCH_BINS) {
		bictcp_search_reset(sk);
		search_init_bins(sk, now_us, rtt_us, app_limited);
		return;
	}

	for (i = ca->search.curr_idx + 1; i < ca->search.curr_idx + passed_bins; i++) {
		ca->search.acked_bin[i % SEARCH_ACKED_BINS] = ca->search.acked_bin[ca->search.curr_idx % SEARCH_ACKED_BINS];
		ca->search.sent_bin[i % SEARCH_SENT_BINS] = ca->search.sent_bin[ca->search.curr_idx % SEARCH_SENT_BINS];
		ca->search.app_limited_bin[i % SEARCH_BINS] = ca->search.app_limited_bin[ca->search.curr_idx % SEARCH_BINS];
	}

	ca->search.bin_end_us += passed_bins * ca->search.bin_duration_us;
	ca->search.curr_idx += passed_bins;
	search_fill_bin(sk, ca->search.curr_idx, app_limited);
}

/* Count app-limited intervals in the delivered-data comparison window. */
static inline u32 search_count_app_limited_bins(struct sock *sk)
{
	struct bictcp *ca = inet_csk_ca(sk);
	u32 count = 0;
	s32 i;

	for (i = ca->search.curr_idx - SEARCH_BINS + 1;
	     i <= ca->search.curr_idx; i++) {
		if (ca->search.app_limited_bin[i % SEARCH_BINS])
			count++;
	}
	return count;
}

/* Calculate delivered bytes for a window*/
static inline u64 search_compute_delivered_window(struct sock *sk, s32 left, s32 right)
{
	struct bictcp *ca = inet_csk_ca(sk);
	u64 delivered = 0;

	delivered = ca->search.acked_bin[right % SEARCH_ACKED_BINS] - ca->search.acked_bin[left % SEARCH_ACKED_BINS];

	return delivered;
}

/* Calculate sent bytes for a window considering interpolation */
static inline u64 search_compute_sent_window(struct sock *sk, s32 left, s32 right, u32 fraction)
{
	struct bictcp *ca = inet_csk_ca(sk);
	u64 sent = 0;

	sent = ca->search.sent_bin[(right - 1) % SEARCH_SENT_BINS] - ca->search.sent_bin[left % SEARCH_SENT_BINS];
	
	if (left == 0) /* If we are interpolating using the very first bin, the "previous" bin value is 0. */
		sent += (ca->search.sent_bin[left % SEARCH_SENT_BINS]) * fraction / 100;
	else
		sent += (ca->search.sent_bin[left % SEARCH_SENT_BINS] - ca->search.sent_bin[(left - 1) % SEARCH_SENT_BINS]) * fraction / 100;

	sent += (ca->search.sent_bin[right % SEARCH_SENT_BINS] - ca->search.sent_bin[(right - 1) % SEARCH_SENT_BINS]) * (100 - fraction) / 100;

	return sent;
}

/*
 * SEARCH: Compute target congestion window for CWND rollback.
 *
 * Estimates the target CWND based on delivered bytes from a past RTT window
 * (BDP approximation) and prepares SEARCH to drain excess in-flight data.
 */
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

	if (!ca->search.bin_duration_us || search_window_duration_factor <= 0) {
		bictcp_search_reset(sk);
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

	/* Apply 1.25x margin to the estimated BDP */
	target_pkts = div_u64(target_pkts * SEARCH_DRAIN_FACTOR, 100);

	ca->search.search_targeted_cwnd = max((u32)target_pkts, (u32)TCP_INIT_CWND);

	return true;
}

static inline void search_push_norm(struct sock *sk, s16 norm)
{
    struct bictcp *ca = inet_csk_ca(sk);

    ca->search.norm_hist[ca->search.norm_hist_count % SEARCH_NORM_HISTORY_MAX] = norm;
    ca->search.norm_hist_count++;

    /* Keep count in [6, 11] once full: no u8 wrap, and count % 6 stays continuous */
    if (ca->search.norm_hist_count >= 2 * SEARCH_NORM_HISTORY_MAX)
        ca->search.norm_hist_count -= SEARCH_NORM_HISTORY_MAX;
}

/*
 * Adaptive exit threshold (new in 5.0), from the norms seen before this one.
 * SEARCH exits when the norm is a clear signal above the noise of the recent
 * norms (signal-to-noise ratio) and not too small:
 *     norm / std(last 6 norms) >= 2.5   and   norm >= SEARCH_THRESH_MIN
 * Written without a division (std may be 0), this is norm >= threshold with
 *     threshold = clamp(2.5 * std, SEARCH_THRESH_MIN, SEARCH_THRESH_MAX).
 * Fewer than SEARCH_NORM_HISTORY_MAX samples: SEARCH_EARLY_THRESH.
 */
static inline u16 search_compute_dyn_thresh(struct sock *sk)
{
	struct bictcp *ca = inet_csk_ca(sk);
	s64 sum = 0, var_sum = 0;
	s32 mean, std;
	s16 thr;
	int i;

	if (ca->search.norm_hist_count < SEARCH_NORM_HISTORY_MAX)
		return SEARCH_EARLY_THRESH;

	/* History is full here */
	for (i = 0; i < SEARCH_NORM_HISTORY_MAX; i++)
		sum += ca->search.norm_hist[i];

	mean = div_s64(sum, SEARCH_NORM_HISTORY_MAX);

	for (i = 0; i < SEARCH_NORM_HISTORY_MAX; i++) {
		s64 d = ca->search.norm_hist[i] - mean;
		var_sum += d * d;
	}

	std = int_sqrt(div_u64((u64)var_sum, SEARCH_NORM_HISTORY_MAX - 1));

	/* norm / std >= 2.5  <=>  norm >= 2.5 * std */
	thr = (SEARCH_SNR_MIN * std) / 10;

	return clamp_t(s16, thr, SEARCH_THRESH_MIN, SEARCH_THRESH_MAX);
}

/*
 * Scaled growth factor (new in 5.0), x100, from how far the norm has come
 * toward the exit threshold, p = norm / threshold, clamped to 0..1:
 *   p = 0     (no sign of a queue):  3x     (SEARCH_GROWTH_MAX)
 *   p = 0.2  (knee):                1.25x     (SEARCH_GROWTH_KNEE)
 *   p = 1     (at the threshold):    1.25x  (SEARCH_GROWTH_MIN)
 * and linear between these points (flat after the knee, since the knee
 * value equals the minimum). A negative norm counts as p = 0.
 */
static inline u32 search_compute_growth_factor(s16 norm, u16 thresh)
{
	s32 p = clamp_t(s32, (s32)norm * 100 / max_t(s32, thresh, 1), 0, 100);

	if (p <= SEARCH_GROWTH_KNEE_P)
		return SEARCH_GROWTH_MAX -
		       (SEARCH_GROWTH_MAX - SEARCH_GROWTH_KNEE) * p / SEARCH_GROWTH_KNEE_P;

	return SEARCH_GROWTH_KNEE -
	       (SEARCH_GROWTH_KNEE - SEARCH_GROWTH_MIN) * (p - SEARCH_GROWTH_KNEE_P) /
	       (100 - SEARCH_GROWTH_KNEE_P);
}

/*
 * Record this ACK in the bins. Returns true when a bin boundary was crossed
 * and the windows can be evaluated.
 */
static bool search_advance_bins(struct sock *sk, u32 rtt_us)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);
	u32 now_us = bictcp_clock_us(sk);

	/* Mark the current bin if any ACK in it is app-limited. */
	if (tp->rate_app_limited)
		ca->search.current_app_limited = 1;

	/* First ACK: set the bin duration and fill the first bin. */
	if (ca->search.curr_idx < 0) {
		search_init_bins(sk, now_us, rtt_us, ca->search.current_app_limited);
		return false;
	}

	if (now_us < ca->search.bin_end_us)
		return false;

	/* Reached or passed the bin boundary: update the bins. */
	search_update_bins(sk, now_us, rtt_us, ca->search.current_app_limited);

	if (ca->search.bin_duration_us == 0) {
		bictcp_search_reset(sk);
		return false;
	}
	return true;
}

/* One SEARCH sample: delivered now vs. sent one RTT earlier. */
struct search_sample {
	u64 curr_delv;	/* delivered in the current window (scaled bytes) */
	u64 prev_sent;	/* sent in the window one RTT earlier (scaled bytes) */
	s16 norm;	/* (prev_sent - curr_delv) * 100 / prev_sent */
};

/* Fill @s. Returns false while there is not enough bin history yet. */
static bool search_compute_norm(struct sock *sk, u32 rtt_us, struct search_sample *s)
{
	struct bictcp *ca = inet_csk_ca(sk);
	s32 prev_idx;
	u32 fraction;
	s64 diff_bytes;

	/* Need a full window, shifted back by one RTT, inside the sent-bin history. */
	prev_idx = ca->search.curr_idx - (rtt_us / ca->search.bin_duration_us);
	if (!(prev_idx >= SEARCH_BINS &&
	      (ca->search.curr_idx - prev_idx) < SEARCH_EXTRA_SENT_BINS - 1))
		return false;

	s->curr_delv = search_compute_delivered_window(sk,
						       ca->search.curr_idx - SEARCH_BINS,
						       ca->search.curr_idx);

	fraction = ((rtt_us % ca->search.bin_duration_us) * 100 / ca->search.bin_duration_us);

	s->prev_sent = search_compute_sent_window(sk,
						  prev_idx - SEARCH_BINS,
						  prev_idx,
						  fraction);
	if (s->prev_sent == 0)
		return false;

	diff_bytes = (s64)s->prev_sent - (s64)s->curr_delv;
	s->norm = (s16)(diff_bytes * 100 / (s64)s->prev_sent);
	return true;
}

/*
 * Exit threshold for this sample. In adaptive mode the threshold comes from
 * the previous samples, then this norm is added to the history.
 */
static u16 search_exit_thresh(struct sock *sk, s16 norm)
{
	u16 thresh = 0;

	if (search_thresh_mode == SEARCH_THRESH_FIXED) {
		thresh = search_thresh;
	} else if (search_thresh_mode == SEARCH_THRESH_DYNAMIC) {
		thresh = search_compute_dyn_thresh(sk);
		search_push_norm(sk, norm);
	}
	return thresh;
}

/*
 * The norm reached the threshold. Do not act on it when too many bins in the
 * window were app-limited (4.1 protection): a low delivery rate there may come
 * from the application, not from the network.
 */
static bool search_exit_allowed(struct sock *sk)
{
	int app_thresh;

	app_thresh = clamp(search_app_limited_bin_thresh, 0, SEARCH_BINS);
	if (app_thresh && search_count_app_limited_bins(sk) >= app_thresh)
		return false;

	return true;
}

/*
 * Congestion found (same as 4.1): exit slow start now, or start draining
 * toward 1.25 x the BDP estimated one RTT ago.
 */
static void search_exit_or_drain(struct sock *sk, s16 norm, u16 thresh)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

	if (!search_enable_drain) {
		search_exit_slow_start(sk, tcp_snd_cwnd(tp), "Drain disabled");
		return;
	}

	/* No valid estimate yet: keep measuring. */
	if (!search_compute_target_cwnd(sk))
		return;

	/* Nothing to drain (cwnd or inflight already at the target): exit now. */
	if (ca->search.search_targeted_cwnd >= tcp_snd_cwnd(tp) ||
	    tcp_packets_in_flight(tp) <= ca->search.search_targeted_cwnd) {
		search_exit_slow_start(sk, tcp_snd_cwnd(tp),
			ca->search.search_targeted_cwnd >= tcp_snd_cwnd(tp) ?
				"target >= cwnd" : "inflight <= target");
		return;
	}

	/* Excess data in flight: drain it (see search_drain()). */
	ca->search.search_draining = 1;
	ca->search.prior_delivered = tp->delivered;
	ca->search.search_drain_ackedseg = 0;
	if (search_should_log(sk)) {
		pr_info("[SEARCH] [sk: %p] STAGE: SLOW_START -> DRAIN | Reason: norm_diff (%d%%) >= exit_thresh (%d%%, %s) | cwnd: %u, target_cwnd: %u, inflight: %u, growth_factor: %u.%02u\n",
			sk, norm, (int)thresh,
			search_thresh_mode == SEARCH_THRESH_DYNAMIC ?
				"ADAPTIVE" : "FIXED",
			tcp_snd_cwnd(tp), ca->search.search_targeted_cwnd,
			tcp_packets_in_flight(tp),
			search_log_growth_factor(ca) / 100,
			search_log_growth_factor(ca) % 100);
	}
}

/**
 * search_update - SEARCH per-ACK update: measure, set growth, and decide exit
 * @sk: the socket
 * @rtt_us: RTT sample of this ACK, in microseconds
 *
 * Called from cubictcp_acked() only in slow start (cwnd < ssthresh), only in
 * the Open or Disorder state (not in CWR, Recovery or Loss), and not while
 * draining (cubictcp_cong_avoid() runs the drain).
 *
 * Measuring:
 * - Keeps 10 time bins covering one window (3.5 x the first RTT by default)
 *   with the running totals of bytes sent and bytes ACKed, plus a flag if any
 *   ACK in the bin was app-limited.
 * - When a bin ends, compares the bytes delivered in the last window with the
 *   bytes sent in the window one RTT earlier:
 *       norm = (sent - delivered) * 100 / sent
 * - Exit threshold: search_thresh (fixed mode), or in dynamic mode
 *   SEARCH_EARLY_THRESH until 6 norms are collected, then the norm must reach
 *   norm / std(last 6 norms) >= 2.5 and norm >= SEARCH_THRESH_MIN, i.e.
 *   threshold = clamp(2.5 x std, SEARCH_THRESH_MIN, SEARCH_THRESH_MAX).
 * - Scaled growth (search_growth_policy = 1): sets the growth factor from
 *   p = clamp(norm / threshold, 0, 1): 3x at p = 0, 1.25x from p = 0.2
 *   up to p = 1, linear in between.
 *
 * Exit decision, when norm >= threshold and too few bins were app-limited:
 * - Drain enabled: computes the target cwnd = 1.25 x the bytes delivered in
 *   the last RTT (BDP estimate; if there is not enough history yet, keeps
 *   measuring). If both cwnd and inflight are above the target, starts the
 *   drain; otherwise exits slow start now with ssthresh = cwnd.
 * - Drain disabled: exits slow start now with ssthresh = cwnd.
 *
 * Every exit resets SEARCH, so the next slow start starts fresh.
 */
static void search_update(struct sock *sk, u32 rtt_us)
{
	struct bictcp *ca = inet_csk_ca(sk);
	struct search_sample s;
	u16 thresh;

	if (unlikely(search_window_duration_factor <= 0)) {
		bictcp_search_reset(sk);
		return;
	}

	if (!search_advance_bins(sk, rtt_us))		/* first ACK, or bin not finished */
		return;

	if (!search_compute_norm(sk, rtt_us, &s))	/* not enough history yet */
		return;

	/* New feature 1: fixed or adaptive exit threshold. */
	thresh = search_exit_thresh(sk, s.norm);

	/* New feature 2: growth factor from p = norm / threshold. */
	if (search_growth_policy == SEARCH_GROWTH_SCALING)
		ca->search.growth_factor_scaled =
			search_compute_growth_factor(s.norm, thresh);

	if (search_should_log(sk)) {
		pr_info("[SEARCH] [sk: %p] ROUND EVAL | stage: SLOW_START, cwnd: %u, mss: %u, rtt: %u us, prev_sent: %llu, curr_delv: %llu, norm_diff: %d%%, exit_thresh: %d%% (%s), growth_factor: %u.%02u\n",
			sk, tcp_snd_cwnd(tcp_sk(sk)), tcp_sk(sk)->mss_cache,
			rtt_us, s.prev_sent, s.curr_delv, s.norm, (int)thresh,
			search_thresh_mode == SEARCH_THRESH_DYNAMIC ?
				"ADAPTIVE" : "FIXED",
			search_log_growth_factor(ca) / 100,
			search_log_growth_factor(ca) % 100);
	}

	/* Congestion signal: exit slow start or start the drain. */
	if (s.prev_sent >= s.curr_delv && s.norm >= thresh &&
	    search_exit_allowed(sk))
		search_exit_or_drain(sk, s.norm, thresh);
}

//////////////////////////////////////////////////////////////
__bpf_kfunc static void cubictcp_acked(struct sock *sk, const struct ack_sample *sample)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);
	u32 delay;

	/* Some calls are for duplicates without timestamps */
	if (sample->rtt_us < 0)
		return;

	/* Discard delay samples right after fast recovery */
	if (ca->epoch_start && (s32)(tcp_jiffies32 - ca->epoch_start) < HZ)
		return;

	delay = sample->rtt_us;
	if (delay == 0)
		delay = 1;

	/* first time call or link delay decreases */
	if (ca->delay_min == 0 || ca->delay_min > delay)
		ca->delay_min = delay;

	if (slow_start_mode == SS_SEARCH && search_should_log(sk)) {
		const char *stage_str = "UNKNOWN";
		const char *thresh_mode =
			search_thresh_mode == SEARCH_THRESH_DYNAMIC ?
				"ADAPTIVE" : "FIXED";
		u16 exit_thresh =
			search_thresh_mode == SEARCH_THRESH_DYNAMIC ?
				search_compute_dyn_thresh(sk) : search_thresh;
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
			if (search_in_drain(ca))
				stage_str = "DRAIN";
			else
				stage_str = "SLOW_START";
		} else {
			stage_str = "CONGESTION_AVOIDANCE";
		}

		pr_info("[SEARCH] [sk: %p] ACK | stage: %s, cwnd: %u, rtt: %u us, inflight: %u, exit_thresh: %d%% (%s), growth_factor: %u.%02u\n",
			sk, stage_str, tcp_snd_cwnd(tp), delay,
			tcp_packets_in_flight(tp), (int)exit_thresh, thresh_mode,
			search_log_growth_factor(ca) / 100,
			search_log_growth_factor(ca) % 100);
	}

	if (tcp_in_slow_start(tp)) {
		if (slow_start_mode == SS_SEARCH) {
			/* SEARCH runs only in Open/Disorder: not in CWR, Recovery or Loss.
			 * In Drain, cubictcp_cong_avoid() lowers cwnd, so nothing to do here. */
			if (inet_csk(sk)->icsk_ca_state <= TCP_CA_Disorder &&
			    !search_in_drain(ca))
				search_update(sk, delay);
		} else if (slow_start_mode == SS_HYSTART && !ca->hystart.found)
			hystart_update(sk, delay);
	}
}

static struct tcp_congestion_ops cubictcp __read_mostly = {
	.init		= cubictcp_init,
	.ssthresh	= cubictcp_recalc_ssthresh,
	.cong_avoid	= cubictcp_cong_avoid,
	.set_state	= cubictcp_state,
	.undo_cwnd	= tcp_reno_undo_cwnd,
	.cwnd_event	= cubictcp_cwnd_event,
	.pkts_acked     = cubictcp_acked,
	.owner		= THIS_MODULE,
	.name		= "cubic_search",
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

	/* Precompute a bunch of the scaling factors that are used per-packet
	 * based on SRTT of 100ms
	 */

	beta_scale = 8*(BICTCP_BETA_SCALE+beta) / 3
		/ (BICTCP_BETA_SCALE - beta);

	cube_rtt_scale = (bic_scale * 10);	/* 1024*c/rtt */

	/* calculate the "K" for (wmax-cwnd) = c/rtt * K^3
	 *  so K = cubic_root( (wmax-cwnd)*rtt/c )
	 * the unit of K is bictcp_HZ=2^10, not HZ
	 *
	 *  c = bic_scale >> 10
	 *  rtt = 100ms
	 *
	 * the following code has been designed and tested for
	 * cwnd < 1 million packets
	 * RTT < 100 seconds
	 * HZ < 1,000,00  (corresponding to 10 nano-second)
	 */

	/* 1/c * 2^2*bictcp_HZ * srtt */
	cube_factor = 1ull << (10+3*BICTCP_HZ); /* 2^40 */

	/* divide by bic_scale and by constant Srtt (100ms) */
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