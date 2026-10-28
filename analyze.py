"""Analisis estadistico y figuras para el manuscrito.

Lee los CSV de results/ y genera en results/analysis/:
  - summary_<exp>.csv  : n, media, DE, mediana, P95 e IC95 % (bootstrap) por condicion
  - tests.txt          : pruebas no parametricas (Mann-Whitney U, Kruskal-Wallis)
  - fig_*.png          : diagramas de caja listos para el articulo (300 dpi)

    python3 analyze.py
"""
import glob
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from scipy import stats  # noqa: E402

import config as C  # noqa: E402

OUT = os.path.join(C.RESULTS_DIR, "analysis")
RNG = np.random.default_rng(42)


def load(prefix):
    files = sorted(glob.glob(os.path.join(C.RESULTS_DIR, f"{prefix}*.csv")))
    if not files:
        return None
    return pd.concat([pd.read_csv(f) for f in files], ignore_index=True)


def boot_ci(x, n=5000, alpha=0.05):
    x = np.asarray(pd.to_numeric(x, errors="coerce").dropna(), dtype=float)
    if len(x) < 2:
        return (np.nan, np.nan)
    means = RNG.choice(x, size=(n, len(x)), replace=True).mean(axis=1)
    return tuple(np.quantile(means, [alpha / 2, 1 - alpha / 2]))


def holm(pvals):
    """Correccion de Holm-Bonferroni (ignora p NaN)."""
    p = np.array(pvals, dtype=float)
    out = np.full_like(p, np.nan)
    idx = [i for i in np.argsort(p) if not np.isnan(p[i])]
    m, running = len(idx), 0.0
    for rank, i in enumerate(idx):
        running = max(running, min(1.0, (m - rank) * p[i]))
        out[i] = running
    return out


def summarize(df, by, cols):
    rows = []
    for key, g in df.groupby(by):
        key = key if isinstance(key, tuple) else (key,)
        for c in cols:
            x = pd.to_numeric(g[c], errors="coerce").dropna()
            lo, hi = boot_ci(x)
            rows.append({**dict(zip(by, key)), "metric": c, "n": len(x),
                         "mean": x.mean(), "sd": x.std(ddof=1), "median": x.median(),
                         "p95": x.quantile(0.95) if len(x) else np.nan,
                         "ci95_low": lo, "ci95_high": hi})
    return pd.DataFrame(rows)


def boxplot(df, by, col, title, ylabel, fname):
    groups = [(str(k), pd.to_numeric(g[col], errors="coerce").dropna())
              for k, g in df.groupby(by)]
    if not groups:
        return
    fig, ax = plt.subplots(figsize=(6, 3.6))
    ax.boxplot([g for _, g in groups], showfliers=True)
    ax.set_xticks(range(1, len(groups) + 1), [k for k, _ in groups])
    ax.set_title(title, fontsize=10)
    ax.set_ylabel(ylabel)
    ax.set_xlabel(by if isinstance(by, str) else ", ".join(by))
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, fname), dpi=300)
    plt.close(fig)


def main():
    os.makedirs(OUT, exist_ok=True)
    tests = []

    e1 = load("e1_enforcement")
    if e1 is not None:
        summarize(e1, ["hosts", "action"], ["t_api_ms", "t_flow_ms", "t_dp_ms"]).to_csv(
            os.path.join(OUT, "summary_e1.csv"), index=False)
        if "t_dp_below_probe" in e1:
            (e1[e1.action == "block"].groupby("hosts").t_dp_below_probe.mean()
             .rename("share_block_effect_below_10ms").to_csv(
                 os.path.join(OUT, "summary_e1_probe.csv")))
        samples = [pd.to_numeric(g["t_flow_ms"], errors="coerce").dropna()
                   for _, g in e1[e1.action == "block"].groupby("hosts")]
        if len(samples) > 1:
            h = stats.kruskal(*samples)
            tests.append(f"E1 t_flow_ms (bloqueo) por numero de hosts: Kruskal-Wallis "
                         f"H={h.statistic:.2f}, p={h.pvalue:.4g}")
        boxplot(e1, ["action", "hosts"], "t_flow_ms",
                "Time until the flow table reflects the order", "ms", "fig_e1_flow.png")

    e2 = load("e2_overhead_")
    if e2 is not None:
        cols = ["rtt_avg_ms", "loss_pct", "tcp_mbps", "udp_jitter_ms", "udp_loss_pct"]
        summarize(e2, ["scenario"], cols).to_csv(
            os.path.join(OUT, "summary_e2.csv"), index=False)
        pairs = [("baseline", "firewall_empty"), ("firewall_empty", "firewall_rules"),
                 ("firewall_empty", "firewall_mirror")]
        for c in cols:
            res = []
            for a_, b_ in pairs:
                a = pd.to_numeric(e2[e2.scenario == a_][c], errors="coerce").dropna()
                b = pd.to_numeric(e2[e2.scenario == b_][c], errors="coerce").dropna()
                if len(a) > 1 and len(b) > 1 and (a.nunique() > 1 or b.nunique() > 1):
                    u = stats.mannwhitneyu(a, b, alternative="two-sided")
                    rbc = 1 - 2 * u.statistic / (len(a) * len(b))
                    res.append((f"{a_} vs {b_}", u.statistic, u.pvalue, rbc))
            for (lab, U_, pv, rbc), padj in zip(res, holm([r[2] for r in res])):
                tests.append(f"E2 {c} {lab}: U={U_:.1f}, p={pv:.4g}, p_Holm={padj:.4g}, "
                             f"rank-biserial={rbc:.3f}")
        boxplot(e2, "scenario", "rtt_avg_ms", "Mean RTT of permitted traffic", "ms",
                "fig_e2_rtt.png")
        boxplot(e2, "scenario", "tcp_mbps", "TCP throughput of permitted traffic",
                "Mbit/s", "fig_e2_tcp.png")

    e3 = load("e3_scalability")
    if e3 is not None:
        summarize(e3, ["hosts", "rules"],
                  ["t_api_block_ms", "t_flow_ms", "t_get_rules_ms",
                   "flow_table_size", "ryu_cpu_ms_per_cycle", "ryu_mem_mb"]).to_csv(
            os.path.join(OUT, "summary_e3.csv"), index=False)
        samples = [pd.to_numeric(g["t_flow_ms"], errors="coerce").dropna()
                   for _, g in e3.groupby("rules")]
        if len(samples) > 1:
            h = stats.kruskal(*samples)
            tests.append(f"E3 t_flow_ms por numero de reglas: Kruskal-Wallis "
                         f"H={h.statistic:.2f}, p={h.pvalue:.4g}")
        boxplot(e3, "rules", "t_flow_ms", "Enforcement latency vs installed rules",
                "ms", "fig_e3_rules.png")

    e3b = load("e3b_poll_cost")
    if e3b is not None:
        summarize(e3b, ["rules", "flow_table_size"], ["dump_ms"]).to_csv(
            os.path.join(OUT, "summary_e3b.csv"), index=False)

    e4 = load("e4_access_control")
    if e4 is not None:
        acc = e4.groupby(["credential", "status"]).size().reset_index(name="count")
        acc.to_csv(os.path.join(OUT, "summary_e4_access.csv"), index=False)
    e4o = pd.concat([d for d in (load("e4_overhead_auth"), load("e4_overhead_noauth"))
                     if d is not None], ignore_index=True) if glob.glob(
        os.path.join(C.RESULTS_DIR, "e4_overhead_*.csv")) else None
    if e4o is not None:
        summarize(e4o, ["mode"], ["latency_ms"]).to_csv(
            os.path.join(OUT, "summary_e4_overhead.csv"), index=False)
        if set(e4o["mode"]) == {"auth", "noauth"}:
            u = stats.mannwhitneyu(e4o[e4o["mode"] == "auth"].latency_ms,
                                   e4o[e4o["mode"] == "noauth"].latency_ms)
            tests.append(f"E4 latencia auth vs noauth: U={u.statistic:.1f}, "
                         f"p={u.pvalue:.4g}")

    e5 = load("e5_detection_")
    if e5 is not None:
        rows = []
        e5["rate_pps"] = e5["rate_pps"].fillna("")
        for (sc, rate), g in e5.groupby(["scenario", "rate_pps"]):
            t = pd.to_numeric(g.t_detect_ms, errors="coerce").dropna()
            attack = sc in ("dos", "portscan")
            rows.append({"scenario": sc, "rate_pps": rate, "trials": len(g),
                         "detection_rate": g.attacker_blocked.mean() if attack else np.nan,
                         "client_blocked_rate": g.client_blocked.mean(),
                         "victim_blocked_rate": g.victim_blocked.mean(),
                         "t_detect_median_ms": t.median(), "t_detect_p95_ms": t.quantile(.95)
                         if len(t) else np.nan, "t_detect_mean_ms": t.mean(),
                         "t_detect_sd_ms": t.std(ddof=1)})
        pd.DataFrame(rows).to_csv(os.path.join(OUT, "summary_e5.csv"), index=False)

    e6 = load("e6_persistence")
    if e6 is not None:
        summarize(e6, ["rules"], ["t_restore_ms", "missing_after_restore", "kept_while_down", "restored_all"]).to_csv(
            os.path.join(OUT, "summary_e6.csv"), index=False)

    with open(os.path.join(OUT, "tests.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(tests) or "Sin pruebas: faltan datos.")
    print("Analisis guardado en", OUT)
    print("\n".join(tests))


if __name__ == "__main__":
    main()
