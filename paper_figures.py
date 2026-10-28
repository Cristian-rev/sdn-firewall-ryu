"""Figuras del manuscrito (PNG 300 dpi) a partir de results/*.csv."""
import glob
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

import config as C  # noqa: E402

OUT = os.path.join(C.RESULTS_DIR, "analysis")
# paleta categorica validada (orden fijo): azul, naranja, aqua, amarillo
CAT = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e4e3df"

plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 8, "axes.edgecolor": INK2,
    "axes.labelcolor": INK, "xtick.color": INK2, "ytick.color": INK2,
    "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True,
    "grid.color": GRID, "grid.linewidth": 0.6, "axes.axisbelow": True,
    "legend.frameon": False, "savefig.dpi": 300, "savefig.bbox": "tight"})


def load(prefix):
    fs = sorted(glob.glob(os.path.join(C.RESULTS_DIR, f"{prefix}*.csv")))
    return pd.concat([pd.read_csv(f) for f in fs], ignore_index=True) if fs else None


def box(ax, groups, labels, color):
    bp = ax.boxplot(groups, widths=0.55, patch_artist=True, showfliers=True,
                    medianprops={"color": INK, "linewidth": 1.2},
                    flierprops={"marker": "o", "markersize": 2.5, "markerfacecolor": color,
                                "markeredgewidth": 0, "alpha": 0.6},
                    whiskerprops={"color": INK2, "linewidth": 0.8},
                    capprops={"color": INK2, "linewidth": 0.8})
    for b in bp["boxes"]:
        b.set_facecolor(color)
        b.set_alpha(0.85)
        b.set_edgecolor(INK2)
        b.set_linewidth(0.6)
    ax.set_xticks(range(1, len(labels) + 1), labels)


def fig_e1():
    e1 = load("e1_enforcement")
    if e1 is None:
        return
    hosts = sorted(e1.hosts.unique())
    fig, axes = plt.subplots(1, 2, figsize=(7, 2.6), sharey=False)
    for ax, metric, title in ((axes[0], "t_flow_ms", "(a) Order sent → rules in flow table"),
                              (axes[1], "t_dp_ms", "(b) Order sent → effect on traffic")):
        pos, data, cols = [], [], []
        for i, h in enumerate(hosts):
            for j, act in enumerate(("block", "unblock")):
                x = pd.to_numeric(e1[(e1.hosts == h) & (e1.action == act)][metric],
                                  errors="coerce").dropna()
                pos.append(i * 3 + j + 1)
                data.append(x)
                cols.append(CAT[j])
        bp = ax.boxplot(data, positions=pos, widths=0.8, patch_artist=True,
                        medianprops={"color": INK, "linewidth": 1.1},
                        flierprops={"marker": "o", "markersize": 2, "markeredgewidth": 0},
                        whiskerprops={"color": INK2, "linewidth": 0.7},
                        capprops={"color": INK2, "linewidth": 0.7})
        for b, c in zip(bp["boxes"], cols):
            b.set_facecolor(c)
            b.set_edgecolor(INK2)
            b.set_linewidth(0.5)
        ax.set_xticks([i * 3 + 1.5 for i in range(len(hosts))], [str(h) for h in hosts])
        ax.set_xlabel("Hosts in topology")
        ax.set_ylabel("ms")
        ax.set_title(title, fontsize=8, loc="left", color=INK)
    handles = [plt.Rectangle((0, 0), 1, 1, fc=CAT[0], ec=INK2, lw=0.5),
               plt.Rectangle((0, 0), 1, 1, fc=CAT[1], ec=INK2, lw=0.5)]
    fig.legend(handles, ["Block", "Unblock"], loc="upper center", ncol=2,
               bbox_to_anchor=(0.5, 1.06))
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "paper_fig_e1.png"))
    plt.close(fig)


E2_ORDER = [("baseline", "Learning switch\n(simple_switch_13)"), ("firewall_empty", "Firewall\n(empty)"),
            ("firewall_rules", "Firewall\n(100 rules)"), ("firewall_mirror", "Firewall\n(copy to ctrl.)")]


def fig_e2():
    e2 = load("e2_overhead_")
    if e2 is None:
        return
    present = [(k, l) for k, l in E2_ORDER if k in set(e2.scenario)]
    fig, axes = plt.subplots(1, 2, figsize=(7.4, 2.8))
    for ax, metric, ylab, title in ((axes[0], "tcp_mbps", "Mbit/s", "(a) TCP throughput"),
                                    (axes[1], "rtt_avg_ms", "ms", "(b) Mean RTT")):
        groups = [pd.to_numeric(e2[e2.scenario == k][metric], errors="coerce").dropna()
                  for k, _ in present]
        box(ax, groups, [l for _, l in present], CAT[0])
        ax.tick_params(axis="x", labelsize=6.5)
        ax.set_ylabel(ylab)
        ax.set_title(title, fontsize=8, loc="left", color=INK)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "paper_fig_e2.png"))
    plt.close(fig)


def fig_e3():
    e3 = load("e3_scalability")
    e3b = load("e3b_poll_cost")
    if e3 is None:
        return
    fig, axes = plt.subplots(1, 2, figsize=(7, 2.7))
    rules = sorted(e3.rules.unique())
    for i, h in enumerate(sorted(e3.hosts.unique())):
        med = e3[e3.hosts == h].groupby("rules").t_flow_ms.median()
        axes[0].plot(med.index, med.values, color=CAT[i % 4], lw=2, marker="o", ms=4,
                     label=f"{h} hosts")
    if e3b is not None:
        med = e3b.groupby("rules").dump_ms.median()
        axes[1].plot(med.index, med.values, color=CAT[0], lw=2, marker="o", ms=4,
                     label="One flow-table query")
        base = e3.groupby("rules").t_flow_ms.median()
        axes[1].plot(base.index, base.values - base.values[0], color=CAT[1], lw=2,
                     marker="o", ms=4, label="Increase in median t_flow")
        axes[1].legend(loc="upper left", fontsize=7)
    for ax, ylab, title in ((axes[0], "Median t_flow (ms)", "(a) Enforcement latency"),
                            (axes[1], "ms", "(b) Measurement cost vs latency increase")):
        ax.set_xscale("log")
        ax.set_xticks(rules, [str(r) for r in rules])
        ax.minorticks_off()
        ax.set_xlabel("Installed blocked addresses")
        ax.set_ylabel(ylab)
        ax.set_title(title, fontsize=8, loc="left", color=INK)
        ax.set_ylim(bottom=0)
    axes[0].legend(loc="lower right", fontsize=7, ncol=2)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "paper_fig_e3.png"))
    plt.close(fig)


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    fig_e1()
    fig_e2()
    fig_e3()
    print("figuras en", OUT)
