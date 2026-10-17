"""Shared visual components for the Streamlit security dashboard."""

from html import escape

import streamlit as st


def inject_dashboard_styles():
    """Apply the dashboard's shared theme and responsive layout styles."""
    st.markdown(
        """
        <style>
        :root {
            --cb-bg: #080810;
            --cb-panel: #10101c;
            --cb-card: #151522;
            --cb-border: #30243d;
            --cb-text: #f5f3ff;
            --cb-muted: #a09aaf;
            --cb-purple: #a855f7;
            --cb-pink: #ff3cac;
            --cb-red: #ff3355;
            --cb-green: #39ff88;
        }

        html, body, [class*="css"], [data-testid="stAppViewContainer"] {
            font-family: 'Segoe UI', 'Aptos', sans-serif;
        }
        .stApp {
            color: var(--cb-text);
            background:
                radial-gradient(ellipse at 70% -10%, rgba(168,85,247,.13), transparent 36%),
                radial-gradient(ellipse at 0% 45%, rgba(255,60,172,.05), transparent 28%),
                var(--cb-bg);
        }
        [data-testid="stAppViewContainer"] > .main .block-container {
            max-width: 1500px;
            padding: 2.2rem 3.2rem 4rem;
        }
        [data-testid="stSidebar"] {
            background: linear-gradient(180deg, #10101c 0%, #0b0b14 100%);
            border-right: 1px solid var(--cb-border);
        }
        [data-testid="stSidebar"] > div:first-child { padding-top: 1.4rem; }
        [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p {
            color: var(--cb-muted);
        }
        [data-testid="stSidebar"] [data-testid="stRadio"] label {
            color: #d9d3e8;
            font-weight: 600;
        }
        [data-testid="stSidebar"] [data-testid="stRadio"] [role="radiogroup"] {
            gap: .2rem;
        }
        h1, h2, h3, h4 { color: var(--cb-text); letter-spacing: -.035em; }
        h1 { font-weight: 800 !important; }
        h2, h3 { font-weight: 700 !important; }
        p, li, [data-testid="stCaptionContainer"] { color: #c4bfd0; }
        [data-testid="stCaptionContainer"] { color: var(--cb-muted); }
        [data-testid="stMetric"] {
            background: transparent;
        }
        [data-testid="stExpander"] {
            border: 1px solid var(--cb-border);
            border-radius: 14px;
            background: rgba(21,21,34,.72);
        }
        [data-testid="stExpander"] summary:hover { color: var(--cb-pink); }
        [data-testid="stAlert"] { border-radius: 12px; }
        [data-testid="stDownloadButton"] button,
        [data-testid="stButton"] button {
            border: 1px solid rgba(168,85,247,.55);
            border-radius: 10px;
            color: var(--cb-text);
            background: linear-gradient(115deg, rgba(168,85,247,.24), rgba(255,60,172,.13));
            transition: transform .18s ease, border-color .18s ease, box-shadow .18s ease;
        }
        [data-testid="stDownloadButton"] button:hover,
        [data-testid="stButton"] button:hover {
            border-color: var(--cb-pink);
            box-shadow: 0 0 22px rgba(255,60,172,.18);
            transform: translateY(-1px);
        }
        [data-testid="stCode"] {
            border: 1px solid var(--cb-border);
            border-radius: 12px;
        }
        .cb-brand {
            padding: 1.15rem 1rem 1rem;
            margin: 0 0 1.5rem;
            border: 1px solid rgba(168,85,247,.25);
            border-radius: 16px;
            background: linear-gradient(145deg, rgba(168,85,247,.12), rgba(255,60,172,.04));
        }
        .cb-brand-mark {
            display: flex;
            align-items: center;
            gap: .7rem;
            color: var(--cb-text);
            font-size: 1rem;
            font-weight: 800;
            letter-spacing: .08em;
        }
        .cb-brand-glyph {
            display: grid;
            width: 34px;
            height: 34px;
            place-items: center;
            border-radius: 10px;
            color: white;
            background: linear-gradient(135deg, var(--cb-purple), var(--cb-pink));
            box-shadow: 0 0 20px rgba(168,85,247,.3);
        }
        .cb-micro {
            color: var(--cb-muted);
            font: 500 .67rem Consolas, monospace;
            letter-spacing: .17em;
            text-transform: uppercase;
        }
        .cb-hero {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 1.5rem;
            padding: 1.1rem 0 2rem;
        }
        .cb-hero h1 {
            margin: .4rem 0 .2rem;
            font-size: clamp(2rem, 4vw, 3.25rem);
            letter-spacing: .015em;
        }
        .cb-hero h1 span { color: var(--cb-pink); }
        .cb-hero-subtitle {
            color: var(--cb-muted);
            font: 500 .76rem Consolas, monospace;
            letter-spacing: .16em;
        }
        .cb-local-badge {
            flex: 0 0 auto;
            padding: .62rem .8rem;
            border: 1px solid rgba(57,255,136,.35);
            border-radius: 999px;
            color: var(--cb-green);
            background: rgba(57,255,136,.06);
            font: 500 .67rem Consolas, monospace;
            letter-spacing: .1em;
            white-space: nowrap;
        }
        .cb-local-dot {
            display: inline-block;
            width: 7px;
            height: 7px;
            margin-right: .5rem;
            border-radius: 50%;
            background: var(--cb-green);
            box-shadow: 0 0 10px rgba(57,255,136,.7);
        }
        .cb-metric {
            position: relative;
            height: 100%;
            min-height: 142px;
            padding: 1.15rem 1.2rem;
            overflow: hidden;
            border: 1px solid var(--cb-border);
            border-radius: 16px;
            background: linear-gradient(145deg, rgba(21,21,34,.96), rgba(16,16,28,.94));
            transition: border-color .2s ease, transform .2s ease, box-shadow .2s ease;
        }
        .cb-metric:hover {
            transform: translateY(-2px);
            border-color: rgba(168,85,247,.68);
            box-shadow: 0 12px 34px rgba(0,0,0,.2), 0 0 24px rgba(168,85,247,.08);
        }
        .cb-metric::after {
            position: absolute;
            right: -28px;
            bottom: -44px;
            width: 105px;
            height: 105px;
            border-radius: 50%;
            background: var(--metric-glow, rgba(168,85,247,.2));
            content: '';
            filter: blur(34px);
            opacity: .65;
        }
        .cb-metric-label { color: var(--cb-muted); font-size: .76rem; font-weight: 700; letter-spacing: .1em; text-transform: uppercase; }
        .cb-metric-value { margin: .45rem 0 .1rem; color: var(--cb-text); font-size: 2.25rem; font-weight: 800; line-height: 1.1; }
        .cb-metric-detail { color: var(--cb-muted); font-size: .77rem; }
        .cb-panel {
            padding: 1.15rem 1.25rem;
            border: 1px solid var(--cb-border);
            border-radius: 16px;
            background: rgba(21,21,34,.72);
        }
        .cb-status {
            padding: 1.3rem 1.45rem;
            border: 1px solid var(--status-border);
            border-radius: 16px;
            background: linear-gradient(115deg, var(--status-bg), rgba(21,21,34,.84) 76%);
        }
        .cb-status-title { margin: .35rem 0; color: var(--status-color); font-size: 1.15rem; font-weight: 800; }
        .cb-status-copy { color: #c4bfd0; font-size: .9rem; }
        .cb-section-kicker { margin-bottom: .35rem; color: var(--cb-purple); font: 500 .68rem Consolas, monospace; letter-spacing: .17em; text-transform: uppercase; }
        .cb-finding {
            margin: .55rem 0;
            padding: 1rem 1.1rem;
            border: 1px solid var(--finding-border);
            border-left: 3px solid var(--finding-accent);
            border-radius: 12px;
            background: linear-gradient(105deg, var(--finding-wash), rgba(21,21,34,.88) 38%);
        }
        .cb-finding-heading { display: flex; align-items: center; justify-content: space-between; gap: 1rem; }
        .cb-finding-title { color: var(--cb-text); font-size: .98rem; font-weight: 800; }
        .cb-finding-badge, .cb-pill {
            display: inline-block;
            padding: .26rem .55rem;
            border: 1px solid var(--finding-border);
            border-radius: 999px;
            color: var(--finding-accent);
            font: 500 .62rem Consolas, monospace;
            letter-spacing: .09em;
            text-transform: uppercase;
            white-space: nowrap;
        }
        .cb-finding-rule { margin: .5rem 0 .2rem; color: var(--finding-accent); font: 500 .69rem Consolas, monospace; letter-spacing: .1em; text-transform: uppercase; }
        .cb-finding-copy { color: #c4bfd0; font-size: .86rem; }
        .cb-finding-action { margin-top: .45rem; color: var(--cb-text); font-size: .83rem; }
        .cb-path {
            margin: .55rem 0;
            padding: 1rem 1.1rem;
            border: 1px solid rgba(255,51,85,.29);
            border-radius: 13px;
            background: linear-gradient(110deg, rgba(255,51,85,.07), rgba(21,21,34,.9) 56%);
        }
        .cb-path-top { display: flex; justify-content: space-between; align-items: center; gap: .8rem; }
        .cb-path-title { color: var(--cb-text); font-weight: 800; }
        .cb-score { color: var(--cb-red); font: 500 .73rem Consolas, monospace; white-space: nowrap; }
        .cb-score-track { height: 5px; margin: .7rem 0; overflow: hidden; border-radius: 5px; background: rgba(255,255,255,.09); }
        .cb-score-fill { height: 100%; border-radius: inherit; background: linear-gradient(90deg, var(--cb-purple), var(--cb-pink), var(--cb-red)); }
        .cb-route { color: #e8e2f4; font: 500 .77rem Consolas, monospace; line-height: 1.9; overflow-wrap: anywhere; }
        .cb-route-arrow { color: var(--cb-red); padding: 0 .22rem; }
        .cb-empty {
            padding: 1.2rem 1.3rem;
            border: 1px dashed rgba(57,255,136,.32);
            border-radius: 14px;
            color: #c4bfd0;
            background: rgba(57,255,136,.035);
        }
        .cb-code {
            color: #e1d9ef;
            font: 500 .82rem Consolas, monospace;
        }
        @media (max-width: 760px) {
            [data-testid="stAppViewContainer"] > .main .block-container { padding: 1rem 1rem 3rem; }
            .cb-hero { align-items: flex-start; flex-direction: column; padding-bottom: 1.3rem; }
            .cb-hero h1 { font-size: 2rem; }
            .cb-metric { min-height: 125px; padding: .9rem; }
            .cb-metric-value { font-size: 1.8rem; }
        }
        @media (prefers-reduced-motion: reduce) {
            *, *::before, *::after { scroll-behavior: auto !important; transition-duration: .01ms !important; }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_metric_card(label, value, detail, accent="#A855F7"):
    st.markdown(
        f"""
        <div class="cb-metric" style="--metric-glow:{escape(accent)};">
            <div class="cb-metric-label">{escape(str(label))}</div>
            <div class="cb-metric-value">{escape(str(value))}</div>
            <div class="cb-metric-detail">{escape(str(detail))}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_status_card(reachable, protected_asset, entry_point):
    if reachable:
        color = "#FF3355"
        border = "rgba(255,51,85,.42)"
        background = "rgba(255,51,85,.10)"
        status = "EXPOSED THROUGH DISCOVERED PATHS"
        copy = "At least one enumerated route reaches the protected asset."
    else:
        color = "#39FF88"
        border = "rgba(57,255,136,.36)"
        background = "rgba(57,255,136,.07)"
        status = "NO DISCOVERED ROUTE"
        copy = "No path was found from the configured entry point."
    st.markdown(
        f"""
        <div class="cb-status" style="--status-color:{color};--status-border:{border};--status-bg:{background};">
            <div class="cb-micro">Protected asset exposure</div>
            <div class="cb-status-title">{status}</div>
            <div class="cb-status-copy">
                <span class="cb-code">{escape(str(protected_asset))}</span>
                &nbsp; · &nbsp; entry <span class="cb-code">{escape(str(entry_point))}</span>
                &nbsp; · &nbsp; {copy}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_finding_card(finding):
    high_severity = str(finding["severity"]).upper() == "HIGH"
    accent = "#FF3355" if high_severity else "#A855F7"
    border = "rgba(255,51,85,.34)" if high_severity else "rgba(168,85,247,.3)"
    wash = "rgba(255,51,85,.055)" if high_severity else "rgba(168,85,247,.05)"
    st.markdown(
        f"""
        <div class="cb-finding" style="--finding-accent:{accent};--finding-border:{border};--finding-wash:{wash};">
            <div class="cb-finding-heading">
                <div class="cb-finding-title">{escape(str(finding["resource_name"]))}</div>
                <span class="cb-finding-badge">{escape(str(finding["severity"]))}</span>
            </div>
            <div class="cb-finding-rule">{escape(str(finding["rule"]))}</div>
            <div class="cb-finding-copy">{escape(str(finding["message"]))}</div>
            <div class="cb-finding-action"><strong>Recommended action</strong> · {escape(str(finding["recommendation"]))}</div>
            <div class="cb-micro" style="margin-top:.65rem;">Resource ID · {escape(str(finding["resource_id"]))}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_attack_path_card(item, number):
    score = max(0, min(100, int(item["risk_score"])))
    route = "".join(
        f'<span>{escape(str(resource))}</span>'
        + ('<span class="cb-route-arrow">→</span>' if index < len(item["path"]) - 1 else "")
        for index, resource in enumerate(item["path"])
    )
    st.markdown(
        f"""
        <div class="cb-path">
            <div class="cb-path-top">
                <div class="cb-path-title">PATH {number:02d} · EXPOSED ROUTE</div>
                <div class="cb-score">ILLUSTRATIVE SCORE &nbsp; {score}<span style="color:#a09aaf;"> / 100</span></div>
            </div>
            <div class="cb-score-track"><div class="cb-score-fill" style="width:{score}%;"></div></div>
            <div class="cb-route">{route}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
