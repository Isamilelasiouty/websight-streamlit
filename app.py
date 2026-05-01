"""
WebSight Analyzer — by Ismail El Asiouty
Streamlit version — runs free on Streamlit Cloud
"""

import asyncio
import streamlit as st
from analyzer import WebsiteAnalyzer

# ── Page Config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="WebSight Analyzer",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ── Custom CSS ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;900&display=swap');

html, body, [class*="css"] {
    font-family: 'Cairo', sans-serif !important;
    direction: rtl;
}

/* Hide Streamlit default elements */
#MainMenu, footer, header { visibility: hidden; }
.block-container { padding-top: 2rem; padding-bottom: 2rem; max-width: 900px; }

/* ── Hero ── */
.hero {
    text-align: center;
    padding: 2.5rem 1rem 1.5rem;
    background: linear-gradient(135deg, #1a0533 0%, #0d1133 50%, #001a33 100%);
    border-radius: 20px;
    margin-bottom: 2rem;
    border: 1px solid #2a2a3d;
    position: relative;
    overflow: hidden;
}
.hero::before {
    content: '';
    position: absolute;
    top: -60%; right: -20%;
    width: 400px; height: 400px;
    background: radial-gradient(circle, rgba(99,102,241,0.2) 0%, transparent 70%);
    pointer-events: none;
}
.hero h1 {
    font-size: 2.4rem;
    font-weight: 900;
    background: linear-gradient(135deg, #818cf8, #c084fc);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    margin-bottom: 0.5rem;
}
.hero p { color: #94a3b8; font-size: 1rem; margin: 0; }

/* ── Score Card ── */
.score-card {
    background: linear-gradient(135deg, #12121a, #1a1a28);
    border: 1px solid #2a2a3d;
    border-radius: 16px;
    padding: 1.5rem;
    text-align: center;
    margin-bottom: 1rem;
}
.score-num {
    font-size: 4rem;
    font-weight: 900;
    line-height: 1;
}
.grade { font-size: 1.2rem; font-weight: 700; margin-top: 0.3rem; }

/* ── Stat Cards ── */
.stat-row {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 0.8rem;
    margin-bottom: 1.5rem;
}
.stat-box {
    background: #12121a;
    border: 1px solid #2a2a3d;
    border-radius: 12px;
    padding: 1rem;
    text-align: center;
}
.stat-box .val { font-size: 1.8rem; font-weight: 900; }
.stat-box .lbl { font-size: 0.72rem; color: #64748b; margin-top: 0.2rem; }

/* ── Issue Cards ── */
.issue-critical {
    background: rgba(239,68,68,0.05);
    border: 1px solid rgba(239,68,68,0.3);
    border-right: 4px solid #ef4444;
    border-radius: 12px;
    padding: 1.2rem;
    margin-bottom: 0.8rem;
    direction: rtl;
}
.issue-warning {
    background: rgba(245,158,11,0.05);
    border: 1px solid rgba(245,158,11,0.3);
    border-right: 4px solid #f59e0b;
    border-radius: 12px;
    padding: 1.2rem;
    margin-bottom: 0.8rem;
    direction: rtl;
}
.issue-title { font-size: 1rem; font-weight: 700; margin-bottom: 0.4rem; }
.issue-desc { color: #94a3b8; font-size: 0.85rem; line-height: 1.7; margin-bottom: 0.5rem; }
.issue-fix {
    background: rgba(99,102,241,0.1);
    border: 1px solid rgba(99,102,241,0.2);
    border-radius: 8px;
    padding: 0.5rem 0.8rem;
    font-size: 0.82rem;
    color: #c4b5fd;
}
.issue-extra { color: #cbd5e1; font-size: 0.82rem; font-weight: 600; margin-bottom: 0.5rem; }

/* ── Section Title ── */
.sec-title {
    font-size: 1.1rem;
    font-weight: 700;
    color: #e2e8f0;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid #2a2a3d;
    margin-bottom: 1rem;
    direction: rtl;
}

/* ── Security Table ── */
.sec-row-ok { color: #86efac; }
.sec-row-fail { color: #fca5a5; }

/* ── Footer ── */
.footer {
    text-align: center;
    color: #475569;
    font-size: 0.78rem;
    padding: 1.5rem 0 0;
    direction: rtl;
}
.footer a { color: #818cf8; text-decoration: none; }
</style>
""", unsafe_allow_html=True)


# ── Helpers ────────────────────────────────────────────────────────────────────
GRADE_COLORS = {"A": "#22c55e", "B": "#84cc16", "C": "#f59e0b", "D": "#f97316", "F": "#ef4444"}
SEV_ICONS = {"critical": "🔴", "warning": "🟡", "info": "🔵"}
SEV_LABELS = {"critical": "خطير", "warning": "تحذير", "info": "معلومة"}


def run_analysis(url: str):
    async def _run():
        analyzer = WebsiteAnalyzer(url)
        return await analyzer.run()
    return asyncio.run(_run())


def render_score(results):
    score = results["summary"]["score"]
    grade = results["summary"]["grade"]
    color = GRADE_COLORS.get(grade, "#ef4444")
    st.markdown(f"""
    <div class="score-card">
        <div class="score-num" style="color:{color}">{score}</div>
        <div class="grade" style="color:{color}">درجة {grade} — من 100</div>
        <div style="color:#64748b;font-size:0.8rem;margin-top:0.4rem">
            🌐 {results['url']}
        </div>
    </div>
    """, unsafe_allow_html=True)

    perf = results["summary"]
    load_color = "#22c55e" if perf["load_time"] < 3 else "#f59e0b" if perf["load_time"] < 8 else "#ef4444"
    req_color = "#22c55e" if perf["total_requests"] < 50 else "#f59e0b" if perf["total_requests"] < 80 else "#ef4444"
    issues_color = "#22c55e" if perf["total_issues"] == 0 else "#f59e0b" if perf["total_issues"] < 5 else "#ef4444"

    st.markdown(f"""
    <div class="stat-row">
        <div class="stat-box">
            <div class="val" style="color:{load_color}">{perf['load_time']}s</div>
            <div class="lbl">⏱️ وقت التحميل</div>
        </div>
        <div class="stat-box">
            <div class="val" style="color:{req_color}">{perf['total_requests']}</div>
            <div class="lbl">📡 عدد الـ Requests</div>
        </div>
        <div class="stat-box">
            <div class="val" style="color:{issues_color}">{perf['total_issues']}</div>
            <div class="lbl">⚠️ مشاكل مكتشفة</div>
        </div>
    </div>
    """, unsafe_allow_html=True)


def render_issues(results):
    issues = sorted(results["issues"], key=lambda x: ["critical", "warning", "info"].index(x["severity"]))
    if not issues:
        st.success("✅ ممتاز! لم يتم اكتشاف أي مشاكل")
        return

    for issue in issues:
        sev = issue["severity"]
        extra_html = f'<div class="issue-extra">📊 {issue["extra"]}</div>' if issue.get("extra") else ""
        st.markdown(f"""
        <div class="issue-{sev}">
            <div class="issue-title">{SEV_ICONS[sev]} {issue['title']}
                <span style="font-size:0.7rem;padding:0.2rem 0.5rem;border-radius:20px;
                background:{'#ef4444' if sev=='critical' else '#f59e0b'};color:white;
                font-weight:700;margin-right:0.5rem">{SEV_LABELS[sev]}</span>
            </div>
            <div class="issue-desc">{issue['description']}</div>
            {extra_html}
            <div class="issue-fix">💡 <strong>الحل:</strong> {issue['fix']}</div>
        </div>
        """, unsafe_allow_html=True)


def render_security(results):
    sec = results.get("security", {})
    checks = [
        ("Content-Security-Policy", sec.get("csp", {})),
        ("Strict-Transport-Security", sec.get("hsts", {})),
        ("Referrer-Policy", sec.get("referrer_policy", {})),
        ("Permissions-Policy", sec.get("permissions_policy", {})),
        ("X-Frame-Options", sec.get("x_frame_options", {})),
        ("X-Content-Type-Options", sec.get("x_content_type", {})),
    ]
    rows = ""
    for name, data in checks:
        present = data.get("present", False)
        value = str(data.get("value", "—"))[:60]
        icon = "✅" if present else "❌"
        css = "sec-row-ok" if present else "sec-row-fail"
        rows += f'<tr class="{css}"><td>{icon}</td><td><code>{name}</code></td><td style="color:#94a3b8;font-size:0.8rem">{value}</td></tr>'

    st.markdown(f"""
    <table style="width:100%;border-collapse:collapse;font-size:0.85rem;direction:rtl">
      <tr style="color:#64748b;border-bottom:2px solid #2a2a3d">
        <th style="padding:0.5rem;text-align:right">الحالة</th>
        <th style="padding:0.5rem;text-align:right">الهيدر</th>
        <th style="padding:0.5rem;text-align:right">القيمة</th>
      </tr>
      {rows}
    </table>
    """, unsafe_allow_html=True)


def render_resources(results):
    col1, col2 = st.columns(2)

    with col1:
        st.markdown('<div class="sec-title">🐌 أبطأ الملفات</div>', unsafe_allow_html=True)
        for r in results.get("resources", {}).get("slowest", [])[:8]:
            name = r["url"].split("?")[0].split("/")[-1] or r["url"][:30]
            ms = r["duration_ms"]
            color = "#ef4444" if ms > 3000 else "#f59e0b" if ms > 1000 else "#22c55e"
            bar = min(100, ms / 50)
            st.markdown(f"""
            <div style="margin-bottom:0.6rem;direction:ltr">
              <div style="font-size:0.75rem;color:#c4b5fd;margin-bottom:0.2rem;
                overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{name[:40]}</div>
              <div style="display:flex;align-items:center;gap:0.5rem">
                <div style="flex:1;height:5px;background:#1a1a28;border-radius:3px">
                  <div style="width:{bar}%;height:100%;background:{color};border-radius:3px"></div>
                </div>
                <span style="font-size:0.72rem;color:#64748b;white-space:nowrap">{ms}ms</span>
              </div>
            </div>
            """, unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="sec-title">📏 أكبر الملفات</div>', unsafe_allow_html=True)
        largest = results.get("resources", {}).get("largest", [])
        max_size = max((r["size_bytes"] for r in largest), default=1)
        for r in largest[:8]:
            name = r["url"].split("?")[0].split("/")[-1] or r["url"][:30]
            bar = min(100, (r["size_bytes"] / max_size) * 100)
            color = "#ef4444" if r["size_bytes"] > 500*1024 else "#f59e0b" if r["size_bytes"] > 100*1024 else "#22c55e"
            st.markdown(f"""
            <div style="margin-bottom:0.6rem;direction:ltr">
              <div style="font-size:0.75rem;color:#c4b5fd;margin-bottom:0.2rem;
                overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{name[:40]}</div>
              <div style="display:flex;align-items:center;gap:0.5rem">
                <div style="flex:1;height:5px;background:#1a1a28;border-radius:3px">
                  <div style="width:{bar}%;height:100%;background:{color};border-radius:3px"></div>
                </div>
                <span style="font-size:0.72rem;color:#64748b;white-space:nowrap">{r['size']}</span>
              </div>
            </div>
            """, unsafe_allow_html=True)


def render_perf_details(results):
    perf = results["performance"]
    js = perf.get("js_stats", {})
    css = perf.get("css_stats", {})

    cols = st.columns(4)
    items = [
        ("⚡ JS الكلي", js.get("total_size", "—"), "#f59e0b"),
        ("📁 ملفات JS", js.get("file_count", 0), "#f59e0b"),
        ("🎨 CSS الكلي", css.get("total_size", "—"), "#6366f1"),
        ("🖼️ الصور", perf.get("total_images", 0), "#22c55e"),
    ]
    for col, (label, val, color) in zip(cols, items):
        col.markdown(f"""
        <div class="stat-box">
            <div class="val" style="color:{color};font-size:1.3rem">{val}</div>
            <div class="lbl">{label}</div>
        </div>
        """, unsafe_allow_html=True)


# ── Main App ───────────────────────────────────────────────────────────────────
def main():
    # Hero
    st.markdown("""
    <div class="hero">
        <div style="font-size:3rem;margin-bottom:0.5rem;filter:drop-shadow(0 0 20px rgba(99,102,241,0.5))">🔍</div>
        <h1>WebSight Analyzer</h1>
        <p>حلل أي موقع في ثوانٍ — أداء، أمان، وسيو</p>
    </div>
    """, unsafe_allow_html=True)

    # Input
    col1, col2 = st.columns([4, 1])
    with col1:
        url = st.text_input(
            "",
            placeholder="https://example.com",
            label_visibility="collapsed"
        )
    with col2:
        analyze = st.button("🚀 حلل", use_container_width=True, type="primary")

    # Run Analysis
    if analyze and url:
        url = url.strip()
        if not url.startswith("http"):
            url = "https://" + url

        with st.spinner("⏳ جاري التحليل... قد يستغرق 30-60 ثانية"):
            try:
                results = run_analysis(url)
                st.session_state["results"] = results
            except Exception as e:
                st.error(f"⚠️ خطأ أثناء التحليل: {e}")
                st.stop()

    # Show Results
    if "results" in st.session_state:
        results = st.session_state["results"]

        st.markdown("---")

        # Score
        render_score(results)

        # Tabs
        tab1, tab2, tab3, tab4 = st.tabs([
            "⚠️ المشاكل المكتشفة",
            "🔒 Security Headers",
            "📊 تفاصيل الأداء",
            "📡 الملفات والموارد"
        ])

        with tab1:
            st.markdown('<div class="sec-title">⚠️ المشاكل المكتشفة</div>', unsafe_allow_html=True)
            render_issues(results)

        with tab2:
            st.markdown('<div class="sec-title">🔒 Security Headers</div>', unsafe_allow_html=True)
            render_security(results)

        with tab3:
            render_perf_details(results)
            perf = results["performance"]
            metrics = perf.get("metrics", {})
            if metrics:
                st.markdown('<div class="sec-title" style="margin-top:1rem">⚡ Core Web Vitals</div>', unsafe_allow_html=True)
                m_cols = st.columns(3)
                m_cols[0].metric("First Contentful Paint", f"{metrics.get('firstContentfulPaint', 0)}s")
                m_cols[1].metric("DOM Content Loaded", f"{metrics.get('domContentLoaded', 0)}s")
                m_cols[2].metric("DOM Elements", metrics.get("domElements", 0))

            canonical = perf.get("has_canonical")
            st.markdown(f"""
            <div style="margin-top:1rem;padding:0.8rem;background:#12121a;border:1px solid #2a2a3d;
            border-radius:10px;direction:rtl;font-size:0.85rem">
                {'✅' if canonical else '❌'} Canonical Tag:
                <code style="color:#818cf8">{perf.get('canonical_url') or 'غير موجود'}</code>
            </div>
            """, unsafe_allow_html=True)

        with tab4:
            render_resources(results)

        # By Type
        by_type = results["performance"].get("by_type", {})
        if by_type:
            st.markdown('<div class="sec-title" style="margin-top:1rem">📦 الموارد حسب النوع</div>', unsafe_allow_html=True)
            type_icons = {"script": "⚡", "stylesheet": "🎨", "image": "🖼️", "font": "🔤",
                          "fetch": "📡", "xhr": "📡", "document": "📄", "other": "📦"}
            type_data = [
                {"النوع": f"{type_icons.get(k, '📦')} {k}", "العدد": v["count"], "الحجم": v["size"]}
                for k, v in sorted(by_type.items(), key=lambda x: x[1]["size_bytes"], reverse=True)
            ]
            st.dataframe(type_data, use_container_width=True, hide_index=True)

    # Footer
    st.markdown("""
    <div class="footer">
        صُنع بواسطة <a href="https://www.linkedin.com/in/ismail-el-asiouty" target="_blank">Ismail El Asiouty</a>
    </div>
    """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
