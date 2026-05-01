"""
WebSite Performance & Security Analyzer
========================================
Analyzes any website for:
- Performance issues (slow requests, large files, too many requests)
- Security headers (CSP, HSTS, Referrer-Policy, Permissions-Policy)
- Font Awesome usage & optimization
- JavaScript bloat
- Image optimization
- Cache-Control per resource type
- Duplicate content (srsltid and tracking params)
- Core Web Vitals estimation
"""

import asyncio
import json
import sys
import time
import argparse
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, parse_qs

import requests
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright


# ─── Severity Levels ──────────────────────────────────────────────────────────
CRITICAL = "critical"
WARNING  = "warning"
INFO     = "info"
OK       = "ok"


# ─── Issue Registry ───────────────────────────────────────────────────────────
ISSUE_DETAILS = {
    "no_csp": {
        "title": "Content-Security-Policy غير موجود",
        "severity": CRITICAL,
        "description": "موقعك مكشوف لهجمات XSS — هكر يقدر يحقن كود JavaScript خبيث يسرق بيانات اليوزرين أو يحولهم لمواقع أخرى.",
        "fix": "أضف CSP Header عن طريق Cloudflare Transform Rules أو السيرفر مباشرة."
    },
    "no_hsts": {
        "title": "Strict-Transport-Security غير موجود",
        "severity": CRITICAL,
        "description": "موقعك مكشوف لهجمات SSL Stripping — هكر في نفس الشبكة يقدر يحول HTTPS لـ HTTP ويشوف كل البيانات.",
        "fix": "أضف: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    },
    "no_referrer_policy": {
        "title": "Referrer-Policy غير موجود",
        "severity": WARNING,
        "description": "بيانات اليوزرين (URLs الداخلية الحساسة) بتتبعت للمواقع الخارجية، وبيانات Analytics بتبقى غلط.",
        "fix": "أضف: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "no_permissions_policy": {
        "title": "Permissions-Policy غير موجود",
        "severity": WARNING,
        "description": "سكريبتات خارجية (إعلانات، ويدجتس) تقدر تطلب الكاميرا والمايك والـ GPS بدون إذن منك.",
        "fix": "أضف: Permissions-Policy: camera=(), microphone=(), geolocation=()"
    },
    "no_xframe": {
        "title": "X-Frame-Options غير موجود",
        "severity": WARNING,
        "description": "موقعك مكشوف لـ Clickjacking — هكر يقدر يعمل iframe لموقعك ويخلي اليوزر يضغط على أزرار من غير ما يعرف.",
        "fix": "أضف: X-Frame-Options: SAMEORIGIN"
    },
    "no_xcontent": {
        "title": "X-Content-Type-Options غير موجود",
        "severity": WARNING,
        "description": "المتصفح ممكن يفسر ملفات بشكل غلط ويشغل كود خبيث.",
        "fix": "أضف: X-Content-Type-Options: nosniff"
    },
    "high_requests": {
        "title": "عدد كبير جداً من الـ Requests",
        "severity": CRITICAL,
        "description": "كل request إضافي بيضيف وقت تحميل وبيرهق السيرفر والمتصفح، بيأثر مباشرة على Core Web Vitals والسيو.",
        "fix": "دمج ملفات CSS/JS، تفعيل Lazy Loading، تقليل Font Awesome."
    },
    "slow_load": {
        "title": "وقت التحميل بطيء جداً",
        "severity": CRITICAL,
        "description": "Google بتعاقب المواقع البطيئة في الـ Ranking مباشرة، والـ Bounce Rate بيرتفع لأن اليوزر بيمشي قبل ما الصفحة تتحمل.",
        "fix": "تفعيل LiteSpeed Cache، ضغط الصور، تقليل Render-blocking resources."
    },
    "font_awesome": {
        "title": "Font Awesome بيحمل بالطريقة القديمة",
        "severity": CRITICAL,
        "description": "بيتحمل 2000+ أيقونة حتى لو بتستخدم 10 بس، بيضيف +300KB وعدة requests غير ضرورية.",
        "fix": "استخدم Font Awesome Kit الرسمي أو SVG مباشرة للأيقونات اللي محتاجها بس."
    },
    "large_js": {
        "title": "ملفات JavaScript كبيرة جداً",
        "severity": CRITICAL,
        "description": "JS الكبير بيحجب عرض الصفحة (Render Blocking)، بيأخر LCP وFID اللي هم Core Web Vitals المهمة لـ Google.",
        "fix": "Code Splitting، Tree Shaking، تحميل JS بـ async/defer."
    },
    "large_css": {
        "title": "ملفات CSS كبيرة جداً",
        "severity": WARNING,
        "description": "CSS الكبير بيحجب عرض الصفحة ويأخر First Contentful Paint.",
        "fix": "Minify CSS، إزالة CSS غير المستخدم (PurgeCSS)، تحميل بـ media queries."
    },
    "no_lazy_images": {
        "title": "صور بدون Lazy Loading",
        "severity": WARNING,
        "description": "كل الصور بتتحمل في نفس الوقت حتى اللي مش ظاهرة، بيبطئ التحميل ويهدر bandwidth.",
        "fix": "أضف loading='lazy' لكل صورة مش في الـ viewport الأول."
    },
    "arabic_filenames": {
        "title": "أسماء ملفات بالعربي",
        "severity": WARNING,
        "description": "Google مش بتفهم محتوى الصورة من اسمها العربي المشفر، بيضعف Image SEO وبيطول الـ URLs.",
        "fix": "اعمل rename للصور بأسماء إنجليزية وصفية قبل الرفع."
    },
    "srsltid_param": {
        "title": "بارامتر srsltid في الـ URL",
        "severity": CRITICAL,
        "description": "Google شايفة نسختين من نفس الصفحة = Duplicate Content، بيشتت الـ Ranking Power ويضعف الـ SEO.",
        "fix": "تأكد من وجود Canonical Tags، أضف srsltid لـ URL Parameters في Google Search Console."
    },
    "no_cache_html": {
        "title": "صفحات HTML بدون Cache-Control صح",
        "severity": WARNING,
        "description": "الصفحات بتتحمل من السيرفر كل مرة بدون استفادة من الـ Cache، بيبطئ التحميل ويزود الضغط على السيرفر.",
        "fix": "أضف Cache-Control: no-cache للـ HTML و max-age=31536000 للـ assets."
    },
    "no_webp": {
        "title": "صور بتنسيقات قديمة (JPG/PNG)",
        "severity": WARNING,
        "description": "صيغة WebP أصغر بـ 25-34% من JPG وبـ 26% من PNG بنفس الجودة، الفرق في السرعة واضح.",
        "fix": "حوّل الصور لـ WebP باستخدام LiteSpeed Cache أو Cloudflare Image Optimization."
    },
    "render_blocking": {
        "title": "موارد تحجب عرض الصفحة",
        "severity": CRITICAL,
        "description": "CSS وJS محملين في الـ <head> بيخلوا المتصفح يوقف عرض الصفحة لحين تحميلهم كاملاً.",
        "fix": "أضف defer/async لـ JS، حمّل CSS غير الضروري بـ preload أو media queries."
    },
    "too_many_fonts": {
        "title": "عدد كبير من الفونتات",
        "severity": WARNING,
        "description": "كل font weight مختلف = request منفصل، 5 weights = 5 requests = تأخير في عرض النص.",
        "fix": "قلّل font weights لـ 2-3 بس، ادمجهم في request واحد."
    }
}


# ─── Analyzer Class ────────────────────────────────────────────────────────────
class WebsiteAnalyzer:
    def __init__(self, url: str):
        self.url = url if url.startswith("http") else f"https://{url}"
        self.domain = urlparse(self.url).netloc
        self.results = {
            "url": self.url,
            "domain": self.domain,
            "timestamp": datetime.now().isoformat(),
            "summary": {},
            "security": {},
            "performance": {},
            "resources": [],
            "issues": [],
            "score": 100
        }

    # ── Security Headers ───────────────────────────────────────────────────────
    def analyze_headers(self):
        print("🔒 فحص Security Headers...")
        try:
            resp = requests.get(self.url, timeout=15, allow_redirects=True,
                                headers={"User-Agent": "Mozilla/5.0 (compatible; SiteAnalyzer/1.0)"})
            headers = {k.lower(): v for k, v in resp.headers.items()}

            checks = {
                "content-security-policy":    ("csp",                "no_csp"),
                "strict-transport-security":  ("hsts",               "no_hsts"),
                "referrer-policy":            ("referrer_policy",    "no_referrer_policy"),
                "permissions-policy":         ("permissions_policy", "no_permissions_policy"),
                "x-frame-options":            ("x_frame_options",    "no_xframe"),
                "x-content-type-options":     ("x_content_type",     "no_xcontent"),
            }

            sec = {}
            for header, (key, issue_key) in checks.items():
                value = headers.get(header)
                sec[key] = {"present": bool(value), "value": value or "غير موجود"}
                if not value:
                    self._add_issue(issue_key)

            # Cache-Control for main page
            cc = headers.get("cache-control", "")
            sec["cache_control"] = {"value": cc, "present": bool(cc)}
            if not cc or ("no-store" not in cc and "no-cache" not in cc and "max-age" not in cc):
                self._add_issue("no_cache_html")

            self.results["security"] = sec
            self.results["response_code"] = resp.status_code
            self.results["server"] = headers.get("server", "unknown")
            self.results["cdn"] = "cloudflare" if "cloudflare" in headers.get("server", "").lower() else "unknown"

        except Exception as e:
            print(f"  ⚠️ خطأ في فحص الهيدرز: {e}")

    # ── Browser Analysis via Playwright ───────────────────────────────────────
    async def analyze_with_browser(self):
        print("🌐 تشغيل المتصفح وتسجيل كل الـ Requests...")
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
                viewport={"width": 1280, "height": 720}
            )
            page = await context.new_page()

            requests_log = []
            start_time = time.time()

            # Intercept all requests
            async def on_request(request):
                requests_log.append({
                    "url": request.url,
                    "resource_type": request.resource_type,
                    "method": request.method,
                    "start": time.time() - start_time
                })

            async def on_response(response):
                for req in requests_log:
                    if req["url"] == response.url and "duration" not in req:
                        req["status"] = response.status
                        req["duration"] = (time.time() - start_time) - req["start"]
                        try:
                            body = await response.body()
                            req["size"] = len(body)
                        except:
                            req["size"] = int(response.headers.get("content-length", 0))
                        req["headers"] = dict(response.headers)
                        break

            page.on("request", on_request)
            page.on("response", on_response)

            # Navigate and wait
            try:
                await page.goto(self.url, wait_until="networkidle", timeout=60000)
                await page.wait_for_timeout(3000)
                load_time = time.time() - start_time

                # Get page HTML
                html = await page.content()
                self._analyze_html(html)

                # Get performance metrics
                metrics = await page.evaluate("""() => {
                    const nav = performance.getEntriesByType('navigation')[0];
                    const paint = performance.getEntriesByType('paint');
                    return {
                        domContentLoaded: nav ? nav.domContentLoadedEventEnd : 0,
                        loadComplete: nav ? nav.loadEventEnd : 0,
                        firstPaint: paint.find(p => p.name === 'first-paint')?.startTime || 0,
                        firstContentfulPaint: paint.find(p => p.name === 'first-contentful-paint')?.startTime || 0,
                        transferSize: nav ? nav.transferSize : 0,
                        domElements: document.querySelectorAll('*').length
                    };
                }""")

                self.results["performance"]["load_time_seconds"] = round(load_time, 2)
                self.results["performance"]["metrics"] = {k: round(v/1000, 2) for k, v in metrics.items() if k not in ["domElements"]}
                self.results["performance"]["metrics"]["domElements"] = metrics["domElements"]

                if load_time > 10:
                    self._add_issue("slow_load", extra=f"وقت التحميل: {load_time:.1f} ثانية")
                elif load_time > 5:
                    self._add_issue("slow_load", severity_override=WARNING, extra=f"وقت التحميل: {load_time:.1f} ثانية")

            except Exception as e:
                print(f"  ⚠️ خطأ في تحميل الصفحة: {e}")
                load_time = 0

            await browser.close()
            self._analyze_requests(requests_log)

    # ── HTML Analysis ──────────────────────────────────────────────────────────
    def _analyze_html(self, html: str):
        print("📄 تحليل HTML...")
        soup = BeautifulSoup(html, "html.parser")

        # Check for srsltid in URLs
        all_links = [a.get("href", "") for a in soup.find_all("a", href=True)]
        srsltid_found = any("srsltid" in link for link in all_links)
        if srsltid_found:
            self._add_issue("srsltid_param")

        # Check Canonical
        canonical = soup.find("link", rel="canonical")
        self.results["performance"]["has_canonical"] = bool(canonical)
        self.results["performance"]["canonical_url"] = canonical.get("href") if canonical else None

        # Check images lazy loading
        images = soup.find_all("img")
        lazy_count = sum(1 for img in images if img.get("loading") == "lazy")
        non_lazy = len(images) - lazy_count
        self.results["performance"]["total_images"] = len(images)
        self.results["performance"]["lazy_images"] = lazy_count
        self.results["performance"]["non_lazy_images"] = non_lazy
        if non_lazy > 3:
            self._add_issue("no_lazy_images", extra=f"{non_lazy} صورة بدون lazy loading")

        # Check Arabic filenames in images
        arabic_imgs = []
        for img in images:
            src = img.get("src", "")
            if any(f"%D{c}" in src.upper() for c in "89ABCDEF"):
                arabic_imgs.append(src.split("/")[-1][:50])
        if arabic_imgs:
            self._add_issue("arabic_filenames", extra=f"{len(arabic_imgs)} صورة بأسماء عربية")
            self.results["performance"]["arabic_filenames"] = arabic_imgs[:10]

        # Check render-blocking resources
        head = soup.find("head")
        blocking = []
        if head:
            for script in head.find_all("script", src=True):
                if not script.get("async") and not script.get("defer"):
                    blocking.append(script.get("src", "")[:60])
            for link in head.find_all("link", rel="stylesheet"):
                if not link.get("media") or link.get("media") == "all":
                    blocking.append(link.get("href", "")[:60])

        if len(blocking) > 3:
            self._add_issue("render_blocking", extra=f"{len(blocking)} مورد يحجب العرض")
            self.results["performance"]["render_blocking"] = blocking[:10]

        # Font Awesome detection
        fa_links = []
        for link in soup.find_all("link"):
            href = link.get("href", "")
            if "font-awesome" in href.lower() or "fontawesome" in href.lower():
                fa_links.append(href[:80])
        for script in soup.find_all("script"):
            src = script.get("src", "")
            if "fontawesome" in src.lower() or "font-awesome" in src.lower():
                fa_links.append(src[:80])

        if fa_links:
            self._add_issue("font_awesome", extra=f"مصادر: {', '.join(fa_links[:2])}")
            self.results["performance"]["font_awesome_links"] = fa_links

        # Google Fonts / external fonts
        font_requests = []
        for link in soup.find_all("link"):
            href = link.get("href", "")
            if "fonts.googleapis.com" in href or "fonts.gstatic.com" in href:
                font_requests.append(href[:80])
        if len(font_requests) > 2:
            self._add_issue("too_many_fonts", extra=f"{len(font_requests)} طلب فونت")
        self.results["performance"]["font_requests"] = font_requests

        # WebP check
        img_srcs = [img.get("src", "") for img in images]
        old_format = [s for s in img_srcs if s.endswith((".jpg", ".jpeg", ".png", ".gif"))]
        if len(old_format) > 3:
            self._add_issue("no_webp", extra=f"{len(old_format)} صورة بتنسيقات قديمة")

        self.results["performance"]["has_viewport_meta"] = bool(
            soup.find("meta", attrs={"name": "viewport"})
        )

    # ── Requests Analysis ──────────────────────────────────────────────────────
    def _analyze_requests(self, requests_log: list):
        print("📊 تحليل الـ Requests...")

        total = len(requests_log)
        total_size = sum(r.get("size", 0) for r in requests_log)

        # Group by type
        by_type = {}
        for req in requests_log:
            rtype = req.get("resource_type", "other")
            if rtype not in by_type:
                by_type[rtype] = {"count": 0, "size": 0, "items": []}
            by_type[rtype]["count"] += 1
            by_type[rtype]["size"] += req.get("size", 0)
            by_type[rtype]["items"].append(req)

        # Top slowest requests
        slowest = sorted(
            [r for r in requests_log if "duration" in r],
            key=lambda x: x.get("duration", 0), reverse=True
        )[:15]

        # Top largest requests
        largest = sorted(
            [r for r in requests_log if r.get("size", 0) > 0],
            key=lambda x: x.get("size", 0), reverse=True
        )[:15]

        # JS analysis
        js_files = by_type.get("script", {}).get("items", [])
        total_js_size = sum(j.get("size", 0) for j in js_files)
        large_js = [j for j in js_files if j.get("size", 0) > 100 * 1024]  # >100KB
        if total_js_size > 500 * 1024:  # >500KB
            self._add_issue("large_js", extra=f"إجمالي JS: {self._fmt_size(total_js_size)}")
        elif total_js_size > 200 * 1024:
            self._add_issue("large_js", severity_override=WARNING, extra=f"إجمالي JS: {self._fmt_size(total_js_size)}")

        # CSS analysis
        css_files = by_type.get("stylesheet", {}).get("items", [])
        total_css_size = sum(c.get("size", 0) for c in css_files)
        if total_css_size > 200 * 1024:
            self._add_issue("large_css", extra=f"إجمالي CSS: {self._fmt_size(total_css_size)}")

        # Font Awesome in woff files
        all_fonts = by_type.get("font", {}).get("items", [])
        fa_fonts = [f for f in all_fonts if "fa-" in f["url"].lower() or "fontawesome" in f["url"].lower()]
        if fa_fonts:
            self._add_issue("font_awesome", extra=f"وجد {len(fa_fonts)} ملف فونت Font Awesome")

        # High requests
        if total > 100:
            self._add_issue("high_requests", extra=f"عدد الـ Requests: {total}")
        elif total > 60:
            self._add_issue("high_requests", severity_override=WARNING, extra=f"عدد الـ Requests: {total}")

        self.results["performance"]["total_requests"] = total
        self.results["performance"]["total_size_bytes"] = total_size
        self.results["performance"]["total_size_formatted"] = self._fmt_size(total_size)
        self.results["performance"]["by_type"] = {
            k: {"count": v["count"], "size": self._fmt_size(v["size"]), "size_bytes": v["size"]}
            for k, v in by_type.items()
        }
        self.results["performance"]["js_stats"] = {
            "total_size": self._fmt_size(total_js_size),
            "total_size_bytes": total_js_size,
            "file_count": len(js_files),
            "large_files": [{"url": j["url"][:80], "size": self._fmt_size(j.get("size", 0))} for j in large_js]
        }
        self.results["performance"]["css_stats"] = {
            "total_size": self._fmt_size(total_css_size),
            "file_count": len(css_files)
        }

        # Store top resources
        self.results["resources"] = {
            "slowest": [
                {
                    "url": r["url"][:90],
                    "type": r.get("resource_type", "?"),
                    "duration_ms": round(r.get("duration", 0) * 1000),
                    "size": self._fmt_size(r.get("size", 0))
                }
                for r in slowest
            ],
            "largest": [
                {
                    "url": r["url"][:90],
                    "type": r.get("resource_type", "?"),
                    "size": self._fmt_size(r.get("size", 0)),
                    "size_bytes": r.get("size", 0)
                }
                for r in largest
            ]
        }

    # ── Issue Management ───────────────────────────────────────────────────────
    def _add_issue(self, key: str, severity_override=None, extra=None):
        detail = ISSUE_DETAILS.get(key, {})
        if not detail:
            return

        # Avoid duplicate issues
        existing_keys = [i["key"] for i in self.results["issues"]]
        if key in existing_keys:
            return

        severity = severity_override or detail.get("severity", INFO)
        penalty = {CRITICAL: 20, WARNING: 10, INFO: 2}.get(severity, 0)
        self.results["score"] = max(0, self.results["score"] - penalty)

        self.results["issues"].append({
            "key": key,
            "title": detail["title"],
            "severity": severity,
            "description": detail["description"],
            "fix": detail["fix"],
            "extra": extra
        })

    # ── Helpers ────────────────────────────────────────────────────────────────
    def _fmt_size(self, size_bytes: int) -> str:
        if size_bytes > 1024 * 1024:
            return f"{size_bytes / (1024*1024):.1f} MB"
        elif size_bytes > 1024:
            return f"{size_bytes / 1024:.1f} KB"
        return f"{size_bytes} B"

    def _calculate_summary(self):
        issues = self.results["issues"]
        self.results["summary"] = {
            "score": self.results["score"],
            "grade": self._score_to_grade(self.results["score"]),
            "critical_count": sum(1 for i in issues if i["severity"] == CRITICAL),
            "warning_count": sum(1 for i in issues if i["severity"] == WARNING),
            "total_issues": len(issues),
            "total_requests": self.results["performance"].get("total_requests", 0),
            "load_time": self.results["performance"].get("load_time_seconds", 0),
            "total_size": self.results["performance"].get("total_size_formatted", "?"),
        }

    def _score_to_grade(self, score: int) -> str:
        if score >= 90: return "A"
        if score >= 75: return "B"
        if score >= 60: return "C"
        if score >= 40: return "D"
        return "F"

    # ── Main Run ───────────────────────────────────────────────────────────────
    async def run(self):
        print(f"\n🚀 بدء تحليل: {self.url}\n{'─'*50}")
        self.analyze_headers()
        await self.analyze_with_browser()
        self._calculate_summary()
        print(f"\n✅ انتهى التحليل — تم اكتشاف {len(self.results['issues'])} مشكلة")
        return self.results


# ─── HTML Dashboard Generator ─────────────────────────────────────────────────
def generate_dashboard(results: dict, output_path: str = "report.html"):
    score = results["summary"]["score"]
    grade = results["summary"]["grade"]
    grade_colors = {"A": "#22c55e", "B": "#84cc16", "C": "#f59e0b", "D": "#f97316", "F": "#ef4444"}
    grade_color = grade_colors.get(grade, "#ef4444")

    issues_html = ""
    severity_icons = {CRITICAL: "🔴", WARNING: "🟡", INFO: "🔵"}
    severity_labels = {CRITICAL: "خطير", WARNING: "تحذير", INFO: "معلومة"}
    severity_colors = {CRITICAL: "#ef4444", WARNING: "#f59e0b", INFO: "#3b82f6"}

    for issue in sorted(results["issues"], key=lambda x: [CRITICAL, WARNING, INFO].index(x["severity"])):
        sev = issue["severity"]
        issues_html += f"""
        <div class="issue-card issue-{sev}">
            <div class="issue-header">
                <span class="issue-icon">{severity_icons[sev]}</span>
                <span class="issue-title">{issue['title']}</span>
                <span class="issue-badge" style="background:{severity_colors[sev]}">{severity_labels[sev]}</span>
            </div>
            <p class="issue-desc">{issue['description']}</p>
            {f'<p class="issue-extra">📊 {issue["extra"]}</p>' if issue.get("extra") else ""}
            <div class="issue-fix">
                <span class="fix-label">💡 الحل:</span> {issue['fix']}
            </div>
        </div>"""

    # Security headers table
    sec = results.get("security", {})
    sec_checks = [
        ("Content-Security-Policy", sec.get("csp", {}).get("present", False), sec.get("csp", {}).get("value", "—")),
        ("Strict-Transport-Security", sec.get("hsts", {}).get("present", False), sec.get("hsts", {}).get("value", "—")),
        ("Referrer-Policy", sec.get("referrer_policy", {}).get("present", False), sec.get("referrer_policy", {}).get("value", "—")),
        ("Permissions-Policy", sec.get("permissions_policy", {}).get("present", False), sec.get("permissions_policy", {}).get("value", "—")),
        ("X-Frame-Options", sec.get("x_frame_options", {}).get("present", False), sec.get("x_frame_options", {}).get("value", "—")),
        ("X-Content-Type-Options", sec.get("x_content_type", {}).get("present", False), sec.get("x_content_type", {}).get("value", "—")),
    ]
    sec_rows = ""
    for name, present, value in sec_checks:
        icon = "✅" if present else "❌"
        row_class = "sec-ok" if present else "sec-fail"
        display_val = (value[:60] + "...") if len(str(value)) > 60 else value
        sec_rows += f"""<tr class="{row_class}">
            <td>{icon}</td><td><code>{name}</code></td><td>{display_val}</td>
        </tr>"""

    # Slowest resources
    slowest_rows = ""
    for r in results.get("resources", {}).get("slowest", []):
        bar_width = min(100, r['duration_ms'] / 50)
        color = "#ef4444" if r['duration_ms'] > 3000 else "#f59e0b" if r['duration_ms'] > 1000 else "#22c55e"
        name = r['url'].split('?')[0].split('/')[-1] or r['url'][:50]
        slowest_rows += f"""
        <tr>
            <td class="res-name" title="{r['url']}">{name[:45]}</td>
            <td><span class="tag tag-{r['type']}">{r['type']}</span></td>
            <td>{r['size']}</td>
            <td>
                <div class="bar-wrap">
                    <div class="bar" style="width:{bar_width}%;background:{color}"></div>
                    <span>{r['duration_ms']}ms</span>
                </div>
            </td>
        </tr>"""

    # Largest resources
    largest_rows = ""
    max_size = max((r['size_bytes'] for r in results.get("resources", {}).get("largest", [])), default=1)
    for r in results.get("resources", {}).get("largest", []):
        bar_width = min(100, (r['size_bytes'] / max_size) * 100)
        color = "#ef4444" if r['size_bytes'] > 500*1024 else "#f59e0b" if r['size_bytes'] > 100*1024 else "#22c55e"
        name = r['url'].split('?')[0].split('/')[-1] or r['url'][:50]
        largest_rows += f"""
        <tr>
            <td class="res-name" title="{r['url']}">{name[:45]}</td>
            <td><span class="tag tag-{r['type']}">{r['type']}</span></td>
            <td>
                <div class="bar-wrap">
                    <div class="bar" style="width:{bar_width}%;background:{color}"></div>
                    <span>{r['size']}</span>
                </div>
            </td>
        </tr>"""

    # By type chart data
    by_type = results["performance"].get("by_type", {})
    type_rows = ""
    type_icons = {"script": "⚡", "stylesheet": "🎨", "image": "🖼️", "font": "🔤",
                  "fetch": "📡", "xhr": "📡", "document": "📄", "other": "📦", "media": "🎬"}
    sorted_types = sorted(by_type.items(), key=lambda x: x[1]["size_bytes"], reverse=True)
    max_type_size = max((v["size_bytes"] for _, v in sorted_types), default=1)
    for rtype, data in sorted_types:
        bar_w = min(100, (data["size_bytes"] / max_type_size) * 100)
        type_rows += f"""
        <tr>
            <td>{type_icons.get(rtype, '📦')} {rtype}</td>
            <td>{data['count']}</td>
            <td>
                <div class="bar-wrap">
                    <div class="bar" style="width:{bar_w}%;background:#6366f1"></div>
                    <span>{data['size']}</span>
                </div>
            </td>
        </tr>"""

    perf = results["performance"]
    metrics = perf.get("metrics", {})
    load_time = perf.get("load_time_seconds", 0)
    load_color = "#22c55e" if load_time < 3 else "#f59e0b" if load_time < 8 else "#ef4444"
    req_count = perf.get("total_requests", 0)
    req_color = "#22c55e" if req_count < 50 else "#f59e0b" if req_count < 80 else "#ef4444"

    html = f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>تقرير تحليل الموقع — {results['domain']}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;900&display=swap');

  :root {{
    --bg: #0a0a0f;
    --surface: #12121a;
    --surface2: #1a1a28;
    --border: #2a2a3d;
    --text: #e2e8f0;
    --muted: #64748b;
    --accent: #6366f1;
    --accent2: #8b5cf6;
    --red: #ef4444;
    --yellow: #f59e0b;
    --green: #22c55e;
  }}

  * {{ margin:0; padding:0; box-sizing:border-box; }}

  body {{
    font-family: 'Cairo', sans-serif;
    background: var(--bg);
    color: var(--text);
    direction: rtl;
    min-height: 100vh;
  }}

  /* ── Header ── */
  .header {{
    background: linear-gradient(135deg, #1a0533 0%, #0d1133 50%, #001a33 100%);
    border-bottom: 1px solid var(--border);
    padding: 2.5rem 2rem 2rem;
    position: relative;
    overflow: hidden;
  }}
  .header::before {{
    content: '';
    position: absolute;
    top: -50%;
    right: -20%;
    width: 600px; height: 600px;
    background: radial-gradient(circle, rgba(99,102,241,0.15) 0%, transparent 70%);
    pointer-events: none;
  }}
  .header-inner {{
    max-width: 1200px;
    margin: 0 auto;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 1.5rem;
  }}
  .header-left h1 {{
    font-size: 1.8rem;
    font-weight: 900;
    background: linear-gradient(135deg, #818cf8, #c084fc);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
  }}
  .header-left .url-tag {{
    font-size: 0.85rem;
    color: var(--muted);
    margin-top: 0.3rem;
  }}
  .header-left .url-tag a {{
    color: #818cf8;
    text-decoration: none;
  }}
  .score-circle {{
    width: 120px; height: 120px;
    border-radius: 50%;
    background: conic-gradient({grade_color} {score}%, var(--surface2) 0%);
    display: flex; align-items: center; justify-content: center;
    position: relative;
  }}
  .score-inner {{
    width: 90px; height: 90px;
    border-radius: 50%;
    background: var(--bg);
    display: flex; flex-direction: column;
    align-items: center; justify-content: center;
  }}
  .score-num {{ font-size: 1.8rem; font-weight: 900; color: {grade_color}; }}
  .score-grade {{ font-size: 0.75rem; color: var(--muted); }}

  /* ── Layout ── */
  .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}

  /* ── Stats Bar ── */
  .stats-bar {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
  }}
  .stat-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.2rem;
    text-align: center;
    position: relative;
    overflow: hidden;
  }}
  .stat-card::before {{
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    background: var(--accent-color, var(--accent));
  }}
  .stat-val {{ font-size: 2rem; font-weight: 900; }}
  .stat-label {{ font-size: 0.75rem; color: var(--muted); margin-top: 0.2rem; }}

  /* ── Section ── */
  .section {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
  }}
  .section-title {{
    font-size: 1.1rem;
    font-weight: 700;
    margin-bottom: 1.2rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding-bottom: 0.8rem;
    border-bottom: 1px solid var(--border);
  }}

  /* ── Issues ── */
  .issue-card {{
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.2rem;
    margin-bottom: 1rem;
    transition: transform 0.2s;
  }}
  .issue-card:hover {{ transform: translateX(-4px); }}
  .issue-critical {{ border-right: 4px solid var(--red); background: rgba(239,68,68,0.05); }}
  .issue-warning {{ border-right: 4px solid var(--yellow); background: rgba(245,158,11,0.05); }}
  .issue-info {{ border-right: 4px solid #3b82f6; background: rgba(59,130,246,0.05); }}
  .issue-header {{ display: flex; align-items: center; gap: 0.7rem; margin-bottom: 0.6rem; flex-wrap: wrap; }}
  .issue-title {{ font-weight: 700; font-size: 1rem; flex: 1; }}
  .issue-badge {{
    font-size: 0.7rem; padding: 0.2rem 0.6rem;
    border-radius: 20px; color: white; font-weight: 700;
  }}
  .issue-desc {{ color: #94a3b8; font-size: 0.88rem; line-height: 1.7; margin-bottom: 0.5rem; }}
  .issue-extra {{ color: #cbd5e1; font-size: 0.82rem; font-weight: 600; margin-bottom: 0.5rem; }}
  .issue-fix {{
    background: rgba(99,102,241,0.1);
    border: 1px solid rgba(99,102,241,0.2);
    border-radius: 8px;
    padding: 0.6rem 0.8rem;
    font-size: 0.82rem;
    color: #c4b5fd;
  }}
  .fix-label {{ font-weight: 700; }}

  /* ── Tables ── */
  table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  th {{
    text-align: right; padding: 0.6rem 0.8rem;
    color: var(--muted); font-weight: 600;
    border-bottom: 2px solid var(--border);
  }}
  td {{ padding: 0.6rem 0.8rem; border-bottom: 1px solid var(--border); vertical-align: middle; }}
  tr:last-child td {{ border-bottom: none; }}
  .sec-ok td {{ color: #86efac; }}
  .sec-fail td {{ color: #fca5a5; }}
  code {{ font-size: 0.8rem; background: var(--surface2); padding: 0.1rem 0.4rem; border-radius: 4px; }}

  /* ── Tags ── */
  .tag {{
    display: inline-block;
    padding: 0.15rem 0.5rem;
    border-radius: 20px;
    font-size: 0.72rem;
    font-weight: 700;
    text-transform: uppercase;
  }}
  .tag-script {{ background: rgba(245,158,11,0.2); color: #fcd34d; }}
  .tag-stylesheet {{ background: rgba(99,102,241,0.2); color: #a5b4fc; }}
  .tag-image {{ background: rgba(34,197,94,0.2); color: #86efac; }}
  .tag-font {{ background: rgba(168,85,247,0.2); color: #d8b4fe; }}
  .tag-fetch, .tag-xhr {{ background: rgba(14,165,233,0.2); color: #7dd3fc; }}
  .tag-document {{ background: rgba(239,68,68,0.2); color: #fca5a5; }}
  .tag-other, .tag-media {{ background: rgba(100,116,139,0.2); color: #94a3b8; }}

  /* ── Bar ── */
  .bar-wrap {{ display: flex; align-items: center; gap: 0.5rem; }}
  .bar {{ height: 6px; border-radius: 3px; min-width: 4px; }}
  .bar-wrap span {{ font-size: 0.8rem; color: var(--muted); white-space: nowrap; }}

  .res-name {{ max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #c4b5fd; }}

  /* ── JS Stats ── */
  .js-box {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 1rem;
    margin-bottom: 1rem;
  }}
  .js-stat {{
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1rem;
    text-align: center;
  }}
  .js-stat .val {{ font-size: 1.5rem; font-weight: 800; color: #f59e0b; }}
  .js-stat .lbl {{ font-size: 0.75rem; color: var(--muted); }}

  /* ── Timestamp ── */
  .footer {{
    text-align: center;
    padding: 2rem;
    color: var(--muted);
    font-size: 0.8rem;
    border-top: 1px solid var(--border);
    margin-top: 2rem;
  }}

  /* ── Responsive ── */
  @media (max-width: 600px) {{
    .header-inner {{ flex-direction: column; text-align: center; }}
    .container {{ padding: 1rem; }}
    .stat-val {{ font-size: 1.5rem; }}
  }}
</style>
</head>
<body>

<div class="header">
  <div class="header-inner">
    <div class="header-left">
      <h1>🔍 تقرير تحليل الموقع</h1>
      <div class="url-tag">
        🌐 <a href="{results['url']}" target="_blank">{results['url']}</a>
        &nbsp;|&nbsp; 📅 {results['timestamp'][:19].replace('T', ' ')}
        &nbsp;|&nbsp; 🖥️ {results.get('server', '?')}
        {' &nbsp;|&nbsp; ☁️ Cloudflare' if results.get('cdn') == 'cloudflare' else ''}
      </div>
    </div>
    <div class="score-circle">
      <div class="score-inner">
        <div class="score-num">{score}</div>
        <div class="score-grade">درجة {grade}</div>
      </div>
    </div>
  </div>
</div>

<div class="container">

  <!-- Stats Bar -->
  <div class="stats-bar">
    <div class="stat-card" style="--accent-color:{load_color}">
      <div class="stat-val" style="color:{load_color}">{perf.get('load_time_seconds', '?')}s</div>
      <div class="stat-label">⏱️ وقت التحميل</div>
    </div>
    <div class="stat-card" style="--accent-color:{req_color}">
      <div class="stat-val" style="color:{req_color}">{req_count}</div>
      <div class="stat-label">📡 عدد الـ Requests</div>
    </div>
    <div class="stat-card" style="--accent-color:var(--accent)">
      <div class="stat-val" style="color:var(--accent)">{perf.get('total_size_formatted', '?')}</div>
      <div class="stat-label">📦 الحجم الكلي</div>
    </div>
    <div class="stat-card" style="--accent-color:var(--red)">
      <div class="stat-val" style="color:var(--red)">{results['summary']['critical_count']}</div>
      <div class="stat-label">🔴 مشاكل خطيرة</div>
    </div>
    <div class="stat-card" style="--accent-color:var(--yellow)">
      <div class="stat-val" style="color:var(--yellow)">{results['summary']['warning_count']}</div>
      <div class="stat-label">🟡 تحذيرات</div>
    </div>
    <div class="stat-card" style="--accent-color:var(--green)">
      <div class="stat-val" style="color:var(--green)">{round(metrics.get('firstContentfulPaint', 0), 2)}s</div>
      <div class="stat-label">🎨 First Paint</div>
    </div>
  </div>

  <!-- Issues -->
  <div class="section">
    <div class="section-title">⚠️ المشاكل المكتشفة ({len(results['issues'])} مشكلة)</div>
    {issues_html if issues_html else '<p style="color:var(--green);text-align:center;padding:1rem">✅ لم يتم اكتشاف مشاكل!</p>'}
  </div>

  <!-- Security Headers -->
  <div class="section">
    <div class="section-title">🔒 Security Headers</div>
    <table>
      <tr><th>الحالة</th><th>الهيدر</th><th>القيمة</th></tr>
      {sec_rows}
    </table>
  </div>

  <!-- JS Stats -->
  <div class="section">
    <div class="section-title">⚡ تحليل JavaScript</div>
    <div class="js-box">
      <div class="js-stat">
        <div class="val">{results['performance'].get('js_stats', {}).get('total_size', '?')}</div>
        <div class="lbl">إجمالي حجم JS</div>
      </div>
      <div class="js-stat">
        <div class="val">{results['performance'].get('js_stats', {}).get('file_count', 0)}</div>
        <div class="lbl">عدد ملفات JS</div>
      </div>
      <div class="js-stat">
        <div class="val">{results['performance'].get('css_stats', {}).get('total_size', '?')}</div>
        <div class="lbl">إجمالي حجم CSS</div>
      </div>
      <div class="js-stat">
        <div class="val">{results['performance'].get('total_images', 0)}</div>
        <div class="lbl">عدد الصور</div>
      </div>
      <div class="js-stat">
        <div class="val">{results['performance'].get('lazy_images', 0)}</div>
        <div class="lbl">Lazy Loaded</div>
      </div>
      <div class="js-stat">
        <div class="val">{'✅' if results['performance'].get('has_canonical') else '❌'}</div>
        <div class="lbl">Canonical Tag</div>
      </div>
    </div>
  </div>

  <!-- Resources by Type -->
  <div class="section">
    <div class="section-title">📦 الموارد حسب النوع</div>
    <table>
      <tr><th>النوع</th><th>العدد</th><th>الحجم</th></tr>
      {type_rows}
    </table>
  </div>

  <!-- Slowest Resources -->
  <div class="section">
    <div class="section-title">🐌 أبطأ الملفات في التحميل</div>
    <table>
      <tr><th>الملف</th><th>النوع</th><th>الحجم</th><th>الوقت</th></tr>
      {slowest_rows}
    </table>
  </div>

  <!-- Largest Resources -->
  <div class="section">
    <div class="section-title">📏 أكبر الملفات حجماً</div>
    <table>
      <tr><th>الملف</th><th>النوع</th><th>الحجم</th></tr>
      {largest_rows}
    </table>
  </div>

</div>

<div class="footer">
  تم إنشاء التقرير بواسطة WebSite Analyzer &nbsp;|&nbsp;
  {results['timestamp'][:19].replace('T', ' ')}
</div>

</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\n📊 Dashboard: {output_path}")


# ─── CLI Entry Point ───────────────────────────────────────────────────────────
async def main():
    parser = argparse.ArgumentParser(
        description="🔍 Website Performance & Security Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
مثال:
  python analyzer.py https://arabian-traveler.com
  python analyzer.py arabian-traveler.com --output my-report.html
  python analyzer.py https://mysite.com --json
        """
    )
    parser.add_argument("url", help="رابط الموقع المراد تحليله")
    parser.add_argument("--output", "-o", default="report.html", help="اسم ملف التقرير (default: report.html)")
    parser.add_argument("--json", "-j", action="store_true", help="حفظ النتائج بصيغة JSON أيضاً")
    args = parser.parse_args()

    analyzer = WebsiteAnalyzer(args.url)
    results = await analyzer.run()

    # Generate HTML Dashboard
    generate_dashboard(results, args.output)

    # Optional JSON output
    if args.json:
        json_path = args.output.replace(".html", ".json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"📄 JSON: {json_path}")

    # Print summary to console
    print(f"""
{'═'*50}
📊 ملخص التقرير
{'═'*50}
🌐 الموقع:       {results['url']}
🏆 النتيجة:      {results['summary']['score']}/100 (درجة {results['summary']['grade']})
⏱️  وقت التحميل:  {results['summary']['load_time']} ثانية
📡 الـ Requests:  {results['summary']['total_requests']}
📦 الحجم الكلي:  {results['summary']['total_size']}
🔴 مشاكل خطيرة: {results['summary']['critical_count']}
🟡 تحذيرات:      {results['summary']['warning_count']}
{'═'*50}
📊 افتح: {args.output}
""")


if __name__ == "__main__":
    asyncio.run(main())
