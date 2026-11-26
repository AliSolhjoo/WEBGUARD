"""Bilingual, evidence-backed WEBGUARD PDF report generation."""

from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether

from apps.scans.risk import security_score


TRANSLATIONS = {
    "fa": {
        "title": "گزارش ارزیابی امنیت وب",
        "target": "دامنه هدف",
        "scan_id": "شناسه اسکن",
        "status": "وضعیت",
        "generated": "زمان تولید",
        "summary": "خلاصه ارزیابی",
        "score": "امتیاز امنیتی WEBGUARD",
        "checks": "مجموع بررسی‌ها",
        "passed": "موفق",
        "failed": "ناموفق",
        "info": "اطلاعات / خطا",
        "score_note": "این امتیاز یک معیار ابتکاری WEBGUARD است و امتیاز CVSS محسوب نمی‌شود.",
        "findings": "یافته‌های نیازمند بررسی",
        "no_findings": "در این ارزیابی بررسی ناموفقی ثبت نشده است.",
        "recommendation": "راهکار اصلاح",
        "evidence": "شواهد فنی",
        "scope": "محدوده و محدودیت‌ها",
        "scope_text": "این گزارش بر اساس بررسی محدود و غیرفعال نقطه اصلی دامنه تأییدشده تهیه شده است. این گزارش آزمون نفوذ نیست، نبود آسیب‌پذیری را اثبات نمی‌کند و ممکن است مسیرهای احراز هویت‌شده یا تمام مسیرهای برنامه را پوشش ندهد. پیش از تصمیم‌گیری درباره ریسک، یافته‌ها را به‌صورت دستی بازبینی کنید.",
        "priority": "اولویت",
        "critical": "بحرانی",
        "high": "زیاد",
        "medium": "متوسط",
        "low": "کم",
        "informational": "اطلاع‌رسانی",
        "fail": "ناموفق",
        "error": "خطا",
        "info_status": "اطلاعاتی",
        "pass": "موفق",
        "category": "دسته‌بندی",
        "check": "شناسه بررسی",
        "page": "صفحه",
        "footer": "گزارش محرمانه ارزیابی امنیتی WEBGUARD",
        "pending": "در انتظار",
        "running": "در حال اجرا",
        "completed": "تکمیل‌شده",
        "failed": "ناموفق",
        "cancelled": "لغوشده",
    }
}


CHECK_TRANSLATIONS = {
    "WG-HTTP-001": ("دردسترس‌بودن HTTPS", "امنیت انتقال", "نقطه پایانی HTTPS یک TLS handshake معتبر را تکمیل کرد."),
    "WG-HTTP-002": ("انتقال HTTP به HTTPS", "امنیت انتقال", "انتقال HTTP به HTTPS در همان میزبان تأیید نشد."),
    "WG-TLS-001": ("اعتبار زمانی گواهی TLS", "TLS", "گواهی TLS منقضی شده یا کمتر از ۳۰ روز تا انقضای آن باقی مانده است."),
    "WG-TLS-002": ("نسخه توافق‌شده TLS", "TLS", "نسخه پروتکل TLS مذاکره‌شده با سیاست امنیتی مورد انتظار تطبیق ندارد."),
    "WG-HDR-001": ("Content-Security-Policy", "هدرهای امنیتی", "هدر CSP روی پاسخ مشاهده‌شده وجود ندارد یا مقدار قابل تشخیصی نداشت."),
    "WG-HDR-002": ("Strict-Transport-Security", "هدرهای امنیتی", "هدر HSTS با max-age مناسب روی پاسخ HTTPS مشاهده نشد."),
    "WG-HDR-003": ("X-Content-Type-Options", "هدرهای امنیتی", "هدر X-Content-Type-Options با مقدار دقیق nosniff مشاهده نشد."),
    "WG-HDR-004": ("Referrer-Policy", "هدرهای امنیتی", "هدر Referrer-Policy مشاهده نشد."),
    "WG-HDR-005": ("Permissions-Policy", "هدرهای امنیتی", "هدر Permissions-Policy مشاهده نشد."),
    "WG-HDR-006": ("محافظت در برابر Clickjacking", "هدرهای امنیتی", "محدودیت شناخته‌شده‌ای برای بارگذاری صفحه در Frame مشاهده نشد."),
    "WG-HDR-007": ("دستورهای ناامن اسکریپت در CSP", "هدرهای امنیتی", "دستور unsafe-inline یا unsafe-eval در سیاست اجرای اسکریپت مشاهده شد."),
    "WG-COOKIE-001": ("ویژگی‌های امنیتی Cookie", "Cookieها", "یک یا چند Cookie مشاهده‌شده فاقد ویژگی‌های امنیتی موردنیاز هستند."),
    "WG-DNS-001": ("رکورد SPF", "DNS", "رکورد SPF در دامنه مشاهده نشد."),
    "WG-DNS-002": ("رکورد DMARC", "DNS", "رکورد DMARC در _dmarc دامنه مشاهده نشد."),
    "WG-DNS-003": ("سخت‌گیری سیاست SPF", "DNS", "سیاست SPF بیش از حد permissive است یا چند رکورد SPF مشاهده شده است."),
    "WG-DNS-004": ("سیاست اعمال DMARC", "DNS", "سیاست DMARC به مرحله اعمال quarantine یا reject نرسیده یا معتبر نیست."),
    "WG-DNS-005": ("رکورد CAA", "DNS", "رکورد CAA برای محدود کردن مراجع صدور گواهی مشاهده نشد."),
    "WG-CONTENT-001": ("ارجاع به Mixed Content", "امنیت محتوا", "نمونه محدود HTML شامل منابع HTTP در صفحه HTTPS است."),
    "WG-CONTENT-002": ("افشای اطلاعات فناوری عمومی", "افشای اطلاعات", "نمونه عمومی شامل نشانه‌هایی از افشای نسخه فناوری یا ارجاع Source Map است."),
}

RECOMMENDATIONS_FA = {
    "WG-HTTP-001": "یک گواهی معتبر نصب کنید، زنجیره گواهی را کامل نگه دارید و اتصال HTTPS را دوباره اعتبارسنجی کنید.",
    "WG-HTTP-002": "درخواست HTTP را به HTTPS همان میزبان با Redirect دائمی و امن منتقل کنید.",
    "WG-TLS-001": "گواهی را پیش از انقضا تمدید و اعتبار آن را به‌صورت پیوسته پایش کنید.",
    "WG-TLS-002": "TLS 1.2 یا TLS 1.3 را مجاز و نسخه‌های منسوخ را غیرفعال کنید.",
    "WG-HDR-001": "CSP محدودکننده و سازگار با برنامه تعریف کنید و تا حد امکان unsafe-inline و unsafe-eval را حذف کنید.",
    "WG-HDR-002": "پس از تأیید آمادگی HTTPS، HSTS با max-age مناسب تنظیم کنید.",
    "WG-HDR-003": "هدر X-Content-Type-Options: nosniff را تنظیم کنید.",
    "WG-HDR-004": "Referrer-Policy متناسب با حریم خصوصی، مانند strict-origin-when-cross-origin، تنظیم کنید.",
    "WG-HDR-005": "Permissions-Policy را با حداقل قابلیت‌های موردنیاز برنامه تنظیم کنید.",
    "WG-HDR-006": "X-Frame-Options محدودکننده یا دستور CSP frame-ancestors تعریف کنید.",
    "WG-HDR-007": "unsafe-inline و unsafe-eval را حذف و برای اسکریپت‌های درون‌خطی از Nonce یا Hash استفاده کنید.",
    "WG-COOKIE-001": "برای Cookieهای حساس Secure و HttpOnly و SameSite مناسب را فعال کنید.",
    "WG-DNS-001": "یک رکورد SPF واحد و منطبق با تمام فرستنده‌های مجاز منتشر کنید.",
    "WG-DNS-002": "رکورد DMARC منتشر کنید و پس از تحلیل گزارش‌ها به‌تدریج سیاست اعمالی را فعال کنید.",
    "WG-DNS-003": "یک رکورد SPF با Qualifier پایانی آگاهانه مانند -all یا ~all نگه دارید.",
    "WG-DNS-004": "پس از بررسی گزارش‌ها و هم‌ترازی SPF/DKIM، سیاست DMARC را به quarantine یا reject ارتقا دهید.",
    "WG-DNS-005": "رکوردهای CAA را برای محدود کردن مراجع صدور گواهی مجاز بررسی و منتشر کنید.",
    "WG-CONTENT-001": "منابع HTTP را با HTTPS یا مسیر نسبی هم‌مبدأ جایگزین کنید.",
    "WG-CONTENT-002": "هدرهای نسخه غیرضروری و Source Mapهای ناخواسته را از انتشار عمومی حذف کنید.",
}


def _find_font(language):
    if language != "fa":
        return "Helvetica", "Helvetica-Bold"
    candidates = [
        (r"C:\Windows\Fonts\tahoma.ttf", r"C:\Windows\Fonts\tahomabd.ttf"),
        (r"C:\Windows\Fonts\arial.ttf", r"C:\Windows\Fonts\arialbd.ttf"),
        ("/usr/share/fonts/truetype/noto/NotoSansArabic-Regular.ttf", "/usr/share/fonts/truetype/noto/NotoSansArabic-Bold.ttf"),
        ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
    ]
    for regular, bold in candidates:
        if Path(regular).exists():
            regular_name, bold_name = "WEBGUARDUnicode", "WEBGUARDUnicodeBold"
            if regular_name not in pdfmetrics.getRegisteredFontNames():
                pdfmetrics.registerFont(TTFont(regular_name, regular))
            if Path(bold).exists() and bold_name not in pdfmetrics.getRegisteredFontNames():
                pdfmetrics.registerFont(TTFont(bold_name, bold))
            else:
                bold_name = regular_name
            return regular_name, bold_name
    raise RuntimeError("Persian PDF generation requires a Unicode Arabic/Persian TrueType font. Install Tahoma or Noto Sans Arabic on this computer.")


def _shape(text, language):
    value = str(text or "")
    if language != "fa":
        return value
    try:
        import arabic_reshaper
        from bidi.algorithm import get_display
        return get_display(arabic_reshaper.reshape(value))
    except ImportError as exc:
        raise RuntimeError("Persian PDF generation requires arabic-reshaper and python-bidi. Run the project setup script again.") from exc


def _label(key, language):
    return TRANSLATIONS.get(language, {}).get(key, key.replace("_", " ").title())


def _safe_paragraph(value, language):
    return escape(_shape(value, language)).replace("\n", "<br/>")


def build_report(scan, language="en"):
    language = language if language in {"en", "fa"} else "en"
    regular_font, bold_font = _find_font(language)
    rtl = language == "fa"
    alignment = TA_RIGHT if rtl else TA_LEFT
    output = BytesIO()
    doc = SimpleDocTemplate(
        output, pagesize=A4, rightMargin=16 * mm, leftMargin=16 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm,
        title=f"{_label('title', language)} - {scan.asset.domain}",
        author="WEBGUARD Security Assessment Platform",
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="WGBody", parent=styles["BodyText"], fontName=regular_font,
        fontSize=8.5, leading=13, alignment=alignment, spaceAfter=2 * mm,
    ))
    styles.add(ParagraphStyle(
        name="WGSmall", parent=styles["BodyText"], fontName=regular_font,
        fontSize=7.5, leading=10, textColor=colors.HexColor("#64748b"), alignment=alignment,
    ))
    styles.add(ParagraphStyle(
        name="WGHeading", parent=styles["Heading2"], fontName=bold_font,
        fontSize=12, leading=16, textColor=colors.HexColor("#172554"), alignment=alignment,
        spaceBefore=5 * mm, spaceAfter=2 * mm,
    ))
    styles.add(ParagraphStyle(
        name="WGTitle", parent=styles["Title"], fontName=bold_font,
        fontSize=21, leading=26, textColor=colors.HexColor("#0f172a"), alignment=alignment,
    ))
    styles.add(ParagraphStyle(
        name="WGFinding", parent=styles["Heading3"], fontName=bold_font,
        fontSize=9.5, leading=12, spaceBefore=2 * mm, spaceAfter=1.5 * mm, alignment=alignment,
    ))

    checks = list(scan.checks.all().order_by("category", "check_id"))
    failed = [item for item in checks if item.status == "fail"]
    score = security_score(failed)
    story = [
        Paragraph(_safe_paragraph(_label("title", language), language), styles["WGTitle"]),
        Spacer(1, 2 * mm),
    ]
    meta = [
        [Paragraph(f"<b>{_safe_paragraph(_label('target', language), language)}</b>", styles["WGSmall"]),
         Paragraph(_safe_paragraph(scan.asset.domain, language), styles["WGBody"])],
        [Paragraph(f"<b>{_safe_paragraph(_label('scan_id', language), language)}</b>", styles["WGSmall"]),
         Paragraph(str(scan.id), styles["WGBody"])],
        [Paragraph(f"<b>{_safe_paragraph(_label('status', language), language)}</b>", styles["WGSmall"]),
         Paragraph(_safe_paragraph(_label(scan.status, language), language), styles["WGBody"])],
        [Paragraph(f"<b>{_safe_paragraph(_label('generated', language), language)}</b>", styles["WGSmall"]),
         Paragraph(_safe_paragraph(datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), language), styles["WGBody"])],
    ]
    meta_table = Table(meta, colWidths=[42 * mm, 130 * mm], hAlign="RIGHT" if rtl else "LEFT")
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#dbeafe")),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "RIGHT" if rtl else "LEFT"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story += [meta_table, Paragraph(_safe_paragraph(_label("summary", language), language), styles["WGHeading"])]

    headers = [
        _shape(_label("score", language), language), _shape(_label("checks", language), language),
        _shape(_label("passed", language), language), _shape(_label("failed", language), language),
        _shape(_label("info", language), language),
    ]
    values = [str(score), str(scan.total_checks), str(scan.passed_checks), str(scan.failed_checks), str(scan.info_checks)]
    summary_table = Table([headers, values], colWidths=[34.4 * mm] * 5, repeatRows=1)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#172554")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#eff6ff")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTNAME", (0, 0), (-1, 0), bold_font),
        ("FONTNAME", (0, 1), (-1, 1), regular_font),
        ("FONTSIZE", (0, 0), (-1, -1), 7.2),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story += [summary_table, Spacer(1, 2 * mm), Paragraph(_safe_paragraph(_label("score_note", language), language), styles["WGSmall"])]
    story.append(Paragraph(_safe_paragraph(_label("findings", language), language), styles["WGHeading"]))

    if not failed:
        story.append(Paragraph(_safe_paragraph(_label("no_findings", language), language), styles["WGBody"]))
    for item in failed:
        severity = _label(item.severity, language) if rtl else item.severity.upper()
        if rtl:
            translated = CHECK_TRANSLATIONS.get(item.check_id, (item.name, item.category, item.description))
            item_name, _item_category, item_description = translated
            item_recommendation = RECOMMENDATIONS_FA.get(item.check_id, item.recommendation)
        else:
            item_name, item_description, item_recommendation = item.name, item.description, item.recommendation
        block = [
            Paragraph(f"{escape(_shape(severity, language))} — {escape(_shape(item_name, language))} ({escape(item.check_id)})", styles["WGFinding"]),
            Paragraph(_safe_paragraph(item_description, language), styles["WGBody"]),
            Paragraph(f"<b>{_safe_paragraph(_label('recommendation', language), language)}:</b> {_safe_paragraph(item_recommendation, language)}", styles["WGBody"]),
            Paragraph(f"<b>{_safe_paragraph(_label('evidence', language), language)}:</b> {_safe_paragraph(str(item.evidence)[:1200], language)}", styles["WGSmall"]),
        ]
        story.append(KeepTogether(block))

    story += [
        Paragraph(_safe_paragraph(_label("scope", language), language), styles["WGHeading"]),
        Paragraph(_safe_paragraph(_label("scope_text", language), language), styles["WGBody"]),
    ]

    def draw_footer(canvas, _doc):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#e2e8f0"))
        canvas.line(16 * mm, 13 * mm, A4[0] - 16 * mm, 13 * mm)
        canvas.setFont(regular_font, 7)
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.drawString(16 * mm, 8 * mm, _shape(_label("footer", language), language))
        canvas.drawRightString(A4[0] - 16 * mm, 8 * mm, f"{_shape(_label('page', language), language)} {canvas.getPageNumber()}")
        canvas.restoreState()

    doc.build(story, onFirstPage=draw_footer, onLaterPages=draw_footer)
    output.seek(0)
    return output
