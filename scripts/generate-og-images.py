#!/usr/bin/env python3
"""
Generate high-fidelity 1200x630 PNG Open Graph images for all tools matching DESIGN.md.
"""
import os
from PIL import Image, ImageDraw, ImageFont

OUTPUT_DIR = "/home/ashutosh/Desktop/CMS/public"
SANS_BOLD = "/usr/share/fonts/liberation-sans-fonts/LiberationSans-Bold.ttf"
SANS_REG = "/usr/share/fonts/liberation-sans-fonts/LiberationSans-Regular.ttf"
MONO_REG = "/usr/share/fonts/liberation-mono-fonts/LiberationMono-Regular.ttf"
MONO_BOLD = "/usr/share/fonts/liberation-mono-fonts/LiberationMono-Bold.ttf"

CARDS = [
    {
        "filename": "og-default.png",
        "eyebrow": "DETERMINISTIC WEB INTELLIGENCE · CLOUDFLARE EDGE",
        "title": "CMS Detector",
        "title2": "Identify Any Website's Tech Stack",
        "subtitle": "Discover CMS platforms, frontend frameworks, hosting providers, and CDNs with verifiable evidence.",
        "badge": "100% Free · Evidence-Based",
    },
    {
        "filename": "og-shopify.png",
        "eyebrow": "SHOPIFY STOREFRONT INTELLIGENCE · EDGE PROBE",
        "title": "Shopify Theme Detector",
        "title2": "Find Any Store's Active Theme",
        "subtitle": "Instant lookup for Shopify themes, official Theme Store links, custom modifications, and store IDs.",
        "badge": "Shopify 2.0 & Headless Ready",
    },
    {
        "filename": "og-wordpress.png",
        "eyebrow": "WORDPRESS STACK INSPECTOR · STYLE.CSS PARSER",
        "title": "WordPress Theme Detector",
        "title2": "Inspect Themes, Parents & Plugins",
        "subtitle": "Extract active theme names, child themes, author details, version numbers, and active plugins instantly.",
        "badge": "WordPress Core & Plugin Fingerprinting",
    },
    {
        "filename": "og-martech.png",
        "eyebrow": "MARTECH & ANALYTICS STACK INSPECTOR",
        "title": "Growth & Marketing Detector",
        "title2": "Pixels, Analytics, CRM & Payments",
        "subtitle": "Identify Google Tag Manager containers, Meta pixels, GA4 measurement IDs, Klaviyo, and Stripe checkout.",
        "badge": "GTM Container & SDK Extraction",
    },
    {
        "filename": "og-security.png",
        "eyebrow": "SECURITY, THREATS & COMPLIANCE SCANNER",
        "title": "Is This Site Safe?",
        "title2": "Website Safety & Header Checker",
        "subtitle": "Check for phishing indicators, malware signals, suspicious redirects, TLS certificate, and security headers.",
        "badge": "Edge Threat & Security Analysis",
    },
]

def render_card(card):
    width, height = 1200, 630
    img = Image.new("RGBA", (width, height), (11, 11, 11, 255))
    draw = ImageDraw.Draw(img)

    # 1. Subtle background grid / accent lines
    grid_color = (33, 33, 33, 160)
    for x in range(0, width, 60):
        draw.line([(x, 0), (x, height)], fill=grid_color, width=1)
    for y in range(0, height, 60):
        draw.line([(0, y), (width, y)], fill=grid_color, width=1)

    # Gradient-like ambient glow overlay in top right & bottom left
    # Draw dark overlay on top to keep text contrast high
    overlay = Image.new("RGBA", (width, height), (11, 11, 11, 215))
    img = Image.alpha_composite(img, overlay)
    draw = ImageDraw.Draw(img)

    # Outer border
    draw.rectangle([(20, 20), (width - 20, height - 20)], outline=(53, 53, 53, 255), width=2)
    draw.rectangle([(22, 22), (width - 22, height - 22)], outline=(25, 25, 25, 255), width=1)

    # Fonts
    font_brand = ImageFont.truetype(SANS_BOLD, 26)
    font_eyebrow = ImageFont.truetype(MONO_BOLD, 16)
    font_title1 = ImageFont.truetype(SANS_BOLD, 68)
    font_title2 = ImageFont.truetype(SANS_REG, 42)
    font_sub = ImageFont.truetype(SANS_REG, 24)
    font_badge = ImageFont.truetype(MONO_REG, 17)
    font_domain = ImageFont.truetype(SANS_BOLD, 20)

    # Header brand row
    # Brand dot
    draw.ellipse([(64, 62), (84, 82)], fill=(243, 100, 88, 255))
    draw.text((96, 59), "CMS Detector AI", fill=(255, 255, 255, 255), font=font_brand)

    # Top right domain badge
    domain_box = [(width - 290, 54), (width - 64, 92)]
    draw.rounded_rectangle(domain_box, radius=8, fill=(33, 33, 33, 255), outline=(60, 71, 88, 255), width=1)
    draw.text((width - 270, 62), "cmsdetectorai.com", fill=(243, 100, 88, 255), font=font_domain)

    # Eyebrow tag
    draw.text((64, 150), card["eyebrow"], fill=(185, 185, 185, 255), font=font_eyebrow)

    # Main titles
    draw.text((64, 190), card["title"], fill=(255, 255, 255, 255), font=font_title1)
    draw.text((64, 276), card["title2"], fill=(243, 100, 88, 255), font=font_title2)

    # Subtitle (wrapped)
    draw.text((64, 360), card["subtitle"], fill=(185, 185, 185, 255), font=font_sub)

    # Horizontal hairline divider
    draw.line([(64, 490), (width - 64, 490)], fill=(53, 53, 53, 255), width=1)

    # Bottom badge / feature pill
    pill_box = [(64, 520), (520, 570)]
    draw.rounded_rectangle(pill_box, radius=6, fill=(33, 33, 33, 255), outline=(53, 53, 53, 255), width=1)
    # Green status dot
    draw.ellipse([(84, 540), (94, 550)], fill=(55, 205, 132, 255))
    draw.text((106, 534), card["badge"], fill=(255, 255, 255, 255), font=font_badge)

    # Bottom right label
    draw.text((width - 320, 534), "Free · Real-Time · No Sign-Up", fill=(121, 121, 121, 255), font=font_badge)

    out_path = os.path.join(OUTPUT_DIR, card["filename"])
    img.convert("RGB").save(out_path, format="PNG", optimize=True)
    print(f"Generated {out_path} ({os.path.getsize(out_path)} bytes)")

for c in CARDS:
    render_card(c)
