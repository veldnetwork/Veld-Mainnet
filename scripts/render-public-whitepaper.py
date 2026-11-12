#!/usr/bin/env python3
"""Render WHITEPAPER.md in the existing public PDF's Arial/green layout.

Requires ReportLab 4.4.10 and the licensed Arial fonts installed on Windows.
No new cover, navigation, palette or document design is introduced.
"""

from pathlib import Path
import argparse
import html
import os
import re

import reportlab
from reportlab import rl_config
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=root / "docs/WHITEPAPER.md")
    parser.add_argument("--output", type=Path, default=root / "website/whitepaper.pdf")
    parser.add_argument(
        "--fonts",
        type=Path,
        default=Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts",
    )
    args = parser.parse_args()
    if reportlab.Version != "4.4.10":
        raise SystemExit("Use ReportLab 4.4.10 for reproducible output.")
    for name, file in [
        ("VeldArial", "arial.ttf"),
        ("VeldArialBold", "arialbd.ttf"),
        ("VeldArialItalic", "ariali.ttf"),
    ]:
        pdfmetrics.registerFont(TTFont(name, str(args.fonts / file)))
    pdfmetrics.registerFontFamily(
        "VeldArial",
        normal="VeldArial",
        bold="VeldArialBold",
        italic="VeldArialItalic",
        boldItalic="VeldArialBold",
    )
    rl_config.invariant = 1
    ink, green, rule = [colors.HexColor(c) for c in ("#15241d", "#087f42", "#c8d9cf")]
    body = ParagraphStyle(
        "body",
        fontName="VeldArial",
        fontSize=8.9,
        leading=13.1,
        textColor=ink,
        spaceAfter=7,
        allowWidows=0,
        allowOrphans=0,
    )
    styles = {
        "body": body,
        "title": ParagraphStyle(
            "title",
            parent=body,
            fontName="VeldArialBold",
            fontSize=20,
            leading=24,
            spaceAfter=16,
            keepWithNext=True,
        ),
        "h2": ParagraphStyle(
            "h2",
            parent=body,
            fontName="VeldArialBold",
            fontSize=13.2,
            leading=17,
            textColor=green,
            spaceBefore=12,
            spaceAfter=8,
            keepWithNext=True,
        ),
        "h3": ParagraphStyle(
            "h3",
            parent=body,
            fontName="VeldArialBold",
            fontSize=10.5,
            leading=14,
            spaceBefore=9,
            spaceAfter=7,
            keepWithNext=True,
        ),
        "cell": ParagraphStyle(
            "cell", parent=body, fontSize=7.8, leading=10.8, spaceAfter=0
        ),
        "code": ParagraphStyle(
            "code",
            parent=body,
            fontName="Courier",
            fontSize=7,
            leading=11,
            leftIndent=8,
            textColor=colors.HexColor("#62746b"),
        ),
        "bullet": ParagraphStyle(
            "bullet", parent=body, leftIndent=10, firstLineIndent=-8
        ),
    }

    def inline(text):
        text = html.escape(text)
        text = re.sub(
            r"\[([^\]]+)\]\((https?://[^)]+)\)",
            r'<link href="\2" color="#087f42">\1</link>',
            text,
        )
        text = re.sub(r"`([^`]+)`", r'<font name="Courier" size="7">\1</font>', text)
        text = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", text)
        return text

    def para(text, style="body"):
        return Paragraph(inline(text), styles[style])

    story = []
    lines = args.input.read_text(encoding="utf-8").splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        i += 1
        if not line or line == "---":
            continue
        if line.startswith(("# ", "## ", "### ")):
            level = len(line.split(" ", 1)[0])
            story.append(para(line[level + 1 :], {1: "title", 2: "h2", 3: "h3"}[level]))
        elif line.startswith("```"):
            block = []
            while i < len(lines) and not lines[i].startswith("```"):
                block.append(html.escape(lines[i]))
                i += 1
            i += 1
            story.append(Paragraph("<br/>".join(block), styles["code"]))
        elif line.startswith("|"):
            rows = []
            i -= 1
            while i < len(lines) and lines[i].strip().startswith("|"):
                cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                i += 1
                if not all(re.fullmatch(r"[-: ]+", c) for c in cells):
                    rows.append(cells)
            n = len(rows[0])
            weights = (
                [0.4, 0.6]
                if n == 2 and rows[0][0] == "Area"
                else (
                    [0.45, 0.55]
                    if n == 2
                    else ([0.4, 0.15, 0.15, 0.15, 0.15] if n == 5 else [1 / n] * n)
                )
            )
            data = [
                [para("**" + c + "**" if j == 0 else c, "cell") for c in row]
                for j, row in enumerate(rows)
            ]
            table = Table(
                data,
                colWidths=[(A4[0] - 94) * w for w in weights],
                repeatRows=1,
                hAlign="LEFT",
            )
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0f6f2")),
                        ("GRID", (0, 0), (-1, -1), 0.35, rule),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 6),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                        ("TOPPADDING", (0, 0), (-1, -1), 4.5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4.5),
                    ]
                )
            )
            story.extend([table, Spacer(1, 9)])
        elif line.startswith("- "):
            story.append(para("- " + line[2:], "bullet"))
        else:
            block = [line]
            while (
                i < len(lines)
                and lines[i].strip()
                and not lines[i].startswith(("#", "|", "```", "- "))
            ):
                block.append(lines[i].strip())
                i += 1
            story.append(para(" ".join(block)))

    def page(canvas, doc):
        canvas.saveState()
        width, height = A4
        canvas.setStrokeColor(rule)
        canvas.setLineWidth(0.6)
        canvas.line(41, height - 39, width - 41, height - 39)
        canvas.line(41, 37, width - 41, 37)
        canvas.setFillColor(green)
        canvas.setFont("VeldArialBold", 7.5)
        canvas.drawString(41, height - 31, "VELD  /  PROTOCOL WHITEPAPER")
        canvas.setFillColor(colors.HexColor("#62746b"))
        canvas.setFont("VeldArial", 7.5)
        canvas.drawString(41, 26, "veld-public-mainnet-v2  /  3.3.4")
        canvas.drawRightString(width - 41, 26, str(doc.page))
        canvas.restoreState()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(args.output),
        pagesize=A4,
        leftMargin=41,
        rightMargin=41,
        topMargin=52,
        bottomMargin=46,
        title="VELD Protocol Whitepaper",
        author="Veld Network",
        subject="3.3.4 - activation at block 34750",
    )
    doc.build(story, onFirstPage=page, onLaterPages=page)
    print(args.output)


if __name__ == "__main__":
    main()
