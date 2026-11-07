import io
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

def _table(data, widths=None):
    t = Table(data, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F3864")),
                           ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("FONTSIZE", (0, 0), (-1, -1), 8),
                           ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                           ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F2F2F2")])]))
    return t

def build_pdf(df, max_rows=50) -> bytes:
    """df: alerts dataframe (as returned by db.get_alerts). Returns PDF bytes."""
    buf = io.BytesIO(); s = getSampleStyleSheet()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), title="NIDS Alert Summary")
    el = [Paragraph("NIDS Alert Summary", s["Title"]),
          Paragraph(f"Generated {datetime.now():%Y-%m-%d %H:%M} | {len(df)} alerts | prototype output, "
                    "not proof that an attack occurred.", s["Normal"]), Spacer(1, 12)]
    summ = df.groupby(["severity", "review_status"]).size().reset_index(name="count")
    el += [Paragraph("Severity / review status", s["Heading2"]),
           _table([["Severity", "Review status", "Count"]] + summ.values.tolist(), [100, 120, 60]), Spacer(1, 12)]
    cols = ["event_time", "severity", "source", "destination", "protocol", "reason", "confidence", "review_status"]
    top = df.sort_values("confidence", ascending=False).head(max_rows)[cols]
    el += [Paragraph(f"Top {len(top)} alerts by confidence", s["Heading2"]),
           _table([cols] + top.astype(str).values.tolist())]
    doc.build(el); return buf.getvalue()
