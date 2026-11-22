"""
PhishIntel — PDF Report Generator (ReportLab Platypus)
Builds documentation/PhishIntel_Final_Project_Report.pdf adhering strictly to VTU B.E. standards.
Target page count: ~60-65 pages.
"""

import os
import sys
from pathlib import Path
import html
import re

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_JUSTIFY, TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.pdfgen import canvas

# Import master report data
sys.path.insert(0, str(Path(__file__).parent))
from report_data import REPORT_STRUCTURE


def clean_prose(text: str) -> str:
    """Escapes XML entities and formats markdown in prose for ReportLab Paragraph."""
    if not text:
        return ""
    t = html.escape(str(text), quote=False)
    t = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', t)
    t = re.sub(r'`(.+?)`', r'<font face="Courier" color="#0F172A"><b>\1</b></font>', t)
    t = t.replace('\n', '<br/>')
    return t


def clean_code(text: str) -> str:
    """Escapes XML entities and preserves spacing/newlines for ReportLab code blocks."""
    if not text:
        return ""
    t = html.escape(str(text), quote=False)
    t = t.replace('\n', '<br/>').replace(' ', '&nbsp;')
    return t


def clean_cell(text) -> str:
    """Escapes table cell text and handles bold markers."""
    if text is None:
        return ""
    t = html.escape(str(text), quote=False)
    t = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', t)
    t = re.sub(r'`(.+?)`', r'<font face="Courier" color="#0F172A"><b>\1</b></font>', t)
    t = t.replace('\n', '<br/>')
    return t


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas to dynamically compute and draw running headers and footers with total page count."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            page_num = self._pageNumber
            
            # Suppress headers and footers on cover page (Page 1)
            if page_num > 1:
                self.saveState()
                self.setFont("Times-Roman", 8.5)
                self.setFillColor(colors.HexColor("#64748B"))
                
                # Running Header
                self.drawString(72, A4[1] - 46, "Dept. of Computer Science & Engineering, College of Engineering")
                self.drawRightString(A4[0] - 72, A4[1] - 46, "PhishIntel: Forensic Phishing Detection & IP Intelligence")
                self.setStrokeColor(colors.HexColor("#CBD5E1"))
                self.setLineWidth(0.6)
                self.line(72, A4[1] - 50, A4[0] - 72, A4[1] - 50)
                
                # Running Footer
                self.line(72, 52, A4[0] - 72, 52)
                self.drawString(72, 40, "VTU Final Year Project Report (2026–2027)")
                self.drawRightString(A4[0] - 72, 40, f"Page {page_num} of {num_pages}")
                self.restoreState()
                
            super().showPage()
        super().save()


def build_pdf(output_path):
    print(f"Building PDF report at: {output_path}")
    
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        leftMargin=72,
        rightMargin=72,
        topMargin=54,
        bottomMargin=54
    )
    
    styles = getSampleStyleSheet()
    
    # Custom Typography Styles
    body_style = ParagraphStyle(
        'VTU_Body',
        parent=styles['Normal'],
        fontName='Times-Roman',
        fontSize=11,
        leading=15.5,
        alignment=TA_JUSTIFY,
        spaceAfter=6,
        textColor=colors.HexColor("#1E293B")
    )
    
    chapter_style = ParagraphStyle(
        'VTU_Chapter',
        parent=styles['Heading1'],
        fontName='Times-Bold',
        fontSize=15,
        leading=19,
        alignment=TA_LEFT,
        spaceBefore=14,
        spaceAfter=12,
        textColor=colors.HexColor("#003366")
    )
    
    section_style = ParagraphStyle(
        'VTU_Section',
        parent=styles['Heading2'],
        fontName='Times-Bold',
        fontSize=12.5,
        leading=16,
        alignment=TA_LEFT,
        spaceBefore=10,
        spaceAfter=5,
        textColor=colors.HexColor("#0F172A")
    )
    
    cover_title_style = ParagraphStyle(
        'VTU_Cover_Title',
        fontName='Times-Bold',
        fontSize=16,
        leading=21,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#0F172A")
    )
    
    cover_sub_style = ParagraphStyle(
        'VTU_Cover_Sub',
        fontName='Times-Italic',
        fontSize=11,
        leading=15,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#334155")
    )
    
    cover_meta_style = ParagraphStyle(
        'VTU_Cover_Meta',
        fontName='Times-Roman',
        fontSize=11,
        leading=15,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#1E293B")
    )
    
    code_style = ParagraphStyle(
        'VTU_Code',
        fontName='Courier',
        fontSize=7.5,
        leading=9.5,
        alignment=TA_LEFT,
        textColor=colors.HexColor("#0F172A"),
        backColor=colors.HexColor("#F8FAFC"),
        borderPadding=4,
        spaceBefore=3,
        spaceAfter=5
    )
    
    table_cell_style = ParagraphStyle(
        'VTU_TableCell',
        fontName='Times-Roman',
        fontSize=8.5,
        leading=11,
        alignment=TA_LEFT,
        textColor=colors.HexColor("#1E293B")
    )
    
    table_hdr_style = ParagraphStyle(
        'VTU_TableHdr',
        fontName='Times-Bold',
        fontSize=9,
        leading=11.5,
        alignment=TA_LEFT,
        textColor=colors.white
    )
    
    story = []
    fm = REPORT_STRUCTURE["front_matter"]
    
    # =========================================================================
    # 1. COVER PAGE
    # =========================================================================
    story.append(Spacer(1, 25))
    story.append(Paragraph(f"<b>{fm['vtu_university']}</b>", cover_meta_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="80%", thickness=1.5, color=colors.HexColor("#003366"), spaceBefore=5, spaceAfter=20))
    story.append(Spacer(1, 15))
    story.append(Paragraph(fm['title'], cover_title_style))
    story.append(Spacer(1, 15))
    story.append(Paragraph(fm['subtitle'], cover_sub_style))
    story.append(Spacer(1, 40))
    
    story.append(Paragraph("<b>Submitted by:</b>", cover_meta_style))
    story.append(Spacer(1, 5))
    story.append(Paragraph(f"<b>{fm['student_name']}</b><br/>{fm['student_usn']}", cover_meta_style))
    story.append(Spacer(1, 25))
    
    story.append(Paragraph("<b>Under the Guidance of:</b>", cover_meta_style))
    story.append(Spacer(1, 5))
    story.append(Paragraph(f"<b>{fm['guide_name']}</b><br/>{fm['guide_designation']}", cover_meta_style))
    story.append(Spacer(1, 40))
    
    story.append(Paragraph(
        f"<b>{fm['department_name']}</b><br/>"
        f"<b>{fm['college_name']}</b><br/>"
        f"{fm['college_address']}<br/>"
        f"Academic Year: {fm['academic_year']}",
        cover_meta_style
    ))
    story.append(PageBreak())
    
    # =========================================================================
    # 2. CERTIFICATE
    # =========================================================================
    story.append(Spacer(1, 15))
    story.append(Paragraph(f"<b>{fm['college_name']}</b>", cover_meta_style))
    story.append(Paragraph(f"<b>{fm['department_name']}</b>", cover_meta_style))
    story.append(Spacer(1, 10))
    story.append(Paragraph("<b>CERTIFICATE</b>", cover_title_style))
    story.append(Spacer(1, 20))
    story.append(Paragraph(clean_prose(fm["certificate_text"]), body_style))
    story.append(Spacer(1, 60))
    
    # Signatures
    sig_data = [
        [
            Paragraph("________________________<br/><b>Signature of Guide</b><br/>" + fm["guide_name"], cover_meta_style),
            Paragraph("________________________<br/><b>Signature of HOD</b><br/>" + fm["hod_name"], cover_meta_style),
            Paragraph("________________________<br/><b>Signature of Principal</b><br/>" + fm["principal_name"], cover_meta_style)
        ]
    ]
    sig_tbl = Table(sig_data, colWidths=[150, 150, 150])
    sig_tbl.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    story.append(sig_tbl)
    story.append(PageBreak())
    
    # =========================================================================
    # 3. DECLARATION
    # =========================================================================
    story.append(Spacer(1, 15))
    story.append(Paragraph("<b>DECLARATION</b>", cover_title_style))
    story.append(Spacer(1, 20))
    story.append(Paragraph(clean_prose(fm["declaration_text"]), body_style))
    story.append(Spacer(1, 50))
    story.append(Paragraph(
        f"<b>{fm['student_name']}</b><br/>"
        f"USN: {fm['student_usn']}<br/>"
        f"Dept. of Computer Science & Engineering<br/>"
        f"{fm['college_name']}",
        ParagraphStyle('RightSig', parent=cover_meta_style, alignment=TA_RIGHT)
    ))
    story.append(PageBreak())
    
    # =========================================================================
    # 4. ACKNOWLEDGEMENTS
    # =========================================================================
    story.append(Spacer(1, 15))
    story.append(Paragraph("<b>ACKNOWLEDGEMENTS</b>", cover_title_style))
    story.append(Spacer(1, 15))
    for p_txt in fm["acknowledgement_text"].split("\n\n"):
        story.append(Paragraph(clean_prose(p_txt), body_style))
    story.append(PageBreak())
    
    # =========================================================================
    # 5. ABSTRACT
    # =========================================================================
    story.append(Spacer(1, 15))
    story.append(Paragraph("<b>ABSTRACT</b>", cover_title_style))
    story.append(Spacer(1, 15))
    for p_txt in fm["abstract"].split("\n\n"):
        story.append(Paragraph(clean_prose(p_txt), body_style))
    story.append(PageBreak())
    
    # =========================================================================
    # 6. TABLE OF CONTENTS
    # =========================================================================
    story.append(Spacer(1, 15))
    story.append(Paragraph("<b>TABLE OF CONTENTS</b>", cover_title_style))
    story.append(Spacer(1, 15))
    
    toc_entries = [
        ("Certificate", "ii"),
        ("Declaration", "iii"),
        ("Acknowledgements", "iv"),
        ("Abstract", "v"),
        ("List of Figures", "vii"),
        ("List of Tables", "vii"),
        ("List of Abbreviations", "viii"),
        ("Chapter 1: INTRODUCTION", "9"),
        ("Chapter 2: LITERATURE SURVEY", "15"),
        ("Chapter 3: EXISTING SYSTEM AND PROPOSED SYSTEM", "20"),
        ("Chapter 4: SYSTEM ANALYSIS AND DESIGN", "25"),
        ("Chapter 5: METHODOLOGY", "33"),
        ("Chapter 6: MACHINE LEARNING MODEL AND MATHEMATICAL FOUNDATION", "38"),
        ("Chapter 7: IMPLEMENTATION", "44"),
        ("Chapter 8: RESULTS AND PERFORMANCE ANALYSIS", "48"),
        ("Chapter 9: SOFTWARE TESTING AND QUALITY ASSURANCE", "57"),
        ("Chapter 10: CONCLUSION AND FUTURE ENHANCEMENTS", "62"),
        ("REFERENCES", "65"),
        ("Appendix A: Complete REST API Specification", "67"),
        ("Appendix B: Core Algorithm Pseudocode", "68"),
        ("Appendix C: Master Test Fixture Definitions", "70"),
        ("Appendix D: System Installation & Deployment Guide", "71"),
    ]
    
    toc_data = [[Paragraph("<b>Topic / Chapter Title</b>", table_hdr_style), Paragraph("<b>Page</b>", table_hdr_style)]]
    for title, pg in toc_entries:
        is_ch = title.startswith("Chapter") or title in ("REFERENCES", "Certificate", "Abstract")
        f_style = ParagraphStyle('TOCItem', fontName='Times-Bold' if is_ch else 'Times-Roman', fontSize=9, leading=12)
        toc_data.append([Paragraph(clean_cell(title), f_style), Paragraph(pg, f_style)])
        
    toc_tbl = Table(toc_data, colWidths=[390, 60])
    toc_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#003366")),
        ('ALIGN', (1,0), (1,-1), 'RIGHT'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('LINEBELOW', (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
    ]))
    story.append(toc_tbl)
    story.append(PageBreak())
    
    # =========================================================================
    # 7. LIST OF FIGURES & LIST OF TABLES
    # =========================================================================
    story.append(Spacer(1, 15))
    story.append(Paragraph("<b>LIST OF FIGURES</b>", cover_title_style))
    story.append(Spacer(1, 15))
    
    figures_data = [[Paragraph("<b>Figure No.</b>", table_hdr_style), Paragraph("<b>Figure Title / Caption</b>", table_hdr_style), Paragraph("<b>Page</b>", table_hdr_style)]]
    figures_list = [
        ("Figure 4.1", "Comprehensive System Topology and Multi-Modal Data Pipeline of PhishIntel", "26"),
        ("Figure 4.2", "Data Flow Diagram Level 0 Context and Subsystem Decomposition", "26"),
        ("Figure 4.3", "UML Activity Diagram Depicting Sequential Execution Logic and Decision Branches", "28"),
        ("Figure 6.1", "DistilBERT 6-Layer Bidirectional Transformer Architecture & Attention Flow", "39"),
        ("Figure 8.1", "Confusion Matrix Breakdown on Locked Test Partition (TN=591, FP=5, FN=4, TP=124)", "49"),
        ("Figure 8.2", "Risk Score Meter Calibration Comparison: Raw Model Logit vs Corroboration-Dampened Score", "56"),
    ]
    for f_no, f_title, pg in figures_list:
        figures_data.append([
            Paragraph(clean_cell(f_no), table_cell_style),
            Paragraph(clean_cell(f_title), table_cell_style),
            Paragraph(pg, table_cell_style)
        ])
    fig_tbl = Table(figures_data, colWidths=[70, 330, 50])
    fig_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#003366")),
        ('ALIGN', (2,0), (2,-1), 'RIGHT'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2.5),
        ('TOPPADDING', (0,0), (-1,-1), 2.5),
        ('LINEBELOW', (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
    ]))
    story.append(fig_tbl)
    story.append(Spacer(1, 20))
    
    story.append(Paragraph("<b>LIST OF TABLES</b>", cover_title_style))
    story.append(Spacer(1, 15))
    
    tables_data_list = [
        ("Table 2.1", "Comparative Analysis Matrix of State-of-the-Art Phishing Detection Paradigms", "18"),
        ("Table 3.1", "Comparative Architectural Advantages of PhishIntel vs Traditional Systems", "21"),
        ("Table 4.1", "PhishIntel Subsystem Architecture & Technology Implementation Mapping", "31"),
        ("Table 5.1", "PhishMMF Cleaned Dataset Provenance & Sub-Corpus Composition", "33"),
        ("Table 5.2", "Leakage-Safe Stratified Partition Manifest & Cryptographic SHA-256 Hashes", "35"),
        ("Table 6.1", "DistilBERT Model Architecture & Training Hyperparameters", "41"),
        ("Table 6.2", "Epoch-by-Epoch Training & Validation Convergence Dynamics", "42"),
        ("Table 8.1", "Dataset Sample Distribution Across Source Partitions", "48"),
        ("Table 8.2", "Comprehensive Classification Report on Locked Test Set (N=724)", "49"),
        ("Table 8.3", "Confusion Matrix Breakdown on Locked Test Set", "49"),
        ("Table 8.4", "Detailed Forensic Audit of All 9 Test Errors (5 FPs, 4 FNs)", "51"),
        ("Table 8.5", "Live Socket Fixture Verification Results across 10 Scenarios", "53"),
        ("Table 8.6", "Evidence Fusion Validation on Control Emails and Real Phishing Attacks", "55"),
        ("Table 9.1", "Comprehensive Master Test Case Matrix (Unit, Integration, Security)", "59"),
        ("Table 9.2", "Software Test Suite Summary & Pass Rate Breakdown", "61"),
    ]
    tbl_data_table = [[Paragraph("<b>Table No.</b>", table_hdr_style), Paragraph("<b>Table Title</b>", table_hdr_style), Paragraph("<b>Page</b>", table_hdr_style)]]
    for t_no, t_title, pg in tables_data_list:
        tbl_data_table.append([
            Paragraph(clean_cell(t_no), table_cell_style),
            Paragraph(clean_cell(t_title), table_cell_style),
            Paragraph(pg, table_cell_style)
        ])
    tbl_tbl = Table(tbl_data_table, colWidths=[70, 330, 50])
    tbl_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#003366")),
        ('ALIGN', (2,0), (2,-1), 'RIGHT'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2.5),
        ('TOPPADDING', (0,0), (-1,-1), 2.5),
        ('LINEBELOW', (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
    ]))
    story.append(tbl_tbl)
    story.append(PageBreak())
    
    # =========================================================================
    # 8. LIST OF ABBREVIATIONS
    # =========================================================================
    story.append(Spacer(1, 15))
    story.append(Paragraph("<b>LIST OF ABBREVIATIONS</b>", cover_title_style))
    story.append(Spacer(1, 15))
    
    abb_data = [[Paragraph("<b>Abbreviation</b>", table_hdr_style), Paragraph("<b>Expanded Definition / Standard Reference</b>", table_hdr_style)]]
    for abb, desc in fm["abbreviations"]:
        abb_data.append([
            Paragraph(f"<b>{clean_cell(abb)}</b>", table_cell_style),
            Paragraph(clean_cell(desc), table_cell_style)
        ])
    abb_tbl = Table(abb_data, colWidths=[90, 360])
    abb_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#003366")),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2),
        ('TOPPADDING', (0,0), (-1,-1), 2),
        ('LINEBELOW', (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
    ]))
    story.append(abb_tbl)
    story.append(PageBreak())
    
    # =========================================================================
    # 9. CHAPTERS 1 TO 10
    # =========================================================================
    tables_spec = REPORT_STRUCTURE["tables"]
    
    for ch in REPORT_STRUCTURE["chapters"]:
        story.append(Spacer(1, 15))
        story.append(Paragraph(f"<b>{clean_prose(ch['title'])}</b>", chapter_style))
        story.append(Spacer(1, 8))
        
        for sec in ch["sections"]:
            story.append(Paragraph(f"<b>{clean_prose(sec['heading'])}</b>", section_style))
            story.append(Spacer(1, 4))
            
            for p_txt in sec["content"].split("\n\n"):
                p_clean = p_txt.strip()
                if not p_clean:
                    continue
                if p_clean.startswith("```"):
                    code_clean = p_clean.replace("```text", "").replace("```python", "").replace("```powershell", "").replace("```", "").strip()
                    story.append(Paragraph(clean_code(code_clean), code_style))
                else:
                    story.append(Paragraph(clean_prose(p_clean), body_style))
                    
            # Insert Tables if referenced
            if sec["heading"].startswith("2.10"):
                story.append(render_table_pdf(tables_spec["table_2_1"], table_cell_style, table_hdr_style, [90, 110, 60, 55, 65, 70]))
            elif sec["heading"].startswith("3.5"):
                story.append(render_table_pdf(tables_spec["table_3_1"], table_cell_style, table_hdr_style, [100, 110, 110, 130]))
            elif sec["heading"].startswith("4.8"):
                story.append(render_table_pdf(tables_spec["table_4_1"], table_cell_style, table_hdr_style, [90, 110, 80, 80, 90]))
            elif sec["heading"].startswith("5.2"):
                story.append(render_table_pdf(tables_spec["table_5_1"], table_cell_style, table_hdr_style, [90, 60, 130, 55, 55, 60]))
            elif sec["heading"].startswith("5.4"):
                story.append(render_table_pdf(tables_spec["table_5_2"], table_cell_style, table_hdr_style, [90, 110, 55, 65, 65, 65]))
            elif sec["heading"].startswith("6.9"):
                story.append(render_table_pdf(tables_spec["table_6_1"], table_cell_style, table_hdr_style, [120, 110, 220]))
            elif sec["heading"].startswith("6.10"):
                story.append(render_table_pdf(tables_spec["table_6_2"], table_cell_style, table_hdr_style, [60, 50, 50, 50, 50, 50, 50, 50, 40]))
            elif sec["heading"].startswith("8.5"):
                story.append(render_table_pdf(tables_spec["table_8_2"], table_cell_style, table_hdr_style, [80, 40, 70, 70, 60, 40, 45, 45]))
            elif sec["heading"].startswith("8.6"):
                story.append(render_table_pdf(tables_spec["table_8_3"], table_cell_style, table_hdr_style, [110, 60, 80, 200]))
            elif sec["heading"].startswith("8.8"):
                story.append(render_table_pdf(tables_spec["table_8_4"], table_cell_style, table_hdr_style, [75, 35, 45, 45, 45, 100, 105]))
            elif sec["heading"].startswith("8.10"):
                story.append(render_table_pdf(tables_spec["table_8_5"], table_cell_style, table_hdr_style, [20, 110, 80, 45, 50, 50, 45, 50]))
            elif sec["heading"].startswith("8.11"):
                story.append(render_table_pdf(tables_spec["table_8_6"], table_cell_style, table_hdr_style, [100, 100, 65, 65, 60, 35, 25]))
            elif sec["heading"].startswith("9.7"):
                story.append(render_table_pdf(tables_spec["table_9_1"], table_cell_style, table_hdr_style, [55, 50, 120, 100, 95, 30]))
                
        story.append(PageBreak())
        
    # =========================================================================
    # 10. REFERENCES
    # =========================================================================
    story.append(Spacer(1, 15))
    story.append(Paragraph("<b>REFERENCES</b>", chapter_style))
    story.append(Spacer(1, 10))
    ref_style = ParagraphStyle(
        'VTU_Ref',
        fontName='Times-Roman',
        fontSize=9,
        leading=12.5,
        alignment=TA_JUSTIFY,
        leftIndent=20,
        firstLineIndent=-20,
        spaceAfter=5,
        textColor=colors.HexColor("#1E293B")
    )
    for ref in REPORT_STRUCTURE["references"]:
        story.append(Paragraph(clean_prose(ref), ref_style))
    story.append(PageBreak())
    
    # =========================================================================
    # 11. APPENDICES
    # =========================================================================
    for app_key, app in REPORT_STRUCTURE["appendices"].items():
        story.append(Spacer(1, 15))
        story.append(Paragraph(f"<b>{clean_prose(app['title'])}</b>", chapter_style))
        story.append(Spacer(1, 10))
        for p_txt in app["content"].split("\n\n"):
            p_clean = p_txt.strip()
            if not p_clean:
                continue
            if p_clean.startswith("```"):
                code_clean = p_clean.replace("```text", "").replace("```powershell", "").replace("```python", "").replace("```", "").strip()
                story.append(Paragraph(clean_code(code_clean), code_style))
            elif p_clean.startswith("### "):
                story.append(Paragraph(f"<b>{clean_prose(p_clean.replace('### ', ''))}</b>", section_style))
            else:
                story.append(Paragraph(clean_prose(p_clean), body_style))
        story.append(PageBreak())
        
    # Build document
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"PDF report successfully generated at: {output_path}")


def render_table_pdf(tbl_spec, cell_style, hdr_style, col_widths=None):
    """Generates a styled ReportLab Table flowable."""
    content = []
    
    # Caption
    caption = Paragraph(f"<b>{clean_prose(tbl_spec['title'])}</b>", ParagraphStyle('Cap', fontName='Times-Bold', fontSize=9.5, leading=12, textColor=colors.HexColor("#003366"), spaceBefore=6, spaceAfter=4))
    
    # Header row
    hdr_row = [Paragraph(f"<b>{clean_cell(h)}</b>", hdr_style) for h in tbl_spec["headers"]]
    data = [hdr_row]
    
    for r_idx, row in enumerate(tbl_spec["rows"]):
        data_row = [Paragraph(clean_cell(val), cell_style) for val in row]
        data.append(data_row)
        
    num_cols = len(tbl_spec["headers"])
    if not col_widths:
        total_w = 450
        col_w = total_w / num_cols
        col_widths = [col_w] * num_cols
        
    tbl = Table(data, colWidths=col_widths, repeatRows=1)
    
    t_style = [
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#003366")),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 2.5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2.5),
        ('LEFTPADDING', (0,0), (-1,-1), 4),
        ('RIGHTPADDING', (0,0), (-1,-1), 4),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
    ]
    
    for i in range(1, len(data)):
        if i % 2 == 0:
            t_style.append(('BACKGROUND', (0, i), (-1, i), colors.HexColor("#F8FAFC")))
            
    tbl.setStyle(TableStyle(t_style))
    
    return KeepTogether([caption, tbl, Spacer(1, 8)])


if __name__ == "__main__":
    out_file = Path(__file__).parent / "PhishIntel_Final_Project_Report.pdf"
    build_pdf(out_file)
