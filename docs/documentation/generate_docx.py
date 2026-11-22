"""
PhishIntel — DOCX Report Generator
Builds documentation/PhishIntel_Final_Project_Report.docx adhering to VTU B.E. standards.
"""

import os
import sys
from pathlib import Path

import docx
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn

# Import master report data
sys.path.insert(0, str(Path(__file__).parent))
from report_data import REPORT_STRUCTURE


def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    """Sets cell padding in dxa (1 pt = 20 dxa)."""
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = OxmlElement('w:tcMar')
    for m, val in [('top', top), ('bottom', bottom), ('left', left), ('right', right)]:
        node = OxmlElement(f'w:{m}')
        node.set(qn('w:w'), str(val))
        node.set(qn('w:type'), 'dxa')
        tcMar.append(node)
    tcPr.append(tcMar)


def set_cell_shading(cell, color_hex):
    """Sets background shading of a cell."""
    shading_xml = f'<w:shd {nsdecls("w")} w:fill="{color_hex}"/>'
    cell._tc.get_or_add_tcPr().append(parse_xml(shading_xml))


def set_table_borders(table, color="CCCCCC", sz="4", val="single"):
    """Sets clean subtle borders for tables."""
    tblPr = table._tbl.tblPr
    borders_xml = f"""
    <w:tblBorders {nsdecls("w")}>
        <w:top w:val="{val}" w:sz="{sz}" w:space="0" w:color="{color}"/>
        <w:left w:val="none"/>
        <w:bottom w:val="{val}" w:sz="{sz}" w:space="0" w:color="{color}"/>
        <w:right w:val="none"/>
        <w:insideH w:val="{val}" w:sz="{sz}" w:space="0" w:color="{color}"/>
        <w:insideV w:val="none"/>
    </w:tblBorders>
    """
    tblPr.append(parse_xml(borders_xml))


def add_page_number_to_run(run):
    """Injects dynamic page number field into a run."""
    fldSimple = OxmlElement('w:fldSimple')
    fldSimple.set(qn('w:instr'), 'PAGE')
    run._r.append(fldSimple)


def build_docx(output_path):
    print(f"Building DOCX report at: {output_path}")
    doc = Document()
    
    # 1. Page Setup: A4, 1-inch margins
    sections = doc.sections
    for section in sections:
        section.page_width = Inches(8.27)
        section.page_height = Inches(11.69)
        section.top_margin = Inches(1.0)
        section.bottom_margin = Inches(1.0)
        section.left_margin = Inches(1.0)
        section.right_margin = Inches(1.0)
        
        # Configure Header
        header = section.header
        hp = header.paragraphs[0]
        hp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        hrun = hp.add_run("PhishIntel: Forensic Phishing Detection & IP Intelligence")
        hrun.font.name = "Times New Roman"
        hrun.font.size = Pt(8.5)
        hrun.font.color.rgb = RGBColor(120, 120, 120)
        
        # Configure Footer
        footer = section.footer
        fp = footer.paragraphs[0]
        fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
        frun1 = fp.add_run("VTU Final Year Project Report — Page ")
        frun1.font.name = "Times New Roman"
        frun1.font.size = Pt(9)
        frun1.font.color.rgb = RGBColor(120, 120, 120)
        add_page_number_to_run(fp.add_run())
        frun2 = fp.add_run(" of ")
        frun2.font.name = "Times New Roman"
        frun2.font.size = Pt(9)
        frun2.font.color.rgb = RGBColor(120, 120, 120)
        # Add NUMPAGES
        fld_num = OxmlElement('w:fldSimple')
        fld_num.set(qn('w:instr'), 'NUMPAGES')
        fp.add_run()._r.append(fld_num)

    # 2. Configure Typography Styles
    normal_style = doc.styles['Normal']
    normal_style.font.name = 'Times New Roman'
    normal_style.font.size = Pt(12)
    normal_style.font.color.rgb = RGBColor(30, 30, 30)
    normal_style.paragraph_format.line_spacing = 1.5
    normal_style.paragraph_format.space_after = Pt(6)
    normal_style.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY

    # 3. COVER PAGE
    fm = REPORT_STRUCTURE["front_matter"]
    
    cp_title = doc.add_paragraph()
    cp_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    cp_title.paragraph_format.space_before = Pt(36)
    cp_title.paragraph_format.space_after = Pt(18)
    run_t = cp_title.add_run(fm["vtu_university"] + "\n\n")
    run_t.font.name = "Times New Roman"
    run_t.font.size = Pt(13)
    run_t.font.bold = True
    run_t.font.color.rgb = RGBColor(0, 51, 102)

    run_title = cp_title.add_run(fm["title"] + "\n\n")
    run_title.font.name = "Times New Roman"
    run_title.font.size = Pt(16)
    run_title.font.bold = True
    run_title.font.color.rgb = RGBColor(15, 23, 42)

    cp_sub = doc.add_paragraph()
    cp_sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    cp_sub.paragraph_format.space_after = Pt(36)
    run_sub = cp_sub.add_run(fm["subtitle"] + "\n")
    run_sub.font.name = "Times New Roman"
    run_sub.font.size = Pt(11)
    run_sub.font.italic = True

    cp_meta = doc.add_paragraph()
    cp_meta.alignment = WD_ALIGN_PARAGRAPH.CENTER
    cp_meta.paragraph_format.space_after = Pt(24)
    run_subm = cp_meta.add_run("Submitted by:\n")
    run_subm.font.name = "Times New Roman"
    run_subm.font.size = Pt(11)
    run_subm.font.bold = True
    run_sname = cp_meta.add_run(f"{fm['student_name']} ({fm['student_usn']})\n\n")
    run_sname.font.name = "Times New Roman"
    run_sname.font.size = Pt(12)
    run_sname.font.bold = True

    run_guid = cp_meta.add_run("Under the Guidance of:\n")
    run_guid.font.name = "Times New Roman"
    run_guid.font.size = Pt(11)
    run_guid.font.bold = True
    run_gname = cp_meta.add_run(f"{fm['guide_name']}\n{fm['guide_designation']}\n\n")
    run_gname.font.name = "Times New Roman"
    run_gname.font.size = Pt(11)

    cp_dept = doc.add_paragraph()
    cp_dept.alignment = WD_ALIGN_PARAGRAPH.CENTER
    cp_dept.paragraph_format.space_after = Pt(12)
    run_dept = cp_dept.add_run(f"{fm['department_name']}\n{fm['college_name']}\n{fm['college_address']}\nAcademic Year: {fm['academic_year']}")
    run_dept.font.name = "Times New Roman"
    run_dept.font.size = Pt(11)
    run_dept.font.bold = True
    run_dept.font.color.rgb = RGBColor(0, 51, 102)

    doc.add_page_break()

    # 4. CERTIFICATE
    cert_h = doc.add_paragraph()
    cert_h.alignment = WD_ALIGN_PARAGRAPH.CENTER
    cert_h.paragraph_format.space_before = Pt(18)
    cert_h.paragraph_format.space_after = Pt(18)
    run_ch = cert_h.add_run(f"{fm['college_name']}\n{fm['department_name']}\n\nCERTIFICATE")
    run_ch.font.name = "Times New Roman"
    run_ch.font.size = Pt(14)
    run_ch.font.bold = True
    run_ch.font.color.rgb = RGBColor(0, 51, 102)

    cp_body = doc.add_paragraph()
    cp_body.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    cp_body.paragraph_format.line_spacing = 1.5
    cp_body.paragraph_format.space_after = Pt(40)
    run_cb = cp_body.add_run(fm["certificate_text"])
    run_cb.font.name = "Times New Roman"
    run_cb.font.size = Pt(12)

    # Signatures Table
    sig_table = doc.add_table(rows=2, cols=3)
    sig_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    sig_cells = sig_table.rows[0].cells
    sig_cells[0].paragraphs[0].text = "____________________\nSignature of Guide\n" + fm["guide_name"]
    sig_cells[1].paragraphs[0].text = "____________________\nSignature of HOD\n" + fm["hod_name"]
    sig_cells[2].paragraphs[0].text = "____________________\nSignature of Principal\n" + fm["principal_name"]
    for row in sig_table.rows:
        for cell in row.cells:
            cell.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
            for run in cell.paragraphs[0].runs:
                run.font.name = "Times New Roman"
                run.font.size = Pt(10)

    doc.add_page_break()

    # 5. DECLARATION
    decl_h = doc.add_paragraph()
    decl_h.alignment = WD_ALIGN_PARAGRAPH.CENTER
    decl_h.paragraph_format.space_before = Pt(18)
    decl_h.paragraph_format.space_after = Pt(18)
    run_dh = decl_h.add_run("DECLARATION")
    run_dh.font.name = "Times New Roman"
    run_dh.font.size = Pt(14)
    run_dh.font.bold = True

    dp_body = doc.add_paragraph()
    dp_body.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    dp_body.paragraph_format.line_spacing = 1.5
    dp_body.paragraph_format.space_after = Pt(36)
    run_db = dp_body.add_run(fm["declaration_text"])
    run_db.font.name = "Times New Roman"
    run_db.font.size = Pt(12)

    dp_sig = doc.add_paragraph()
    dp_sig.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    run_ds = dp_sig.add_run(f"\n\n________________________\n{fm['student_name']}\nUSN: {fm['student_usn']}\nDept. of CSE, {fm['college_name']}")
    run_ds.font.name = "Times New Roman"
    run_ds.font.size = Pt(11)

    doc.add_page_break()

    # 6. ACKNOWLEDGEMENTS
    ack_h = doc.add_paragraph()
    ack_h.alignment = WD_ALIGN_PARAGRAPH.CENTER
    ack_h.paragraph_format.space_before = Pt(18)
    ack_h.paragraph_format.space_after = Pt(18)
    run_ah = ack_h.add_run("ACKNOWLEDGEMENTS")
    run_ah.font.name = "Times New Roman"
    run_ah.font.size = Pt(14)
    run_ah.font.bold = True

    for para_text in fm["acknowledgement_text"].split("\n\n"):
        ap = doc.add_paragraph()
        ap.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        ap.paragraph_format.line_spacing = 1.5
        ap.paragraph_format.space_after = Pt(8)
        arun = ap.add_run(para_text)
        arun.font.name = "Times New Roman"
        arun.font.size = Pt(12)

    doc.add_page_break()

    # 7. ABSTRACT
    abs_h = doc.add_paragraph()
    abs_h.alignment = WD_ALIGN_PARAGRAPH.CENTER
    abs_h.paragraph_format.space_before = Pt(18)
    abs_h.paragraph_format.space_after = Pt(18)
    run_abh = abs_h.add_run("ABSTRACT")
    run_abh.font.name = "Times New Roman"
    run_abh.font.size = Pt(14)
    run_abh.font.bold = True

    for para_text in fm["abstract"].split("\n\n"):
        absp = doc.add_paragraph()
        absp.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        absp.paragraph_format.line_spacing = 1.5
        absp.paragraph_format.space_after = Pt(10)
        absrun = absp.add_run(para_text)
        absrun.font.name = "Times New Roman"
        absrun.font.size = Pt(12)

    doc.add_page_break()

    # 8. TABLE OF CONTENTS
    toc_h = doc.add_paragraph()
    toc_h.alignment = WD_ALIGN_PARAGRAPH.CENTER
    toc_h.paragraph_format.space_before = Pt(18)
    toc_h.paragraph_format.space_after = Pt(14)
    run_toch = toc_h.add_run("TABLE OF CONTENTS")
    run_toch.font.name = "Times New Roman"
    run_toch.font.size = Pt(14)
    run_toch.font.bold = True

    # Generate complete TOC table
    toc_table = doc.add_table(rows=1, cols=3)
    toc_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    set_table_borders(toc_table)
    th_cells = toc_table.rows[0].cells
    th_cells[0].paragraphs[0].text = "Chapter No."
    th_cells[1].paragraphs[0].text = "Title of the Chapter"
    th_cells[2].paragraphs[0].text = "Page No."
    for cell in th_cells:
        set_cell_shading(cell, "003366")
        p = cell.paragraphs[0]
        for run in p.runs:
            run.font.name = "Times New Roman"
            run.font.size = Pt(10)
            run.font.bold = True
            run.font.color.rgb = RGBColor(255, 255, 255)

    toc_entries = [
        ("", "Certificate", "ii"),
        ("", "Declaration", "iii"),
        ("", "Acknowledgements", "iv"),
        ("", "Abstract", "v"),
        ("", "List of Figures", "vii"),
        ("", "List of Tables", "vii"),
        ("", "List of Abbreviations", "viii"),
        ("1", "INTRODUCTION", "9"),
        ("2", "LITERATURE SURVEY", "15"),
        ("3", "EXISTING SYSTEM AND PROPOSED SYSTEM", "20"),
        ("4", "SYSTEM ANALYSIS AND DESIGN", "25"),
        ("5", "METHODOLOGY", "33"),
        ("6", "MACHINE LEARNING MODEL AND MATHEMATICAL FOUNDATION", "38"),
        ("7", "IMPLEMENTATION", "44"),
        ("8", "RESULTS AND PERFORMANCE ANALYSIS", "48"),
        ("9", "SOFTWARE TESTING AND QUALITY ASSURANCE", "57"),
        ("10", "CONCLUSION AND FUTURE ENHANCEMENTS", "62"),
        ("", "REFERENCES", "65"),
        ("A", "Appendix A: Complete REST API Specification", "67"),
        ("B", "Appendix B: Core Algorithm Pseudocode", "68"),
        ("C", "Appendix C: Master Test Fixture Definitions", "70"),
        ("D", "Appendix D: System Installation & Deployment Guide", "71"),
    ]

    for ch_num, ch_title, pg in toc_entries:
        row = toc_table.add_row()
        cells = row.cells
        set_cell_margins(cells[0], top=40, bottom=40)
        set_cell_margins(cells[1], top=40, bottom=40)
        set_cell_margins(cells[2], top=40, bottom=40)
        cells[0].paragraphs[0].text = ch_num
        cells[1].paragraphs[0].text = ch_title
        cells[2].paragraphs[0].text = pg
        cells[2].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.RIGHT
        for cell in cells:
            for r in cell.paragraphs[0].runs:
                r.font.name = "Times New Roman"
                r.font.size = Pt(10)
                if ch_num and not ch_num.isalpha():
                    r.font.bold = True

    doc.add_page_break()

    # 9. LIST OF FIGURES & LIST OF TABLES
    lof_h = doc.add_paragraph()
    lof_h.alignment = WD_ALIGN_PARAGRAPH.CENTER
    lof_h.paragraph_format.space_before = Pt(18)
    lof_h.paragraph_format.space_after = Pt(14)
    run_lofh = lof_h.add_run("LIST OF FIGURES")
    run_lofh.font.name = "Times New Roman"
    run_lofh.font.size = Pt(14)
    run_lofh.font.bold = True

    figures_list = [
        ("Figure 4.1", "Comprehensive System Topology and Multi-Modal Data Pipeline of PhishIntel", "26"),
        ("Figure 4.2", "Data Flow Diagram Level 0 Context and Subsystem Decomposition", "26"),
        ("Figure 4.3", "UML Activity Diagram Depicting Sequential Execution Logic and Decision Branches", "28"),
        ("Figure 6.1", "DistilBERT 6-Layer Bidirectional Transformer Architecture & Attention Flow", "39"),
        ("Figure 8.1", "Confusion Matrix Breakdown on Locked Test Partition (TN=591, FP=5, FN=4, TP=124)", "49"),
        ("Figure 8.2", "Risk Score Meter Calibration Comparison: Raw Model Logit vs Corroboration-Dampened Score", "56"),
    ]

    lof_table = doc.add_table(rows=1, cols=3)
    lof_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    set_table_borders(lof_table)
    th_cells = lof_table.rows[0].cells
    th_cells[0].paragraphs[0].text = "Figure No."
    th_cells[1].paragraphs[0].text = "Figure Caption / Title"
    th_cells[2].paragraphs[0].text = "Page No."
    for cell in th_cells:
        set_cell_shading(cell, "003366")
        for r in cell.paragraphs[0].runs:
            r.font.name = "Times New Roman"
            r.font.size = Pt(10)
            r.font.bold = True
            r.font.color.rgb = RGBColor(255, 255, 255)

    for f_no, f_title, pg in figures_list:
        row = lof_table.add_row()
        cells = row.cells
        set_cell_margins(cells[0], top=30, bottom=30)
        set_cell_margins(cells[1], top=30, bottom=30)
        set_cell_margins(cells[2], top=30, bottom=30)
        cells[0].paragraphs[0].text = f_no
        cells[1].paragraphs[0].text = f_title
        cells[2].paragraphs[0].text = pg
        cells[2].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.RIGHT
        for cell in cells:
            for r in cell.paragraphs[0].runs:
                r.font.name = "Times New Roman"
                r.font.size = Pt(9.5)

    doc.add_page_break()

    # 10. LIST OF TABLES
    lot_h = doc.add_paragraph()
    lot_h.alignment = WD_ALIGN_PARAGRAPH.CENTER
    lot_h.paragraph_format.space_before = Pt(18)
    lot_h.paragraph_format.space_after = Pt(14)
    run_loth = lot_h.add_run("LIST OF TABLES")
    run_loth.font.name = "Times New Roman"
    run_loth.font.size = Pt(14)
    run_loth.font.bold = True

    tables_list = [
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

    lot_table = doc.add_table(rows=1, cols=3)
    lot_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    set_table_borders(lot_table)
    th_cells = lot_table.rows[0].cells
    th_cells[0].paragraphs[0].text = "Table No."
    th_cells[1].paragraphs[0].text = "Table Title"
    th_cells[2].paragraphs[0].text = "Page No."
    for cell in th_cells:
        set_cell_shading(cell, "003366")
        for r in cell.paragraphs[0].runs:
            r.font.name = "Times New Roman"
            r.font.size = Pt(10)
            r.font.bold = True
            r.font.color.rgb = RGBColor(255, 255, 255)

    for t_no, t_title, pg in tables_list:
        row = lot_table.add_row()
        cells = row.cells
        set_cell_margins(cells[0], top=30, bottom=30)
        set_cell_margins(cells[1], top=30, bottom=30)
        set_cell_margins(cells[2], top=30, bottom=30)
        cells[0].paragraphs[0].text = t_no
        cells[1].paragraphs[0].text = t_title
        cells[2].paragraphs[0].text = pg
        cells[2].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.RIGHT
        for cell in cells:
            for r in cell.paragraphs[0].runs:
                r.font.name = "Times New Roman"
                r.font.size = Pt(9.5)

    doc.add_page_break()

    # 11. LIST OF ABBREVIATIONS
    abb_h = doc.add_paragraph()
    abb_h.alignment = WD_ALIGN_PARAGRAPH.CENTER
    abb_h.paragraph_format.space_before = Pt(18)
    abb_h.paragraph_format.space_after = Pt(14)
    run_abbh = abb_h.add_run("LIST OF ABBREVIATIONS")
    run_abbh.font.name = "Times New Roman"
    run_abbh.font.size = Pt(14)
    run_abbh.font.bold = True

    abb_table = doc.add_table(rows=1, cols=2)
    abb_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    set_table_borders(abb_table)
    th_cells = abb_table.rows[0].cells
    th_cells[0].paragraphs[0].text = "Abbreviation"
    th_cells[1].paragraphs[0].text = "Expanded Definition / Standard Reference"
    for cell in th_cells:
        set_cell_shading(cell, "003366")
        for r in cell.paragraphs[0].runs:
            r.font.name = "Times New Roman"
            r.font.size = Pt(10)
            r.font.bold = True
            r.font.color.rgb = RGBColor(255, 255, 255)

    for abb, desc in fm["abbreviations"]:
        row = abb_table.add_row()
        cells = row.cells
        set_cell_margins(cells[0], top=25, bottom=25)
        set_cell_margins(cells[1], top=25, bottom=25)
        cells[0].paragraphs[0].text = abb
        cells[1].paragraphs[0].text = desc
        cells[0].paragraphs[0].runs[0].font.bold = True
        for cell in cells:
            for r in cell.paragraphs[0].runs:
                r.font.name = "Times New Roman"
                r.font.size = Pt(9.5)

    doc.add_page_break()

    # 12. CHAPTERS 1 TO 10
    tables_data = REPORT_STRUCTURE["tables"]

    for ch in REPORT_STRUCTURE["chapters"]:
        # Chapter Heading
        ch_p = doc.add_paragraph()
        ch_p.paragraph_format.space_before = Pt(24)
        ch_p.paragraph_format.space_after = Pt(18)
        ch_run = ch_p.add_run(ch["title"])
        ch_run.font.name = "Times New Roman"
        ch_run.font.size = Pt(16)
        ch_run.font.bold = True
        ch_run.font.color.rgb = RGBColor(0, 51, 102)

        for sec in ch["sections"]:
            sec_p = doc.add_paragraph()
            sec_p.paragraph_format.space_before = Pt(14)
            sec_p.paragraph_format.space_after = Pt(6)
            sec_run = sec_p.add_run(sec["heading"])
            sec_run.font.name = "Times New Roman"
            sec_run.font.size = Pt(13)
            sec_run.font.bold = True
            sec_run.font.color.rgb = RGBColor(30, 41, 59)

            # Body paragraphs
            paragraphs = sec["content"].split("\n\n")
            for p_text in paragraphs:
                p_text_clean = p_text.strip()
                if not p_text_clean:
                    continue
                
                # Check if it is a code / diagram block
                if p_text_clean.startswith("```"):
                    code_lines = p_text_clean.replace("```text", "").replace("```python", "").replace("```", "").strip()
                    cp = doc.add_paragraph()
                    cp.paragraph_format.space_before = Pt(4)
                    cp.paragraph_format.space_after = Pt(4)
                    cp.paragraph_format.line_spacing = 1.0
                    crun = cp.add_run(code_lines)
                    crun.font.name = "Consolas"
                    crun.font.size = Pt(8.5)
                    crun.font.color.rgb = RGBColor(20, 20, 20)
                else:
                    bp = doc.add_paragraph()
                    bp.paragraph_format.line_spacing = 1.5
                    bp.paragraph_format.space_after = Pt(6)
                    bp.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
                    brun = bp.add_run(p_text_clean)
                    brun.font.name = "Times New Roman"
                    brun.font.size = Pt(12)

            # Insert Tables if referenced in this section
            if sec["heading"].startswith("2.10"):
                insert_table_docx(doc, tables_data["table_2_1"])
            elif sec["heading"].startswith("3.5"):
                insert_table_docx(doc, tables_data["table_3_1"])
            elif sec["heading"].startswith("4.8"):
                insert_table_docx(doc, tables_data["table_4_1"])
            elif sec["heading"].startswith("5.2"):
                insert_table_docx(doc, tables_data["table_5_1"])
            elif sec["heading"].startswith("5.4"):
                insert_table_docx(doc, tables_data["table_5_2"])
            elif sec["heading"].startswith("6.9"):
                insert_table_docx(doc, tables_data["table_6_1"])
            elif sec["heading"].startswith("6.10"):
                insert_table_docx(doc, tables_data["table_6_2"])
            elif sec["heading"].startswith("8.5"):
                insert_table_docx(doc, tables_data["table_8_2"])
            elif sec["heading"].startswith("8.6"):
                insert_table_docx(doc, tables_data["table_8_3"])
            elif sec["heading"].startswith("8.8"):
                insert_table_docx(doc, tables_data["table_8_4"])
            elif sec["heading"].startswith("8.10"):
                insert_table_docx(doc, tables_data["table_8_5"])
            elif sec["heading"].startswith("8.11"):
                insert_table_docx(doc, tables_data["table_8_6"])
            elif sec["heading"].startswith("9.7"):
                insert_table_docx(doc, tables_data["table_9_1"])

        doc.add_page_break()

    # 13. REFERENCES
    ref_p = doc.add_paragraph()
    ref_p.paragraph_format.space_before = Pt(24)
    ref_p.paragraph_format.space_after = Pt(14)
    ref_run = ref_p.add_run("REFERENCES")
    ref_run.font.name = "Times New Roman"
    ref_run.font.size = Pt(16)
    ref_run.font.bold = True
    ref_run.font.color.rgb = RGBColor(0, 51, 102)

    for ref in REPORT_STRUCTURE["references"]:
        rp = doc.add_paragraph()
        rp.paragraph_format.line_spacing = 1.15
        rp.paragraph_format.space_after = Pt(6)
        rp.paragraph_format.left_indent = Inches(0.4)
        rp.paragraph_format.first_line_indent = Inches(-0.4)
        rp.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        rrun = rp.add_run(ref)
        rrun.font.name = "Times New Roman"
        rrun.font.size = Pt(10.5)

    doc.add_page_break()

    # 14. APPENDICES
    for app_key, app in REPORT_STRUCTURE["appendices"].items():
        ap_p = doc.add_paragraph()
        ap_p.paragraph_format.space_before = Pt(24)
        ap_p.paragraph_format.space_after = Pt(14)
        ap_run = ap_p.add_run(app["title"])
        ap_run.font.name = "Times New Roman"
        ap_run.font.size = Pt(15)
        ap_run.font.bold = True
        ap_run.font.color.rgb = RGBColor(0, 51, 102)

        for p_text in app["content"].split("\n\n"):
            p_clean = p_text.strip()
            if not p_clean:
                continue
            if p_clean.startswith("```"):
                code_text = p_clean.replace("```text", "").replace("```powershell", "").replace("```", "").strip()
                cp = doc.add_paragraph()
                cp.paragraph_format.space_before = Pt(4)
                cp.paragraph_format.space_after = Pt(4)
                cp.paragraph_format.line_spacing = 1.0
                crun = cp.add_run(code_text)
                crun.font.name = "Consolas"
                crun.font.size = Pt(8.5)
            elif p_clean.startswith("### "):
                hp = doc.add_paragraph()
                hp.paragraph_format.space_before = Pt(10)
                hp.paragraph_format.space_after = Pt(4)
                hrun = hp.add_run(p_clean.replace("### ", ""))
                hrun.font.name = "Times New Roman"
                hrun.font.size = Pt(12)
                hrun.font.bold = True
            else:
                bp = doc.add_paragraph()
                bp.paragraph_format.line_spacing = 1.3
                bp.paragraph_format.space_after = Pt(6)
                bp.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
                brun = bp.add_run(p_clean)
                brun.font.name = "Times New Roman"
                brun.font.size = Pt(11)

        doc.add_page_break()

    # Save document
    doc.save(output_path)
    print(f"DOCX report successfully generated at: {output_path}")


def insert_table_docx(doc, tbl_spec):
    """Helper to insert formatted tables into the docx document."""
    # Caption
    cp = doc.add_paragraph()
    cp.paragraph_format.space_before = Pt(10)
    cp.paragraph_format.space_after = Pt(4)
    crun = cp.add_run(tbl_spec["title"])
    crun.font.name = "Times New Roman"
    crun.font.size = Pt(11)
    crun.font.bold = True
    crun.font.color.rgb = RGBColor(0, 51, 102)

    num_rows = len(tbl_spec["rows"]) + 1
    num_cols = len(tbl_spec["headers"])
    table = doc.add_table(rows=num_rows, cols=num_cols)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    set_table_borders(table)

    # Format header
    hdr_cells = table.rows[0].cells
    for i, h_text in enumerate(tbl_spec["headers"]):
        hdr_cells[i].paragraphs[0].text = h_text
        set_cell_shading(hdr_cells[i], "003366")
        set_cell_margins(hdr_cells[i], top=50, bottom=50, left=80, right=80)
        for r in hdr_cells[i].paragraphs[0].runs:
            r.font.name = "Times New Roman"
            r.font.size = Pt(9.5)
            r.font.bold = True
            r.font.color.rgb = RGBColor(255, 255, 255)

    # Format data rows
    for r_idx, row_data in enumerate(tbl_spec["rows"]):
        row_cells = table.rows[r_idx + 1].cells
        bg_col = "F8FAFC" if (r_idx % 2 == 1) else "FFFFFF"
        for c_idx, val in enumerate(row_data):
            row_cells[c_idx].paragraphs[0].text = str(val)
            set_cell_shading(row_cells[c_idx], bg_col)
            set_cell_margins(row_cells[c_idx], top=35, bottom=35, left=70, right=70)
            for r in row_cells[c_idx].paragraphs[0].runs:
                r.font.name = "Times New Roman"
                r.font.size = Pt(9.0)

    doc.add_paragraph().paragraph_format.space_after = Pt(8)


if __name__ == "__main__":
    out_file = Path(__file__).parent / "PhishIntel_Final_Project_Report.docx"
    build_docx(out_file)
