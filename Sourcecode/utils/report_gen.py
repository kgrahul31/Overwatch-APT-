import os
import pandas as pd
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def generate_pdf_report(scan_history_df, filepath="Executive_Report.pdf"):
    """
    Generates a professional PDF Executive Summary from the scan history.
    """
    doc = SimpleDocTemplate(filepath, pagesize=letter)
    styles = getSampleStyleSheet()
    
    # Custom Styles
    title_style = ParagraphStyle(
        'TitleStyle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=20,
        alignment=1 # Center
    )
    
    h2_style = ParagraphStyle(
        'H2Style',
        parent=styles['Heading2'],
        fontSize=16,
        textColor=colors.HexColor("#334155"),
        spaceBefore=15,
        spaceAfter=10
    )
    
    normal_style = styles['Normal']
    
    elements = []
    
    # Title
    elements.append(Paragraph("OVERWATCH-APT", title_style))
    elements.append(Paragraph("Executive Threat Intelligence Report", title_style))
    
    # Meta Info
    report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    elements.append(Paragraph(f"<b>Report Generated:</b> {report_date}", normal_style))
    elements.append(Spacer(1, 20))
    
    # High-level Summary
    Total_Scans = len(scan_history_df)
    Total_Threats = scan_history_df['threats_found'].sum() if not scan_history_df.empty else 0
    Total_Events = scan_history_df['events_scanned'].sum() if not scan_history_df.empty else 0
    
    elements.append(Paragraph("<b>Executive Summary</b>", h2_style))
    summary_text = (f"This report summarizes {Total_Scans} scanning operations performed. "
                    f"A total of {Total_Events:,} events were analyzed, resulting in the detection of "
                    f"<b>{Total_Threats:,} critical threats</b>.")
    elements.append(Paragraph(summary_text, normal_style))
    elements.append(Spacer(1, 20))
    
    # Data Table
    elements.append(Paragraph("<b>Recent Scan Operations</b>", h2_style))
    
    if not scan_history_df.empty:
        # Convert df to list of lists for ReportLab Table
        # Only take top 20 rows for the report
        recent_df = scan_history_df.head(20)
        table_data = [["Timestamp", "Type", "Source", "Events", "Threats"]]
        
        for _, row in recent_df.iterrows():
            table_data.append([
                str(row['timestamp']),
                str(row['scan_type']),
                str(row['source'])[:20],
                str(row['events_scanned']),
                str(row['threats_found'])
            ])
            
        t = Table(table_data, colWidths=[120, 80, 150, 60, 60])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0ea5e9")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ('FONTSIZE', (0,1), (-1,-1), 9),
        ]))
        elements.append(t)
    else:
        elements.append(Paragraph("No scan history available to report.", normal_style))
        
    # Build PDF
    doc.build(elements)
    
    return os.path.abspath(filepath)
