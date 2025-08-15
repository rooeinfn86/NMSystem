from typing import List, Dict, Any, Optional
from pathlib import Path
import json
from datetime import datetime
import pytz
from fpdf import FPDF
import pandas as pd
from app.services.nist_engine.nist_analyzer import NISTAnalyzer

class ReportGenerator:
    def __init__(self):
        self.nist_analyzer = NISTAnalyzer()
        self.local_tz = pytz.timezone('America/Los_Angeles')

    def _get_local_time(self):
        local_now = datetime.now(self.local_tz)
        return local_now.strftime('%Y-%m-%d %I:%M:%S %p %Z')

    def generate_pdf_report(
        self,
        scan_id: int,
        scan_name: str,
        findings: List[Dict[str, Any]],
        metrics: Dict[str, int],
        output_path: str,
        files: Optional[List[Dict[str, Any]]] = None
    ) -> str:
        """
        Generate a PDF compliance report with professional formatting.
        
        Args:
            scan_id: The ID of the scan
            scan_name: The name of the scan
            findings: List of findings to include in the report
            metrics: Dictionary of metrics for the report
            output_path: Path where the PDF should be saved
            files: Optional list of files associated with the findings
        """
        pdf = FPDF()
        pdf.add_page()
        
        # Title with professional styling
        pdf.set_font("Arial", "B", 24)
        pdf.set_text_color(0, 0, 0)  # Black color
        pdf.cell(0, 20, "NIST Compliance Assessment Report", ln=True, align="C")
        pdf.ln(5)
        
        # Report metadata with subtle styling
        pdf.set_font("Arial", "", 10)
        pdf.set_text_color(100, 100, 100)  # Dark gray
        pdf.cell(0, 5, f"Report Generated: {self._get_local_time()}", ln=True, align="R")
        pdf.cell(0, 5, f"Report ID: {scan_id}", ln=True, align="R")
        pdf.ln(10)
        
        # Executive Summary with professional formatting
        pdf.set_font("Arial", "B", 16)
        pdf.set_text_color(0, 0, 0)  # Black
        pdf.cell(0, 10, "Executive Summary", ln=True)
        pdf.ln(5)
        
        pdf.set_font("Arial", "", 12)
        compliance_score = (metrics['compliant'] / metrics['total_controls'] * 100) if metrics['total_controls'] > 0 else 0
        pdf.multi_cell(0, 10, f"This compliance assessment report evaluates the organization's adherence to NIST security controls. "
                         f"The assessment identified {metrics['total_controls']} findings, with an overall compliance score of {compliance_score:.1f}%. "
                         f"Key areas of concern include access control policies, authentication mechanisms, and secure communications.")
        pdf.ln(10)
        
        # Assessment Details with clean formatting
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Assessment Details", ln=True)
        pdf.ln(5)
        
        pdf.set_font("Arial", "", 12)
        details = [
            ("Scan Name", scan_name),
            ("Total Controls", str(metrics['total_controls'])),
            ("Compliant", str(metrics['compliant'])),
            ("Non-Compliant", str(metrics['non_compliant'])),
            ("Not Applicable", str(metrics['not_applicable'])),
            ("Assessment Date", self._get_local_time())
        ]
        
        for label, value in details:
            pdf.cell(60, 10, label + ":", 0)
            pdf.cell(0, 10, value, ln=True)
        
        pdf.ln(10)
        
        # Group findings by file
        findings_by_file = {}
        if files:
            # Initialize findings for all files
            for file in files:
                file_name = file.get('filename', 'Unknown File')
                findings_by_file[file_name] = []
            
            # Distribute findings to their respective files
            for finding in findings:
                file_id = finding.get('file_id')
                if file_id:
                    # Find the file with matching ID
                    for file in files:
                        if file.get('id') == file_id:
                            file_name = file.get('filename', 'Unknown File')
                            findings_by_file[file_name].append(finding)
                            break
                else:
                    # If no file_id, add to the first file's findings
                    first_file = next(iter(findings_by_file.values()))
                    first_file.append(finding)
        else:
            # If no files provided, group by file_name in findings
            for finding in findings:
                file_name = finding.get('file_name', 'Unknown File')
                if file_name not in findings_by_file:
                    findings_by_file[file_name] = []
                findings_by_file[file_name].append(finding)

        # Process findings by file
        for file_name, file_findings in findings_by_file.items():
            # Add file header with page break and centered filename
            pdf.add_page()
            # Calculate center position
            pdf.set_font("Arial", "B", 24)  # Larger font for filename
            text_width = pdf.get_string_width(file_name)
            page_width = pdf.w
            x_position = (page_width - text_width) / 2
            y_position = pdf.h / 2  # Center vertically
            
            # Move to center position and add filename
            pdf.set_xy(x_position, y_position)
            pdf.set_text_color(0, 0, 128)  # Blue
            pdf.cell(text_width, 10, file_name, ln=True)
            
            # Add a new page for findings
            pdf.add_page()
            
            # Reset text color for findings
            pdf.set_text_color(0, 0, 0)  # Black
            
            if not file_findings:
                # If no findings, add a message
                pdf.set_font("Arial", "I", 12)
                pdf.cell(0, 10, "No findings were identified for this file.", ln=True)
                pdf.ln(10)
            else:
                for finding in file_findings:
                    # Control ID with clear formatting
                    pdf.set_font("Arial", "B", 12)
                    pdf.set_text_color(0, 0, 0)  # Black
                    pdf.cell(0, 10, f"Control ID: {finding['control_id']}", ln=True)
                    
                    # Status with color coding
                    status = finding['status'].title()
                    if status == "Non-Compliant":
                        pdf.set_text_color(220, 0, 0)  # Red
                    elif status == "Compliant":
                        pdf.set_text_color(0, 128, 0)  # Green
                    elif status == "Informational":
                        pdf.set_text_color(0, 0, 128)  # Blue
                    else:
                        pdf.set_text_color(128, 128, 128)  # Gray
                    pdf.cell(0, 10, f"Status: {status}", ln=True)
                    pdf.set_text_color(0, 0, 0)  # Reset to black
                    pdf.ln(5)
                    
                    # Control Description with clear formatting
                    pdf.set_font("Arial", "B", 11)
                    pdf.cell(0, 10, "Control Description:", ln=True)
                    pdf.set_font("Arial", "", 11)
                    description = finding.get('description', 'Control description not available.')
                    # Ensure description is not empty or generic
                    if not description or description.startswith("No specific"):
                        description = "Control description not available."
                    pdf.multi_cell(0, 10, description)
                    pdf.ln(5)
                    
                    # Evidence Summary with professional formatting
                    pdf.set_font("Arial", "B", 11)
                    pdf.cell(0, 10, "Evidence Summary:", ln=True)
                    pdf.set_font("Arial", "", 11)
                    evidence = finding.get('evidence_summary', 'No specific findings were identified.')
                    
                    # Format evidence as a structured list for Nessus findings
                    if "Nessus" in evidence or "port" in evidence.lower():
                        evidence_parts = []
                        if "Synopsis" in evidence:
                            evidence_parts.append("Synopsis: " + evidence.split("Synopsis")[1].split("Description")[0].strip())
                        if "Description" in evidence:
                            evidence_parts.append("Description: " + evidence.split("Description")[1].split("Solution")[0].strip())
                        if "Plugin Output" in evidence:
                            evidence_parts.append("Plugin Output: " + evidence.split("Plugin Output")[1].strip())
                        if evidence_parts:
                            evidence = "\n".join(evidence_parts)
                    
                    # Format evidence as numbered list if it contains multiple items
                    if '\n' in evidence:
                        evidence_items = evidence.split('\n')
                        evidence = '\n'.join(f"{i+1}. {item.strip()}" for i, item in enumerate(evidence_items) if item.strip())
                    
                    # Ensure evidence is not empty or generic
                    if not evidence or evidence.startswith("No specific"):
                        evidence = "No specific findings were identified."
                    pdf.multi_cell(0, 10, evidence)
                    pdf.ln(5)
                    
                    # Risk Rating with clear formatting
                    pdf.set_font("Arial", "B", 11)
                    pdf.cell(0, 10, "Risk Rating:", ln=True)
                    pdf.set_font("Arial", "", 11)
                    risk_rating = finding.get('risk_rating', {})
                    risk_level = risk_rating.get('level', 'Unknown')
                    impact = risk_rating.get('impact', 'Impact cannot be determined')
                    
                    # Color code risk levels
                    if risk_level.lower() == 'high':
                        pdf.set_text_color(220, 0, 0)  # Red
                    elif risk_level.lower() == 'medium':
                        pdf.set_text_color(255, 165, 0)  # Orange
                    elif risk_level.lower() == 'low':
                        pdf.set_text_color(0, 128, 0)  # Green
                    else:
                        pdf.set_text_color(128, 128, 128)  # Gray
                        
                    pdf.multi_cell(0, 10, f"Level: {risk_level}\nImpact: {impact}")
                    pdf.set_text_color(0, 0, 0)  # Reset to black
                    pdf.ln(5)
                    
                    # Recommended Remediation with clear formatting
                    pdf.set_font("Arial", "B", 11)
                    pdf.cell(0, 10, "Recommended Remediation:", ln=True)
                    pdf.set_font("Arial", "", 11)
                    remediation = finding.get('recommendation', 'No specific remediation steps provided.')
                    # Format remediation as numbered list if it contains multiple items
                    if '\n' in remediation:
                        remediation_items = remediation.split('\n')
                        remediation = '\n'.join(f"{i+1}. {item.strip()}" for i, item in enumerate(remediation_items) if item.strip())
                    # Ensure remediation is not empty or generic
                    if not remediation or remediation.lower() in ['n/a', 'none', 'no specific remediation steps provided.']:
                        remediation = "No specific remediation steps provided."
                    pdf.multi_cell(0, 10, remediation)
                    pdf.ln(10)
        
        # Save the PDF
        pdf_path = Path(output_path) / f"nist_compliance_report_{scan_id}.pdf"
        pdf.output(str(pdf_path))
        
        return str(pdf_path)

    def generate_excel_report(
        self,
        scan_id: int,
        scan_name: str,
        findings: List[Dict[str, Any]],
        metrics: Dict[str, int],
        output_path: str
    ) -> str:
        """
        Generate an Excel compliance report.
        """
        # Create DataFrame for findings
        findings_data = []
        for finding in findings:
            findings_data.append({
                "Control ID": finding["control_id"],
                "Status": finding["status"],
                "Description": finding["description"],
                "Evidence & Findings Summary": finding.get("evidence_summary", ""),
                "Risk Level": finding.get("risk_rating", {}).get("level", "Unknown"),
                "Impact": finding.get("risk_rating", {}).get("impact", ""),
                "Recommended Remediation": finding.get("recommendation", "")
            })
        
        # Create DataFrame for metrics
        metrics_data = [{
            "Metric": "Total Controls",
            "Value": metrics["total_controls"]
        }, {
            "Metric": "Compliant",
            "Value": metrics["compliant"]
        }, {
            "Metric": "Non-Compliant",
            "Value": metrics["non_compliant"]
        }, {
            "Metric": "Not Applicable",
            "Value": metrics["not_applicable"]
        }]
        
        # Create Excel writer
        excel_path = Path(output_path) / f"nist_compliance_report_{scan_id}.xlsx"
        with pd.ExcelWriter(str(excel_path)) as writer:
            # Write findings sheet
            pd.DataFrame(findings_data).to_excel(
                writer,
                sheet_name="Findings",
                index=False
            )
            
            # Write metrics sheet
            pd.DataFrame(metrics_data).to_excel(
                writer,
                sheet_name="Metrics",
                index=False
            )
            
            # Write summary sheet
            summary_data = [{
                "Scan ID": scan_id,
                "Scan Name": scan_name,
                "Generated": self._get_local_time(),
                "Total Controls": metrics["total_controls"],
                "Compliance Score": f"{metrics['compliant'] / metrics['total_controls'] * 100:.2f}%"
            }]
            pd.DataFrame(summary_data).to_excel(
                writer,
                sheet_name="Summary",
                index=False
            )
        
        return str(excel_path)

    def generate_json_report(
        self,
        scan_id: int,
        scan_name: str,
        findings: List[Dict[str, Any]],
        metrics: Dict[str, int],
        output_path: str
    ) -> str:
        """
        Generate a JSON compliance report.
        """
        report_data = {
            "scan_id": scan_id,
            "scan_name": scan_name,
            "generated": self._get_local_time(),
            "metrics": metrics,
            "findings": findings
        }
        
        json_path = Path(output_path) / f"nist_compliance_report_{scan_id}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
        
        return str(json_path) 