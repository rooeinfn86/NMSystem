from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, status, Form, BackgroundTasks
from datetime import datetime, timezone
import os
from pathlib import Path
from app.core.dependencies import get_current_user
import pdfplumber
import docx
import pandas as pd
import openai
from openai import OpenAI
import json
import glob
from fastapi.responses import FileResponse
from fpdf import FPDF
import csv
import re
from typing import List, Optional
from sqlalchemy.orm import Session
from app.api.deps import get_db
from app.crud import compliance as crud
from app.schemas.compliance import (
    ComplianceScan,
    ComplianceScanCreate,
    ComplianceScanUpdate,
    ComplianceFinding,
    ComplianceFile,
    ComplianceFileCreate,
    ComplianceFindingCreate
)
from app.schemas.user import User
# from app.services.nist_engine.nist_analyzer import NISTAnalyzer
import shutil
import logging
import io
import xlsxwriter
from fastapi.responses import StreamingResponse
import unicodedata
import zipfile
from app.models import compliance as models
from app.models.base import Network, UserNetworkAccess
# from app.services.nist_engine.report_generator import ReportGenerator

# Custom FPDF class that handles Unicode characters
class UnicodeFPDF(FPDF):
    def __init__(self):
        super().__init__()
        # Use built-in fonts instead of trying to load external font files
        self.set_font('helvetica', '', 12)  # Default font

    def _normalize_text(self, text):
        if not isinstance(text, str):
            return text
        # Replace smart quotes and other special characters with their ASCII equivalents
        text = text.replace('"', '"').replace('"', '"')
        text = text.replace(''', "'").replace(''', "'")
        text = text.replace('–', '-').replace('—', '--')
        text = text.replace('…', '...')
        # Normalize Unicode characters to their closest ASCII equivalent
        text = unicodedata.normalize('NFKD', text).encode('ascii', 'ignore').decode('ascii')
        return text

    def cell(self, w, h=0, txt='', border=0, ln=0, align='', fill=False, link=''):
        txt = self._normalize_text(txt)
        super().cell(w, h, txt, border, ln, align, fill, link)

    def multi_cell(self, w, h=0, txt='', border=0, align='J', fill=False):
        txt = self._normalize_text(txt)
        super().multi_cell(w, h, txt, border, align, fill)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter(
    tags=["Compliance"]
)

# Set up upload directory in the data folder
UPLOAD_DIR = Path(__file__).parent.parent.parent.parent.parent / 'data' / 'uploads' / 'compliance'
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Initialize the OpenAI client
# Use secure configuration for OpenAI API key
from app.core.secure_config import secure_settings
client = OpenAI(api_key=secure_settings.OPENAI_API_KEY)

# Load CIS controls mapping once at startup
controls_path = Path(__file__).parent.parent.parent.parent / 'config' / 'controls_map.json'
with open(controls_path, "r", encoding="utf-8") as f:
    CIS_CONTROLS = json.load(f)

# Initialize NIST analyzer (commented out for production deployment)
# nist_analyzer = NISTAnalyzer()

# Allowed file types and their extensions
ALLOWED_FILE_TYPES = {
    "application/pdf": ".pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    "application/msword": ".doc",
    "application/vnd.ms-excel": ".xls"
}

def extract_text_from_file(file_path: str, file_type: str) -> str:
    """
    Extract text content from different file types.
    """
    try:
        logger.info(f"Extracting text from file: {file_path} of type: {file_type}")
        if file_type == "application/pdf":
            with pdfplumber.open(file_path) as pdf:
                text = ""
                for page in pdf.pages:
                    text += page.extract_text() or ""
                return text
        elif file_type in ["application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/msword"]:
            doc = docx.Document(file_path)
            return "\n".join([paragraph.text for paragraph in doc.paragraphs])
        elif file_type in ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/vnd.ms-excel"]:
            df = pd.read_excel(file_path)
            return df.to_string()
        else:
            raise ValueError(f"Unsupported file type: {file_type}")
    except Exception as e:
        logger.error(f"Error extracting text from file: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error extracting text from file: {str(e)}")

def extract_ip_addresses(text):
    """Extract and validate IP addresses from text, handling concatenated IPs."""
    # First, try to find IP addresses in the "List of hosts" section
    host_ips = []
    in_hosts_section = False
    for line in text.split('\n'):
        if 'List of hosts' in line:
            in_hosts_section = True
            continue
        if in_hosts_section and 'Severity problem(s) found' in line:
            parts = line.split()
            if parts and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parts[0]):
                host_ips.append(parts[0])
        elif in_hosts_section and not line.strip():
            break  # End of hosts section

    # Then look for IP addresses in the "Affected Systems" field
    affected_ips = []
    for line in text.split('\n'):
        if 'Affected Systems:' in line:
            # Extract the part after "Affected Systems:"
            ip_text = line.split('Affected Systems:', 1)[1].strip()
            
            # Special handling for concatenated IPs (e.g., "172.16.20.1172.17.20.1")
            # Look for patterns where the last octet of one IP is the first octet of the next
            potential_ips = []
            current_ip = ""
            for char in ip_text:
                if char.isdigit() or char == '.':
                    current_ip += char
                    # Check if we have a complete IP address
                    if len(current_ip.split('.')) == 4:
                        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', current_ip):
                            potential_ips.append(current_ip)
                            current_ip = ""
                else:
                    current_ip = ""
            
            # Also try splitting by common separators
            potential_ips.extend(re.split(r'[^\d.]', ip_text))
            
            # Validate and add unique IPs
            for ip in potential_ips:
                ip = ip.strip()
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                    affected_ips.append(ip)

    # Combine and deduplicate
    all_ips = list(set(host_ips + affected_ips))
    print(f"Found {len(all_ips)} unique IP addresses in the report")
    print(f"Host IPs: {host_ips}")
    print(f"Affected IPs: {affected_ips}")
    return all_ips

def extract_vulnerabilities_with_gpt(text):
    # First, extract severity levels for each host
    host_severities = {}
    for line in text.split('\n'):
        if 'Severity problem(s) found' in line:
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[0]
                severity = parts[1]  # High, Medium, or Low
                host_severities[ip] = severity

    # Extract all valid IP addresses from the text
    all_ips = extract_ip_addresses(text)

    prompt = (
        "You are analyzing a Nessus vulnerability scan report. Extract all unique vulnerabilities from the following text. "
        "For each vulnerability, return a JSON object with: "
        "cve_id (if any), description, affected_systems (as an array), remediation_steps, and severity. "
        "Look for sections that describe vulnerabilities, their severity, and affected systems. "
        "Pay special attention to: "
        "1. IP addresses and hostnames in the 'List of hosts' section "
        "2. Vulnerability descriptions and their severity levels "
        "3. Any CVE IDs mentioned in the report "
        "4. Recommended fixes or patches "
        "If you find a CVE ID, include it. If not, set cve_id to null. "
        "For affected_systems, include all IP addresses or hostnames mentioned, separated by commas. "
        "IMPORTANT: When multiple IP addresses are listed, make sure to separate them with commas. "
        "For example, if you see '172.16.20.1172.17.20.1', it should be split into ['172.16.20.1', '172.17.20.1']. "
        "For remediation_steps, include any recommended fixes or patches mentioned. "
        "For severity, use the highest severity level among the affected systems. "
        "Return a JSON array of unique vulnerabilities. If no vulnerabilities are found, return an empty array.\n\n"
        f"Report Text:\n{text[:8000]}"  # Increased to 8000 chars
    )
    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=2000,  # Increased token limit
            temperature=0.2,
        )
        # Extract JSON from the response
        import json
        import re
        match = re.search(r"\[.*\]", response.choices[0].message.content, re.DOTALL)
        if match:
            vulnerabilities = json.loads(match.group(0))
            # Clean up and deduplicate vulnerabilities
            unique_vulns = {}
            for vuln in vulnerabilities:
                key = f"{vuln.get('cve_id')}_{vuln.get('description')}"
                if key not in unique_vulns:
                    unique_vulns[key] = {
                        "cve_id": vuln.get("cve_id"),
                        "description": vuln.get("description"),
                        "affected_systems": [],
                        "remediation_steps": vuln.get("remediation_steps"),
                        "severity": "Unknown",  # Will be updated based on affected systems
                        "cis_controls": []
                    }
                # Add affected systems if not already present
                if isinstance(vuln.get("affected_systems"), list):
                    for system in vuln["affected_systems"]:
                        if system in all_ips and system not in unique_vulns[key]["affected_systems"]:
                            unique_vulns[key]["affected_systems"].append(system)
                elif isinstance(vuln.get("affected_systems"), str):
                    # Split by common separators and clean up
                    systems = re.split(r'[,;\s]+', vuln["affected_systems"])
                    for system in systems:
                        system = system.strip()
                        # Only add if it's a valid IP from our list
                        if system in all_ips and system not in unique_vulns[key]["affected_systems"]:
                            unique_vulns[key]["affected_systems"].append(system)
            
            # Convert back to list and map to CIS controls
            result = []
            for vuln in unique_vulns.values():
                # Determine severity based on affected systems
                severity_levels = []
                for system in vuln["affected_systems"]:
                    if system in host_severities:
                        severity_levels.append(host_severities[system])
                
                # Set severity based on the highest level found
                if "High" in severity_levels:
                    vuln["severity"] = "High"
                elif "Medium" in severity_levels:
                    vuln["severity"] = "Medium"
                elif "Low" in severity_levels:
                    vuln["severity"] = "Low"
                
                vuln["cis_controls"] = map_vulnerability_to_cis(vuln)
                result.append(vuln)
            
            return result
        else:
            print("No JSON array found in GPT response")
            return []
    except Exception as e:
        print(f"Error in GPT processing: {str(e)}")
        return [{"error": str(e)}]

def map_vulnerability_to_cis(vuln):
    description = (vuln.get("description") or "").lower()
    cve_id = (vuln.get("cve_id") or "").lower()
    matched_controls = []
    for control in CIS_CONTROLS:
        for kw in control["keywords"]:
            if kw in description or kw in cve_id:
                matched_controls.append({
                    "cis_control": control["cis_control"],
                    "title": control["title"]
                })
                break
    return matched_controls

@router.post("/upload")
async def upload_compliance_file(
    files: List[UploadFile] = File(...),
    current_user: dict = Depends(get_current_user)
):
    print(f"Received upload request from user: {current_user.get('username')}")
    print(f"Number of files received: {len(files)}")

    # Restrict to company_admin and full_control roles
    if current_user.get("role") not in ["company_admin", "full_control"]:
        print(f"Unauthorized access attempt by user: {current_user.get('username')}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only company admins and full control users can upload compliance files"
        )

    # Validate file types
    allowed_types = {
        "application/pdf": ".pdf",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
        "text/plain": ".txt",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
        "application/msword": ".doc",
        "application/vnd.ms-excel": ".xls",
        "application/zip": ".zip",
        "application/x-zip-compressed": ".zip"
    }
    
    processed_files = []
    errors = []

    try:
        for file in files:
            print(f"Processing file: {file.filename} of type: {file.content_type}")
            
            # Validate file type
            if file.content_type not in allowed_types:
                errors.append(f"Invalid file type for {file.filename}: {file.content_type}")
                continue

            # Handle ZIP files
            if file.content_type in ["application/zip", "application/x-zip-compressed"]:
                # Save ZIP file temporarily
                timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
                zip_path = os.path.join(UPLOAD_DIR, f"{timestamp}_{file.filename}")
                
                with open(zip_path, "wb") as f:
                    content = await file.read()
                    f.write(content)
                
                # Extract ZIP contents
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    # Create a directory for extracted files
                    extract_dir = os.path.join(UPLOAD_DIR, f"{timestamp}_extracted")
                    os.makedirs(extract_dir, exist_ok=True)
                    zip_ref.extractall(extract_dir)
                
                # Process each extracted file
                for root, _, extracted_files in os.walk(extract_dir):
                    for extracted_file in extracted_files:
                        file_path = os.path.join(root, extracted_file)
                        _, ext = os.path.splitext(extracted_file)
                        ext = ext.lower()
                        
                        # Skip non-allowed file types
                        if ext not in [v for v in allowed_types.values()]:
                            continue
                        
                        # Process the extracted file
                        try:
                            extracted_text = extract_text_from_file(file_path, ext)
                            processed_files.append({
                                "filename": extracted_file,
                                "path": file_path,
                                "text_preview": extracted_text[:500] + ("..." if len(extracted_text) > 500 else ""),
                                "text_path": file_path + ".txt"
                            })
                        except Exception as e:
                            errors.append(f"Error processing {extracted_file}: {str(e)}")
                
                # Clean up ZIP file
                os.remove(zip_path)
                
            else:
                # Process regular file
                timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
                filename = f"{timestamp}_{file.filename}"
                file_path = os.path.join(UPLOAD_DIR, filename)
                
                with open(file_path, "wb") as f:
                    content = await file.read()
                    f.write(content)
                
                # Extract text based on file type
                _, ext = os.path.splitext(filename)
                ext = ext.lower()
                try:
                    extracted_text = extract_text_from_file(file_path, ext)
                    processed_files.append({
                        "filename": filename,
                        "path": file_path,
                        "text_preview": extracted_text[:500] + ("..." if len(extracted_text) > 500 else ""),
                        "text_path": file_path + ".txt"
                    })
                except Exception as e:
                    errors.append(f"Error processing {file.filename}: {str(e)}")

        # Return results
        return {
            "processed_files": processed_files,
            "errors": errors,
            "total_files": len(processed_files),
            "total_errors": len(errors)
        }

    except Exception as e:
        print(f"Error processing files: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error processing files: {str(e)}"
        )

@router.get("/reports")
def list_compliance_reports(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") not in ["company_admin", "full_control"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    files = glob.glob(os.path.join(UPLOAD_DIR, "*.txt"))
    reports = []
    for txt_path in files:
        base = os.path.basename(txt_path)
        pdf_path = txt_path.replace(".txt", "")
        if os.path.exists(pdf_path):
            reports.append({
                "filename": os.path.basename(pdf_path),
                "text_path": txt_path,
                "upload_time": base.split("_")[0],  # crude, but works with your naming
            })
    return sorted(reports, key=lambda x: x["upload_time"], reverse=True)

@router.get("/report/{filename}")
def get_compliance_report(filename: str, current_user: dict = Depends(get_current_user)):
    if current_user.get("role") not in ["company_admin", "full_control"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    file_path = os.path.join(UPLOAD_DIR, filename)
    text_path = file_path + ".txt"
    vuln_path = file_path + ".vuln.json"
    
    print(f"Fetching report: {filename}")
    
    if not os.path.exists(file_path) or not os.path.exists(text_path):
        raise HTTPException(status_code=404, detail="Report not found")
    
    with open(text_path, "r", encoding="utf-8") as f:
        extracted_text = f.read()
    
    # Load vulnerabilities from JSON if it exists
    vulnerabilities = []
    if os.path.exists(vuln_path):
        print("Loading vulnerabilities from JSON")
        try:
            with open(vuln_path, "r", encoding="utf-8") as f:
                vulnerabilities = json.load(f)
            print(f"Loaded {len(vulnerabilities)} vulnerabilities from JSON")
        except Exception as e:
            print(f"Error loading JSON: {str(e)}")
            # If JSON is corrupted or empty, re-run analysis
            print("Re-running vulnerability analysis")
            vulnerabilities = extract_vulnerabilities_with_gpt(extracted_text)
            with open(vuln_path, "w", encoding="utf-8") as f:
                json.dump(vulnerabilities, f)
    else:
        print("No JSON found, running vulnerability analysis")
        # If no JSON exists, run analysis and save
        vulnerabilities = extract_vulnerabilities_with_gpt(extracted_text)
        with open(vuln_path, "w", encoding="utf-8") as f:
            json.dump(vulnerabilities, f)
    
    # Format the report preview
    preview_lines = []
    for line in extracted_text.split('\n'):
        if line.strip() and not line.startswith('[') and not line.startswith('©'):
            preview_lines.append(line)
        if len(preview_lines) >= 15:  # Limit to 15 meaningful lines
            break
    preview = '\n'.join(preview_lines)
    
    return {
        "filename": filename,
        "text_preview": preview,
        "vulnerabilities": vulnerabilities
    }

@router.get("/report/{filename}/csv")
def download_report_csv(filename: str, current_user: dict = Depends(get_current_user)):
    # ... (role check and file existence as before)
    file_path = os.path.join(UPLOAD_DIR, filename)
    text_path = file_path + ".txt"
    if not os.path.exists(file_path) or not os.path.exists(text_path):
        raise HTTPException(status_code=404, detail="Report not found")
    with open(text_path, "r", encoding="utf-8") as f:
        extracted_text = f.read()
    vulnerabilities = extract_vulnerabilities_with_gpt(extracted_text)
    for vuln in vulnerabilities:
        vuln["cis_controls"] = map_vulnerability_to_cis(vuln)
    # Write CSV to temp file
    csv_path = file_path + ".csv"
    with open(csv_path, "w", newline='', encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["CVE ID", "Description", "Affected Systems", "Remediation", "CIS Controls"])
        for v in vulnerabilities:
            cis = "; ".join([f'{c["cis_control"]}: {c["title"]}' for c in v.get("cis_controls", [])])
            writer.writerow([v.get("cve_id"), v.get("description"), v.get("affected_systems"), v.get("remediation_steps"), cis])
    return FileResponse(csv_path, filename=os.path.basename(csv_path), media_type="text/csv")

@router.get("/report/{filename}/pdf")
def download_report_pdf(filename: str, current_user: dict = Depends(get_current_user)):
    # ... (role check and file existence as before)
    file_path = os.path.join(UPLOAD_DIR, filename)
    text_path = file_path + ".txt"
    if not os.path.exists(file_path) or not os.path.exists(text_path):
        raise HTTPException(status_code=404, detail="Report not found")
    with open(text_path, "r", encoding="utf-8") as f:
        extracted_text = f.read()
    vulnerabilities = extract_vulnerabilities_with_gpt(extracted_text)
    for vuln in vulnerabilities:
        vuln["cis_controls"] = map_vulnerability_to_cis(vuln)
    # Write PDF to temp file
    pdf_path = file_path + ".pdf"
    pdf = UnicodeFPDF()
    pdf.add_page()
    pdf.set_font("helvetica", "B", 24)
    pdf.cell(0, 20, "NIST Compliance Assessment Report", ln=True, align="C")
    pdf.ln(5)
    
    pdf.set_font("helvetica", "", 10)
    pdf.cell(0, 5, f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="R")
    pdf.cell(0, 5, f"Report ID: {filename}", ln=True, align="R")
    pdf.ln(10)
    
    pdf.set_font("helvetica", "B", 16)
    pdf.cell(0, 10, "Executive Summary", ln=True)
    pdf.ln(5)
    
    pdf.set_font("helvetica", "", 12)
    compliance_score = (scan.compliant / scan.total_findings * 100) if scan.total_findings > 0 else 0
    pdf.multi_cell(0, 10, f"This compliance assessment report evaluates the organization's adherence to NIST security controls. "
                         f"The assessment identified {scan.total_findings} findings, with an overall compliance score of {compliance_score:.1f}%. "
                         f"Key areas of concern include access control policies, authentication mechanisms, and secure communications.")
    pdf.ln(10)
    
    pdf.set_font("helvetica", "B", 14)
    pdf.cell(0, 10, "Assessment Details", ln=True)
    pdf.ln(5)
    
    pdf.set_font("helvetica", "", 12)
    details = [
        ("Scan Name", scan.name),
        ("Compliance Type", scan.compliance_type),
        ("Status", scan.status),
        ("Total Findings", str(scan.total_findings)),
        ("Compliant", str(scan.compliant)),
        ("Non-Compliant", str(scan.non_compliant)),
        ("Assessment Date", str(scan.created_at))
    ]
    
    for label, value in details:
        pdf.cell(60, 10, label + ":", 0)
        pdf.cell(0, 10, value, ln=True)
    
    pdf.ln(10)
    
    pdf.set_font("helvetica", "B", 14)
    pdf.cell(0, 10, "Compliance Status Overview", ln=True)
    pdf.ln(5)
    
    status_groups = {}
    for finding in findings:
        if finding.status not in status_groups:
            status_groups[finding.status] = []
        status_groups[finding.status].append(finding)
    
    for status, status_findings in status_groups.items():
        pdf.set_font("helvetica", "B", 12)
        pdf.cell(0, 10, f"{status.title()} Findings ({len(status_findings)})", ln=True)
        pdf.set_font("helvetica", "", 12)
        
        for finding in status_findings:
            pdf.cell(0, 10, f"Control ID: {finding.control_id}", ln=True)
            pdf.multi_cell(0, 10, f"Description: {finding.description}")
            pdf.ln(5)
    
    pdf.add_page()
    pdf.set_font("helvetica", "B", 16)
    pdf.cell(0, 10, "Detailed Findings and Recommendations", ln=True)
    pdf.ln(5)
    
    for finding in findings:
        pdf.set_font("helvetica", "B", 12)
        pdf.cell(0, 10, f"Control ID: {finding.control_id}", ln=True)
        pdf.set_font("helvetica", "", 12)
        
        status_color = (255, 0, 0) if finding.status == "non-compliant" else (0, 128, 0)
        pdf.set_text_color(*status_color)
        pdf.cell(0, 10, f"Status: {finding.status.title()}", ln=True)
        pdf.set_text_color(0, 0, 0)
        
        pdf.set_font("helvetica", "B", 11)
        pdf.cell(0, 10, "Description:", ln=True)
        pdf.set_font("helvetica", "", 11)
        
        # Get control details from NIST catalog through the rules engine
        control_details = nist_analyzer.rules_engine._get_control_details(finding.control_id)
        control_description = control_details.get('description', 'Control description not found')
        pdf.multi_cell(0, 10, control_description)
        
        # Evidence & Findings Summary
        pdf.set_font("helvetica", "B", 11)
        pdf.cell(0, 10, "Evidence & Findings Summary:", ln=True)
        pdf.set_font("helvetica", "", 11)
        
        # Get evidence summary from the finding's description field
        evidence_summary = finding.description if finding.description else "No specific findings were identified."
        
        # Check if the evidence summary is actually a NIST control description
        if (evidence_summary.startswith("Control ") or 
            evidence_summary.startswith("The organization ") or 
            evidence_summary.startswith("The system ") or
            "not found in NIST catalog" in evidence_summary):
            evidence_summary = "No specific findings were identified."
        
        pdf.multi_cell(0, 10, evidence_summary)
        
        if finding.recommendation:
            pdf.set_font("helvetica", "B", 11)
            pdf.cell(0, 10, "Recommendation:", ln=True)
            pdf.set_font("helvetica", "", 11)
            pdf.multi_cell(0, 10, finding.recommendation)
        
        pdf.ln(10)
    
    pdf.set_y(-15)
    pdf.set_font("helvetica", "I", 8)
    pdf.cell(0, 10, f"Page {pdf.page_no()}", 0, 0, "C")
    
    pdf.output(pdf_path)
    
    return FileResponse(
        str(pdf_path),
        media_type="application/pdf",
        filename=f"{scan.name}_report.pdf"
    )

@router.delete("/report/{filename}")
def delete_compliance_report(filename: str, current_user: dict = Depends(get_current_user)):
    if current_user.get("role") not in ["company_admin", "full_control"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    file_path = os.path.join(UPLOAD_DIR, filename)
    text_path = file_path + ".txt"
    vuln_path = file_path + ".vuln.json"
    
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Report not found")
    
    try:
        # Delete all associated files
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(text_path):
            os.remove(text_path)
        if os.path.exists(vuln_path):
            os.remove(vuln_path)
        
        return {"message": "Report deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete report: {str(e)}")

@router.get("/scans/", response_model=List[ComplianceScan])
def get_compliance_scans(
    network_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get compliance scans for a specific network."""
    # Check if user has access to the network
    network = db.query(Network).filter(Network.id == network_id).first()
    if not network:
        raise HTTPException(status_code=404, detail="Network not found")

    # For company admins, get all scans in their company's networks
    if current_user["role"] == "company_admin":
        return db.query(models.ComplianceScan).filter(
            models.ComplianceScan.network_id == network_id
        ).all()
    
    # For other users, check network access
    access_record = db.query(UserNetworkAccess).filter(
        UserNetworkAccess.user_id == current_user["user_id"],
        UserNetworkAccess.network_id == network_id
    ).first()
    
    if not access_record:
        raise HTTPException(status_code=403, detail="Not authorized to access this network")
    
    return db.query(models.ComplianceScan).filter(
        models.ComplianceScan.network_id == network_id
    ).all()

async def process_compliance_scan(scan_id: int, db: Session):
    """Background task to process a compliance scan."""
    try:
        # Get the scan
        scan = db.query(models.ComplianceScan).filter(models.ComplianceScan.id == scan_id).first()
        if not scan:
            logger.error(f"Scan {scan_id} not found")
            return

        # Update status to processing
        scan.status = "processing"
        db.commit()

        # Get all files for this scan
        files = db.query(models.ComplianceFile).filter(models.ComplianceFile.scan_id == scan_id).all()
        
        if not files:
            logger.error(f"No files found for scan {scan_id}")
            scan.status = "failed"
            db.commit()
            return

        total_findings = 0
        compliant = 0
        non_compliant = 0

        # Initialize NIST analyzer
        nist_analyzer = NISTAnalyzer()

        # Process each file
        for file in files:
            try:
                # Extract text from file
                text = extract_text_from_file(file.file_path, file.file_type)
                if not text:
                    logger.warning(f"No text extracted from file {file.filename}")
                    continue
                
                # Analyze text using NIST analyzer
                findings = nist_analyzer.analyze_report(text, scan.compliance_type)
                
                # Create findings in database
                for finding in findings:
                    # Use evidence_summary for description if it exists, otherwise use description
                    finding_description = finding.get("evidence_summary")
                    if not finding_description:
                        finding_description = finding.get("description")
                    
                    # Format recommendation as a string
                    recommendation = finding.get("remediation") or finding.get("recommendation")
                    if isinstance(recommendation, dict) and "steps" in recommendation:
                        recommendation = "\n".join(f"{i+1}. {step}" for i, step in enumerate(recommendation["steps"]))
                    elif not recommendation:
                        recommendation = "No specific remediation steps provided."
                    
                    # Create the finding object
                    db_finding = models.ComplianceFinding(
                        scan_id=scan_id,
                        file_id=file.id,
                        control_id=finding.get("control_id"),
                        description=finding_description,
                        status=finding.get("status", "non-compliant").lower().replace("_", "-"),
                        recommendation=recommendation,
                        confidence=finding.get("confidence", 0.8)
                    )
                    db.add(db_finding)
                    
                    total_findings += 1
                    if finding.get("status", "").lower() == "compliant":
                        compliant += 1
                    else:
                        non_compliant += 1
                
                # Mark file as analyzed
                file.is_analyzed = True
                db.add(file)
                
                # Commit after each file
                db.commit()
                
            except Exception as e:
                logger.error(f"Error processing file {file.filename}: {str(e)}")
                continue

        # Update scan metrics
        scan.status = "completed"
        scan.total_findings = total_findings
        scan.compliant = compliant
        scan.non_compliant = non_compliant
        db.commit()

        logger.info(f"Completed processing scan {scan_id} with {total_findings} findings ({compliant} compliant, {non_compliant} non-compliant)")

    except Exception as e:
        logger.error(f"Error processing scan {scan_id}: {str(e)}")
        # Update scan status to failed
        scan = db.query(models.ComplianceScan).filter(models.ComplianceScan.id == scan_id).first()
        if scan:
            scan.status = "failed"
            db.commit()

@router.post("/scans", response_model=ComplianceScan)
async def create_compliance_scan(
    name: str = Form(...),
    network_id: int = Form(...),
    compliance_type: str = Form(...),
    files: List[UploadFile] = File(None),
    background_tasks: BackgroundTasks = None,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Create a new compliance scan for a network."""
    try:
        # Check if network exists and user has access
        network = db.query(Network).filter(Network.id == network_id).first()
        if not network:
            raise HTTPException(status_code=404, detail="Network not found")

        # For company admins and full control users, allow creation
        if current_user["role"] in ["company_admin", "full_control"]:
            db_scan = models.ComplianceScan(
                name=name,
                network_id=network_id,
                organization_id=network.organization_id,
                compliance_type=compliance_type,
                status="pending",
                total_findings=0,
                compliant=0,
                non_compliant=0
            )
            db.add(db_scan)
            db.commit()
            db.refresh(db_scan)

            # Handle file uploads if any
            if files:
                for file in files:
                    # Save file to upload directory
                    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
                    filename = f"{timestamp}_{file.filename}"
                    file_path = os.path.join(UPLOAD_DIR, filename)
                    
                    # Save file content
                    content = await file.read()
                    with open(file_path, "wb") as f:
                        f.write(content)
                    
                    # Create compliance file record
                    db_file = models.ComplianceFile(
                        scan_id=db_scan.id,
                        filename=filename,
                        file_path=file_path,
                        file_type=file.content_type
                    )
                    db.add(db_file)
                
                db.commit()

                # Start background processing
                if background_tasks:
                    background_tasks.add_task(process_compliance_scan, db_scan.id, db)

            return db_scan
        
        # For other users, check network access
        access_record = db.query(UserNetworkAccess).filter(
            UserNetworkAccess.user_id == current_user["user_id"],
            UserNetworkAccess.network_id == network_id
        ).first()
        
        if not access_record:
            raise HTTPException(status_code=403, detail="Not authorized to create scans for this network")
        
        db_scan = models.ComplianceScan(
            name=name,
            network_id=network_id,
            organization_id=network.organization_id,
            compliance_type=compliance_type,
            status="pending",
            total_findings=0,
            compliant=0,
            non_compliant=0
        )
        db.add(db_scan)
        db.commit()
        db.refresh(db_scan)

        # Handle file uploads if any
        if files:
            for file in files:
                # Save file to upload directory
                timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
                filename = f"{timestamp}_{file.filename}"
                file_path = os.path.join(UPLOAD_DIR, filename)
                
                # Save file content
                content = await file.read()
                with open(file_path, "wb") as f:
                    f.write(content)
                
                # Create compliance file record
                db_file = models.ComplianceFile(
                    scan_id=db_scan.id,
                    filename=filename,
                    file_path=file_path,
                    file_type=file.content_type
                )
                db.add(db_file)
            
            db.commit()

            # Start background processing
            if background_tasks:
                background_tasks.add_task(process_compliance_scan, db_scan.id, db)

        return db_scan
    except Exception as e:
        db.rollback()
        logger.error(f"Error creating compliance scan: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error creating compliance scan: {str(e)}")

@router.get("/scans/{scan_id}", response_model=ComplianceScan)
def read_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get a specific compliance scan."""
    scan = crud.get_compliance_scan(db=db, scan_id=scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Allow company admins and full control users to access any scan
    if current_user.get('role') in ['company_admin', 'full_control']:
        logger.info(f"{current_user.get('role')} access granted for scan ID: {scan_id}")
    # For other users, verify organization access
    elif current_user.get('company_id') != scan.organization_id:
        logger.error(f"Unauthorized access attempt for scan ID: {scan_id} by user: {current_user.get('username')}")
        logger.error(f"User company_id ({current_user.get('company_id')}) does not match scan organization_id ({scan.organization_id})")
        raise HTTPException(status_code=403, detail="Not authorized to access this scan")
    
    # If scan is in processing state, check if it's been too long
    if scan.status == "processing":
        # If scan has been processing for more than 30 minutes, mark it as failed
        if (datetime.now(timezone.utc) - scan.updated_at).total_seconds() > 1800:  # 30 minutes
            scan.status = "failed"
            db.commit()
            logger.warning(f"Scan {scan_id} marked as failed due to timeout")
    
    return scan

@router.put("/scans/{scan_id}", response_model=ComplianceScan)
def update_scan(
    scan_id: int,
    scan: ComplianceScanUpdate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    db_scan = crud.get_compliance_scan(db=db, scan_id=scan_id)
    if db_scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Verify user has access to the organization
    if not any(org.id == db_scan.organization_id for org in current_user.organizations):
        raise HTTPException(status_code=403, detail="Not authorized to update this scan")
    
    return crud.update_compliance_scan(db=db, scan_id=scan_id, scan=scan)

@router.delete("/scans/{scan_id}")
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    db_scan = crud.get_compliance_scan(db=db, scan_id=scan_id)
    if db_scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Allow company admins and full control users to delete any scan
    if current_user["role"] in ["company_admin", "full_control"]:
        success = crud.delete_compliance_scan(db=db, scan_id=scan_id)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to delete scan")
        return {"message": "Scan deleted successfully"}
    
    # For other users, verify access to the organization
    if current_user.get('company_id') != db_scan.organization_id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this scan")
    
    success = crud.delete_compliance_scan(db=db, scan_id=scan_id)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to delete scan")
    
    return {"message": "Scan deleted successfully"}

@router.get("/scans/{scan_id}/findings", response_model=List[ComplianceFinding])
def read_findings(
    scan_id: int,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    scan = crud.get_compliance_scan(db=db, scan_id=scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Allow company admins and full control users to access any scan
    if current_user.get('role') in ['company_admin', 'full_control']:
        logger.info(f"{current_user.get('role')} access granted for scan ID: {scan_id}")
    # For other users, verify organization access through UserNetworkAccess
    else:
        access_record = db.query(UserNetworkAccess).filter(
            UserNetworkAccess.user_id == current_user["user_id"],
            UserNetworkAccess.network_id == scan.network_id
        ).first()
        
        if not access_record:
            logger.error(f"Unauthorized access attempt for scan ID: {scan_id} by user: {current_user.get('username')}")
            logger.error(f"User does not have access to network_id: {scan.network_id}")
            raise HTTPException(status_code=403, detail="Not authorized to access these findings")
    
    findings = crud.get_compliance_findings(
        db=db,
        scan_id=scan_id,
        skip=skip,
        limit=limit
    )
    return findings

@router.get("/scans/{scan_id}/files", response_model=List[ComplianceFile])
def read_files(
    scan_id: int,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    scan = crud.get_compliance_scan(db=db, scan_id=scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Verify user has access to the organization
    if not any(org.id == scan.organization_id for org in current_user.organizations):
        raise HTTPException(status_code=403, detail="Not authorized to access these files")
    
    files = crud.get_compliance_files(
        db=db,
        scan_id=scan_id,
        skip=skip,
        limit=limit
    )
    return files

@router.get("/scans/{scan_id}/download-pdf")
def download_scan_pdf(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    logger.info(f"Starting PDF generation for scan ID: {scan_id}")
    
    # Get scan and verify access
    scan = crud.get_compliance_scan(db=db, scan_id=scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Check user access
    if current_user.get("role") in ["company_admin", "full_control"]:
        logger.info(f"User role: {current_user.get('role')}")
        logger.info(f"{current_user.get('role')} access granted for scan ID: {scan_id}")
    else:
        if not crud.verify_user_access(db=db, user_id=current_user.get("user_id"), organization_id=scan.organization_id):
            raise HTTPException(status_code=403, detail="Not authorized to access this scan")
    
    # Get findings
    findings = crud.get_compliance_findings(db=db, scan_id=scan_id)
    logger.info(f"Found {len(findings)} findings")
    
    # Get files
    files = crud.get_compliance_files(db=db, scan_id=scan_id)
    logger.info(f"Found {len(files)} files")
    
    # Create reports directory if it doesn't exist
    reports_dir = Path("data/reports")
    reports_dir.mkdir(parents=True, exist_ok=True)
    logger.info(f"Reports directory: {reports_dir}")
    
    # Create report generator
    report_generator = ReportGenerator()
    
    # Calculate metrics
    metrics = {
        "total_controls": len(findings),
        "compliant": sum(1 for f in findings if f.status == "compliant"),
        "non_compliant": sum(1 for f in findings if f.status == "non-compliant"),
        "not_applicable": sum(1 for f in findings if f.status == "not_applicable")
    }
    
    # Convert findings to dict format
    findings_data = []
    for finding in findings:
        # Get control details from NIST catalog
        control_details = nist_analyzer.rules_engine._get_control_details(finding.control_id)
        
        # Get the filename for this finding
        filename = "Unknown File"
        if finding.file_id:
            for file in files:
                if file.id == finding.file_id:
                    filename = file.filename
                    break
        
        findings_data.append({
            "control_id": finding.control_id,
            "status": finding.status,
            "description": control_details.get('description', 'Control description not found'),
            "evidence_summary": finding.description,  # Use description as evidence since it contains the findings
            "risk_rating": {
                "level": "High" if finding.status == "non-compliant" else "Low",
                "impact": "Significant impact on security posture" if finding.status == "non-compliant" else "Minimal impact on security posture"
            },
            "recommendation": finding.recommendation or "No specific remediation steps provided.",
            "file_name": filename  # Add the filename directly to the finding
        })
    
    # Generate PDF report
    logger.info("Creating PDF document")
    pdf_path = report_generator.generate_pdf_report(
        scan_id=scan_id,
        scan_name=scan.name,
        findings=findings_data,
        metrics=metrics,
        output_path=str(reports_dir)
    )
    logger.info(f"Saving PDF to: {pdf_path}")
    logger.info("PDF generation completed successfully")
    
    return FileResponse(
        path=pdf_path,
        filename=f"nist_compliance_report_{scan_id}.pdf",
        media_type="application/pdf"
    )

@router.get("/scans/{scan_id}/download-excel")
def download_scan_excel(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    logger.info(f"Starting Excel generation for scan ID: {scan_id}")
    try:
        scan = crud.get_compliance_scan(db=db, scan_id=scan_id)
        if scan is None:
            logger.error(f"Scan not found for ID: {scan_id}")
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Add debug logging
        logger.info(f"User company_id: {current_user.get('company_id')}")
        logger.info(f"Scan organization_id: {scan.organization_id}")
        logger.info(f"User role: {current_user.get('role')}")
        
        # Allow company admins and full control users to access any scan
        if current_user.get('role') in ['company_admin', 'full_control']:
            logger.info(f"{current_user.get('role')} access granted for scan ID: {scan_id}")
        # For other users, verify organization access
        elif current_user.get('company_id') != scan.organization_id:
            logger.error(f"Unauthorized access attempt for scan ID: {scan_id} by user: {current_user.get('username')}")
            logger.error(f"User company_id ({current_user.get('company_id')}) does not match scan organization_id ({scan.organization_id})")
            raise HTTPException(status_code=403, detail="Not authorized to access this scan")
        
        # Get all findings for this scan
        findings = crud.get_compliance_findings(db=db, scan_id=scan_id)
        
        # Create Excel file
        output = io.BytesIO()
        workbook = xlsxwriter.Workbook(output)
        
        # Add formats
        header_format = workbook.add_format({
            'bold': True,
            'bg_color': '#4472C4',
            'font_color': 'white',
            'border': 1
        })
        
        status_format = workbook.add_format({
            'bold': True,
            'bg_color': '#92D050',
            'border': 1
        })
        
        non_compliant_format = workbook.add_format({
            'bold': True,
            'bg_color': '#FF0000',
            'font_color': 'white',
            'border': 1
        })
        
        # Create Overview sheet
        overview_sheet = workbook.add_worksheet("Overview")
        overview_sheet.set_column('A:B', 30)
        
        # Add scan details
        details = [
            ["Scan Name", scan.name],
            ["Compliance Type", scan.compliance_type],
            ["Status", scan.status],
            ["Total Findings", scan.total_findings],
            ["Compliant", scan.compliant],
            ["Non-Compliant", scan.non_compliant],
            ["Created At", str(scan.created_at)]
        ]
        
        for row, (label, value) in enumerate(details):
            overview_sheet.write(row, 0, label, header_format)
            overview_sheet.write(row, 1, value)
        
        # Add compliance score
        compliance_score = (scan.compliant / scan.total_findings * 100) if scan.total_findings > 0 else 0
        overview_sheet.write(8, 0, "Compliance Score", header_format)
        overview_sheet.write(8, 1, f"{compliance_score:.1f}%")
        
        # Create Findings sheet
        findings_sheet = workbook.add_worksheet("Findings")
        findings_sheet.set_column('A:A', 15)  # Control ID
        findings_sheet.set_column('B:B', 15)  # Status
        findings_sheet.set_column('C:C', 50)  # Description
        findings_sheet.set_column('D:D', 50)  # Recommendation
        
        # Add headers
        headers = ["Control ID", "Status", "Description", "Recommendation"]
        for col, header in enumerate(headers):
            findings_sheet.write(0, col, header, header_format)
        
        # Add findings with conditional formatting
        for row, finding in enumerate(findings, start=1):
            findings_sheet.write(row, 0, finding.control_id)
            
            # Apply status-based formatting
            status_format_to_use = status_format if finding.status == "compliant" else non_compliant_format
            findings_sheet.write(row, 1, finding.status, status_format_to_use)
            
            findings_sheet.write(row, 2, finding.description)
            findings_sheet.write(row, 3, finding.recommendation)
        
        # Create Summary sheet
        summary_sheet = workbook.add_worksheet("Summary")
        summary_sheet.set_column('A:B', 30)
        
        # Group findings by status
        status_groups = {}
        for finding in findings:
            if finding.status not in status_groups:
                status_groups[finding.status] = []
            status_groups[finding.status].append(finding)
        
        # Add status summary
        summary_sheet.write(0, 0, "Status", header_format)
        summary_sheet.write(0, 1, "Count", header_format)
        
        for row, (status, status_findings) in enumerate(status_groups.items(), start=1):
            summary_sheet.write(row, 0, status.title())
            summary_sheet.write(row, 1, len(status_findings))
        
        # Add chart
        chart_sheet = workbook.add_worksheet("Charts")
        
        # Create pie chart for compliance status
        pie_chart = workbook.add_chart({'type': 'pie'})
        pie_chart.add_series({
            'name': 'Compliance Status',
            'categories': ['Summary', 1, 0, len(status_groups), 0],
            'values': ['Summary', 1, 1, len(status_groups), 1],
        })
        chart_sheet.insert_chart('A1', pie_chart)
        
        workbook.close()
        output.seek(0)
        
        # Return file
        return StreamingResponse(
            output,
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f"attachment; filename={scan.name}_report.xlsx"}
        )
        
    except Exception as e:
        logger.error(f"Error generating Excel report: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error generating Excel report: {str(e)}")

@router.post("/scans/{scan_id}/reprocess")
async def reprocess_scan(
    scan_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Reprocess a compliance scan."""
    # Get the scan
    scan = crud.get_compliance_scan(db=db, scan_id=scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Allow company admins and full control users to access any scan
    if current_user.get('role') in ['company_admin', 'full_control']:
        logger.info(f"{current_user.get('role')} access granted for scan ID: {scan_id}")
    # For other users, verify organization access
    elif current_user.get('company_id') != scan.organization_id:
        logger.error(f"Unauthorized access attempt for scan ID: {scan_id} by user: {current_user.get('username')}")
        logger.error(f"User company_id ({current_user.get('company_id')}) does not match scan organization_id ({scan.organization_id})")
        raise HTTPException(status_code=403, detail="Not authorized to access this scan")
    
    # Delete existing findings
    db.query(models.ComplianceFinding).filter(models.ComplianceFinding.scan_id == scan_id).delete()
    
    # Reset scan status and metrics
    scan.status = "pending"
    scan.total_findings = 0
    scan.compliant = 0
    scan.non_compliant = 0
    db.commit()
    
    # Start background processing
    background_tasks.add_task(process_compliance_scan, scan_id, db)
    
    return {"message": "Scan reprocessing started"} 