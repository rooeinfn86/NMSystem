import os
import logging
from typing import List, Dict, Any, Optional
from openai import OpenAI
from pathlib import Path
import json
from app.services.nist_engine.gpt_cache import GPTCache
from app.services.nist_engine.gpt_cost_tracker import GPTCostTracker
from app.core.config import settings
import re
import tiktoken
from collections import defaultdict
import time
import openai
import hashlib
import ijson

# Set up logging
logger = logging.getLogger(__name__)

class NISTGPTAnalyzer:
    def __init__(self):
        # Initialize OpenAI client
        self.client = OpenAI(api_key=settings.OPENAI_API_KEY)
        logger.info("Initialized NISTGPTAnalyzer with OpenAI client")
        
        # Initialize tokenizer
        self.tokenizer = tiktoken.encoding_for_model("gpt-4-turbo-preview")
        
        # Load NIST catalog
        catalog_path = Path(__file__).parent / "NIST_SP-800-53_rev5_catalog.json"
        logger.info(f"Loading NIST catalog from: {catalog_path}")
        self.nist_catalog = []
        try:
            with open(catalog_path, "rb") as f:  # Open in binary mode for ijson
                # Stream parse the JSON file
                parser = ijson.parse(f)
                current_control = {}
                in_control = False
                
                for prefix, event, value in parser:
                    if prefix.endswith('.controls.item'):
                        if event == 'start_map':
                            current_control = {}
                            in_control = True
                        elif event == 'end_map' and in_control:
                            if current_control:  # Only add if we have data
                                self.nist_catalog.append(current_control)
                            in_control = False
                    elif in_control:
                        if prefix.endswith('.id'):
                            # Normalize control ID to uppercase during loading
                            current_control['id'] = value.upper() if value else ''
                        elif prefix.endswith('.title'):
                            current_control['title'] = value
                        elif prefix.endswith('.parts.item.name') and value == 'statement':
                            # Get next prose value
                            for p, e, v in parser:
                                if p.endswith('.prose'):
                                    current_control['description'] = v
                                    break
                        elif prefix.endswith('.parts.item.name') and value == 'guidance':
                            if 'requirements' not in current_control:
                                current_control['requirements'] = []
                            # Get next prose value
                            for p, e, v in parser:
                                if p.endswith('.prose'):
                                    current_control['requirements'].append(v)
                                    break
            
            logger.info(f"Loaded {len(self.nist_catalog)} controls from NIST catalog")
            
            # Log sample control IDs to verify structure
            if self.nist_catalog:
                sample_controls = self.nist_catalog[:5]
                control_ids = [c.get('id', 'unknown').split('_')[0].upper() for c in sample_controls]
                logger.info(f"Sample control IDs: {control_ids}")
            
        except Exception as e:
            logger.error(f"Error loading NIST catalog: {str(e)}")
            self.nist_catalog = []
        
        # Initialize cache
        self.cache = {}
        
        # Initialize cost tracker
        self.cost_tracker = GPTCostTracker()

    def _count_tokens(self, text: str) -> int:
        """Count the number of tokens in a text string."""
        return len(self.tokenizer.encode(text))

    def _smart_chunk_text(self, text: str, max_tokens: int = 4000) -> List[str]:
        """
        Intelligently chunk text while preserving context and reducing token usage.
        
        Args:
            text: The text to chunk
            max_tokens: Maximum tokens per chunk (default: 4000 to stay well under limits)
            
        Returns:
            List of text chunks
        """
        # First, try to split by sections if they exist
        sections = re.split(r'\n(?=#|\d+\.|\w+\s*:)', text)
        
        chunks = []
        current_chunk = []
        current_tokens = 0
        
        for section in sections:
            section_tokens = self._count_tokens(section)
            
            # If section is too large, split it into smaller pieces
            if section_tokens > max_tokens:
                # Split by paragraphs
                paragraphs = section.split('\n\n')
                for paragraph in paragraphs:
                    para_tokens = self._count_tokens(paragraph)
                    
                    if current_tokens + para_tokens > max_tokens:
                        if current_chunk:
                            chunks.append('\n\n'.join(current_chunk))
                            current_chunk = []
                            current_tokens = 0
                        
                        # If paragraph itself is too large, split by sentences
                        if para_tokens > max_tokens:
                            sentences = re.split(r'(?<=[.!?])\s+', paragraph)
                            for sentence in sentences:
                                sent_tokens = self._count_tokens(sentence)
                                if current_tokens + sent_tokens > max_tokens:
                                    if current_chunk:
                                        chunks.append('\n\n'.join(current_chunk))
                                        current_chunk = []
                                        current_tokens = 0
                                current_chunk.append(sentence)
                                current_tokens += sent_tokens
                        else:
                            current_chunk.append(paragraph)
                            current_tokens += para_tokens
                    else:
                        current_chunk.append(paragraph)
                        current_tokens += para_tokens
            else:
                if current_tokens + section_tokens > max_tokens:
                    if current_chunk:
                        chunks.append('\n\n'.join(current_chunk))
                        current_chunk = []
                        current_tokens = 0
                current_chunk.append(section)
                current_tokens += section_tokens
        
        if current_chunk:
            chunks.append('\n\n'.join(current_chunk))
        
        return chunks

    def _split_large_chunk(self, chunk: str, max_tokens: int) -> List[str]:
        """Split a large chunk into smaller pieces."""
        sub_chunks = []
        current_sub_chunk = []
        current_tokens = 0
        
        # Split by sentences first
        sentences = re.split(r'(?<=[.!?])\s+', chunk)
        
        for sentence in sentences:
            sent_tokens = self._count_tokens(sentence)
            
            if current_tokens + sent_tokens > max_tokens:
                if current_sub_chunk:
                    sub_chunks.append(' '.join(current_sub_chunk))
                    current_sub_chunk = []
                    current_tokens = 0
            
            current_sub_chunk.append(sentence)
            current_tokens += sent_tokens
        
        if current_sub_chunk:
            sub_chunks.append(' '.join(current_sub_chunk))
        
        return sub_chunks

    def _merge_findings(self, findings_list: List[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """
        Merge findings from multiple chunks, removing duplicates and combining evidence.
        
        Args:
            findings_list: List of findings from each chunk
            
        Returns:
            Merged list of findings
        """
        merged_findings = defaultdict(lambda: {
            'control_id': '',
            'status': '',
            'description': '',
            'recommendation': '',
            'confidence': 0,
            'evidence': []
        })
        
        for findings in findings_list:
            for finding in findings:
                control_id = finding['control_id']
                if control_id not in merged_findings:
                    merged_findings[control_id] = finding.copy()
                else:
                    # Update confidence if new finding has higher confidence
                    if finding['confidence'] > merged_findings[control_id]['confidence']:
                        merged_findings[control_id]['confidence'] = finding['confidence']
                        merged_findings[control_id]['status'] = finding['status']
                    
                    # Combine evidence
                    merged_findings[control_id]['evidence'].extend(finding['evidence'])
                    
                    # Combine descriptions and recommendations
                    if finding['description'] not in merged_findings[control_id]['description']:
                        merged_findings[control_id]['description'] += f"\n{finding['description']}"
                    if finding['recommendation'] not in merged_findings[control_id]['recommendation']:
                        merged_findings[control_id]['recommendation'] += f"\n{finding['recommendation']}"
        
        return list(merged_findings.values())

    def _get_cache_key(self, text: str) -> str:
        """Generate a cache key for the text content."""
        return hashlib.md5(text.encode()).hexdigest()

    def analyze_report(
        self,
        report_text: str,
        report_type: str,
        rule_findings: List[Dict[str, Any]] = None,
        user_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Analyze a report using GPT to identify NIST control findings.
        """
        logger.info("Starting GPT analysis of report")
        all_findings = []

        try:
            # Verify OpenAI API key is set
            if not settings.OPENAI_API_KEY:
                logger.error("OpenAI API key is not set")
                return []
            
            # Check cache first
            cache_key = self._get_cache_key(report_text)
            if cache_key in self.cache:
                logger.info("Using cached GPT analysis results")
                return self.cache[cache_key]
            
            # Split the report into smaller chunks
            chunks = self._split_text(report_text)
            logger.info(f"Split report into {len(chunks)} chunks")
            
            # Process each chunk
            for i, chunk in enumerate(chunks, 1):
                logger.info(f"Analyzing chunk {i}/{len(chunks)}")
                try:
                    chunk_findings = self._analyze_chunk(
                        chunk,
                        i,
                        len(chunks),
                        report_type,
                        rule_findings or []
                    )
                    if chunk_findings:
                        logger.info(f"Found {len(chunk_findings)} findings in chunk {i}")
                        all_findings.extend(chunk_findings)
                    else:
                        logger.info(f"No findings in chunk {i}")
                    
                    # Add a delay between chunks to avoid rate limits
                    if i < len(chunks):
                        time.sleep(5)
                except Exception as e:
                    logger.error(f"Error analyzing chunk {i}: {str(e)}")
                    continue
            
            # Cache the results
            self.cache[cache_key] = all_findings
            logger.info(f"GPT analysis complete. Total findings: {len(all_findings)}")
            
        except Exception as e:
            logger.error(f"Error in GPT analysis: {str(e)}")
            logger.error(f"Error type: {type(e).__name__}")
            logger.error(f"Error details: {str(e)}")
        
        return all_findings

    def _split_text(self, text: str) -> List[str]:
        """Split text into chunks for GPT analysis."""
        # Use the smart chunking method
        return self._smart_chunk_text(text)

    def _analyze_chunk(
        self,
        chunk: str,
        chunk_num: int,
        total_chunks: int,
        report_type: str,
        rule_findings: List[Dict[str, Any]]
    ) -> List[Dict]:
        """Analyze a single chunk of the report."""
        max_retries = 5
        base_delay = 5
        max_delay = 60

        for attempt in range(max_retries):
            try:
                # Calculate delay with exponential backoff
                delay = min(base_delay * (2 ** attempt), max_delay)
                
                logger.info(f"Calling GPT API for chunk {chunk_num} (attempt {attempt + 1}/{max_retries})")
                logger.info(f"Waiting {delay} seconds before API call...")
                time.sleep(delay)
                
                # Prepare messages
                system_message = self._prepare_system_message(report_type, rule_findings)
                user_message = self._prepare_user_message(chunk, chunk_num, total_chunks)
                
                # Call GPT API
                response = self.client.chat.completions.create(
                    model="gpt-4-turbo-preview",
                    messages=[
                        {"role": "system", "content": system_message},
                        {"role": "user", "content": user_message}
                    ],
                    temperature=0.2,
                    max_tokens=2000
                )
                
                # Get the response content
                content = response.choices[0].message.content
                logger.info(f"Raw GPT response for chunk {chunk_num}: {content}")
                
                # Parse JSON response
                findings = []
                if not content.strip():
                    return findings
                
                # Try to extract JSON if wrapped in ```json or ```
                if "```json" in content:
                    content = content.split("```json")[1].split("```")[0]
                elif "```" in content:
                    content = content.split("```")[1].split("```")[0]
                
                # Parse the JSON content
                try:
                    finding_data = json.loads(content)
                    
                    # Handle both single finding and list of findings
                    if isinstance(finding_data, dict):
                        finding_data = [finding_data]
                    
                    for finding in finding_data:
                        # Normalize and validate control ID
                        control_id = finding.get('control_id', '')
                        if not control_id:
                            continue
                        
                        # Normalize control ID to uppercase and remove any suffixes
                        control_id = control_id.split('_')[0].upper()
                        
                        # Check if control exists in catalog (case-insensitive)
                        control_exists = any(
                            c.get('id', '').split('_')[0].split('.')[0].upper() == control_id.split('.')[0]
                            for c in self.nist_catalog
                        )
                        
                        if not control_exists:
                            logger.warning(f"Control ID {control_id} not found in catalog")
                            continue
                        
                        # Ensure required fields are present
                        if not all(key in finding for key in ['status', 'evidence_summary']):
                            continue
                        
                        # Validate evidence is not generic
                        evidence = finding.get('evidence_summary', '')
                        if not evidence or evidence.lower().startswith("no specific"):
                            continue
                        
                        # Add finding with normalized fields
                        processed_finding = {
                            'control_id': control_id,  # Use normalized uppercase ID
                            'status': finding.get('status', 'unknown'),
                            'description': finding.get('description', ''),
                            'evidence_summary': evidence,
                            'risk_rating': finding.get('risk_rating', {
                                'level': 'Unknown',
                                'impact': 'Impact cannot be determined'
                            }),
                            'recommendation': finding.get('remediation', finding.get('recommendation', '')),
                            'confidence': finding.get('confidence', 0.8),
                            'technical_details': finding.get('technical_details', ''),
                            'type': 'analysis'
                        }
                        findings.append(processed_finding)
                        logger.info(f"Found valid finding for control {control_id}")
                    
                    if not findings:
                        logger.warning(f"No valid findings in chunk {chunk_num}")
                    else:
                        logger.info(f"Found {len(findings)} valid findings in chunk {chunk_num}")
                    
                    return findings
                    
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse GPT response as JSON: {str(e)}")
                    logger.error(f"Raw response: {content}")
                    if attempt < max_retries - 1:
                        continue
                    return []
                
            except Exception as e:
                logger.error(f"Error in GPT API call (attempt {attempt + 1}): {str(e)}")
                if attempt < max_retries - 1:
                    continue
                else:
                    logger.error("Max retries reached for GPT API call")
                    return []
        
        logger.info(f"No findings in chunk {chunk_num}")
        return []

    def _prepare_system_message(self, report_type: str, rule_findings: List[Dict[str, Any]]) -> str:
        """Prepare the system message for GPT analysis."""
        relevant_controls = []
        for finding in rule_findings[:50]:
            control_id = finding.get('control_id')
            if control_id:
                for control in self.nist_catalog:
                    if control['id'].upper() == control_id.upper():
                        relevant_controls.append(control)
                        break
        
        return f"""You are a cybersecurity compliance expert analyzing a {report_type} report for NIST SP 800-53 Rev 5 compliance.

Your task is to perform a deep analysis of the report to identify ALL findings that demonstrate compliance or non-compliance with NIST controls. You must be thorough and identify every relevant finding, even if it seems minor.

Response Format:
You MUST respond with a JSON object or array containing findings. Each finding MUST include:
- control_id: The NIST control ID in UPPERCASE format (e.g., "AC-3", not "ac-3")
- status: "compliant", "non-compliant", "not_applicable", or "informational"
- evidence_summary: SPECIFIC technical findings from the report, not control descriptions
- risk_rating: Object with "level" and "impact" fields
- remediation: ALWAYS provide specific recommendations, even for compliant/informational findings

Control Mapping Rules:

1. Vulnerability Assessment Findings:
   - Scan failures due to technical issues:
     * SSL/TLS certificate issues -> RA-5 (Non-Compliant, High)
     * Authentication failures -> RA-5 (Non-Compliant, High)
     * Network connectivity issues -> RA-5 (Non-Compliant, Medium)
   - Scan results:
     * Missing patches -> SI-2 (Non-Compliant, High)
     * Configuration issues -> CM-6 (Non-Compliant, Medium)
     * Unauthorized services -> CM-7 (Non-Compliant, Medium)

2. Service Detection Findings:
   - Required services:
     * Web servers (80/443) -> CM-7 (Compliant, None)
     * Management interfaces -> CM-7 (Compliant, None)
     * Database services -> CM-7 (Compliant, None)
   - Unauthorized services:
     * Unnecessary services -> CM-7 (Non-Compliant, Medium)
     * Default services -> CM-7 (Non-Compliant, Low)
   - Service inventory:
     * Service detection -> CM-8 (Informational, None)
     * Port information -> CM-8 (Informational, None)

3. Security Configuration Findings:
   - SSL/TLS:
     * Invalid certificates -> SC-8 (Non-Compliant, High)
     * Weak protocols -> SC-8 (Non-Compliant, High)
     * Missing HSTS -> SC-23 (Non-Compliant, Medium)
   - Authentication:
     * Default credentials -> IA-5 (Non-Compliant, High)
     * Weak passwords -> IA-5 (Non-Compliant, High)
     * Missing MFA -> IA-2 (Non-Compliant, High)

4. Network Security Findings:
   - Firewall rules:
     * Excessive access -> SC-7 (Non-Compliant, High)
     * Missing rules -> SC-7 (Non-Compliant, High)
   - Network services:
     * Unnecessary ports -> SC-7 (Non-Compliant, Medium)
     * Required ports -> SC-7 (Compliant, None)

5. System Configuration Findings:
   - Patch management:
     * Missing patches -> SI-2 (Non-Compliant, High)
     * Outdated software -> SI-2 (Non-Compliant, High)
   - System hardening:
     * Default configurations -> CM-6 (Non-Compliant, Medium)
     * Unnecessary features -> CM-7 (Non-Compliant, Medium)

Status Guidelines:
- "compliant": Finding shows proper implementation of control requirements
- "non-compliant": Finding shows security weakness or missing control
- "informational": Finding provides context but doesn't indicate compliance/non-compliance
- "not_applicable": Control truly doesn't apply to the system

Risk Rating Guidelines:
- High: Critical vulnerabilities that could lead to system compromise
- Medium: Security issues that could lead to unauthorized access
- Low: Minor security issues with limited impact
- None: Informational findings with no direct security impact

Remediation Guidelines:
1. For Compliant Findings:
   - Provide maintenance recommendations
   - Suggest monitoring practices
   - Recommend periodic verification steps

2. For Informational Findings:
   - Suggest potential improvements
   - Recommend best practices
   - Provide configuration optimization tips

3. For Non-Compliant Findings:
   - Provide specific technical steps
   - Include configuration changes
   - Suggest security controls

Example Mappings for Common Findings:
1. Finding: "SSL certificate validation failed during scan"
   Control: RA-5 (Non-Compliant, High)
   Evidence: Include scan error details and affected ports
   Remediation: "1. Fix SSL certificate issues on affected ports. 2. Configure proper certificate chain. 3. Enable certificate validation in scanner settings."

2. Finding: "Web server detected on port 80"
   Control: CM-8 (Informational, None)
   Evidence: Include service details and port information
   Remediation: "1. Document web server in system inventory. 2. Consider enabling HTTP/2 for better performance. 3. Implement regular service verification."

3. Finding: "HSTS implemented with max-age"
   Control: SC-23 (Compliant, None)
   Evidence: Include HSTS configuration details
   Remediation: "1. Maintain current HSTS configuration. 2. Monitor for any changes in HSTS headers. 3. Consider adding includeSubDomains directive."

4. Finding: "Captive Portal on management ports"
   Control: CM-7 (Informational, None)
   Evidence: Include portal details and ports
   Remediation: "1. Document captive portal in system inventory. 2. Consider implementing rate limiting. 3. Monitor for unauthorized access attempts."

5. Finding: "HTTP/1.1 with disabled Keep-Alive"
   Control: CM-8 (Informational, None)
   Evidence: Include protocol details
   Remediation: "1. Consider enabling HTTP Keep-Alive for better performance. 2. Document current protocol configuration. 3. Plan for HTTP/2 implementation."

Relevant Controls from Rule-Based Analysis:
{json.dumps([{
    'id': c['id'].upper(),
    'title': c['title'],
    'requirements': c.get('requirements', [])
} for c in relevant_controls], indent=2)}"""

    def _prepare_user_message(self, chunk: str, chunk_num: int, total_chunks: int) -> str:
        """Prepare the user message for GPT analysis."""
        return f"""
        Report Section:
        {chunk}
        
        Instructions:
        You must analyze the report section and extract ONLY specific technical findings that relate to each NIST control.
        DO NOT include any control descriptions, templates, or placeholders in the evidence section.
        """

    def _parse_gpt_response(self, response: str) -> List[Dict[str, Any]]:
        """Parse and validate GPT response."""
        try:
            findings = json.loads(response)
            if not isinstance(findings, list):
                logger.warning("GPT response is not a list")
                return []
            
            validated_findings = []
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                    
                # Check required fields
                required_fields = [
                    "control_id", "status", "description", "evidence_summary",
                    "risk_rating", "remediation", "confidence"
                ]
                if not all(k in finding for k in required_fields):
                    continue
                    
                # Validate control ID format
                control_id = finding["control_id"]
                if not re.match(r'^[A-Z]{2}-\d+$', control_id):
                    continue
                
                # Get control details from catalog
                control_details = None
                for control in self.nist_catalog:
                    if control["id"] == control_id:
                        control_details = control
                        break
                
                if not control_details:
                    continue
                
                # Set proper description from catalog
                finding["description"] = f"Control {control_id} ({control_details.get('title', '')}): {control_details.get('description', '')}"
                
                # Validate evidence summary doesn't contain control description
                evidence = finding.get("evidence_summary", "").strip()
                if evidence.startswith(f"Control {control_id}"):
                    evidence = "Evidence & Findings Summary:\nNo specific findings from the security assessment."
                finding["evidence_summary"] = evidence
                
                # Validate status
                status = finding.get("status", "not_assessed").lower()
                if status not in ["compliant", "non-compliant", "not_applicable", "informational"]:
                    continue
                
                # Special handling for CM-7 and AC-4
                if control_id == "CM-7":
                    # If service is required and detected, mark as compliant
                    if "service detected" in evidence.lower() and "required" in evidence.lower():
                        finding["status"] = "compliant"
                elif control_id == "AC-4":
                    # If only basic service detection, mark as informational
                    if "fqdn" in evidence.lower() or "dns" in evidence.lower():
                        finding["status"] = "informational"
                
                # Validate confidence
                try:
                    confidence = float(finding["confidence"])
                    if not 0.0 <= confidence <= 1.0:
                        continue
                except (ValueError, TypeError):
                    continue
                
                validated_findings.append(finding)
            
            return validated_findings
            
        except Exception as e:
            logger.error(f"Error parsing GPT response: {str(e)}")
            return []

    def _validate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Validate and clean up findings before returning them.
        """
        logger.info("Validating findings")
        validated_findings = []
        
        # Phrases that indicate generic or policy statements
        generic_phrases = [
            "should implement",
            "must implement",
            "needs to",
            "requires",
            "should have",
            "must have",
            "policy states",
            "control requires",
            "according to",
            "based on the",
            "organization should",
            "organization must",
            "no specific",
            "n/a",
            "none",
            "not applicable"
        ]
        
        # Template parameter patterns
        template_patterns = [
            r"{{.*?}}",  # Matches {{ anything }}
            r"{{\s*insert:\s*param,.*?}}",  # Matches {{ insert: param, ... }}
            r"\[\[.*?\]\]",  # Matches [[ anything ]]
            r"<.*?>",  # Matches <anything>
            r"\$\{.*?\}",  # Matches ${anything}
            r"%\(.*?\)s"  # Matches %(anything)s
        ]
        
        for finding in findings:
            try:
                # Skip if any required field is missing
                if not all(k in finding for k in ['control_id', 'status', 'evidence_summary']):
                    continue
                
                # Skip if evidence is generic or contains template parameters
                evidence = finding.get('evidence_summary', '').lower()
                if any(phrase in evidence for phrase in generic_phrases):
                    continue
                if any(re.search(pattern, evidence) for pattern in template_patterns):
                    continue
                
                # Skip if status is invalid
                status = finding.get('status', '').lower()
                if status not in ['compliant', 'non-compliant', 'not_applicable', 'informational']:
                    continue
                
                # Skip if control ID is invalid
                control_id = finding.get('control_id', '')
                if not re.match(r'^[A-Z]{2}-\d+(\.\d+)?$', control_id):
                    continue
                
                # Ensure risk rating is properly formatted
                risk_rating = finding.get('risk_rating', {})
                if not isinstance(risk_rating, dict):
                    risk_rating = {'level': 'Unknown', 'impact': 'Impact cannot be determined'}
                if 'level' not in risk_rating:
                    risk_rating['level'] = 'Unknown'
                if 'impact' not in risk_rating:
                    risk_rating['impact'] = 'Impact cannot be determined'
                
                # Normalize risk level
                risk_level = risk_rating['level'].lower()
                if risk_level in ['critical', 'high']:
                    risk_rating['level'] = 'High'
                elif risk_level in ['medium', 'moderate']:
                    risk_rating['level'] = 'Medium'
                elif risk_level in ['low', 'minimal']:
                    risk_rating['level'] = 'Low'
                elif risk_level in ['none', 'informational']:
                    risk_rating['level'] = 'None'
                else:
                    risk_rating['level'] = 'Unknown'
                
                # Add validated finding
                validated_findings.append({
                    'control_id': control_id,
                    'status': status,
                    'evidence_summary': finding['evidence_summary'],
                    'risk_rating': risk_rating,
                    'remediation': finding.get('remediation', 'No specific remediation steps provided.'),
                    'confidence': finding.get('confidence', 0.8)
                })
                
            except Exception as e:
                logger.error(f"Error validating finding: {str(e)}")
                continue
        
        return validated_findings 