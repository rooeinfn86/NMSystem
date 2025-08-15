import re
from typing import List, Dict, Any
from pathlib import Path
import json
import ijson  # For streaming JSON parsing
import logging

logger = logging.getLogger(__name__)

class NISTRulesEngine:
    def __init__(self):
        # Load NIST catalog
        catalog_path = Path(__file__).parent / "NIST_SP-800-53_rev5_catalog.json"
        self.nist_catalog = []
        try:
            with open(catalog_path, "r", encoding='utf-8') as f:
                # Load the entire catalog as JSON
                catalog_data = json.load(f)
                logger.info("Successfully loaded NIST catalog JSON")
                
                # Extract controls from the catalog
                if isinstance(catalog_data, dict):
                    catalog = catalog_data.get('catalog', {})
                    groups = catalog.get('groups', [])
                    
                    for group in groups:
                        controls = []
                        # Handle both direct controls and nested controls
                        if 'controls' in group:
                            controls.extend(group['controls'])
                        # Also check for controls in subgroups
                        for subgroup in group.get('groups', []):
                            if 'controls' in subgroup:
                                controls.extend(subgroup['controls'])
                        
                        for control in controls:
                            if isinstance(control, dict):
                                control_id = control.get('id', '').upper()
                                title = control.get('title', '')
                                description = ''
                                
                                # Get description from statement
                                parts = control.get('parts', [])
                                for part in parts:
                                    if part.get('name') == 'statement':
                                        # Try different ways to get the prose
                                        if isinstance(part, dict):
                                            # Direct prose
                                            if 'prose' in part:
                                                description = part['prose']
                                                break
                                            # Prose in parts
                                            for subpart in part.get('parts', []):
                                                if isinstance(subpart, dict) and 'prose' in subpart:
                                                    description = subpart['prose']
                                                    break
                                            # If we found description in subparts, break outer loop
                                            if description:
                                                break
                                
                                # Clean up any templated parameters in the description
                                description = self._clean_description(description)
                                
                                if control_id:
                                    logger.debug(f"Loading control {control_id} with description length: {len(description)}")
                                    self.nist_catalog.append({
                                        'id': control_id,
                                        'title': title,
                                        'description': description if description else f'The organization must implement {control_id} controls to ensure proper security measures.',
                                        'requirements': [],
                                        'family': control_id.split('-')[0] if '-' in control_id else '',
                                        'priority': control.get('priority', 'P1'),
                                        'baseline_impact': control.get('baseline-impact', 'MODERATE')
                                    })
                
                logger.info(f"Successfully loaded {len(self.nist_catalog)} controls from NIST catalog")
                # Log some sample controls to verify content
                for control in self.nist_catalog[:5]:
                    logger.debug(f"Loaded control {control['id']}: {control['description'][:100]}...")
            
        except Exception as e:
            logger.error(f"Error loading NIST catalog: {str(e)}")
            # Load minimal default catalog for critical controls
            self.nist_catalog = [
                {
                    'id': 'AC-2',
                    'title': 'Account Management',
                    'description': 'The organization manages system accounts by verifying, as part of the initial authenticator distribution, the identity of the individual receiving the authenticator.',
                    'requirements': ['Implement proper account management procedures']
                },
                {
                    'id': 'IA-5',
                    'title': 'Authenticator Management',
                    'description': 'The organization manages system authenticators by verifying, as part of the initial authenticator distribution, the identity of the individual receiving the authenticator.',
                    'requirements': ['Establish and implement authenticator management processes']
                },
                {
                    'id': 'AC-17',
                    'title': 'Remote Access',
                    'description': 'The organization establishes and documents usage restrictions, configuration/connection requirements, and implementation guidance for each type of remote access allowed.',
                    'requirements': ['Monitor and control communications at system boundaries']
                }
            ]
            logger.warning("Using minimal default catalog due to loading error")
        
        # Initialize control keywords
        self.control_keywords = self._load_control_keywords()
        self.min_confidence = 0.6

    def analyze_report(self, report_text: str, report_type: str = None) -> List[Dict[str, Any]]:
        """
        Analyze a report using rule-based matching.
        Args:
            report_text: The text content of the report to analyze
            report_type: The type of report (optional)
        Returns:
            List of findings mapped to NIST controls
        """
        findings = []
        
        # Extract security findings from the report
        security_findings = self._extract_security_findings(report_text)
        logger.info(f"Extracted {len(security_findings)} security findings from report")
        
        for finding in security_findings:
            # Skip if no description or it's a generic message
            if not finding.get('description') or finding['description'].startswith("Details for control"):
                continue
            
            # Map finding to controls
            control_ids = self._map_finding_to_controls(finding)
            
            # Skip if no controls mapped
            if not control_ids:
                logger.warning(f"No controls mapped for finding: {finding.get('description', '')[:100]}...")
                continue
            
            # Create a finding entry for each mapped control
            for control_id in control_ids:
                control_details = self._get_control_details(control_id)
                
                finding_entry = {
                    'control_id': control_id,
                    'title': control_details['title'],
                    'description': control_details['description'],
                    'status': 'non-compliant',  # Default to non-compliant for security findings
                    'evidence_summary': finding.get('description', ''),
                    'technical_details': self._format_technical_details(finding),
                    'risk_rating': {
                        'level': self._determine_risk_level(finding),
                        'impact': self._get_risk_impact(self._determine_risk_level(finding), finding.get('description', ''))
                    },
                    'recommendation': self._get_specific_recommendation(control_id, finding),
                    'family': control_details.get('family', control_id.split('-')[0] if '-' in control_id else 'UNKNOWN'),
                    'baseline_impact': control_details.get('baseline_impact', 'MODERATE'),
                    'confidence': 1.0
                }
                
                findings.append(finding_entry)
                logger.info(f"Added finding for control {control_id}")
        
        if not findings:
            logger.warning("No findings were mapped to NIST controls")
            
        return findings

    def _extract_security_findings(self, report_text: str) -> List[Dict[str, Any]]:
        """Extract security findings from a report text."""
        findings = []
        current_finding = {}
        in_finding = False
        
        # Define section headers that indicate the start of finding sections
        section_headers = [
            'Finding:', 'Technical Details:', 'Risk factor:', 'Solution:',
            'Plugin output:', 'CVE:', 'Affected Systems:', 'Impact:',
            'Vulnerability:', 'Issue:', 'Description:', 'Remediation:',
            'Risk Level:', 'Evidence:', 'Observation:'
        ]
        
        # Split report into lines and process each line
        lines = report_text.split('\n')
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            
            # Skip empty lines
            if not line:
                i += 1
                continue
            
            # Check if this line starts a new finding
            if any(line.startswith(header) for header in section_headers):
                # Save previous finding if it exists and has actual technical details
                if current_finding and 'description' in current_finding:
                    if not any(current_finding['description'].startswith(x) for x in ['Details for control', 'No findings', 'Control details']):
                        findings.append(current_finding)
                    current_finding = {}
                
                # Start new finding
                if line.startswith('Finding:') or line.startswith('Technical Details:') or line.startswith('Vulnerability:') or line.startswith('Issue:'):
                    # These headers indicate specific technical findings
                    header = next(h for h in section_headers if line.startswith(h))
                    desc_lines = [line.split(header)[1].strip()]
                    i += 1
                    while i < len(lines) and not any(lines[i].strip().startswith(h) for h in section_headers):
                        if lines[i].strip():
                            desc_lines.append(lines[i].strip())
                        i += 1
                    i -= 1
                    current_finding['description'] = ' '.join(desc_lines)
                    current_finding['type'] = 'technical_finding'
                elif line.startswith('Description:'):
                    desc_lines = [line.split('Description:')[1].strip()]
                    i += 1
                    while i < len(lines) and not any(lines[i].strip().startswith(h) for h in section_headers):
                        if lines[i].strip():
                            desc_lines.append(lines[i].strip())
                        i += 1
                    i -= 1
                    current_finding['description'] = ' '.join(desc_lines)
                elif line.startswith('Risk factor:') or line.startswith('Risk Level:'):
                    header = 'Risk factor:' if line.startswith('Risk factor:') else 'Risk Level:'
                    current_finding['risk_factor'] = line.split(header)[1].strip()
                elif line.startswith('Solution:') or line.startswith('Remediation:'):
                    header = 'Solution:' if line.startswith('Solution:') else 'Remediation:'
                    sol_lines = [line.split(header)[1].strip()]
                    i += 1
                    while i < len(lines) and not any(lines[i].strip().startswith(h) for h in section_headers):
                        if lines[i].strip():
                            sol_lines.append(lines[i].strip())
                        i += 1
                    i -= 1
                    current_finding['solution'] = ' '.join(sol_lines)
                elif line.startswith('Plugin output:'):
                    output_lines = [line.split('Plugin output:')[1].strip()]
                    i += 1
                    while i < len(lines) and not any(lines[i].strip().startswith(h) for h in section_headers):
                        if lines[i].strip():
                            output_lines.append(lines[i].strip())
                        i += 1
                    i -= 1
                    current_finding['plugin_output'] = ' '.join(output_lines)
                elif line.startswith('CVE:'):
                    current_finding['cve'] = line.split('CVE:')[1].strip()
                elif line.startswith('Affected Systems:'):
                    current_finding['affected_systems'] = line.split('Affected Systems:')[1].strip()
                elif line.startswith('Impact:'):
                    impact_lines = [line.split('Impact:')[1].strip()]
                    i += 1
                    while i < len(lines) and not any(lines[i].strip().startswith(h) for h in section_headers):
                        if lines[i].strip():
                            impact_lines.append(lines[i].strip())
                        i += 1
                    i -= 1
                    current_finding['impact'] = ' '.join(impact_lines)
                elif line.startswith('Evidence:'):
                    evidence_lines = [line.split('Evidence:')[1].strip()]
                    i += 1
                    while i < len(lines) and not any(lines[i].strip().startswith(h) for h in section_headers):
                        if lines[i].strip():
                            evidence_lines.append(lines[i].strip())
                        i += 1
                    i -= 1
                    current_finding['plugin_output'] = ' '.join(evidence_lines)
            
            # If we're in a finding but the line doesn't start with a known header,
            # it might be continuation of the last field
            elif in_finding:
                for field in ['description', 'solution', 'plugin_output', 'impact']:
                    if field in current_finding:
                        current_finding[field] = current_finding[field].rstrip() + ' ' + line
                        break
            
            i += 1
        
        # Don't forget to add the last finding if it has actual technical details
        if current_finding and 'description' in current_finding:
            if not any(current_finding['description'].startswith(x) for x in ['Details for control', 'No findings', 'Control details']):
                findings.append(current_finding)
        
        # Post-process findings to ensure they're specific and well-formatted
        processed_findings = []
        for finding in findings:
            # Skip findings that don't have enough information or are too generic
            if not finding.get('description'):
                continue
                
            description = finding.get('description', '').strip()
            
            # Skip generic or placeholder content
            if (description.startswith('Details for control') or
                'not found in NIST catalog' in description or
                description.startswith('No findings') or
                description.startswith('Control details')):
                continue
            
            # Clean up and format the finding
            processed_finding = {
                'description': description,
                'risk_factor': finding.get('risk_factor', 'Unknown'),
                'solution': finding.get('solution', '').strip(),
                'plugin_output': finding.get('plugin_output', '').strip(),
                'cve': finding.get('cve', ''),
                'affected_systems': finding.get('affected_systems', ''),
                'impact': finding.get('impact', '').strip(),
                'type': finding.get('type', 'security_finding')
            }
            
            # Only include findings with actual technical details
            if processed_finding['description']:
                processed_findings.append(processed_finding)
        
        return processed_findings

    def _map_finding_to_controls(self, finding: Dict[str, Any]) -> List[str]:
        """Map a finding to relevant NIST controls based on keywords and context."""
        evidence = finding.get('evidence', '').lower()
        title = finding.get('title', '').lower()
        description = finding.get('description', '').lower()

        # Direct mappings for common findings
        if any(kw in evidence or kw in title or kw in description for kw in ['password', 'credentials', 'authentication']):
            return ['IA-5', 'AC-2']
        
        if any(kw in evidence or kw in title or kw in description for kw in ['telnet', 'ftp', 'cleartext']):
            return ['AC-17', 'SC-8']
            
        if any(kw in evidence or kw in title or kw in description for kw in ['firewall', 'acl', 'access list', 'filter']):
            return ['AC-3', 'SC-7']
            
        if any(kw in evidence or kw in title or kw in description for kw in ['configuration', 'settings', 'hardening']):
            return ['CM-6', 'CM-7']
            
        if any(kw in evidence or kw in title or kw in description for kw in ['patch', 'update', 'version', 'vulnerability']):
            return ['SI-2', 'RA-5']
            
        if any(kw in evidence or kw in title or kw in description for kw in ['encryption', 'tls', 'ssl', 'crypto']):
            return ['SC-8', 'SC-13']
            
        if any(kw in evidence or kw in title or kw in description for kw in ['audit', 'log', 'monitoring']):
            return ['AU-2', 'AU-6']
            
        if any(kw in evidence or kw in title or kw in description for kw in ['backup', 'restore', 'recovery']):
            return ['CP-9', 'CP-10']

        # If no specific mapping found, try to determine based on context
        context_controls = []
        
        if 'access' in evidence or 'access' in title:
            context_controls.append('AC-3')
            
        if 'remote' in evidence or 'remote' in title:
            context_controls.append('AC-17')
            
        if 'network' in evidence or 'network' in title:
            context_controls.append('SC-7')
            
        if context_controls:
            return list(set(context_controls))

        # Default to AC-3 (Access Enforcement) if no other mapping found
        # This is better than returning N/A since most Cisco findings relate to access control
        logger.warning(f"No specific control mapping found for finding. Defaulting to AC-3. Evidence: {evidence[:100]}...")
        return ['AC-3']

    def _load_control_keywords(self) -> Dict[str, List[str]]:
        """Load keywords for each control from the catalog."""
        keywords = {}
        for control in self.nist_catalog:
            control_id = control.get('id')
            if not control_id:
                continue
                
            # Extract keywords from description and requirements
            words = set()
            
            # Add control ID as a keyword
            words.add(control_id.lower())
            
            # Add description words if available
            description = control.get('description', '')
            if description:
                desc_words = description.lower().split()
                words.update(desc_words)
            
            # Add requirement words if available
            requirements = control.get('requirements', [])
            for req in requirements:
                if isinstance(req, str):
                    req_words = req.lower().split()
                    words.update(req_words)
            
            # Add common variations and synonyms
            variations = set()
            for word in words:
                if len(word) > 3:  # Only process meaningful words
                    # Add base word
                    variations.add(word)
                    
                    # Add common variations
                    if word.endswith('s'):
                        variations.add(word[:-1])  # Remove 's' for singular
                    if word.endswith('ing'):
                        variations.add(word[:-3])  # Remove 'ing'
                    if word.endswith('ed'):
                        variations.add(word[:-2])  # Remove 'ed'
                    
                    # Add common synonyms
                    if 'access' in word:
                        variations.update(['permission', 'authorization', 'rights'])
                    if 'control' in word:
                        variations.update(['manage', 'regulate', 'govern'])
                    if 'security' in word:
                        variations.update(['protection', 'safeguard', 'defense'])
                    if 'policy' in word:
                        variations.update(['procedure', 'guideline', 'standard'])
                    if 'audit' in word:
                        variations.update(['review', 'inspect', 'examine'])
                    if 'monitor' in word:
                        variations.update(['track', 'observe', 'watch'])
            
            # Filter out very short words and common words
            common_words = {'the', 'and', 'for', 'with', 'that', 'this', 'from', 'have', 'which', 'when', 'where', 'what', 'how', 'why', 'who'}
            keywords[control_id] = [w for w in variations if len(w) > 2 and w not in common_words]
        
            # Ensure we have at least some keywords for each control
            if not keywords[control_id]:
                keywords[control_id] = [control_id.lower()]
                logger.warning(f"No meaningful keywords found for control {control_id}, using control ID as keyword")
        
        logger.info(f"Generated keywords for {len(keywords)} controls")
        return keywords

    def analyze_control(self, text: str, control_id: str) -> Dict[str, Any]:
        """
        Analyze text against a specific NIST control.
        Returns a dictionary with analysis results.
        """
        if not text or not control_id:
            return {
                "control_id": control_id,
                "status": "not_assessed",
                "confidence": 0.0,
                "matches": []
            }
        
        # Get keywords for this control
        control_keywords = self.control_keywords.get(control_id, [])
        if not control_keywords:
            return {
                "control_id": control_id,
                "status": "not_assessed",
                "confidence": 0.0,
                "matches": []
            }
        
        # Convert text to lowercase for case-insensitive matching
        text = text.lower()
        
        # Find keyword matches
        matches = []
        for keyword in control_keywords:
            if keyword in text:
                matches.append(keyword)
        
        # Calculate confidence based on matches
        confidence = len(matches) / len(control_keywords) if control_keywords else 0.0
        
        # Determine status based on confidence
        if confidence >= self.min_confidence:
            status = "compliant"
        elif confidence > 0:
            status = "non_compliant"
        else:
            status = "not_assessed"
        
        return {
            "control_id": control_id,
            "status": status,
            "confidence": confidence,
            "matches": matches
        }

    def _get_control_details(self, control_id: str) -> Dict[str, Any]:
        """Get control details from the NIST catalog."""
        if not control_id:
            logger.warning("Attempted to get details for empty control ID")
            return {
                'id': 'UNKNOWN',
                'title': 'Unknown Control',
                'description': 'Control details not available',
                'requirements': [],
                'family': 'UNKNOWN',
                'priority': 'P1',
                'baseline_impact': 'MODERATE'
            }

        # Handle N/A control ID
        if control_id == 'N/A':
            logger.info("Returning default details for N/A control ID")
            return {
                'id': 'N/A',
                'title': 'Not Applicable',
                'description': 'This finding has not been mapped to a specific NIST control. Further analysis may be needed to determine the appropriate control mapping.',
                'requirements': [],
                'family': 'UNMAPPED',
                'priority': 'P1',
                'baseline_impact': 'MODERATE'
            }

        # First check our predefined complete descriptions
        complete_descriptions = {
            'AC-2': 'Manage system accounts by: (1) identifying account types, (2) establishing conditions for group membership, (3) specifying authorized users, (4) requiring account approval, (5) establishing automated account management processes, (6) monitoring account usage, and (7) notifying administrators of account changes.',
            'IA-5': 'Manage system authenticators by: (1) verifying user identity before distributing authenticators, (2) establishing strong password requirements, (3) changing default authenticators upon installation, (4) changing/refreshing authenticators periodically, (5) protecting authenticator content from unauthorized disclosure, (6) requiring multi-factor authentication for privileged accounts, and (7) implementing automated tools for authenticator management.',
            'AC-17': 'Control remote access to the system by: (1) establishing usage restrictions and implementation guidance, (2) documenting allowed remote access methods, (3) implementing secure remote access protocols, (4) requiring multi-factor authentication, (5) monitoring remote access sessions, and (6) disabling unnecessary remote access capabilities.',
            'SC-8': 'Protect the confidentiality and integrity of transmitted information by: (1) implementing FIPS-validated cryptography, (2) using secure protocols for data transmission, (3) encrypting sensitive data in transit, (4) validating cryptographic implementations, and (5) monitoring for unauthorized data transmission.',
        }

        if control_id in complete_descriptions:
            logger.debug(f"Found predefined description for control {control_id}")
            return {
                'id': control_id,
                'title': control_id,
                'description': complete_descriptions[control_id],
                'requirements': [],
                'family': control_id.split('-')[0] if '-' in control_id else '',
                'priority': 'P1',
                'baseline_impact': 'MODERATE'
            }

        # Try to find in loaded catalog
        for control in self.nist_catalog:
            if control.get('id') == control_id:
                logger.debug(f"Found control {control_id} in NIST catalog")
                return control

        # If not found in catalog, create a minimal control detail
        logger.warning(f"Control {control_id} not found in NIST catalog or predefined descriptions")
        minimal_descriptions = {
            'AC-2': 'Implement account management processes including account creation, modification, enabling, disabling, and removal.',
            'IA-5': 'Implement authenticator management processes including password policies and authentication mechanisms.',
            'AC-17': 'Implement secure remote access controls and protocols.',
            'SC-8': 'Implement transmission confidentiality and integrity controls.',
            'CM-6': 'Configure systems according to security configuration settings.',
            'CM-7': 'Configure systems to provide only essential capabilities.',
        }

        if control_id in minimal_descriptions:
            logger.debug(f"Using minimal description for control {control_id}")
            return {
                'id': control_id,
                'title': control_id,
                'description': minimal_descriptions[control_id],
                'requirements': [],
                'family': control_id.split('-')[0] if '-' in control_id else '',
                'priority': 'P1',
                'baseline_impact': 'MODERATE'
            }

        # Return a generic control detail as last resort
        return {
            'id': control_id,
            'title': f'Control {control_id}',
            'description': f'Details for control {control_id} not found in NIST catalog. This control may need to be reviewed and properly mapped.',
            'requirements': [],
            'family': control_id.split('-')[0] if '-' in control_id else 'UNKNOWN',
            'priority': 'P1',
            'baseline_impact': 'MODERATE'
        }

    def _get_risk_impact(self, risk_level: str, evidence: str) -> str:
        """Generate a specific risk impact description based on the risk level and evidence."""
        if risk_level == 'Critical':
            return "Critical security vulnerabilities that require immediate attention - unauthorized access or system compromise possible"
        elif risk_level == 'High':
            return "High-risk security weaknesses that could lead to unauthorized access or data exposure"
        elif risk_level == 'Medium':
            return "Medium-risk security issues that could be exploited to gain unauthorized access"
        elif risk_level == 'Low':
            return "Low-risk security findings with limited potential impact"
        else:
            return "Impact severity cannot be determined from available evidence"

    def _clean_description(self, description: str) -> str:
        """Clean up templated descriptions to make them more readable."""
        if not description:
            return ''
        
        # Map of control IDs to their complete descriptions
        control_descriptions = {
            'AU-2': 'Configure the system to generate audit records for the following events: account creation/modification/deletion, privilege escalation, authentication attempts, system configuration changes, data access/modification, security policy changes, and administrative actions.',
            'AU-3': 'Configure audit records to include detailed information about security events including: (1) what type of event occurred, (2) when the event occurred (date and time), (3) where the event occurred (system location), (4) source of the event, (5) outcome of the event (success or failure), and (6) identity of any user/subject associated with the event.',
            'SI-2': 'Implement a comprehensive flaw remediation process that includes: (1) identifying and documenting system flaws, (2) reporting flaws to designated personnel, (3) correcting flaws with automated tools when possible, (4) testing flaw remediation changes, (5) installing security-relevant updates, and (6) incorporating flaw remediation into the configuration management process.',
            'SI-4': 'Monitor the system to detect: (1) attacks and indicators of potential attacks, (2) unauthorized local, network, and remote connections, (3) suspicious or malicious code execution, (4) unauthorized privilege escalation attempts, (5) unauthorized configuration changes, and (6) unauthorized data exfiltration.',
            'CM-7': 'Configure the system to provide only essential capabilities by: (1) identifying necessary system functions and services, (2) disabling or removing unnecessary functions and services, (3) prohibiting unauthorized functions and ports, (4) implementing allow-listing of authorized software, and (5) regularly reviewing and validating enabled system functions.',
            'SC-8': 'Protect the confidentiality and integrity of transmitted information by: (1) implementing FIPS-validated cryptography, (2) using secure protocols for data transmission, (3) encrypting sensitive data in transit, (4) validating cryptographic implementations, and (5) monitoring for unauthorized data transmission.',
            'AC-17': 'Control remote access to the system by: (1) establishing usage restrictions and implementation guidance, (2) documenting allowed remote access methods, (3) implementing secure remote access protocols, (4) requiring multi-factor authentication, (5) monitoring remote access sessions, and (6) disabling unnecessary remote access capabilities.',
            'IA-5': 'Manage system authenticators by: (1) verifying user identity before distributing authenticators, (2) establishing strong password requirements, (3) changing default authenticators upon installation, (4) changing/refreshing authenticators periodically, (5) protecting authenticator content from unauthorized disclosure, (6) requiring multi-factor authentication for privileged accounts, and (7) implementing automated tools for authenticator management.',
            'AC-3': 'Enforce approved authorizations for logical access by: (1) implementing role-based access control, (2) enforcing separation of duties, (3) implementing least privilege principles, (4) logging and monitoring access attempts, and (5) automatically revoking access when no longer needed.',
            'AC-4': 'Control information flow between systems by: (1) enforcing approved authorizations, (2) implementing data flow policies, (3) monitoring and controlling data transfers, (4) implementing content filtering, and (5) preventing unauthorized data exfiltration.',
            'SC-13': 'Implement cryptographic protection by: (1) using FIPS-validated cryptographic modules, (2) implementing approved algorithms and key lengths, (3) protecting cryptographic keys, (4) regularly validating cryptographic implementations, and (5) maintaining secure key management processes.',
            'SI-3': 'Implement malicious code protection by: (1) deploying anti-malware solutions at entry/exit points, (2) configuring real-time scanning, (3) performing periodic scans, (4) automatically updating malware definitions, (5) blocking or quarantining malicious code, and (6) alerting administrators of detection events.',
            'AC-2': 'Manage system accounts by: (1) identifying account types, (2) establishing conditions for group membership, (3) specifying authorized users, (4) requiring account approval, (5) establishing automated account management processes, (6) monitoring account usage, and (7) notifying administrators of account changes.',
            'AC-6': 'Implement least privilege principles by: (1) assigning minimal privileges required for tasks, (2) separating privileged functions from non-privileged functions, (3) restricting privileged accounts, (4) logging privileged role assignments, and (5) reviewing privilege levels periodically.',
            'AU-6': 'Review and analyze audit records by: (1) integrating audit review with incident response, (2) analyzing audit records for indicators of compromise, (3) correlating audit information from multiple sources, (4) reporting findings to appropriate personnel, and (5) adjusting audit review frequency based on risk.',
            'SC-7': 'Implement boundary protection by: (1) monitoring and controlling communications at system boundaries, (2) implementing subnetworks for public-facing components, (3) denying network traffic by default, (4) allowing only authorized incoming connections, and (5) implementing intrusion detection/prevention systems.',
            'RA-5': 'Perform vulnerability scanning by: (1) scanning for vulnerabilities in systems and applications, (2) analyzing scan reports and results, (3) remediating legitimate vulnerabilities, (4) sharing results with appropriate personnel, and (5) updating scan tools and databases regularly.'
        }
        
        # First try to find a complete description for the control
        for control_id, complete_desc in control_descriptions.items():
            if control_id.lower() in description.lower():
                return complete_desc
        
        # If no complete description found, clean up the templated one
        # Replace common parameter templates with meaningful text
        replacements = {
            '{{ insert: param, sc-13_odp.01 }}': 'required',
            '{{ insert: param, sc-13_odp.02 }}': 'approved',
            '{{ insert: param, ac-3_odp }}': 'security',
            '{{ insert: param, au-2_odp.01 }}': 'security-relevant',
            '{{ insert: param, au-2_odp.02 }}': 'defined',
            '{{ insert: param, au-3_odp }}': 'detailed',
            '{{ insert: param, au-6_odp.01 }}': 'regular',
            '{{ insert: param, au-6_odp.02 }}': 'security',
            '{{ insert: param, sc-7_odp }}': 'secure',
            '{{ insert: param, ac-4_odp }}': 'approved',
            '[organization-defined parameters]': 'required security',
            '[Assignment: organization-defined parameters]': 'required security',
            '[Assignment: organization-defined frequency]': 'regular',
            '[Assignment: organization-defined information]': 'sensitive information',
            '[Assignment: organization-defined audit record content]': 'security-relevant audit information',
            '[Assignment: organization-defined protocols]': 'approved secure protocols'
        }
        
        # Replace all parameter templates
        for template, replacement in replacements.items():
            description = description.replace(template, replacement)
        
        # Remove any remaining parameter templates
        description = re.sub(r'{{\s*insert:\s*param,\s*[^}]+\s*}}', 'required', description)
        description = re.sub(r'\[Assignment:[^]]+\]', 'required', description)
        description = re.sub(r'\[[^]]+\]', 'required', description)
        
        # Clean up multiple spaces and line breaks
        description = ' '.join(description.split())
        
        return description.strip()

    def _get_recommendations(self, control_id: str, findings: List[Dict[str, Any]]) -> str:
        """Generate specific recommendations based on the control and findings."""
        recommendations = set()
        for finding in findings:
            if finding.get('solution'):
                recommendations.add(finding['solution'])
        
        if recommendations:
            return '\n'.join(f"{i+1}. {rec}" for i, rec in enumerate(recommendations))
        
        # Default recommendations based on control ID if no specific solutions
        default_recommendations = {
            'AC-2': 'Implement proper account management procedures including strong passwords and regular access reviews.',
            'IA-5': 'Configure strong password policies and implement multi-factor authentication where possible.',
            'CM-6': 'Review and update system configurations to align with security best practices.',
            'AC-17': 'Implement secure remote access protocols and disable insecure services like Telnet.',
            'SC-8': 'Enable encryption for all network communications and disable cleartext protocols.',
            'SC-13': 'Implement FIPS-validated cryptographic modules and secure key management.',
        }
        
        return default_recommendations.get(control_id, "Review and implement security best practices for this control.")

    def _determine_risk_level(self, finding: Dict[str, Any]) -> str:
        """Determine risk level from finding."""
        risk_factor = finding.get('risk_factor', '').lower()
        if risk_factor == 'critical':
            return 'Critical'
        elif risk_factor == 'high':
            return 'High'
        elif risk_factor == 'medium':
            return 'Medium'
        elif risk_factor == 'low':
            return 'Low'
        return 'Unknown'

    def _format_technical_details(self, finding: Dict[str, Any]) -> str:
        """Format technical details from finding."""
        details = []
        if finding.get('plugin_output'):
            details.append(f"Technical Details: {finding['plugin_output']}")
        if finding.get('solution'):
            details.append(f"Solution: {finding['solution']}")
        if finding.get('risk_factor'):
            details.append(f"Risk Level: {finding['risk_factor']}")
        if finding.get('plugin_id'):
            details.append(f"Plugin ID: {finding['plugin_id']}")
        return '\n'.join(details) if details else ''

    def _get_specific_recommendation(self, control_id: str, finding: Dict[str, Any]) -> str:
        """Generate specific recommendation based on the finding."""
        # First try to use the finding's solution
        if finding.get('solution'):
            return finding['solution']
        
        # If no specific solution, use control-specific recommendations
        specific_recommendations = {
            'AC-2': {
                'default_password': 'Change all default passwords and implement strong password policies.',
                'telnet': 'Disable Telnet service and implement secure remote access using SSH.',
                'weak_password': 'Implement strong password policies and regular password changes.'
            },
            'IA-5': {
                'default_password': 'Change default credentials and implement automated password management.',
                'weak_password': 'Configure password complexity requirements and implement password aging.',
                'password_policy': 'Implement comprehensive password management policies.'
            },
            'SC-8': {
                'telnet': 'Replace Telnet with SSH for encrypted communications.',
                'cleartext': 'Implement encryption for all network communications.',
                'unencrypted': 'Enable encryption for all sensitive data transmissions.'
            },
            'AC-17': {
                'telnet': 'Disable Telnet and configure secure remote access protocols.',
                'remote_access': 'Implement secure remote access controls and monitoring.',
                'unauthorized_access': 'Review and restrict remote access capabilities.'
            }
        }
        
        # Look for keyword matches in the finding description
        description = finding.get('description', '').lower()
        if control_id in specific_recommendations:
            for keyword, recommendation in specific_recommendations[control_id].items():
                if keyword in description:
                    return recommendation
        
        # Default recommendations if no specific match found
        default_recommendations = {
            'AC-2': 'Review and update account management procedures.',
            'IA-5': 'Implement comprehensive authenticator management.',
            'CM-6': 'Update system configurations to align with security baselines.',
            'AC-17': 'Implement secure remote access protocols.',
            'SC-8': 'Enable encryption for all network communications.',
            'SC-13': 'Implement FIPS-validated cryptographic modules.'
        }
        
        return default_recommendations.get(control_id, "Implement security best practices for this control.") 