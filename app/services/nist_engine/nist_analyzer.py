import json
import os
import logging
from pathlib import Path
from typing import List, Dict, Any, Union, Optional
from app.services.nist_engine.nist_rules_engine import NISTRulesEngine
from app.services.nist_engine.nist_gpt_analyzer import NISTGPTAnalyzer
import re
import ijson

# Set up logging
logger = logging.getLogger(__name__)

class NISTAnalyzer:
    def __init__(self):
        # Initialize analyzers
        self.rules_engine = NISTRulesEngine()
        self.gpt_analyzer = NISTGPTAnalyzer()
        logger.info("Initialized NISTAnalyzer with rules engine and GPT analyzer")
        
        # Load NIST catalog
        catalog_path = Path(__file__).parent / "NIST_SP-800-53_rev5_catalog.json"
        logger.info(f"Loading NIST catalog from: {catalog_path}")
        self.nist_catalog = []
        try:
            with open(catalog_path, "rb") as f:
                parser = ijson.parse(f)
                current_control = {}
                in_control = False
                
                for prefix, event, value in parser:
                    if prefix.endswith('.controls.item'):
                        if event == 'start_map':
                            current_control = {}
                            in_control = True
                        elif event == 'end_map' and in_control:
                            if current_control:
                                self.nist_catalog.append(current_control)
                            in_control = False
                    elif in_control:
                        if prefix.endswith('.id'):
                            current_control['id'] = value.upper() if value else ''
                        elif prefix.endswith('.title'):
                            current_control['title'] = value
                        elif prefix.endswith('.parts.item.name') and value == 'statement':
                            for p, e, v in parser:
                                if p.endswith('.prose'):
                                    current_control['description'] = v
                                    break
                        elif prefix.endswith('.parts.item.name') and value == 'guidance':
                            if 'requirements' not in current_control:
                                current_control['requirements'] = []
                            for p, e, v in parser:
                                if p.endswith('.prose'):
                                    current_control['requirements'].append(v)
                                    break
            
            logger.info(f"Loaded {len(self.nist_catalog)} controls from NIST catalog")
            if self.nist_catalog:
                sample_controls = self.nist_catalog[:5]
                control_ids = [c.get('id', 'unknown') for c in sample_controls]
                logger.info(f"Sample control IDs: {control_ids}")
        except Exception as e:
            logger.error(f"Error loading NIST catalog: {str(e)}")
            self.nist_catalog = []
        
        # Initialize control keywords
        self.control_keywords = self._load_control_keywords()
        logger.info(f"Initialized keywords for {len(self.control_keywords)} controls")

    def _load_control_keywords(self) -> Dict[str, List[str]]:
        """Load keywords for each control from the catalog."""
        keywords = {}
        try:
            # First, check if the catalog is a list of controls
            if isinstance(self.nist_catalog, list):
                for control in self.nist_catalog:
                    if isinstance(control, dict):
                        control_id = control.get('id')
                        if control_id:
                            # Extract keywords from description and requirements
                            words = set()
                            description = control.get('description', '')
                            if description:
                                words.update(description.lower().split())
                            
                            # Handle requirements which might be in different formats
                            requirements = control.get('requirements', [])
                            if isinstance(requirements, list):
                                for req in requirements:
                                    if isinstance(req, str):
                                        words.update(req.lower().split())
                            elif isinstance(requirements, str):
                                words.update(requirements.lower().split())
                            
                            # Filter out common words and short terms
                            keywords[control_id] = [w for w in words if len(w) > 3]
            
            # If no keywords were loaded, create a default set
            if not keywords:
                logger.warning("No keywords could be loaded from the catalog. Using default keywords.")
                keywords = {
                    "AC-1": ["access", "control", "policy", "procedures"],
                    "AC-2": ["account", "management"],
                    "AC-3": ["access", "enforcement"],
                    "AC-4": ["information", "flow", "enforcement"],
                    "AC-5": ["separation", "duties"]
                }
            
            logger.info(f"Loaded keywords for {len(keywords)} controls")
            return keywords
            
        except Exception as e:
            logger.error(f"Error loading control keywords: {str(e)}")
            # Return default keywords in case of error
            return {
                "AC-1": ["access", "control", "policy", "procedures"],
                "AC-2": ["account", "management"],
                "AC-3": ["access", "enforcement"],
                "AC-4": ["information", "flow", "enforcement"],
                "AC-5": ["separation", "duties"]
            }

    def analyze_report(
        self,
        report_text: str,
        report_type: str,
        user_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Analyze a report using both rule-based and GPT analysis.
        """
        try:
            logger.info("Starting NIST analysis process")
            
            # Run rule-based analysis first to get technical findings
            logger.info("Running rule-based analysis")
            rule_findings = self.rules_engine.analyze_report(report_text, report_type)
            logger.info(f"Rule-based analysis found {len(rule_findings)} findings")
            
            # Log each rule-based finding
            for finding in rule_findings:
                logger.info(f"Rule-based match - Control: {finding.get('control_id', 'N/A')}, "
                           f"Status: {finding.get('status', 'unknown')}, "
                           f"Confidence: {finding.get('confidence', 0):.2f}")
            
            # Run GPT analysis with context from rule-based findings
            logger.info("Running GPT analysis")
            gpt_findings = self.gpt_analyzer.analyze_report(report_text, report_type, rule_findings, user_id)
            
            # Log GPT findings
            if gpt_findings:
                logger.info(f"GPT analysis found {len(gpt_findings)} findings")
                for finding in gpt_findings:
                    logger.info(f"GPT match - Control: {finding.get('control_id', 'N/A')}, "
                              f"Status: {finding.get('status', 'unknown')}, "
                              f"Confidence: {finding.get('confidence', 0):.2f}")
            else:
                logger.info("GPT analysis returned no findings")
                gpt_findings = []
            
            # Combine findings from both analyzers
            logger.info("Combining findings from both analyzers")
            combined_findings = []
            
            # Process rule-based findings first since they contain technical details
            for finding in rule_findings:
                # Ensure finding has all required fields
                processed_finding = {
                    'control_id': finding.get('control_id', 'N/A'),
                    'status': finding.get('status', 'unknown'),
                    'confidence': finding.get('confidence', 0.0),
                    'source': 'rule_based',
                    'type': 'technical_finding',  # Set type for all rule-based findings
                    'description': finding.get('description', ''),
                    'technical_details': finding.get('technical_details', finding.get('description', '')),
                    'evidence_summary': finding.get('evidence_summary', ''),
                    'risk_rating': finding.get('risk_rating', {
                        'level': 'Unknown',
                        'impact': 'Impact cannot be determined'
                    }),
                    'recommendation': finding.get('recommendation', ''),
                    'risk_factor': finding.get('risk_factor', 'Unknown'),
                    'solution': finding.get('solution', ''),
                    'impact': finding.get('impact', ''),
                    'affected_systems': finding.get('affected_systems', ''),
                    'plugin_output': finding.get('plugin_output', ''),
                    'cve': finding.get('cve', '')
                }
                
                # Only add if we have actual evidence
                if (processed_finding['evidence_summary'] and 
                    not processed_finding['evidence_summary'].startswith("No specific")):
                    combined_findings.append(processed_finding)
                    logger.info(f"Added rule-based finding for control {processed_finding['control_id']}")

            # Process GPT findings
            for finding in gpt_findings:
                processed_finding = {
                    'control_id': finding.get('control_id', 'N/A'),
                    'status': finding.get('status', 'unknown'),
                    'confidence': finding.get('confidence', 0.8),  # GPT findings typically have 0.8 confidence
                    'source': 'gpt',
                    'type': 'ai_finding',
                    'description': finding.get('description', ''),
                    'evidence_summary': finding.get('evidence_summary', ''),
                    'risk_rating': finding.get('risk_rating', {
                        'level': 'Unknown',
                        'impact': 'Impact cannot be determined'
                    }),
                    'recommendation': finding.get('remediation', finding.get('recommendation', '')),
                    'risk_factor': finding.get('risk_factor', 'Unknown'),
                    'solution': finding.get('remediation', ''),
                    'impact': finding.get('risk_rating', {}).get('impact', ''),
                    'affected_systems': finding.get('affected_systems', '')
                }
                
                # Only add if we have actual evidence and it's not a duplicate
                if (processed_finding['evidence_summary'] and 
                    not any(f['control_id'] == processed_finding['control_id'] for f in combined_findings)):
                    combined_findings.append(processed_finding)
                    logger.info(f"Added GPT finding for control {processed_finding['control_id']}")
            
            logger.info(f"Final combined findings count: {len(combined_findings)}")
            return combined_findings
        except Exception as e:
            logger.error(f"Error in analyze_report: {str(e)}")
            return []

    def _generate_recommendation(self, control: Dict[str, Any], status: str) -> str:
        """Generate a recommendation based on the control and compliance status."""
        if status == "compliant":
            return "Continue maintaining current controls and monitoring for changes."
        elif status == "partial":
            return f"Review and enhance implementation of control {control.get('id', 'unknown')}."
        else:
            return f"Implement and document compliance with control {control.get('id', 'unknown')}."

    def analyze_report_with_rules(self, report_text: str, report_type: str) -> Dict[str, Any]:
        """
        Analyze a compliance report against NIST controls.
        
        Args:
            report_text: The text content of the report
            report_type: Type of report (e.g., "vulnerability", "penetration_test")
            
        Returns:
            Dictionary containing analysis results
        """
        # First, use rules engine for basic control matching
        rule_based_findings = self.rules_engine.analyze_report(report_text, report_type)
        
        # Then, use GPT for deeper analysis and recommendations
        gpt_findings = self.gpt_analyzer.analyze_report(
            report_text,
            report_type,
            rule_based_findings
        )
        
        # Combine and deduplicate findings
        combined_findings = self._combine_findings(rule_based_findings, gpt_findings)
        
        # Calculate compliance metrics
        metrics = self._calculate_metrics(combined_findings)
        
        return {
            "findings": combined_findings,
            "metrics": metrics
        }

    def _combine_findings(
        self,
        rule_findings: List[Dict[str, Any]],
        gpt_findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Combine findings from rule-based and GPT analysis.
        """
        findings_map = {}
        
        # Process rule-based findings first
        for finding in rule_findings:
            control_id = finding.get('control_id', '').split('_')[0].split('.')[0].upper()
            if control_id:
                # Get control details from catalog
                control_details = None
                for control in self.nist_catalog:
                    if control.get('id', '').split('_')[0].split('.')[0].upper() == control_id:
                        control_details = control
                        break
                
                if control_details:
                    # Update finding with control details but preserve evidence
                    evidence = finding.get('evidence_summary', '')
                    technical_details = finding.get('technical_details', '')
                    plugin_output = finding.get('plugin_output', '')
                    
                    # Combine all available evidence
                    evidence_parts = []
                    if evidence and not evidence.startswith("Details for control"):
                        evidence_parts.append(evidence)
                    if technical_details:
                        evidence_parts.append(f"Technical Details:\n{technical_details}")
                    if plugin_output:
                        evidence_parts.append(f"Plugin Output:\n{plugin_output}")
                    
                    combined_evidence = "\n\n".join(evidence_parts)
                    
                    finding.update({
                        'control_id': control_id,
                        'description': control_details.get('description', ''),
                        'title': control_details.get('title', ''),
                        'evidence_summary': combined_evidence if combined_evidence else evidence
                    })
                
                # Use a unique key for each finding
                key = f"{control_id}_{len(findings_map)}"
                findings_map[key] = finding
                logger.info(f"Added rule-based finding for control {control_id}")
        
        # Process GPT findings
        for finding in gpt_findings:
            control_id = finding.get('control_id', '').split('_')[0].split('.')[0].upper()
            if not control_id:
                continue
                
            # Get control details from catalog
            control_details = None
            for control in self.nist_catalog:
                if control.get('id', '').split('_')[0].split('.')[0].upper() == control_id:
                    control_details = control
                    break
            
            if control_details:
                # Update finding with control details but preserve evidence
                evidence = finding.get('evidence_summary', '')
                technical_details = finding.get('technical_details', '')
                remediation = finding.get('remediation', '')
                risk_rating = finding.get('risk_rating', {})
                
                # Combine all available evidence
                evidence_parts = []
                if evidence and not evidence.startswith("Details for control"):
                    evidence_parts.append(evidence)
                if technical_details:
                    evidence_parts.append(f"Technical Details:\n{technical_details}")
                
                combined_evidence = "\n\n".join(evidence_parts)
                
                finding.update({
                    'control_id': control_id,
                    'description': control_details.get('description', ''),
                    'title': control_details.get('title', ''),
                    'evidence_summary': combined_evidence if combined_evidence else evidence,
                    'remediation': remediation,
                    'risk_rating': risk_rating
                })
                
                # Use a unique key for each finding
                key = f"{control_id}_{len(findings_map)}"
                findings_map[key] = finding
                logger.info(f"Added GPT finding for control {control_id}")
        
        return list(findings_map.values())

    def _calculate_metrics(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Calculate compliance metrics from findings.
        """
        total_controls = len(self.nist_catalog)
        
        # Initialize counters
        compliant = 0
        non_compliant = 0
        not_applicable = 0
        partial = 0
        
        # Count findings by status
        for finding in findings:
            status = finding.get("status", "").lower()
            control_id = finding.get("control_id", "unknown")
            logger.info(f"Processing finding - Control: {control_id}, Status: {status}")
            
            if status == "compliant":
                compliant += 1
                logger.info(f"Control {control_id} marked as compliant")
            elif status in ["non-compliant", "non_compliant"]:
                non_compliant += 1
                logger.info(f"Control {control_id} marked as non-compliant")
            elif status == "not_applicable":
                not_applicable += 1
                logger.info(f"Control {control_id} marked as not applicable")
            elif status == "partial":
                partial += 1
                logger.info(f"Control {control_id} marked as partial")
            else:
                logger.warning(f"Unknown status '{status}' for control {control_id}")
        
        # Calculate not assessed
        not_assessed = total_controls - (compliant + non_compliant + not_applicable + partial)
        
        # Log detailed metrics
        logger.info("Calculating compliance metrics:")
        logger.info(f"Total controls in catalog: {total_controls}")
        logger.info(f"Compliant controls: {compliant}")
        logger.info(f"Non-compliant controls: {non_compliant}")
        logger.info(f"Not applicable controls: {not_applicable}")
        logger.info(f"Partially compliant controls: {partial}")
        logger.info(f"Not assessed controls: {not_assessed}")
        
        # Return metrics
        metrics = {
            "total_controls": total_controls,
            "compliant": compliant,
            "non_compliant": non_compliant,
            "not_applicable": not_applicable,
            "partial": partial,
            "not_assessed": not_assessed
        }
        
        logger.info(f"Final metrics: {metrics}")
        return metrics 

    def _validate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate and normalize findings."""
        logger.info("Validating findings")
        validated_findings = []
        valid_statuses = {'compliant', 'non-compliant', 'not_applicable', 'partial'}
        
        try:
            for finding in findings:
                # Skip findings missing required fields
                if not all(k in finding for k in ['control_id', 'status', 'description']):
                    logger.warning(f"Missing required fields in finding: {finding.get('control_id', 'unknown')}")
                    continue
                
                # Normalize status
                status = finding['status'].lower().replace('_', '-')
                if status not in valid_statuses:
                    if status == 'not_assessed':
                        status = 'not_applicable'
                    else:
                        logger.warning(f"Invalid status '{status}' for control {finding['control_id']}")
                        continue
                finding['status'] = status
                
                # Add missing fields with default values
                if 'evidence_summary' not in finding:
                    finding['evidence_summary'] = "No specific findings from the security assessment."
                
                if 'risk_rating' not in finding:
                    finding['risk_rating'] = {
                        'level': 'Unknown',
                        'impact': 'Impact cannot be determined without specific findings'
                    }
                
                if 'recommendation' not in finding:
                    finding['recommendation'] = "A thorough security assessment is recommended."
                
                if 'confidence' not in finding:
                    finding['confidence'] = 1.0 if status in ['compliant', 'non-compliant'] else 0.0
                
                validated_findings.append(finding)
        except Exception as e:
            logger.error(f"Error validating findings: {str(e)}")
        
        logger.info(f"Validated {len(validated_findings)} findings")
        return validated_findings 