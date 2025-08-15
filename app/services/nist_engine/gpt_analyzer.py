from typing import List, Dict, Any
import json
from pathlib import Path
import openai
from app.core.config import settings

class GPTAnalyzer:
    def __init__(self):
        # Load NIST catalog
        catalog_path = Path(__file__).parent / "nist_catalog.json"
        with open(catalog_path, "r", encoding="utf-8") as f:
            self.nist_catalog = json.load(f)
        
        # Initialize OpenAI client
        openai.api_key = settings.OPENAI_API_KEY

    def analyze_report(self, report_text: str, report_type: str) -> List[Dict[str, Any]]:
        """
        Analyze a report using GPT to identify NIST control compliance.
        
        Args:
            report_text: The text content of the report
            report_type: Type of report (e.g., "vulnerability", "penetration_test")
            
        Returns:
            List of findings with control matches
        """
        findings = []
        
        # Create a prompt for GPT
        prompt = f"""
        Analyze the following {report_type} report and identify which NIST 800-53 controls are addressed or violated.
        For each control, provide:
        1. Control ID
        2. Compliance status (compliant, partial, non-compliant)
        3. Description of how the control is addressed/violated
        4. Confidence level (0-100)
        
        Report content:
        {report_text}
        
        Please respond in JSON format with the following structure:
        [
            {{
                "control_id": "string",
                "status": "string",
                "description": "string",
                "confidence": number
            }}
        ]
        """
        
        try:
            # Call GPT API
            response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity compliance expert analyzing reports against NIST 800-53 controls."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=2000
            )
            
            # Parse the response
            result = response.choices[0].message.content
            findings = json.loads(result)
            
            # Validate findings against NIST catalog
            validated_findings = []
            for finding in findings:
                control_id = finding["control_id"]
                if any(control["id"] == control_id for control in self.nist_catalog):
                    validated_findings.append(finding)
            
            return validated_findings
            
        except Exception as e:
            print(f"Error in GPT analysis: {e}")
            return []

    def generate_recommendation(self, finding: Dict[str, Any]) -> str:
        """
        Generate a recommendation for improving compliance based on a finding.
        
        Args:
            finding: A finding from the analysis
            
        Returns:
            Recommendation text
        """
        prompt = f"""
        Based on the following NIST control finding, provide a specific recommendation for improving compliance:
        
        Control ID: {finding['control_id']}
        Status: {finding['status']}
        Description: {finding['description']}
        
        Please provide a detailed recommendation that includes:
        1. Specific actions to take
        2. Best practices to implement
        3. Potential tools or resources to use
        """
        
        try:
            response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity compliance expert providing recommendations."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=500
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            print(f"Error generating recommendation: {e}")
            return "Unable to generate recommendation at this time." 