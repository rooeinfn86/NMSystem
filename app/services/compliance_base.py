from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BaseComplianceAnalyzer:
    def __init__(self, db: Session):
        self.db = db
        self.rules_engine = None  # To be set by child classes
        self.gpt_analyzer = None  # To be set by child classes
        self.last_gpt_call = 0
        self.gpt_call_interval = 2  # seconds between GPT calls

    def process_report(self, report_id: int) -> Dict[str, Any]:
        """Process a compliance report using hybrid approach."""
        try:
            # Get the report from the database
            report = self._get_report(report_id)
            if not report:
                return {
                    "status": "error",
                    "message": f"Report with ID {report_id} not found"
                }
            
            # Extract content from the report file
            content = self._extract_content(report)
            logger.info(f"Extracted content from report: {len(content)} characters")
            
            # Analyze with hybrid approach
            findings = self._analyze_with_hybrid_approach(report, content)
            
            # Update report status
            self._update_report_status(report_id, "Completed")
            
            return {
                "status": "success",
                "message": "Report processed successfully",
                "findings_count": len(findings)
            }
        except Exception as e:
            logger.error(f"Error processing report: {str(e)}")
            return {
                "status": "error",
                "message": str(e)
            }

    def _analyze_with_hybrid_approach(self, report, content: str) -> List[Any]:
        """Analyze report content using both rule-based and GPT approaches."""
        findings = []
        benchmarks = self._get_benchmarks()
        
        for benchmark in benchmarks:
            # Get GPT analysis first
            gpt_analysis = self.gpt_analyzer.analyze_with_gpt(report, content, benchmark)
            
            # Only do basic text matching if GPT analysis is not confident
            if gpt_analysis.get('confidence_score', 0.0) < 0.7:
                matches = self.rules_engine._find_matches(benchmark, content)
            else:
                matches = {'title_match': False, 'description_match': False, 
                         'recommendation_match': False, 'context_matches': []}
            
            # Create finding with combined analysis
            finding = self._create_finding(report, benchmark, matches, gpt_analysis)
            findings.append(finding)
        
        return findings

    def _get_report(self, report_id: int) -> Any:
        """Get report from database. To be implemented by child classes."""
        raise NotImplementedError

    def _extract_content(self, report) -> str:
        """Extract content from report file. To be implemented by child classes."""
        raise NotImplementedError

    def _get_benchmarks(self) -> List[Any]:
        """Get benchmarks from database. To be implemented by child classes."""
        raise NotImplementedError

    def _create_finding(self, report, benchmark, matches: Dict[str, Any], 
                       gpt_analysis: Dict[str, Any]) -> Any:
        """Create a compliance finding. To be implemented by child classes."""
        raise NotImplementedError

    def _update_report_status(self, report_id: int, status: str):
        """Update report status in database. To be implemented by child classes."""
        raise NotImplementedError

class BaseRulesEngine:
    def __init__(self, db: Session):
        self.db = db

    def analyze_report(self, report, content: str) -> List[Any]:
        """Analyze a report against benchmarks and generate findings."""
        findings = []
        benchmarks = self._get_benchmarks()

        for benchmark in benchmarks:
            # Get GPT analysis first
            gpt_analysis = self.gpt_analyzer.analyze_with_gpt(report, content, benchmark)
            
            # Only do basic text matching if GPT analysis is not confident
            if gpt_analysis.get('confidence_score', 0.0) < 0.7:
                matches = self._find_matches(benchmark, content)
            else:
                matches = {'title_match': False, 'description_match': False, 
                         'recommendation_match': False, 'context_matches': []}
            
            # Create finding
            finding = self._create_finding(report, benchmark, matches, gpt_analysis)
            findings.append(finding)

        return findings

    def _find_matches(self, benchmark, content: str) -> Dict[str, Any]:
        """Find matches between benchmark and report content."""
        # Extract key terms from benchmark
        key_terms = self._extract_key_terms(benchmark)
        
        # Find matches for each term
        context_matches = []
        for term in key_terms:
            if term.lower() in content.lower():
                context_matches.append(term)
        
        # Check for partial matches in title, description, and recommendation
        title_match = any(term in benchmark.title.lower() for term in key_terms)
        description_match = any(term in benchmark.description.lower() for term in key_terms)
        recommendation_match = any(term in benchmark.recommendation.lower() for term in key_terms)
        
        return {
            'title_match': title_match,
            'description_match': description_match,
            'recommendation_match': recommendation_match,
            'context_matches': context_matches
        }

    def _extract_key_terms(self, benchmark) -> List[str]:
        """Extract key terms from benchmark for matching."""
        # Combine title, description, and recommendation
        text = f"{benchmark.title} {benchmark.description} {benchmark.recommendation}"
        
        # Extract words (excluding common words)
        words = re.findall(r'\b\w+\b', text.lower())
        common_words = {'the', 'and', 'or', 'but', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
                       'should', 'must', 'ensure', 'configure', 'set', 'enable', 'disable', 'use'}
        
        # Return unique words that aren't common
        return list(set(words) - common_words)

    def _create_finding(self, report, benchmark, matches: Dict[str, Any], 
                       gpt_analysis: Dict[str, Any]) -> Any:
        """Create a compliance finding. To be implemented by child classes."""
        raise NotImplementedError

    def _get_benchmarks(self) -> List[Any]:
        """Get benchmarks from database. To be implemented by child classes."""
        raise NotImplementedError 