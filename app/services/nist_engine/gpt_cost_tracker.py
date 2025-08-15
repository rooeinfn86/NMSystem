import json
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict

class GPTCostTracker:
    def __init__(self, cost_file: str = "gpt_costs.json"):
        self.cost_file = Path(cost_file)
        self.costs = self._load_costs()
        self.model_costs = {
            "gpt-4-turbo-preview": {
                "input": 0.01,  # $0.01 per 1K tokens
                "output": 0.03  # $0.03 per 1K tokens
            }
        }

    def _load_costs(self) -> Dict[str, Any]:
        """Load cost data from file."""
        if self.cost_file.exists():
            try:
                with open(self.cost_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading costs: {str(e)}")
        return {
            "daily_costs": defaultdict(float),
            "total_cost": 0.0,
            "last_reset": datetime.now().isoformat()
        }

    def _save_costs(self) -> None:
        """Save cost data to file."""
        try:
            with open(self.cost_file, "w", encoding="utf-8") as f:
                json.dump(self.costs, f, indent=2)
        except Exception as e:
            print(f"Error saving costs: {str(e)}")

    def track_usage(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int,
        user_id: Optional[str] = None
    ) -> None:
        """
        Track GPT API usage and calculate costs.
        
        Args:
            model: The GPT model used
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens
            user_id: Optional user ID for per-user tracking
        """
        if model not in self.model_costs:
            print(f"Unknown model: {model}")
            return
            
        # Calculate costs
        input_cost = (input_tokens / 1000) * self.model_costs[model]["input"]
        output_cost = (output_tokens / 1000) * self.model_costs[model]["output"]
        total_cost = input_cost + output_cost
        
        # Update costs
        today = datetime.now().strftime("%Y-%m-%d")
        self.costs["daily_costs"][today] += total_cost
        self.costs["total_cost"] += total_cost
        
        # Update per-user costs if user_id provided
        if user_id:
            if "user_costs" not in self.costs:
                self.costs["user_costs"] = defaultdict(float)
            self.costs["user_costs"][user_id] += total_cost
        
        # Save updated costs
        self._save_costs()

    def get_daily_costs(self, days: int = 7) -> Dict[str, float]:
        """
        Get daily costs for the last N days.
        
        Args:
            days: Number of days to retrieve
            
        Returns:
            Dictionary of daily costs
        """
        today = datetime.now()
        daily_costs = {}
        
        for i in range(days):
            date = (today - timedelta(days=i)).strftime("%Y-%m-%d")
            daily_costs[date] = self.costs["daily_costs"].get(date, 0.0)
            
        return daily_costs

    def get_total_cost(self) -> float:
        """Get total cost since tracking began."""
        return self.costs["total_cost"]

    def get_user_costs(self, user_id: str) -> float:
        """
        Get total cost for a specific user.
        
        Args:
            user_id: The user ID
            
        Returns:
            Total cost for the user
        """
        return self.costs.get("user_costs", {}).get(user_id, 0.0)

    def reset_costs(self) -> None:
        """Reset all cost tracking."""
        self.costs = {
            "daily_costs": defaultdict(float),
            "total_cost": 0.0,
            "last_reset": datetime.now().isoformat()
        }
        self._save_costs() 