"""Token Usage Tracker for AI Operations."""

import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class TokenUsage:
    """Track token usage for cost estimation."""
    
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    request_count: int = 0
    
    # Azure OpenAI gpt-4o pricing (per 1M tokens)
    INPUT_COST_PER_MILLION = 2.50  # $2.50 per 1M input tokens
    OUTPUT_COST_PER_MILLION = 10.00  # $10.00 per 1M output tokens
    
    def add_usage(self, prompt: int, completion: int):
        """Add usage from a single API call."""
        self.prompt_tokens += prompt
        self.completion_tokens += completion
        self.total_tokens += (prompt + completion)
        self.request_count += 1
    
    def get_input_cost(self) -> float:
        """Calculate input token cost."""
        return (self.prompt_tokens / 1_000_000) * self.INPUT_COST_PER_MILLION
    
    def get_output_cost(self) -> float:
        """Calculate output token cost."""
        return (self.completion_tokens / 1_000_000) * self.OUTPUT_COST_PER_MILLION
    
    def get_total_cost(self) -> float:
        """Calculate total cost."""
        return self.get_input_cost() + self.get_output_cost()
    
    def print_summary(self):
        """Print usage summary."""
        print("\n" + "="*60)
        print("🤖 AI USAGE SUMMARY")
        print("="*60)
        print(f"Total Requests:      {self.request_count:>10,}")
        print(f"Input Tokens:        {self.prompt_tokens:>10,}")
        print(f"Output Tokens:       {self.completion_tokens:>10,}")
        print(f"Total Tokens:        {self.total_tokens:>10,}")
        print("-"*60)
        print(f"Input Cost:          ${self.get_input_cost():>9.4f}")
        print(f"Output Cost:         ${self.get_output_cost():>9.4f}")
        print(f"TOTAL COST:          ${self.get_total_cost():>9.4f}")
        print("="*60)
        print(f"Average tokens/req:  {self.total_tokens // max(1, self.request_count):>10,}")
        print(f"Cost per request:    ${self.get_total_cost() / max(1, self.request_count):>9.4f}")
        print("="*60 + "\n")
    
    def save_to_file(self, filepath: str = "ai_usage_log.json"):
        """Save usage to JSON file for tracking."""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "request_count": self.request_count,
            "total_cost": self.get_total_cost(),
        }
        
        # Append to existing log
        logs = []
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r') as f:
                    logs = json.load(f)
            except:
                logs = []
        
        logs.append(log_entry)
        
        with open(filepath, 'w') as f:
            json.dump(logs, f, indent=2)
        
        print(f"✅ Usage saved to {filepath}")


class GlobalTokenTracker:
    """Global singleton for tracking all token usage."""
    
    _instance: Optional[TokenUsage] = None
    
    @classmethod
    def get_tracker(cls) -> TokenUsage:
        """Get or create the global tracker."""
        if cls._instance is None:
            cls._instance = TokenUsage()
        return cls._instance
    
    @classmethod
    def reset(cls):
        """Reset the tracker."""
        cls._instance = TokenUsage()
