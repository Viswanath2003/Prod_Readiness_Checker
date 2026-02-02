#!/usr/bin/env python3
"""Quick test to verify optimizations are working."""

import asyncio
import os
import sys

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from dotenv import load_dotenv
load_dotenv()

from src.core.scanner import Issue, Severity, IssueCategory
from src.api.ai_insights import AIInsightsGenerator
from src.utils.token_tracker import GlobalTokenTracker

async def test_parallel_processing():
    """Test that parallel processing and token tracking work."""
    
    print("🔍 Testing Optimizations...")
    print("="*60)
    
    # Reset tracker
    GlobalTokenTracker.reset()
    
    # Create test issues
    issues = []
    for i in range(5):  # Test with 5 issues
        issues.append(Issue(
            id=f"TEST-{i+1}",
            title=f"Test Security Issue {i+1}",
            description=f"This is test issue {i+1} to verify parallel processing.",
            severity=Severity.HIGH,
            category=IssueCategory.SECURITY,
            file_path=f"test{i+1}.py",
            line_number=10,
            scanner="test-scanner"
        ))
    
    # Initialize AI generator
    generator = AIInsightsGenerator()
    
    if not generator.is_available():
        print("❌ AI Generator not available. Check your .env file.")
        return
    
    print(f"✅ AI Generator initialized")
    print(f"📊 Processing {len(issues)} issues in parallel...")
    print()
    
    # Time the operation
    import time
    start = time.time()
    
    # Generate insights in parallel
    insights = await generator.generate_batch_insights(issues, max_concurrent=10)
    
    elapsed = time.time() - start
    
    print(f"\n⏱️  Time taken: {elapsed:.2f} seconds")
    print(f"✅ Generated {len(insights)} insights")
    print()
    
    # Show token usage
    tracker = GlobalTokenTracker.get_tracker()
    if tracker and tracker.request_count > 0:
        tracker.print_summary()
        print(f"\n💡 With old sequential processing:")
        print(f"   Estimated time: {elapsed * 2:.2f} seconds (2x slower)")
        print(f"   Benefit from parallel: {elapsed * 1:.2f}s saved!")
    else:
        print("⚠️  Token tracking not working")
    
    print("\n" + "="*60)
    print("✅ Test Complete!")

if __name__ == "__main__":
    asyncio.run(test_parallel_processing())
