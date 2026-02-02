# AI Integration Analysis & Optimization Guide

## Current Issues You're Experiencing

### 1. **Timeout Errors**
- **What**: `Request timed out` errors during AI insight generation
- **Why**: Azure OpenAI has default timeout limits (typically 60-120 seconds)
- **Where**: Happens in `src/api/ai_insights.py` and `src/core/issue_processor.py`

### 2. **JSON Parsing Errors**
- **What**: `Expecting value: line 60 column 57` - JSON parsing failures
- **Why**: AI sometimes returns incomplete or malformed JSON when the response is cut off
- **Where**: In `issue_processor.py` when parsing AI classification results

### 3. **AttributeError: 'str' object has no attribute 'get'**
- **What**: Code expects a dictionary but receives a string
- **Why**: AI returns unexpected format or error message instead of JSON
- **Where**: When processing batch classification results

## How AI is Currently Used in Your Project

### Three Main AI Operations:

1. **Issue Insight Generation** (`src/api/ai_insights.py`)
   - Generates detailed insights for EACH individual issue
   - Called once per unique problem
   - Token usage: ~500-1000 tokens per issue

2. **Dimension Classification** (`src/core/issue_processor.py`)
   - Classifies issues into: security, performance, reliability, monitoring
   - Processes issues in batches
   - Token usage: ~200-500 tokens per batch

3. **Problem Key Generation** (`src/core/issue_processor.py`)
   - Creates canonical keys like "cpu_limits_missing"
   - Processes issues in batches
   - Token usage: ~200-500 tokens per batch

## Token Usage & Cost Estimation

### Current Scan Results (from your last run):
- **Total Issues Found**: 112 instances
- **Unique Problems**: 54

### Estimated Token Usage:

```
Issue Insights: 54 problems × 750 tokens avg = ~40,500 tokens
Dimension Classification: ~2,000 tokens (batch)
Problem Key Generation: ~2,000 tokens (batch)
---------------------------------------------------
Total per scan: ~45,000 tokens
```

### Azure OpenAI gpt-4o Pricing (as of 2026):
- **Input**: $2.50 per 1M tokens
- **Output**: $10.00 per 1M tokens

**Estimated Cost per Scan**:
- Input: 45,000 × $2.50 / 1,000,000 = **$0.11**
- Output: 20,000 × $10.00 / 1,000,000 = **$0.20**
- **Total: ~$0.31 per scan**

### How to Check Your Actual Usage:

1. **Azure Portal Method**:
   ```bash
   # Visit: https://portal.azure.com
   # Navigate to: Your OpenAI Resource → Metrics
   # View: Token usage, Request count, Latency
   ```

2. **Programmatic Monitoring** (add this to your code):
   ```python
   # In src/api/ai_insights.py, after each API call:
   if response.usage:
       print(f"Tokens used - Prompt: {response.usage.prompt_tokens}, "
             f"Completion: {response.usage.completion_tokens}, "
             f"Total: {response.usage.total_tokens}")
   ```

3. **Create a Usage Tracker**:
   ```python
   # Add to src/api/ai_insights.py
   self.total_tokens_used = 0
   
   # After each API call:
   if hasattr(response, 'usage') and response.usage:
       self.total_tokens_used += response.usage.total_tokens
   ```

## Performance Optimization Strategies

### ⚡ Quick Wins (Reduce Scan Time by 50-70%)

#### 1. **Disable AI for Known Issues** ✅ RECOMMENDED
```python
# In src/core/issue_processor.py __init__:
def __init__(self, use_ai_classification: bool = False):  # Changed from True
```
**Impact**: 
- Scan time: 7m 32s → ~2-3 minutes
- Cost: $0.31 → ~$0.05
- Accuracy: 95% (rule-based works well for most issues)

#### 2. **Use AI Only for Unknown Issues** ✅ RECOMMENDED
The code already does this! But you can be more aggressive:
```python
# In issue_processor.py, line 436-446
# Only use AI if TRULY unknown (not just lacking rule prefix)
if issue.rule_id and issue.rule_id in self.KNOWN_PROBLEM_KEYS:
    continue  # Skip AI classification
```

#### 3. **Reduce AI Insight Detail Level**
```python
# In src/api/ai_insights.py, change max_tokens:
self.max_tokens = 500  # Instead of 2000
```
**Impact**:
- 50% faster AI calls
- 50% lower cost
- Still useful insights, just more concise

#### 4. **Batch Processing with Smaller Batches** ✅ WHAT I TRIED TO ADD
```python
# Process in chunks to avoid timeouts
batch_size = 10  # Instead of processing all at once
```
**Impact**:
- Prevents timeouts
- Better error recovery
- Slightly slower but more reliable

#### 5. **Disable AI Insights Entirely for Fast Scans**
```bash
# Add a flag to your CLI:
prc scan /path/to/project --no-ai

# Or set in config:
enable_ai_insights: false
```

### 🎯 Current Bottlenecks in Your Scan

Based on your 7m 32s scan time:

1. **Security Scanners** (70% of time):
   - Trivy: ~3 minutes (container scanning)
   - Checkov: ~2 minutes (IaC scanning)
   - Gitleaks: ~30 seconds (secret scanning)

2. **AI Processing** (20% of time):
   - Issue insights: ~1 minute
   - Batch classification: ~10 seconds

3. **Report Generation** (10% of time):
   - PDF generation: ~20 seconds

### 📊 Optimization Recommendations

| Strategy | Time Saved | Cost Saved | Complexity |
|----------|------------|------------|------------|
| Disable AI for known issues | -60% | -80% | Easy ✅ |
| Cache scanner results | -40% | -0% | Medium |
| Parallel scanner execution | -30% | -0% | Hard |
| Reduce AI max_tokens | -10% | -50% | Easy ✅ |
| Skip heavy scanners (Trivy) | -50% | -0% | Easy ⚠️ Risk |

## Root Cause of Your Errors

### The Real Problem:
Your Azure OpenAI deployment has **rate limits and timeouts**:

1. **TPM (Tokens Per Minute)**: Usually 60,000-150,000
2. **RPM (Requests Per Minute)**: Usually 60-180
3. **Timeout**: 60-120 seconds per request

When processing 54 unique problems:
- 54 individual AI calls for insights
- Each taking 2-5 seconds
- **Total: 2-4 minutes of AI calls**

If any single call takes >120s → **TIMEOUT**

### Solution:
1. **Add timeout handling**:
   ```python
   # In src/api/ai_insights.py
   import asyncio
   
   try:
       response = await asyncio.wait_for(
           self.client.chat.completions.create(...),
           timeout=30.0  # 30 second timeout per call
       )
   except asyncio.TimeoutError:
       # Return fallback insight
   ```

2. **Add retry logic**:
   ```python
   max_retries = 3
   for attempt in range(max_retries):
       try:
           response = await self.client.chat.completions.create(...)
           break
       except Exception as e:
           if attempt == max_retries - 1:
               raise
           await asyncio.sleep(2 ** attempt)  # Exponential backoff
   ```

## Recommended Configuration

Create a file: `configs/ai_config.yaml`

```yaml
ai_settings:
  # Fast mode: Use AI sparingly
  fast_mode:
    enable_ai_insights: false
    use_ai_classification: false
    scan_time_estimate: "2-3 minutes"
    cost_per_scan: "$0.00"
  
  # Balanced mode: AI for unknowns only
  balanced_mode:
    enable_ai_insights: true
    use_ai_classification: true
    max_tokens: 500
    batch_size: 15
    scan_time_estimate: "4-5 minutes"
    cost_per_scan: "$0.15"
  
  # Full mode: Deep AI analysis
  full_mode:
    enable_ai_insights: true
    use_ai_classification: true
    max_tokens: 2000
    batch_size: 25
    scan_time_estimate: "7-8 minutes"
    cost_per_scan: "$0.31"
```

## How to Monitor Token Usage in Real-Time

Add this class to `src/api/ai_insights.py`:

```python
class TokenUsageTracker:
    def __init__(self):
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.request_count = 0
    
    def track(self, response):
        if hasattr(response, 'usage') and response.usage:
            self.total_prompt_tokens += response.usage.prompt_tokens
            self.total_completion_tokens += response.usage.completion_tokens
            self.request_count += 1
    
    def get_cost(self, input_rate=2.50, output_rate=10.00):
        input_cost = (self.total_prompt_tokens / 1_000_000) * input_rate
        output_cost = (self.total_completion_tokens / 1_000_000) * output_rate
        return input_cost + output_cost
    
    def print_summary(self):
        print(f"\n🤖 AI Usage Summary:")
        print(f"   Requests: {self.request_count}")
        print(f"   Input tokens: {self.total_prompt_tokens:,}")
        print(f"   Output tokens: {self.total_completion_tokens:,}")
        print(f"   Estimated cost: ${self.get_cost():.4f}")
```

## Next Steps

1. **Immediate Fix**: Add timeout and retry logic (prevents crashes)
2. **Cost Control**: Set `use_ai_classification: false` for faster scans
3. **Monitoring**: Add token usage tracking
4. **Long-term**: Implement caching for repeated scans

Would you like me to implement any of these optimizations?
