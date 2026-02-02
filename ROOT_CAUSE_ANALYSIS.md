# ROOT CAUSE ANALYSIS

## The Problem:

When using Azure OpenAI, the API call uses **TWO DIFFERENT model parameters**:

### 1. In the Azure Client (CORRECT):
```python
client = AsyncAzureOpenAI(
    azure_deployment="gpt-4o"  # ✅ This is correct
)
```

### 2. In the API Call (WRONG):
```python
response = await client.chat.completions.create(
    model="gpt-4o-mini",  # ❌ This should be the deployment name!
)
```

## Why This Causes Errors:

### Error 1: "'str' object has no attribute 'get'"
- The AI returns error messages as strings instead of JSON
- Because the model parameter is wrong, Azure rejects the request
- Error response is a string, but code expects dict

### Error 2: "Unterminated string" JSON errors  
- Similar - getting error responses instead of valid JSON
- JSON parser fails on error messages

### Error 3: "Request timed out"
- Azure is confused by wrong model parameter
- Takes forever to process or hangs
- Timeout triggers

## The Fix:

When using Azure, the `model` parameter in `chat.completions.create()` should be:
- **Azure Deployment Name** (from AZURE_OPENAI_DEPLOYMENT)
- NOT the model name like "gpt-4o-mini"

Currently:
```python
# ai_insights.py line 167
model=self.model,  # This is "gpt-4o-mini" (WRONG for Azure!)
```

Should be:
```python
# For Azure, use deployment name
model=self.azure_deployment if self.azure_deployment else self.model
```

This is the ROOT CAUSE of all three errors!
