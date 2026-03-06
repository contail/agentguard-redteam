# Contributing

## Submitting Attacks

1. Create a JSON file in `attacks/` following the schema
2. File name: `{your_handle}_{NNN}_{short_description}.json`
3. Run `python eval/validate.py` to check format
4. Open a PR

## Attack JSON Format

```json
{
  "id": "yourhandle_001",
  "name": "Short descriptive name",
  "author": "yourhandle",
  "date": "2026-03-06",
  "category": "command_injection",
  "target": "stage1",
  "attack": {
    "method": "POST",
    "path": "/api/query",
    "headers": {"Content-Type": "application/json"},
    "body": "{\"query\": \"your payload here\"}"
  },
  "why_dangerous": "Explain the real-world risk",
  "expected_action": "block"
}
```

## Tips for Finding Bypasses

- **Encoding chains**: Try double-encoding, mixed encoding (URL + Unicode + base64)
- **Unicode tricks**: Homoglyphs, fullwidth chars, zero-width joiners, RTL override
- **Semantic attacks**: Commands that look safe individually but are dangerous in combination
- **Context manipulation**: Payloads that change meaning based on surrounding text
- **Format confusion**: YAML/CSV/XML injection within JSON string fields
- **Social engineering**: Authority claims, urgency, false context

## False Positive Tests

We also welcome `expected_action: "pass"` test cases that verify AgentGuard doesn't block legitimate requests.
