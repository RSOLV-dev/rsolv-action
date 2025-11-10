# Pattern Detection Separation: Code Injection, Prototype Pollution, and Insecure Deserialization

## Overview

This document describes the changes made to properly separate three distinct vulnerability types that were previously being misclassified:

- **Code Injection** (CWE-94)
- **Prototype Pollution** (CWE-1321)
- **Insecure Deserialization** (CWE-502)

## Problem Statement

Based on RailsGoat workflow #19210870938 analysis, the SCAN phase was misclassifying vulnerabilities:

1. JavaScript `eval()` and `Function()` constructor → labeled "insecure_deserialization" (should be "code_injection")
2. JavaScript prototype pollution (CWE-1321) → labeled "insecure_deserialization" (should be "prototype_pollution")
3. Ruby `Marshal.load()` → correctly labeled but sometimes excluded

## Changes Made to rsolv-action

### 1. Added CODE_INJECTION to VulnerabilityType Enum

**File**: `src/security/types.ts`

```typescript
export enum VulnerabilityType {
  // ... existing types ...
  COMMAND_INJECTION = 'command_injection',
  CODE_INJECTION = 'code_injection',  // NEW
  PATH_TRAVERSAL = 'path_traversal',
  // ... rest of types ...
}
```

### 2. Updated Minimal Patterns

**File**: `src/security/minimal-patterns.ts`

Changed all eval-related patterns from `COMMAND_INJECTION` to `CODE_INJECTION`:

- JavaScript: `eval()`, `Function()`, `setTimeout()` with strings
- Python: `eval()`, `exec()`
- Ruby: `eval()`, `instance_eval()`
- PHP: `eval()`, `assert()`
- Elixir: `Code.eval_string()`, `Code.eval_quoted()`

All these patterns now use:
- **Type**: `VulnerabilityType.CODE_INJECTION`
- **CWE**: `CWE-94` (Improper Control of Generation of Code)
- **Severity**: `critical`

### 3. Added Prototype Pollution Pattern

**File**: `src/security/minimal-patterns.ts`

New pattern added:

```typescript
{
  id: 'prototype-pollution',
  name: 'Prototype Pollution',
  type: VulnerabilityType.PROTOTYPE_POLLUTION,
  severity: 'high',
  cweId: 'CWE-1321',
  owaspCategory: 'A08:2021',
  patterns: {
    regex: [
      /__proto__\s*[=:]/gi,
      /constructor\s*\.\s*prototype\s*[=:]/gi,
      /\[\s*['"](__proto__|constructor|prototype)['"]\s*\]\s*=/gi,
      /Object\.assign\s*\([^,)]*,\s*[^)]*\b(req|request|params|query|body)\b/gi,
      /(_\.merge|_\.extend|_\.defaults|_\.assign)\s*\([^,)]*,\s*[^)]*\b(req|request|params|query|body)\b/gi
    ]
  },
  // ...
}
```

### 4. Preserved Insecure Deserialization

The following patterns remain as `INSECURE_DESERIALIZATION` (CWE-502):

- Python: `pickle.loads()`, `cPickle.loads()`
- Ruby: `YAML.load()`, `Psych.load()`, `Marshal.load()`
- PHP: `unserialize()`
- Java: `ObjectInputStream.readObject()`

### 5. Updated Tests

**File**: `src/security/__tests__/detector-v2-patterns.test.ts`

Updated test expectations from `command_injection` to `code_injection`:

```typescript
// Should find at least 2 vulnerabilities (SQL injection and code injection)
expect(types.has('code_injection')).toBe(true);
```

## Required Changes to RSOLV-platform API

The platform's pattern database needs corresponding updates to ensure consistent classification:

### 1. Create New Vulnerability Type

Add `code_injection` to the vulnerability types table/enum:

```sql
-- Example (adjust to match actual schema)
INSERT INTO vulnerability_types (id, name, cwe_id, owasp_category, severity)
VALUES ('code_injection', 'Code Injection', 'CWE-94', 'A03:2021', 'critical');
```

### 2. Update Existing Patterns

Reclassify eval-related patterns from `insecure_deserialization` or `command_injection` to `code_injection`:

**Patterns to update**:
- JavaScript/TypeScript: `eval()`, `Function()`, `setTimeout()` with string
- Python: `eval()`, `exec()`
- Ruby: `eval()`, `instance_eval()`
- PHP: `eval()`, `assert()`
- Elixir: `Code.eval_string()`, `Code.eval_quoted()`
- Java: `ScriptEngine.eval()`

**New classification**:
- **type**: `code_injection`
- **cwe_id**: `CWE-94`
- **severity**: `critical`

### 3. Add Prototype Pollution Patterns

Create new patterns for CWE-1321:

```json
{
  "id": "js-prototype-pollution",
  "name": "Prototype Pollution",
  "type": "prototype_pollution",
  "cwe_id": "CWE-1321",
  "severity": "high",
  "languages": ["javascript", "typescript"],
  "patterns": [
    "__proto__\\s*[=:]",
    "constructor\\s*\\.\\s*prototype\\s*[=:]",
    "\\[\\s*['\"](__proto__|constructor|prototype)['\"]\\s*\\]\\s*=",
    "Object\\.assign\\s*\\([^,)]*,\\s*[^)]*\\b(req|request|params|query|body)\\b",
    "(_\\.merge|_\\.extend|_\\.defaults|_\\.assign)\\s*\\([^,)]*,\\s*[^)]*\\b(req|request|params|query|body)\\b"
  ]
}
```

### 4. Reserve Insecure Deserialization for True Deserialization

Ensure `insecure_deserialization` (CWE-502) is only used for actual unsafe deserialization:

- Python: `pickle`, `cPickle`, `marshal`, `shelve`
- Ruby: `YAML.load`, `Marshal.load`
- PHP: `unserialize`
- Java: `ObjectInputStream.readObject`, `XStream.fromXML`
- .NET: `BinaryFormatter.Deserialize`

## Validation

### Testing with RailsGoat

After platform changes, re-run the RailsGoat workflow to verify:

1. **jquery.snippet.js eval()** → Creates issue with type `code_injection` (not `insecure_deserialization`)
2. **jsapi.js prototype pollution** → Creates separate issue with type `prototype_pollution`
3. **Ruby Marshal.load()** → Creates issue with type `insecure_deserialization`

### Expected Result

Three separate GitHub issues should be created, one for each vulnerability type.

## CWE Mapping Reference

| Vulnerability Type | CWE | Description |
|-------------------|-----|-------------|
| code_injection | CWE-94 | Improper Control of Generation of Code ('Code Injection') |
| prototype_pollution | CWE-1321 | Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution') |
| insecure_deserialization | CWE-502 | Deserialization of Untrusted Data |

## Rationale

These are fundamentally different vulnerability classes with different:

- **Attack vectors**: Code injection executes arbitrary code directly; prototype pollution modifies object behavior; deserialization exploits object reconstruction
- **Mitigation strategies**: Different fixes required for each type
- **Severity implications**: Different CVSS scores and risk levels
- **Developer understanding**: Separating them improves educational value

## References

- RFC-067-RAILSGOAT-ANALYSIS.md (original analysis)
- RailsGoat workflow #19210870938
- CWE-94: https://cwe.mitre.org/data/definitions/94.html
- CWE-1321: https://cwe.mitre.org/data/definitions/1321.html
- CWE-502: https://cwe.mitre.org/data/definitions/502.html
