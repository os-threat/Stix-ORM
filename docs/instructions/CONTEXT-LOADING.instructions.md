---
description: 'Context-aware instruction loading strategy'
applyTo: '**/*'
priority: 2
---

# CONTEXT-AWARE LOADING STRATEGY

## 🧠 SMART CONTEXT SELECTION

### Trigger-Based Loading
When AI detects specific keywords/contexts, auto-load relevant instruction files:

#### TypeQL/Database Context
**Triggers**: "typeql", "database", "variable", "collision", "insertion"
**Load**: 
- MASTER-INDEX.instructions.md (always)
- typeql-integration.instructions.md (core patterns)
- dependency-sorting.instructions.md (ordering)

#### STIX Processing Context  
**Triggers**: "clean", "process", "stix", "enrichment", "external"
**Load**:
- MASTER-INDEX.instructions.md (always)
- enhancement-summary.instructions.md (pipeline)
- cleaning-pipeline.instructions.md (operations)

#### Reference Detection Context
**Triggers**: "reference", "field", "detection", "custom", "extension"
**Load**:
- MASTER-INDEX.instructions.md (always)
- python-patterns.instructions.md (dynamic detection)

#### Testing Context
**Triggers**: "test", "validate", "coverage", "collision test"
**Load**:
- MASTER-INDEX.instructions.md (always)
- testing-patterns.instructions.md (requirements)

## 📋 LAYERED INFORMATION ARCHITECTURE

### Layer 1: Essential Patterns (Always Loaded)
```markdown
# CRITICAL PATTERNS ONLY - Ultra-compact format

## TypeQL Variables
- Relation-aware: `f"{prop.replace('_','-')}-{type}{i}"`
- Example: on_completion → on-completion-sequence0

## Error Handling  
- Pattern: preserve input + detailed report
- Never: silent failures or input mutation

## Reference Detection
- Dynamic: standard patterns + STIX ID regex
- Never: hardcoded field lists
```

### Layer 2: Implementation Details (Context-Triggered)
```markdown
# DETAILED IMPLEMENTATIONS - Full examples and edge cases

[Complete patterns with multiple examples, error scenarios, performance notes]
```

### Layer 3: Supporting Context (Reference Only)
```markdown
# BACKGROUND & RATIONALE - Historical context and design decisions

[Why patterns were chosen, alternative approaches considered, evolution]
```

## 🔍 COMPRESSED KNOWLEDGE FORMAT

### Ultra-Efficient Pattern Encoding
```markdown
# PATTERN LIBRARY - Maximum density format

P1: TypeQL-VarGen | rel-aware-prefix | `f"{prop.replace('_','-')}-{type}{i}"` | ❌generic-naming
P2: Error-Handle | preserve-input | `try/except→input,report` | ❌silent-fail  
P3: Ref-Detect | dual-method | `standard+regex` | ❌hardcode-fields
P4: Conditional | explicit-bool | `enrich=False,sco=False` | ❌implicit-behavior
P5: Dependency | topo-sort | `deps-first` | ❌constraint-violations
```

### Lookup Table Format
```markdown
# QUICK LOOKUP - Instant reference

| Context | Pattern | File | Line |
|---------|---------|------|------|
| TypeQL-collision | P1 | typeql-integration | 45-67 |
| Missing-deps | P2+P4 | enhancement-summary | 123-145 |
| Custom-fields | P3 | python-patterns | 78-102 |
```