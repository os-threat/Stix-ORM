---
description: 'PRIMARY: Read this first before all other instructions - Size-efficient AI instruction optimization'
applyTo: '**/*'
---

# PRIMARY INSTRUCTIONS - READ FIRST

## 🏢 **CRITICAL REPOSITORY INFORMATION - READ FIRST**

### **Copyright & Ownership**
- **Company**: OS Threat Pty Limited
- **License**: Apache 2.0 (Open for use and contribution)
- **Copyright**: OS Threat Pty Limited asserts copyright over all code in this repository
- **Co-Authors & Inventors** (Equal Contributors): 
  - denis@osthreat.com
  - brett@osthreat.com  
  - paolo@osthreat.com

### **Key Collaborative Contributions**
- **Paolo**: Critical architectural insight - created definitions directory structure, separated dialect data from ORM
- **Brett**: Original STIX-ORM implementation, STIX21 content, ORM and parsing foundations, initial TypeDB classes
- **Denis**: Complete TypeDB interaction pipeline (stixorm\module\typedb_lib), functional data pipeline architecture

### **Usage Rights**
- **Apache 2.0 License**: People are welcome to use and contribute to this codebase
- **Copyright Notice**: All contributions and usage must respect OS Threat Pty Limited copyright
- **Repository**: Stix-ORM (os-threat/Stix-ORM)

### **Contributors to Instructions & Architecture Documentation**
Based on git history analysis, key contributors to the instructions and architecture documentation include:
- **Brett Forbes (BrettForbes)**: Primary author of instruction optimization framework and pan-dialect analysis
- **Additional Contributors**: Multiple team members have contributed to the broader codebase and foundational research that enabled this documentation

**Attribution Note**: All documentation builds upon collaborative work across the STIX-ORM development team. Contributors are identified from git commit history where available.

## 🚨 CRITICAL: SIZE-EFFICIENT INSTRUCTION OPTIMIZATION

### AI Context Constraints
- **Total Capacity**: ~30,000 words maximum
- **Current Usage**: ~12,000 words (40% capacity)
- **Optimization Target**: Maximum information density per token

### Token-Efficient Instruction Writing Rules

#### RULE 1: Hierarchical Bullet Structure (Saves 60% tokens)
```markdown
# ✅ EFFICIENT
## Pattern: TypeQL Variables
- **Rule**: Relation-aware prefixes prevent collisions
- **Code**: `f"{prop.replace('_','-')}-{type}{i}"`
- **Example**: on_completion → on-completion-sequence0
- **Never**: Generic naming like sequence0, sequence1

# ❌ INEFFICIENT (verbose prose)
The TypeQL variable generation system implements relation-aware prefixes...
```

#### RULE 2: Front-Load Critical Information
```markdown
# ✅ CRITICAL INFO FIRST
## Rule: Always Use Relation-Aware Variables
**Why**: Prevents TypeDB insertion failures
**How**: `f"{prop.replace('_','-')}-{type}{i}"`
**Details**: → typeql-integration.instructions.md#collision-prevention

# ❌ BACKGROUND FIRST
TypeQL is a query language for TypeDB databases. Variables must be unique...
```

#### RULE 3: Strategic Code Examples (Essential only)
```markdown
# ✅ CRITICAL PATTERN ONLY
```python
# ESSENTIAL: Collision prevention
relation_prefix = prop.replace('_', '-')
variable = f"{relation_prefix}-{prop_type}{i}"
```

# ❌ EXCESSIVE IMPLEMENTATION
```python
def process_stix_object(obj):
    # ... 50 lines of routine code
```

#### RULE 4: Cross-Reference Instead of Duplicate
- **Error Handling**: → python-patterns.instructions.md#error-handling
- **Variable Generation**: → typeql-integration.instructions.md#examples
- **NEVER**: Repeat same content across files

### File Organization Strategy
1. **MASTER-INDEX** (1,500 words) - Critical patterns, ultra-compact
2. **Domain Files** (2,000 words each) - Context-triggered details
3. **Reference Files** (500 words) - Background only

## 🔥 MANDATORY IMPLEMENTATION PATTERNS

### TypeQL Variable Collision Prevention
- **Pattern**: `relation_prefix = prop.replace('_', '-'); var = f"{relation_prefix}-{type}{i}"`
- **Critical**: Prevents database insertion failures
- **Example**: `on_completion` → `on-completion-sequence0`
- **Never**: `sequence0`, `sequence1` (causes collisions)

### Conditional Enrichment System  
- **Signature**: `clean_stix_list(objects, clean_sco_fields=False, enrich_from_external_sources=False)`
- **Default**: Air-gapped mode (False, False)
- **Purpose**: Operational control over external source integration

### Dynamic Reference Detection
- **Method 1**: Standard patterns (`_ref`, `_refs`)
- **Method 2**: STIX ID regex `^[a-zA-Z0-9\-]+--[0-9a-fA-F\-]+$`
- **Never**: Hardcoded field lists (breaks extensions)

### Error Handling Standard
- **Pattern**: `try: result = process(deepcopy(input)) except: return input, failure_report`
- **Critical**: Always preserve original input on failure
- **Never**: Silent failures or input mutation

## 📋 CONTEXT-AWARE LOADING TRIGGERS

### Auto-Load Priority by Keywords
```
"typeql" + "variable" + "collision" → MASTER-INDEX + typeql-integration
"stix" + "clean" + "enrichment" → MASTER-INDEX + enhancement-summary  
"reference" + "detection" + "custom" → MASTER-INDEX + python-patterns
"test" + "collision" + "validation" → MASTER-INDEX + testing-patterns
```

### File Loading Strategy
- **MASTER-INDEX.instructions.md**: Always load first (critical patterns)
- **Domain files**: Load based on context triggers
- **Reference files**: Load only when specifically needed

## ❌ CRITICAL ANTI-PATTERNS - NEVER DO

### Code Patterns to Avoid
```python
# ❌ Hard-coded reference fields
REFERENCE_FIELDS = ['created_by_ref', 'object_refs']  # Breaks extensions

# ❌ Generic TypeQL variables  
variable = f"{obj_type}{i}"  # Causes database collisions

# ❌ Input mutation
for obj in objects: obj['modified'] = True  # Mutates original

# ❌ Silent failures
except: return None  # User doesn't know what failed
```

### Implementation Anti-Patterns
- ❌ Duplicate content across instruction files
- ❌ Verbose prose instead of bullet points
- ❌ Background theory before critical patterns
- ❌ Excessive code examples for routine tasks
- ❌ Missing cross-references to detailed files

## 🎯 INSTRUCTION WRITING CHECKLIST

When creating/updating instruction files:
- [ ] Critical patterns in first 500 words
- [ ] Bullet points instead of paragraphs
- [ ] Code examples for essential patterns only
- [ ] Cross-references instead of duplication
- [ ] Anti-patterns prominently displayed
- [ ] Context triggers clearly defined
- [ ] File size under 2,000 words (except MASTER-INDEX)

## 📊 CURRENT INSTRUCTION INVENTORY

### Tier 1: Critical Core (Always Load)
- MASTER-INDEX.instructions.md (this system)
- enhancement-summary.instructions.md (major implementations)
- typeql-integration.instructions.md (collision prevention)

### Tier 2: Implementation (Context-Triggered)
- python-patterns.instructions.md (dynamic detection)
- cleaning-pipeline.instructions.md (7-operation pipeline)
- dependency-sorting.instructions.md (topological ordering)

### Tier 3: Process (Reference Only)
- python.instructions.md (code standards)
- task-implementation.instructions.md (workflow)

---

**This PRIMARY instruction file ensures size-efficient instruction optimization is always the first consideration in all development work.**