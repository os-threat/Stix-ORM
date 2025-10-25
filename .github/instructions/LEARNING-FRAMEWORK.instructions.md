---
description: 'STIX-ORM AI learning framework with size-efficient knowledge acquisition strategy'
applyTo: '**/*'
---

# STIX-ORM LEARNING FRAMEWORK

## 🚨 OPTIMIZATION NOTE
**Instruction Writing**: Follow size-efficient patterns → PRIMARY.instructions.md

## 🎯 LEARNING MISSION

**Primary Objective**: Master STIX-ORM library - cybersecurity intelligence transformation system bridging seven STIX dialects with TypeDB's hypergraph database technology.

**Core Innovation**: Universal transformation patterns preventing database insertion failures while maintaining semantic fidelity across cybersecurity frameworks.

## 🔥 CRITICAL PATTERNS TO MASTER

### TypeQL Variable Collision Prevention
- **Pattern**: `relation_prefix = prop.replace('_', '-'); var = f"{relation_prefix}-{type}{i}"`
- **Critical**: Database insertion failures without this pattern
- **Example**: `on_completion` → `on-completion-sequence0`
- **Never**: Generic naming like `sequence0`, `sequence1`

### Conditional Enrichment System
- **Signature**: `clean_stix_list(objects, clean_sco_fields=False, enrich_from_external_sources=False)`
- **Default**: Air-gapped mode (no external calls)
- **External Sources**: 5 MITRE/MBC endpoints when enabled

### Dynamic Reference Detection  
- **Method 1**: Standard patterns (`_ref`, `_refs`)
- **Method 2**: STIX ID regex `^[a-zA-Z0-9\-]+--[0-9a-fA-F\-]+$`
- **Never**: Hardcoded field lists (breaks extensions)

## 📋 SYSTEM ARCHITECTURE

### Seven STIX Dialects
1. **STIX 2.1** - Core cybersecurity threat intelligence
2. **MITRE ATT&CK** - Adversarial tactics and techniques
3. **MITRE ATLAS** - AI/ML security framework
4. **OCA Extensions** - Open Cybersecurity Alliance
5. **MBC Extensions** - Malware Behavior Catalog
6. **OS-Threat** - Custom threat intelligence objects
7. **Attack Flow** - Attack sequence modeling

### Core Modules
- **`stixorm/module/parsing/`** - 7-operation cleaning pipeline
- **`stixorm/module/orm/`** - TypeQL integration with collision prevention
- **`stixorm/module/definitions/`** - Seven dialect definitions
- **`stixorm/module/typedb_lib/`** - Database interaction layer

## 🚀 LEARNING PHASES (Token-Efficient)

### Phase 0: Background Research (Ready to Begin)
**Objective**: Essential foundation knowledge before implementation

#### Setup
```bash
mkdir -p architecture/{background_research,generate,analysis}
```

#### Research Tasks (Size-Efficient)
1. **TypeQL Fundamentals** → `typeql-crash-course.md`
   - **Focus**: Variable naming, query structure, relationships
   - **Source**: TypeDB crash course documentation
   
2. **TypeDB PERA Model** → `typedb-pera-model.md`
   - **Focus**: Entity-relationship-attribute patterns
   - **Source**: TypeDB PERA documentation
   
3. **STIX 2.1 Specification** → `stix-21-specification.md`
   - **Focus**: Object types, relationships, reference patterns
   - **Source**: OASIS STIX documentation

#### Knowledge Checkpoints
- [ ] TypeQL variable naming principles (foundation for collision prevention)
- [ ] TypeDB relationship modeling (supports dynamic reference detection)
- [ ] STIX object structure (enables conditional enrichment understanding)

### Phase 1: Architecture Analysis
**Objective**: Document system comprehension using optimized format

#### Critical Analysis Areas
- **Collision Prevention Implementation** → Focus on `embedded_relation()` function
- **Conditional Pipeline Architecture** → Focus on `clean_stix_list()` operations
- **Dynamic Detection Patterns** → Focus on reference field identification

#### Documentation Strategy
- **Format**: Bullet points, front-loaded critical info
- **Location**: `./architecture/analysis/`
- **Cross-Reference**: Link to `.github/instructions/` for patterns

### Phase 2: Hands-On Validation
**Objective**: Validate critical patterns through testing

#### Essential Tests
```python
# TypeQL collision prevention validation
def test_collision_prevention():
    complex_incident = {
        'on_completion': 'sequence--target-1',
        'sequence': 'sequence--target-2',
        'other_sequence_ref': 'sequence--target-3'
    }
    variables = generate_typeql_variables(complex_incident)
    assert len(variables) == len(set(variables))  # No collisions

# Conditional pipeline validation
def test_conditional_paths():
    test_cases = [(False, False), (True, False), (False, True), (True, True)]
    for clean_sco, enrich_external in test_cases:
        result = clean_stix_list(objects, clean_sco, enrich_external)
        validate_conditional_behavior(result, clean_sco, enrich_external)
```

### Phase 3: System Enhancement
**Objective**: Apply patterns to improve existing systems

#### Integration Tasks
- **Testing Enhancement**: Apply collision prevention to all test scenarios
- **Documentation Optimization**: Use size-efficient format from PRIMARY.instructions.md
- **Pattern Validation**: Ensure dynamic detection works with custom fields

### Phase 4: Expert Mastery
**Objective**: Synthesize knowledge into optimized instructions

#### Knowledge Transfer
- **Update**: `.github/instructions/` with new learnings
- **Follow**: Size-efficiency guidelines from PRIMARY.instructions.md
- **Maintain**: Token-efficient bullet format
- **Emphasize**: Critical patterns first, background last

## 📊 SUCCESS METRICS

### Foundation Level (Quantified)
- **TypeQL Collision Rate**: 0% (prevention success)
- **Missing Dependency Detection**: 100% accuracy
- **External Source Integration**: 5 MITRE/MBC operational
- **Pipeline Performance**: <1s for typical datasets

### Advanced Level Targets
- **Test Coverage**: 95%+ on critical modules
- **Documentation Efficiency**: 40%+ information density
- **Pattern Recognition**: All seven dialects supported

### Expert Level Goals
- **System Optimization**: Performance improvements across operations
- **Extensibility**: Clean patterns for new dialect integration
- **Knowledge Transfer**: Size-efficient instruction mastery

## 🎯 LEARNING PRINCIPLES (Optimized)

### Efficiency-First Documentation
- **Bullet Points**: Not verbose prose
- **Critical Patterns First**: Background information last
- **Cross-References**: Instead of content duplication
- **Code Examples**: Essential patterns only

### Pattern-Based Learning
- **Focus**: Critical implementation solutions
- **Validate**: Through hands-on testing
- **Document**: Using optimized instruction format
- **Apply**: To system improvements

### Context-Aware Integration
- **Auto-Load Triggers**: Based on learning scenarios
- **Smart References**: Connect to existing instructions
- **Progressive Depth**: Layer 1 → Layer 2 → Layer 3 knowledge

## 🔗 INTEGRATION WITH INSTRUCTION SYSTEM

### Mandatory Reading Order
1. **PRIMARY.instructions.md** - Size-efficient optimization (ALWAYS FIRST)
2. **MASTER-INDEX.instructions.md** - Critical patterns overview
3. **This learning framework** - Applied learning strategy
4. **Domain-specific instructions** - Based on learning phase

### Learning Context Triggers
- **TypeQL Issues** → typeql-integration.instructions.md + collision testing
- **STIX Processing** → enhancement-summary.instructions.md + conditional testing
- **Reference Detection** → python-patterns.instructions.md + dynamic validation
- **System Improvement** → ALL instruction files + optimization patterns

---

**This learning framework ensures efficient mastery of STIX-ORM's critical implementation patterns while maintaining size-efficient knowledge transfer and progressive skill development.**