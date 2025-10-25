# STIX-ORM AI Learning Framework

## 🚨 CRITICAL: Read PRIMARY.instructions.md First
**Mandatory**: Follow size-efficient instruction optimization → `.github/instructions/PRIMARY.instructions.md`

## 🎯 AI Learning Mission

**Primary Objective**: Master the **STIX-ORM library** - a sophisticated cybersecurity intelligence transformation system that bridges seven STIX dialects with TypeDB's hypergraph database technology.

**Core Innovation**: Universal transformation patterns that prevent database insertion failures while maintaining semantic fidelity across all cybersecurity frameworks.

## 🔥 CRITICAL IMPLEMENTATION KNOWLEDGE (Learn First)

### TypeQL Variable Collision Prevention
- **Pattern**: `relation_prefix = prop.replace('_', '-'); var = f"{relation_prefix}-{type}{i}"`
- **Critical**: Database insertion failures without this pattern
- **Example**: `on_completion` → `on-completion-sequence0` (unique)
- **Never**: Generic naming like `sequence0`, `sequence1` (causes collisions)

### Conditional Enrichment System
- **Signature**: `clean_stix_list(objects, clean_sco_fields=False, enrich_from_external_sources=False)`
- **Default**: Air-gapped mode (no external calls)
- **Purpose**: Operational control over external source integration

### Dynamic Reference Detection
- **Method 1**: Standard patterns (`_ref`, `_refs`)
- **Method 2**: STIX ID regex `^[a-zA-Z0-9\-]+--[0-9a-fA-F\-]+$`
- **Never**: Hardcoded field lists (breaks extensions)

## 📋 STIX-ORM System Architecture

### Seven Supported STIX Dialects
1. **STIX 2.1** - Core cybersecurity threat intelligence
2. **MITRE ATT&CK** - Adversarial tactics and techniques  
3. **MITRE ATLAS** - AI/ML security framework
4. **OCA Extensions** - Open Cybersecurity Alliance
5. **MBC Extensions** - Malware Behavior Catalog
6. **OS-Threat** - Custom threat intelligence objects
7. **Attack Flow** - Attack sequence modeling

### Core Module Structure
- **`stixorm/module/parsing/`** - 7-operation cleaning pipeline with conditional enrichment
- **`stixorm/module/orm/`** - TypeQL integration with collision prevention
- **`stixorm/module/definitions/`** - Seven dialect definitions and mappings
- **`stixorm/module/typedb_lib/`** - Database interaction layer

## 🚀 LEARNING PHASES (Optimized)

### Phase 0: Background Research (Ready to Begin)
**Status**: Not yet started - Essential foundation research needed

#### Critical Prerequisites
Before diving into STIX-ORM implementation, establish foundational knowledge of the underlying technologies and standards.

#### 0.1 Architecture Directory Setup
```bash
# Create learning framework structure
mkdir -p architecture/background_research
mkdir -p architecture/generate
mkdir -p architecture/analysis
```

#### 0.2 Technology Foundation Research
**Objective**: Convert key documentation to markdown for comprehensive understanding

##### HTML-to-Markdown Conversion Tasks
1. **TypeQL Fundamentals**
   - **Source**: [TypeDB Crash Course for Relational Users](https://typedb.com/docs/home/2.x/crash-course/relational-users)
   - **Output**: `architecture/background_research/typeql-crash-course.md`
   - **Focus**: Variable naming, query structure, relationship modeling

2. **TypeDB PERA Model**
   - **Source**: [TypeDB PERA Model Documentation](https://typedb.com/docs/home/2.x/concepts/pera-model)
   - **Output**: `architecture/background_research/typedb-pera-model.md`
   - **Focus**: Entity-relationship-attribute patterns

3. **STIX 2.1 Specification**
   - **Source**: [STIX 2.1 Introduction](https://oasis-open.github.io/cti-documentation/stix/intro)
   - **Output**: `architecture/background_research/stix-21-specification.md`
   - **Focus**: Object types, relationships, reference patterns

##### Conversion Implementation
```python
# Create: architecture/generate/html_to_markdown_converter.py
import requests
from markdownify import markdownify
import os

def convert_webpage_to_markdown(url, output_file):
    """Convert webpage to markdown with proper formatting"""
    # Implementation following size-efficient patterns
    pass

# Convert all three sources using standardized approach
```

#### 0.3 STIX-TypeQL Mapping Foundation
**Objective**: Document the conceptual bridge between STIX objects and TypeDB constructs

##### Core Mapping Concepts (To Research)
- **STIX Object → TypeDB Entity**: How STIX objects become TypeDB entities
- **STIX Relationships → TypeDB Relations**: Reference mapping strategies  
- **STIX Properties → TypeDB Attributes**: Data type transformations
- **Variable Naming Strategy**: Foundation for collision prevention patterns

##### Documentation Output
- `architecture/background_research/stix-typeql-mapping-concepts.md`
- Focus on conceptual understanding before implementation details

#### 0.4 Transpilation Architecture Research
**Objective**: Understand the data-driven mapping system

##### Key Research Areas
- **Dialect Definition Structure**: How each STIX dialect is defined
- **Mapping Dictionary Patterns**: Standard filename conventions and structures
- **Property Classification**: Six-type mapping system analysis
- **Dynamic vs. Hardcoded**: Understanding data-driven approaches

##### Documentation Output  
- `architecture/background_research/transpilation-architecture.md`
- Foundation for understanding current implementation patterns

#### 0.5 Background Research Validation
**Success Criteria**: Complete understanding of foundational concepts before proceeding to Phase 1

##### Knowledge Checkpoints
- [ ] TypeQL query structure and variable naming principles
- [ ] TypeDB PERA model entity-relationship patterns  
- [ ] STIX 2.1 object structure and reference mechanisms
- [ ] Conceptual mapping between STIX objects and TypeDB constructs
- [ ] Data-driven transpilation architecture principles

##### Integration with Existing Knowledge
Once background research is complete, integrate findings with:
- **TypeQL Variable Collision Prevention**: Apply foundational TypeQL knowledge
- **Dynamic Reference Detection**: Connect with STIX reference patterns  
- **Seven STIX Dialects**: Understand how different dialects extend base STIX

---

**Note**: This background research phase provides essential context for understanding why the critical implementation patterns (collision prevention, conditional enrichment, dynamic detection) were developed and how they solve fundamental challenges in STIX-TypeDB transpilation.

### Phase 1: Architecture Analysis
**Objective**: Document system comprehension using size-efficient format

#### 1.1 Critical Pattern Analysis
```python
# Document understanding of collision prevention
def analyze_collision_prevention():
    """Analyze how relation-aware prefixes prevent database failures"""
    # Focus on embedded_relation() function in import_utilities.py
    
# Document conditional enrichment understanding  
def analyze_conditional_processing():
    """Analyze 7-operation pipeline with conditional execution"""
    # Focus on clean_stix_list() in clean_list_or_bundle.py
```

#### 1.2 Architecture Documentation Strategy
- **Format**: Follow PRIMARY.instructions.md guidelines (bullet points, front-loaded critical info)
- **Location**: `./architecture/analysis/`
- **Focus**: Implementation patterns, not background theory
- **Cross-Reference**: Link to `.github/instructions/` for detailed patterns

### Phase 2: Hands-On Validation
**Objective**: Validate critical patterns through practical application

#### 2.1 TypeQL Collision Testing
```python
# Enhanced exercise with collision validation
def test_collision_prevention():
    """Validate that complex STIX objects generate unique TypeQL variables"""
    
    complex_incident = {
        'on_completion': 'sequence--target-1',
        'sequence': 'sequence--target-2', 
        'other_sequence_ref': 'sequence--target-3'
    }
    
    # CRITICAL: Verify no collisions
    variables = generate_typeql_variables(complex_incident)
    assert len(variables) == len(set(variables))
```

#### 2.2 Conditional Pipeline Testing
```python
# Test all conditional operation paths
def test_conditional_paths():
    """Test all 4 parameter combinations of clean_stix_list()"""
    
    test_cases = [
        (False, False),  # Air-gapped mode
        (True, False),   # SCO cleaning only
        (False, True),   # External enrichment only  
        (True, True)     # Full processing
    ]
    
    for clean_sco, enrich_external in test_cases:
        result = clean_stix_list(objects, clean_sco, enrich_external)
        validate_result(result, clean_sco, enrich_external)
```

### Phase 3: System Enhancement
**Objective**: Apply critical patterns to improve existing systems

#### 3.1 Testing System Integration
- **Apply**: Collision prevention patterns to all test scenarios
- **Validate**: All conditional enrichment paths are tested
- **Ensure**: Dynamic reference detection works with custom fields
- **Location**: Integrate with existing `stixorm/tests/`

#### 3.2 Documentation Generation Enhancement  
- **Apply**: Size-efficient documentation format from PRIMARY.instructions.md
- **Focus**: Critical implementation patterns over background theory
- **Emphasize**: Anti-patterns and collision prevention prominently

### Phase 4: Expert Mastery
**Objective**: Synthesize knowledge into optimized instruction updates

#### 4.1 Instruction Optimization
- **Update**: `.github/instructions/` with new learnings
- **Follow**: PRIMARY.instructions.md size-efficiency guidelines
- **Maintain**: Token-efficient bullet format
- **Emphasize**: Critical patterns first, background last

#### 4.2 Best Practices Documentation
- **Pattern Library**: Expand with new collision prevention examples
- **Anti-Pattern Catalog**: Document what never to do
- **Performance Guidelines**: Optimize for large-scale datasets

## 📊 Success Metrics (Quantified)

### Foundation Level (Achieved ✅)
- **TypeQL Collision Rate**: 0% (100% prevention success)
- **Missing Dependency Detection**: 100% accuracy
- **External Source Integration**: 5 MITRE/MBC sources operational
- **Pipeline Performance**: <1s for typical datasets

### Advanced Level (Target)
- **Test Coverage**: 95%+ on critical modules
- **Documentation Efficiency**: 40%+ information density improvement
- **Pattern Recognition**: All seven STIX dialects supported

### Expert Level (Aspiration)
- **System Optimization**: Performance improvements across all operations
- **Extensibility**: Clean patterns for new STIX dialect integration
- **Knowledge Transfer**: Size-efficient instruction optimization mastery

## 🎯 Key Learning Principles (Optimized)

### 1. Efficiency-First Documentation
- **Bullet Points**: Not verbose prose
- **Critical Patterns First**: Background information last
- **Cross-References**: Instead of content duplication
- **Code Examples**: Essential patterns only

### 2. Pattern-Based Learning
- **Focus**: Critical implementation solutions (collision prevention, conditional enrichment)
- **Validate**: Through hands-on testing and implementation
- **Document**: Using optimized instruction format
- **Apply**: To system improvements and extensions

### 3. Continuous Optimization
- **Update Instructions**: Follow PRIMARY.instructions.md guidelines
- **Maintain Knowledge**: In `.github/instructions/` using efficient format
- **Test Patterns**: Validate all critical implementations work correctly
- **Improve System**: Apply learnings to enhance STIX-ORM architecture

## 🔗 Integration with Existing Instructions

### Mandatory Reading Order
1. **PRIMARY.instructions.md** - Size-efficient optimization (ALWAYS FIRST)
2. **MASTER-INDEX.instructions.md** - Critical patterns overview
3. **enhancement-summary.instructions.md** - Major implementations
4. **typeql-integration.instructions.md** - Collision prevention details
5. **This document** - Learning framework application

### Context-Aware Learning Triggers
- **TypeQL Issues** → Load: typeql-integration.instructions.md + collision testing
- **STIX Processing** → Load: enhancement-summary.instructions.md + conditional testing  
- **Reference Detection** → Load: python-patterns.instructions.md + dynamic validation
- **System Improvement** → Load: ALL instruction files + optimization patterns

---

**This learning framework ensures mastery of STIX-ORM's critical implementation patterns while maintaining size-efficient knowledge transfer and documentation practices.**


