# TypeQL Crash Course - Essential Fundamentals

*Source: TypeDB Documentation - Crash Course for Relational Database Users*
*Focus: Variable naming, query structure, relationships for STIX-ORM implementation*

## 🎯 Critical Learning Objectives

**Primary Focus**: Master TypeQL variable naming principles that prevent database insertion failures
**Secondary Focus**: Understand query structure for STIX object relationship modeling
**Application**: Foundation for TypeQL collision prevention in STIX-ORM

## 🔥 Key Variable Naming Principles

### Variable Declaration Syntax
```typeql
$variable-name isa type-name;
$user-1 isa user;
$order-relation isa order;
```

**Critical Rules**:
- Variables use `$` prefix
- Naming convention: `$descriptive-name-type`
- Variables are scoped to single query
- **Variable names must be unique within query scope**

### Relation Variable Patterns
```typeql
# Relation tuple syntax
$relation (role-1: $entity-1, role-2: $entity-2) isa relation-type;

# Example: Order relation
$order (buyer: $user) isa order;

# Complex relation with multiple roles
$order-line (order: $order, item: $book) isa order-line;
```

**STIX-ORM Application**: 
- Each property reference needs unique variable
- Relation-aware prefixes prevent collisions
- Pattern: `$property-name-object-type-sequence`

## 📋 Query Structure Fundamentals

### Insert Query Pattern
```typeql
match
  $existing-entity isa entity-type, has id "value";
insert
  $new-entity isa entity-type,
    has attribute-1 "value-1",
    has attribute-2 "value-2";
  $relation (role: $existing-entity, role: $new-entity) isa relation-type;
```

### Match-Fetch Query Pattern
```typeql
match
  $entity isa entity-type;
  $relation (role: $entity) isa relation-type;
fetch
  $entity: attribute-type-1, attribute-type-2;
  $relation: attribute-type-3;
```

## 🔗 Relationship Modeling

### Entity-Relationship-Attribute (PERA) Model

#### Entity Types
```typeql
define
  user sub entity,
    owns id @key,
    owns name,
    plays order:buyer;
```

#### Relation Types
```typeql
define
  order sub relation,
    relates buyer,
    relates item,
    owns timestamp;
```

#### Attribute Types
```typeql
define
  id sub attribute, value string;
  name sub attribute, value string;
  timestamp sub attribute, value datetime;
```

### Multi-Type References (Critical for STIX)
```typeql
# Multiple types can play same role
book plays order-line:item;
accessory plays order-line:item;

# Query matches both types
match
  $item plays order-line:item;  # Matches books AND accessories
```

**STIX-ORM Relevance**: 
- Multiple STIX object types can reference same target
- Dynamic detection must handle all reference types
- Avoid hardcoded type lists

## 🚨 Variable Collision Prevention Insights

### Problem Scenario
```typeql
# PROBLEMATIC: Multiple same-type references
match
  $incident isa incident;
  $sequence-1 isa sequence;  # First sequence reference
  $sequence-2 isa sequence;  # Second sequence reference - COLLISION RISK
  $sequence-3 isa sequence;  # Third sequence reference - COLLISION RISK
```

### Solution Approach
```typeql
# SOLUTION: Context-aware variable naming
match
  $incident isa incident;
  $on-completion-sequence isa sequence;     # Unique based on property context
  $sequence-sequence isa sequence;          # Unique based on property context  
  $other-reference-sequence isa sequence;   # Unique based on property context
```

### Rule Application for STIX-ORM
- **Property Context**: `on_completion` → `on-completion-sequence`
- **Normalization**: Replace `_` with `-` for TypeQL compatibility
- **Sequence Numbers**: Add incrementing suffix for multiple instances
- **Pattern**: `{property-context}-{object-type}-{sequence}`

## 📊 Schema Definition Patterns

### Type Hierarchy (STIX Object Inheritance)
```typeql
define
  stix-object sub entity, abstract;
  
  # STIX Domain Objects
  attack-pattern sub stix-object;
  malware sub stix-object;
  indicator sub stix-object;
  
  # STIX Relationship Objects  
  stix-relationship sub relation, abstract;
  uses sub stix-relationship,
    relates source,
    relates target;
```

### Attribute Reuse (STIX Properties)
```typeql
define
  # Shared STIX attributes
  id sub attribute, value string;
  created sub attribute, value datetime;
  modified sub attribute, value datetime;
  
  # Multiple types own same attributes
  attack-pattern owns id @key, owns created, owns modified;
  malware owns id @key, owns created, owns modified;
  indicator owns id @key, owns created, owns modified;
```

## 🎯 Learning Checkpoints

### Variable Naming Mastery
- [ ] Understand `$variable` syntax requirements
- [ ] Recognize collision risks in same-type references
- [ ] Apply context-aware naming strategies
- [ ] Implement normalization rules (`_` → `-`)

### Query Structure Comprehension  
- [ ] Master match-insert pattern for data creation
- [ ] Understand match-fetch pattern for data retrieval
- [ ] Apply relation tuple syntax correctly
- [ ] Handle multi-type references in queries

### Relationship Modeling Understanding
- [ ] Distinguish entity, relation, and attribute types
- [ ] Model inheritance hierarchies appropriately
- [ ] Handle shared attributes across types
- [ ] Design role-based relationship connections

## 🔗 Integration with STIX-ORM Patterns

### Connection to Collision Prevention
This TypeQL foundation directly supports:
- **Relation-aware variable generation** in `embedded_relation()` function
- **Property-based context naming** for STIX object references
- **Schema-compliant normalization** for database insertion

### Next Learning Steps
1. **TypeDB PERA Model** → Advanced relationship patterns
2. **STIX 2.1 Specification** → Object type and reference structures
3. **Architecture Analysis** → Apply to existing STIX-ORM codebase

---

**This crash course provides the essential TypeQL foundation needed to understand and implement variable collision prevention in STIX-ORM's TypeDB integration layer.**