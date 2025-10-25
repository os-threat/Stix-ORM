# STIX-ORM

**Sophisticated cybersecurity intelligence transformation system bridging seven STIX dialects with TypeDB's hypergraph database technology.**

## 🚀 Quick Start

```python
from stixorm.module.parsing.clean_list_or_bundle import clean_stix_list

# Basic STIX object processing
raw_stix_objects = load_your_stix_data()
cleaned_objects, report = clean_stix_list(raw_stix_objects)

if report.clean_operation_outcome:
    print(f"Successfully processed {len(cleaned_objects)} STIX objects")
else:
    print(f"Processing failed: {report.return_message}")
```

## 🌟 Key Features

- **7-Dialect STIX Support**: Core STIX 2.1, MITRE ATT&CK, ATLAS, OCA, MBC, OS-Threat, Attack Flow
- **TypeQL Integration**: Variable collision prevention and safe database insertion
- **Conditional Processing**: Optional external enrichment and SCO field cleaning
- **Dynamic Reference Detection**: Future-proof handling of custom STIX extensions
- **Comprehensive Error Handling**: Detailed reporting with original data preservation

## 📖 Documentation Structure

### Getting Started
- **[PROJECT-OVERVIEW.md](PROJECT-OVERVIEW.md)** - Complete project introduction and architecture overview
- **[QUICK-REFERENCE.md](QUICK-REFERENCE.md)** - Essential functions, patterns, and examples for immediate use

### Development Resources  
- **[CODING-STANDARDS.md](CODING-STANDARDS.md)** - Python conventions and STIX-ORM specific patterns
- **[TESTING-STANDARDS.md](TESTING-STANDARDS.md)** - Comprehensive testing requirements and validation approaches

### Technical Documentation
- **[blueprint.md](blueprint.md)** - Detailed architectural design with critical implementation solutions
- **[docs/implementation-guide.md](docs/implementation-guide.md)** - Complete technical implementation guide
- **[docs/overview.md](docs/overview.md)** - Documentation navigation and structure

### Implementation Knowledge
- **[.github/instructions/README.md](.github/instructions/README.md)** - Critical implementation patterns and anti-patterns
- **[.github/prompts/README.md](.github/prompts/README.md)** - Technical specifications and context files

## 🏗️ Architecture Highlights

### Critical Implementation Solutions

#### TypeQL Variable Collision Prevention
Prevents database insertion failures through relation-aware variable naming:
```python
# Before: "sequence0", "sequence1" (collisions)
# After: "on-completion-sequence0", "sequence-sequence1" (unique)
relation_prefix = prop.replace('_', '-')  
variable_name = f"{relation_prefix}-{prop_type}{i}"
```

#### Conditional Enrichment System
Provides operational control over external source integration:
```python
clean_stix_list(
    objects,
    clean_sco_fields=True,           # Optional SCO compliance
    enrich_from_external_sources=True # Optional external fetching
)
```

#### Dynamic Reference Detection
Future-proof handling of custom STIX extensions:
```python
# Detects both standard (_ref, _refs) and custom fields (on_completion, behavior_refs)
if field.endswith('_ref') or is_stix_id_pattern(value):
    handle_as_reference(field, value)
```

## 🛠️ Installation

```bash
# Clone repository
git clone https://github.com/your-org/stix-orm.git
cd stix-orm

# Install with Poetry (recommended)
pip install poetry
poetry install

# Or install with pip
pip install -r requirements.txt
```

## 🧪 Testing

```bash
# Run all tests
poetry run pytest

# Run with coverage
poetry run pytest --cov=stixorm --cov-report=html

# Run specific test categories
poetry run pytest -m unit          # Unit tests only
poetry run pytest -m integration   # Integration tests only
```

## 📋 Supported STIX Dialects

| Dialect | Purpose | Objects Supported |
|---------|---------|-------------------|
| **STIX 2.1** | Core cybersecurity threat intelligence | All standard STIX objects |
| **MITRE ATT&CK** | Adversarial tactics and techniques | Attack patterns, malware, tools |
| **MITRE ATLAS** | AI/ML security framework | AI-specific threat objects |
| **OCA Extensions** | Open Cybersecurity Alliance | Extended threat intelligence |
| **MBC** | Malware Behavior Catalog | Malware behavior classifications |
| **OS-Threat** | Custom threat objects | Custom incident and sequence objects |
| **Attack Flow** | Attack sequence modeling | Flow-based attack representations |

## 🔧 Configuration Options

### Processing Modes

| Mode | Configuration | Use Case |
|------|---------------|----------|
| **Air-gapped** | Default settings | Secure environments without external access |
| **Enriched** | `enrich_from_external_sources=True` | Complete datasets with missing dependency resolution |
| **Compliant** | `clean_sco_fields=True` | STIX standard compliance validation |
| **Full** | Both options enabled | Complete processing with all features |

### External Sources (when enrichment enabled)

- MITRE ATT&CK Enterprise, Mobile, ICS
- MITRE ATLAS Framework  
- Malware Behavior Catalog (MBC)

## 🎯 Use Cases

### Enterprise Threat Intelligence
```python
# Centralized threat intelligence processing
threat_data = load_multiple_sources()
processed, report = clean_stix_list(
    threat_data,
    enrich_from_external_sources=True
)
store_in_typedb(processed)
```

### Security Research
```python
# Custom STIX extension validation
custom_objects = load_custom_stix_extensions()
cleaned, report = clean_stix_list(custom_objects)
validate_extension_compliance(cleaned, report)
```

### Incident Response
```python
# Rapid threat context gathering
incident_data = load_incident_stix()
enriched, report = clean_stix_list(
    incident_data,
    enrich_from_external_sources=True
)
analyze_threat_context(enriched)
```

## 📊 Performance Characteristics

- **Processing Speed**: <1s for typical datasets (100-1000 objects)
- **Memory Usage**: Linear scaling with dataset size
- **Accuracy**: 100% TypeQL variable collision prevention
- **Coverage**: 95%+ test coverage on critical modules

## 🤝 Contributing

### Development Workflow

1. **Read Documentation**: Start with [PROJECT-OVERVIEW.md](PROJECT-OVERVIEW.md)
2. **Check Standards**: Review [CODING-STANDARDS.md](CODING-STANDARDS.md)
3. **Follow Patterns**: Implement according to [.github/instructions/](.github/instructions/)
4. **Write Tests**: Validate with [TESTING-STANDARDS.md](TESTING-STANDARDS.md)
5. **Update Docs**: Keep documentation current

### Code Quality Requirements

- Follow PEP 8 and project-specific standards
- Maintain 90%+ test coverage
- Include comprehensive type hints and docstrings
- Validate TypeQL variable collision prevention
- Test all conditional operation paths

## 📄 License

- **Client Libraries**: Apache 2.0 License
- **Server Components**: AGPL v3 License

## 🆘 Support

### Documentation Navigation
- **Quick Help**: [QUICK-REFERENCE.md](QUICK-REFERENCE.md)
- **Implementation Details**: [docs/implementation-guide.md](docs/implementation-guide.md)
- **Architecture Overview**: [blueprint.md](blueprint.md)

### Community Resources
- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Community support and questions
- **Documentation Site**: Comprehensive guides and examples

---

**STIX-ORM represents the state-of-the-art in cybersecurity intelligence transformation, providing robust, scalable, and extensible solutions for complex threat intelligence processing and analysis.**

For detailed information about any aspect of the system, please consult the comprehensive documentation files listed above.

