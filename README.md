# Production Readiness Checker (PRC)

A comprehensive automated system that evaluates applications and their deployment configurations for production readiness across security, performance, reliability, and monitoring dimensions.

## Features

- **Multi-dimensional Assessment**: Evaluates security, performance, reliability, and monitoring aspects
- **Multiple Scanners**: Integrates with Trivy, Checkov, and Gitleaks for comprehensive scanning
- **AI-Powered Insights**: Uses OpenAI GPT to generate actionable remediation suggestions
- **Automated Fixes**: Generates and applies fixes for common configuration issues
- **Rich Reporting**: Generates reports in JSON, HTML, and PDF formats
- **Local Storage**: Tracks scan history and improvement trends over time
- **CLI Interface**: Beautiful command-line interface with rich output

## Installation

### Prerequisites

1. **Python 3.9+**
2. **Security Scanning Tools** (install at least one):
   - [Trivy](https://trivy.dev/latest/getting-started/installation/) - Vulnerability and misconfiguration scanner
   - [Checkov](https://www.checkov.io/2.Basics/Installing%20Checkov.html) - Infrastructure as Code scanner
   - [Gitleaks](https://github.com/gitleaks/gitleaks#installing) - Secret detection

### Install PRC

```bash
# Clone the repository
git clone https://github.com/your-org/production-readiness-checker.git
cd production-readiness-checker

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install PRC
pip install -e .
```

### Install Scanning Tools

```bash
# Trivy (Linux/macOS)
brew install trivy
# or
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Checkov
pip install checkov

# Gitleaks
brew install gitleaks
# or download from https://github.com/gitleaks/gitleaks/releases
```

## Quick Start

### Basic Scan

```bash
# Scan current directory
prc scan

# Scan specific directory
prc scan /path/to/project

# Scan with specific output formats
prc scan --format json --format html --format pdf

# Scan with AI insights (requires OPENAI_API_KEY)
export OPENAI_API_KEY=your-api-key
prc scan --ai
```

### View Results

```bash
# Show scan history
prc history

# Show current status
prc status

# List issues from latest scan
prc issues

# Filter issues by severity
prc issues --severity critical
```

### Check Tool Availability

```bash
prc check-tools
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENAI_API_KEY` | OpenAI API key for AI insights | None |
| `PRC_DATA_DIR` | Data directory for storage | `~/.prc` |
| `PRC_CONFIG` | Path to configuration file | None |

### Configuration File

Create a `prc.yaml` in your project root:

```yaml
scoring:
  readiness_threshold: 75.0
  weights:
    security: 0.40
    performance: 0.20
    reliability: 0.25
    monitoring: 0.15

scanners:
  trivy:
    enabled: true
    severity_threshold: "MEDIUM"

reporting:
  formats:
    - json
    - html
```

## Architecture

```
production-readiness-checker/
├── src/
│   ├── core/                 # Core modules
│   │   ├── file_discovery.py # File discovery and categorization
│   │   ├── scanner.py        # Base scanner classes
│   │   ├── scorer.py         # Scoring algorithm
│   │   └── parallel_executor.py
│   │
│   ├── scanners/             # Scanner implementations
│   │   └── security/
│   │       ├── trivy_scanner.py
│   │       ├── checkov_scanner.py
│   │       └── gitleaks_scanner.py
│   │
│   ├── reporters/            # Report generators
│   │   ├── json_reporter.py
│   │   ├── html_reporter.py
│   │   └── pdf_reporter.py
│   │
│   ├── fixers/               # Automated fix generators
│   │   ├── dockerfile_fixer.py
│   │   ├── kubernetes_fixer.py
│   │   └── config_fixer.py
│   │
│   ├── database/             # Local storage
│   │   ├── storage.py
│   │   └── models.py
│   │
│   ├── api/                  # External integrations
│   │   └── ai_insights.py    # OpenAI integration
│   │
│   └── cli/                  # Command-line interface
│       └── main.py
│
├── configs/                  # Configuration files
├── tests/                    # Test suite
└── data/                     # Local data storage
```

## Scoring System

The scoring algorithm evaluates across four dimensions:

| Category | Weight | Description |
|----------|--------|-------------|
| Security | 35% | Vulnerabilities, secrets, misconfigurations |
| Performance | 25% | Resource limits, optimization |
| Reliability | 25% | Health checks, replicas, error handling |
| Monitoring | 15% | Logging, metrics, alerting |

### Severity Penalties

| Severity | Points Deducted |
|----------|-----------------|
| Critical | 25 |
| High | 15 |
| Medium | 8 |
| Low | 3 |
| Info | 1 |

### Production Readiness Criteria

- Overall score >= 70
- Zero critical issues (configurable)
- Maximum 3 high severity issues (configurable)

## Automated Fixes

PRC can automatically generate and apply fixes for common issues:

### Dockerfile Fixes
- Add non-root USER instruction
- Add HEALTHCHECK instruction
- Replace ADD with COPY
- Add apt-get clean
- Specify image version tags
- Remove --insecure flags

### Kubernetes Fixes
- Set securityContext (runAsNonRoot, runAsUser)
- Add resource limits and requests
- Drop capabilities
- Set readOnlyRootFilesystem
- Add liveness/readiness probes
- Fix image tags

## CI/CD Integration

### GitHub Actions

```yaml
name: Production Readiness Check

on: [push, pull_request]

jobs:
  prc-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Trivy
        run: |
          sudo apt-get install wget apt-transport-https gnupg lsb-release
          wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
          echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list
          sudo apt-get update
          sudo apt-get install trivy

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install PRC
        run: |
          pip install -r requirements.txt
          pip install -e .

      - name: Run Production Readiness Check
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: prc scan --format json --format html

      - name: Upload Reports
        uses: actions/upload-artifact@v3
        with:
          name: prc-reports
          path: prc_reports/
```

### GitLab CI

```yaml
production-readiness:
  stage: test
  image: python:3.11
  before_script:
    - apt-get update && apt-get install -y wget
    - wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add -
    - pip install -r requirements.txt
    - pip install -e .
  script:
    - prc scan --format json
  artifacts:
    paths:
      - prc_reports/
    expire_in: 1 week
```

## API Usage

```python
import asyncio
from src.core.file_discovery import FileDiscovery
from src.scanners.security.trivy_scanner import TrivyScanner
from src.core.scorer import Scorer
from src.reporters.report_generator import ReportGenerator

async def run_assessment(project_path: str):
    # Discover files
    discovery = FileDiscovery()
    files = discovery.discover(project_path)

    # Run security scan
    scanner = TrivyScanner()
    scan_result = await scanner.scan(project_path)

    # Calculate score
    scorer = Scorer()
    score = scorer.calculate_score([scan_result])

    # Generate reports
    generator = ReportGenerator()
    reports = await generator.generate_reports(
        project_name="my-project",
        project_path=project_path,
        scan_results=[scan_result],
        score=score,
        formats=["json", "html"],
    )

    return score, reports

# Run assessment
score, reports = asyncio.run(run_assessment("/path/to/project"))
print(f"Score: {score.overall_score}/100")
print(f"Production Ready: {score.is_production_ready}")
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Trivy](https://trivy.dev/) - Comprehensive vulnerability scanner
- [Checkov](https://www.checkov.io/) - Infrastructure as Code scanner
- [Gitleaks](https://github.com/gitleaks/gitleaks) - Secret detection tool
- [OpenAI](https://openai.com/) - AI-powered insights
