# Contributing to Windows System Intelligence (WSI)

Thank you for your interest in contributing to WSI! We welcome contributions that expand diagnostic coverage, enhance analytical rules, and improve cross-version Windows compatibility.

## Core Contributing Invariant: Strict Read-Only Policy

All code in this repository must obey the **Strict Read-Only Policy**:

1. **Zero Modifications**: Collectors and analyzers **must never** perform destructive operations (no registry writes, no file creation outside the target output path, no process termination, no service state changes).
2. **Safe Subprocess Invocations**: Never invoke shell scripts or binaries with write, delete, install, or repair flags.
3. **Synthetic Dataset Testing**: All test cases must use synthetic mock datasets. Tests must never modify the host environment.
4. **Standard Library First**: Core collectors and analyzers must avoid heavy third-party dependencies where native Windows APIs, CIM, or registry enumeration suffice.

## Development Workflow

### 1. Clone & Set Up Environment

```powershell
# Clone the repository
git clone https://github.com/<your-username>/windows-system-intelligence.git
cd windows-system-intelligence

# Create virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1

# Install project in editable mode
pip install -e ".[dev]"
```

### 2. Project Layout

```
wsi/
├── core/            # Base interfaces, registry helpers, formatting, HTML dashboard
├── collectors/      # Read-only collectors inheriting from BaseCollector
├── analyzers/       # Diagnostic analyzers inheriting from BaseAnalyzer
└── cli.py           # Command-line interface
```

### 3. Adding a New Collector

1. Create a new module under `wsi/collectors/<name>.py`.
2. Inherit from `BaseCollector` and implement `collect() -> CollectorResult`.
3. Register the collector in `wsi/collectors/__init__.py`.
4. Ensure all exceptions are captured gracefully into `result.errors` without terminating execution.

### 4. Adding a New Diagnostic Analyzer

1. Create a module under `wsi/analyzers/<name>.py`.
2. Inherit from `BaseAnalyzer` and implement `analyze(collector_results) -> AnalysisResult`.
3. Register the analyzer in `wsi/analyzers/__init__.py`.
4. Add corresponding unit tests under `tests/` using synthetic fixtures.

### 5. Running the Test Suite

```powershell
python -m unittest discover -s tests -v
```

All PRs must pass the test suite with 100% green status.

## Pull Request Guidelines

- Give your PR a clear, descriptive title.
- Link any related issues.
- Confirm in your PR description that no host modifications are introduced.
