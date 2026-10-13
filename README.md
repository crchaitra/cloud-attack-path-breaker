# 🛡️ Cloud Attack-Path Breaker

A Python-based cloud security simulation tool that discovers potential attack paths, evaluates illustrative risk scores, identifies risky resource configurations, and simulates remediation strategies to protect sensitive cloud assets.

## 🚀 Project Overview

Cloud environments contain interconnected resources, and insecure connections can create paths that attackers could potentially exploit.

**Cloud Attack-Path Breaker** models a cloud environment as a directed graph to identify paths from an entry point to a protected asset. It evaluates discovered paths, recommends connection removals, and compares the original environment with a simulated remediated environment.

This project runs locally using a sample cloud environment. It does not connect to or modify a real cloud account.

## ✨ Features

- **Attack-Path Discovery:** Finds possible routes from an entry point to a protected asset.
- **Risk Scoring:** Assigns illustrative risk scores and explains the contributing factors.
- **Misconfiguration Detection:** Checks for selected risky resource configurations using rule-based checks.
- **Remediation Recommendations:** Suggests connections that could be removed to reduce attack paths.
- **Multi-Connection Remediation:** Simulates removing multiple connections while preserving configured legitimate access.
- **Before-and-After Visualization:** Compares network graphs before and after simulated remediation.
- **Residual Exposure Analysis:** Examines remaining paths and reachable sensitive resources.
- **Security Report Export:** Exports assessment results, misconfiguration findings, and remediation details as JSON.
- **Automated Tests:** Includes tests for core functionality and validation.

## 🧰 Technology Stack

- Python
- NetworkX
- Streamlit
- Matplotlib
- Pytest
- JSON

## ⚙️ Getting Started

### Prerequisites

Install Python and Git.

### 1. Clone the repository

```bash
git clone https://github.com/crchaitra/cloud-attack-path-breaker.git
cd cloud-attack-path-breaker
```

### 2. Create a virtual environment

**Windows:**

```bash
python -m venv .venv
.venv\Scripts\activate
```

### 3. Install dependencies

Install the project's required Python packages:

```bash
python -m pip install streamlit networkx matplotlib pytest
```

### 4. Run the dashboard

```bash
python -m streamlit run app.py
```

Streamlit will provide a local URL to open the dashboard in your browser.

### 5. Run the tests

```bash
python -m pytest -v
```

## 🔍 How It Works

1. Loads and validates a sample cloud environment from JSON.
2. Builds a directed graph representing resources and their connections.
3. Discovers paths between the configured entry point and protected asset.
4. Calculates illustrative risk scores for discovered paths.
5. checks selected resource properties for potential misconfigurations.
6. Evaluates remediation options while checking configured legitimate access.
7. Simulates the proposed changes and compares the resulting graph.
8. Exports the security assessment as a JSON report.

## 📊 Example Results

In the included sample environment:

- Resources: 7
- Connections: 7
- Discovered attack paths: 2
- Attack paths after the demonstrated multi-connection remediation: 0
- Connections removed in that simulation: 2

These are results from the sample configuration, not measurements of a real cloud deployment.

## 🔐 Security and Limitations

- This is a local simulation; it does not connect to AWS, Azure, or Google Cloud.
- Remediation does not modify real infrastructure.
- Risk scores are illustrative project heuristics, not validated real-world risk ratings.
- Misconfiguration checks cover only the rules implemented in this project.
- Results are intended for educational and portfolio demonstration purposes, not as a complete cloud security audit.

## 🧪 Testing

Run the automated test suite with:

```bash
python -m pytest -v
```

The project has reached **58 passing tests** in its current development progress.

## 🎯 Project Goal

The goal is to demonstrate practical concepts in cloud security, graph-based attack-path analysis, defensive remediation planning, security validation, and automated testing.

## 👩‍💻 Author

**Chaitra CR**

GitHub: [@crchaitra](https://github.com/crchaitra)
