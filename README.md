# 🧠 Log Analyzer for Attack Detection  
[![Hacktoberfest](https://img.shields.io/badge/Hacktoberfest-2025-blueviolet?style=flat&logo=hackaday)](https://hacktoberfest.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)
![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue)
![Contributions welcome](https://img.shields.io/badge/Contributions-welcome-brightgreen.svg)
![Tests](https://img.shields.io/badge/Tests-passing-success.svg)

A modular **Python-based Apache Log Analyzer** built to detect common web attack patterns such as **Brute Force, SQL Injection, and XSS**.  
Developed for **security engineers**, **SOC analysts**, and **students** aiming to understand real-world threat detection from server logs.  

---

## 📚 Table of Contents  
- [🚀 Features](#-features)  
- [📁 Project Structure](#-project-structure)  
- [⚙️ Usage](#️-usage)  
- [📊 Example Visualization](#-example-visualization)  
- [🧪 Tests](#-tests)  
- [🎯 Contribution Guide](#-contribution-guide)  
- [🏷️ Hacktoberfest](#️-hacktoberfest)  
- [📜 License](#-license)  

---

## 🚀 Features  

- **Rule-Based Attack Detection**  
  Detects Brute Force, SQL Injection, and XSS attempts using modular detection rules (`analyzer/rules/`).  

- **Apache Log Parsing**  
  Parses large Apache access logs efficiently with normalization and error-handling (`analyzer/parser.py`).  

- **Adaptive Anomaly Detection**  
  Scores and highlights outliers in activity patterns using machine learning–ready logic (`analyzer/anomaly_engine.py`).  

- **Visual Reporting**  
  Visualizes key metrics like IP frequency, attack type trends, and anomaly scores via `matplotlib` (`scripts/visualize_results.py`).  

- **Command-Line Interface (CLI)**  
  Run analysis directly from the terminal for quick, modular operation (`cli/main.py`).  

- **Comprehensive Unit Tests**  
  Includes test coverage for parsing and detection logic to ensure high reliability.  

---

## 📁 Project Structure  

log-analyzer-attack-detection/
├── analyzer/
│ ├── parser.py
│ ├── anomaly_engine.py
│ └── rules/
│ ├── brute_force.py
│ ├── sql_injection.py
│ └── xss.py
├── cli/
│ └── main.py
├── scripts/
│ └── visualize_results.py
├── tests/
│ ├── test_parser.py
│ └── test_rules.py
├── requirements.txt
├── CONTRIBUTING.md
├── LICENSE
└── README.md


---

## ⚙️ Usage  

# Clone the repository
git clone https://github.com/Rohit30Confluence/log-analyzer-attack-detection.git
cd log-analyzer-attack-detection

# Install dependencies
pip install -r requirements.txt

# Run analyzer with visualization
python cli/main.py --log path/to/access.log --visualize


📊 Example Visualization
Using scripts/visualize_results.py, the tool generates:
Attack frequency over time
Most targeted endpoints
IP activity distribution
python scripts/visualize_results.py --input results.json

## 🧪 Tests

pytest

pytest --cov=analyzer


## 🎯 Contribution Guide
We welcome contributors to help strengthen this project:
Add new attack detection rules
Improve anomaly detection heuristics
Enhance visualization modules
Optimize parser performance
See CONTRIBUTING.md before submitting pull requests.


## 🏷️ Hacktoberfest
This repository proudly participates in Hacktoberfest 2025.
All PRs labeled hacktoberfest-accepted count toward your official contribution progress.

## 📜 License
Distributed under the MIT License.
See LICENSE for more information.

---

Now commit this to your branch:  
**Branch:** `update-readme-enhanced`  
**Commit title:** `Enhance README with badges, visuals, and structured documentation`
