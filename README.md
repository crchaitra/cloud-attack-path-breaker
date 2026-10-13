# 🛡️ Cloud Attack-Path Breaker

<p align="left">
  <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/Streamlit-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white" alt="Streamlit" />
  <img src="https://img.shields.io/badge/NetworkX-306998?style=for-the-badge" alt="NetworkX" />
  <img src="https://img.shields.io/badge/Cybersecurity-00C853?style=for-the-badge" alt="Cybersecurity" />
</p>

A Python project that looks at how an attacker could move through a cloud environment and reach sensitive data. It finds possible attack paths and lets me test ways to block them without breaking the legitimate access defined in the environment.

The project runs locally using a sample environment, so no cloud account is needed.

What it does
- Finds paths from an entry point to a protected resource.
- Assigns risk scores to discovered paths.
- Checks for a few common risky resource configurations.
- Suggests connections that could be removed.
- Simulates removing multiple connections and checks whether legitimate access is preserved.
- Shows network maps before and after remediation.
- Exports the results as a JSON report.

Built with
- Python
- NetworkX
- Streamlit
- Matplotlib
- Pytest

Run locally
1. Clone the repository**

```bash
git clone https://github.com/crchaitra/cloud-attack-path-breaker.git
cd cloud-attack-path-breaker
```

2. Create and activate a virtual environment**

```bash
python -m venv .venv
.venv\Scripts\activate
```

3. Install the dependencies**

```bash
python -m pip install streamlit networkx matplotlib pytest
```

4. Start the dashboard**

```bash
python -m streamlit run app.py
```

5. Run the tests**

```bash
python -m pytest -v
```

![Tests](https://img.shields.io/badge/Tests-58%20passed-2EA44F?style=for-the-badge)

Sample results:
The included environment has 7 resources and 7 connections. The tool finds 2 attack paths to the protected storage resource.
In the multi-connection remediation simulation, removing 2 connections reduces the discovered attack paths from 2 to 0, while preserving the configured legitimate access.

Limitations:
This is a local simulation, not a live cloud scanner. It doesn't connect to or modify AWS, Azure, or Google Cloud resources. The risk scores are based on simple rules I defined for the project, and the misconfiguration checks only cover the cases I've implemented.

Why I built this:
I wanted to work on something practical in cybersecurity instead of just studying the concepts. This project gave me a way to experiment with attack paths, graph analysis, and remediation, and see how the network changes when connections are removed.

-Author
Chaitra CR · [GitHub](https://github.com/crchaitra)

---

<p align="center">
  <i>Find the path. Break the connection.</i>
</p>
