# Contributing

Contributions are welcome. Please keep every check passive, explainable, and safe to run against systems the user is authorized to assess.

## Development setup

```bash
git clone https://github.com/changemk/secure-site-auditor.git
cd secure-site-auditor
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -v
```

On Windows PowerShell, activate the environment with `.\.venv\Scripts\Activate.ps1`.

Open an issue before starting a large change. Pull requests should include tests for new checks or changed behavior.
