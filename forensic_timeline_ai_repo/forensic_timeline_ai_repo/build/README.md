# Forensic Timeline AI Demo Repo

This GitHub-ready repo demonstrates an evidence-first cyber investigation workflow:

- AWS CloudTrail, Microsoft Entra, and CrowdStrike Falcon parsers
- UTC timeline assembly
- IOC extraction
- optional threat-intelligence enrichment via AbuseIPDB, AlienVault OTX, and VirusTotal
- optional ChatGPT API enrichment via `OPENAI_API_KEY`
- executive Streamlit timeline UI
- AI compromise artifact training data
- top 50 SaaS breach-investigation profiles
- broad DFIR artifact-family catalog modeled on log2timeline / forensic-artifact coverage
- Operation Hollow Ledger breach scenario
- Windows packaging assets for a Streamlit launcher executable

## Quick start on Windows

```bat
py -3.14 -m venv venv
venv\Scripts\activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e .
python -m pip install -r requirements.txt
copy .env.example .env
python -m src.timeline_demo.run_real_pipeline
pytest tests -q
cd streamlit_timeline_ui
python -m streamlit run app/app.py
```

## Demo assets

- `catalogs/scenarios/orion_insurance_hollow_ledger.md`
- `docs/demo_guide.md`
- `catalogs/ai_artifacts/training_data.jsonl`
- `catalogs/saas_profiles/top50_saas_profiles.json`
- `catalogs/log2timeline_artifacts/artifact_catalog.json`
<img width="1681" height="528" alt="image" src="https://github.com/user-attachments/assets/bb2c0e0b-1806-45f5-8a2a-e63fa12c0fd0" />

## Windows executable build

```bat
build\build_windows.bat
```

This uses `launch_streamlit.py` and `build/timeline_demo.spec`.

## Evidence boundary

AI enrichment reads verified timeline outputs, extracted IOCs, and optional TI results. It does not modify evidence, timestamps, hashes, or event ordering.

## Note

This repo ships a broad artifact-family catalog modeled on log2timeline / forensic artifact coverage. It is not a mirrored copy of every upstream Plaso parser or every upstream artifact-definition file.
