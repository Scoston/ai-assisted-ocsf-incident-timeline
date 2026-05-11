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
<img width="846" height="203" alt="image" src="https://github.com/user-attachments/assets/0df978c1-d872-49bd-8987-e7872d5b27ca" />
<img width="511" height="320" alt="image" src="https://github.com/user-attachments/assets/bdaf5d02-dfc7-4505-9f2e-97d68d8e691e" /><img width="301" height="381" alt="image" src="https://github.com/user-attachments/assets/234957c7-1c59-436c-bff6-fdef42bf6de1" /><img width="255" height="339" alt="image" src="https://github.com/user-attachments/assets/9c60d1d6-db00-4cd2-a1ab-dcd465ff3365" /><img width="342" height="325" alt="image" src="https://github.com/user-attachments/assets/004f1e4c-f953-4b8f-9ff2-b417fb32301c" /><img width="314" height="348" alt="image" src="https://github.com/user-attachments/assets/04288ca4-37fc-4181-8fe0-6a0c98e1bc32" />




## Windows executable build

```bat
build\build_windows.bat
```

This uses `launch_streamlit.py` and `build/timeline_demo.spec`.

## Evidence boundary

AI enrichment reads verified timeline outputs, extracted IOCs, and optional TI results. It does not modify evidence, timestamps, hashes, or event ordering.

## Note

This repo ships a broad artifact-family catalog modeled on log2timeline / forensic artifact coverage. It is not a mirrored copy of every upstream Plaso parser or every upstream artifact-definition file.
