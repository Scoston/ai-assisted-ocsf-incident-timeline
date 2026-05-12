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
<img width="860" height="271" alt="image" src="https://github.com/user-attachments/assets/96ac93bb-3336-4ebc-b51e-8ba4d898ca08" /><img width="832" height="190" alt="image" src="https://github.com/user-attachments/assets/3c1811c0-1bf9-48d6-b26b-5fee44da1a6b" /><img width="839" height="220" alt="image" src="https://github.com/user-attachments/assets/c8aae210-c2e6-42e6-8a64-7b98a8d2b65d" /><img width="874" height="345" alt="image" src="https://github.com/user-attachments/assets/1eab477a-e2d1-4814-a678-47e471a6aaee" /><img width="851" height="343" alt="image" src="https://github.com/user-attachments/assets/d0de80fa-2c8e-4c10-a043-3617af707041" /><img width="845" height="363" alt="image" src="https://github.com/user-attachments/assets/46551e21-612e-4095-a66b-6182b6c50ff5" /><img width="864" height="308" alt="image" src="https://github.com/user-attachments/assets/61151f6b-8b3e-4bff-abdd-9624850c1d06" /><img width="708" height="281" alt="image" src="https://github.com/user-attachments/assets/f409a542-9d3a-48c0-80c9-4bf84092e250" /><img width="846" height="347" alt="image" src="https://github.com/user-attachments/assets/182c10aa-d907-4b5b-86cd-890588890be6" />

## Windows executable build

```bat
build\build_windows.bat
```

This uses `launch_streamlit.py` and `build/timeline_demo.spec`.

## Evidence boundary

AI enrichment reads verified timeline outputs, extracted IOCs, and optional TI results. It does not modify evidence, timestamps, hashes, or event ordering.

## Note

This repo ships a broad artifact-family catalog modeled on log2timeline / forensic artifact coverage. It is not a mirrored copy of every upstream Plaso parser or every upstream artifact-definition file.
