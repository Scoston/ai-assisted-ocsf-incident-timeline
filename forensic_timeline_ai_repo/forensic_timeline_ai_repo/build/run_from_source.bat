@echo off
call venv\Scripts\activate
python -m src.timeline_demo.run_real_pipeline
cd streamlit_timeline_ui
python -m streamlit run app/app.py
