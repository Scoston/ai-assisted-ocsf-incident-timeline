from PyInstaller.utils.hooks import collect_submodules
hiddenimports = collect_submodules("streamlit") + collect_submodules("pandas") + collect_submodules("openai")
datas = [("streamlit_timeline_ui/app", "streamlit_timeline_ui/app"),("streamlit_timeline_ui/.streamlit", "streamlit_timeline_ui/.streamlit"),("streamlit_timeline_ui/sample_data", "streamlit_timeline_ui/sample_data"),("catalogs", "catalogs"),(".env.example", ".")]
a = Analysis(["launch_streamlit.py"], pathex=[], binaries=[], datas=datas, hiddenimports=hiddenimports, hookspath=[], hooksconfig={}, runtime_hooks=[], excludes=[], noarchive=False)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, a.binaries, a.datas, [], name="TimelineDemo", debug=False, strip=False, upx=True, console=False)
