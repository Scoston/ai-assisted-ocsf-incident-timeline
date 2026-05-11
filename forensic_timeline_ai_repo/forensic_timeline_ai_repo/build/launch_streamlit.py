from __future__ import annotations
import os, socket, subprocess, sys, time, webbrowser
from pathlib import Path

def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def resource_path(relative: str) -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS) / relative
    return Path(__file__).resolve().parent / relative

def main() -> None:
    app_path = resource_path("streamlit_timeline_ui/app/app.py")
    port = free_port()
    env = os.environ.copy()
    env["STREAMLIT_SERVER_HEADLESS"] = "true"
    env["STREAMLIT_BROWSER_GATHER_USAGE_STATS"] = "false"
    proc = subprocess.Popen([sys.executable, "-m", "streamlit", "run", str(app_path), "--server.port", str(port), "--server.address", "127.0.0.1"], env=env)
    time.sleep(2)
    webbrowser.open(f"http://127.0.0.1:{port}")
    proc.wait()

if __name__ == "__main__":
    main()
