"""Record the real Streamlit viewer in CI, using only bundled synthetic evidence."""

import json
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

from playwright.sync_api import expect, sync_playwright


def main():
    output = Path("output/demo-video/capture")
    output.mkdir(parents=True, exist_ok=False)
    command = [
        sys.executable, "-m", "streamlit", "run", "streamlit_timeline_ui/app.py",
        "--server.address", "127.0.0.1", "--server.port", "8501",
        "--server.headless", "true", "--browser.gatherUsageStats", "false",
        "--theme.base", "dark", "--theme.primaryColor", "#42dfb9",
    ]
    with (output / "streamlit.log").open("w") as log:
        server = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
        try:
            for _ in range(60):
                try:
                    with urllib.request.urlopen("http://127.0.0.1:8501/_stcore/health", timeout=1) as r:
                        if r.status == 200:
                            break
                except OSError:
                    if server.poll() is not None:
                        raise RuntimeError("Streamlit exited before readiness")
                    time.sleep(0.5)
            else:
                raise RuntimeError("Streamlit readiness deadline exceeded")
            with sync_playwright() as pw:
                browser = pw.chromium.launch()
                context = browser.new_context(
                    viewport={"width": 1600, "height": 900},
                    record_video_dir=str(output),
                    record_video_size={"width": 1600, "height": 900},
                    device_scale_factor=1,
                )
                page = context.new_page()
                page.goto("http://127.0.0.1:8501")
                expect(page.get_by_text("Bundle file hashes verified.", exact=False)).to_be_visible(timeout=30000)
                expect(page.get_by_text("Displaying 5 of 5 events in UTC order.")).to_be_visible()
                page.screenshot(path=str(output / "viewer.png"))
                page.wait_for_timeout(5000)  # Deliberate viewing time in the recording.
                page.get_by_role("combobox").first.click()
                page.get_by_role("option", name="cloudtrail", exact=True).click()
                page.screenshot(path=str(output / "filtered.png"))
                page.wait_for_timeout(5000)
                page.get_by_text("Inspect source provenance", exact=True).scroll_into_view_if_needed()
                page.mouse.wheel(0, 350)
                page.wait_for_timeout(1000)
                page.screenshot(path=str(output / "provenance.png"))
                page.wait_for_timeout(5000)
                page.get_by_text("Extracted indicators (not verdicts)", exact=True).click()
                page.get_by_text("Extracted indicators (not verdicts)", exact=True).scroll_into_view_if_needed()
                page.mouse.wheel(0, 400)
                page.wait_for_timeout(1000)
                page.screenshot(path=str(output / "indicators.png"))
                page.wait_for_timeout(5000)
                (output / "visible-text.txt").write_text(page.locator("body").inner_text())
                video = page.video
                await_path = str(video.path())
                context.close()
                Path(await_path).rename(output / "viewer.webm")
                browser.close()
            (output / "capture.json").write_text(json.dumps({
                "evidence": "bundled synthetic five-event case",
                "viewport": [1600, 900], "ui": "unmodified Streamlit app",
                "cloud_connections": False, "paid_model_calls": 0,
            }, indent=2) + "\n")
        finally:
            server.terminate()
            server.wait(timeout=15)


if __name__ == "__main__":
    main()
