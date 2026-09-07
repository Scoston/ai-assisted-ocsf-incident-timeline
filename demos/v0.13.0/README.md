# v0.13.0 feature demo production

The [video and companions](https://github.com/Scoston/ai-assisted-ocsf-incident-timeline/releases/tag/demo-v0.13.0) cover all major current features in 20 narrated chapters. See the [viewer guide](../../docs/DEMO.md) for the chapter index and commands.

## What is actually demonstrated

- `prepare.py` executes the current CLI and Python APIs against bundled synthetic evidence: ingestion, verification, deliberate tampering of a temporary copy, strict OCSF export, model planning, signer retirement/revocation, developer-source parsing, and checkpoint backup/restore/resume.
- The AI cache portion injects the repository's offline test double. It does not claim provider output quality or actual paid usage.
- `capture_viewer.py` starts the unmodified Streamlit app on loopback, verifies the loaded case, filters sources, and records the real interface with Playwright in CI. No customer browser or authenticated tenant is recorded.
- Tines, Databricks, and shared OIDC deployment are labeled configuration walkthroughs. Native fixture totals and performance figures are explicitly historical measurements linked to their validation records.
- Narration is synthetic: Kokoro ONNX, stock voice `af_sarah`. No voice cloning, customer evidence, API keys, or paid model calls are used. Investigation commands run offline; installing tools and downloading pinned narration assets requires network access.

## Reproduce locally

Use Python 3.12 on Linux, FFmpeg, and DejaVu Sans fonts. Install media tools in a dedicated environment; they are not runtime dependencies of the incident tool.

```bash
python -m venv .venv-media
source .venv-media/bin/activate
python -m pip install -e '.[dev,ui,signing]' 'playwright==1.62.0' -r demos/v0.13.0/requirements-media.txt
python -m playwright install --with-deps chromium
python scripts/demo_video/prepare.py
python scripts/demo_video/capture_viewer.py
python scripts/demo_video/narrate.py
python scripts/demo_video/render.py --frames-only
# Review the frames before encoding.
python scripts/demo_video/render.py
ffmpeg -v error -xerror -i output/demo-video/deliverables/timeline-v0.13.0-demo.mp4 -f null -
python scripts/demo_video/package.py
```

Start with a fresh `output/demo-video/` directory. The scripts reject existing evidence, audio, capture and segment outputs. Move prior generated output to an archive directory before a new build. `render.py --frames-only` can refresh draft frames. Dependencies, host fonts and codecs can affect bytes and timing; this is a reproducible workflow, not a promise of identical encodes on different hosts.

The narration script verifies SHA-256 for the exact model and voice assets before loading them. A small adapter supplies the float speed input required by the pinned model; `kokoro-onnx==0.4.9` otherwise constructs an integer for that input. The script validates the model's declared input type.

## Review and publication

The `Build feature demo video` workflow produces a full candidate on the demo branch. It verifies feature assertions, renders 1920×1080 H.264/AAC with burned captions, embeds an optional English subtitle track and 20 chapters, and decodes the finished MP4. It uploads a commit-named candidate ZIP to the dedicated demo release for review.

`approved.json` pins the reviewed candidate ZIP and every companion file by SHA-256. Once that record is merged, the main-branch publish job promotes those exact bytes; it does not regenerate narration or footage. Existing files with different hashes cause a conflict rather than being overwritten. Build jobs have read-only repository permission; only the release-upload jobs have `contents: write`. The workflow uses no tenant credentials or model API keys.

For a future version, create a new versioned media directory, release tag and workflow target. For a revision of this demo, remove its local approval record on a working branch, render a new commit-named candidate, review it and update the pins. Use a new release/version for replacement public filenames; the publisher deliberately refuses conflicting existing media.

## Companions and attribution

The release includes the MP4, PNG poster, SRT and WebVTT captions, chapter list, Markdown transcript, build provenance, checksums and a ZIP of synthetic command results and UI source captures. Large media and model weights stay outside git history. The checked-in storyboard and scripts are covered by the repository's Apache-2.0 license.

- [Kokoro ONNX](https://github.com/thewh1teagle/kokoro-onnx): MIT wrapper; upstream identifies the Kokoro model as Apache-2.0. [Pinned model release](https://github.com/thewh1teagle/kokoro-onnx/releases/tag/model-files-v1.1).
- [DejaVu fonts](https://dejavu-fonts.github.io/License.html): distributed under the included permissive font licenses; fonts are rendered into the video, not redistributed as font files.
- [Playwright recording API](https://playwright.dev/python/docs/videos): real browser recording, with the context closed to finalize the video.

There is no background music or externally sourced stock footage.
