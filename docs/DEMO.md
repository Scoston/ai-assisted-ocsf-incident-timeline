# v0.13.0 feature demo

[Watch or download the narrated 1080p video](https://github.com/Scoston/ai-assisted-ocsf-incident-timeline/releases/download/demo-v0.13.0/timeline-v0.13.0-demo.mp4) (**7 minutes 42 seconds**).

The video has burned captions, an optional English subtitle track, and 20 embedded chapters. The [release](https://github.com/Scoston/ai-assisted-ocsf-incident-timeline/releases/tag/demo-v0.13.0) also includes the [transcript](https://github.com/Scoston/ai-assisted-ocsf-incident-timeline/releases/download/demo-v0.13.0/timeline-v0.13.0-demo-transcript.md), [SRT captions](https://github.com/Scoston/ai-assisted-ocsf-incident-timeline/releases/download/demo-v0.13.0/timeline-v0.13.0-demo.srt), WebVTT captions, a poster, provenance and checksums. Open the MP4 directly or download it to a player that supports chapters.

## Chapters

Chapter positions below are rounded down to the nearest second. The embedded chapter track and downloadable chapter file retain the generated timing.

| Start | Feature |
| --- | --- |
| 00:00 | Follow the evidence |
| 00:19 | Start with source evidence |
| 00:38 | Explore the investigation |
| 00:58 | Trace every event |
| 01:16 | Detect altered evidence |
| 01:40 | Collect across the enterprise |
| 02:04 | Include developer incidents |
| 02:24 | Bring native artifacts into scope |
| 02:46 | Preserve the forensic context |
| 03:14 | Export validated OCSF |
| 03:38 | Control who can sign |
| 04:00 | Orchestrate with Tines |
| 04:24 | Publish into Databricks |
| 04:52 | Investigate in Jupyter |
| 05:17 | Choose a model by task |
| 05:40 | Spend tokens deliberately |
| 06:06 | Recover interrupted collection |
| 06:31 | Deploy with explicit access |
| 06:56 | Keep the claims measurable |
| 07:23 | Run your first verified case |

## Follow along

Install the project as described in the [README](../README.md#start-locally). From the repository root, use fresh output directories:

```bash
timeline ingest --case-id demo-013 --input cloudtrail=examples/raw/aws/cloudtrail_real_sample.json --input entra_signin=examples/raw/entra/entra_signin_real_sample.jsonl --input crowdstrike_detection=examples/raw/edr/crowdstrike_detection_real_sample.json --output output/demo-013 --parquet
timeline verify output/demo-013
timeline export-ocsf output/demo-013 --output output/demo-013-ocsf
timeline verify-ocsf output/demo-013-ocsf --bundle output/demo-013
timeline analyze output/demo-013 --task summarize
timeline parsers
timeline plaso-parsers
streamlit run streamlit_timeline_ui/app.py
# In another terminal:
jupyter lab notebooks/
```

The viewer footage opens the bundled `demo-001` case; the CLI demonstration creates `demo-013` from the same five-event synthetic inputs. Select your new bundle in the viewer sidebar. The video presents readable excerpts of command results; the source-capture ZIP contains full recorded command arguments, exit codes and output.

The AI planning command sends no request. The model table shows repository policy defaults: `gpt-5.6-luna` for summarization, `gpt-5.6-terra` for correlation and `gpt-6-astra` for explicitly requested review. Limits are conservative input bounds and output caps, not measured model quality. The cache demonstration uses an offline test double and is labeled accordingly.

## Scope of the demonstration

| Segment | Evidence and limits |
| --- | --- |
| Ingest, verify, OCSF, signing | Executed local CLI/Python APIs with synthetic evidence; deliberate alteration affects only a temporary copy |
| Viewer | Real recording of the unmodified Streamlit app using the bundled synthetic case |
| Collection and recovery | Configuration inventory plus a simulated source exercising the actual checkpoint, backup, restore and health implementation |
| Plaso | Exact pinned inventory and historical upstream/native CI results; not a new live extraction during the video |
| Tines, Databricks, shared OIDC | Repository configuration walkthroughs; no live tenant, workspace or identity-provider session |
| Jupyter | Inventory of all ten executable notebooks; real offline kernel validation recorded in release CI |
| AI models and cache | No-call planning and an explicitly simulated cache contract; no paid provider response or quality claim |
| Scale and validation | Linked release CI and synthetic benchmark observations with their stated scope |

The native backend inventory is **59 parsers + 186 parser plugins + 4 cookie helpers**. These are registrations, not 249 distinct enterprise logs or 249 live collectors. See the [complete Plaso guide](PLASO.md), [validation record](VALIDATION.md), and [benchmark scope](EVALUATION.md).

Synthetic narration uses Kokoro's stock `af_sarah` voice. The [production recipe](../demos/v0.13.0/README.md), [storyboard](../demos/v0.13.0/storyboard.json), and [media workflow](../.github/workflows/demo-video.yml) make the demo maintainable. The final publication is pinned to the reviewed media bytes.
