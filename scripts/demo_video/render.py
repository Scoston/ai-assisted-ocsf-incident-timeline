"""Render the feature tour from recorded results, real UI capture and narration."""

import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import subprocess
import textwrap

from PIL import Image, ImageDraw, ImageFont

ROOT = Path("output/demo-video")
W, H = 1920, 1080
BG, PANEL, LINE = "#081522", "#112538", "#294358"
WHITE, MUTED, MINT, BLUE, AMBER = "#f2f7fc", "#a9bdcd", "#49e4bc", "#75bfff", "#ffc681"
FONT = Path("/usr/share/fonts/truetype/dejavu")


def font(size, bold=False, mono=False):
    name = "DejaVuSansMono" if mono else "DejaVuSans"
    return ImageFont.truetype(str(FONT / (name + ("-Bold" if bold else "") + ".ttf")), size)


def text(draw, xy, value, size=30, color=WHITE, bold=False, mono=False):
    draw.text(xy, str(value), font=font(size, bold, mono), fill=color)


def paragraph(draw, xy, value, width, size=30, color=MUTED, gap=12, bold=False):
    x, y = xy
    words, line = value.split(), ""
    for word in words:
        trial = (line + " " + word).strip()
        if draw.textlength(trial, font=font(size, bold)) > width:
            text(draw, (x, y), line, size, color, bold)
            y += size + gap
            line = word
        else:
            line = trial
    if line:
        text(draw, (x, y), line, size, color, bold)
        y += size + gap
    return y


def card(draw, box, label, body, accent=MINT, title_size=34):
    x, y, right, bottom = box
    draw.rounded_rectangle(box, 20, fill=PANEL, outline=LINE, width=2)
    draw.rounded_rectangle((x + 24, y + 30, x + 30, bottom - 30), 3, fill=accent)
    text(draw, (x + 56, y + 32), label, title_size, WHITE, True)
    end = paragraph(draw, (x + 56, y + 96), body, right - x - 94, 28)
    if end > bottom - 12:
        raise ValueError("Card text overflows: " + label)


def base(scene, index, total):
    im = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(im)
    for x in range(0, W, 96):
        d.line((x, 0, x, 940), fill="#0d1d2c")
    for y in range(0, 940, 96):
        d.line((0, y, W, y), fill="#0d1d2c")
    d.ellipse((86, 50, 105, 69), fill=MINT)
    text(d, (119, 43), "TIMELINE  /  EVIDENCE TO INSIGHT", 24, WHITE, True)
    d.rounded_rectangle((1570, 36, 1834, 85), 24, outline=LINE, width=2, fill=PANEL)
    text(d, (1610, 45), "v0.13.0  /  DEMO", 24, MINT, True)
    text(d, (86, 115), scene["kicker"], 24, MINT, True)
    if scene["kind"] not in {"hero", "close"}:
        text(d, (86, 153), scene["title"], 52, WHITE, True)
    text(d, (86, 928), scene["source"], 20, MUTED)
    d.rectangle((0, 969, W, H), fill="#050d15")
    for n in range(total):
        x = 86 + n * 88
        d.rounded_rectangle((x, 904, x + 70, 908), 2, fill=MINT if n <= index else LINE)
    return im, d


def terminal(draw, lines, stat, label, notes):
    size = 112
    while draw.textlength(stat, font=font(size, bold=True)) > 480:
        size -= 1
    text(draw, (86, 268), stat, size, MINT, True)
    y = paragraph(draw, (90, 410), label, 455, 32, WHITE, bold=True)
    for note in notes:
        y += 25
        draw.ellipse((92, y + 13, 102, y + 23), fill=MINT)
        y = paragraph(draw, (119, y), note, 420, 27)
    if y > 874:
        raise ValueError("Terminal side notes overflow")
    draw.rounded_rectangle((620, 253, 1834, 873), 20, fill="#060f19", outline=LINE, width=2)
    for n, color in enumerate(("#ff897e", AMBER, MINT)):
        draw.ellipse((650 + n * 27, 278, 664 + n * 27, 292), fill=color)
    text(draw, (753, 270), "RECORDED RESULTS  /  SYNTHETIC EVIDENCE", 21, MUTED)
    draw.line((621, 314, 1832, 314), fill=LINE, width=2)
    y = 340
    for line in lines:
        color = MINT if line.startswith("$") else AMBER if line.startswith("!") else MUTED if line.startswith("#") else WHITE
        if draw.textlength(line, font=font(25, mono=True)) > 1138:
            raise ValueError("Terminal line too long: " + line)
        text(draw, (655, y), line, 25, color, mono=True)
        y += 37
    if y > 862:
        raise ValueError("Terminal result overflows")


def frame(scene, index, total, data):
    im, d = base(scene, index, total)
    kind = scene["kind"]
    if kind in {"hero", "close"}:
        text(d, (86, 230), "Follow the", 108, WHITE, True)
        text(d, (86, 359), "evidence.", 108, MINT, True)
        paragraph(d, (92, 510), "AI-assisted OCSF incident timeline", 1300, 41, WHITE)
        if kind == "hero":
            paragraph(d, (92, 575), "Cloud. Identity. Endpoint. Native forensic artifacts.", 1600, 30)
            for n, (value, label) in enumerate((("28", "parser contracts"), ("19", "collectors"), ("10", "notebooks"), ("0", "offline model tokens"))):
                x = 90 + n * 435
                d.rounded_rectangle((x, 685, x + 410, 865), 16, fill=PANEL, outline=LINE, width=2)
                text(d, (x + 28, 700), value, 70, MINT, True)
                text(d, (x + 28, 799), label, 27, WHITE)
        else:
            text(d, (92, 599), "README  →  Synthetic case  →  First notebook", 35, MINT, True)
            paragraph(d, (92, 702), "github.com/Scoston/", 1700, 34, MUTED)
            text(d, (92, 758), "ai-assisted-ocsf-incident-timeline", 42, WHITE, True)
    elif kind == "terminal":
        by_id = {
            "ingest": (["$ timeline ingest ... --parquet", "", '# Selected manifest fields',
                        'case_id:              "demo-013"', 'source_records:       5', 'event_count:          5',
                        'quarantined_records:  0', 'duplicate_events:     0', '',
                        'evidence/  timeline.jsonl  timeline.csv', 'timeline.parquet  receipts.jsonl  audit_manifest.json'],
                       "5", "events, three sources", ["UTC ordering and deterministic event IDs", "Original evidence preserved", "JSONL, CSV and Parquet"]),
            "integrity": (["$ timeline verify results/bundle", "verified: true", "", '# Alter a temporary copy, then verify it',
                           '$ timeline verify <temporary altered copy>', "! " + data["tamper_error"][:72], "",
                           '# The original bundle is unchanged', 'Strict ingestion: fail on invalid records',
                           'Explicit --quarantine: retain rejection receipts'],
                          "SHA-256", "integrity before interpretation", ["Manifest covers every artifact", "Record hashes retain parser provenance", "Authenticity is assessed separately"]),
            "developer": (["# Executed fixtures: developer incident notebook", "", 'source:    github_audit', 'activity:  repo.access',
                           'class:     6003', '', 'source:    kubernetes_audit', 'activity:  list', 'class:     6003', '',
                           '# Synthetic Kubernetes source: response code 403', '# Request: /api/v1/namespaces/payments/secrets'],
                          "2", "developer audit contracts", ["GitHub audit collection and import", "Kubernetes audit export import", "Source evidence stays attached"]),
            "ocsf": (["$ timeline export-ocsf results/bundle --output results/ocsf", "", 'ocsf_version:     "1.3.0"',
                      'source_events:   5', 'exported_events: 5', 'rejected_events: 0', 'model_tokens:    0', "",
                      '$ timeline verify-ocsf results/ocsf --bundle results/bundle', 'Source binding + file hashes + event schemas: verified'],
                     "9", "pinned core event classes", ["Separate validated OCSF export", "Strict or explicit quarantine mode", "Verified binding to the source bundle"]),
            "signing": (["# Executed signer lifecycle", "", 'sign_artifact(bundle, ...)       → signed',
                         'verify_signature(bundle, ...)   → active', '', 'retire signer; verify again     → verify_only',
                         'revoke signer; verify again:', '! ' + data["signing"]["revoked_error"], '',
                         'source manifest unchanged: true', '# Temporary encrypted demo key; never published'],
                        "Ed25519", "detached signatures", ["Independent trust-policy pins", "Retirement and revocation", "Evidence remains immutable"]),
            "tokens": (["$ timeline analyze results/bundle --task summarize", "", 'status:             "planned"',
                        'model:              "gpt-5.6-luna"', 'covered / omitted:  5 / 0',
                        f'input_token_bound:  {data["plan"]["input_token_bound"]}',
                        f'reserved_tokens:    {data["plan"]["reserved_tokens"]}', '',
                        '# Cache contract: OFFLINE TEST DOUBLE', 'provider calls after two identical runs: 1',
                        'cache_hit: true     repeat tokens: 0', '# No paid model request made in this demo'],
                       "0", "tokens for the offline plan", ["Coverage visible before dispatch", "24,000 tokens / 3 calls per case", "No automatic escalation or per-event calls"]),
            "recovery": (["# Simulated source; actual SQLite checkpoint store", "collection paused: page budget reached", "",
                          'backup → pinned snapshot → restore', 'remaining pages fetched: 1', '',
                          'timeline_collection_healthy 1', 'timeline_collection_pages 2',
                          'timeline_collection_pending_runs 0', 'timeline_collection_published_runs 1', '',
                          'verified health: healthy     model_tokens: 0'],
                         "1", "remaining page fetched", ["Resume committed checkpoints", "Pin and verify recovery snapshots", "Health reports and Prometheus metrics"]),
        }
        terminal(d, *by_id[scene["id"]])
    elif kind == "viewer":
        d.rounded_rectangle((150, 219, 1770, 883), 18, fill=PANEL, outline=LINE, width=2)
        text(d, (160, 225), "ACTUAL VIEWER  /  Recorded interaction with the bundled synthetic case", 23, MUTED)
        # The actual captured browser video is composited here by FFmpeg.
    elif kind == "provenance":
        event = json.loads((ROOT / "results/bundle/timeline.jsonl").read_text().splitlines()[0])
        card(d, (86, 255, 569, 536), "Source context", "Original timestamp, explicit time-zone assumptions, parser and mapping versions.")
        card(d, (86, 566, 569, 869), "IOC candidates", "Addresses, domains and hashes support investigation. An extracted indicator needs context.", BLUE)
        d.rounded_rectangle((608, 255, 1834, 869), 20, fill="#060f19", outline=LINE, width=2)
        text(d, (644, 287), "ACTUAL EVENT  /  Selected fields", 25, MINT, True)
        y = 352
        for key in ("activity_name", "original_timestamp", "parser_name", "parser_version", "evidence_path", "raw_file_hash", "raw_data_hash"):
            text(d, (644, y), key, 23, MUTED, mono=True)
            value = str(event[key])
            if key == "evidence_path":
                value = "evidence/" + value.split("/")[-1][:22] + "…json"
            text(d, (644, y + 30), value, 23, WHITE, mono=True)
            y += 69
    elif kind == "collectors":
        names = data["collectors"]
        for n, name in enumerate(names):
            col, row = n // 7, n % 7
            x, y = 86 + col * 588, 270 + row * 72
            d.rounded_rectangle((x, y, x + 564, y + 59), 10, fill=PANEL, outline=LINE)
            d.ellipse((x + 22, y + 24, x + 31, y + 33), fill=MINT)
            text(d, (x + 51, y + 13), name, 27, WHITE, mono=True)
        text(d, (90, 817), "Fixed windows  ·  Raw response receipts  ·  Checkpoints  ·  Overlap  ·  Source inventory", 28, MINT)
    elif kind == "plaso":
        counts = Counter(e["kind"] for e in data["plaso"]["entries"])
        assert counts == {"parser": 59, "plugin": 186, "cookie_plugin": 4}
        for n, (value, label) in enumerate(((59, "parsers"), (186, "parser plugins"), (4, "cookie plugins"))):
            x = 86 + n * 588
            d.rounded_rectangle((x, 278, x + 558, 556), 18, fill=PANEL, outline=LINE, width=2)
            text(d, (x + 33, 303), value, 116, MINT, True)
            text(d, (x + 37, 469), label, 37, WHITE, True)
        paragraph(d, (92, 612), "EVTX · Registry · Prefetch · Browser history · SQLite · systemd · ESXi · archives", 1680, 33, WHITE)
        paragraph(d, (92, 725), "Pinned upstream source + format inventory + runtime registration checks", 1700, 31, MINT)
        text(d, (92, 815), "Registration counts describe the pinned release. They are not counts of live collectors.", 26, MUTED)
    elif kind == "native":
        card(d, (86, 260, 935, 512), "Acquired artifacts & images", "Read-only source snapshots; partitions, archives and supported storage round trips.")
        card(d, (965, 260, 1834, 512), "Pinned execution", "Source and dependency hashes, isolated Docker runtime, processing limits and receipts.")
        text(d, (96, 565), "RECORDED RELEASE VALIDATION", 25, MINT, True)
        for n, (value, label) in enumerate((("14,991", "source records"), ("14,988", "timeline events"), ("3", "quarantined"), ("37", "image/archive events"))):
            x = 92 + n * 438
            text(d, (x, 628), value, 73, WHITE, True)
            text(d, (x, 733), label, 27, MUTED)
        text(d, (96, 823), "Upstream native fixtures in CI; source evidence retained for quarantined records.", 26, MINT)
    elif kind in {"tines", "databricks", "access"}:
        contents = {
            "tines": [("Publish & monitor", "Receive bundle → Validate contract → Submit job", MINT),
                      ("Bounded polling", "Track status, failures and timeouts. Preserve asynchronous receipts.", BLUE),
                      ("Inspect an existing run", "Receive run → Validate run → Read existing run → Status receipt", BLUE),
                      ("Tenant activation", "Import the two disabled stories, configure resources and credentials, then test acceptance.", AMBER)],
            "databricks": [("01  Unity Catalog Volumes", "Upload and download verified bundles. Publish the manifest last.", MINT),
                           ("02  Databricks Jobs", "Submit with stable idempotency keys. Poll and inspect the run.", BLUE),
                           ("03  Delta publication", "Insert-only event records, final publication markers and committed views.", BLUE),
                           ("04  Verified round trip", "Bind downloaded artifacts to expected hashes. Configure grants and signer policy.", AMBER)],
            "access": [("Local viewer", "Loopback binding and integrity verification before display.", MINT),
                       ("Shared access", "OpenID Connect and explicit case assignments. Audit allowed and denied access.", BLUE),
                       ("Trusted evidence", "Pinned manifests and signer policies. Required trusted signatures in shared mode.", BLUE),
                       ("Deployment acceptance", "Test identity, grants, case isolation, retention and recovery in your environment.", AMBER)],
        }[kind]
        for n, (label, body, accent) in enumerate(contents):
            x, y = 86 + (n % 2) * 879, 265 + (n // 2) * 295
            card(d, (x, y, x + 849, y + 270), label, body, accent, 33)
    elif kind == "notebooks":
        labels = ["Offline investigation", "Databricks integration", "AI harness", "Validated OCSF export", "Evaluation", "Signed manifests", "Enterprise collection", "Operations & recovery", "Developer incidents", "Plaso coverage"]
        for n, label in enumerate(labels):
            col, row = n // 5, n % 5
            x, y = 86 + col * 880, 258 + row * 108
            d.rounded_rectangle((x, y, x + 845, y + 90), 14, fill=PANEL, outline=LINE, width=2)
            text(d, (x + 24, y + 22), f"{n+1:02}", 35, MINT, True, mono=True)
            text(d, (x + 108, y + 26), label, 31, WHITE, True)
        text(d, (94, 829), "$ jupyter lab notebooks/", 31, MINT, mono=True)
        text(d, (955, 831), "Live connections disabled by default", 28, MUTED)
    elif kind == "models":
        columns = (116, 478, 1070, 1365, 1620)
        headers = ("TASK", "MODEL", "INPUT MAX", "OUTPUT MAX", "EFFORT")
        d.rounded_rectangle((86, 270, 1834, 743), 18, fill=PANEL, outline=LINE, width=2)
        for x, label in zip(columns, headers):
            text(d, (x, 304), label, 23, MUTED, True)
        for n, (task, cfg) in enumerate(data["models"]["tasks"].items()):
            y = 385 + n * 110
            d.line((110, y - 22, 1810, y - 22), fill=LINE, width=1)
            for x, value in zip(columns, (task, cfg["model"], f'{cfg["max_input_tokens"]:,}', f'{cfg["max_output_tokens"]:,}', cfg["reasoning_effort"])):
                text(d, (x, y), value, 30, MINT if x == 478 else WHITE, mono=x == 478)
        text(d, (97, 796), "Case ceiling: 24,000 tokens / 3 calls   ·   Explicit tasks   ·   No automatic escalation", 29, MINT)
        text(d, (98, 850), "These are configured routes and limits, not measured model quality or actual token counts.", 25, MUTED)
    elif kind == "validation":
        for n, (label, body) in enumerate((("864", "project tests passed*"), ("637", "upstream parser tests"), ("10", "Jupyter notebooks"))):
            x = 86 + n * 588
            d.rounded_rectangle((x, 265, x + 558, 508), 18, fill=PANEL, outline=LINE, width=2)
            text(d, (x + 34, 286), label, 95, MINT, True)
            text(d, (x + 35, 427), body, 30, WHITE)
        paragraph(d, (94, 558), "100,000 unique synthetic events: about 20 seconds to ingest", 1700, 38, WHITE, bold=True)
        paragraph(d, (94, 640), "Historical measurement on the recorded host; no production capacity guarantee. Live tenant and model quality acceptance remain separate.", 1660, 30)
        text(d, (96, 779), "Spark/Delta replay  ·  Dependency audits  ·  CodeQL  ·  Main-build attestations", 29, MINT)
        text(d, (96, 842), "*Release baseline; the real Delta test runs in its own CI job. See the linked validation records.", 23, MUTED)
    else:
        raise ValueError("Unknown scene " + kind)
    return im


def timestamp(seconds, separator=","):
    milliseconds = round(seconds * 1000)
    seconds, ms = divmod(milliseconds, 1000)
    minutes, sec = divmod(seconds, 60)
    hours, minute = divmod(minutes, 60)
    return f"{hours:02}:{minute:02}:{sec:02}{separator}{ms:03}"


def ass_time(seconds):
    centiseconds = round(seconds * 100)
    minutes, cs = divmod(centiseconds, 6000)
    hours, minute = divmod(minutes, 60)
    sec, fraction = divmod(cs, 100)
    return f"{hours}:{minute:02}:{sec:02}.{fraction:02}"


def subtitles(timing, offset=0):
    header = """[Script Info]
ScriptType: v4.00+
PlayResX: 1920
PlayResY: 1080
WrapStyle: 0
[V4+ Styles]
Format: Name, Fontname, Fontsize, PrimaryColour, SecondaryColour, OutlineColour, BackColour, Bold, Italic, Underline, StrikeOut, ScaleX, ScaleY, Spacing, Angle, BorderStyle, Outline, Shadow, Alignment, MarginL, MarginR, MarginV, Encoding
Style: Default,DejaVu Sans,30,&H00FFFFFF,&H00FFFFFF,&H00050D15,&H00050D15,0,0,0,0,100,100,0,0,1,2,0,2,120,120,28,1
[Events]
Format: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text
"""
    for cue in timing:
        value = r"\N".join(textwrap.wrap(cue["text"], 103))
        header += f'Dialogue: 0,{ass_time(cue["start"]-offset)},{ass_time(cue["end"]-offset)},Default,,0,0,0,,{value}\n'
    return header


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--frames-only", action="store_true")
    args = parser.parse_args()
    spec = json.loads(Path("demos/v0.13.0/storyboard.json").read_text())
    data = json.loads((ROOT / "results/recordings.json").read_text())
    timing = json.loads((ROOT / "audio/timing.json").read_text())
    frames, segments, deliver = (ROOT / p for p in ("frames", "segments", "deliverables"))
    for directory in (frames, segments, deliver):
        directory.mkdir(parents=True, exist_ok=True)
    stem = "timeline-v0.13.0-demo"
    cues = [cue for entry in timing for cue in entry["cues"]]
    for index, (scene, entry) in enumerate(zip(spec["scenes"], timing, strict=True)):
        assert scene["id"] == entry["id"]
        im = frame(scene, index, len(timing), data)
        path = frames / (scene["id"] + ".png")
        im.save(path)
        if index == 0:
            im.save(deliver / (stem + "-poster.png"))
        ass = frames / (scene["id"] + ".ass")
        ass.write_text(subtitles(entry["cues"], entry["start"]))
        if args.frames_only:
            continue
        destination = segments / (scene["id"] + ".mp4")
        if destination.exists():
            raise FileExistsError("Use a new or empty segments directory for a fresh render")
        duration = entry["duration"]
        command = ["ffmpeg", "-hide_banner", "-loglevel", "error", "-loop", "1", "-framerate", "30", "-i", str(path)]
        filters = f"subtitles={ass},fade=t=in:st=0:d=0.25,fade=t=out:st={duration-0.25}:d=0.25"
        if scene["id"] == "viewer":
            command += ["-ss", "3", "-i", str(ROOT / "capture/viewer.webm"), "-i", str(ROOT / "audio/viewer.wav")]
            command += ["-filter_complex", f"[1:v]crop=1600:610:0:100[ui];[0:v][ui]overlay=160:270:eof_action=repeat,{filters}[v]", "-map", "[v]", "-map", "2:a"]
        else:
            command += ["-i", str(ROOT / "audio" / (scene["id"] + ".wav")), "-vf", filters]
        command += ["-t", str(duration), "-c:v", "libx264", "-preset", "fast", "-crf", "22", "-pix_fmt", "yuv420p",
                    "-r", "30", "-af", "loudnorm=I=-16:TP=-1.5:LRA=11", "-c:a", "aac", "-b:a", "160k",
                    "-ar", "48000", "-ac", "2", "-movflags", "+faststart", str(destination)]
        subprocess.run(command, check=True, timeout=300)
        print("Rendered", scene["id"], flush=True)
    if args.frames_only:
        return
    srt = "\n".join(f'{n}\n{timestamp(c["start"])} --> {timestamp(c["end"])}\n{c["text"]}\n' for n, c in enumerate(cues, 1))
    (deliver / (stem + ".srt")).write_text(srt)
    vtt = "WEBVTT\n\n" + "\n".join(f'{timestamp(c["start"], ".")} --> {timestamp(c["end"], ".")}\n{c["text"]}\n' for c in cues)
    (deliver / (stem + ".vtt")).write_text(vtt)
    transcript, chapters = ["# v0.13.0 narrated feature demo\n", "Synthetic narration (Kokoro af_sarah); synthetic evidence only.\n"], []
    metadata = [";FFMETADATA1", "title=AI-assisted OCSF incident timeline — v0.13.0 feature demo", "artist=Scoston", "comment=Synthetic evidence and synthetic narration; see transcript for scope."]
    for entry in timing:
        stamp = timestamp(entry["start"], ".").split(".")[0]
        chapters.append(f'{stamp} {entry["title"]}')
        transcript.extend([f'\n## {stamp} — {entry["title"]}\n', " ".join(c["text"] for c in entry["cues"]) + "\n"])
        metadata += ["[CHAPTER]", "TIMEBASE=1/1000", f'START={round(entry["start"]*1000)}',
                     f'END={round((entry["start"]+entry["duration"])*1000)}', "title=" + entry["title"]]
    (deliver / (stem + "-transcript.md")).write_text("\n".join(transcript))
    (deliver / (stem + "-chapters.txt")).write_text("\n".join(chapters) + "\n")
    meta = ROOT / "chapters.ffmeta"
    meta.write_text("\n".join(metadata) + "\n")
    concat = ROOT / "segments.txt"
    concat.write_text("".join(f"file '{(segments/(s['id']+'.mp4')).resolve()}'\n" for s in timing))
    target = deliver / (stem + ".mp4")
    subprocess.run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", str(concat),
                    "-i", str(meta), "-i", str(deliver/(stem+".srt")), "-map", "0:v", "-map", "0:a", "-map", "2:s",
                    "-map_metadata", "1", "-map_chapters", "1", "-c", "copy", "-c:s", "mov_text", "-metadata:s:s:0", "language=eng",
                    "-disposition:s:0", "0", "-movflags", "+faststart", str(target)], check=True, timeout=180)
    probe = json.loads(subprocess.check_output(["ffprobe", "-v", "error", "-show_streams", "-show_format", "-show_chapters", "-of", "json", str(target)]))
    video = next(s for s in probe["streams"] if s["codec_type"] == "video")
    assert video["width"] == W and video["height"] == H and video["codec_name"] == "h264"
    assert len(probe["chapters"]) == len(timing)
    expected_duration = sum(s["duration"] for s in timing)
    assert math.isclose(float(probe["format"]["duration"]), expected_duration, abs_tol=1.0)
    evidence = {
        "version": "1.0", "feature_base_commit": data["feature_base_commit"], "build_commit": data["build_commit"],
        "duration_seconds": float(probe["format"]["duration"]), "width": W, "height": H,
        "chapters": len(timing), "caption_cues": len(cues), "synthetic_evidence": True,
        "synthetic_narration": "Kokoro ONNX af_sarah", "live_cloud_connections": False, "paid_model_calls": 0,
        "storyboard_sha256": hashlib.sha256(Path("demos/v0.13.0/storyboard.json").read_bytes()).hexdigest(),
        "recordings_sha256": hashlib.sha256((ROOT/"results/recordings.json").read_bytes()).hexdigest(),
    }
    (deliver / (stem + "-provenance.json")).write_text(json.dumps(evidence, indent=2) + "\n")
    (deliver / "SHA256SUMS").write_text("".join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in sorted(deliver.iterdir()) if p.name != "SHA256SUMS"))
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
