"""Produce local synthetic narration with verified, openly licensed Kokoro assets."""

import argparse
import hashlib
import json
from pathlib import Path
import urllib.request

import numpy as np
from kokoro_onnx import Kokoro
import soundfile as sf

ASSETS = {
    "kokoro-v1.0.onnx": "beb0d1848dee9a49da392cc3df26958d46cfa35d321edf434f52949153f0df3a",
    "voices-v1.0.bin": "bca610b8308e8d99f32e6fe4197e7ec01679264efed0cac9140fe9c29f1fbf7d",
}
BASE = "https://github.com/thewh1teagle/kokoro-onnx/releases/download/model-files-v1.1/"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--models", type=Path, default=Path("output/demo-video/models"))
    args = parser.parse_args()
    args.models.mkdir(parents=True, exist_ok=True)
    for name, digest in ASSETS.items():
        path = args.models / name
        if not path.exists():
            temporary = path.with_suffix(".part")
            with urllib.request.urlopen(BASE + name, timeout=60) as response, temporary.open("wb") as f:
                while data := response.read(1024 * 1024):
                    f.write(data)
            if hashlib.sha256(temporary.read_bytes()).hexdigest() != digest:
                raise ValueError("Narration asset checksum mismatch")
            temporary.rename(path)
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError("Narration asset checksum mismatch")
    spec = json.loads(Path("demos/v0.13.0/storyboard.json").read_text())
    output = Path("output/demo-video/audio")
    output.mkdir(parents=True, exist_ok=False)
    engine = Kokoro(str(args.models / "kokoro-v1.0.onnx"), str(args.models / "voices-v1.0.bin"))

    class FloatSpeedSession:
        """Adapt kokoro-onnx 0.4.9's int speed to the pinned model's float input."""

        def __init__(self, session):
            self.session = session
            assert {i.name: i.type for i in session.get_inputs()}["speed"] == "tensor(float)"

        def get_inputs(self):
            return self.session.get_inputs()

        def run(self, names, inputs):
            inputs = {**inputs, "speed": np.array([spec["speed"]], dtype=np.float32)}
            return self.session.run(names, inputs)

    engine.sess = FloatSpeedSession(engine.sess)
    timeline, offset, rate = [], 0.0, 24000
    for scene in spec["scenes"]:
        clips = [np.zeros(int(0.5 * rate), dtype=np.float32)]
        cues, local = [], 0.5
        for sentence in scene["narration"]:
            # Spell technical initialisms for clear narration; captions retain the source text.
            speech = sentence.replace("OCSF", "O C S F").replace("JSON", "jay son")
            speech = speech.replace("CSV", "C S V").replace("Ed25519", "Ed two five five one nine")
            speech = speech.replace("CodeQL", "Code Q L")
            samples, sample_rate = engine.create(speech, voice=spec["voice"], speed=spec["speed"], lang="en-us")
            assert sample_rate == rate and len(samples) > 0 and np.isfinite(samples).all()
            duration = len(samples) / rate
            cues.append({"start": round(offset + local, 3), "end": round(offset + local + duration, 3),
                         "text": sentence})
            clips.extend([samples, np.zeros(int(0.25 * rate), dtype=np.float32)])
            local += duration + 0.25
        clips.append(np.zeros(int(0.75 * rate), dtype=np.float32))
        audio = np.concatenate(clips)
        sf.write(output / (scene["id"] + ".wav"), audio, rate, subtype="PCM_16")
        duration = len(audio) / rate
        timeline.append({"id": scene["id"], "title": scene["title"], "start": round(offset, 3),
                         "duration": round(duration, 3), "cues": cues})
        offset += duration
        print(scene["id"], round(duration, 2), "seconds", flush=True)
    (output / "timing.json").write_text(json.dumps(timeline, indent=2) + "\n")
    print("Total seconds:", round(offset, 3))


if __name__ == "__main__":
    main()
