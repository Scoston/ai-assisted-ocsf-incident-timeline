"""Execute offline notebook cells; --kernel also verifies the Jupyter kernel transport."""

import argparse
from pathlib import Path

import nbformat

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kernel", action="store_true")
    args = parser.parse_args()
    for path in sorted((ROOT / "notebooks").glob("*.ipynb")):
        notebook = nbformat.read(path, as_version=4)
        nbformat.validate(notebook)
        if args.kernel:
            from nbclient import NotebookClient

            NotebookClient(
                notebook,
                timeout=60,
                startup_timeout=30,
                kernel_name="python3",
                resources={"metadata": {"path": str(ROOT)}},
            ).execute()
        else:
            namespace = {"__name__": "__notebook__"}
            for index, cell in enumerate(notebook.cells):
                if cell.cell_type == "code":
                    exec(compile(cell.source, f"{path.name}:cell{index}", "exec"), namespace)
        print(path.name, "PASS")


if __name__ == "__main__":
    main()
