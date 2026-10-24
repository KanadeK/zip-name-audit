"""Generate tiny synthetic archives; no contents are ever extracted."""

import argparse
import zipfile
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("output", type=Path)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
for filename, names in {
    "good.zip": ["guide/intro.txt", "guide/setup.txt"],
    "problem.zip": ["Guide/intro.txt", "guide/setup.txt", "NUL.txt", "assets", "assets/icon.txt"],
}.items():
    path = args.output / filename
    with path.open("xb") as stream, zipfile.ZipFile(stream, "w") as archive:
        for name in names:
            archive.writestr(name, "Synthetic sample\n")
    print(path)
