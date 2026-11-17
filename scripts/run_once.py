from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from compass.cli import main


if __name__ == "__main__":
    arguments = list(sys.argv[1:])
    configuration = []
    if "--config" in arguments:
        index = arguments.index("--config")
        configuration = arguments[index:index + 2]
        del arguments[index:index + 2]
    raise SystemExit(main(configuration + ["offline", "run-once"] + arguments))
