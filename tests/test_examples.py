import pathlib
import runpy
import sys

import pytest

# Add project root to path so examples can import the library if not installed
PROJECT_ROOT = pathlib.Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

examples_dir = PROJECT_ROOT / "examples"


def test_example_runs(subtests) -> None:
    """
    Ensures that every example script in the examples directory runs without error.
    """
    example_files = list(examples_dir.glob("*.py"))

    for example_file in example_files:
        with subtests.test(path=example_file.name):
            try:
                runpy.run_path(str(example_file), run_name="__main__")
            except Exception as e:
                pytest.fail(f"Example {example_file.name} failed to run: {e}")
