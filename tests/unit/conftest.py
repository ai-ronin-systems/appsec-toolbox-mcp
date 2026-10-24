"""Load the toolbox scripts, whose file names are not importable module names."""

import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def profiles():
    return _load("run-language-profiles")


@pytest.fixture(scope="session")
def manifest():
    return _load("write-manifest")


@pytest.fixture(scope="session")
def suppressions():
    return _load("find-suppressions")
