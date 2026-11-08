import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
os.environ.setdefault("IAMLENS_WARM", "0")

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


@pytest.fixture(scope="session")
def env():
    from iamlens.model import load_environment

    return load_environment(EXAMPLES)


@pytest.fixture(scope="session")
def graph(env):
    from iamlens.escalation import EscalationGraph

    return EscalationGraph(env)


@pytest.fixture(scope="session")
def findings(env, graph):
    from iamlens.findings import analyze

    return analyze(env, graph)
