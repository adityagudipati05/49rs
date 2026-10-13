"""
tests/conftest.py - Shared pytest fixtures.
"""
import json
import os
import sys
import tempfile

import pytest

# Ensure project root is on path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture(scope="session")
def pipeline_result():
    """Run the full pipeline once per test session."""
    import pipeline
    return pipeline.build_pipeline()


@pytest.fixture(scope="session")
def incidents(pipeline_result):
    return pipeline_result["incidents"]


@pytest.fixture(scope="session")
def unlinked(pipeline_result):
    return pipeline_result["unlinked"]


@pytest.fixture(scope="session")
def stats(pipeline_result):
    return pipeline_result["stats"]


@pytest.fixture
def tmp_db(tmp_path):
    """Create a fresh SQLite DB in a temp directory."""
    import db
    db_path = str(tmp_path / "test.db")
    db.init_db(db_path)
    return db_path
