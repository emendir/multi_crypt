"""Script for configuring tests.

Runs automatically when pytest runs a test before loading the test module.
"""

import logging
import os

import pytest
from emtest import (
    add_path_to_python,
    are_we_in_docker,
    assert_is_loaded_from_source,
    configure_pytest_reporter,
    set_env_var,
)
from loguru import logger

PRINT_ERRORS = True  # whether or not to print error messages after failed tests

WORKDIR = os.path.dirname(os.path.abspath(__file__))
PROJ_DIR = os.path.dirname(WORKDIR)
SRC_DIR = os.path.join(PROJ_DIR, "src")

os.chdir(WORKDIR)

# add source code paths to python's search paths
add_path_to_python(SRC_DIR)


@pytest.hookimpl(trylast=True)
def pytest_configure(config):
    """Make changes to pytest's behaviour."""
    configure_pytest_reporter(config, print_errors=PRINT_ERRORS)
