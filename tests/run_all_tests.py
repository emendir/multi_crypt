import os
import importlib
import importlib.util
import sys


def load_module_from_path(path: str):
    """Load a python module from a file or a folder.
    Args:
        path (str): the path of the module file or folder
    Returns:
        module: the imported module
    """
    module_name = os.path.basename(path).strip(".py")
    if os.path.isdir(path):
        path = os.path.join(path, '__init__.py')
    spec = importlib.util.spec_from_file_location(
        module_name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


tests = []  # list of all test modules

# load test modules into the list
for filename in os.listdir("."):
    if not (os.path.isfile(filename) and filename[-3:] == ".py") \
            or filename == os.path.basename(__file__):
        continue

    tests.append(load_module_from_path(filename))

# run all test modules
for test in tests:
    test.run_tests()
    print("")
