"""Various helper functions"""
import os
import sys
import importlib


def to_bytearray(data, variable_name: str = "Value"):
    """Convert the input data from bytes or hex-string to bytearray,
    raising an error if it has the wrong type.
    Parameters:
        data: the data to convert
        variable_name (str): for error message
    """

    if isinstance(data, bytearray):
        return data
    if isinstance(data, bytes):
        return bytearray(data)
    if isinstance(data, str):
        return bytearray.fromhex(data)
    raise ValueError((
        f"{variable_name} must be of type bytearray, bytes, or str, not "
        f"{type(data)}"
    ))


def load_module_from_path(path: str):
    """Load a python module from a file or a folder.
    Parameters:
        path (str): the path of the module file or folder
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
