"""Module registry — auto-discovers every Module subclass in this package.

Drop a new ``*.py`` file here with a ``Module`` subclass and it's instantly
available to the pipeline and the ``modules`` command. No registration needed.
"""
from __future__ import annotations

import importlib
import inspect
import pkgutil

from wstrike.modules.base import Module


def discover() -> list[type[Module]]:
    found: list[type[Module]] = []
    for mod_info in pkgutil.iter_modules(__path__):
        if mod_info.name == "base":
            continue
        module = importlib.import_module(f"{__name__}.{mod_info.name}")
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, Module) and obj is not Module and obj.__module__ == module.__name__:
                found.append(obj)
    return found
