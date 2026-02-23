# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""Template loading utilities using importlib.resources for Python 3.8+ compatibility."""

import sys

if sys.version_info >= (3, 9):
    from importlib.resources import files
else:
    from importlib.resources import read_text

from ghas_cli import templates


def load_template(template_name: str) -> str:
    """Load a template file by name.

    Args:
        template_name: The filename of the template (e.g., 'codeql.md')

    Returns:
        The content of the template file as a string.
    """
    if sys.version_info >= (3, 9):
        return files(templates).joinpath(template_name).read_text(encoding="utf-8")
    else:
        return read_text(templates, template_name)
