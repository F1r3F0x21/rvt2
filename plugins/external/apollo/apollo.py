# Copyright (C) DEFION.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

# Inspired by APOLLO (Apple Pattern of Life Lazy Output'er) by Sarah Edwards
# https://github.com/mac4n6/APOLLO

import os
import sqlite3
import importlib.util

MODULES_DIR = os.path.join(os.path.dirname(__file__), "modules")


def load_modules(modules_dir=None):
    """Load all query modules from the modules directory. Returns a list of module objects."""
    if modules_dir is None:
        modules_dir = MODULES_DIR
    modules = []
    for filename in sorted(os.listdir(modules_dir)):
        if filename.endswith(".py") and not filename.startswith("_"):
            path = os.path.join(modules_dir, filename)
            spec = importlib.util.spec_from_file_location(filename[:-3], path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            modules.append(mod)
    return modules


def list_streams(db_path):
    """Return all distinct ZSTREAMNAME values present in the knowledgeC database."""
    with sqlite3.connect(f"file://{db_path}?mode=ro", uri=True) as conn:
        conn.text_factory = str
        c = conn.cursor()
        c.execute("SELECT DISTINCT ZSTREAMNAME FROM ZOBJECT ORDER BY ZSTREAMNAME;")
        return [row[0] for row in c.fetchall()]


def run_module(db_path, module):
    """Run a single APOLLO module query against a knowledgeC database.
    Returns (output_columns, rows) where rows is a list of tuples.
    """
    with sqlite3.connect(f"file://{db_path}?mode=ro", uri=True) as conn:
        conn.text_factory = str
        c = conn.cursor()
        c.execute(module.query)
        return module.output_columns, c.fetchall()


def run_all(db_path, modules_dir=None):
    """Run all modules against a knowledgeC database.
    Yields (module, output_columns, rows_or_exception) for each module.
    """
    for module in load_modules(modules_dir):
        try:
            columns, rows = run_module(db_path, module)
            yield module, columns, rows
        except Exception as exc:
            yield module, [], exc
