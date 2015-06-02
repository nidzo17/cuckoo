# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os


ROOT = os.environ['HOME']

PATHS = {"root": ROOT,
         "temp": os.path.join(ROOT, "tmp"),
         "logs": os.path.join(ROOT, "logs"),
         "files": os.path.join(ROOT, "files"),
         "shots": os.path.join(ROOT, "shots"),
         "memory": os.path.join(ROOT, "memory"),
         "drop": os.path.join(ROOT, "drop")}
