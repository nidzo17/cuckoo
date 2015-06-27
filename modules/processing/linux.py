import os

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError


class LinuxModule(Processing):

    def run(self):
        self.key = "linux"
        fajl = os.path.join(self.analysis_path, 'logs', 'hablo')

        if not os.path.exists(fajl):
            raise CuckooProcessingError("Sample file doesn't exist: \"%s\"" % fajl)
        try:
            data = open(fajl, "r").read()
        except (IOError, OSError) as e:
            raise CuckooProcessingError("Error opening file %s" % e)

        return [data]
