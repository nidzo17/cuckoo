import os

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError


class LinuxModule(Processing):

    def run(self):
        self.key = "linux"
        results = {}
        log_file = os.path.join(self.analysis_path, 'logs', 'linux.log')

        if not os.path.exists(log_file):
            raise CuckooProcessingError("Sample file doesn't exist: \"%s\"" % log_file)

        with open(log_file, "r") as linux_log:
            for line in linux_log:
                if '->' in line:
                    self.add_to_dict(results, 'ip_address', line)
                else:
                    self.add_to_dict(results, 'dependencies', line)
            return results

    @staticmethod
    def add_to_dict(name, key, value):
        if key in name:
            name[key].append(value)
        else:
            name[key] = [value]
