import subprocess
import logging
import sys
import xmlrpclib
import traceback
from datetime import datetime
import os
import time

from lib.core.config import Config
from lib.core.startup import create_folders, init_logging


class Analyzer:
    def __init__(self):
        self.config = None
        self.target = None

    def prepare(self):
        """Prepare env for analysis."""

        # Create the folders used for storing the results.
        create_folders()

        # Initialize logging.
        init_logging()

        # Parse the analysis configuration file generated by the agent.
        self.config = Config(cfg="analysis.conf")

        # Set virtual machine clock.
        clock = datetime.strptime(self.config.clock, "%Y%m%dT%H:%M:%S")
        # Setting date and time.
        # NOTE: Windows system has only localized commands with date format
        # following localization settings, so these commands for english date
        # format cannot work in other localizations.
        # In addition DATE and TIME commands are blocking if an incorrect
        # syntax is provided, so an echo trick is used to bypass the input
        # request and not block analysis.
        os.system("echo date {0}".format(clock.strftime("%m-%d-%y")))
        os.system("echo time {0}".format(clock.strftime("%H:%M:%S")))


        # We update the target according to its category. If it's a file, then
        # we store the path.
        print self.config.file_name

        if self.config.category == "file":
            self.target = os.path.join('/home/nidzo/tmp', str(self.config.file_name))
        # If it's a URL, well.. we store the URL.
        else:
            self.target = self.config.target

        return self.target

    def start(self, path):
        print path
        print time.sleep(10)
        proc = subprocess.Popen(path)
        print "PID:", proc.pid
        print "Return code:", proc.wait()

        return True

class CuckooPackageError(Exception):
    pass

def run():
    print "Printing inside guest machine"
    # subprocess.call(['sudo', 'sysdig', '-w', '/home/nidzo/trace.scap'])
    subprocess.call(['sudo', 'sysdig'])

if __name__ == "__main__":
    # run()
    success = False
    error = ""
    log = logging.getLogger()

    try:
        analyzer = Analyzer()
        target = analyzer.prepare()
        success = analyzer.start(target)

    # This is not likely to happen.
    except KeyboardInterrupt:
        error = "Keyboard Interrupt"

    # If the analysis process encountered a critical error, it will raise a
    # CuckooError exception, which will force the termination of the analysis.
    # Notify the agent of the failure. Also catch unexpected exceptions.
    except Exception as e:
        # Store the error.
        error_exc = traceback.format_exc()
        error = str(e)

        # Just to be paranoid.
        if len(log.handlers):
            log.exception(error_exc)
        else:
            sys.stderr.write("{0}\n".format(error_exc))

    finally:
        server = xmlrpclib.Server("http://127.0.0.1:8000")
        server.complete(success, error, '/home')