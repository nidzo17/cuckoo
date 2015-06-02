import subprocess
import logging
import sys
import xmlrpclib
import traceback
from datetime import datetime
import os
import time
import pkgutil
import hashlib
import random
import socket
import signal
import tempfile

from lib.common.constants import PATHS
from lib.core.config import Config
from lib.core.startup import create_folders, init_logging
from lib.common.abstracts import Auxiliary
from lib.common.hashing import hash_file
from modules import auxiliary
from lib.common.results import upload_to_host, NetlogHandler


log = logging.getLogger()
FILES_LIST = []
DUMPED_LIST = []
PROCESS_LIST = []


class CuckooPackageError(Exception):
    pass


def test_run():
    print "Printing inside guest machine"
    # subprocess.call(['sudo', 'sysdig', '-w', '/home/nidzo/trace.scap'])
    subprocess.call(['sudo', 'sysdig'])


def add_pid(pid):
    """Add a process to process list."""
    if isinstance(pid, (int, long, str)):
        log.info("Added new process to list with pid: %s", pid)
        PROCESS_LIST.append(int(pid))


def add_pids(pids):
    """Add PID."""
    if isinstance(pids, (tuple, list)):
        for pid in pids:
            add_pid(pid)
    else:
        add_pid(pids)


def is_process_alive(pid):
    """ Check For the existence of a unix pid. """
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    else:
        return True


def dump_file(file_path):
    """Create a copy of the given file path."""
    try:
        if os.path.exists(file_path):
            sha256 = hash_file(hashlib.sha256, file_path)
            if sha256 in DUMPED_LIST:
                # The file was already dumped, just skip.
                return
        else:
            log.warning("File at path \"%s\" does not exist, skip.",
                        file_path)
            return
    except IOError as e:
        log.warning("Unable to access file at path \"%s\": %s", file_path, e)
        return

    # Check if the path has a valid file name, otherwise it's a directory
    # and we should abort the dump.
    if file_path:
        # Should be able to extract Alternate Data Streams names too.
        file_name = file_path[file_path.find(":") + 1:]
    else:
        return

    upload_path = os.path.join("files",
                               str(random.randint(100000000, 9999999999)),
                               file_name)
    try:
        upload_to_host(file_path, upload_path)
        DUMPED_LIST.append(sha256)
    except (IOError, socket.error) as e:
        log.error("Unable to upload dropped file at path \"%s\": %s",
                  file_path, e)


def dump_files():
    """Dump all the dropped files."""
    for file_path in FILES_LIST:
        dump_file(file_path)


def terminate_process(pid):
    os.kill(pid, signal.SIGKILL)  # or signal.SIGQUIT


class SysdigParser:
    def __init__(self):
        pass

    def process(self, thread_tid, evt_type, evt_args):
        if evt_type == 'open' or evt_type == 'creat':
            # dump_file(file_path)
            print "=====> dump_file ", evt_args


class Analyzer:
    def __init__(self):
        self.config = None
        self.target = None
        self.pids = []

    def set_pids(self, pids):
        """Update list of monitored PIDs in the package context.
        @param pids: list of pids.
        """
        self.pids = pids

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
        subprocess.call(['echo', 'date', clock.strftime("%m-%d-%y")])
        subprocess.call(['echo', 'time', clock.strftime("%H:%M:%S")])

        # We update the target according to its category. If it's a file, then
        # we store the path.

        print self.config.file_name

        if self.config.category == "file":
            # self.target = os.path.join(tempfile.gettempdir(), str(self.config.file_name))
            self.target = os.path.join('/tmp', str(self.config.file_name))
            # self.target = os.path.join(PATHS["temp"], str(self.config.file_name))


        # If it's a URL, well.. we store the URL.
        else:
            self.target = self.config.target

    def complete(self):
        """End analysis."""
        # Dump all the notified files.
        dump_files()

        # Hell yeah.
        log.info("Analysis completed.")

    def run_auxiliary(self):
        # Initialize Auxiliary modules
        Auxiliary()
        prefix = auxiliary.__name__ + "."
        for loader, name, ispkg in pkgutil.iter_modules(auxiliary.__path__, prefix):
            if ispkg:
                continue
            # Import the auxiliary module.
            try:
                __import__(name, globals(), locals(), ["dummy"], -1)
            except ImportError as e:
                log.warning("Unable to import the auxiliary module "
                            "\"%s\": %s", name, e)

        # Walk through the available auxiliary modules.
        aux_enabled, aux_avail = [], []
        for module in Auxiliary.__subclasses__():
            # Try to start the auxiliary module.
            try:
                aux = module(self.config.get_options())
                aux_avail.append(aux)
                aux.start()
                print "SCREENSHOT!"
            except (NotImplementedError, AttributeError):
                log.warning("Auxiliary module %s was not implemented",
                            aux.__class__.__name__)
                continue
            except Exception as e:
                log.warning("Cannot execute auxiliary module %s: %s",
                            aux.__class__.__name__, e)
                continue
            finally:
                log.debug("Started auxiliary module %s",
                          aux.__class__.__name__)
                aux_enabled.append(aux)

        return aux_enabled, aux_avail

    def start(self, path):
        print path
        time.sleep(2)
        os.chmod(path, 0755)
        proc = subprocess.Popen(['/bin/bash', '-c', path])
        # proc = subprocess.Popen([sys.executable, path])
        # proc = subprocess.Popen(path, shell=True)  # security holes

        print "PID:", proc.pid
        # print "Return code:", proc.wait()

        return proc.pid


    def execute(self, pid):
        parser = SysdigParser()
        sysdig_monitor = subprocess.Popen(['sudo', 'sysdig', 'proc.pid = ', '%s' % pid], stdout=subprocess.PIPE)
        lines_iterator = iter(sysdig_monitor.stdout.readline, b"")

        for line in lines_iterator:
            splitted_line = line.split()
            (evt_num, evt_time, evt_cpu, proc_name, thread_tid, evt_dir, evt_type), evt_args = \
                splitted_line[:7], splitted_line[8:]

            parser.process(thread_tid, evt_type, evt_args)

            if thread_tid == pid and evt_type == 'procexit':
                break

    def run(self):
        """Run analysis.
        @return: operation status.
        """
        self.prepare()

        log.debug("Starting analyzer from: %s", os.getcwd())
        log.debug("Storing results at: %s", PATHS["temp"])

        aux_enabled, aux_avail = self.run_auxiliary()

        # call execute method + monitor (and parser)

        pids = self.start(self.target)

        self.execute(pids)
        # sysdig_monitor = subprocess.Popen(['sudo', 'sysdig', 'proc.pid = ', '%s' % pids], stdout=subprocess.PIPE)


        # If the analysis package returned a list of process IDs, we add them
        # to the list of monitored processes and enable the process monitor.
        if pids:
            add_pids(pids)
            pid_check = True

        # If the package didn't return any process ID (for example in the case
        # where the package isn't enabling any behavioral analysis), we don't
        # enable the process monitor.
        else:
            log.info("No process IDs returned by the package, running "
                     "for the full timeout.")
            pid_check = False

        # Check in the options if the user toggled the timeout enforce. If so,
        # we need to override pid_check and disable process monitor.
        if self.config.enforce_timeout:
            log.info("Enabled timeout enforce, running for the full timeout.")
            pid_check = False

        time_counter = 0

        while True:
            time_counter += 1
            # if time_counter == int(self.config.timeout):
            if time_counter == 22:
                log.info("Analysis timeout hit, terminating analysis.")
                break

            try:
                # If the process monitor is enabled we start checking whether
                # the monitored processes are still alive.
                if pid_check:
                    for pid in PROCESS_LIST:
                        if not is_process_alive(pid):
                            log.info("Process with pid %s has terminated", pid)
                            PROCESS_LIST.remove(pid)

                    # If none of the monitored processes are still alive, we
                    # can terminate the analysis.
                    if not PROCESS_LIST:
                        log.info("Process list is empty, "
                                 "terminating analysis.")
                        break

                    # Update the list of monitored processes available to the
                    # analysis package. It could be used for internal
                    # operations within the module.
                    self.set_pids(PROCESS_LIST)

            finally:
                # Zzz.
                time.sleep(1)


        # TODO: check memdump conf option and call memory dump and Upload files
        # the package created to package_files in the results folder

        # Terminate the Auxiliary modules.
        for aux in aux_enabled:
            try:
                aux.stop()
            except (NotImplementedError, AttributeError):
                continue
            except Exception as e:
                log.warning("Cannot terminate auxiliary module %s: %s",
                            aux.__class__.__name__, e)

        if self.config.terminate_processes:
            # Try to terminate remaining active processes. We do this to make sure
            # that we clean up remaining open handles (sockets, files, etc.).
            log.info("Terminating remaining processes before shutdown.")

            for pid in PROCESS_LIST:
                if is_process_alive(pid):
                    try:
                        terminate_process(pid)
                    except:
                        continue

        # Run the finish callback of every available Auxiliary module.
        for aux in aux_avail:
            try:
                aux.finish()
            except (NotImplementedError, AttributeError):
                continue
            except Exception as e:
                log.warning("Exception running finish callback of auxiliary "
                            "module %s: %s", aux.__class__.__name__, e)

        # Let's invoke the completion procedure.
        self.complete()

        return True


if __name__ == "__main__":
    # run()
    success = False
    error = ""

    try:
        # Initialize the main analyzer class.
        analyzer = Analyzer()

        # Run it and wait for the response.
        success = analyzer.run()

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

    # Once the analysis is completed or terminated for any reason, we report
    # back to the agent, notifying that it can report back to the host.
    finally:
        # Establish connection with the agent XMLRPC server.
        server = xmlrpclib.Server("http://127.0.0.1:8000")
        server.complete(success, error, PATHS["root"])
