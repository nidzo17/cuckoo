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
import threading

from lib.common.constants import PATHS
from lib.core.config import Config
from lib.common.exceptions import CuckooError
from lib.core.startup import create_folders, init_logging
from lib.common.abstracts import Auxiliary
from lib.common.hashing import hash_file
from modules import auxiliary
from lib.common.results import upload_to_host


log = logging.getLogger()
FILES_LIST = []
DUMPED_LIST = []
PROCESS_LIST = []
dump_events = False

class CuckooPackageError(Exception):
    pass


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


def add_file(file_path):
    """Add a file to file list."""
    if file_path not in FILES_LIST:
        log.info("Added new file to list with path: %s",
                 unicode(file_path).encode("utf-8", "replace"))
        FILES_LIST.append(file_path)


def del_file(file_path):
    dump_file(file_path)

    # If this filename exists in the FILES_LIST, then delete it, because it
    # doesn't exist anymore anyway.
    if file_path in FILES_LIST:
        FILES_LIST.pop(FILES_LIST.index(file_path))


def move_file(old_path, new_path):
    # Check whether the old filename is in the FILES_LIST.
    if old_path.lower() in FILES_LIST:

        # Get the index of the old filename.
        idx = FILES_LIST.index(old_path.lower())

        # Replace the old filename by the new filename.
        FILES_LIST[idx] = new_path


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
        file_name = os.path.basename(file_path)
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


def execute(pid):
    parser = SysdigParser()
    sysdig_monitor = subprocess.Popen(['sudo', 'sysdig', 'proc.pid = ', '%s' % pid, 'or proc.apid = ', '%s' % pid],
                                      stdout=subprocess.PIPE)
    lines_iterator = iter(sysdig_monitor.stdout.readline, b"")

    for event in lines_iterator:
        parser.process(event)


class SysdigParser:
    def __init__(self):
        pass

    def process(self, event):
        if dump_events:
            with open('events.log', "a") as outfile:
                outfile.write("%s\n" % event)

        event_info = event.split()
        (evt_num, evt_time, evt_cpu, proc_name, thread_tid, evt_dir, evt_type), evt_args = \
            event_info[:7], event_info[8:]

        # In case of open or creat, the client is trying to notify the creation
        # of a new file.
        if (evt_type == 'open' or evt_type == 'creat') and evt_dir == '<':
            if any("O_RDONLY" in evt_arg for evt_arg in evt_args):
                return
            for evt_arg in evt_args:
                # args: name=file_name(file_path)
                if evt_arg.startswith('name='):
                    # We extract the file path.
                    file_path = evt_arg[evt_arg.find("(")+1:evt_arg.find(")")]
                    # We add the file to the list.
                    add_file(file_path)

        elif evt_type == 'unlink' and evt_dir == '>':
            # args: path=file_path
            file_path = evt_args[5:]
            del_file(file_path)

        elif evt_type == 'unlinkatMOZDAAA' and evt_dir == '>':
            for evt_arg in evt_args:
                if evt_arg.startswith('name='):
                    file_name = evt_arg[5:]
                    file_path = os.path.abspath(file_name)
                    del_file(file_path)

        elif evt_type == 'rename':
            for evt_arg in evt_args:
                if evt_arg.startswith('oldpath='):
                    old_name = evt_arg[8:]
                    old_path = os.path.abspath(old_name)
                elif evt_arg.startswith('newpath='):
                    new_name = evt_arg[8:]
                    new_path = os.path.abspath(new_name)
            if 'old_path' in locals() and 'new_path' in locals():
                move_file(old_path.decode("utf-8"), new_path.decode("utf-8"))

        elif evt_type == 'connect' and evt_dir == '<':
            for evt_arg in evt_args:
                if evt_arg.startswith('tuple='):
                    ip_addresses = evt_arg[6:]
                    if ip_addresses.startswith('0->'):
                        continue
                    if not ip_addresses == '0.0.0.0:0->0.0.0.0:0':
                        with open('linux.log', "a") as outfile:
                            #outfile.write(evt_arg)
                            outfile.write("\n%s" % ip_addresses)


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
            self.target = os.path.join('/tmp', str(self.config.file_name))

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

        os.chmod(path, 0755)
        process = subprocess.Popen(['/bin/bash', '-c', path])
        print "PID: ", process.pid

        return process

    def run(self):
        """Run analysis.
        @return: operation status.
        """
        self.prepare()

        log.debug("Starting analyzer from: %s", os.getcwd())
        log.debug("Storing results at: %s", PATHS["temp"])

        aux_enabled, aux_avail = self.run_auxiliary()

        with open('linux.log', "a") as outfile:
            #file_info = subprocess.Popen(['file', self.target], stdout=subprocess.PIPE)
            #if "dynamically linked" in file_info.communicate()[0]:
            subprocess.call(['ldd', self.target], stdout=outfile)
            # lsof -P -T -p Application_PID  8 po redu su imena

        # call execute method + monitor (and parser)
        try:
            process = self.start(self.target)

        except Exception as e:
            raise CuckooError("The Linux binary package start function encountered "
                              "an unhandled exception: ", str(e))

        pids = process.pid
        monitor_thread = threading.Thread(target=execute, args=(pids,))
        monitor_thread.start()

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
            if time_counter == int(self.config.timeout):
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

        upload_to_host('linux.log', 'logs/linux.log')
        if dump_events:
            upload_to_host('events.log', 'logs/events.log')
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
