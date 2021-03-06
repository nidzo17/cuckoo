# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import time
import logging
import os
from threading import Thread

from lib.common.abstracts import Auxiliary
from lib.common.results import upload_to_host
import gtk.gdk

log = logging.getLogger(__name__)
SHOT_DELAY = 1  # Minimum 0.33
# Skip the following area when comparing screen shots.
# Example for 800x600 screen resolution.
# SKIP_AREA = ((735, 575), (790, 595))
SKIP_AREA = None


def take():
    window = gtk.gdk.get_default_root_window()
    window_size = window.get_size()
    pix_buffer = gtk.gdk.Pixbuf(gtk.gdk.COLORSPACE_RGB, False, 8, window_size[0], window_size[1])
    pix_buffer = pix_buffer.get_from_drawable(window, window.get_colormap(),
                                              0, 0, 0, 0, window_size[0], window_size[1])
    if pix_buffer is not None:
        return pix_buffer
    else:
        print "Unable to get the screenshot."


class Screenshots(Auxiliary, Thread):
    """Take screenshots."""

    def __init__(self, options):
        Thread.__init__(self)
        Auxiliary.__init__(self, options)
        self.do_run = True

    def stop(self):
        """Stop screenshotting."""
        self.do_run = False

    def run(self):
        """Run screenshotting.
        @return: operation status.
        """
        if "screenshots" in self.options:
            self.do_run = int(self.options["screenshots"])

        img_counter = 0

        while self.do_run:
            time.sleep(SHOT_DELAY)

            try:
                img_current = take()
            except IOError as e:
                log.error("Cannot take screenshot: %s", e)
                continue

            img_counter += 1
            img_current.save('/tmp/screenshot.jpg', "jpeg")

            # Sending photo...
            upload_to_host('/tmp/screenshot.jpg', "shots/%s.jpg" % str(img_counter).rjust(4, "0"))
            os.unlink('/tmp/screenshot.jpg')

        return True
