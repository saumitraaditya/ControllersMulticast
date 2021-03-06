# ipop-project
# Copyright 2016, University of Florida
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import time
import psutil
from controller.framework.CFx import CFX


# Function checks the system process table for Tincan process
def is_tincan_proc():
    # Iterates across process table to find Tincan process
    for process in psutil.process_iter():
        if process.name().find("ipop-tincan") != -1:
            return True
    return False


def main():
    # Wait for ipop-tincan process to start
    while is_tincan_proc() is False:
        print("Waiting on IPOP Tincan to start...")
        time.sleep(10)
    # Create CFX object that initializes internal data structure of all the controller modules
    cfx = CFX()
    cfx.initialize()
    cfx.wait_for_shutdown_event()
    cfx.terminate()

if __name__ == "__main__":
    main()
