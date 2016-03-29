# Authors:
#   Tomas Babej <tbabej@redhat.com>
#
# Copyright (C) 2013  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import time


def run_repeatedly(host, command, assert_zero_rc=True, test=None,
                timeout=30, **kwargs):
    """
    Runs command on host repeatedly until it's finished successfully (returns
    0 exit code and its stdout passes the test function).

    Returns True if the command was executed succesfully, False otherwise.

    This method accepts additional kwargs and passes these arguments
    to the actual run_command method.
    """

    time_waited = 0
    time_step = 2

    # Check that the test is a function
    if test:
        assert callable(test)

    while(time_waited <= timeout):
        result = host.run_command(command, raiseonerr=False, **kwargs)

        return_code_ok = not assert_zero_rc or (result.returncode == 0)
        test_ok = not test or test(result.stdout_text)

        if return_code_ok and test_ok:
            # Command successful
            return True
        else:
            # Command not successful
            time.sleep(time_step)
            time_waited += time_step

    raise AssertionError("Command: {cmd} repeatedly failed {times} times, "
                         "exceeding the timeout of {timeout} seconds."
                         .format(cmd=' '.join(command),
                                 times=timeout / time_step,
                                 timeout=timeout))
