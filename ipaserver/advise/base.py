# Authors: Tomas Babej <tbabej@redhat.com>
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
#

import os
from ipalib import api
from ipalib.plugable import Plugin, API
from ipalib.errors import ValidationError
from ipapython import admintool
from textwrap import wrap
from ipapython.ipa_log_manager import log_mgr


"""
To add configuration instructions for a new use case, define a new class that
inherits from Advice class.

You should create a plugin file for it in ipaserver/advise/plugins folder.

The class can run any arbitrary code or IPA command via api.Command['command']()
calls. It needs to override get_info() method, which returns the formatted
advice string.

>>> class sample_advice(Advice):
>>>     description = 'Instructions for machine with SSSD 1.0 setup.'

Description provided shows itself as a header and in the list of all advices
currently available via ipa-advise.

Optionally, you can require root privileges for your plugin:

>>>     require_root = True

The following method should be implemented in your plugin:

>>>     def get_info():
>>>         self.log.debug('Entering execute() method')
>>>         self.log.comment('Providing useful advice just for you')
>>>         self.log.command('yum update sssd -y')

As you can see, Advice's log has 3 different levels. Debug lines are printed
out with '# DEBUG:' prefix if --verbose had been used. Comment lines utilize
'# ' prefix and command lines are printed raw.

Please note that comments are automatically wrapped after 70 characters.
Use wrapped=False option to force the unwrapped line in the comment.

>>>         self.log.comment("This line should not be wrapped", wrapped=False)

As a result, you can redirect the advice's output directly to a script file.

# ipa-advise sample-advice > script.sh
# ./script.sh

Important! Do not forget to register the class to the API.

>>> api.register(sample_advice)
"""


class _AdviceOutput(object):

    def __init__(self):
        self.content = []
        self.prefix = '# '
        self.options = None

    def comment(self, line, wrapped=True):
        if wrapped:
            for wrapped_line in wrap(line, 70):
                self.content.append(self.prefix + wrapped_line)
        else:
            self.content.append(self.prefix + line)

    def debug(self, line):
        if self.options.verbose:
            self.comment('DEBUG: ' + line)

    def command(self, line):
        self.content.append(line)


class Advice(Plugin):
    """
    Base class for advices, plugins for ipa-advise.
    """

    options = None
    require_root = False
    description = ''

    def __init__(self, api):
        super(Advice, self).__init__(api)
        self.log = _AdviceOutput()

    def set_options(self, options):
        self.options = options
        self.log.options = options

    def get_info(self):
        """
        This method should be overriden by child Advices.

        Returns a string with instructions.
        """

        raise NotImplementedError


class AdviseAPI(API):
    bases = (Advice,)
    modules = ('ipaserver.advise.plugins.*',)

advise_api = AdviseAPI()


class IpaAdvise(admintool.AdminTool):
    """
    Admin tool that given systems's configuration provides instructions how to
    configure the systems for various use cases.
    """

    command_name = 'ipa-advise'
    usage = "%prog ADVICE"
    description = "Provides configuration advice for various use cases. To "\
                  "see the list of possible ADVICEs, run ipa-advise without "\
                  "any arguments."

    def __init__(self, options, args):
        super(IpaAdvise, self).__init__(options, args)

    @classmethod
    def add_options(cls, parser):
        super(IpaAdvise, cls).add_options(parser)

    def validate_options(self):
        super(IpaAdvise, self).validate_options(needs_root=False)

        if len(self.args) > 1:
            raise self.option_parser.error("You can only provide one "
                                           "positional argument.")

    def log_success(self):
        pass

    def print_config_list(self):
        self.print_header('List of available advices')

        max_keyword_len = max((len(keyword) for keyword in advise_api.Advice))

        for keyword in advise_api.Advice:
            advice = getattr(advise_api.Advice, keyword, '')
            description = getattr(advice, 'description', '')
            keyword = keyword.replace('_', '-')

            # Compute the number of spaces needed for the table to be aligned
            offset = max_keyword_len - len(keyword)
            prefix = "    {key} {off}: ".format(key=keyword, off=' ' * offset)
            wrapped_description = wrap(description, 80 - len(prefix))

            # Print the first line with the prefix (keyword)
            print prefix + wrapped_description[0]

            # Print the rest wrapped behind the colon
            for line in wrapped_description[1:]:
                print "{off}{line}".format(off=' ' * len(prefix), line=line)

    def print_header(self, header, print_shell=False):
        header_size = len(header)

        prefix = ''
        if print_shell:
            prefix = '# '
            print '#!/bin/sh'

        # Do not print out empty header
        if header_size > 0:
            print(prefix + '-' * 70)
            for line in wrap(header, 70):
                print(prefix + line)
            print(prefix + '-' * 70)

    def print_advice(self, keyword):
        advice = getattr(advise_api.Advice, keyword, None)

        # Ensure that Configuration class for given --setup option value exists
        if advice is None:
            raise ValidationError(
                name="advice",
                error="No instructions are available for '{con}'. "
                      "See the list of available configuration "
                      "by invoking the ipa-advise command with no argument."
                      .format(con=keyword.replace('_', '-')))

        # Check whether root privileges are needed
        if advice.require_root and os.getegid() != 0:
            raise admintool.ScriptError(
                'Must be root to get advice for {adv}'
                .format(adv=keyword.replace('_', '-')), 1)

        # Print out nicely formatted header
        self.print_header(advice.description, print_shell=True)

        # Set options so that plugin can use verbose/quiet options
        advice.set_options(self.options)

        # Print out the actual advice
        api.Backend.rpcclient.connect()
        advice.get_info()
        api.Backend.rpcclient.disconnect()
        for line in advice.log.content:
            print line

    def run(self):
        super(IpaAdvise, self).run()

        api.bootstrap(in_server=False, context='cli')
        api.finalize()
        advise_api.bootstrap(in_server=False, context='cli')
        advise_api.finalize()
        if not self.options.verbose:
            # Do not print connection information by default
            logger_name = r'ipa\.ipalib\.plugins\.rpcclient'
            log_mgr.configure(dict(logger_regexps=[(logger_name, 'warning')]))

        # With no argument, print the list out and exit
        if not self.args:
            self.print_config_list()
            return
        else:
            keyword = self.args[0].replace('-', '_')
            self.print_advice(keyword)
