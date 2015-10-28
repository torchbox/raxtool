# vim:set sw=4 ts=4 et:

import re, gnureadline

class CLIError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value

class Parser(object):
    def __init__(self, ctx):
        self.commands = {}
        self.ctx = ctx

    def add_command(self, command, handler):
        parts = command.split(' ')
        at = self.commands

        for part in parts:
            if part[0] == '<' and part[-1] == '>':
                if '__arg__' not in at:
                    at['__arg__'] = {}
                at = at['__arg__']
            else:
                if part not in at:
                    at[part] = {}
                at = at[part]

        at['__handler__'] = handler

    def add_commands(self, commands):
        for cmd in commands:
            self.add_command(cmd[0], cmd[1])

    def dispatch(self, command):
        r = re.compile('[ \t]+')

        parts = r.split(command)
        at = self.commands
        args = []

        for part in parts:
            if part not in at:
                if '__arg__' in at:
                    args.append(part)
                    at = at['__arg__']
                else:
                    raise CLIError("Unknown command: {}".format(command))
            else:
                at = at[part]

        if '__handler__' not in at:
                raise CLIError("Incomplete command: {}".format(command))

        at['__handler__'](self.ctx, args)

    def complete(self, text, state):
        print("self.complete, text=[{}] state=[{}]".format(text, state))
        if state == 0:
            self.completes = []

            r = re.compile('[ \t]+')

            parts = r.split(text)
            at = self.commands
            args = []

            for part in parts[:-1]:
                print("switching {}".format(part))
                if part not in at:
                    if '__arg__' in at:
                        args.append(part)
                        at = at['__arg__']
                    else:
                        return None
                else:
                    at = at[part]

            match = parts[-1]
            print("match=[{}]".format(match))
            for maybe in at.keys():
                print("considering [{}] for [{}]".format(maybe, match))
                if maybe[0:len(match)] == match:
                    self.completes.append(maybe + ' ')

        try:
            return self.completes[state]
        except IndexError:
            return None

    
    def run(self, prompt='raxtool> '):
        #gnureadline.parse_and_bind('tab: complete')
        #gnureadline.set_completer(self.complete)

        while True:
            cmd = raw_input(prompt)
            try:
                self.dispatch(cmd)
            except CLIError, e:
                print("% {}".format(e))
