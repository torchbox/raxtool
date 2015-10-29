# vim:set sw=4 ts=4 et:

import re, sys, pprint
import linereader
from functools import partial

class CLIError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value

class CommandNode(object):
    def __init__(self, handler = None, help = ""):
        self._handler = handler
        self._help = help
        self._children = {}
        self._arg = None

    @property
    def help(self):
        return self._help

    @help.setter
    def help(self, h):
        self._help = h

    @property
    def handler(self):
        return self._handler

    @handler.setter
    def handler(self, h):
        self._handler = h

    def set_child(self, name, node):
        self._children[name] = node
        if name[0] == '<':
            self._arg = name

    def ensure_child(self, name, node = None):
        if node is None:
            node = CommandNode()

        if name not in self._children:
            self.set_child(name, node)

        return self.child(name)

    def child(self, name):
        return self._children[name]

    def child_match(self, name):
        if name in self._children:
            return [ name ]

        return [ k for k, v in self._children.iteritems() if k[0:len(name)] == name ]

    @property
    def has_arg(self):
        return True if self._arg is not None else False

    @property
    def arg(self):
        return self.child(self._arg)

class Mode(object):
    def __init__(self, prompt):
        self.root = CommandNode()
        self._prompt = prompt
        self.add_command("exit", self.c_exit, "Return to previous mode")

    def c_exit(self, p, ctx, args):
        p.modes.pop()

    @property
    def prompt(self):
        return self._prompt

    def add_command(self, command, handler, help = ""):
        parts = command.split(' ')
        at = self.root

        for part in parts:
            at.ensure_child(part)
            at = at.child(part)

        if handler is not None:
            at.handler = handler
        if help is not None:
            at.help = help

    def add_commands(self, commands):
        for cmd in commands:
            self.add_command(cmd[0], cmd[1], cmd[2] if len(cmd) > 2 else "")

    def descend(self, parts):
        at = self.root
        args = []

        for part in parts:
            matches = at.child_match(part)

            if len(matches) == 1:
                at = at.child(matches[0])
            elif len(matches) == 0:
                if at.has_arg:
                    args.append(part)
                    at = at.arg
                else:
                    raise CLIError("Unknown command.")
            else:
                raise CLIError("Ambigious command ({}).".format(", ".join(matches)))

        return (at, args)

    def dispatch(self, parser, command):
        r = re.compile('[ \t]+')
        parts = r.split(command.strip())
        (at, args) = self.descend(parts)

        if at.handler is None:
                raise CLIError("Incomplete command.".format(command))

        at.handler(parser, parser.ctx, args)

    def do_help(self, ctx, char):
        r = re.compile('[ \t]+')
        parts = r.split(ctx.line)
        (at, args) = self.descend(parts[:-1])

        try:
            ctx._linereader.term_cooked()
            sys.stdout.write('\n')

            matches = at.child_match(parts[-1])
            matches.sort()

            for match in matches:
                sys.stdout.write("  {:<30}    {}\n".format(match, at.child(match).help))

            if at.handler is not None:
                sys.stdout.write("  <cr>\n")
        finally:
            ctx._linereader.term_raw()
            ctx.redraw()

    def do_tab(self, ctx, char):
        r = re.compile('[ \t]+')
        parts = r.split(ctx.line)
        (at, args) = self.descend(parts[:-1])

        matches = at.child_match(parts[-1])
        matches.sort()

        if len(matches) == 0:
            return
        elif len(matches) == 1 and matches[0][0] != '<':
            rest = matches[0][len(parts[-1]):]
            sys.stdout.write(rest + ' ')
            ctx.line += rest + ' '
            return
        else:
            ctx._linereader.term_cooked()
            sys.stdout.write('\n')

            for match in matches:
                sys.stdout.write("{} ".format(match))
            sys.stdout.write('\n')

            ctx._linereader.term_raw()
            ctx.redraw()


class Parser(object):
    def __init__(self, ctx, default_mode):
        self.root = CommandNode()
        self.ctx = ctx
        self.linereader = linereader.Linereader()
        self.modes = [default_mode]

    def do_help(self, ctx, char):
        self.mode.do_help(ctx, char)

    def do_tab(self, ctx, char):
        self.mode.do_tab(ctx, char)

    def run(self):
        self.linereader.bind('?', self.do_help)
        self.linereader.bind('\t', self.do_tab)

        while True:
            self.mode = self.modes[-1]
            if len(self.modes) > 1:
                mode_prompt = "({})".format('-'.join([ m.prompt for m in self.modes[1:] ]))
            else:
                mode_prompt = ""
            prompt = "{}{}> ".format(self.modes[0].prompt, mode_prompt)

            cmd = self.linereader.readline(prompt)
            if cmd.strip() == '':
                continue

            try:
                self.mode.dispatch(self, cmd)
            except CLIError, e:
                print("% {}".format(e))

def _do_set_mode(mode, ctargs, parser, ctx, args):
    m = mode(ctx, args, *ctargs)
    parser.modes.append(m)

def set_mode(mode, *ctargs):
    return partial(_do_set_mode, mode, ctargs)
