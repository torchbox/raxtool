#! /usr/bin/env python

import cli, sys

def show_foo(args):
    print "showing foo"

def show_foo_name(args):
    print("showing the foo {}".format(args[0]))

def show_foo_status(args):
    print("showing the status of foo {}".format(args[0]))

def show_bar(args):
    print "showing bar"

def exit(args):
    sys.exit(0)

commands = [
    [ 'show foo', show_foo ],
    [ 'show foo <name>', show_foo_name ],
    [ 'show foo <name> status', show_foo_status ],
    [ 'show bar', show_bar ],
]

p = cli.Parser()
p.add_commands(commands)
p.run()
