#! /usr/bin/env python
# vim:set sw=4 ts=4 et:

import sys, cli, commands, lb
import rax.api, lb

ctx = rax.api.Context()

if not ctx.check_token():
    username = raw_input("Username: ")
    apikey = raw_input("API key: ")
    region = raw_input("Region (e.g. LON): ")

    try:
        ctx.login(region, username, apikey)
    except rax.Error, e:
        print(e)
        sys.exit(1)

def c_logout(p, ctx, args):
    ctx.logout()

def c_exit(p, ctx, args):
    sys.exit(0)

global_mode = cli.Mode('raxtool')
global_mode.add_commands(lb.commands)
#global_mode.add_commands(rax.cdn.commands)
global_mode.add_command("no", None, "Remove or negate configuration")
global_mode.add_command("show", None, "Display configuration and status information")
global_mode.add_command("exit", c_exit, "Exit raxtool")

p = cli.Parser(ctx, global_mode)

if len(sys.argv) > 1:
    try:
        p.dispatch(" ".join(sys.argv[1:]))
    except cli.CLIError, e:
        print("% {}".format(e))
else:
    p.run()
