#! /usr/bin/env python
# vim:set sw=4 ts=4 et:

import sys, rax, cli, commands, lb

ctx = rax.Context()

if not ctx.check_token():
    username = raw_input("Username: ")
    apikey = raw_input("API key: ")
    region = raw_input("Region (e.g. LON): ")

    try:
        ctx.login(region, username, apikey)
    except rax.Error, e:
        print(e)
        sys.exit(1)

def c_logout(ctx, args):
    ctx.logout()

def c_exit(ctx, args):
    sys.exit(0)

p = cli.Parser(ctx)
p.add_commands(lb.commands)
p.add_command("exit", c_exit)

if len(sys.argv) > 1:
    try:
        p.dispatch(" ".join(sys.argv[1:]))
    except cli.CLIError, e:
        print(e)
else:
    p.run('raxtool> ')
