# vim:set sw=4 ts=4 et:

class CommandError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value

class UnknownCommandError(CommandError):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return 'Unknown command "{}"'.format(self.value)

class CommandDispatcher(object):
    def __init__(self, cmd_table):
        self.cmd_table = cmd_table

    def __call__(self, ctx, args):
        try:
            cmd = args.pop(0)
        except IndexError:
            raise CommandError("Incomplete command")

        if cmd not in self.cmd_table:
            raise UnknownCommandError(cmd)
        call = self.cmd_table[cmd](ctx, args)

    @staticmethod
    def create(cmd_table):
        cd = CommandDispatcher(cmd_table)
        return cd.__call__.__get__(cd)
