import termios, tty, sys

class Linereader(object):
    def __init__(self):
        self._binds = {
            '__default__':  self.handle_char,
            '\x7f':         self.backspace_char,
            '\x08':         self.backspace_char,
            '\n':           self.enter,
            '\r':           self.enter,
            '\x15':         self.kill_line,
        }

        self.oflags = termios.tcgetattr(sys.stdin)

    def bind(self, char, func):
        self._binds[char] = func

    def handle_char(self, ctx, c):
        ctx.line += c
        sys.stdout.write(c)

    def backspace_char(self, ctx, c):
        ctx.line = ctx.line[:-1]
        sys.stdout.write('\b \b')

    def enter(self, ctx, c):
        sys.stdout.write('\r\n')
        ctx.finished = True

    def kill_line(self, ctx, c):
        sys.stdout.write('^U\r\n')
        ctx.line = ''
        ctx.redraw()

    class Context(object):
        def __init__(self, linereader):
            self._linereader = linereader
            self._line = ''
            self._finished = False

        def append(self, text):
            self._line += text

        @property
        def line(self):
            return self._line

        @line.setter
        def line(self, value):
            self._line = value

        @property
        def finished(self):
            return self._finished

        @finished.setter
        def finished(self, value):
            self._finished = True

        def redraw(self):
            sys.stdout.write(self._linereader._prompt)
            sys.stdout.write(self._line)

    def term_raw(self):
        tty.setraw(sys.stdin)
        nflags = termios.tcgetattr(sys.stdin)
        nflags[3] &~ (termios.ECHO | termios.ECHONL | termios.ICANON)
        termios.tcsetattr(sys.stdin, termios.TCSANOW, nflags)

    def term_cooked(self):
        tty.setcbreak(sys.stdin)
        termios.tcsetattr(sys.stdin, termios.TCSANOW, self.oflags)

    def readline(self, prompt):
        self._prompt = prompt
        sys.stdout.write(prompt)
        ctx = Linereader.Context(self)

        try:
            self.term_raw()

            while True:
                c = sys.stdin.read(1)
                if c in self._binds:
                    self._binds[c](ctx, c)
                else:
                    self._binds['__default__'](ctx, c)
                if ctx.finished:
                    return ctx.line
        finally:
            self.term_cooked()
