#!/usr/bin/env python3
"""Run a TUI binary in a pseudo-terminal, drive it with keys, and poll the
screen for the expected text (via pyte if available, else the raw stream
stripped of escapes).

    ptyrun.py SPEC-JSON [EXPECTED-TEXT...]

The spec (one JSON argument; trailing arguments are added to expect):
  cmd      argv
  keys     steps, in order:
             "text"            write it, then pump briefly
             1.5               pump for that many seconds (a short pause)
             {"wait": "text"}  poll until "text" is on screen
  expect   texts that must each appear on screen at some point (polled
           after the keys; a toast counts even if it has gone by the end)
  timeout  seconds each wait, and the expect phase, may take
  name     scenario name for the report
  verbose  print the last screen even on success

Prints "ok   name: text" per expectation; on a timeout prints "FAIL ..." and
the last screen to stderr. Exits 0 when everything was seen, 1 otherwise.
"""
import os, pty, sys, time, select, json, re

SETTLE = 0.3  # pump after each written key


ESCAPE = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]")
SPACE = re.compile(r"\s+")


class Screen:
    """The terminal as text. With pyte, the emulated screen. Without it,
    the stream stripped of escapes, kept incrementally; since cursor moves
    replace some spaces there, contains() ignores whitespace."""

    def __init__(self, cols, rows):
        self.pending = b""  # raw bytes not yet stripped (a split escape)
        self.stripped = ""
        self.squashed = ""  # self.stripped without whitespace
        try:
            import pyte
            self.screen = pyte.Screen(cols, rows)
            self.stream = pyte.ByteStream(self.screen)
        except ImportError:
            self.screen = None

    def feed(self, data):
        if self.screen is not None:
            self.stream.feed(data)
            return
        buf = self.pending + data
        # Hold back a trailing escape that may continue in the next read.
        cut = buf.rfind(b"\x1b")
        if cut != -1 and len(buf) - cut < 32 and not ESCAPE.match(buf, cut):
            buf, self.pending = buf[:cut], buf[cut:]
        else:
            self.pending = b""
        text = ESCAPE.sub(b"", buf).decode(errors="replace")
        self.stripped += text
        self.squashed += SPACE.sub("", text)

    def contains(self, want):
        if self.screen is not None:
            return want in "\n".join(self.screen.display)
        return SPACE.sub("", want) in self.squashed

    def nonblank(self):
        if self.screen is not None:
            return any(line.strip() for line in self.screen.display)
        return self.squashed != ""

    def last(self):
        """What to show on a failure: the screen, or the stream's tail."""
        if self.screen is not None:
            return "\n".join(line.rstrip() for line in self.screen.display)
        return self.stripped[-6000:]


def run(spec):
    cmd = spec["cmd"]
    cols, rows = spec.get("cols", 140), spec.get("rows", 40)
    timeout = float(spec.get("timeout", 60))
    name = spec.get("name", cmd[0])
    expect = list(spec.get("expect", []))

    pid, fd = pty.fork()
    if pid == 0:
        os.environ["TERM"] = "xterm-256color"
        os.environ["COLUMNS"] = str(cols)
        os.environ["LINES"] = str(rows)
        os.environ.update(spec.get("env") or {})
        os.execvp(cmd[0], cmd)
    import fcntl, termios, struct
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

    screen = Screen(cols, rows)
    seen = set()
    alive = True

    def pump(t, until=None):
        """Read output for up to t seconds; stop early once until() holds."""
        nonlocal alive
        end = time.monotonic() + t
        fresh = True  # check the screen only after new output
        while True:
            if fresh:
                for e in expect:
                    if e not in seen and screen.contains(e):
                        seen.add(e)
                if until is not None and until():
                    return True
            if not alive or time.monotonic() >= end:
                return False
            fresh = False
            r, _, _ = select.select([fd], [], [], 0.05)
            if r:
                try:
                    data = os.read(fd, 65536)
                except OSError:
                    data = b""
                if not data:
                    alive = False
                screen.feed(data)
                fresh = True

    ok = True
    # Let the app enter raw mode and draw before any key is written.
    pump(timeout, until=screen.nonblank)
    for i, k in enumerate(spec.get("keys", [])):
        if isinstance(k, (int, float)):
            pump(k)
        elif isinstance(k, dict):
            want = k["wait"]
            if not pump(timeout, until=lambda: screen.contains(want)):
                print(f'FAIL {name}: step {i} timed out after {timeout:g}s waiting for "{want}"',
                      file=sys.stderr)
                ok = False
                break
        else:
            os.write(fd, k.encode())
            pump(SETTLE)
    if ok:
        pump(timeout, until=lambda: all(e in seen for e in expect))
        for e in expect:
            if e in seen:
                print(f"ok   {name}: {e}", flush=True)
            else:
                print(f'FAIL {name}: expected "{e}" (not seen within {timeout:g}s)', file=sys.stderr, flush=True)
                ok = False

    try:
        os.kill(pid, 9)
    except ProcessLookupError:
        pass
    # Close the master before reaping: a child killed while its tty still
    # holds unread output can sit in exit until the pty goes away, so a
    # blocking wait would hang. Reap briefly, never block.
    os.close(fd)
    for _ in range(40):
        try:
            if os.waitpid(pid, os.WNOHANG)[0] != 0:
                break
        except ChildProcessError:
            break
        time.sleep(0.05)
    if not ok:
        print(f"--- {name}: last screen ---", file=sys.stderr, flush=True)
        print(screen.last(), file=sys.stderr, flush=True)
    elif spec.get("verbose"):
        print(f"=== {name} ===")
        print(screen.last())
    return ok


if __name__ == "__main__":
    spec = json.loads(sys.argv[1])
    # Expectations may also follow the spec as plain arguments.
    spec["expect"] = spec.get("expect", []) + sys.argv[2:]
    sys.exit(0 if run(spec) else 1)
