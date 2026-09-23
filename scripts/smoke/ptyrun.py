#!/usr/bin/env python3
"""Run a TUI binary in a pseudo-terminal, send keys with delays, dump the
final screen (via pyte if available, else the raw stream stripped)."""
import os, pty, sys, time, select, json

def run(cmd, keys, cols=140, rows=40, settle=0.6, env=None, total=6.0):
    pid, fd = pty.fork()
    if pid == 0:
        os.environ["TERM"] = "xterm-256color"
        os.environ["COLUMNS"] = str(cols)
        os.environ["LINES"] = str(rows)
        if env:
            os.environ.update(env)
        os.execvp(cmd[0], cmd)
    import fcntl, termios, struct
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    out = b""
    def pump(t):
        nonlocal out
        end = time.time() + t
        while time.time() < end:
            r, _, _ = select.select([fd], [], [], 0.05)
            if r:
                try:
                    out += os.read(fd, 65536)
                except OSError:
                    return
    pump(settle * 3)
    for k in keys:
        if isinstance(k, (int, float)):
            pump(k)
            continue
        os.write(fd, k.encode())
        pump(settle)
    pump(settle)
    try:
        os.kill(pid, 9)
    except ProcessLookupError:
        pass
    try:
        import pyte
        screen = pyte.Screen(cols, rows)
        stream = pyte.ByteStream(screen)
        stream.feed(out)
        return "\n".join(screen.display)
    except ImportError:
        import re
        return re.sub(rb"\x1b\[[0-9;?]*[A-Za-z]", b"", out).decode(errors="replace")

if __name__ == "__main__":
    spec = json.loads(sys.argv[1])
    print(run(spec["cmd"], spec["keys"], env=spec.get("env"), cols=spec.get("cols", 140), rows=spec.get("rows", 40)))
