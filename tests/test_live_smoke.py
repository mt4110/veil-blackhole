"""No sudo, network query, or device access: orchestration uses fake processes."""
import contextlib
import io
import pathlib
import types
import unittest
from unittest import mock

SOURCE = pathlib.Path(__file__).resolve().parent.parent / "scripts" / "live-smoke.py"
smoke = types.ModuleType("live_smoke")
smoke.__file__ = str(SOURCE)
exec(compile(SOURCE.read_text(), str(SOURCE), "exec"), smoke.__dict__)


class Selector:
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def register(self, *args): pass
    def select(self, **kwargs): return [True]


class Process:
    pid = 12345
    def __init__(self, startup=True, malformed=0):
        self.returncode = None if startup else 3
        self.stdout = io.StringIO("mode=live names=false endpoints=false\n" if startup else "sudo failed\n")
        self.malformed = malformed
    def poll(self): return self.returncode
    def communicate(self, **kwargs):
        self.returncode = 0
        return (f"queries=1 unsupported=0 malformed={self.malformed} truncated=0 display_dropped=0\n", None)


class LiveSmokeTests(unittest.TestCase):
    def execute(self, process, arguments=()):
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(smoke, "configured_resolver", return_value="2001:db8::53"))
            stack.enter_context(mock.patch.object(smoke.os, "geteuid", return_value=501))
            stack.enter_context(mock.patch.object(smoke.sys, "platform", "darwin"))
            stack.enter_context(mock.patch.object(smoke.sys, "argv", ["live-smoke.py", *arguments]))
            binary = stack.enter_context(mock.patch.object(smoke, "BINARY"))
            binary.is_file.return_value = True
            stack.enter_context(mock.patch.object(smoke.selectors, "DefaultSelector", Selector))
            popen = stack.enter_context(mock.patch.object(smoke.subprocess, "Popen", return_value=process))
            run = stack.enter_context(mock.patch.object(smoke.subprocess, "run", return_value=types.SimpleNamespace(returncode=0)))
            output = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            try:
                result = smoke.main()
            except RuntimeError:
                result = "startup-failure"
            return result, run, popen, output.getvalue()

    def test_failed_startup_never_sends_a_query(self):
        result, run, _, _ = self.execute(Process(startup=False))
        self.assertEqual(result, "startup-failure")
        run.assert_not_called()

    def test_success_sends_once_without_banner_or_tcp_retry(self):
        result, run, popen, output = self.execute(Process())
        self.assertEqual(result, 0)
        run.assert_called_once()
        command = run.call_args.args[0]
        self.assertEqual(command[:3], ["/usr/bin/dig", "-6", "@2001:db8::53"])
        for flag in ["+tries=1", "+notcp", "+ignore", "+noall", "+nocmd"]:
            self.assertIn(flag, command)
        self.assertNotIn("--show-names", popen.call_args.args[0])
        self.assertNotIn("--show-endpoints", popen.call_args.args[0])
        self.assertNotIn("2001:db8", output)
        self.assertNotIn("example.com", output)

    def test_malformed_counts_do_not_pass(self):
        result, _, _, output = self.execute(Process(malformed=1))
        self.assertEqual(result, 1)
        self.assertIn("result=unconfirmed", output)

    def test_check_only_never_starts_capture_or_query(self):
        result, run, popen, _ = self.execute(Process(), arguments=["--check"])
        self.assertEqual(result, 0)
        run.assert_not_called()
        popen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
