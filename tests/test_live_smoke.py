"""No sudo, network query, or device access: mocks plus owned Python pipe children."""
import contextlib
import io
import pathlib
import subprocess
import sys
import time
import types
import unittest
from unittest import mock

SOURCE = pathlib.Path(__file__).resolve().parent.parent / "scripts" / "live-smoke.py"
smoke = types.ModuleType("live_smoke")
smoke.__file__ = str(SOURCE)
exec(compile(SOURCE.read_text(), str(SOURCE), "exec"), smoke.__dict__)


class Process:
    pid = 12345
    def __init__(self, startup=True, malformed=0):
        self.returncode = None if startup else 3
        self.stdout = io.StringIO("mode=live names=false endpoints=false\n" if startup else "sudo failed\n")
        self.malformed = malformed
    def poll(self): return self.returncode
    def communicate(self, **kwargs):
        self.returncode = 0
        return (f"queries=1 unsupported=0 malformed={self.malformed} truncated=0 display_dropped=0\n".encode(), None)


class LiveSmokeTests(unittest.TestCase):
    def execute(self, process, arguments=()):
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(smoke, "configured_resolver", return_value="2001:db8::53"))
            stack.enter_context(mock.patch.object(smoke.os, "geteuid", return_value=501))
            stack.enter_context(mock.patch.object(smoke.sys, "platform", "darwin"))
            stack.enter_context(mock.patch.object(smoke.sys, "argv", ["live-smoke.py", *arguments]))
            binary = stack.enter_context(mock.patch.object(smoke, "BINARY"))
            binary.is_file.return_value = True
            wait = stack.enter_context(mock.patch.object(smoke, "wait_for_startup", return_value=b""))
            if process.returncode is not None:
                wait.side_effect = RuntimeError("startup failed")
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


class RealPipeStartupTests(unittest.TestCase):
    """Real owned Python children; resolver, dig and privileged kill are substituted."""
    def execute(self, code, startup_timeout=0.2):
        real_popen = subprocess.Popen
        children = []
        queries = []
        stops = []

        def launch(_args, **kwargs):
            child = real_popen([sys.executable, "-c", code], **kwargs)
            children.append(child)
            return child

        def substitute(args, **kwargs):
            if args[0] == "/usr/bin/dig":
                queries.append(args)
            elif args[:4] == ["sudo", "-n", "/bin/kill", "-TERM"]:
                self.assertEqual(int(args[4]), children[0].pid)
                stops.append(children[0].pid)
                children[0].terminate()
            else:
                self.fail(f"unexpected external command: {args[0]}")
            return types.SimpleNamespace(returncode=0)

        started = time.monotonic()
        try:
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(smoke, "configured_resolver", return_value="2001:db8::53"))
                stack.enter_context(mock.patch.object(smoke.os, "geteuid", return_value=501))
                stack.enter_context(mock.patch.object(smoke.sys, "platform", "darwin"))
                stack.enter_context(mock.patch.object(smoke.sys, "argv", ["live-smoke.py"]))
                stack.enter_context(mock.patch.object(smoke, "STARTUP_TIMEOUT", startup_timeout))
                binary = stack.enter_context(mock.patch.object(smoke, "BINARY"))
                binary.is_file.return_value = True
                stack.enter_context(mock.patch.object(smoke.subprocess, "Popen", side_effect=launch))
                stack.enter_context(mock.patch.object(smoke.subprocess, "run", side_effect=substitute))
                output = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                try:
                    status = smoke.main()
                except RuntimeError:
                    status = "startup-failure"
            elapsed = time.monotonic() - started
            self.assertIsNotNone(children[0].returncode, "owned child must already be reaped")
            children[0].wait(timeout=1)
            return status, queries, stops, elapsed, output.getvalue()
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=2)
                if child.stdout:
                    child.stdout.close()

    def test_partial_startup_line_times_out_without_query_and_reaps_child(self):
        status, queries, stops, elapsed, _ = self.execute(
            "import os,time; os.write(1,b'mode=live '); time.sleep(2)")
        self.assertEqual(status, "startup-failure")
        self.assertEqual(queries, [])
        self.assertLess(elapsed, 1.5, "0.2-second startup deadline plus cleanup margin")
        self.assertEqual(len(stops), 1)

    def test_fragmented_normal_startup_preserves_following_summary(self):
        status, queries, stops, _, output = self.execute(
            "import os,time; os.write(1,b'mode=li'); time.sleep(0.03); "
            "os.write(1,b've names=false endpoints=false\\nqueries=1 unsupported=0 malformed=0 truncated=0 display_dropped=0\\n'); time.sleep(0.1)",
            startup_timeout=2)
        self.assertEqual(status, 0)
        self.assertEqual(len(queries), 1)
        self.assertEqual(stops, [])
        self.assertIn("queries=1", output)
        self.assertIn("result=observed", output)

    def test_eof_with_partial_line_never_sends_query(self):
        status, queries, _, _, _ = self.execute("import os; os.write(1,b'mode=live ')")
        self.assertEqual(status, "startup-failure")
        self.assertEqual(queries, [])

    def test_startup_output_limit_stops_and_reaps_child(self):
        status, queries, stops, _, _ = self.execute(
            "import os,time; os.write(1,b'x'*65537); time.sleep(2)", startup_timeout=2)
        self.assertEqual(status, "startup-failure")
        self.assertEqual(queries, [])
        self.assertEqual(len(stops), 1)


if __name__ == "__main__":
    unittest.main()
