#!/usr/bin/env python3
"""One bounded live check, launched by the user in their authenticated terminal.

No sudoers edits, build as root, public resolver selection, QNAME/IP output,
packet files, or raw injection. Sends one normal IPv6 UDP DNS question to an
already configured resolver after the analyzer reports successful startup.
"""
import ipaddress
import os
import pathlib
import re
import selectors
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
INTERFACE = "en0"
BINARY = ROOT / "target" / "release" / "veil-blackhole"
STARTUP_TIMEOUT = 20
MAX_STARTUP_BYTES = 64 * 1024


def configured_resolver():
    servers = re.findall(r"^nameserver\s+(\S+)", pathlib.Path("/etc/resolv.conf").read_text(), re.M)
    for server in servers:
        try:
            address = ipaddress.ip_address(server)
        except ValueError:
            continue
        if address.version != 6 or address.ipv4_mapped:
            continue
        route = subprocess.run(["/sbin/route", "-n", "get", "-inet6", server],
                               capture_output=True, text=True, timeout=3)
        interface = re.search(r"^\s*interface:\s*(\S+)", route.stdout, re.M)
        if route.returncode == 0 and interface and interface.group(1) == INTERFACE:
            return server
    raise RuntimeError("en0を通る既存IPv6リゾルバーを確認できません。問い合わせは送信しません")


def stop_capture(process):
    if process.poll() is None:
        # sudo's monitor may still be root; stop only the child PID we launched.
        subprocess.run(["sudo", "-n", "/bin/kill", "-TERM", str(process.pid)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
        process.communicate(timeout=5)


def wait_for_startup(process, timeout):
    """Read complete startup lines by deadline, retaining bytes after readiness."""
    fd = process.stdout.fileno()
    blocking = os.get_blocking(fd)
    os.set_blocking(fd, False)
    pending = bytearray()
    received = 0
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(fd, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                if not selector.select(timeout=min(0.2, remaining)):
                    continue
                try:
                    chunk = os.read(fd, 4096)
                except BlockingIOError:
                    continue
                if not chunk:
                    break
                received += len(chunk)
                if received > MAX_STARTUP_BYTES:
                    raise RuntimeError("取得開始前の出力が上限を超えました。問い合わせは送信しません")
                pending.extend(chunk)
                while b"\n" in pending:
                    line, _, rest = pending.partition(b"\n")
                    pending = bytearray(rest)
                    print(line.decode("utf-8", errors="replace").rstrip(), flush=True)
                    if line.startswith(b"mode=live "):
                        return bytes(pending)
    finally:
        os.set_blocking(fd, blocking)
    raise RuntimeError("取得開始を期限内に確認できません。問い合わせは送信しません")


def main():
    if sys.platform != "darwin" or os.geteuid() == 0:
        raise RuntimeError("macOSの一般ユーザーで起動してください。script自体にsudoは付けません")
    if len(sys.argv) > 1 and sys.argv[1:] != ["--check"]:
        raise RuntimeError("引数は--checkのみ指定できます")
    server = configured_resolver()
    print("preflight interface=en0 resolver_transport=IPv6 names=false endpoints=false", flush=True)
    if sys.argv[1:] == ["--check"]:
        print("preflightのみ完了。device open・query送信なし")
        return 0
    if not BINARY.is_file():
        raise RuntimeError("release binaryがありません。一般ユーザーでcargo build --locked --releaseを実行してください")
    # Same controlling terminal preserves normal per-TTY sudo caching. All FDs
    # except stdio are closed in the child; no credential is read by this script.
    process = subprocess.Popen(["sudo", "-n", str(BINARY), "capture", "--interface", INTERFACE,
                                "--duration", "10"], stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, bufsize=0, close_fds=True)
    try:
        pending = wait_for_startup(process, STARTUP_TIMEOUT)
        if process.poll() is not None:
            raise RuntimeError("取得開始を確認できません。問い合わせは送信しません")
        # Existing server only. One attempt; no TCP retry, no banner or DNS data.
        query = subprocess.run(["/usr/bin/dig", "-6", "@" + server, "example.com", "A",
                                "+notcp", "+ignore", "+tries=1", "+time=2", "+noall", "+nocmd"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        print(f"test_query_attempts=1 dig_exit={query.returncode}", flush=True)
        rest, _ = process.communicate(timeout=20)
        output = (pending + rest).decode("utf-8", errors="replace")
        print(output, end="", flush=True)
        print(f"capture_exit={process.returncode}", flush=True)
        counts = re.search(r"^queries=(\d+) .*malformed=(\d+) truncated=(\d+)", output, re.M)
        if process.returncode == 0 and counts and int(counts.group(1)) > 0 and counts.group(2, 3) == ("0", "0"):
            print("result=observed（実DNSのread・デコードを確認。queryの個別同定はしていません）")
            return 0
        print("result=unconfirmed（集計結果から追加の切り分けが必要）")
        return 1
    finally:
        stop_capture(process)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("停止要求を受けました", file=sys.stderr)
        sys.exit(130)
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as error:
        # TimeoutExpired includes the resolver in argv; do not echo that object.
        message = str(error) if isinstance(error, RuntimeError) else "OS操作または待機に失敗しました"
        print(message, file=sys.stderr)
        sys.exit(2)
