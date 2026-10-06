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
                               stderr=subprocess.STDOUT, text=True, bufsize=1, close_fds=True)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + 20
            started = False
            while time.monotonic() < deadline:
                if not selector.select(timeout=0.2):
                    continue
                line = process.stdout.readline()
                if not line:
                    break
                print(line.rstrip(), flush=True)
                if line.startswith("mode=live "):
                    started = True
                    break
        if not started or process.poll() is not None:
            raise RuntimeError("取得開始を確認できません。問い合わせは送信しません")
        # Existing server only. One attempt; no TCP retry, no banner or DNS data.
        query = subprocess.run(["/usr/bin/dig", "-6", "@" + server, "example.com", "A",
                                "+notcp", "+ignore", "+tries=1", "+time=2", "+noall", "+nocmd"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        print(f"test_query_attempts=1 dig_exit={query.returncode}", flush=True)
        output, _ = process.communicate(timeout=20)
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
