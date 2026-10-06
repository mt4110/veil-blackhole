#!/usr/bin/env python3
"""Evaluate synthetic frames with system libpcap, without opening a device."""
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
if sys.platform != "darwin":
    raise SystemExit("This independent check requires macOS SDK and system libpcap")

dump = subprocess.check_output(
    ["cargo", "run", "--quiet", "--locked", "--example", "filter_dump"], cwd=ROOT, text=True
)
instructions = [tuple(map(int, line.split())) for line in dump.splitlines()]

def fixture(name):
    return bytes.fromhex((ROOT / "tests" / "fixtures" / name).read_text())

frame = fixture("query-a.hex")
cases = [(frame, True), (fixture("query-options.hex"), True)]
first = bytearray(frame)
first[26:30] = bytes([203, 0, 113, 1])
cases.append((bytes(first), True))
for offset, value in [(12, 0x86), (14, 0x65), (14, 0x44), (23, 6),
                      (20, 0x20), (20, 0x80), (21, 1), (29, 11), (37, 54)]:
    changed = bytearray(frame)
    changed[offset] = value
    cases.append((bytes(changed), False))
cases += [(frame[:length], False) for length in range(38)]
v6 = fixture("query-v6.hex")
cases.append((v6, True))
other = bytearray(v6)
import ipaddress
other[22:38] = ipaddress.IPv6Address("2001:db8:1::11").packed
cases.append((bytes(other), True))
for offset in [22, 26, 30, 37]:
    other = bytearray(v6)
    other[offset] ^= 1
    cases.append((bytes(other), False))
for offset, value in [(14, 0x45), (20, 0), (20, 44), (20, 6), (57, 54)]:
    other = bytearray(v6)
    other[offset] = value
    cases.append((bytes(other), False))
cases += [(v6[:length], False) for length in range(58)]

source = ["#include <pcap/pcap.h>", "#include <stdio.h>",
          "static struct bpf_insn instructions[] = {"]
source += ["{%d,%d,%d,%d}," % row for row in instructions]
source += ["};", "int main(void) {", "struct bpf_program program = {",
           "sizeof(instructions)/sizeof(instructions[0]), instructions};",
           "struct pcap_pkthdr header = {0};"]
for number, (data, accepted) in enumerate(cases):
    source += ["{", "unsigned char data[] = {" + ",".join(map(str, data or b"\x00")) + "};",
               f"header.caplen = {len(data)}; header.len = {len(data)};",
               "unsigned int result = pcap_offline_filter(&program, &header, data);",
               f"if (result != {65589 if accepted else 0}U) {{",
               f'fprintf(stderr, "case {number}: %u\\n", result); return 1; }}', "}"]
source += [f'puts("system libpcap: {len(cases)} synthetic cases passed; no live device access");',
           "return 0; }"]

output = ROOT / ".local" / "validation" / "native-filter"
output.mkdir(parents=True, exist_ok=True)
c_file, binary = output / "check.c", output / "check"
c_file.write_text("\n".join(source) + "\n")
subprocess.run(["xcrun", "clang", "-Wall", "-Wextra", "-Werror", str(c_file),
                "-lpcap", "-o", str(binary)], check=True, cwd=ROOT)
subprocess.run([str(binary)], check=True, cwd=ROOT)
