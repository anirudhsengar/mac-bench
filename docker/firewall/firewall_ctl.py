#!/usr/bin/env python3
"""Deterministic network-namespace firewall controller and packet-drop counter for the isolated agent sandbox."""

from __future__ import annotations

import ipaddress
import json
import signal
import socket
import subprocess
import sys
import time


def run_cmd(args: list[str]) -> str:
    res = subprocess.run(args, check=True, capture_output=True, text=True)
    return res.stdout


def resolve_proxy_ip(retries: int = 30) -> str:
    for _ in range(retries):
        try:
            return socket.gethostbyname("proxy")
        except OSError:
            time.sleep(0.5)
    raise RuntimeError("Could not resolve 'proxy' hostname on agent_net")


def detect_bridge_gateway_ip() -> str:
    out = run_cmd(["ip", "-4", "-j", "addr", "show", "dev", "eth0"])
    info = json.loads(out)
    for iface in info:
        for addr in iface.get("addr_info", []):
            local_ip = addr.get("local")
            prefix = addr.get("prefixlen")
            if local_ip and prefix:
                net = ipaddress.IPv4Network(f"{local_ip}/{prefix}", strict=False)
                # First usable host in Docker bridge subnet is the host's bridge interface IP
                first_host = str(next(net.hosts()))
                return first_host
    raise RuntimeError("Could not detect eth0 IPv4 subnet")


def apply_rules() -> dict[str, str]:
    proxy_ip = resolve_proxy_ip()
    host_bridge_ip = detect_bridge_gateway_ip()

    # Flush and rebuild deterministic OUTPUT + categorized block chain
    subprocess.run(["iptables", "-F", "OUTPUT"], check=True)
    subprocess.run(["iptables", "-F", "AGENT_FW_BLOCK"], check=False)
    subprocess.run(["iptables", "-X", "AGENT_FW_BLOCK"], check=False)
    subprocess.run(["iptables", "-N", "AGENT_FW_BLOCK"], check=True)

    # Default policy DROP as fail-safe
    subprocess.run(["iptables", "-P", "OUTPUT", "DROP"], check=True)

    # 1. Allow loopback (Playwright local CDP + local Unix-socket LLM bridge)
    subprocess.run(["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"], check=True)

    # 2. Allow established/related return frames for permitted flows
    subprocess.run(
        ["iptables", "-A", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        check=True,
    )

    # 3. Allow Docker embedded DNS resolver (127.0.0.11:53)
    subprocess.run(
        ["iptables", "-A", "OUTPUT", "-d", "127.0.0.11", "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
        check=True,
    )
    subprocess.run(
        ["iptables", "-A", "OUTPUT", "-d", "127.0.0.11", "-p", "tcp", "--dport", "53", "-j", "ACCEPT"],
        check=True,
    )

    # 4. Allow ONLY TCP to deterministic mediator proxy on port 8080
    subprocess.run(
        ["iptables", "-A", "OUTPUT", "-d", proxy_ip, "-p", "tcp", "--dport", "8080", "-j", "ACCEPT"],
        check=True,
    )

    # 5. Everything else goes to categorized AGENT_FW_BLOCK chain (counted + fast-rejected)
    subprocess.run(["iptables", "-A", "OUTPUT", "-j", "AGENT_FW_BLOCK"], check=True)

    # Category A: Host bridge interface access attempts
    subprocess.run(
        [
            "iptables",
            "-A",
            "AGENT_FW_BLOCK",
            "-d",
            host_bridge_ip,
            "-m",
            "comment",
            "--comment",
            "cat:host_service_access",
            "-j",
            "REJECT",
        ],
        check=True,
    )

    # Category B: Unauthorized port on proxy host
    subprocess.run(
        [
            "iptables",
            "-A",
            "AGENT_FW_BLOCK",
            "-d",
            proxy_ip,
            "-m",
            "comment",
            "--comment",
            "cat:unauthorized_proxy_port",
            "-j",
            "REJECT",
        ],
        check=True,
    )

    # Category C: Any other direct socket egress / direct target network / unauthorized port attempt
    subprocess.run(
        [
            "iptables",
            "-A",
            "AGENT_FW_BLOCK",
            "-m",
            "comment",
            "--comment",
            "cat:direct_socket_egress_or_target",
            "-j",
            "REJECT",
        ],
        check=True,
    )

    state = {"proxy_ip": proxy_ip, "host_bridge_ip": host_bridge_ip, "status": "locked"}
    with open("/tmp/fw_state.json", "w", encoding="utf-8") as f:
        json.dump(state, f)
    return state


def snapshot_counters() -> dict[str, object]:
    out = run_cmd(["iptables", "-vxnL", "AGENT_FW_BLOCK"])
    categories: dict[str, dict[str, int]] = {}
    total_packets = 0
    total_bytes = 0
    for line in out.splitlines()[2:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        pkts = int(parts[0])
        byt = int(parts[1])
        cat = "uncategorized"
        if "cat:" in line:
            after = line.split("cat:", 1)[1]
            cat = after.split()[0].strip("*/")
        categories[cat] = {"packets": pkts, "bytes": byt}
        total_packets += pkts
        total_bytes += byt

    meta = {}
    try:
        with open("/tmp/fw_state.json", encoding="utf-8") as f:
            meta = json.load(f)
    except OSError:
        pass

    return {
        "total_dropped_packets": total_packets,
        "total_dropped_bytes": total_bytes,
        "by_category": categories,
        "firewall_meta": meta,
    }


def reset_counters() -> dict[str, object]:
    subprocess.run(["iptables", "-Z", "AGENT_FW_BLOCK"], check=True)
    return snapshot_counters()


def main() -> None:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "daemon"
    if cmd == "apply":
        print(json.dumps(apply_rules()))
    elif cmd == "snapshot":
        print(json.dumps(snapshot_counters()))
    elif cmd == "reset":
        print(json.dumps(reset_counters()))
    elif cmd == "daemon":
        state = apply_rules()
        print(f"Firewall locked: {json.dumps(state)}", flush=True)
        stop = False

        def _handle(_sig: int, _frame: object) -> None:
            nonlocal stop
            stop = True

        signal.signal(signal.SIGTERM, _handle)
        signal.signal(signal.SIGINT, _handle)
        while not stop:
            time.sleep(1.0)
    else:
        raise SystemExit(f"Unknown command: {cmd}")


if __name__ == "__main__":
    main()
