"""
Traffic Control - Bandwidth limiting per WireGuard peer using tc (HTB) and u32 filters.
Limits apply to egress (download from peer's perspective = what we send to them).
Requires: tc (iproute2), root privileges.
"""
import subprocess
from flask import current_app


def _get_first_allowed_ip(allowed_ip: str) -> str | None:
    """Extract first IP from allowed_ip (e.g. '10.8.0.6/32' or '10.8.0.6, 10.8.0.8/32')."""
    if not allowed_ip or allowed_ip == "N/A":
        return None
    first = allowed_ip.replace(" ", "").split(",")[0]
    if not first:
        return None
    # Normalize to IP only for u32 match (no /32 suffix needed for single IP)
    if "/" in first:
        return first
    return first + "/32"


def _class_id_from_ip(ip: str) -> int:
    """Generate numeric classid from IP (100-65535 range for tc)."""
    h = hash(ip) % 64536
    return 100 + abs(h)


def ensure_root_qdisc(interface: str) -> bool:
    """Ensure HTB root qdisc exists on interface. Returns True on success."""
    try:
        out = subprocess.run(
            ["tc", "qdisc", "show", "dev", interface],
            capture_output=True, text=True, timeout=5
        )
        if "htb" in out.stdout and "root" in out.stdout:
            return True
        subprocess.run(
            ["tc", "qdisc", "add", "dev", interface, "root", "handle", "1:", "htb", "default", "1"],
            capture_output=True, timeout=5, check=True
        )
        subprocess.run(
            ["tc", "class", "add", "dev", interface, "parent", "1:", "classid", "1:1",
             "htb", "rate", "1000mbit", "ceil", "1000mbit"],
            capture_output=True, timeout=5, check=True
        )
        current_app.logger.info(f"[TrafficControl] Created HTB root qdisc on {interface}")
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
        current_app.logger.error(f"[TrafficControl] ensure_root_qdisc failed: {e}")
        return False


def apply_peer_limit(interface: str, allowed_ip: str, rate_down_kbit: int, rate_up_kbit: int = 0) -> bool:
    """
    Apply bandwidth limit for a peer.
    rate_down_kbit: limit for traffic we send TO peer (peer's download), in Kbit/s.
    rate_up_kbit: reserved for future (ingress limiting via ifb).
    """
    ip = _get_first_allowed_ip(allowed_ip)
    if not ip:
        return False
    if rate_down_kbit <= 0:
        remove_peer_limit(interface, allowed_ip)
        return True

    if not ensure_root_qdisc(interface):
        return False

    cid = _class_id_from_ip(ip)
    rate = f"{rate_down_kbit}kbit"

    try:
        # Remove existing class/filter for this peer
        remove_peer_limit(interface, allowed_ip)

        subprocess.run(
            ["tc", "class", "add", "dev", interface, "parent", "1:1", "classid", f"1:{cid}",
             "htb", "rate", rate, "ceil", rate],
            capture_output=True, timeout=5, check=True
        )
        # u32 match: destination IP (traffic we send to peer)
        ip_parts = ip.split("/")[0].split(".")
        if len(ip_parts) == 4:
            subprocess.run(
                ["tc", "filter", "add", "dev", interface, "parent", "1:", "protocol", "ip",
                 "prio", "1", "u32", "match", "ip", "dst", ip, "flowid", f"1:{cid}"],
                capture_output=True, timeout=5, check=True
            )
        current_app.logger.info(f"[TrafficControl] Applied limit {rate} for {ip} on {interface}")
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        current_app.logger.error(f"[TrafficControl] apply_peer_limit failed: {e}")
        return False


def remove_peer_limit(interface: str, allowed_ip: str) -> bool:
    """Remove bandwidth limit for a peer."""
    ip = _get_first_allowed_ip(allowed_ip)
    if not ip:
        return True

    cid = _class_id_from_ip(ip)

    try:
        subprocess.run(
            ["tc", "filter", "del", "dev", interface, "parent", "1:", "protocol", "ip",
             "prio", "1", "u32", "match", "ip", "dst", ip],
            capture_output=True, timeout=5
        )
        subprocess.run(
            ["tc", "class", "del", "dev", interface, "parent", "1:1", "classid", f"1:{cid}"],
            capture_output=True, timeout=5
        )
        current_app.logger.info(f"[TrafficControl] Removed limit for {ip} on {interface}")
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        current_app.logger.debug(f"[TrafficControl] remove_peer_limit: {e}")
        return True


def apply_group_limit(interface: str, peer_allowed_ips: list[str], rate_down_kbit: int, rate_up_kbit: int = 0) -> bool:
    """Apply same bandwidth limit to multiple peers (group)."""
    ok = True
    for allowed_ip in peer_allowed_ips:
        if not apply_peer_limit(interface, allowed_ip, rate_down_kbit, rate_up_kbit):
            ok = False
    return ok


def remove_all_limits(interface: str) -> bool:
    """Remove root qdisc (cleans all limits). Use when bringing interface down."""
    try:
        subprocess.run(
            ["tc", "qdisc", "del", "dev", interface, "root"],
            capture_output=True, timeout=5
        )
        current_app.logger.info(f"[TrafficControl] Removed all limits on {interface}")
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        current_app.logger.debug(f"[TrafficControl] remove_all_limits: {e}")
        return True


def is_tc_available() -> bool:
    """Check if tc is available."""
    try:
        subprocess.run(["tc", "-V"], capture_output=True, timeout=2)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
