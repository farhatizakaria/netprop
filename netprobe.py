#!/usr/bin/env python3
"""
NetProbe — Network & Traffic Troubleshooting Toolkit
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Smart CLI/TUI tool for IT Technicians.
Primary: Windows  |  Supported: Linux / macOS
"""

__version__ = "1.0.0"

import platform
import subprocess
import socket
import os
import sys
import re
import time
import json
import ipaddress
from collections import Counter
from datetime import datetime
from typing import Optional, List, Dict, Tuple, Generator
import concurrent.futures
import threading

# ── third-party ───────────────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table   import Table
    from rich.panel   import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.prompt  import Prompt, Confirm, IntPrompt
    from rich.text    import Text
    from rich.rule    import Rule
    from rich.live    import Live
    from rich.align   import Align
    from rich         import box
    import psutil
    import requests
except ImportError as e:
    print(f"\n[!] Missing package: {e}")
    print("    Run setup.bat (Windows) / setup.sh (Linux), or:")
    print("    pip install rich psutil requests\n")
    sys.exit(1)

try:
    import dns.resolver as _dns
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

console = Console()

# ── OS detection ──────────────────────────────────────────────────────────────
OS     = platform.system()   # 'Windows' | 'Linux' | 'Darwin'
IS_WIN = OS == 'Windows'
IS_LIN = OS == 'Linux'
IS_MAC = OS == 'Darwin'

# ─────────────────────────────────────────────────────────────────────────────
# COMMON PORT REGISTRY
# ─────────────────────────────────────────────────────────────────────────────
COMMON_PORTS: Dict[int, str] = {
    21: 'FTP',      22: 'SSH',       23: 'Telnet',   25: 'SMTP',
    53: 'DNS',      80: 'HTTP',     110: 'POP3',    135: 'RPC',
   139: 'NetBIOS', 143: 'IMAP',    161: 'SNMP',    389: 'LDAP',
   443: 'HTTPS',   445: 'SMB',     514: 'Syslog',  587: 'SMTPS',
   636: 'LDAPS',   993: 'IMAPS',   995: 'POP3S',  1433: 'MSSQL',
  1521: 'Oracle', 3306: 'MySQL',  3389: 'RDP',    5432: 'PostgreSQL',
  5900: 'VNC',    6379: 'Redis',  8080: 'HTTP-Alt',8443: 'HTTPS-Alt',
 27017: 'MongoDB',
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ENVIRONMENT DISCOVERY
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class Environment:
    """Auto-discovers the local network environment on startup."""

    def __init__(self) -> None:
        self.platform     = OS
        self.os_release   = platform.release()
        self.os_version   = platform.version()
        self.architecture = platform.machine()
        self.python_ver   = platform.python_version()
        self.hostname     = socket.gethostname()
        self.is_admin     = self._detect_admin()
        self.interfaces   = self._get_interfaces()
        self.default_gw   = self._get_default_gateway()
        self.dns_servers  = self._get_dns_servers()
        self._public_ip   = None          # lazy-loaded
        self.discovered   = datetime.now()

    # ── privilege detection ──────────────────────────────────────────────────
    def _detect_admin(self) -> bool:
        try:
            if IS_WIN:
                import ctypes
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            return os.geteuid() == 0
        except Exception:
            return False

    # ── network interfaces ───────────────────────────────────────────────────
    def _get_interfaces(self) -> Dict[str, Dict]:
        result = {}
        addrs  = psutil.net_if_addrs()
        stats  = psutil.net_if_stats()

        for name, addr_list in addrs.items():
            info: Dict = {
                'ipv4': [], 'ipv6': [], 'mac': 'N/A',
                'is_up': False, 'speed': 0, 'mtu': 0,
            }
            if name in stats:
                s = stats[name]
                info.update(is_up=s.isup, speed=s.speed, mtu=s.mtu)

            for addr in addr_list:
                if addr.family == socket.AF_INET:
                    info['ipv4'].append({
                        'address':   addr.address,
                        'netmask':   addr.netmask   or 'N/A',
                        'broadcast': addr.broadcast or 'N/A',
                    })
                elif addr.family == socket.AF_INET6:
                    info['ipv6'].append(addr.address.split('%')[0])
                elif addr.family == psutil.AF_LINK:
                    info['mac'] = addr.address or 'N/A'

            result[name] = info
        return result

    # ── default gateway ──────────────────────────────────────────────────────
    def _get_default_gateway(self) -> Optional[str]:
        try:
            if IS_WIN:
                out = subprocess.check_output(
                    ['route', 'print', '0.0.0.0'], text=True, timeout=5,
                    stderr=subprocess.DEVNULL, encoding='utf-8', errors='ignore',
                )
                for line in out.splitlines():
                    parts = line.split()
                    if parts and parts[0] == '0.0.0.0' and len(parts) >= 3:
                        gw = parts[2]
                        if gw != '0.0.0.0':
                            return gw
            else:
                out = subprocess.check_output(
                    ['ip', 'route', 'show', 'default'], text=True, timeout=5,
                    stderr=subprocess.DEVNULL,
                )
                m = re.search(r'default via (\S+)', out)
                if m:
                    return m.group(1)
        except Exception:
            pass

        # Fallback: UDP trick to find outbound source
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(('8.8.8.8', 80))
                local_ip = s.getsockname()[0]
            parts = local_ip.split('.')
            parts[-1] = '1'
            return '.'.join(parts)
        except Exception:
            return None

    # ── DNS servers ──────────────────────────────────────────────────────────
    def _get_dns_servers(self) -> List[str]:
        servers: List[str] = []
        try:
            if HAS_DNS:
                r = _dns.Resolver()
                return list(r.nameservers)[:4]
            if IS_WIN:
                out = subprocess.check_output(
                    ['ipconfig', '/all'], text=True, timeout=5,
                    stderr=subprocess.DEVNULL, encoding='utf-8', errors='ignore',
                )
                in_dns = False
                for line in out.splitlines():
                    if 'DNS Servers' in line:
                        in_dns = True
                    if in_dns:
                        m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
                        if m:
                            ip = m.group(1)
                            if ip not in servers:
                                servers.append(ip)
                        # Stop when we hit a new labelled field
                        if ':' in line and 'DNS Servers' not in line:
                            in_dns = False
            else:
                with open('/etc/resolv.conf') as f:
                    for line in f:
                        if line.startswith('nameserver'):
                            servers.append(line.split()[1])
        except Exception:
            pass
        return servers[:4]

    # ── public IP (lazy) ─────────────────────────────────────────────────────
    @property
    def public_ip(self) -> str:
        if self._public_ip is None:
            for url in [
                'https://api.ipify.org?format=json',
                'https://api4.my-ip.io/v2/ip.json',
            ]:
                try:
                    r = requests.get(url, timeout=5)
                    data = r.json()
                    self._public_ip = data.get('ip') or data.get('IP', 'N/A')
                    break
                except Exception:
                    pass
            if self._public_ip is None:
                self._public_ip = 'Unavailable'
        return self._public_ip

    def primary_interface(self) -> Optional[str]:
        """Return the name of the active outbound interface."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(('8.8.8.8', 80))
                local_ip = s.getsockname()[0]
            for name, info in self.interfaces.items():
                for v4 in info['ipv4']:
                    if v4['address'] == local_ip:
                        return name
        except Exception:
            pass
        return None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# NETWORK DIAGNOSTIC FUNCTIONS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def resolve_host(host: str) -> Optional[str]:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


# ── Ping ─────────────────────────────────────────────────────────────────────
def do_ping(host: str, count: int = 4, timeout: int = 2) -> Dict:
    try:
        if IS_WIN:
            cmd = ['ping', '-n', str(count), '-w', str(timeout * 1000), host]
        else:
            cmd = ['ping', '-c', str(count), '-W', str(timeout), host]

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30,
            encoding='utf-8', errors='ignore',
        )
        output = result.stdout + result.stderr

        latencies: List[float] = []
        if IS_WIN:
            latencies = [int(m) for m in re.findall(r'time[=<](\d+)ms', output, re.I)]
            loss_m = re.search(r'(\d+)%\s+loss', output, re.I)
        else:
            latencies = [float(m) for m in re.findall(r'time=(\d+\.?\d*)\s*ms', output, re.I)]
            loss_m = re.search(r'(\d+)%\s+packet loss', output, re.I)

        loss = int(loss_m.group(1)) if loss_m else 100

        return {
            'host':      host,
            'resolved':  resolve_host(host),
            'sent':      count,
            'received':  len(latencies),
            'loss_pct':  loss,
            'latencies': latencies,
            'min_ms':    round(min(latencies), 2)                      if latencies else None,
            'max_ms':    round(max(latencies), 2)                      if latencies else None,
            'avg_ms':    round(sum(latencies) / len(latencies), 2)    if latencies else None,
            'success':   loss < 100,
            'raw':       output,
        }
    except subprocess.TimeoutExpired:
        return {'host': host, 'success': False, 'error': 'Command timed out', 'latencies': []}
    except Exception as e:
        return {'host': host, 'success': False, 'error': str(e), 'latencies': []}


# ── Traceroute ────────────────────────────────────────────────────────────────
def do_traceroute(host: str, max_hops: int = 30) -> Generator[Dict, None, None]:
    """Stream traceroute hops as they arrive."""
    try:
        if IS_WIN:
            cmd = ['tracert', '-d', '-h', str(max_hops), '-w', '2000', host]
        else:
            cmd = ['traceroute', '-n', '-m', str(max_hops), '-w', '2', host]

        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding='utf-8', errors='ignore',
        )

        for line in proc.stdout:  # type: ignore[union-attr]
            hop_m = re.match(r'^\s*(\d+)', line)
            if not hop_m:
                continue
            hop_num = int(hop_m.group(1))
            ips     = re.findall(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
            times   = re.findall(r'(\d+\.?\d*)\s*ms', line, re.I)
            rtts    = [float(t) for t in times]
            ip      = ips[0] if ips else '*'

            # Reverse DNS (best-effort, don't block)
            hostname = ip
            if ip != '*':
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except Exception:
                    hostname = ip

            yield {
                'hop':      hop_num,
                'ip':       ip,
                'hostname': hostname,
                'rtts':     rtts,
                'avg':      round(sum(rtts) / len(rtts), 1) if rtts else None,
                'timeout':  ip == '*',
            }

        proc.wait()

    except FileNotFoundError:
        yield {
            'hop': 1, 'ip': 'ERROR',
            'hostname': 'tracert/traceroute not found — install it first',
            'rtts': [], 'avg': None, 'timeout': True,
        }
    except Exception as e:
        yield {
            'hop': 1, 'ip': 'ERROR',
            'hostname': str(e),
            'rtts': [], 'avg': None, 'timeout': True,
        }


# ── Port Scanner ─────────────────────────────────────────────────────────────
def _scan_port(host: str, port: int, timeout: float) -> Tuple[int, bool, str]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                banner = ''
                try:
                    s.settimeout(0.3)
                    banner = s.recv(256).decode('utf-8', errors='ignore').strip()[:80]
                except Exception:
                    pass
                return (port, True, banner)
    except Exception:
        pass
    return (port, False, '')


def do_port_scan(
    host: str, ports: List[int], timeout: float = 1.0, workers: int = 100
) -> List[Dict]:
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_scan_port, host, p, timeout): p for p in ports}
        for fut in concurrent.futures.as_completed(futs):
            port, is_open, banner = fut.result()
            results.append({
                'port':    port,
                'open':    is_open,
                'service': COMMON_PORTS.get(port, 'Unknown'),
                'banner':  banner,
            })
    return sorted(results, key=lambda x: x['port'])


# ── DNS Lookup ────────────────────────────────────────────────────────────────
def do_dns_lookup(
    host: str,
    record_types: Optional[List[str]] = None,
    server: Optional[str] = None,
) -> Dict[str, List[str]]:

    if record_types is None:
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']

    results: Dict[str, List[str]] = {}

    if HAS_DNS:
        resolver = _dns.Resolver()
        if server:
            resolver.nameservers = [server]
        for rtype in record_types:
            try:
                answers = resolver.resolve(host, rtype)
                results[rtype] = [str(r) for r in answers]
            except _dns.NoAnswer:
                results[rtype] = []
            except _dns.NXDOMAIN:
                results[rtype] = ['[red]NXDOMAIN — host not found[/]']
            except Exception as e:
                results[rtype] = [f'[dim]Error: {e}[/]']
    else:
        # Basic fallback via stdlib
        try:
            ip = socket.gethostbyname(host)
            results['A'] = [ip]
        except Exception as e:
            results['A'] = [str(e)]
        results['_note'] = ['[yellow]dnspython not installed — only A records available[/]']

    return results


def do_reverse_dns(ip: str) -> Optional[str]:
    try:
        if HAS_DNS:
            return str(_dns.resolve_address(ip)[0])
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


# ── ARP Table ─────────────────────────────────────────────────────────────────
def get_arp_table() -> List[Dict]:
    entries: List[Dict] = []
    try:
        if IS_WIN:
            out = subprocess.check_output(
                ['arp', '-a'], text=True, timeout=5,
                encoding='utf-8', errors='ignore',
            )
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
                    entries.append({
                        'ip':   parts[0],
                        'mac':  parts[1] if len(parts) > 1 else 'N/A',
                        'type': parts[2] if len(parts) > 2 else 'dynamic',
                    })
        else:
            # Try /proc/net/arp first (no external binary needed)
            try:
                with open('/proc/net/arp') as f:
                    for line in f.readlines()[1:]:
                        parts = line.split()
                        if len(parts) >= 4 and parts[3] != '00:00:00:00:00:00':
                            entries.append({'ip': parts[0], 'mac': parts[3], 'type': 'dynamic'})
            except FileNotFoundError:
                out = subprocess.check_output(
                    ['arp', '-n'], text=True, timeout=5, stderr=subprocess.DEVNULL,
                )
                for line in out.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 3:
                        entries.append({'ip': parts[0], 'mac': parts[2], 'type': 'dynamic'})
    except Exception:
        pass
    return entries


# ── Routing Table ─────────────────────────────────────────────────────────────
def get_routing_table() -> List[Dict]:
    routes: List[Dict] = []
    try:
        if IS_WIN:
            out = subprocess.check_output(
                ['route', 'print', '-4'], text=True, timeout=5,
                encoding='utf-8', errors='ignore',
            )
            in_section = False
            for line in out.splitlines():
                if 'Active Routes' in line:
                    in_section = True
                    continue
                if 'Persistent Routes' in line:
                    break
                if in_section:
                    parts = line.split()
                    if len(parts) >= 5 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
                        routes.append({
                            'destination': parts[0],
                            'netmask':     parts[1],
                            'gateway':     parts[2],
                            'interface':   parts[3],
                            'metric':      parts[4],
                        })
        else:
            out = subprocess.check_output(
                ['ip', 'route'], text=True, timeout=5, stderr=subprocess.DEVNULL,
            )
            for line in out.splitlines():
                parts = line.split()
                if not parts:
                    continue
                dest = parts[0]
                gw   = parts[parts.index('via') + 1] if 'via' in parts else 'direct'
                dev  = parts[parts.index('dev') + 1] if 'dev' in parts else ''
                met  = parts[parts.index('metric') + 1] if 'metric' in parts else ''
                routes.append({
                    'destination': dest,
                    'netmask':     '',
                    'gateway':     gw,
                    'interface':   dev,
                    'metric':      met,
                })
    except Exception:
        pass
    return routes


# ── Active Connections ────────────────────────────────────────────────────────
def get_active_connections(kind: str = 'inet') -> List[Dict]:
    conns: List[Dict] = []
    try:
        for c in psutil.net_connections(kind=kind):
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ''
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ''
            pid   = c.pid or 0
            name  = ''
            if pid:
                try:
                    name = psutil.Process(pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            conns.append({
                'proto':  'TCP' if c.type == socket.SOCK_STREAM else 'UDP',
                'laddr':  laddr,
                'raddr':  raddr,
                'status': c.status or '',
                'pid':    pid,
                'name':   name,
            })
    except psutil.AccessDenied:
        console.print('[yellow]Note: Run as admin for full connection details.[/]')
    except Exception:
        pass
    return conns


# ── HTTP/HTTPS Test ───────────────────────────────────────────────────────────
def do_http_test(url: str) -> Dict:
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    result: Dict = {'url': url, 'success': False}
    try:
        t0 = time.time()
        r  = requests.get(
            url, timeout=10, allow_redirects=True,
            headers={'User-Agent': 'NetProbe/1.0'},
        )
        elapsed = round((time.time() - t0) * 1000, 1)
        code = r.status_code
        result.update({
            'success':      True,
            'status_code':  code,
            'reason':       r.reason,
            'elapsed_ms':   elapsed,
            'final_url':    r.url,
            'server':       r.headers.get('Server',         'N/A'),
            'content_type': r.headers.get('Content-Type',   'N/A'),
            'content_len':  r.headers.get('Content-Length', 'N/A'),
            'ssl':          r.url.startswith('https://'),
        })
    except requests.exceptions.SSLError as e:
        result['error'] = f'SSL Error: {e}'
    except requests.exceptions.ConnectionError as e:
        result['error'] = f'Connection failed: {e}'
    except requests.exceptions.Timeout:
        result['error'] = 'Request timed out (>10 s)'
    except Exception as e:
        result['error'] = str(e)
    return result


# ── Interface Stats ───────────────────────────────────────────────────────────
def get_iface_stats() -> Dict[str, Dict]:
    return {
        name: {
            'bytes_sent': c.bytes_sent,  'bytes_recv': c.bytes_recv,
            'pkts_sent':  c.packets_sent,'pkts_recv':  c.packets_recv,
            'errs_in':    c.errin,       'errs_out':   c.errout,
            'drop_in':    c.dropin,      'drop_out':   c.dropout,
        }
        for name, c in psutil.net_io_counters(pernic=True).items()
    }


# ── Bandwidth Monitor ─────────────────────────────────────────────────────────
def do_bandwidth_monitor(iface: Optional[str], duration: int = 15) -> None:
    def _fmt(b: float) -> str:
        for unit in ['B/s', 'KB/s', 'MB/s', 'GB/s']:
            if b < 1024.0:
                return f"{b:6.1f} {unit}"
            b /= 1024.0
        return f"{b:6.1f} TB/s"

    t = Table(box=box.SIMPLE_HEAVY, expand=False)
    t.add_column("Time",       width=6,  style="dim")
    t.add_column("Interface",  min_width=16, style="cyan")
    t.add_column("↓ Recv/s",   justify="right", style="green",  min_width=14)
    t.add_column("↑ Sent/s",   justify="right", style="yellow", min_width=14)
    t.add_column("Pkts ↓/s",  justify="right")
    t.add_column("Pkts ↑/s",  justify="right")

    console.print(f"[dim]Monitoring {iface or 'all interfaces'} for {duration}s — Ctrl+C to stop[/]")

    prev = psutil.net_io_counters(pernic=True)
    with Live(t, refresh_per_second=2, console=console):
        try:
            for i in range(1, duration + 1):
                time.sleep(1)
                curr = psutil.net_io_counters(pernic=True)
                first = True
                for name in sorted(curr):
                    if iface and name != iface:
                        continue
                    if name not in prev:
                        continue
                    s, p = curr[name], prev[name]
                    dr  = max(s.bytes_recv   - p.bytes_recv,   0)
                    ds  = max(s.bytes_sent   - p.bytes_sent,   0)
                    dpr = max(s.packets_recv - p.packets_recv, 0)
                    dps = max(s.packets_sent - p.packets_sent, 0)
                    t.add_row(
                        f"+{i:02d}s" if first else "",
                        name,
                        _fmt(dr), _fmt(ds),
                        str(dpr), str(dps),
                    )
                    first = False
                prev = curr
        except KeyboardInterrupt:
            pass
    console.print()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# REPORT GENERATION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def generate_full_report(env: Environment) -> str:
    ts    = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    lines = [
        "=" * 60,
        f"  NetProbe Full Diagnostic Report",
        f"  Generated : {ts}",
        "=" * 60,
    ]

    lines += [
        "\n[SYSTEM]",
        f"  Hostname  : {env.hostname}",
        f"  Platform  : {env.platform} {env.os_release}",
        f"  OS Detail : {env.os_version[:80]}",
        f"  Arch      : {env.architecture}",
        f"  Python    : {env.python_ver}",
        f"  Admin     : {env.is_admin}",
        f"  Gateway   : {env.default_gw or 'Unknown'}",
        f"  DNS       : {', '.join(env.dns_servers) or 'None found'}",
        f"  Public IP : {env.public_ip}",
    ]

    lines.append("\n[INTERFACES]")
    for name, info in env.interfaces.items():
        state = 'UP' if info['is_up'] else 'DOWN'
        for v4 in info['ipv4']:
            lines.append(
                f"  {name:<22} {state:<5} {v4['address']:<18}"
                f" mask={v4['netmask']:<18} mac={info['mac']}"
            )
        if not info['ipv4']:
            lines.append(f"  {name:<22} {state:<5} (no IPv4)  mac={info['mac']}")

    lines.append("\n[PING TESTS]")
    test_hosts = list(filter(None, ['8.8.8.8', '1.1.1.1', env.default_gw]))
    for host in test_hosts:
        r = do_ping(host, count=4)
        lines.append(
            f"  {host:<20}  loss={r.get('loss_pct', 100):3d}%"
            f"  avg={str(r.get('avg_ms', 'N/A')):>8} ms"
            f"  min={str(r.get('min_ms', 'N/A')):>8} ms"
            f"  max={str(r.get('max_ms', 'N/A')):>8} ms"
        )

    lines.append("\n[DNS RESOLUTION]")
    for host in ['google.com', 'microsoft.com', 'cloudflare.com']:
        r = do_dns_lookup(host, ['A'])
        lines.append(f"  {host:<25}  A={r.get('A', ['N/A'])}")

    lines.append("\n[LOCAL OPEN PORTS]")
    local_scan = do_port_scan('127.0.0.1', list(COMMON_PORTS.keys()), timeout=0.5)
    open_ports = [r for r in local_scan if r['open']]
    if open_ports:
        for r in open_ports:
            lines.append(f"  {r['port']:<6} {r['service']}")
    else:
        lines.append("  (none found)")

    lines.append("\n[ARP TABLE]")
    for e in get_arp_table()[:20]:
        lines.append(f"  {e['ip']:<18} {e['mac']}")

    lines.append("\n[ACTIVE CONNECTIONS SUMMARY]")
    conns = get_active_connections()
    for status, count in sorted(Counter(c['status'] for c in conns).items()):
        lines.append(f"  {status:<18} {count}")

    lines.append("\n[ROUTING TABLE]")
    for r in get_routing_table()[:15]:
        lines.append(
            f"  {r.get('destination',''):<20}"
            f"  gw={r.get('gateway',''):<18}"
            f"  if={r.get('interface','')}"
        )

    lines += ['', '=' * 60, f'  End of Report — {ts}', '=' * 60]
    return '\n'.join(lines)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# UI / DISPLAY HELPERS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _bytes_fmt(b: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b //= 1024
    return f"{b} TB"


def print_banner(env: Environment) -> None:
    admin = "[bold green]● ADMIN[/]" if env.is_admin else "[bold yellow]● USER[/]"
    console.print(Panel(
        f"[bold cyan]NetProbe[/bold cyan] [dim]v{__version__}[/dim]"
        f"  —  Network & Traffic Troubleshooter\n"
        f"[dim]Host:[/dim] [bold]{env.hostname}[/bold]   "
        f"[dim]OS:[/dim] {env.platform} {env.os_release}   "
        f"[dim]Arch:[/dim] {env.architecture}   "
        f"{admin}",
        border_style="cyan",
        expand=False,
    ))


def show_menu() -> None:
    console.print(Rule("[bold cyan]Main Menu[/]"))
    items = [
        (" 1", "System & Network Overview"),
        (" 2", "Ping Test"),
        (" 3", "DNS Lookup"),
        (" 4", "Traceroute"),
        (" 5", "Port Scanner"),
        (" 6", "Active Connections"),
        (" 7", "Interface Statistics"),
        (" 8", "ARP Table"),
        (" 9", "Routing Table"),
        ("10", "HTTP / HTTPS Connectivity Test"),
        ("11", "Live Bandwidth Monitor"),
        ("12", "Generate Full Diagnostic Report"),
        (" 0", "Exit"),
    ]
    for num, label in items:
        col = "red" if num.strip() == "0" else "cyan"
        console.print(f"  [{col}][{num}][/{col}]  {label}")
    console.print()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DISPLAY FUNCTIONS (one per tool)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def display_overview(env: Environment) -> None:
    console.print(Rule("[bold]System & Network Overview[/]"))

    # System info table
    st = Table(box=box.ROUNDED, show_header=False, border_style="dim")
    st.add_column("Field", style="bold cyan", no_wrap=True)
    st.add_column("Value")
    st.add_row("Hostname",     env.hostname)
    st.add_row("Platform",     f"{env.platform} {env.os_release}")
    st.add_row("OS Detail",    env.os_version[:90])
    st.add_row("Architecture", env.architecture)
    st.add_row("Python",       env.python_ver)
    st.add_row("Admin/Root",   "[bold green]Yes[/]" if env.is_admin else "[bold yellow]No[/]")
    st.add_row("Default GW",   env.default_gw or "[red]Not detected[/]")
    st.add_row("DNS Servers",  (', '.join(env.dns_servers)) or "[red]None found[/]")
    console.print(Panel(st, title="System", border_style="cyan"))

    # Interfaces table
    it = Table(box=box.ROUNDED, border_style="dim", show_lines=True)
    it.add_column("Interface", style="cyan bold")
    it.add_column("Status",    justify="center", width=6)
    it.add_column("IPv4",      style="green")
    it.add_column("Netmask")
    it.add_column("Broadcast", style="dim")
    it.add_column("MAC",       style="dim")
    it.add_column("Speed",     justify="right")
    it.add_column("MTU",       justify="right")

    for name, info in env.interfaces.items():
        status  = "[bold green]UP[/]" if info['is_up'] else "[bold red]DOWN[/]"
        speed   = f"{info['speed']} Mbps" if info['speed'] > 0 else "N/A"
        ipv4s   = info['ipv4']
        entries = ipv4s if ipv4s else [{'address': '—', 'netmask': '—', 'broadcast': '—'}]
        for i, v4 in enumerate(entries):
            it.add_row(
                name     if i == 0 else "",
                status   if i == 0 else "",
                v4['address'],
                v4['netmask'],
                v4['broadcast'],
                info['mac'] if i == 0 else "",
                speed    if i == 0 else "",
                str(info['mtu']) if i == 0 else "",
            )

    console.print(Panel(it, title="Network Interfaces", border_style="cyan"))

    with console.status("Fetching public IP…", spinner="dots"):
        pub = env.public_ip
    console.print(f"  [bold cyan]Public IP:[/] {pub}\n")


def display_ping(host: str, count: int) -> None:
    console.print(Rule(f"[bold]Ping — {host}[/]"))
    with console.status(f"Pinging {host} ({count} packets)…", spinner="dots"):
        res = do_ping(host, count)

    ip = res.get('resolved')
    if ip is None:
        console.print(f"[bold red]Cannot resolve host:[/] {host}\n")
        return

    loss = res.get('loss_pct', 100)
    lc   = "bold green" if loss == 0 else ("yellow" if loss < 50 else "bold red")

    t = Table(box=box.ROUNDED, border_style="dim")
    t.add_column("Host",    style="cyan")
    t.add_column("IP",      style="green")
    t.add_column("Sent",    justify="right")
    t.add_column("Recv",    justify="right")
    t.add_column("Loss",    justify="right")
    t.add_column("Min ms",  justify="right")
    t.add_column("Avg ms",  justify="right")
    t.add_column("Max ms",  justify="right")

    t.add_row(
        host, ip,
        str(res.get('sent', count)),
        str(res.get('received', 0)),
        f"[{lc}]{loss}%[/]",
        str(res.get('min_ms') or "—"),
        str(res.get('avg_ms') or "—"),
        str(res.get('max_ms') or "—"),
    )
    console.print(t)
    if not res['success']:
        console.print("[bold red]Host unreachable.[/]")
    console.print()


def display_traceroute(host: str, max_hops: int) -> None:
    console.print(Rule(f"[bold]Traceroute — {host}[/]"))
    console.print("[dim]Tracing route… Ctrl+C to stop[/]\n")

    t = Table(box=box.SIMPLE_HEAVY, border_style="dim")
    t.add_column("Hop",      justify="right", width=4, style="bold")
    t.add_column("IP",       style="cyan",    min_width=16)
    t.add_column("Hostname", style="dim",     min_width=28, overflow="fold")
    t.add_column("RTT 1",    justify="right")
    t.add_column("RTT 2",    justify="right")
    t.add_column("RTT 3",    justify="right")
    t.add_column("Avg ms",   justify="right")

    with Live(t, refresh_per_second=4, console=console):
        try:
            for hop in do_traceroute(host, max_hops):
                ip   = hop['ip']
                hn   = hop['hostname']
                rtts = hop.get('rtts', [])
                avg  = hop.get('avg')

                if hop['timeout'] or ip == '*':
                    col, avg_s = "dim", "—"
                elif avg is not None and avg < 20:
                    col, avg_s = "green",  str(avg)
                elif avg is not None and avg < 80:
                    col, avg_s = "yellow", str(avg)
                else:
                    col, avg_s = "red",    str(avg) if avg else "—"

                rtt_cells = [f"[{col}]{r}[/]" for r in rtts[:3]]
                while len(rtt_cells) < 3:
                    rtt_cells.append("[dim]—[/]")

                t.add_row(
                    str(hop['hop']),
                    f"[{col}]{ip}[/]" if ip != '*' else "[dim]*[/]",
                    hn if hn != ip else "[dim]—[/]",
                    *rtt_cells,
                    f"[{col}]{avg_s}[/]",
                )
        except KeyboardInterrupt:
            pass
    console.print()


def display_port_scan(host: str, ports: List[int]) -> None:
    console.print(Rule(f"[bold]Port Scan — {host}[/]"))
    ip = resolve_host(host)
    if not ip:
        console.print(f"[bold red]Cannot resolve host:[/] {host}\n")
        return
    console.print(f"  Target: [cyan]{host}[/]  IP: [green]{ip}[/]  Ports to scan: [bold]{len(ports)}[/]\n")

    results: List[Tuple[int, bool, str]] = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total} ports"),
        console=console, transient=True,
    ) as progress:
        task = progress.add_task("Scanning…", total=len(ports))
        with concurrent.futures.ThreadPoolExecutor(max_workers=150) as ex:
            futs = {ex.submit(_scan_port, ip, p, 1.0): p for p in ports}
            for fut in concurrent.futures.as_completed(futs):
                results.append(fut.result())
                progress.advance(task)

    results.sort(key=lambda x: x[0])
    open_r = [r for r in results if r[1]]

    if open_r:
        t = Table(box=box.ROUNDED, border_style="dim")
        t.add_column("Port",    justify="right", style="cyan")
        t.add_column("State",   justify="center")
        t.add_column("Service", style="green")
        t.add_column("Banner",  style="dim", overflow="fold")
        for port, _, banner in open_r:
            t.add_row(
                str(port),
                "[bold green]OPEN[/]",
                COMMON_PORTS.get(port, "Unknown"),
                banner or "—",
            )
        console.print(t)
        console.print(f"\n  [bold green]{len(open_r)}[/] open port(s) found out of {len(ports)} scanned.")
    else:
        console.print("  [yellow]No open ports found.[/]")
    console.print()


def display_dns(host: str, server: Optional[str]) -> None:
    console.print(Rule(f"[bold]DNS Lookup — {host}[/]"))
    if server:
        console.print(f"  Using DNS server: [cyan]{server}[/]\n")

    with console.status("Querying DNS…", spinner="dots"):
        results = do_dns_lookup(host, server=server)

    t = Table(box=box.ROUNDED, border_style="dim")
    t.add_column("Type",    style="cyan bold", width=8)
    t.add_column("Records", overflow="fold")

    for rtype, records in results.items():
        if records:
            t.add_row(rtype, '\n'.join(records))

    console.print(t)

    # Reverse DNS for A records
    a = [ip for ip in results.get('A', []) if re.match(r'\d+\.\d+\.\d+\.\d+', ip)]
    if a:
        rt = Table(box=box.SIMPLE, show_header=False, border_style="dim")
        rt.add_column("IP",       style="cyan")
        rt.add_column("Reverse",  style="dim")
        for ip in a[:5]:
            rt.add_row(ip, do_reverse_dns(ip) or "—")
        console.print(Panel(rt, title="Reverse DNS", border_style="dim"))
    console.print()


def display_connections(status_filter: Optional[str]) -> None:
    console.print(Rule("[bold]Active Connections[/]"))
    with console.status("Fetching connections…", spinner="dots"):
        conns = get_active_connections()

    if status_filter:
        conns = [c for c in conns if c['status'].upper() == status_filter.upper()]

    STATUS_COLORS = {
        'ESTABLISHED': 'bold green', 'LISTEN': 'cyan',
        'TIME_WAIT':   'yellow',     'CLOSE_WAIT': 'yellow',
        'SYN_SENT':    'magenta',    'CLOSED': 'dim',
        'FIN_WAIT1':   'yellow',     'FIN_WAIT2': 'yellow',
    }

    t = Table(box=box.ROUNDED, border_style="dim")
    t.add_column("Proto",  style="cyan",  width=5)
    t.add_column("Local Address",  min_width=22)
    t.add_column("Remote Address", min_width=22, style="green")
    t.add_column("Status",  width=14)
    t.add_column("PID",    justify="right", width=7)
    t.add_column("Process", style="dim")

    for c in conns:
        sc = STATUS_COLORS.get(c['status'].upper(), 'white')
        t.add_row(
            c['proto'],
            c['laddr'],
            c['raddr'] or "[dim]—[/]",
            f"[{sc}]{c['status']}[/]",
            str(c['pid']) if c['pid'] else "—",
            c['name'] or "—",
        )

    console.print(t)
    summary = Counter(c['status'] for c in conns)
    parts   = [f"[cyan]{s}[/]:[bold]{n}[/]" for s, n in sorted(summary.items())]
    console.print(f"  Total: [bold]{len(conns)}[/]  |  " + "  ".join(parts) + "\n")


def display_iface_stats() -> None:
    console.print(Rule("[bold]Interface Statistics[/]"))
    stats = get_iface_stats()

    t = Table(box=box.ROUNDED, border_style="dim", show_lines=True)
    t.add_column("Interface", style="cyan bold")
    t.add_column("Bytes Recv",  justify="right", style="green")
    t.add_column("Bytes Sent",  justify="right", style="yellow")
    t.add_column("Pkts Recv",   justify="right")
    t.add_column("Pkts Sent",   justify="right")
    t.add_column("Err In",      justify="right", style="red")
    t.add_column("Err Out",     justify="right", style="red")
    t.add_column("Drop In",     justify="right", style="magenta")
    t.add_column("Drop Out",    justify="right", style="magenta")

    for name, s in stats.items():
        t.add_row(
            name,
            _bytes_fmt(s['bytes_recv']), _bytes_fmt(s['bytes_sent']),
            str(s['pkts_recv']),         str(s['pkts_sent']),
            str(s['errs_in']),           str(s['errs_out']),
            str(s['drop_in']),           str(s['drop_out']),
        )
    console.print(t)
    console.print()


def display_arp() -> None:
    console.print(Rule("[bold]ARP Table[/]"))
    with console.status("Reading ARP cache…", spinner="dots"):
        entries = get_arp_table()

    if not entries:
        console.print("[yellow]ARP table empty or access denied.[/]\n")
        return

    t = Table(box=box.ROUNDED, border_style="dim")
    t.add_column("IP Address",  style="green")
    t.add_column("MAC Address", style="cyan")
    t.add_column("Type",        style="dim")
    for e in entries:
        t.add_row(e['ip'], e['mac'], e.get('type', ''))
    console.print(t)
    console.print(f"  {len(entries)} ARP entries\n")


def display_routes() -> None:
    console.print(Rule("[bold]Routing Table[/]"))
    with console.status("Reading routing table…", spinner="dots"):
        routes = get_routing_table()

    if not routes:
        console.print("[yellow]Could not retrieve routing table.[/]\n")
        return

    t = Table(box=box.ROUNDED, border_style="dim")
    t.add_column("Destination",  style="cyan")
    t.add_column("Netmask",      style="dim")
    t.add_column("Gateway",      style="green")
    t.add_column("Interface",    style="yellow")
    t.add_column("Metric",       justify="right")
    for r in routes:
        t.add_row(
            r.get('destination', ''), r.get('netmask', ''),
            r.get('gateway', ''),     r.get('interface', ''),
            str(r.get('metric', '')),
        )
    console.print(t)
    console.print()


def display_http_test(url: str) -> None:
    console.print(Rule(f"[bold]HTTP Test — {url}[/]"))
    with console.status(f"Connecting to {url}…", spinner="dots"):
        res = do_http_test(url)

    t = Table(box=box.ROUNDED, show_header=False, border_style="dim")
    t.add_column("Field", style="bold cyan", no_wrap=True)
    t.add_column("Value")

    if res['success']:
        code = res['status_code']
        cc   = "bold green" if code < 300 else ("yellow" if code < 400 else "bold red")
        t.add_row("Status",       f"[{cc}]{code} {res['reason']}[/]")
        t.add_row("Latency",      f"{res['elapsed_ms']} ms")
        t.add_row("Final URL",    res['final_url'])
        t.add_row("SSL / TLS",    "[bold green]Yes[/]" if res['ssl'] else "[yellow]No[/]")
        t.add_row("Server",       res['server'])
        t.add_row("Content-Type", res['content_type'])
        t.add_row("Content-Len",  str(res['content_len']))
    else:
        t.add_row("Result", "[bold red]FAILED[/]")
        t.add_row("Error",  f"[red]{res.get('error', 'Unknown error')}[/]")

    console.print(t)
    console.print()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# INTERACTIVE FLOW FUNCTIONS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def flow_ping() -> None:
    host  = Prompt.ask("  Host / IP", default="8.8.8.8")
    count = IntPrompt.ask("  Packet count", default=4)
    display_ping(host, count)


def flow_dns() -> None:
    host   = Prompt.ask("  Hostname to query", default="google.com")
    server = Prompt.ask("  Custom DNS server (blank = system default)", default="")
    display_dns(host, server.strip() or None)


def flow_traceroute() -> None:
    host = Prompt.ask("  Target host / IP", default="8.8.8.8")
    hops = IntPrompt.ask("  Max hops", default=30)
    display_traceroute(host, hops)


def flow_portscan() -> None:
    host = Prompt.ask("  Target host / IP", default="127.0.0.1")
    console.print("  Port selection:")
    console.print("    [cyan][1][/] Common ports (well-known services)")
    console.print("    [cyan][2][/] Port range")
    console.print("    [cyan][3][/] Custom list (comma-separated)")
    mode = Prompt.ask("  Choice", default="1", choices=["1", "2", "3"])

    if mode == "1":
        ports = list(COMMON_PORTS.keys())
    elif mode == "2":
        start = IntPrompt.ask("  Start port", default=1)
        end   = IntPrompt.ask("  End port",   default=1024)
        ports = list(range(max(1, start), min(65535, end) + 1))
    else:
        raw   = Prompt.ask("  Ports (e.g. 80,443,22,3389)")
        ports = [int(p.strip()) for p in raw.split(',') if p.strip().isdigit()]
        if not ports:
            console.print("[red]No valid ports entered.[/]")
            return

    display_port_scan(host, ports)


def flow_connections() -> None:
    console.print("  Filter: [cyan]ESTABLISHED[/] | [cyan]LISTEN[/] | [cyan]TIME_WAIT[/] | blank=all")
    flt = Prompt.ask("  Status filter", default="")
    display_connections(flt.strip() or None)


def flow_http() -> None:
    url = Prompt.ask("  URL or hostname", default="https://www.google.com")
    display_http_test(url)


def flow_bandwidth(env: Environment) -> None:
    ifaces  = list(env.interfaces.keys())
    primary = env.primary_interface()
    console.print("  Available interfaces: " + "[dim],[/] ".join(f"[cyan]{i}[/]" for i in ifaces))
    iface = Prompt.ask("  Interface to monitor (blank = all)", default=primary or "")
    secs  = IntPrompt.ask("  Duration (seconds)", default=15)
    do_bandwidth_monitor(iface.strip() or None, secs)


def flow_report(env: Environment) -> None:
    console.print("  [cyan]Running full diagnostic — this may take ~30 seconds…[/]\n")
    with console.status("Collecting data…", spinner="dots"):
        text = generate_full_report(env)

    fname = f"netprobe_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(fname, 'w', encoding='utf-8') as f:
        f.write(text)

    console.print(f"  [bold green]Report saved:[/] [cyan]{fname}[/]")
    if Confirm.ask("  Display report in terminal?", default=True):
        console.print(Panel(text, border_style="dim", expand=False))
    console.print()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ENTRY POINT
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def main() -> None:
    # Boot: auto-discover environment
    console.clear()
    with console.status(
        "[bold cyan]NetProbe[/] — Discovering network environment…", spinner="dots"
    ):
        env = Environment()

    print_banner(env)

    if not env.is_admin:
        console.print(
            "[yellow]⚠  Not running as Administrator / root.[/]  "
            "[dim]Some features (ARP, raw sockets, process names) may be limited.[/]\n"
        )

    handlers = {
        '1':  lambda: display_overview(env),
        '2':  flow_ping,
        '3':  flow_dns,
        '4':  flow_traceroute,
        '5':  flow_portscan,
        '6':  flow_connections,
        '7':  display_iface_stats,
        '8':  display_arp,
        '9':  display_routes,
        '10': flow_http,
        '11': lambda: flow_bandwidth(env),
        '12': lambda: flow_report(env),
    }

    while True:
        show_menu()
        choice = Prompt.ask("  [bold cyan]Select[/]", default="1")
        console.print()

        if choice == '0':
            console.print("[cyan]Goodbye![/]\n")
            break

        handler = handlers.get(choice)
        if handler:
            try:
                handler()
            except KeyboardInterrupt:
                console.print("\n[yellow]Interrupted — returning to menu.[/]\n")
        else:
            console.print("[red]Invalid choice.[/]\n")

        if choice != '0':
            Prompt.ask("  [dim]Press Enter to continue…[/dim]", default="")
            console.clear()
            print_banner(env)


if __name__ == '__main__':
    main()
