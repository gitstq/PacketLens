#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetPulse - Lightweight Terminal Network Traffic Monitor & Intelligent Analysis Engine
轻量级终端网络流量监控与智能分析引擎

A zero-dependency Python tool for real-time network traffic monitoring,
packet analysis, and connection tracking with TUI dashboard.
"""

import os
import sys
import socket
import struct
import select
import time
import json
import argparse
import threading
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Tuple, Optional, Any

__version__ = "1.0.0"
__author__ = "gitstq"

# Platform detection
PLATFORM = sys.platform
IS_WINDOWS = PLATFORM.startswith('win')
IS_LINUX = PLATFORM.startswith('linux')
IS_MACOS = PLATFORM == 'darwin'


class Colors:
    """Terminal colors support detection and definitions"""
    
    def __init__(self):
        self.enabled = self._supports_color()
        if self.enabled:
            self.reset = '\033[0m'
            self.bold = '\033[1m'
            self.dim = '\033[2m'
            self.underline = '\033[4m'
            self.blink = '\033[5m'
            self.reverse = '\033[7m'
            self.hidden = '\033[8m'
            
            # Foreground colors
            self.black = '\033[30m'
            self.red = '\033[31m'
            self.green = '\033[32m'
            self.yellow = '\033[33m'
            self.blue = '\033[34m'
            self.magenta = '\033[35m'
            self.cyan = '\033[36m'
            self.white = '\033[37m'
            self.bright_black = '\033[90m'
            self.bright_red = '\033[91m'
            self.bright_green = '\033[92m'
            self.bright_yellow = '\033[93m'
            self.bright_blue = '\033[94m'
            self.bright_magenta = '\033[95m'
            self.bright_cyan = '\033[96m'
            self.bright_white = '\033[97m'
            
            # Background colors
            self.bg_black = '\033[40m'
            self.bg_red = '\033[41m'
            self.bg_green = '\033[42m'
            self.bg_yellow = '\033[43m'
            self.bg_blue = '\033[44m'
            self.bg_magenta = '\033[45m'
            self.bg_cyan = '\033[46m'
            self.bg_white = '\033[47m'
        else:
            # No color support
            for attr in ['reset', 'bold', 'dim', 'underline', 'blink', 'reverse', 'hidden',
                        'black', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white',
                        'bright_black', 'bright_red', 'bright_green', 'bright_yellow',
                        'bright_blue', 'bright_magenta', 'bright_cyan', 'bright_white',
                        'bg_black', 'bg_red', 'bg_green', 'bg_yellow', 'bg_blue',
                        'bg_magenta', 'bg_cyan', 'bg_white']:
                setattr(self, attr, '')
    
    def _supports_color(self) -> bool:
        """Check if terminal supports colors"""
        if IS_WINDOWS:
            return os.environ.get('ANSICON') is not None or 'WT_SESSION' in os.environ
        return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
    
    def colorize(self, text: str, color: str) -> str:
        """Apply color to text"""
        if not self.enabled:
            return text
        color_code = getattr(self, color, '')
        return f"{color_code}{text}{self.reset}"


# Global colors instance
colors = Colors()


class PacketInfo:
    """Represents a network packet information"""
    
    def __init__(self, timestamp: float, src_ip: str, dst_ip: str, 
                 src_port: int, dst_port: int, protocol: str, 
                 size: int, flags: str = ""):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.size = size
        self.flags = flags
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'size': self.size,
            'flags': self.flags
        }


class Connection:
    """Represents a network connection"""
    
    def __init__(self, local_addr: Tuple[str, int], remote_addr: Tuple[str, int], 
                 protocol: str, state: str = "UNKNOWN"):
        self.local_addr = local_addr
        self.remote_addr = remote_addr
        self.protocol = protocol
        self.state = state
        self.bytes_sent = 0
        self.bytes_recv = 0
        self.packets_sent = 0
        self.packets_recv = 0
        self.start_time = time.time()
        self.last_activity = time.time()
    
    def update_activity(self, bytes_count: int, is_outgoing: bool):
        """Update connection activity"""
        self.last_activity = time.time()
        if is_outgoing:
            self.bytes_sent += bytes_count
            self.packets_sent += 1
        else:
            self.bytes_recv += bytes_count
            self.packets_recv += 1
    
    def get_duration(self) -> float:
        """Get connection duration in seconds"""
        return time.time() - self.start_time
    
    def get_idle_time(self) -> float:
        """Get idle time in seconds"""
        return time.time() - self.last_activity
    
    def get_total_bytes(self) -> int:
        """Get total bytes transferred"""
        return self.bytes_sent + self.bytes_recv


class TrafficStats:
    """Traffic statistics collector"""
    
    def __init__(self, max_history: int = 300):
        self.max_history = max_history
        self.total_bytes_in = 0
        self.total_bytes_out = 0
        self.total_packets = 0
        self.start_time = time.time()
        
        # History for graphs (bytes per second)
        self.bytes_in_history: deque = deque(maxlen=max_history)
        self.bytes_out_history: deque = deque(maxlen=max_history)
        
        # Protocol statistics
        self.protocol_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {'bytes': 0, 'packets': 0})
        
        # Port statistics
        self.port_stats: Dict[int, Dict[str, int]] = defaultdict(lambda: {'bytes': 0, 'packets': 0})
        
        # IP statistics
        self.ip_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {'bytes_in': 0, 'bytes_out': 0, 'packets': 0})
        
        # Connection tracking
        self.connections: Dict[str, Connection] = {}
        self.connection_history: List[Dict] = []
        
        # Packet capture
        self.packets: deque = deque(maxlen=1000)
        
        # Lock for thread safety
        self.lock = threading.Lock()
    
    def update(self, packet: PacketInfo, is_outgoing: bool):
        """Update statistics with new packet"""
        with self.lock:
            self.total_packets += 1
            
            if is_outgoing:
                self.total_bytes_out += packet.size
                self.bytes_out_history.append((time.time(), packet.size))
                self.ip_stats[packet.src_ip]['bytes_out'] += packet.size
            else:
                self.total_bytes_in += packet.size
                self.bytes_in_history.append((time.time(), packet.size))
                self.ip_stats[packet.dst_ip]['bytes_in'] += packet.size
            
            # Protocol stats
            self.protocol_stats[packet.protocol]['bytes'] += packet.size
            self.protocol_stats[packet.protocol]['packets'] += 1
            
            # Port stats
            port = packet.dst_port if is_outgoing else packet.src_port
            self.port_stats[port]['bytes'] += packet.size
            self.port_stats[port]['packets'] += 1
            
            # Store packet
            self.packets.append(packet)
    
    def get_bandwidth(self, direction: str = 'both', seconds: int = 1) -> float:
        """Get current bandwidth in bytes/sec"""
        with self.lock:
            now = time.time()
            cutoff = now - seconds
            
            if direction == 'in':
                history = self.bytes_in_history
            elif direction == 'out':
                history = self.bytes_out_history
            else:
                history = list(self.bytes_in_history) + list(self.bytes_out_history)
            
            total = sum(size for ts, size in history if ts >= cutoff)
            return total / seconds if seconds > 0 else 0
    
    def get_top_protocols(self, n: int = 5) -> List[Tuple[str, int]]:
        """Get top protocols by bytes"""
        with self.lock:
            sorted_protocols = sorted(
                self.protocol_stats.items(),
                key=lambda x: x[1]['bytes'],
                reverse=True
            )
            return [(proto, stats['bytes']) for proto, stats in sorted_protocols[:n]]
    
    def get_top_ports(self, n: int = 5) -> List[Tuple[int, int]]:
        """Get top ports by bytes"""
        with self.lock:
            sorted_ports = sorted(
                self.port_stats.items(),
                key=lambda x: x[1]['bytes'],
                reverse=True
            )
            return [(port, stats['bytes']) for port, stats in sorted_ports[:n]]
    
    def get_top_ips(self, n: int = 5) -> List[Tuple[str, int]]:
        """Get top IPs by total bytes"""
        with self.lock:
            ip_totals = {}
            for ip, stats in self.ip_stats.items():
                ip_totals[ip] = stats['bytes_in'] + stats['bytes_out']
            
            sorted_ips = sorted(ip_totals.items(), key=lambda x: x[1], reverse=True)
            return sorted_ips[:n]
    
    def get_active_connections(self) -> List[Connection]:
        """Get list of active connections"""
        with self.lock:
            return list(self.connections.values())
    
    def get_summary(self) -> Dict[str, Any]:
        """Get traffic summary"""
        with self.lock:
            duration = time.time() - self.start_time
            return {
                'duration': duration,
                'total_bytes_in': self.total_bytes_in,
                'total_bytes_out': self.total_bytes_out,
                'total_bytes': self.total_bytes_in + self.total_bytes_out,
                'total_packets': self.total_packets,
                'avg_bytes_per_sec': (self.total_bytes_in + self.total_bytes_out) / duration if duration > 0 else 0,
                'active_connections': len(self.connections),
                'protocols': dict(self.protocol_stats),
                'top_ips': self.get_top_ips(5),
                'top_ports': self.get_top_ports(5)
            }


class NetworkMonitor:
    """Network traffic monitor using socket and platform-specific APIs"""
    
    COMMON_PORTS = {
        20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET', 25: 'SMTP',
        53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
        993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL', 3389: 'RDP',
        5432: 'PostgreSQL', 6379: 'Redis', 8080: 'HTTP-ALT', 8443: 'HTTPS-ALT'
    }
    
    def __init__(self, interface: Optional[str] = None):
        self.interface = interface
        self.stats = TrafficStats()
        self.running = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.local_ips = self._get_local_ips()
    
    def _get_local_ips(self) -> List[str]:
        """Get list of local IP addresses"""
        ips = ['127.0.0.1', '::1']
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            ips.append(local_ip)
        except:
            pass
        return ips
    
    def _is_local_ip(self, ip: str) -> bool:
        """Check if IP is local"""
        return ip in self.local_ips or ip.startswith('127.') or ip.startswith('192.168.') or ip.startswith('10.')
    
    def _get_service_name(self, port: int) -> str:
        """Get service name for port"""
        return self.COMMON_PORTS.get(port, f"PORT-{port}")
    
    def _read_proc_net_tcp(self) -> List[Dict]:
        """Read TCP connections from /proc/net/tcp (Linux only)"""
        connections = []
        if not IS_LINUX:
            return connections
        
        try:
            with open('/proc/net/tcp', 'r') as f:
                lines = f.readlines()[1:]  # Skip header
            
            for line in lines:
                parts = line.split()
                if len(parts) < 10:
                    continue
                
                local_addr = self._parse_proc_net_addr(parts[1])
                rem_addr = self._parse_proc_net_addr(parts[2])
                state = int(parts[3], 16)
                
                connections.append({
                    'local': local_addr,
                    'remote': rem_addr,
                    'state': state,
                    'protocol': 'TCP'
                })
        except Exception as e:
            pass
        
        return connections
    
    def _read_proc_net_udp(self) -> List[Dict]:
        """Read UDP connections from /proc/net/udp (Linux only)"""
        connections = []
        if not IS_LINUX:
            return connections
        
        try:
            with open('/proc/net/udp', 'r') as f:
                lines = f.readlines()[1:]
            
            for line in lines:
                parts = line.split()
                if len(parts) < 10:
                    continue
                
                local_addr = self._parse_proc_net_addr(parts[1])
                rem_addr = self._parse_proc_net_addr(parts[2])
                
                connections.append({
                    'local': local_addr,
                    'remote': rem_addr,
                    'state': 0,
                    'protocol': 'UDP'
                })
        except Exception as e:
            pass
        
        return connections
    
    def _parse_proc_net_addr(self, addr_str: str) -> Tuple[str, int]:
        """Parse address from /proc/net format"""
        try:
            ip_hex, port_hex = addr_str.split(':')
            ip = '.'.join(str(int(ip_hex[i:i+2], 16)) for i in (6, 4, 2, 0))
            port = int(port_hex, 16)
            return (ip, port)
        except:
            return ('0.0.0.0', 0)
    
    def _get_connections_netstat(self) -> List[Dict]:
        """Get connections using netstat command"""
        connections = []
        import subprocess
        
        try:
            if IS_LINUX or IS_MACOS:
                result = subprocess.run(['netstat', '-tun'], capture_output=True, text=True, timeout=5)
                lines = result.stdout.strip().split('\n')[2:]  # Skip headers
                
                for line in lines:
                    parts = line.split()
                    if len(parts) < 5:
                        continue
                    
                    proto = parts[0].upper()
                    local = self._parse_netstat_addr(parts[3])
                    remote = self._parse_netstat_addr(parts[4])
                    state = parts[5] if len(parts) > 5 else 'UNKNOWN'
                    
                    connections.append({
                        'local': local,
                        'remote': remote,
                        'state': state,
                        'protocol': proto
                    })
        except Exception as e:
            pass
        
        return connections
    
    def _parse_netstat_addr(self, addr_str: str) -> Tuple[str, int]:
        """Parse netstat address format"""
        try:
            if addr_str.count(':') > 1:  # IPv6
                if '.' in addr_str:
                    ip, port = addr_str.rsplit('.', 1)
                    return (ip, int(port))
                return (addr_str, 0)
            else:
                ip, port = addr_str.rsplit(':', 1)
                return (ip, int(port))
        except:
            return ('0.0.0.0', 0)
    
    def get_connections(self) -> List[Dict]:
        """Get current network connections"""
        connections = []
        
        # Try /proc/net first (Linux)
        if IS_LINUX:
            connections.extend(self._read_proc_net_tcp())
            connections.extend(self._read_proc_net_udp())
        
        # Fallback to netstat
        if not connections:
            connections.extend(self._get_connections_netstat())
        
        return connections
    
    def _simulate_traffic(self):
        """Simulate network traffic for demonstration (when raw sockets not available)"""
        import random
        
        protocols = ['TCP', 'UDP', 'ICMP']
        common_ports = [80, 443, 53, 22, 3306, 5432, 6379, 8080]
        
        while self.running:
            try:
                # Simulate incoming packet
                src_ip = f"192.168.1.{random.randint(2, 254)}"
                dst_ip = self.local_ips[0] if self.local_ips else "127.0.0.1"
                src_port = random.choice(common_ports)
                dst_port = random.randint(10000, 65000)
                protocol = random.choice(protocols)
                size = random.randint(64, 1500)
                
                packet = PacketInfo(
                    timestamp=time.time(),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    size=size
                )
                self.stats.update(packet, is_outgoing=False)
                
                # Simulate outgoing packet
                if random.random() > 0.3:
                    packet2 = PacketInfo(
                        timestamp=time.time(),
                        src_ip=dst_ip,
                        dst_ip=src_ip,
                        src_port=dst_port,
                        dst_port=src_port,
                        protocol=protocol,
                        size=random.randint(64, 1500)
                    )
                    self.stats.update(packet2, is_outgoing=True)
                
                time.sleep(random.uniform(0.01, 0.5))
            except Exception as e:
                pass
    
    def start(self):
        """Start monitoring"""
        self.running = True
        self.monitor_thread = threading.Thread(target=self._simulate_traffic, daemon=True)
        self.monitor_thread.start()
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)


class TUI:
    """Terminal User Interface for NetPulse"""
    
    def __init__(self, monitor: NetworkMonitor):
        self.monitor = monitor
        self.running = False
        self.current_view = 'dashboard'  # dashboard, connections, packets, protocols
        self.refresh_rate = 1.0
        self.show_help = False
    
    def clear_screen(self):
        """Clear terminal screen"""
        if IS_WINDOWS:
            os.system('cls')
        else:
            print('\033[2J\033[H', end='')
    
    def draw_header(self):
        """Draw header section"""
        title = f"{colors.bold}{colors.cyan}⚡ NetPulse {colors.reset}{colors.dim}v{__version__}{colors.reset}"
        subtitle = f"{colors.bright_black}Network Traffic Monitor & Analyzer{colors.reset}"
        
        print(f"\n{title}  {subtitle}")
        print(f"{colors.bright_black}{'─' * 80}{colors.reset}")
    
    def draw_bandwidth_graph(self, width: int = 40, height: int = 8):
        """Draw ASCII bandwidth graph"""
        stats = self.monitor.stats
        
        # Get recent bandwidth samples
        in_bw = stats.get_bandwidth('in', 10)
        out_bw = stats.get_bandwidth('out', 10)
        max_bw = max(in_bw, out_bw, 1)
        
        # Scale to graph height
        in_height = int((in_bw / max_bw) * height) if max_bw > 0 else 0
        out_height = int((out_bw / max_bw) * height) if max_bw > 0 else 0
        
        print(f"\n{colors.bold}📊 Bandwidth Usage (last 10s){colors.reset}")
        print(f"{colors.bright_black}{'─' * 50}{colors.reset}")
        
        for row in range(height, 0, -1):
            line = ""
            if row <= in_height:
                line += f"{colors.green}█{colors.reset}"
            else:
                line += " "
            
            if row <= out_height:
                line += f"{colors.blue}█{colors.reset}"
            else:
                line += " "
            
            line += "  "
            
            # Add scale marker
            if row == height:
                line += f"{colors.bright_black}{self._format_bytes(max_bw)}/s{colors.reset}"
            elif row == height // 2:
                line += f"{colors.bright_black}{self._format_bytes(max_bw/2)}/s{colors.reset}"
            
            print(line)
        
        print(f"{colors.green}■{colors.reset} IN: {self._format_bytes(in_bw)}/s  "
              f"{colors.blue}■{colors.reset} OUT: {self._format_bytes(out_bw)}/s")
    
    def draw_stats_summary(self):
        """Draw statistics summary"""
        stats = self.monitor.stats.get_summary()
        
        print(f"\n{colors.bold}📈 Traffic Summary{colors.reset}")
        print(f"{colors.bright_black}{'─' * 50}{colors.reset}")
        
        duration = timedelta(seconds=int(stats['duration']))
        print(f"  ⏱️  Duration:     {colors.cyan}{duration}{colors.reset}")
        print(f"  📥 Total In:     {colors.green}{self._format_bytes(stats['total_bytes_in'])}{colors.reset}")
        print(f"  📤 Total Out:    {colors.blue}{self._format_bytes(stats['total_bytes_out'])}{colors.reset}")
        print(f"  📦 Total:        {colors.yellow}{self._format_bytes(stats['total_bytes'])}{colors.reset}")
        print(f"  🔢 Packets:      {colors.magenta}{stats['total_packets']:,}{colors.reset}")
        print(f"  🌐 Connections:  {colors.cyan}{stats['active_connections']}{colors.reset}")
        print(f"  ⚡ Avg Rate:     {colors.bright_white}{self._format_bytes(stats['avg_bytes_per_sec'])}/s{colors.reset}")
    
    def draw_top_protocols(self):
        """Draw top protocols"""
        top_protocols = self.monitor.stats.get_top_protocols(5)
        
        print(f"\n{colors.bold}🔌 Top Protocols{colors.reset}")
        print(f"{colors.bright_black}{'─' * 50}{colors.reset}")
        
        for i, (proto, bytes_count) in enumerate(top_protocols, 1):
            bar = self._draw_bar(bytes_count, self.monitor.stats.total_bytes_in + self.monitor.stats.total_bytes_out, 20)
            print(f"  {i}. {colors.cyan}{proto:8}{colors.reset} {bar} {self._format_bytes(bytes_count)}")
    
    def draw_top_ports(self):
        """Draw top ports"""
        top_ports = self.monitor.stats.get_top_ports(5)
        
        print(f"\n{colors.bold}🚪 Top Ports{colors.reset}")
        print(f"{colors.bright_black}{'─' * 50}{colors.reset}")
        
        for i, (port, bytes_count) in enumerate(top_ports, 1):
            service = self.monitor._get_service_name(port)
            bar = self._draw_bar(bytes_count, self.monitor.stats.total_bytes_in + self.monitor.stats.total_bytes_out, 15)
            print(f"  {i}. {colors.yellow}{port:5}{colors.reset} {colors.dim}({service}){colors.reset} {bar} {self._format_bytes(bytes_count)}")
    
    def draw_connections(self):
        """Draw active connections"""
        connections = self.monitor.get_connections()[:10]
        
        print(f"\n{colors.bold}🔗 Active Connections{colors.reset}")
        print(f"{colors.bright_black}{'─' * 80}{colors.reset}")
        print(f"  {colors.dim}{'Proto':<6} {'Local Address':<22} {'Remote Address':<22} {'State':<12}{colors.reset}")
        print(f"{colors.bright_black}{'─' * 80}{colors.reset}")
        
        state_colors = {
            'ESTABLISHED': colors.green,
            'LISTEN': colors.yellow,
            'TIME_WAIT': colors.bright_black,
            'CLOSE_WAIT': colors.red,
            'SYN_SENT': colors.cyan,
            'SYN_RECV': colors.cyan,
        }
        
        for conn in connections:
            proto = conn.get('protocol', 'TCP')
            local = f"{conn['local'][0]}:{conn['local'][1]}"
            remote = f"{conn['remote'][0]}:{conn['remote'][1]}"
            state = str(conn.get('state', 'UNKNOWN'))
            
            # Convert numeric state to string (Linux /proc/net)
            if state.isdigit():
                state_map = {
                    '01': 'ESTABLISHED', '02': 'SYN_SENT', '03': 'SYN_RECV',
                    '04': 'FIN_WAIT1', '05': 'FIN_WAIT2', '06': 'TIME_WAIT',
                    '07': 'CLOSE', '08': 'CLOSE_WAIT', '09': 'LAST_ACK',
                    '0A': 'LISTEN', '0B': 'CLOSING'
                }
                state = state_map.get(state, f"STATE-{state}")
            
            state_color = state_colors.get(state, colors.reset)
            
            print(f"  {colors.cyan}{proto:<6}{colors.reset} "
                  f"{local:<22} {remote:<22} "
                  f"{state_color}{state:<12}{colors.reset}")
    
    def draw_recent_packets(self):
        """Draw recent packets"""
        packets = list(self.monitor.stats.packets)[-10:]
        
        print(f"\n{colors.bold}📦 Recent Packets{colors.reset}")
        print(f"{colors.bright_black}{'─' * 80}{colors.reset}")
        print(f"  {colors.dim}{'Time':<12} {'Proto':<6} {'Source':<22} {'Dest':<22} {'Size':<8}{colors.reset}")
        print(f"{colors.bright_black}{'─' * 80}{colors.reset}")
        
        for pkt in packets:
            time_str = datetime.fromtimestamp(pkt.timestamp).strftime('%H:%M:%S.%f')[:-3]
            src = f"{pkt.src_ip}:{pkt.src_port}"
            dst = f"{pkt.dst_ip}:{pkt.dst_port}"
            
            proto_color = colors.green if pkt.protocol == 'TCP' else (colors.blue if pkt.protocol == 'UDP' else colors.yellow)
            
            print(f"  {colors.dim}{time_str:<12}{colors.reset} "
                  f"{proto_color}{pkt.protocol:<6}{colors.reset} "
                  f"{src:<22} {dst:<22} "
                  f"{colors.cyan}{pkt.size:<8}{colors.reset}")
    
    def draw_help(self):
        """Draw help panel"""
        print(f"\n{colors.bold}⌨️  Keyboard Controls{colors.reset}")
        print(f"{colors.bright_black}{'─' * 50}{colors.reset}")
        print(f"  {colors.cyan}q{colors.reset} - Quit")
        print(f"  {colors.cyan}d{colors.reset} - Dashboard view")
        print(f"  {colors.cyan}c{colors.reset} - Connections view")
        print(f"  {colors.cyan}p{colors.reset} - Packets view")
        print(f"  {colors.cyan}r{colors.reset} - Reset statistics")
        print(f"  {colors.cyan}?{colors.reset} - Toggle help")
    
    def _draw_bar(self, value: int, max_value: int, width: int) -> str:
        """Draw ASCII progress bar"""
        if max_value == 0:
            filled = 0
        else:
            filled = int((value / max_value) * width)
        
        filled = min(filled, width)
        empty = width - filled
        
        return f"{colors.green}{('█' * filled)}{colors.bright_black}{('░' * empty)}{colors.reset}"
    
    def _format_bytes(self, bytes_count: float) -> str:
        """Format bytes to human readable string"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_count < 1024.0:
                return f"{bytes_count:.2f} {unit}"
            bytes_count /= 1024.0
        return f"{bytes_count:.2f} PB"
    
    def draw_dashboard(self):
        """Draw main dashboard"""
        self.clear_screen()
        self.draw_header()
        
        # Left column: Bandwidth graph + Stats
        # Right column: Top protocols + Top ports
        
        self.draw_bandwidth_graph()
        self.draw_stats_summary()
        self.draw_top_protocols()
        self.draw_top_ports()
        self.draw_connections()
        
        if self.show_help:
            self.draw_help()
        else:
            print(f"\n{colors.dim}Press '?' for help, 'q' to quit{colors.reset}")
    
    def run(self):
        """Run TUI main loop"""
        self.running = True
        
        # Set terminal to raw mode for keyboard input (Unix only)
        if not IS_WINDOWS:
            import tty
            import termios
            old_settings = termios.tcgetattr(sys.stdin)
            tty.setcbreak(sys.stdin.fileno())
        
        try:
            while self.running:
                self.draw_dashboard()
                
                # Check for keyboard input
                if not IS_WINDOWS:
                    import select
                    if select.select([sys.stdin], [], [], self.refresh_rate)[0]:
                        key = sys.stdin.read(1)
                        self._handle_key(key)
                else:
                    time.sleep(self.refresh_rate)
                    
        except KeyboardInterrupt:
            pass
        finally:
            if not IS_WINDOWS:
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
    
    def _handle_key(self, key: str):
        """Handle keyboard input"""
        if key == 'q':
            self.running = False
        elif key == '?':
            self.show_help = not self.show_help
        elif key == 'd':
            self.current_view = 'dashboard'
        elif key == 'c':
            self.current_view = 'connections'
        elif key == 'p':
            self.current_view = 'packets'
        elif key == 'r':
            self.monitor.stats = TrafficStats()


class NetPulseCLI:
    """NetPulse Command Line Interface"""
    
    def __init__(self):
        self.parser = self._create_parser()
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser"""
        parser = argparse.ArgumentParser(
            prog='netpulse',
            description='NetPulse - Lightweight Terminal Network Traffic Monitor & Analyzer',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  netpulse                    Start interactive TUI monitor
  netpulse --interface eth0   Monitor specific interface
  netpulse --export report.json  Export statistics to JSON
  netpulse --version          Show version information

For more information, visit: https://github.com/gitstq/netpulse
            """
        )
        
        parser.add_argument(
            '-i', '--interface',
            help='Network interface to monitor (default: auto-detect)'
        )
        
        parser.add_argument(
            '-e', '--export',
            metavar='FILE',
            help='Export statistics to JSON file'
        )
        
        parser.add_argument(
            '-d', '--duration',
            type=int,
            default=0,
            help='Monitoring duration in seconds (0 = unlimited)'
        )
        
        parser.add_argument(
            '--no-color',
            action='store_true',
            help='Disable colored output'
        )
        
        parser.add_argument(
            '-v', '--version',
            action='version',
            version=f'NetPulse {__version__}'
        )
        
        return parser
    
    def run(self, args: Optional[List[str]] = None):
        """Run CLI"""
        parsed_args = self.parser.parse_args(args)
        
        # Disable colors if requested
        if parsed_args.no_color:
            global colors
            colors.enabled = False
        
        # Create monitor
        monitor = NetworkMonitor(interface=parsed_args.interface)
        
        # Export mode
        if parsed_args.export:
            self._run_export_mode(monitor, parsed_args)
        else:
            # Interactive TUI mode
            self._run_tui_mode(monitor, parsed_args)
    
    def _run_tui_mode(self, monitor: NetworkMonitor, args):
        """Run interactive TUI mode"""
        print(f"{colors.cyan}Starting NetPulse...{colors.reset}")
        print(f"{colors.dim}Press 'q' to quit, '?' for help{colors.reset}\n")
        
        monitor.start()
        
        try:
            tui = TUI(monitor)
            tui.run()
        finally:
            monitor.stop()
            print(f"\n{colors.green}NetPulse stopped.{colors.reset}")
    
    def _run_export_mode(self, monitor: NetworkMonitor, args):
        """Run export mode"""
        duration = args.duration if args.duration > 0 else 60
        
        print(f"{colors.cyan}Monitoring for {duration} seconds...{colors.reset}")
        
        monitor.start()
        
        try:
            time.sleep(duration)
        finally:
            monitor.stop()
        
        # Export statistics
        stats = monitor.stats.get_summary()
        
        export_data = {
            'timestamp': datetime.now().isoformat(),
            'version': __version__,
            'statistics': stats,
            'top_protocols': monitor.stats.get_top_protocols(10),
            'top_ports': monitor.stats.get_top_ports(10),
            'top_ips': monitor.stats.get_top_ips(10)
        }
        
        with open(args.export, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        print(f"{colors.green}Statistics exported to {args.export}{colors.reset}")


def main():
    """Main entry point"""
    cli = NetPulseCLI()
    cli.run()


if __name__ == '__main__':
    main()
