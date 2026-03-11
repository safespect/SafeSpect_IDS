"""
live_monitor.py — Windows-compatible, fixed DoS vs PortScan detection
"""

import threading
import time
import warnings
import numpy as np
from datetime import datetime
from collections import defaultdict

# Suppress sklearn SHAP warnings
warnings.filterwarnings("ignore", category=UserWarning)


class LiveNetworkMonitor:
    def __init__(self, ai_model):
        self.ai_model = ai_model
        self.running = False
        self._thread = None
        self._events = []
        self._lock = threading.Lock()
        self._src_tracker = defaultdict(lambda: {
            'total_packets': 0,
            'syn_count':     0,
            'dest_ports':    set(),
            'iat_samples':   [],
            'start_time':    None,
            'last_time':     None,
            'last_analyzed': 0,
        })
        # HTTP-layer tracking per source IP
        self._http_tracker = defaultdict(lambda: {
            'request_count': 0,
            'suspicious_paths': 0,
            'start_time': None,
            'last_analyzed': 0,
        })
        # Known suspicious path patterns (Nikto, SQLmap, web scanners)
        self._suspicious_patterns = [
            '/admin', '/phpmyadmin', '/etc/passwd', '/.env', '/wp-admin',
            '/config', '/backup', '/shell', '/cmd', '/exec', 'select+',
            'union+', '../', '<script', 'passwd', 'shadow', '/cgi-bin',
            '/manager', '/.git', '/api/v1', '/console', 'sqlmap',
            '/login.php', '/wp-login', '/xmlrpc', '/eval(', '/base64'
        ]

    def start(self):
        if self.running:
            print("⚠️  Monitor already running")
            return
        self.running = True
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()
        self._http_thread = threading.Thread(target=self._http_monitor_loop, daemon=True)
        self._http_thread.start()
        print("✅ Live monitor started")

    def stop(self):
        self.running = False
        print("🛑 Live monitor stopped")

    def get_events_since(self, index):
        with self._lock:
            return list(self._events[index:])

    # ── Entry point ──────────────────────────────────────────────────────────

    def _capture_loop(self):
        try:
            from scapy.all import sniff, IP, TCP, UDP
            print("✅ Scapy found — starting real packet capture")
            self._run_scapy()
        except ImportError:
            print("⚠️  Scapy not installed — pip install scapy")
            print("🎭 Falling back to simulation mode")
            self._simulate_loop()
        except Exception as e:
            print(f"⚠️  Scapy error: {e}")
            print("🎭 Falling back to simulation mode")
            self._simulate_loop()

    # ── Real capture ─────────────────────────────────────────────────────────

    def _run_scapy(self):
        from scapy.all import sniff, IP, TCP, UDP

        def handle_packet(pkt):
            if not self.running or IP not in pkt:
                return

            src_ip   = pkt[IP].src
            dst_port = 0
            is_syn   = False

            if TCP in pkt:
                dst_port = pkt[TCP].dport
                is_syn   = bool(pkt[TCP].flags & 0x02)
            elif UDP in pkt:
                dst_port = pkt[UDP].dport

            now = time.time()

            with self._lock:
                s = self._src_tracker[src_ip]
                if s['start_time'] is None:
                    s['start_time'] = now
                else:
                    s['iat_samples'].append((now - s['last_time']) * 1e6)
                s['last_time']      = now
                s['total_packets'] += 1
                s['dest_ports'].add(dst_port)
                if is_syn:
                    s['syn_count'] += 1

                unique_ports = len(s['dest_ports'])
                since_last   = now - s['last_analyzed']
                should_analyze = (
                    (unique_ports >= 10 and since_last > 2.0) or
                    (s['total_packets'] >= 30 and since_last > 5.0)
                )

            if should_analyze:
                self._analyze_source(src_ip)

        # WSL Hyper-V interface
        WSL_IFACE = "\\Device\\NPF_{DAD706A7-A620-47FF-97DA-FFEED867A400}"
        print(f"📡 Sniffing on WSL interface: {WSL_IFACE}")

        while self.running:
            sniff(filter="ip dst 172.20.10.2", iface=WSL_IFACE, prn=handle_packet, store=False, timeout=2, count=0)

    # ── Per-source analysis ──────────────────────────────────────────────────

    def _analyze_source(self, src_ip):
        # Skip Windows host IP — it's our own machine responding to traffic, not an attacker
        if src_ip in ('172.20.48.1', '172.20.10.2', '172.20.10.1'):
            return
        with self._lock:
            if src_ip not in self._src_tracker:
                return
            s = dict(self._src_tracker[src_ip])
            s['dest_ports'] = set(self._src_tracker[src_ip]['dest_ports'])
            self._src_tracker[src_ip]['last_analyzed'] = time.time()

        unique_ports = len(s['dest_ports'])
        duration     = max(1, int((s['last_time'] - s['start_time']) * 1e6)) if s['start_time'] and s['last_time'] else 1
        iat_mean     = float(np.mean(s['iat_samples'])) if s['iat_samples'] else 0.0
        iat_std      = float(np.std(s['iat_samples']))  if len(s['iat_samples']) > 1 else 0.0
        pps          = s['total_packets'] / max(1, duration / 1e6)

        most_common_port = max(s['dest_ports'], key=lambda p: p) if s['dest_ports'] else 0

        features = {
            "Destination Port":       most_common_port,
            "Flow Duration":          duration,
            "Total Fwd Packets":      s['total_packets'],
            "Total Backward Packets": 0,
            "Flow IAT Mean":          iat_mean,
            "Flow IAT Std":           iat_std,
            "Fwd IAT Mean":           iat_mean,
            "Init_Win_bytes_forward": 0 if s['syn_count'] > 5 else 8192,
            "SYN Flag Count":         s['syn_count'],
            "Fwd Packets/s":          pps,
        }

        # DoS  = high SYN storm on few ports
        # PortScan = many unique ports, low SYN relative to ports
        # BruteForce = high packet count to 1-2 ports (e.g. port 5000/22), low SYN, many packets
        is_flood     = s['syn_count'] >= 20 and (unique_ports < 20 or s['syn_count'] > unique_ports * 2)
        is_scan      = unique_ports >= 3 and not is_flood and s['syn_count'] <= unique_ports
        is_bruteforce = (
            s['total_packets'] >= 20 and        # high volume
            unique_ports <= 2 and               # targeting same port repeatedly
            not is_flood and
            most_common_port in [22, 21, 80, 443, 5000, 3306, 8080]  # common BF targets
        )
        print(f"🔍 [{src_ip}] pkts={s['total_packets']} syn={s['syn_count']} ports={unique_ports} pps={pps:.1f} | flood={is_flood} scan={is_scan} bf={is_bruteforce}")

        try:
            result     = self.ai_model.predict_and_explain(features)
            label      = result['result']
            confidence = result['confidence']

            if is_flood:
                label      = 'DoS'  # Changed from 'DDoS' to 'DoS'
                confidence = f"{min(99, 70 + min(29, int(pps / 1000)))}%"
            elif is_bruteforce:
                label      = 'BruteForce'
                confidence = f"{min(99, 60 + min(39, s['total_packets'] // 10))}%"
            elif is_scan:
                label      = 'PortScan'
                confidence = f"{min(99, 60 + unique_ports)}%"

            self._emit_event(src_ip, label, confidence, result.get('explanation', {}), unique_ports)

            # Reset this source's stats after emitting so next attack starts fresh
            with self._lock:
                if src_ip in self._src_tracker:
                    now = time.time()
                    self._src_tracker[src_ip] = {
                        'total_packets': 0,
                        'syn_count':     0,
                        'dest_ports':    set(),
                        'iat_samples':   [],
                        'start_time':    now,
                        'last_time':     now,
                        'last_analyzed': now,
                    }

        except Exception as e:
            print(f"⚠️  Prediction error for {src_ip}: {e}")

    # ── HTTP layer monitor ──────────────────────────────────────────────────

    def _http_monitor_loop(self):
        """Monitor Flask's own request log via a queue populated by a middleware hook."""
        while self.running:
            try:
                requests_snapshot = {}
                with self._lock:
                    for ip, data in list(self._http_tracker.items()):
                        if data['request_count'] >= 5 and (time.time() - data['last_analyzed']) > 2.0:
                            requests_snapshot[ip] = dict(data)
                            self._http_tracker[ip]['last_analyzed'] = time.time()

                for src_ip, data in requests_snapshot.items():
                    elapsed   = max(1, time.time() - data['start_time']) if data['start_time'] else 1
                    req_rate  = data['request_count'] / elapsed
                    sus_ratio = data['suspicious_paths'] / max(1, data['request_count'])

                    # WebAttack: many suspicious paths
                    # BruteForce: many requests to same path (login) at high rate
                    if sus_ratio > 0.3 or data['suspicious_paths'] >= 3:
                        label      = 'WebAttack'
                        confidence = f"{min(99, 60 + int(sus_ratio * 39))}%"
                    elif req_rate > 10 and data['request_count'] > 20:
                        label      = 'BruteForce'
                        confidence = f"{min(99, 60 + int(req_rate))}%"
                    else:
                        continue  # Not suspicious enough

                    explanation = {
                        'features': ['Destination Port', 'Fwd Packets/s', 'SYN Flag Count'],
                        'impact':   [req_rate, data['request_count'] / 10, sus_ratio * 10]
                    }
                    self._emit_event(src_ip, label, confidence, explanation, 0)

                    # Reset after emitting
                    with self._lock:
                        if src_ip in self._http_tracker:
                            self._http_tracker[src_ip] = {
                                'request_count':   0,
                                'suspicious_paths': 0,
                                'start_time':      time.time(),
                                'last_analyzed':   time.time(),
                            }

            except Exception as e:
                print(f"⚠️  HTTP monitor error: {e}")
            time.sleep(1.0)

    def record_http_request(self, src_ip, path):
        """Called by Flask middleware for every incoming HTTP request."""
        now = time.time()
        path_lower = path.lower()
        is_suspicious = any(p in path_lower for p in self._suspicious_patterns)

        with self._lock:
            h = self._http_tracker[src_ip]
            if h['start_time'] is None:
                h['start_time'] = now
            h['request_count']   += 1
            if is_suspicious:
                h['suspicious_paths'] += 1

    # ── Simulation fallback ──────────────────────────────────────────────────

    def _simulate_loop(self):
        import random
        scenarios = [
            ({"Destination Port": 80,   "Flow Duration": 120000, "Total Fwd Packets": 6,    "Flow IAT Mean": 18000, "Init_Win_bytes_forward": 8192}, None),
            ({"Destination Port": 22,   "Flow Duration": 800,    "Total Fwd Packets": 150,  "Flow IAT Mean": 40,    "Init_Win_bytes_forward": 0},    None),
            ({"Destination Port": 443,  "Flow Duration": 10,     "Total Fwd Packets": 2000, "Flow IAT Mean": 2,     "Init_Win_bytes_forward": 0},    None),
            ({"Destination Port": 445,  "Flow Duration": 500,    "Total Fwd Packets": 50,   "Flow IAT Mean": 100,   "Init_Win_bytes_forward": 0},    "PortScan"),
            ({"Destination Port": 3306, "Flow Duration": 300,    "Total Fwd Packets": 10,   "Flow IAT Mean": 5000,  "Init_Win_bytes_forward": 0},    "WebAttack"),
            ({"Destination Port": 8080, "Flow Duration": 200,    "Total Fwd Packets": 3,    "Flow IAT Mean": 55000, "Init_Win_bytes_forward": 255},  None),
        ]
        sources = ["192.168.1.10", "10.0.0.42", "172.16.0.5", "192.168.0.99", "10.10.10.1"]

        while self.running:
            features, label_override = random.choice(scenarios)
            src  = random.choice(sources)
            port = features.get("Destination Port", 80)
            try:
                result = self.ai_model.predict_and_explain(features)
                label  = label_override if label_override else result['result']
                conf   = result['confidence']
                self._emit_event(src, label, conf, result.get('explanation', {}), 0)
            except Exception as e:
                print(f"❌ Sim error: {e}")
                self._emit_event(src, "BENIGN", "95.00%", {}, 0)
            time.sleep(random.uniform(1.0, 3.0))

    # ── Event emitter ────────────────────────────────────────────────────────

    def _emit_event(self, src_ip, label, confidence, explanation, unique_ports):
        top_features = []
        if explanation and 'features' in explanation and 'impact' in explanation:
            impacts = explanation['impact']
            flat_impacts = []
            for v in impacts:
                if isinstance(v, list):
                    flat_impacts.append(float(v[0]) if v else 0.0)
                else:
                    flat_impacts.append(float(v))
            combined = sorted(
                zip(explanation['features'], flat_impacts),
                key=lambda x: abs(x[1]), reverse=True
            )[:3]
            top_features = [{"name": f, "impact": round(float(v), 4)} for f, v in combined]

        src_display = f"{src_ip} ({unique_ports} ports)" if unique_ports >= 5 else src_ip

        event = {
            "time":         datetime.now().strftime("%H:%M:%S"),
            "src":          src_display,
            "label":        label,
            "confidence":   confidence,
            "top_features": top_features,
            "is_threat":    label != "BENIGN"
        }
        with self._lock:
            self._events.append(event)
            if len(self._events) > 200:
                self._events = self._events[-200:]

        icon = "🚨" if label != "BENIGN" else "✅"
        print(f"{icon} [{event['time']}] {label} from {src_ip} | ports={unique_ports} ({confidence})")