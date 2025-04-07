import socket
import ssl
import argparse
import json
import sys
from typing import Dict, List
from datetime import datetime


class TLSScanner:
    def __init__(self, host: str, port: int = 443, timeout: int = 10):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.results: Dict[str, any] = {
            'target': f'{host}:{port}',
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': {}
        }

    def _create_ssl_context(self, protocol_version: int = None, ciphers: List[str] = None) -> ssl.SSLContext:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        if protocol_version:
            context.options |= protocol_version

        if ciphers:
            context.set_ciphers(':'.join(ciphers))

        return context

    def _test_connection(self, context: ssl.SSLContext) -> bool:
        try:
            with socket.create_connection((self.host, self.port), self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    return True
        except (ssl.SSLError, ConnectionError, TimeoutError):
            return False

    def check_protocols(self):
        protocols = {
            'SSLv2': ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3,
            'SSLv3': ssl.OP_NO_SSLv2 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3,
            'TLSv1.0': ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3,
            'TLSv1.1': ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3,
            'TLSv1.2': ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_3,
            'TLSv1.3': ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
        }

        supported = []
        for proto, options in protocols.items():
            try:
                context = self._create_ssl_context(options)
                if self._test_connection(context):
                    supported.append(proto)
            except Exception:
                continue
        self.results['protocols'] = supported

    def check_vulnerability(self, name: str, ciphers: List[str], protocol: int) -> bool:
        try:
            context = self._create_ssl_context(protocol, ciphers)
            return self._test_connection(context)
        except Exception:
            return False

    def scan(self):
        self.check_protocols()

        tests = {
            'BEAST': {
                'ciphers': ['AES128-SHA', 'DES-CBC3-SHA'],
                'protocol': ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3
            },
            'POODLE': {
                'ciphers': ['SSLv3'],
                'protocol': ssl.OP_NO_SSLv2 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3
            },
            'FREAK': {
                'ciphers': ['EXP-DES-CBC-SHA', 'EXP-RC2-CBC-MD5'],
                'protocol': ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3
            }
        }

        for name, params in tests.items():
            self.results['vulnerabilities'][name] = self.check_vulnerability(
                name, **params
            )

    def generate_report(self, format: str = 'text') -> str:
        if format == 'json':
            return json.dumps(self.results, indent=2)

        report = [
            f"SSL/TLS Scan Report for {self.results['target']}",
            f"Scan timestamp: {self.results['timestamp']}",
            "\nSupported Protocols:",
            '\n'.join(f"- {proto}" for proto in self.results.get('protocols', [])),
            "\nVulnerabilities:"
        ]

        for vuln, status in self.results['vulnerabilities'].items():
            report.append(f"- {vuln}: {'VULNERABLE' if status else 'OK'}")
        return '\n'.join(report)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='SSL/TLS Vulnerability Scanner')
    parser.add_argument('host', help='Target hostname or IP address')
    parser.add_argument('-p', '--port', type=int, default=443, help='Target port (default: 443)')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Connection timeout (default: 10s)')
    parser.add_argument('-o', '--output', choices=['text', 'json'], default='text', help='Output format')
    args = parser.parse_args()

    try:
        scanner = TLSScanner(args.host, args.port, args.timeout)
        scanner.scan()
        print(scanner.generate_report(args.output))
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)
