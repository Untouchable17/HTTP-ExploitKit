import socket
import ssl
import argparse
import re
from typing import Tuple

MIN_DH_KEY_SIZE: int = 2048
WEAK_PROTOCOLS: set[str] = {'TLSv1', 'TLSv1.1', 'SSLv3'}
SECURE_CIPHERS: str = 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384'


def validate_host(host: str) -> bool:
    ip_pattern: str = r"^\d{1,3}(\.\d{1,3}){3}$"
    domain_pattern: str = r"^[a-zA-Z0-9-]+(\.[a-zA-Z]{2,})+$"
    return bool(re.match(ip_pattern, host) or re.match(domain_pattern, host))


def check_tls_configuration(host: str, port: int = 443) -> Tuple[bool, str]:
    try:
        if not validate_host(host):
            raise ValueError(f"Некорректный формат хоста: {host}")

        context: ssl.SSLContext = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.set_ciphers(SECURE_CIPHERS)

        with socket.create_connection((host, port), timeout=15) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                protocol: str = ssock.version()
                cipher: Tuple[str, str, int] = ssock.cipher()
                cipher_name, _, bits = cipher

                print(f"[+] Установлен протокол: {protocol}")
                print(f"[+] Выбранный шифр: {cipher_name}")
                print(f"[+] Размер ключа: {bits} бит")

                # Проверка на использование DHE/EDH
                if "DHE" in cipher_name or "EDH" in cipher_name:
                    if bits < MIN_DH_KEY_SIZE:
                        return True, f"Обнаружены слабые параметры DH ({bits} бит)"
                    return False, f"Безопасные параметры DH ({bits} бит)"

                # Проверка устаревших протоколов
                if protocol in WEAK_PROTOCOLS:
                    return True, f"Устаревший протокол: {protocol}"

                return False, "Потенциально безопасная конфигурация"

    except ssl.SSLError as e:
        return False, f"Ошибка SSL: {str(e).split(':')[-1].strip()}"
    except socket.error as e:
        return False, f"Сетевая ошибка: {str(e)}"
    except Exception as e:
        return False, f"Критическая ошибка: {str(e)}"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Инструмент проверки уязвимости Logjam (CVE-2015-4000)",
        epilog="Пример использования: python LogjamScan.py example.com --port 443"
    )
    parser.add_argument("host", help="Целевой хост для проверки")
    parser.add_argument("--port", type=int, default=443,
                        help="Порт TLS-сервера (по умолчанию 443)")

    args = parser.parse_args()

    banner: str = r"""
    ██╗      ██████╗  ██████╗     █████╗ ██████╗ ██████╗ 
    ██║     ██╔═══██╗██╔════╝    ██╔══██╗██╔══██╗██╔══██╗
    ██║     ██║   ██║██║         ███████║██████╔╝██║  ██║
    ██║     ██║   ██║██║         ██╔══██║██╔═══╝ ██║  ██║
    ███████╗╚██████╔╝╚██████╗    ██║  ██║██║     ██████╔╝
    ╚══════╝ ╚═════╝  ╚═════╝    ╚═╝  ╚═╝╚═╝     ╚═════╝ 
    """
    print(banner)

    try:
        is_vulnerable, message = check_tls_configuration(args.host, args.port)

        if is_vulnerable:
            print(f"\n[!] ВНИМАНИЕ: {message}")
            print("[!] Дальнейшие действия требуют значительных вычислительных ресурсов для брутфорса открытого "
                  "ключа. Предлагается два ручных варианта:")
            print("- Понижение уровня шифрования")
            print("- Атака Man-in-the-Middle")
            print("[!] Уязвимость наглядно иллюстрируется в репозитории: github.com/concise/logjam-attack-poc/")
        else:
            print(f"\n[+] Результат проверки: {message}")

    except KeyboardInterrupt:
        print("\n[!] Проверка прервана пользователем")


if __name__ == "__main__":
    main()
