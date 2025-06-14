import socket
import sys
import time
import os
import requests
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

# Настройки по умолчанию
default_WORKERS = 200
default_TIMEOUT = 2  # в секундах
GEO_CACHE = {}

# Значения, которые будут использоваться в работе
WORKERS = default_WORKERS
TIMEOUT = default_TIMEOUT

def get_user_config():
    """
    Запрашивает у пользователя ввод для WORKERS и TIMEOUT.
    При некорректном вводе или пустой строке используются значения по умолчанию.
    """
    global WORKERS, TIMEOUT
    # Ввод количества воркеров
    try:
        inp_w = input(f"WORKERS - количество воркеров, стандартное значение ({default_WORKERS}): ")
        if inp_w.strip():
            WORKERS = int(inp_w)
        else:
            WORKERS = default_WORKERS
    except ValueError:
        WORKERS = default_WORKERS

    # Ввод таймаута
    try:
        inp_t = input(f"TIMEOUT - таймаут подключения в секундах, стандартное значение ({default_TIMEOUT}): ")
        if inp_t.strip():
            TIMEOUT = float(inp_t)
        else:
            TIMEOUT = default_TIMEOUT
    except ValueError:
        TIMEOUT = default_TIMEOUT


def check_and_merge_upstream():
    """
    Проверяет наличие новых коммитов в upstream/main, фетчит и мерджит.
    При конфликтах отменяет мердж и завершает работу.
    """
    print("Проверка обновлений в upstream...")
    subprocess.run(['git', 'fetch', 'upstream'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Узнаем количество новых коммитов
    rev = subprocess.run(
        ['git', 'rev-list', 'HEAD..upstream/main', '--count'],
        capture_output=True, text=True
    )
    try:
        count = int(rev.stdout.strip() or "0")
    except ValueError:
        count = 0

    if count == 0:
        print("Нет обновлений в upstream.\n")
        return

    print(f"Найдено {count} новых коммитов в upstream. Фетчим и мерджим...")
    merge = subprocess.run(
        ['git', 'merge', 'upstream/main', '--no-edit'],
        capture_output=True, text=True
    )

    if merge.returncode == 0:
        print("Мердж выполнен успешно, продолжаем работу скрипта.\n")
    else:
        print("При мердже возникли конфликты:")
        print(merge.stdout)
        print(merge.stderr)
        subprocess.run(['git', 'merge', '--abort'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        input("Нажмите любую клавишу для выхода...")
        sys.exit(1)


def ensure_output_dir():
    os.makedirs("available", exist_ok=True)


def get_country(ip):
    if ip in GEO_CACHE:
        return GEO_CACHE[ip]
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode", timeout=3)
        country = r.json().get("countryCode", "??") if r.status_code == 200 else "??"
    except:
        country = "??"
    GEO_CACHE[ip] = country
    return country


def measure_proxy_connection(proxy, handshake_fn):
    try:
        host, port_str = proxy.split(':')
        port = int(port_str)

        start_time = time.perf_counter()
        with socket.create_connection((host, port), timeout=TIMEOUT) as s:
            s.settimeout(TIMEOUT)
            if not handshake_fn(s, host, port):
                return None

            ping = time.perf_counter() - start_time
            country = get_country(host)
            return (proxy, ping, country)
    except:
        return None


def handshake_socks5(s, host, port):
    s.sendall(b'\x05\x01\x00')
    return s.recv(2) == b'\x05\x00'


def handshake_socks4(s, host, port):
    try:
        ip_bytes = socket.inet_aton(host)
    except OSError:
        return False
    port_bytes = port.to_bytes(2, 'big')
    req = b'\x04\x01' + port_bytes + ip_bytes + b'\x00'
    s.sendall(req)
    resp = s.recv(8)
    return len(resp) == 8 and resp[1] == 0x5A


def handshake_http(s, host, port):
    req = b"GET http://example.com/ HTTP/1.0\r\nHost: example.com\r\n\r\n"
    s.sendall(req)
    resp = s.recv(7)
    return resp.startswith(b"HTTP/")


def process_file(input_file, output_filename, handshake_fn, label):
    try:
        with open(input_file, 'r') as f:
            proxies = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{label}: файл {input_file} не найден, пропущено.")
        return

    total = len(proxies)
    if total == 0:
        print(f"{label}: файл пустой.")
        return

    results = []

    with ThreadPoolExecutor(max_workers=WORKERS) as executor:
        futures = {executor.submit(measure_proxy_connection, proxy, handshake_fn): proxy for proxy in proxies}
        for i, future in enumerate(as_completed(futures), 1):
            sys.stdout.write(f"\r{label}: {i}/{total}")
            sys.stdout.flush()
            result = future.result()
            if result:
                results.append(result)

    sys.stdout.write('\n')

    results.sort(key=lambda x: x[1])

    output_path = os.path.join("available", output_filename)
    with open(output_path, 'w') as f:
        for proxy, ping, country in results:
            f.write(f"{proxy} (ping: {ping:.2f}s, country: {country})\n")

    print(f"{label}: найдено {len(results)} рабочих из {total}")


if __name__ == '__main__':
    get_user_config()
    check_and_merge_upstream()
    ensure_output_dir()
    process_file('socks5.txt', 'available_socks5.txt', handshake_socks5, 'SOCKS5')
    process_file('socks4.txt', 'available_socks4.txt', handshake_socks4, 'SOCKS4')
    process_file('http.txt',   'available_http.txt',   handshake_http,   'HTTP')
    input("Нажмите любую клавишу для выхода...")
