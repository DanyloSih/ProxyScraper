import socket
import sys
import time
import os
import requests
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

# =====================================================
# Настройки по умолчанию (для новых пользователей скрипта)
# =====================================================

default_WORKERS = 200  # стандартное количество потоков (воркеров)
# Позволяет параллельно проверять несколько прокси-соединений;
# увеличение ускоряет работу, но требует больше ресурсов.

default_TIMEOUT = 2  # в секундах
# Время ожидания при попытке установить соединение с прокси.
# Если прокси не отвечает за этот период, считается, что он недоступен.

GEO_CACHE = {}
# Кеш для хранения результатов геолокации (страна) по IP,
# чтобы не делать повторные запросы к внешнему API.

# =====================================================
# Переменные, используемые в процессе работы скрипта
# =====================================================

WORKERS = default_WORKERS  # текущее число потоков, заданное пользователем
TIMEOUT = default_TIMEOUT  # текущее время ожидания соединения в секундах

# =====================================================
# Утилита проверки, можно ли строку превратить в float
# =====================================================
def is_float(value):
    try:
        float(value)
        return True
    except ValueError:
        return False

# ================================================
# Функция запроса настроек у пользователя
# ================================================
def get_user_config():
    """
    Запрашивает у пользователя ввод для параметров WORKERS и TIMEOUT.
    Подробные подсказки объясняют назначение параметров.
    При пустом или некорректном вводе используются значения по умолчанию.
    """
    global WORKERS, TIMEOUT

    # Ввод количества воркеров
    prompt_w = (
        f"WORKERS - максимальное число параллельных потоков для проверки прокси. "
        f"Увеличивает скорость за счет ресурсов CPU и сети. "
        f"Стандартное значение: {default_WORKERS}\n"
        "Введите число потоков (или нажмите Enter для значения по умолчанию): "
    )
    inp_w = input(prompt_w).strip()
    if inp_w.isdigit():
        WORKERS = int(inp_w)
    else:
        WORKERS = default_WORKERS

    # Ввод таймаута
    prompt_t = (
        f"TIMEOUT - время ожидания соединения с прокси (в секундах). "
        f"Если прокси не отвечает в этот период, считается недоступным. "
        f"Стандартное значение: {default_TIMEOUT}\n"
        "Введите таймаут в секундах (или нажмите Enter для значения по умолчанию): "
    )
    inp_t = input(prompt_t).strip()
    if inp_t and is_float(inp_t):
        TIMEOUT = float(inp_t)
    else:
        TIMEOUT = default_TIMEOUT

# =====================================================
# Функция проверки и мерджа обновлений из upstream
# =====================================================
def check_and_merge_upstream():
    """
    Проверяет наличие новых коммитов в upstream/main.
    Если есть — фетчит и делает merge без редактирования комментариев.
    При конфликтах — abort merge и завершает скрипт после нажатия клавиши.
    """
    print("Проверка обновлений в upstream...")
    subprocess.run(['git', 'fetch', 'upstream'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
    print(f"Найдено {count} новых коммитов, выполняем merge...")
    merge = subprocess.run(
        ['git', 'merge', 'upstream/main', '--no-edit'],
        capture_output=True, text=True
    )
    if merge.returncode == 0:
        print("Merge выполнен успешно, продолжаем работу.\n")
    else:
        print("При merge возникли конфликты:\n", merge.stdout, merge.stderr)
        subprocess.run(['git', 'merge', '--abort'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        input("Нажмите любую клавишу для выхода...")
        sys.exit(1)

# =====================================================
# Создание директории для результатов
# =====================================================
def ensure_output_dir():
    os.makedirs("available", exist_ok=True)

# =====================================================
# Функция получения страны по IP с кешированием
# =====================================================
def get_country(ip):
    if ip in GEO_CACHE:
        return GEO_CACHE[ip]
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode", timeout=3)
        country = r.json().get("countryCode", "??") if r.status_code == 200 else "??"
    except Exception:
        country = "??"
    GEO_CACHE[ip] = country
    return country

# =====================================================
# Handshake-функции для разных типов прокси
# =====================================================
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

# =====================================================
# Функция проверки одного прокси и измерения пинга
# =====================================================
def measure_proxy_connection(proxy, handshake_fn):
    try:
        host, port_str = proxy.split(':')
        port = int(port_str)
        start = time.perf_counter()
        with socket.create_connection((host, port), timeout=TIMEOUT) as s:
            s.settimeout(TIMEOUT)
            if not handshake_fn(s, host, port):
                return None
            ping = time.perf_counter() - start
            country = get_country(host)
            return proxy, ping, country
    except Exception:
        return None

# =====================================================
# Обработка файла со списком прокси
# =====================================================
def process_file(input_file, output_filename, handshake_fn, label):
    try:
        with open(input_file, 'r') as f:
            proxies = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{label}: файл {input_file} не найден, пропуск.")
        return
    total = len(proxies)
    if total == 0:
        print(f"{label}: файл пустой.")
        return
    results = []
    with ThreadPoolExecutor(max_workers=WORKERS) as executor:
        futures = {executor.submit(measure_proxy_connection, p, handshake_fn): p for p in proxies}
        for i, future in enumerate(as_completed(futures), 1):
            sys.stdout.write(f"\r{label}: {i}/{total}")
            sys.stdout.flush()
            res = future.result()
            if res:
                results.append(res)
    sys.stdout.write("\n")
    results.sort(key=lambda x: x[1])
    output_path = os.path.join("available", output_filename)
    with open(output_path, 'w') as out:
        for proxy, ping, country in results:
            out.write(f"{proxy} (ping: {ping:.2f}s, country: {country})\n")
    print(f"{label}: найдено {len(results)} из {total} рабочих прокси.")

# =====================================================
# Точка входа
# =====================================================
if __name__ == '__main__':
    get_user_config()
    check_and_merge_upstream()
    ensure_output_dir()
    process_file('socks5.txt', 'available_socks5.txt', handshake_socks5, 'SOCKS5')
    process_file('socks4.txt', 'available_socks4.txt', handshake_socks4, 'SOCKS4')
    process_file('http.txt',   'available_http.txt',   handshake_http,   'HTTP')
    input("Работа завершена. Нажмите любую клавишу и Enter для выхода...")
