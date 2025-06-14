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

default_WORKERS = 200
# default_WORKERS - стандартное количество потоков (воркеров)
# Этот параметр определяет, сколько соединений скрипт будет
# одновременно проверять. Увеличение значения может ускорить
# проверку, но потребует больше ресурсов CPU и сети.

default_TIMEOUT = 2  # в секундах
# default_TIMEOUT - стандартное время ожидания при попытке
# установить соединение с прокси-сервером. Если сервер не отвечает
# в течение этого времени, попытка соединения считается неудачной.

GEO_CACHE = {}
# GEO_CACHE - кеш для хранения результатов геолокации (страны)
# по IP-адресам. Предотвращает повторные запросы к внешнему API
# при проверке большого количества прокси.

# =====================================================
# Переменные, используемые в процессе работы скрипта
# =====================================================

WORKERS = default_WORKERS
# WORKERS - текущее количество потоков, установленное
# пользователем при запуске скрипта.

TIMEOUT = default_TIMEOUT
# TIMEOUT - текущее значение таймаута в секундах, установленное
# пользователем при запуске скрипта.

# ================================================
# Функция запроса настроек у пользователя
# ================================================
 def get_user_config():
    """
    Запрашивает у пользователя ввод для параметров WORKERS и TIMEOUT.
    Предоставляет подробные подсказки, объясняющие назначение параметров.
    При пустом или некорректном вводе используются значения по умолчанию.
    """
    global WORKERS, TIMEOUT

    # Ввод количества воркеров
    try:
        prompt_w = (
            f"WORKERS - максимальное количество параллельных потоков для проверки прокси. "
            f"Позволяет ускорить обработку, но увеличивает нагрузку на систему. "
            f"Стандартное значение: {default_WORKERS}\n"
            "Введите число потоков и нажмите Enter: "
        )
        inp_w = input(prompt_w)
        # Преобразуем введенное значение в int или используем default_WORKERS
        WORKERS = int(inp_w) if inp_w.strip().isdigit() else default_WORKERS
    except Exception:
        WORKERS = default_WORKERS

    # Ввод таймаута
    try:
        prompt_t = (
            f"TIMEOUT - время ожидания подключения к прокси-серверу в секундах. "
            f"Если прокси не отвечает в заданное время, попытка считается неуспешной. "
            f"Стандартное значение: {default_TIMEOUT}\n"
            "Введите таймаут в секундах и нажмите Enter: "
        )
        inp_t = input(prompt_t)
        # Преобразуем введенное значение в float или используем default_TIMEOUT
        TIMEOUT = float(inp_t) if inp_t.strip() and is_float(inp_t) else default_TIMEOUT
    except Exception:
        TIMEOUT = default_TIMEOUT


def is_float(value):
    """Проверяет, можно ли преобразовать строку в число с плавающей точкой."""
    try:
        float(value)
        return True
    except ValueError:
        return False

# =====================================================
# Функция проверки и мерджа обновлений из upstream
# =====================================================
 def check_and_merge_upstream():
    """
    Проверяет наличие новых коммитов в upstream/main:
      1. Фетчит обновления из удаленного репозитория upstream.
      2. Считает новые коммиты относительно локальной ветки.
      3. При наличии – выполняет merge и продолжает работу.
      4. При конфликтах – отменяет merge и ждет нажатия клавиши для выхода.
    """
    print("Проверка обновлений в upstream...")
    subprocess.run(['git', 'fetch', 'upstream'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    rev = subprocess.run(['git', 'rev-list', 'HEAD..upstream/main', '--count'], capture_output=True, text=True)
    try:
        count = int(rev.stdout.strip() or "0")
    except ValueError:
        count = 0
    if count == 0:
        print("Нет обновлений в upstream.\n")
        return
    print(f"Найдено {count} новых коммитов в upstream. Выполняем merge...")
    merge = subprocess.run(['git', 'merge', 'upstream/main', '--no-edit'], capture_output=True, text=True)
    if merge.returncode == 0:
        print("Merge успешен! Продолжаем...")
    else:
        print("Конфликты при merge:\n", merge.stdout, merge.stderr)
        subprocess.run(['git', 'merge', '--abort'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        input("Нажмите любую клавишу для выхода...")
        sys.exit(1)

# =====================================================
# Создание директории для результатов
# =====================================================
 def ensure_output_dir():
    os.makedirs("available", exist_ok=True)

# =====================================================
# Получение кода страны по IP с кешированием
# =====================================================
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

# =====================================================
# Handshake для различных типов прокси
# =====================================================
 def handshake_socks5(s, host, port):
    s.sendall(b'\x05\x01\x00')
    return s.recv(2) == b'\x05\x00'
 def handshake_socks4(s, host, port):
    try:
        ip_bytes = socket.inet_aton(host)
    except OSError:
        return False
    req = b'\x04\x01' + port.to_bytes(2, 'big') + ip_bytes + b'\x00'
    s.sendall(req)
    resp = s.recv(8)
    return len(resp) == 8 and resp[1] == 0x5A
 def handshake_http(s, host, port):
    req = b"GET http://example.com/ HTTP/1.0\r\nHost: example.com\r\n\r\n"
    s.sendall(req)
    resp = s.recv(7)
    return resp.startswith(b"HTTP/")

# =====================================================
# Обработка файлов со списками прокси
# =====================================================
 def process_file(input_file, output_filename, handshake_fn, label):
    try:
        with open(input_file) as f:
            proxies = [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        print(f"{label}: файл {input_file} не найден.")
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
    print()
    results.sort(key=lambda x: x[1])
    with open(os.path.join("available", output_filename), 'w') as out:
        for proxy, ping, country in results:
            out.write(f"{proxy} (ping: {ping:.2f}s, country: {country})\n")
    print(f"{label}: найдено {len(results)} из {total}")

# =====================================================
# Точка входа
# =====================================================
if __name__ == '__main__':
    get_user_config()
    check_and_merge_upstream()
    ensure_output_dir()
    process_file('socks5.txt', 'available_socks5.txt', handshake_socks5, 'SOCKS5')
    process_file('socks4.txt', 'available_socks4.txt', handshake_socks4, 'SOCKS4')
    process_file('http.txt', 'available_http.txt', handshake_http, 'HTTP')
    input("
    Работа завершена. Нажмите любую клавишу и Enter для выхода...")
