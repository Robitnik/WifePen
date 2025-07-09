from typing import List

from consolemenu import SelectionMenu
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

# ── ANSI-кольори ──────────────────────────────────────────────────────────────
TITLE_COLOR = Fore.YELLOW + Style.BRIGHT
OPTION_COLOR = Fore.CYAN
RESET = Style.RESET_ALL


def _colorize(opts: List[str]) -> List[str]:
    """Розфарбувати пункти меню."""
    return [f"{OPTION_COLOR}{opt}{RESET}" for opt in opts]


# ── універсальне «діалогове» вікно ────────────────────────────────────────────
def show_message(text: str, title: str = "Info") -> None:
    """Вивести повідомлення й чекати натиснення **OK**."""
    SelectionMenu.get_selection(
        ["OK"],
        title=f"{TITLE_COLOR}{title}{RESET}\n\n{text}",
    )


# ── меню для CLI ─────────────────────────────────────────────────────────────
def choose_main_action(options: List[str]) -> int:
    return SelectionMenu.get_selection(
        _colorize(options), title=f"{TITLE_COLOR}Головне меню{RESET}"
    )


def choose_device(devices: List[str]) -> int:
    if not devices:
        show_message("Не знайдено жодного Wi-Fi-інтерфейсу!", "Помилка")
        return -1
    return SelectionMenu.get_selection(
        _colorize(devices),
        title=f"{TITLE_COLOR}Виберіть мережевий інтерфейс{RESET}",
    )

# ── меню для роботи з роутером ─────────────────────────────────────────────────────────────

def choose_device_actions(info) -> int:
    act = SelectionMenu.get_selection(
        ["Start connect (wait for handshake)", "Brute force password (rockyou.txt)"],
        title=f"{TITLE_COLOR}Network info{RESET}\n\n{info}"
    )
    return act