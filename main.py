import getpass


import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich import box
from cryptography.fernet import InvalidToken

import crypto
import database
import password_generator

app = typer.Typer(
    help="SecureVault — lokalny menedżer haseł z szyfrowaniem",
    add_completion=False,
)
console = Console()


def print_banner() -> None:
    console.print(Panel.fit(
        "[bold cyan]SecureVault CLI[/bold cyan]\n[dim]Encrypted Password Manager[/dim]",
        border_style="cyan",
        padding=(1, 4),
    ))


def get_master_key() -> bytes:
    config = database.get_vault_config()

    if config is None:
        console.print("[red]✗[/red] Vault nie istnieje. Uruchom najpierw: [cyan]python main.py init[/cyan]")
        raise typer.Exit(1)

    master_password = getpass.getpass("🔑 Master password: ")

    salt = config["salt"]
    expected_hash = config["pw_hash"]
    actual_hash = crypto.hash_master_password(master_password, salt)

    if actual_hash != expected_hash:
        console.print("[red]✗ Błędne master password.[/red]")
        raise typer.Exit(1)

    return crypto.derive_key(master_password, salt)


def validate_not_empty(value: str, field_name: str) -> str:
    while not value.strip():
        console.print(f"[yellow]⚠ Pole '{field_name}' nie może być puste.[/yellow]")
        value = Prompt.ask(f"  {field_name}")
    return value.strip()


@app.command()
def init() -> None:
    """Inicjalizuje nowy vault."""
    print_banner()
    console.print("\n[bold]Inicjalizacja nowego vaulta...[/bold]\n")

    if database.is_initialized():
        console.print("[yellow]⚠ Vault już istnieje.[/yellow]")
        overwrite = Confirm.ask("Czy chcesz zresetować vault? [red]USUNIE WSZYSTKIE DANE[/red]")
        if not overwrite:
            console.print("[dim]Anulowano.[/dim]")
            raise typer.Exit(0)

    while True:
        password = getpass.getpass("🔑 Nowe master password: ")

        if len(password) < 8:
            console.print("[red]✗ Hasło musi mieć co najmniej 8 znaków.[/red]")
            continue

        password_confirm = getpass.getpass("🔑 Potwierdź master password: ")

        if password != password_confirm:
            console.print("[red]✗ Hasła nie są identyczne. Spróbuj ponownie.[/red]")
            continue

        break

    database.initialize_database()

    salt = crypto.generate_salt()
    pw_hash = crypto.hash_master_password(password, salt)
    database.save_vault_config(salt, pw_hash)

    console.print("\n[green]✓ Vault zainicjalizowany pomyślnie![/green]")
    console.print(f"[dim]Lokalizacja: {database.DB_PATH}[/dim]")
    console.print("\n[dim]Następny krok:[/dim] [cyan]python main.py add[/cyan]")


@app.command()
def add() -> None:
    """Dodaje nowe dane logowania do vaulta."""
    print_banner()
    console.print("\n[bold]Dodawanie nowego wpisu...[/bold]\n")

    key = get_master_key()

    console.print()

    service = validate_not_empty(
        Prompt.ask("  [cyan]Serwis[/cyan] (np. github.com)"),
        "Serwis"
    )

    login = validate_not_empty(
        Prompt.ask("  [cyan]Login[/cyan]"),
        "Login"
    )

    use_generated = Confirm.ask("  Wygenerować hasło automatycznie?", default=True)

    if use_generated:
        pw_length = Prompt.ask("  Długość hasła", default="16")

        try:
            pw_length = int(pw_length)
        except ValueError:
            pw_length = 16

        generated = password_generator.generate_password(length=pw_length)
        strength, color = password_generator.estimate_strength(generated)

        console.print(f"\n  Wygenerowane hasło: [bold]{generated}[/bold]")
        console.print(f"  Siła: [{color}]{strength}[/{color}]")

        password = generated
    else:
        password = getpass.getpass("  Hasło: ")

        if not password.strip():
            console.print("[red]✗ Hasło nie może być puste.[/red]")
            raise typer.Exit(1)

    notes = Prompt.ask("  [cyan]Notatki[/cyan] (opcjonalne, Enter aby pominąć)", default="")

    encrypted_password = crypto.encrypt(password, key)
    credential_id = database.add_credential(
        service=service,
        login=login,
        encrypted_password=encrypted_password,
        notes=notes if notes.strip() else None,
    )

    console.print(f"\n[green]✓ Wpis #{credential_id} dla '[bold]{service}[/bold]' zapisany pomyślnie![/green]")


@app.command(name="list")
def list_credentials() -> None:
    """Wyświetla listę wszystkich zapisanych wpisów."""
    print_banner()

    get_master_key()

    rows = database.get_all_credentials()

    if not rows:
        console.print("\n[yellow]Vault jest pusty.[/yellow]")
        console.print("[dim]Dodaj pierwszy wpis:[/dim] [cyan]python main.py add[/cyan]")
        return

    table = Table(
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold cyan",
        show_lines=True,
    )

    table.add_column("ID", style="dim", width=4, justify="right")
    table.add_column("Serwis", style="bold white")
    table.add_column("Login", style="green")
    table.add_column("Dodano", style="dim")

    for row in rows:
        created_date = row["created_at"][:10] if row["created_at"] else "—"
        table.add_row(
            str(row["id"]),
            row["service"],
            row["login"],
            created_date,
        )

    console.print(f"\n[dim]Znaleziono {len(rows)} {'wpis' if len(rows) == 1 else 'wpisy' if 1 < len(rows) < 5 else 'wpisów'}[/dim]\n")
    console.print(table)
    console.print(f"\n[dim]Aby zobaczyć hasło: [cyan]python main.py show <serwis>[/cyan][/dim]")


@app.command()
def show(service: str = typer.Argument(..., help="Nazwa serwisu do wyświetlenia")) -> None:
    """Wyświetla i odszyfrowuje dane dla podanego serwisu."""
    print_banner()
    console.print(f"\n[bold]Wpis dla:[/bold] [cyan]{service}[/cyan]\n")

    key = get_master_key()

    row = database.get_credential_by_service(service)

    if row is None:
        console.print(f"\n[red]✗ Nie znaleziono wpisu dla '[bold]{service}[/bold]'.[/red]")
        console.print("[dim]Sprawdź dostępne wpisy:[/dim] [cyan]python main.py list[/cyan]")
        raise typer.Exit(1)

    try:
        decrypted_password = crypto.decrypt(row["password"], key)
    except InvalidToken:
        console.print("[red]✗ Nie można odszyfrować hasła. Klucz jest nieprawidłowy.[/red]")
        raise typer.Exit(1)

    strength, color = password_generator.estimate_strength(decrypted_password)

    content = (
        f"[dim]ID:[/dim]       {row['id']}\n"
        f"[dim]Serwis:[/dim]   [bold white]{row['service']}[/bold white]\n"
        f"[dim]Login:[/dim]    [green]{row['login']}[/green]\n"
        f"[dim]Hasło:[/dim]    [bold yellow]{decrypted_password}[/bold yellow]  "
        f"[{color}]({strength})[/{color}]\n"
        f"[dim]Notatki:[/dim]  {row['notes'] or '—'}\n"
        f"[dim]Dodano:[/dim]   {row['created_at'][:10]}"
    )

    console.print(Panel(
        content,
        title=f"[bold cyan]{row['service']}[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    ))


@app.command()
def generate(
    length: int = typer.Option(16, "--length", "-l", help="Długość hasła"),
    no_symbols: bool = typer.Option(False, "--no-symbols", help="Bez symboli specjalnych"),
    no_digits: bool = typer.Option(False, "--no-digits", help="Bez cyfr"),
    no_uppercase: bool = typer.Option(False, "--no-uppercase", help="Bez wielkich liter"),
    count: int = typer.Option(1, "--count", "-c", help="Ile haseł wygenerować"),
) -> None:
    """Generuje bezpieczne hasło bez zapisywania do vaulta."""
    print_banner()
    console.print("\n[bold]Generator haseł[/bold]\n")

    if length < 8:
        console.print("[red]✗ Minimalna długość to 8 znaków.[/red]")
        raise typer.Exit(1)

    table = Table(
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold cyan",
    )
    table.add_column("#", style="dim", width=3, justify="right")
    table.add_column("Hasło", style="bold yellow")
    table.add_column("Siła", justify="center")
    table.add_column("Długość", justify="center", style="dim")

    for i in range(count):
        try:
            pwd = password_generator.generate_password(
                length=length,
                use_digits=not no_digits,
                use_symbols=not no_symbols,
                use_uppercase=not no_uppercase,
            )
        except ValueError as e:
            console.print(f"[red]✗ {e}[/red]")
            raise typer.Exit(1)

        strength, color = password_generator.estimate_strength(pwd)
        table.add_row(
            str(i + 1),
            pwd,
            f"[{color}]{strength}[/{color}]",
            str(len(pwd)),
        )

    options_used = []
    if not no_digits:
        options_used.append("cyfry")
    if not no_symbols:
        options_used.append("symbole")
    if not no_uppercase:
        options_used.append("wielkie litery")

    console.print(f"[dim]Opcje: {', '.join(options_used)}[/dim]\n")
    console.print(table)
    console.print(f"\n[dim]Aby zapisać hasło do vaulta: [cyan]python main.py add[/cyan][/dim]")


if __name__ == "__main__":
    app()