import secrets
import string

LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"


def generate_password(
    length: int = 16,
    use_digits: bool = True,
    use_symbols: bool = True,
    use_uppercase: bool = True,
) -> str:
    if length < 8:
        raise ValueError("Minimalna długość hasła to 8 znaków")

    charset = LOWERCASE

    if use_uppercase:
        charset += UPPERCASE
    if use_digits:
        charset += DIGITS
    if use_symbols:
        charset += SYMBOLS

    required_chars = [secrets.choice(LOWERCASE)]

    if use_uppercase:
        required_chars.append(secrets.choice(UPPERCASE))
    if use_digits:
        required_chars.append(secrets.choice(DIGITS))
    if use_symbols:
        required_chars.append(secrets.choice(SYMBOLS))

    remaining_length = length - len(required_chars)
    random_chars = [secrets.choice(charset) for _ in range(remaining_length)]

    all_chars = required_chars + random_chars
    secrets.SystemRandom().shuffle(all_chars)

    return "".join(all_chars)


def estimate_strength(password: str) -> tuple[str, str]:
    score = 0

    if len(password) >= 12:
        score += 1
    if len(password) >= 16:
        score += 1
    if any(c in DIGITS for c in password):
        score += 1
    if any(c in SYMBOLS for c in password):
        score += 1
    if any(c in UPPERCASE for c in password):
        score += 1
    if any(c in LOWERCASE for c in password):
        score += 1

    if score <= 2:
        return "Weak", "red"
    elif score <= 4:
        return "Moderate", "yellow"
    else:
        return "Strong", "green"