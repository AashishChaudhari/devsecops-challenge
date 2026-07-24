import re

def validate_password_strength(password):
    """
    Validates password strength.
    Returns (is_valid, list_of_errors)
    """
    errors = []

    if len(password) < 8:
        errors.append("Password must be at least 8 characters")

    if len(password) > 128:
        errors.append("Password must be less than 128 characters")

    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")

    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")

    if not re.search(r'\d', password):
        errors.append("Password must contain at least one number")

    if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-\[\]\\\/`~;\'+=]', password):
        errors.append("Password must contain at least one special character")

    common_passwords = [
        "password", "password1", "Password1!", "12345678",
        "qwerty123", "admin123", "letmein1", "welcome1"
    ]
    if password.lower() in [p.lower() for p in common_passwords]:
        errors.append("Password is too common — choose something unique")

    return len(errors) == 0, errors


def get_password_strength(password):
    """
    Returns a strength score: weak, fair, strong, very_strong
    """
    score = 0
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if re.search(r'[A-Z]', password):
        score += 1
    if re.search(r'[a-z]', password):
        score += 1
    if re.search(r'\d', password):
        score += 1
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1
    if len(password) >= 16:
        score += 1

    if score <= 2:
        return "weak"
    elif score <= 4:
        return "fair"
    elif score <= 6:
        return "strong"
    else:
        return "very_strong"
