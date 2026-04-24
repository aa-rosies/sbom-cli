def truncate(text: str, max_length: int, suffix: str = "...") -> str:
    """Truncate a string to max_length, appending suffix if trimmed."""
    if max_length < len(suffix):
        raise ValueError("max_length must be >= length of suffix")
    if len(text) <= max_length:
        return text
    return text[: max_length - len(suffix)] + suffix
