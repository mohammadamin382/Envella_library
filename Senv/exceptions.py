
"""
Custom exceptions for Senv.
"""

class DotEnvError(Exception):
    """Base exception for all Senv errors."""
    pass

class FileNotFoundError(DotEnvError):
    """Raised when a .env file is not found."""
    pass

class ParseError(DotEnvError):
    """Raised when a .env file cannot be parsed."""
    pass
