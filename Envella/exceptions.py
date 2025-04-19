
"""
Custom exceptions for SecureDotEnv.
"""

class DotEnvError(Exception):
    """Base exception for all SecureDotEnv errors."""
    pass

class FileNotFoundError(DotEnvError):
    """Raised when a .env file is not found."""
    pass

class ParseError(DotEnvError):
    """Raised when a .env file cannot be parsed."""
    pass

class SecurityError(DotEnvError):
    """Raised when a security issue is detected."""
    pass
