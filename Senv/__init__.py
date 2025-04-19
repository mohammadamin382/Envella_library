
"""
Senv
----

A comprehensive, secure and highly advanced library for managing .env files
with extensive features for environment variable parsing, validation, and manipulation.

Author: Mohammad Hosseini
License: GPL-3.0
"""

from Senv.Senv import SecureDotEnv as Senv
# For backwards compatibility
SecureDotEnv = Senv

from Senv.exceptions import DotEnvError, FileNotFoundError, ParseError, SecurityError
from Senv.utils import (
    encrypt_value, decrypt_value, cast_value, generate_secure_key, 
    encrypt_with_quantum_resistant_hybrid, decrypt_with_quantum_resistant_hybrid,
    vault_encrypt, vault_decrypt, generate_mfa_secret, verify_totp_code, 
    generate_recovery_codes, generate_environment_integrity_signature
)

__version__ = '1.0.0'
__author__ = 'Mohammad Hosseini'
__license__ = 'GPL-3.0'
__all__ = [
    'Senv', 'DotEnvError', 'FileNotFoundError', 'ParseError', 'SecurityError',
    'encrypt_value', 'decrypt_value', 'cast_value', 'generate_secure_key',
    'encrypt_with_quantum_resistant_hybrid', 'decrypt_with_quantum_resistant_hybrid',
    'vault_encrypt', 'vault_decrypt', 'generate_mfa_secret', 'verify_totp_code',
    'generate_recovery_codes', 'generate_environment_integrity_signature'
]
