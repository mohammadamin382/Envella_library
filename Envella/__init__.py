
"""
Envella
----

A comprehensive, secure and highly advanced library for managing .env files
with extensive features for environment variable parsing, validation, and manipulation.

Author: Mohammad Hosseini
License: GPL-3.0
"""

from Envella.Envella import SecureDotEnv as Envella
# For backwards compatibility
SecureDotEnv = Envella

from Envella.exceptions import DotEnvError, FileNotFoundError, ParseError, SecurityError
from Envella.utils import (
    encrypt_value, decrypt_value, cast_value, generate_secure_key, 
    encrypt_with_quantum_resistant_hybrid, decrypt_with_quantum_resistant_hybrid,
    vault_encrypt, vault_decrypt, generate_mfa_secret, verify_totp_code, 
    generate_recovery_codes, generate_environment_integrity_signature
)

__version__ = '1.0.0'
__author__ = 'Mohammad Hosseini'
__license__ = 'GPL-3.0'
__all__ = [
    'Envella', 'DotEnvError', 'FileNotFoundError', 'ParseError', 'SecurityError',
    'encrypt_value', 'decrypt_value', 'cast_value', 'generate_secure_key',
    'encrypt_with_quantum_resistant_hybrid', 'decrypt_with_quantum_resistant_hybrid',
    'vault_encrypt', 'vault_decrypt', 'generate_mfa_secret', 'verify_totp_code',
    'generate_recovery_codes', 'generate_environment_integrity_signature'
]
