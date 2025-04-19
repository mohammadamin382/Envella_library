# Envella - Envella library
# Copyright (C) 2025 mohammad hosseini
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
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
