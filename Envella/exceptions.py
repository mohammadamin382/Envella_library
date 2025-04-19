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
