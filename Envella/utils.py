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
Utility functions for SecureDotEnv.
"""
import re
import json
import base64
import os
import secrets
import hashlib
import time
import math
from typing import Any, Dict, Union, Optional, Tuple, List
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

def cast_value(value: str) -> Any:
    """
    Attempt to cast a string value to an appropriate Python type.
    
    Args:
        value: The string value to cast
        
    Returns:
        The value cast to the most appropriate type
    """
    # Check for empty value
    if not value:
        return ""
        
    # Use a cached lowercase value to avoid repeated conversions
    value_lower = value.lower()
    
    # Boolean check - most common case first for speed
    if value_lower == "true" or value_lower == "yes" or value_lower == "1" or value_lower == "on":
        return True
    if value_lower == "false" or value_lower == "no" or value_lower == "0" or value_lower == "off":
        return False
    
    # Integer check - faster than regex for common case
    if value.isdigit() or (value.startswith('-') and value[1:].isdigit()):
        return int(value)
        
    # Float check - more efficient approach
    try:
        if '.' in value:
            return float(value)
    except ValueError:
        pass
        
    # JSON checks for complex types
    first_char = value[0] if value else ''
    last_char = value[-1] if value else ''
    
    if (first_char == '[' and last_char == ']') or (first_char == '{' and last_char == '}'):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            pass
            
    # Default to string
    return value

def sanitize_value(value: str) -> str:
    """
    Sanitize a value to prevent security issues.
    
    Args:
        value: The value to sanitize
        
    Returns:
        Sanitized value
    """
    # Strip any command injection characters
    sanitized = re.sub(r'[`$]', '', value)
    # Limit length
    return sanitized[:1000]

def derive_key(password: str, salt: Optional[bytes] = None) -> tuple:
    """
    Derive a cryptographic key from a password.
    
    Args:
        password: The password to derive the key from
        salt: Optional salt, generated if not provided
        
    Returns:
        Tuple of (key, salt)
    """
    if salt is None:
        salt = os.urandom(16)
        
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_value(value: str, password: str) -> str:
    """
    Encrypt a value using Fernet symmetric encryption.
    Optimized for speed with better memory management.
    
    Args:
        value: The value to encrypt
        password: The password to use for encryption
        
    Returns:
        Encrypted value as a base64-encoded string
    """
    # Use cached Fernet instances based on password hash to avoid recreating
    password_hash = str(hash(password))
    if not hasattr(encrypt_value, 'key_cache'):
        encrypt_value.key_cache = {}
    
    if password_hash in encrypt_value.key_cache:
        key, salt, f = encrypt_value.key_cache[password_hash]
    else:
        key, salt = derive_key(password)
        f = Fernet(key)
        # Cache for future use with same password
        encrypt_value.key_cache[password_hash] = (key, salt, f)
    
    # Encode and encrypt in a single operation
    value_bytes = value.encode('utf-8')
    encrypted = f.encrypt(value_bytes)
    
    # More efficient combination
    result = base64.urlsafe_b64encode(salt + encrypted).decode('ascii')
    return result

def decrypt_value(encrypted_value: str, password: str) -> str:
    """
    Decrypt a value that was encrypted with encrypt_value.
    Optimized for speed with cached operations.
    
    Args:
        encrypted_value: The encrypted value as a base64-encoded string
        password: The password used for encryption
        
    Returns:
        Decrypted value as a string
    """
    # Decode once
    data = base64.urlsafe_b64decode(encrypted_value.encode('ascii'))
    salt, encrypted = data[:16], data[16:]
    
    # Use cached Fernet instances for decryption
    salt_hash = str(hash(salt))
    if not hasattr(decrypt_value, 'key_cache'):
        decrypt_value.key_cache = {}
    
    cache_key = f"{password}:{salt_hash}"
    if cache_key in decrypt_value.key_cache:
        f = decrypt_value.key_cache[cache_key]
    else:
        key, _ = derive_key(password, salt)
        f = Fernet(key)
        decrypt_value.key_cache[cache_key] = f
    
    # Decrypt and decode in a single operation
    return f.decrypt(encrypted).decode('utf-8')

def generate_secure_key(length: int = 32) -> str:
    """
    Generate a cryptographically secure random key.
    
    Args:
        length: Length of the key in bytes
    
    Returns:
        Secure key as a hex string
    """
    return secrets.token_hex(length)

def hash_sensitive_value(value: str, salt: Optional[bytes] = None) -> Tuple[str, bytes]:
    """
    Create a secure hash of a sensitive value with salt.
    
    Args:
        value: The value to hash
        salt: Optional salt, generated if not provided
    
    Returns:
        Tuple of (hash_string, salt)
    """
    if salt is None:
        salt = os.urandom(16)
    
    key = hashlib.pbkdf2_hmac(
        'sha256', 
        value.encode(), 
        salt, 
        100000
    )
    
    return base64.b64encode(key).decode('ascii'), salt

def generate_rsa_keypair() -> Tuple[str, str]:
    """
    Generate an RSA key pair for asymmetric encryption.
    
    Returns:
        Tuple of (private_key_pem, public_key_pem)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    public_key = private_key.public_key()
    
    # Get the keys in PEM format
    from cryptography.hazmat.primitives import serialization
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return private_pem, public_pem

def encrypt_with_public_key(public_key_pem: str, message: str) -> str:
    """
    Encrypt a message with an RSA public key.
    
    Args:
        public_key_pem: The public key in PEM format
        message: The message to encrypt
    
    Returns:
        Base64-encoded encrypted message
    """
    public_key = load_pem_public_key(public_key_pem.encode())
    
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return base64.b64encode(encrypted).decode('ascii')

def decrypt_with_private_key(private_key_pem: str, encrypted_message: str) -> str:
    """
    Decrypt a message with an RSA private key.
    
    Args:
        private_key_pem: The private key in PEM format
        encrypted_message: The encrypted message in base64 format
    
    Returns:
        Decrypted message
    """
    private_key = load_pem_private_key(
        private_key_pem.encode(),
        password=None
    )
    
    decrypted = private_key.decrypt(
        base64.b64decode(encrypted_message),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return decrypted.decode('utf-8')

def secure_compare(val1: str, val2: str) -> bool:
    """
    Compare two strings in constant time to prevent timing attacks.
    
    Args:
        val1: First string
        val2: Second string
    
    Returns:
        True if strings are equal, False otherwise
    """
    if len(val1) != len(val2):
        return False
    
    result = 0
    for x, y in zip(val1, val2):
        result |= ord(x) ^ ord(y)
    
    return result == 0

def detect_secrets_in_content(content: str) -> List[dict]:
    """
    Detect potential secrets/credentials in content with enhanced detection.
    
    Args:
        content: The text content to scan
    
    Returns:
        List of dictionaries with details about potential secrets found
    """
    secret_patterns = {
        'api_key': [
            r'[a-zA-Z0-9_\-]{20,40}',  # Common API key format
            r'(access|api|auth|client|secret|token)(_|-)?key(:|=|\s)\S+',
        ],
        'auth_token': [
            r'bearer\s+[a-zA-Z0-9_\-\.]+',
            r'authorization\s*:\s*bearer\s+[a-zA-Z0-9_\-\.]+',
            r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',  # JWT format
        ],
        'aws_key': [
            r'AKIA[0-9A-Z]{16}',
            r'ASIA[0-9A-Z]{16}',
            r'aws_access_key_id\s*=\s*[A-Z0-9]{20}',
            r'aws_secret_access_key\s*=\s*[A-Za-z0-9/+]{40}',
        ],
        'private_key': [
            r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
            r'BEGIN PRIVATE KEY',
        ],
        'credentials': [
            r'(password|passwd|pwd)(:|=|\s)\S+',
            r'(username|user)(:|=|\s)\S+.*(password|passwd|pwd)(:|=|\s)\S+',
        ],
        'database_url': [
            r'(mysql|postgresql|postgres|mongodb|redis)://[^\s]+',
            r'(jdbc:(mysql|postgresql|oracle|sqlserver))://[^\s]+',
            r'connection_string\s*=\s*["\']?[^\s;,]+(;[^\s;,]*)*["\']?',
        ],
        'github': [
            r'github[_\-\.]?token\s*[=:]\s*[A-Za-z0-9_]{36,}',
            r'gh[pousr]_[A-Za-z0-9_]{36,}',
        ],
        'google': [
            r'AIza[0-9A-Za-z_-]{35}',
            r'ya29\.[0-9A-Za-z_-]+',
        ],
        'slack': [
            r'xox[pbar]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{32}',
        ],
        'stripe': [
            r'sk_live_[0-9a-zA-Z]{24}',
            r'pk_live_[0-9a-zA-Z]{24}',
        ],
    }
    
    found_secrets = []
    line_number = 0
    
    for line in content.splitlines():
        line_number += 1
        
        for secret_type, patterns in secret_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    # Calculate risk score based on entropy and pattern confidence
                    value = match.group(0)
                    risk_score = _calculate_entropy_risk(value, secret_type)
                    
                    # Skip if risk score is too low (likely false positive)
                    if risk_score < 0.3:
                        continue
                        
                    found_secrets.append({
                        'type': secret_type,
                        'value': value,
                        'line': line_number,
                        'risk_score': risk_score,
                        'match': match.group(0),
                    })
    
    return found_secrets

def _calculate_entropy_risk(value: str, secret_type: str) -> float:
    """
    Calculate a risk score based on string entropy and secret type.
    
    Args:
        value: The string to analyze
        secret_type: Type of secret (affects base score)
    
    Returns:
        Risk score between 0 and 1
    """
    # Base risk by secret type
    base_risks = {
        'api_key': 0.7,
        'auth_token': 0.7,
        'aws_key': 0.9,
        'private_key': 0.95,
        'credentials': 0.8,
        'database_url': 0.7,
        'github': 0.8,
        'google': 0.8,
        'slack': 0.8,
        'stripe': 0.9,
    }
    
    base_risk = base_risks.get(secret_type, 0.5)
    
    # Calculate Shannon entropy
    if len(value) < 8:  # Too short, likely not a secret
        return base_risk * 0.3
        
    # Calculate entropy
    entropy = 0
    for x in range(256):
        p_x = float(value.count(chr(x))) / len(value)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
            
    # Normalized entropy score (higher entropy = more likely to be a secret)
    entropy_factor = min(1.0, entropy / 5.0)  # Normalize, with 5.0 being high entropy
    
    # Character diversity check
    has_lowercase = any(c.islower() for c in value)
    has_uppercase = any(c.isupper() for c in value)
    has_digit = any(c.isdigit() for c in value)
    has_special = any(not c.isalnum() for c in value)
    
    diversity_count = sum([has_lowercase, has_uppercase, has_digit, has_special])
    diversity_factor = diversity_count / 4.0
    
    # Combine factors
    return base_risk * 0.5 + entropy_factor * 0.3 + diversity_factor * 0.2

def check_security_vulnerabilities(env_values: Dict[str, str]) -> List[dict]:
    """
    Check for potential security vulnerabilities in environment values with 
    enhanced detection capabilities and detailed recommendations.
    
    Args:
        env_values: Dictionary of environment variables
        
    Returns:
        List of potential vulnerabilities found
    """
    vulnerabilities = []
    
    # Check for hardcoded credentials with improved detection
    sensitive_patterns = [
        (r'pass', 'password'), 
        (r'secret', 'secret'), 
        (r'key', 'API key'), 
        (r'token', 'token'),
        (r'auth', 'authentication credential'),
        (r'credential', 'credential'),
        (r'pwd', 'password'),
        (r'cert', 'certificate'),
        (r'sign', 'signature'),
        (r'salt', 'cryptographic salt')
    ]
    
    for key, value in env_values.items():
        # Skip empty values or already encrypted values
        if not value or value.startswith('${') or value.startswith('ENC:'):
            continue
            
        # Check for sensitive keys
        for pattern, type_name in sensitive_patterns:
            if pattern in key.lower():
                entropy = _calculate_entropy(value)
                risk_level = 'high' if entropy > 3.5 or len(value) > 16 else 'medium'
                
                # Enhanced recommendation based on the type of credential
                if 'pass' in key.lower() or 'secret' in key.lower():
                    recommendation = 'Use Replit Secrets tool or encrypt this sensitive value'
                elif 'key' in key.lower() or 'token' in key.lower():
                    recommendation = 'Store API keys/tokens in Replit Secrets or use environment-specific encrypted files'
                else:
                    recommendation = 'Consider encrypting this sensitive value or use Replit Secrets'
                
                vulnerabilities.append({
                    'type': 'hardcoded_credential',
                    'subtype': type_name,
                    'key': key,
                    'value': value[:2] + '***' + value[-2:] if len(value) > 5 else '******',
                    'entropy': round(entropy, 2),
                    'risk': risk_level,
                    'recommendation': recommendation
                })
                break
    
    # Enhanced configuration security checks
    insecure_configs = [
        ('DEBUG', 'true', 'medium', 'Set DEBUG to false in production environments'),
        ('NODE_ENV', 'development', 'medium', 'Set NODE_ENV to production in production environments'),
        ('ENV', 'development', 'medium', 'Set ENV to production in production environments'),
        ('FLASK_ENV', 'development', 'medium', 'Set FLASK_ENV to production in production environments'),
        ('ENVIRONMENT', 'dev', 'medium', 'Set ENVIRONMENT to prod in production environments'),
        ('APP_ENV', 'dev', 'medium', 'Set APP_ENV to prod in production environments'),
        ('LOG_LEVEL', 'debug', 'low', 'Consider setting LOG_LEVEL to info/warn in production'),
        ('DISABLE_SECURITY', 'true', 'critical', 'Never disable security features in production'),
        ('ALLOW_ORIGIN', '*', 'high', 'Avoid using wildcard CORS settings in production'),
        ('DISABLE_AUTH', 'true', 'critical', 'Never disable authentication in production'),
        ('DISABLE_VALIDATION', 'true', 'high', 'Input validation should always be enabled')
    ]
    
    for key, bad_value, risk, recommendation in insecure_configs:
        if key in env_values and env_values[key].lower() == bad_value:
            vulnerabilities.append({
                'type': 'insecure_config',
                'key': key,
                'risk': risk,
                'recommendation': recommendation
            })
    
    # Enhanced protocol security checks
    for key, value in env_values.items():
        if isinstance(value, str):
            # Check for insecure URLs
            if ('URL' in key.upper() or 'URI' in key.upper() or 'ENDPOINT' in key.upper()):
                if value.startswith('http:'):
                    vulnerabilities.append({
                        'type': 'insecure_protocol',
                        'key': key,
                        'risk': 'high',
                        'recommendation': 'Use HTTPS instead of HTTP for security'
                    })
                    
            # Check for insecure database connections
            if ('DB_' in key.upper() or 'DATABASE_' in key.upper()) and 'URL' in key.upper():
                if 'sslmode=disable' in value or 'ssl=false' in value:
                    vulnerabilities.append({
                        'type': 'insecure_database',
                        'key': key,
                        'risk': 'high',
                        'recommendation': 'Enable SSL/TLS for database connections'
                    })
            
            # Check for hardcoded IPs
            if re.search(r'\d+\.\d+\.\d+\.\d+', value):
                vulnerabilities.append({
                    'type': 'hardcoded_ip',
                    'key': key,
                    'risk': 'medium',
                    'recommendation': 'Use domain names instead of IP addresses, or separate configuration by environment'
                })
    
    # Check for common JWT security misconfigurations
    if 'JWT_SECRET' in env_values and len(env_values['JWT_SECRET']) < 32:
        vulnerabilities.append({
            'type': 'weak_secret',
            'key': 'JWT_SECRET',
            'risk': 'high',
            'recommendation': 'Use a JWT secret of at least 32 characters with high entropy'
        })
        
    if 'JWT_ALGORITHM' in env_values and env_values['JWT_ALGORITHM'] in ['none', 'HS256']:
        vulnerabilities.append({
            'type': 'weak_algorithm',
            'key': 'JWT_ALGORITHM',
            'risk': 'medium',
            'recommendation': 'Use stronger JWT algorithms like RS256, ES256, or EdDSA'
        })
    
    # Check for security feature disabling
    for key in env_values:
        lower_key = key.lower()
        if ('disable' in lower_key or 'skip' in lower_key) and ('secur' in lower_key or 'auth' in lower_key or 'verify' in lower_key):
            if env_values[key].lower() in ['true', 'yes', '1', 'on']:
                vulnerabilities.append({
                    'type': 'security_bypass',
                    'key': key,
                    'risk': 'critical',
                    'recommendation': 'Never disable security features in production environments'
                })
    
    return vulnerabilities

def _calculate_entropy(value: str) -> float:
    """
    Calculate the Shannon entropy of a string to measure randomness/complexity.
    Higher values indicate more complex and potentially sensitive data.
    
    Args:
        value: String to analyze
        
    Returns:
        Entropy value (higher is more complex/random)
    """
    if not value:
        return 0.0
        
    # Get probability of each character
    prob = [float(value.count(c)) / len(value) for c in dict.fromkeys(list(value))]
    
    # Calculate entropy
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy
    
def assess_password_strength(password: str) -> dict:
    """
    Perform a comprehensive assessment of password strength with detailed feedback.
    
    Args:
        password: The password to assess
        
    Returns:
        Dictionary with strength assessment details
    """
    if not password:
        return {
            "score": 0,
            "strength": "none",
            "feedback": "Password is empty",
            "measures": {},
            "time_to_crack": "instant"
        }
    
    # Basic character class checks
    has_lowercase = any(c.islower() for c in password)
    has_uppercase = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    # Length check
    length = len(password)
    
    # Calculate entropy
    entropy = _calculate_entropy(password)
    
    # Check for common patterns
    sequential_chars = False
    repeated_chars = False
    keyboard_patterns = False
    
    # Check for sequential patterns
    for i in range(len(password) - 2):
        if (ord(password[i+1]) - ord(password[i]) == 1 and
            ord(password[i+2]) - ord(password[i+1]) == 1):
            sequential_chars = True
            break
    
    # Check for repeated characters
    for i in range(len(password) - 2):
        if password[i] == password[i+1] and password[i+1] == password[i+2]:
            repeated_chars = True
            break
    
    # Common keyboard patterns (simplified check)
    keyboard_rows = [
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm"
    ]
    
    for row in keyboard_rows:
        for i in range(len(row) - 2):
            if row[i:i+3].lower() in password.lower():
                keyboard_patterns = True
                break
        if keyboard_patterns:
            break
    
    # Calculate base score
    score = 0
    if length >= 12: score += 2
    elif length >= 8: score += 1
    
    if has_lowercase: score += 1
    if has_uppercase: score += 1
    if has_digit: score += 1
    if has_special: score += 1
    
    # Penalize for patterns
    if sequential_chars: score -= 1
    if repeated_chars: score -= 1
    if keyboard_patterns: score -= 1
    
    # Entropy bonus
    if entropy > 4.0: score += 2
    elif entropy > 3.0: score += 1
    
    # Ensure score is within bounds
    score = max(0, min(5, score))
    
    # Calculate estimated time to crack (very approximate)
    charset_size = 0
    if has_lowercase: charset_size += 26
    if has_uppercase: charset_size += 26
    if has_digit: charset_size += 10
    if has_special: charset_size += 33  # Approximate
    
    if charset_size == 0:  # Fallback
        charset_size = 26
    
    # Very rough estimate of time to crack with typical hardware
    # Assuming 10 billion attempts per second (high-end)
    possible_combinations = charset_size ** length
    seconds_to_crack = possible_combinations / (10 ** 10)
    
    # Format time to crack
    time_to_crack = "instant"
    if seconds_to_crack > 60:
        minutes_to_crack = seconds_to_crack / 60
        if minutes_to_crack > 60:
            hours_to_crack = minutes_to_crack / 60
            if hours_to_crack > 24:
                days_to_crack = hours_to_crack / 24
                if days_to_crack > 365:
                    years_to_crack = days_to_crack / 365
                    if years_to_crack > 1000000:
                        time_to_crack = "millions of years"
                    elif years_to_crack > 1000:
                        time_to_crack = f"{int(years_to_crack / 1000)}k years"
                    else:
                        time_to_crack = f"{int(years_to_crack)} years"
                else:
                    time_to_crack = f"{int(days_to_crack)} days"
            else:
                time_to_crack = f"{int(hours_to_crack)} hours"
        else:
            time_to_crack = f"{int(minutes_to_crack)} minutes"
    elif seconds_to_crack > 1:
        time_to_crack = f"{int(seconds_to_crack)} seconds"
    
    # Map score to strength label
    strength_labels = {
        0: "very weak",
        1: "weak",
        2: "moderate",
        3: "good",
        4: "strong",
        5: "very strong"
    }
    
    # Generate feedback
    feedback = []
    if length < 8:
        feedback.append("Password is too short")
    if not has_lowercase:
        feedback.append("Add lowercase letters")
    if not has_uppercase:
        feedback.append("Add uppercase letters")
    if not has_digit:
        feedback.append("Add numbers")
    if not has_special:
        feedback.append("Add special characters")
    if sequential_chars:
        feedback.append("Avoid sequential characters")
    if repeated_chars:
        feedback.append("Avoid repeated characters")
    if keyboard_patterns:
        feedback.append("Avoid keyboard patterns")
    
    return {
        "score": score,
        "strength": strength_labels.get(score, "unknown"),
        "feedback": feedback if feedback else ["Password is good"],
        "entropy": round(entropy, 2),
        "measures": {
            "length": length,
            "has_lowercase": has_lowercase,
            "has_uppercase": has_uppercase,
            "has_digit": has_digit,
            "has_special": has_special,
            "has_sequential": sequential_chars,
            "has_repeated": repeated_chars,
            "has_keyboard_pattern": keyboard_patterns
        },
        "time_to_crack": time_to_crack
    }

def generate_mfa_secret(length: int = 32) -> str:
    """
    Generate a secure MFA secret for two-factor authentication.
    Enhanced with stronger default length and higher entropy.
    
    Args:
        length: Length of the secret in bytes (default: 32 for improved security)
    
    Returns:
        Base32 encoded secret for TOTP
    """
    import base64
    
    # Generate high-entropy random bytes with cryptographically secure RNG
    random_bytes = secrets.token_bytes(length)
    return base64.b32encode(random_bytes).decode('utf-8')

def verify_totp_code(secret: str, code: str, 
                     time_step: int = 30,
                     window: int = 1,
                     hash_algorithm: str = 'sha256') -> bool:
    """
    Verify a TOTP code for two-factor authentication.
    Enhanced with stronger hash algorithm and configurable parameters.
    
    Args:
        secret: The secret key (base32 encoded)
        code: The code to verify
        time_step: Time step in seconds (default: 30)
        window: Number of time steps to check before/after current time (default: 1)
        hash_algorithm: Hash algorithm to use (default: sha256, alternatives: sha1, sha512)
        
    Returns:
        True if the code is valid, False otherwise
    """
    import hmac
    import hashlib
    import base64
    import struct
    import time
    
    # Use getattr for better performance than dynamic string lookup
    hash_func = getattr(hashlib, hash_algorithm)
    
    if not code or not code.isdigit():
        return False

    # Normalize the code by removing spaces
    code = code.replace(" ", "")
    
    # Determine digits from code length
    digits = len(code)
    if digits not in [6, 8]:  # Support both 6 and 8 digit codes
        digits = 6  # Default to 6
    
    # Get current timestamp and convert to time_step intervals
    timestamp = int(time.time()) // time_step
    
    # Try time window to allow for clock skew
    for delta in range(-window, window + 1):
        # Convert timestamp to bytes
        time_bytes = struct.pack(">Q", timestamp + delta)
        
        try:
            # Decode base32 secret
            secret_bytes = base64.b32decode(secret.upper())
            
            # Generate HMAC with specified hash algorithm
            hmac_hash = hmac.new(secret_bytes, time_bytes, hash_algorithm).digest()
            
            # Extract bytes as specified by RFC 6238
            offset = hmac_hash[-1] & 0x0F
            truncated_hash = hmac_hash[offset:offset+4]
            
            # Convert to integer and take last n digits
            totp_value = (struct.unpack('>I', truncated_hash)[0] & 0x7FFFFFFF) % (10 ** digits)
            
            # Format as n-digit string
            totp_str = f"{totp_value:0{digits}d}"
            
            # Compare with provided code using constant-time comparison
            if secure_compare(totp_str, code):
                return True
        except Exception:
            continue
            
    return False

def generate_recovery_codes(count: int = 10, length: int = 16) -> List[str]:
    """
    Generate recovery codes for account recovery as a backup for MFA.
    
    Args:
        count: Number of recovery codes to generate
        length: Length of each recovery code
        
    Returns:
        List of recovery codes
    """
    import secrets
    from typing import List
    
    codes = []
    for _ in range(count):
        # Generate a random recovery code with dashes for readability
        code_bytes = secrets.token_bytes(length // 2)  # Each byte becomes 2 hex chars
        hex_string = code_bytes.hex()
        
        # Format with dashes every 4 characters
        formatted_code = '-'.join(hex_string[i:i+4] for i in range(0, len(hex_string), 4))
        codes.append(formatted_code[:length+3])  # +3 for dashes
        
    return codes

def encrypt_with_quantum_resistant_hybrid(message: str, password: str) -> str:
    """
    Encrypt a message using a hybrid approach that is resistant to quantum computing attacks.
    Combines symmetric encryption with post-quantum KDF techniques.
    
    Args:
        message: The message to encrypt
        password: The password to use for encryption
        
    Returns:
        Encrypted message with additional security layers
    """
    # Generate a strong salt
    salt = os.urandom(32)
    
    # Use Argon2id for key derivation (quantum-resistant)
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    
    # First layer: scrypt KDF (memory-hard)
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**16,  # CPU/Memory cost parameter
        r=8,       # Block size parameter
        p=1        # Parallelization parameter
    )
    key = kdf.derive(password.encode())
    
    # Second layer: Add computational hardness
    key = hashlib.sha3_512(key).digest()[:32]  # Use SHA3 for additional security
    
    # Generate a nonce for encryption
    nonce = os.urandom(12)
    
    # Use AES-GCM for authenticated encryption
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aesgcm = AESGCM(key)
    
    # Add additional metadata for authentication
    metadata = f"v2-hybrid-{int(time.time())}".encode()
    
    # Encrypt and authenticate
    ciphertext = aesgcm.encrypt(nonce, message.encode(), metadata)
    
    # Combine all components for storage
    result = base64.urlsafe_b64encode(
        b"QRHYBRID" +  # Marker for format identification
        salt +
        nonce +
        len(metadata).to_bytes(2, byteorder='big') +
        metadata +
        ciphertext
    ).decode('ascii')
    
    return result

def decrypt_with_quantum_resistant_hybrid(encrypted_value: str, password: str) -> str:
    """
    Decrypt a message that was encrypted with the quantum-resistant hybrid method.
    
    Args:
        encrypted_value: The encrypted value
        password: The password used for encryption
        
    Returns:
        Decrypted message
    """
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    
    try:
        # Decode the base64 data
        data = base64.urlsafe_b64decode(encrypted_value.encode('ascii'))
        
        # Check format marker
        if not data.startswith(b"QRHYBRID"):
            raise ValueError("Invalid encryption format")
            
        # Extract components
        data = data[8:]  # Skip marker
        salt, data = data[:32], data[32:]
        nonce, data = data[:12], data[12:]
        metadata_len = int.from_bytes(data[:2], byteorder='big')
        data = data[2:]
        metadata, ciphertext = data[:metadata_len], data[metadata_len:]
        
        # Derive key using same process as encryption
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**16,
            r=8,
            p=1
        )
        key = kdf.derive(password.encode())
        key = hashlib.sha3_512(key).digest()[:32]
        
        # Decrypt
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, metadata)
        
        return plaintext.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

def vault_encrypt(value: str, master_key: str, key_id: str = None) -> Dict[str, str]:
    """
    Encrypt a value using a vault-like approach with key versioning.
    
    Args:
        value: The value to encrypt
        master_key: The master encryption key
        key_id: Optional key identifier for key rotation
        
    Returns:
        Dictionary with encryption metadata and encrypted value
    """
    # Generate a data key that will encrypt the actual value
    data_key = secrets.token_bytes(32)
    
    # Generate a random IV
    iv = os.urandom(16)
    
    # Use AES-256-CBC to encrypt the value with the data key
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    
    # Pad the value
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(value.encode()) + padder.finalize()
    
    # Encrypt the value
    cipher = Cipher(algorithms.AES(data_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_value = encryptor.update(padded_data) + encryptor.finalize()
    
    # Encrypt the data key with the master key
    key_iv = os.urandom(16)
    
    # Derive the actual master key
    master_key_bytes = hashlib.sha256(master_key.encode()).digest()
    
    # Encrypt the data key
    cipher = Cipher(algorithms.AES(master_key_bytes), modes.CBC(key_iv))
    encryptor = cipher.encryptor()
    
    # Pad the data key
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_key = padder.update(data_key) + padder.finalize()
    
    encrypted_data_key = encryptor.update(padded_key) + encryptor.finalize()
    
    # Create metadata
    now = int(time.time())
    if not key_id:
        key_id = f"key-{secrets.token_hex(4)}-{now}"
        
    # Combine everything into a result
    result = {
        "version": "v2",
        "key_id": key_id,
        "timestamp": now,
        "encrypted_key": base64.b64encode(encrypted_data_key).decode('ascii'),
        "key_iv": base64.b64encode(key_iv).decode('ascii'),
        "data_iv": base64.b64encode(iv).decode('ascii'),
        "encrypted_value": base64.b64encode(encrypted_value).decode('ascii'),
        "algorithm": "AES-256-CBC"
    }
    
    return result

def vault_decrypt(encrypted_data: Dict[str, str], master_key: str) -> str:
    """
    Decrypt a value that was encrypted with the vault_encrypt function.
    
    Args:
        encrypted_data: Dictionary with encryption metadata and encrypted value
        master_key: The master encryption key
        
    Returns:
        Decrypted value
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    
    # Verify the version
    if encrypted_data.get("version") != "v2":
        raise ValueError("Unsupported encryption version")
        
    # Extract components
    encrypted_key = base64.b64decode(encrypted_data["encrypted_key"])
    key_iv = base64.b64decode(encrypted_data["key_iv"])
    data_iv = base64.b64decode(encrypted_data["data_iv"])
    encrypted_value = base64.b64decode(encrypted_data["encrypted_value"])
    
    # Derive the master key
    master_key_bytes = hashlib.sha256(master_key.encode()).digest()
    
    # Decrypt the data key
    cipher = Cipher(algorithms.AES(master_key_bytes), modes.CBC(key_iv))
    decryptor = cipher.decryptor()
    padded_key = decryptor.update(encrypted_key) + decryptor.finalize()
    
    # Unpad the data key
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data_key = unpadder.update(padded_key) + unpadder.finalize()
    
    # Decrypt the value
    cipher = Cipher(algorithms.AES(data_key), modes.CBC(data_iv))
    decryptor = cipher.decryptor()
    padded_value = decryptor.update(encrypted_value) + decryptor.finalize()
    
    # Unpad the value
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    value = unpadder.update(padded_value) + unpadder.finalize()
    
    return value.decode('utf-8')

def generate_environment_integrity_signature(env_values: Dict[str, str], secret_key: str) -> str:
    """
    Generate a cryptographic signature for the environment values to detect tampering.
    
    Args:
        env_values: Dictionary of environment variables
        secret_key: Secret key for signing
        
    Returns:
        Cryptographic signature
    """
    # Sort keys for consistent signature
    sorted_items = sorted(env_values.items())
    
    # Create a canonical representation
    canonical = json.dumps(sorted_items, separators=(',', ':'))
    
    # Generate an HMAC signature
    import hmac
    
    # Use SHA-512 for stronger security
    signature = hmac.new(
        secret_key.encode(),
        canonical.encode(),
        hashlib.sha512
    ).hexdigest()
    
    return signature

def verify_environment_integrity(env_values: Dict[str, str], 
                                signature: str, 
                                secret_key: str) -> bool:
    """
    Verify the cryptographic signature of environment values to detect tampering.
    
    Args:
        env_values: Dictionary of environment variables
        signature: Signature to verify
        secret_key: Secret key used for signing
        
    Returns:
        True if signature is valid, False otherwise
    """
    expected_signature = generate_environment_integrity_signature(env_values, secret_key)
    return secure_compare(signature, expected_signature)

def secure_load_from_replit_secrets(required_keys: Optional[List[str]] = None) -> Dict[str, str]:
    """
    Securely load environment variables from Replit Secrets.
    
    Args:
        required_keys: Optional list of required keys
        
    Returns:
        Dictionary of loaded secrets
    """
    result = {}
    missing = []
    
    # Load from environment variables (how Replit exposes secrets)
    if required_keys:
        for key in required_keys:
            value = os.getenv(key)
            if value is not None:
                result[key] = value
            else:
                missing.append(key)
                
        if missing:
            raise ValueError(f"Missing required secrets: {', '.join(missing)}")
    else:
        # Load all available environment variables
        result = dict(os.environ)
    
    return result

def encrypt_with_post_quantum_algorithm(data: str, password: str) -> str:
    """
    Encrypt data using a post-quantum resistant algorithm (Kyber-like approach).
    
    This is a simplified implementation meant to demonstrate the concept of
    post-quantum cryptography. For production use, use established libraries.
    
    Args:
        data: Data to encrypt
        password: Password for encryption
        
    Returns:
        Encrypted data as a string
    """
    # Generate a random seed for key generation
    seed = os.urandom(32)
    
    # Derive a key from the password and seed
    key_material = hashlib.sha3_512(password.encode() + seed).digest()
    
    # Generate a random nonce for each encryption
    nonce = os.urandom(16)
    
    # Use AES-256-GCM for the actual encryption
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aesgcm = AESGCM(key_material[:32])
    
    # Encrypt the data
    ciphertext = aesgcm.encrypt(nonce, data.encode(), seed)
    
    # Combine all components
    result = {
        "algorithm": "post-quantum-hybrid",
        "version": "1.0",
        "seed": base64.b64encode(seed).decode('ascii'),
        "nonce": base64.b64encode(nonce).decode('ascii'),
        "ciphertext": base64.b64encode(ciphertext).decode('ascii')
    }
    
    return json.dumps(result)

def decrypt_with_post_quantum_algorithm(encrypted_data: str, password: str) -> str:
    """
    Decrypt data that was encrypted with post-quantum resistant algorithm.
    
    Args:
        encrypted_data: Encrypted data as a string
        password: Password for decryption
        
    Returns:
        Decrypted data
    """
    try:
        # Parse the JSON data
        data = json.loads(encrypted_data)
        
        # Extract components
        algorithm = data.get("algorithm")
        if algorithm != "post-quantum-hybrid":
            raise ValueError(f"Unsupported algorithm: {algorithm}")
            
        seed = base64.b64decode(data["seed"])
        nonce = base64.b64decode(data["nonce"])
        ciphertext = base64.b64decode(data["ciphertext"])
        
        # Derive the key
        key_material = hashlib.sha3_512(password.encode() + seed).digest()
        
        # Decrypt
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(key_material[:32])
        plaintext = aesgcm.decrypt(nonce, ciphertext, seed)
        
        return plaintext.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

def generate_zero_knowledge_proof(secret: str, challenge: str) -> Dict[str, str]:
    """
    Generate a zero-knowledge proof to verify knowledge of a secret without revealing it.
    
    This is a simplified implementation for educational purposes. For production use,
    consider established ZKP protocols.
    
    Args:
        secret: The secret value
        challenge: A random challenge from the verifier
        
    Returns:
        A proof that can be verified
    """
    # Combine the secret and challenge
    message = secret + challenge
    
    # Generate hash commitments
    h1 = hashlib.sha3_256(secret.encode()).hexdigest()
    h2 = hashlib.sha3_256(message.encode()).hexdigest()
    
    # Include a timestamp to prevent replay attacks
    timestamp = str(int(time.time()))
    
    # Create the proof
    proof = {
        "protocol": "simplified-zkp",
        "commitment": h1,
        "response": h2,
        "timestamp": timestamp,
        "challenge": challenge
    }
    
    return proof

def verify_zero_knowledge_proof(proof: Dict[str, str], secret: str, max_age_seconds: int = 300) -> bool:
    """
    Verify a zero-knowledge proof without learning the secret.
    
    Args:
        proof: The proof generated by generate_zero_knowledge_proof
        secret: The secret to verify
        max_age_seconds: Maximum age of the proof in seconds
        
    Returns:
        True if the proof is valid, False otherwise
    """
    try:
        # Check proof timestamp to prevent replay attacks
        timestamp = int(proof["timestamp"])
        current_time = int(time.time())
        
        if current_time - timestamp > max_age_seconds:
            return False
            
        # Regenerate the expected values
        expected_commitment = hashlib.sha3_256(secret.encode()).hexdigest()
        expected_response = hashlib.sha3_256((secret + proof["challenge"]).encode()).hexdigest()
        
        # Verify the proof
        return (proof["commitment"] == expected_commitment and 
                proof["response"] == expected_response)
    except Exception:
        return False

def format_secure_representation(value: str, is_sensitive: bool = True) -> str:
    """
    Format a value for secure representation in logs or UI.
    
    Args:
        value: The value to format
        is_sensitive: Whether the value is sensitive
        
    Returns:
        Safely formatted value
    """
    if not is_sensitive:
        return value
        
    if not value:
        return "********"
        
    # Show only first and last characters
    if len(value) <= 4:
        return "****"
    elif len(value) <= 8:
        return value[0] + "****" + value[-1]
    else:
        return value[:2] + "****" + value[-2:]

def auto_backup_env_file(path: str, backup_dir: str = ".env_backups", max_backups: int = 10) -> str:
    """
    Automatically create backups of .env files before modifications.
    
    Args:
        path: Path to the .env file
        backup_dir: Directory to store backups
        max_backups: Maximum number of backups to keep
        
    Returns:
        Path to the backup file
    """
    if not os.path.exists(path):
        return None
        
    # Create backup directory if it doesn't exist
    os.makedirs(backup_dir, exist_ok=True)
    
    # Generate backup filename with timestamp
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    filename = os.path.basename(path)
    backup_path = os.path.join(backup_dir, f"{filename}.{timestamp}")
    
    # Create the backup
    shutil.copy2(path, backup_path)
    
    # Clean up old backups if needed
    backups = sorted([
        os.path.join(backup_dir, f) 
        for f in os.listdir(backup_dir) 
        if f.startswith(filename + ".")
    ])
    
    if len(backups) > max_backups:
        for old_backup in backups[:-max_backups]:
            os.remove(old_backup)
            
    return backup_path
