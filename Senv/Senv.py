
"""
Core implementation of SecureDotEnv library.
"""
import os
import re
import json
import logging
import glob
import time
import math
import datetime
from typing import Dict, List, Any, Union, Optional, Set, Tuple
from pathlib import Path
import hashlib
import secrets
import sys

from Senv.exceptions import DotEnvError, FileNotFoundError, ParseError, SecurityError
from Senv.utils import (
    cast_value, sanitize_value, encrypt_value, decrypt_value,
    detect_secrets_in_content, secure_compare, generate_secure_key,
    check_security_vulnerabilities, generate_mfa_secret, verify_totp_code
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("Senv")


class SecureDotEnv:
    """
    A secure and feature-rich class for loading and manipulating .env files
    with advanced security features and type management.
    
    This class is also available as `Senv` for easier importing and use.
    """
    DEFAULT_ENV_FILES = ['.env', '.env.local', '.env.development', 'config.env', 'settings.env']
    SENSITIVE_KEY_PATTERNS = [
        r'.*pass.*', r'.*secret.*', r'.*key.*', r'.*token.*', r'.*pwd.*',
        r'.*auth.*', r'.*credential.*', r'.*oauth.*', r'.*password.*',
        r'.*private.*', r'.*certificate.*', r'.*salt.*', r'.*hash.*',
        r'.*encrypt.*', r'.*cipher.*', r'.*iv.*', r'.*signature.*',
        r'.*login.*', r'.*jwt.*', r'.*crypt.*', r'.*secure.*'
    ]
    # Add patterns for potentially dangerous values
    DANGEROUS_VALUE_PATTERNS = [
        r'.*eval\(.*', r'.*exec\(.*', r'.*system\(.*', r'.*subprocess\..*',
        r'.*os\..*\(.*', r'.*__import__\(.*', r'.*exec.*\(.*', r'.*shell=True.*',
        r'.*pickle\..*', r'.*marshal\..*', r'.*compile\(.*', r'.*getattr\(.*',
        r'.*setattr\(.*', r'.*__.*__\(.*'
    ]
    
    # Security levels for different environments
    SECURITY_LEVELS = {
        "development": {
            "allow_debug": True,
            "require_encryption": False,
            "block_dangerous_values": True,
            "min_password_length": 8,
            "allow_plain_http": True,
            "max_age_days": 30
        },
        "testing": {
            "allow_debug": True,
            "require_encryption": True,
            "block_dangerous_values": True,
            "min_password_length": 10,
            "allow_plain_http": True,
            "max_age_days": 15
        },
        "staging": {
            "allow_debug": False,
            "require_encryption": True,
            "block_dangerous_values": True,
            "min_password_length": 12,
            "allow_plain_http": False,
            "max_age_days": 7
        },
        "production": {
            "allow_debug": False,
            "require_encryption": True,
            "block_dangerous_values": True,
            "min_password_length": 16,
            "allow_plain_http": False,
            "max_age_days": 3
        }
    }
    
    def __init__(self, encryption_key: Optional[str] = None, 
                environment: str = "development",
                user_config: Optional[Dict[str, Any]] = None):
        """
        Initialize a new SecureDotEnv (Senv) instance with enhanced configuration options.
        
        Args:
            encryption_key: Optional encryption key for sensitive values.
                           If not provided, sensitive values will not be encrypted.
            environment: Environment type (development, testing, staging, production)
                        to apply appropriate security policies.
            user_config: Optional user configuration to override default settings.
        """
        self._values: Dict[str, str] = {}
        self._loaded_files: List[str] = []
        self._encryption_key = encryption_key
        self._sensitive_keys: Set[str] = set()
        self._modified: bool = False
        self._comment_map: Dict[str, str] = {}  # Store comments for each key
        self._created_at = int(time.time())
        
        # Set environment and load appropriate security level
        self._environment = environment.lower()
        self._security_level = self.SECURITY_LEVELS.get(
            self._environment, 
            self.SECURITY_LEVELS["development"]
        )
        
        # Apply user configuration if provided
        if user_config:
            self._apply_user_config(user_config)
        
        # Generate a random encryption key if none is provided
        if not self._encryption_key:
            self._encryption_key = secrets.token_hex(32)
            logger.debug("No encryption key provided, generated random key")
            
    def _apply_user_config(self, user_config: Dict[str, Any]) -> None:
        """
        Apply user configuration to override default settings.
        
        Args:
            user_config: Dictionary of user configuration settings
        """
        # Apply to security level
        for key, value in user_config.items():
            if key in self._security_level:
                self._security_level[key] = value
                
        # Apply other configuration options
        if "log_level" in user_config:
            log_level = user_config["log_level"].upper()
            if hasattr(logging, log_level):
                logger.setLevel(getattr(logging, log_level))
                
        if "sensitive_patterns" in user_config:
            additional_patterns = user_config["sensitive_patterns"]
            if isinstance(additional_patterns, list):
                self.SENSITIVE_KEY_PATTERNS.extend(additional_patterns)
                
        if "dangerous_patterns" in user_config:
            additional_patterns = user_config["dangerous_patterns"]
            if isinstance(additional_patterns, list):
                self.DANGEROUS_VALUE_PATTERNS.extend(additional_patterns)
                
        if "default_files" in user_config:
            additional_files = user_config["default_files"]
            if isinstance(additional_files, list):
                self.DEFAULT_ENV_FILES.extend(additional_files)
    
    def keys(self) -> List[str]:
        """Return list of all environment variable keys loaded."""
        return list(self._values.keys())
    
    def import_env(self, path: str = ".env", override: bool = False, 
                  export_globals: bool = False, safe_mode: bool = True) -> bool:
        """
        Import environment variables from a .env file.
        
        Args:
            path: Path to the .env file
            override: Whether to override existing environment variables
            export_globals: Whether to export variables to os.environ
            safe_mode: Enables additional security checks for sensitive data
            
        Returns:
            True if successful, False otherwise
        """
        if not os.path.isfile(path):
            logger.warning(f"File not found: {path}")
            return False
        
        try:
            with open(path, 'r', encoding='utf-8') as file:
                content = file.read()
                
            # Check for potential security issues in the file
            if safe_mode:
                if not self._security_scan(content, path):
                    logger.error(f"Error importing {path}: Security scan failed")
                    return False
                
            # Parse the file content
            self._parse_env_content(content, path, override)
            
            # Add to loaded files
            if path not in self._loaded_files:
                self._loaded_files.append(path)
            
            # Export to globals if requested
            if export_globals:
                self._export_to_globals(override)
                
            logger.info(f"Successfully imported {len(self._values)} variables from {path}")
            return True
            
        except Exception as e:
            logger.error(f"Error importing {path}: {str(e)}")
            return False
    
    def _parse_env_content(self, content: str, source: str, override: bool) -> None:
        """
        Parse the content of an env file and extract key-value pairs.
        
        Args:
            content: The file content as a string
            source: Source identifier (filename) for error reporting
            override: Whether to override existing values
        """
        lines = content.splitlines()
        line_num = 0
        
        for line in lines:
            line_num += 1
            
            # Skip empty lines and comments
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            # Extract inline comments
            if '#' in line:
                content_part, comment_part = line.split('#', 1)
                line = content_part.strip()
                comment = comment_part.strip()
            else:
                comment = ''
                
            # Parse key-value pair
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                # Store only if key is valid
                if key:
                    # Check if this key already exists and we're not overriding
                    if key in self._values and not override:
                        continue
                        
                    # Check if key matches sensitive patterns
                    if any(re.match(pattern, key, re.IGNORECASE) for pattern in self.SENSITIVE_KEY_PATTERNS):
                        self._sensitive_keys.add(key)
                        
                    # Store the value and comment
                    self._values[key] = value
                    if comment:
                        self._comment_map[key] = comment
                    
                    self._modified = True
            else:
                logger.warning(f"Invalid line format at {source}:{line_num}: {line}")
    
    def _security_scan(self, content: str, source: str) -> bool:
        """
        Scan the file content for potential security issues.
        
        Args:
            content: The file content to scan
            source: Source identifier for error reporting
            
        Returns:
            True if safe, False if security issues detected
        """
        # Check for potential command injection
        dangerous_patterns = [
            r'`.*`',  # Backticks
            r'\$\(.*\)',  # Command substitution
            r'eval\s*\(',  # eval()
            r'system\s*\(',  # system()
            r'exec\s*\(',   # exec()
            r'subprocess\.',  # subprocess module
            r'os\.system',  # os.system
            r'__import__\(', # dynamic imports
            r'importlib\.', # importlib usage
            r'pickle\.', # pickle usage
            r'marshal\.', # marshal usage
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, content):
                logger.error(f"Potential command injection detected in {source}")
                return False
        
        # Check for extremely long values (potential DoS)
        lines = content.splitlines()
        for line in lines:
            if len(line) > 1000:  # Arbitrary limit
                logger.error(f"Extremely long line detected in {source}")
                return False
                
        # Check for private keys
        private_key_patterns = [
            r'-----BEGIN(\s+RSA)?\s+PRIVATE\s+KEY-----',
            r'-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----',
            r'-----BEGIN\s+DSA\s+PRIVATE\s+KEY-----',
            r'-----BEGIN\s+EC\s+PRIVATE\s+KEY-----',
        ]
        
        for pattern in private_key_patterns:
            if re.search(pattern, content):
                logger.error(f"Private key detected in {source}. Never store private keys in .env files!")
                return False
                
        # Check for AWS keys
        if re.search(r'(AKIA|ASIA)[A-Z0-9]{16}', content):
            logger.error(f"AWS access key detected in {source}")
            return False
            
        # Check for generic API keys and tokens
        api_key_patterns = [
            r'api[_-]?key\s*[:=]\s*[A-Za-z0-9_\-]{16,}',
            r'auth[_-]?token\s*[:=]\s*[A-Za-z0-9_\-\.]{16,}',
            r'slack[_-]?token\s*[:=]\s*xox[pbar]-[0-9]{12}-[0-9]{12}',
            r'github[_-]?token\s*[:=]\s*gh[pousr]_[A-Za-z0-9_]{36,}',
        ]
        
        for pattern in api_key_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                logger.warning(f"Potential API key or token detected in {source} - consider encrypting")
                # Not failing but warning
                
        # Check for potential SQL injections
        sql_patterns = [
            r'SELECT\s+.*\s+FROM\s+',
            r'INSERT\s+INTO\s+',
            r'UPDATE\s+.*\s+SET\s+',
            r'DELETE\s+FROM\s+',
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                logger.error(f"SQL query detected in {source} - not recommended in env files")
                return False
                
        return True
    
    def _export_to_globals(self, override: bool = False) -> None:
        """
        Export loaded environment variables to os.environ.
        
        Args:
            override: Whether to override existing environment variables
        """
        for key, value in self._values.items():
            if override or key not in os.environ:
                os.environ[key] = value
                
        logger.debug(f"Exported {len(self._values)} variables to global environment")
    
    def as_dict(self, cast_types: bool = False) -> Dict[str, Any]:
        """
        Return all environment variables as a dictionary.
        
        Args:
            cast_types: Whether to try to cast values to appropriate Python types
            
        Returns:
            Dictionary of environment variables
        """
        if not cast_types:
            return dict(self._values)
        
        result = {}
        for key, value in self._values.items():
            result[key] = cast_value(value)
            
        return result
    
    def load_dotenv_from_directory(self, path: str = ".", 
                                  filename: Optional[str] = None,
                                  override: bool = False) -> List[str]:
        """
        Scan a directory for .env files and load them.
        
        Args:
            path: Directory path to scan
            filename: Specific filename to look for, or None to search for default patterns
            override: Whether to override existing variables when loading files
            
        Returns:
            List of files that were successfully loaded
        """
        loaded_files = []
        
        if not os.path.isdir(path):
            logger.warning(f"Directory not found: {path}")
            return loaded_files
            
        if filename:
            # Look for a specific file
            file_path = os.path.join(path, filename)
            if os.path.isfile(file_path):
                if self.import_env(file_path, override):
                    loaded_files.append(file_path)
        else:
            # Look for default files in priority order
            for pattern in self.DEFAULT_ENV_FILES:
                file_paths = glob.glob(os.path.join(path, pattern))
                for file_path in file_paths:
                    if self.import_env(file_path, override):
                        loaded_files.append(file_path)
        
        return loaded_files
    
    def load_multiple_env_files(self, file_paths: List[str], 
                               override: bool = False,
                               ignore_missing: bool = True) -> List[str]:
        """
        Load multiple .env files in the order specified.
        
        Args:
            file_paths: List of file paths to load
            override: Whether later files should override earlier ones
            ignore_missing: Whether to ignore missing files
            
        Returns:
            List of files that were successfully loaded
        """
        loaded_files = []
        
        for path in file_paths:
            if not os.path.isfile(path) and not ignore_missing:
                raise FileNotFoundError(f"File not found: {path}")
                
            if os.path.isfile(path) and self.import_env(path, override):
                loaded_files.append(path)
                
        return loaded_files
    
    def generate_template(self, output_path: str = ".env.template") -> bool:
        """
        Generate a template file with keys but empty values.
        
        Args:
            output_path: Path for the output template file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(output_path, 'w', encoding='utf-8') as file:
                for key in sorted(self._values.keys()):
                    comment = f" # {self._comment_map[key]}" if key in self._comment_map else ""
                    
                    # Mark sensitive keys with a comment
                    if key in self._sensitive_keys:
                        file.write(f"# SENSITIVE DATA - Protect this value!\n")
                        
                    file.write(f"{key}={comment}\n")
                    
            logger.info(f"Template generated at {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error generating template: {str(e)}")
            return False
    
    def get(self, key: str, default: Any = None, cast_type: Optional[type] = None) -> Any:
        """
        Get a value by key with optional default and type casting.
        
        Args:
            key: The key to retrieve
            default: Default value if key is not found
            cast_type: Optional type to cast the value to
            
        Returns:
            The value (possibly cast) or default if not found
        """
        if key not in self._values:
            return default
            
        value = self._values[key]
        
        if cast_type:
            try:
                return cast_type(value)
            except (ValueError, TypeError):
                logger.warning(f"Failed to cast {key} to {cast_type.__name__}")
                return default
                
        return value
    
    def set(self, key: str, value: Any, comment: Optional[str] = None) -> None:
        """
        Set a value for a key.
        
        Args:
            key: The key to set
            value: The value to set
            comment: Optional comment for the key
        """
        self._values[key] = str(value)
        
        if comment:
            self._comment_map[key] = comment
            
        # Check if this is a sensitive key
        if any(re.match(pattern, key, re.IGNORECASE) for pattern in self.SENSITIVE_KEY_PATTERNS):
            self._sensitive_keys.add(key)
            
        self._modified = True
    
    def save(self, path: Optional[str] = None, include_comments: bool = True) -> bool:
        """
        Save the current environment variables to a file.
        
        Args:
            path: Output file path, defaults to the first loaded file or .env
            include_comments: Whether to include comments in the output
            
        Returns:
            True if successful, False otherwise
        """
        # Determine output path
        if not path:
            path = self._loaded_files[0] if self._loaded_files else ".env"
            
        try:
            with open(path, 'w', encoding='utf-8') as file:
                file.write("# Generated by SecureDotEnv\n")
                file.write(f"# Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                for key in sorted(self._values.keys()):
                    value = self._values[key]
                    
                    # Add comment for sensitive keys
                    if key in self._sensitive_keys:
                        file.write("# SENSITIVE DATA - Protect this value!\n")
                        
                    # Add stored comment if available
                    if include_comments and key in self._comment_map:
                        file.write(f"{key}={value} # {self._comment_map[key]}\n")
                    else:
                        file.write(f"{key}={value}\n")
                        
            logger.info(f"Environment saved to {path}")
            self._modified = False
            return True
            
        except Exception as e:
            logger.error(f"Error saving environment: {str(e)}")
            return False
    
    def encrypt_sensitive_values(self) -> None:
        """
        Encrypt all sensitive values using the encryption key.
        """
        if not self._encryption_key:
            logger.warning("No encryption key provided, skipping encryption")
            return
            
        for key in self._sensitive_keys:
            if key in self._values and not self._values[key].startswith('ENC:'):
                plain_value = self._values[key]
                encrypted = encrypt_value(plain_value, self._encryption_key)
                self._values[key] = f"ENC:{encrypted}"
                
        logger.info(f"Encrypted {len(self._sensitive_keys)} sensitive values")
    
    def decrypt_sensitive_values(self) -> None:
        """
        Decrypt all encrypted sensitive values.
        """
        if not self._encryption_key:
            logger.warning("No encryption key provided, skipping decryption")
            return
            
        for key in self._sensitive_keys:
            if key in self._values and self._values[key].startswith('ENC:'):
                encrypted = self._values[key][4:]  # Remove 'ENC:' prefix
                try:
                    decrypted = decrypt_value(encrypted, self._encryption_key)
                    self._values[key] = decrypted
                except Exception as e:
                    logger.error(f"Failed to decrypt {key}: {str(e)}")
                    
        logger.info("Decrypted sensitive values")
    
    def validate_required_keys(self, required_keys: List[str]) -> Tuple[bool, List[str]]:
        """
        Validate that all required keys are present.
        
        Args:
            required_keys: List of keys that must be present
            
        Returns:
            Tuple of (is_valid, missing_keys)
        """
        missing = [key for key in required_keys if key not in self._values]
        return (len(missing) == 0, missing)
    
    def merge(self, other: 'SecureDotEnv', override: bool = False) -> None:
        """
        Merge another SecureDotEnv instance into this one.
        
        Args:
            other: Another SecureDotEnv instance
            override: Whether to override existing values
        """
        for key, value in other._values.items():
            if override or key not in self._values:
                self._values[key] = value
                
                if key in other._comment_map:
                    self._comment_map[key] = other._comment_map[key]
                    
                if key in other._sensitive_keys:
                    self._sensitive_keys.add(key)
                    
        self._modified = True
        
    def interpolate_values(self) -> None:
        """
        Interpolate values that reference other environment variables.
        Example: DB_URL=${DB_HOST}:${DB_PORT}/${DB_NAME}
        """
        pattern = re.compile(r'\${([A-Za-z0-9_]+)}')
        
        # Multiple passes to handle nested interpolation
        for _ in range(10):  # Limit to 10 passes to prevent infinite loops
            any_replaced = False
            
            for key, value in self._values.items():
                matches = pattern.findall(value)
                
                if not matches:
                    continue
                    
                new_value = value
                for ref_key in matches:
                    if ref_key in self._values:
                        placeholder = f"${{{ref_key}}}"
                        replacement = self._values[ref_key]
                        new_value = new_value.replace(placeholder, replacement)
                        any_replaced = True
                        
                self._values[key] = new_value
                
            if not any_replaced:
                break
                
    def validate_format(self, key: str, pattern: str) -> bool:
        """
        Validate that a value matches a specific format.
        
        Args:
            key: The key to validate
            pattern: Regex pattern to match
            
        Returns:
            True if valid, False otherwise
        """
        if key not in self._values:
            return False
            
        return bool(re.match(pattern, self._values[key]))
    
    def generate_checksum(self) -> str:
        """
        Generate a checksum of all environment variables.
        
        Returns:
            SHA-256 checksum as a hexadecimal string
        """
        # Sort keys for consistent checksum
        content = ""
        for key in sorted(self._values.keys()):
            content += f"{key}={self._values[key]}\n"
            
        return hashlib.sha256(content.encode('utf-8')).hexdigest()
    
    def get_loaded_files(self) -> List[str]:
        """Get list of all files that have been loaded."""
        return self._loaded_files.copy()
    
    def is_modified(self) -> bool:
        """Check if any values have been modified since loading."""
        return self._modified
    
    def get_secure_string(self, key: str) -> Optional[str]:
        """
        Get a sensitive value securely (doesn't log or expose it).
        
        Args:
            key: The key to retrieve
            
        Returns:
            The value or None if not found
        """
        if key not in self._values:
            return None
            
        # Add to sensitive keys automatically
        self._sensitive_keys.add(key)
        
        return self._values[key]
        
    def rotate_encryption_key(self, new_key: str, rotation_window: int = 0) -> bool:
        """
        Rotate the encryption key while preserving encrypted values.
        
        Args:
            new_key: New encryption key to use
            rotation_window: Time window in seconds to keep old key valid for decryption
            
        Returns:
            True if successful, False otherwise
        """
        if not self._encryption_key:
            logger.warning("No previous encryption key to rotate")
            self._encryption_key = new_key
            return True
            
        try:
            # Store old key with timestamp for rotation window
            old_key = self._encryption_key
            rotation_time = int(time.time())
            
            # First decrypt all sensitive values with old key
            self.decrypt_sensitive_values()
            
            # Set the new key
            self._encryption_key = new_key
            
            # Store old key for rotation window if specified
            if rotation_window > 0:
                self._previous_keys = getattr(self, '_previous_keys', {})
                self._previous_keys[old_key] = rotation_time + rotation_window
            
            # Re-encrypt with new key
            self.encrypt_sensitive_values()
            
            logger.info("Encryption key rotated successfully")
            return True
        except Exception as e:
            # Restore old key on failure
            self._encryption_key = old_key
            logger.error(f"Failed to rotate encryption key: {str(e)}")
            return False
            
    def authenticate_with_key(self, key: str) -> bool:
        """
        Authenticate using an encryption key to access sensitive values.
        
        Args:
            key: The encryption key to authenticate with
            
        Returns:
            True if authenticated successfully, False otherwise
        """
        # Store the current key
        current_key = self._encryption_key
        
        # Try to decrypt a test value with the provided key
        try:
            # Create a test encrypted value if none exists
            if not hasattr(self, '_auth_test_value'):
                test_value = "authentication_test"
                encrypted = encrypt_value(test_value, self._encryption_key)
                self._auth_test_value = f"ENC:{encrypted}"
            
            # Try to decrypt with the provided key
            self._encryption_key = key
            encrypted = self._auth_test_value[4:]  # Remove 'ENC:' prefix
            decrypted = decrypt_value(encrypted, key)
            
            # Verify the decrypted value
            if decrypted == "authentication_test":
                # Authentication successful, keep the new key
                logger.info("Authentication successful")
                # Clean up old keys that have expired
                self._cleanup_previous_keys()
                return True
                
        except Exception as e:
            logger.warning(f"Authentication failed: {str(e)}")
            
        # Restore the original key on failure
        self._encryption_key = current_key
        return False
        
    def _cleanup_previous_keys(self) -> None:
        """
        Clean up expired previous keys from the rotation window.
        """
        if not hasattr(self, '_previous_keys'):
            return
            
        current_time = int(time.time())
        expired_keys = []
        
        # Find expired keys
        for key, expiry in self._previous_keys.items():
            if current_time > expiry:
                expired_keys.append(key)
                
        # Remove expired keys
        for key in expired_keys:
            del self._previous_keys[key]
            
        logger.debug(f"Cleaned up {len(expired_keys)} expired encryption keys")
            
    def obfuscate_sensitive_keys(self) -> Dict[str, str]:
        """
        Create an obfuscated representation of the environment with sensitive values masked.
        
        Returns:
            Dictionary with sensitive values replaced with '*****'
        """
        result = {}
        for key, value in self._values.items():
            if key in self._sensitive_keys:
                # Show only first and last character, mask the rest
                if len(value) > 6:
                    result[key] = value[0] + '****' + value[-1]
                else:
                    result[key] = '*****'
            else:
                result[key] = value
                
        return result
        
    def deep_security_scan(self, content: str, source: str) -> List[str]:
        """
        Perform a deep security scan to detect potential security issues.
        
        Args:
            content: Content to scan
            source: Source identifier for reporting
            
        Returns:
            List of security issues found
        """
        issues = []
        
        # Check for potential secrets in content
        secrets = detect_secrets_in_content(content)
        if secrets:
            issues.append(f"Potential secrets detected in {source}: {len(secrets)} instances")
            
        # Check for dangerous patterns
        for pattern in self.DANGEROUS_VALUE_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                issues.append(f"Dangerous pattern '{pattern}' detected in {source}")
                
        # Check for extremely large values
        if len(content) > 10000:
            issues.append(f"Extremely large content detected in {source} ({len(content)} bytes)")
            
        return issues
        
    def export_to_docker_env_file(self, path: str) -> bool:
        """
        Export environment variables to a Docker-compatible .env file.
        
        Args:
            path: Output file path
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(path, 'w', encoding='utf-8') as file:
                file.write("# Generated by SecureDotEnv for Docker\n")
                file.write(f"# Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                for key in sorted(self._values.keys()):
                    value = self._values[key]
                    
                    # Escape special characters for Docker
                    value = value.replace('"', '\\"').replace('$', '$$')
                    
                    # Use Docker format
                    file.write(f"{key}=\"{value}\"\n")
                    
            logger.info(f"Docker environment file saved to {path}")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting Docker environment: {str(e)}")
            return False
            
    def export_to_json(self, path: str, include_sensitive: bool = False, 
                        encrypt_output: bool = False, password: str = None) -> bool:
        """
        Export environment variables to a JSON file with enhanced security options.
        
        Args:
            path: Output file path
            include_sensitive: Whether to include sensitive values
            encrypt_output: Whether to encrypt the entire JSON file
            password: Password for encryption (required if encrypt_output is True)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            result = {}
            
            for key, value in self._values.items():
                if key in self._sensitive_keys and not include_sensitive:
                    continue
                    
                # Try to cast the value appropriately
                result[key] = cast_value(value)
            
            # Generate metadata
            metadata = {
                "version": "2.0",
                "exported_at": datetime.datetime.now().isoformat(),
                "environment": os.environ.get("ENVIRONMENT", "development"),
                "secure_dotenv_version": __version__,
                "sensitive_keys_included": include_sensitive,
                "sensitive_keys_count": len(self._sensitive_keys),
                "total_keys_count": len(result),
                "checksum": self.generate_checksum()
            }
            
            # Combine data and metadata
            final_data = {
                "metadata": metadata,
                "values": result
            }
            
            json_content = json.dumps(final_data, indent=2)
            
            if encrypt_output:
                if not password:
                    raise ValueError("Password is required for encrypted export")
                
                # Encrypt the entire JSON content
                encrypted_content = encrypt_with_quantum_resistant_hybrid(json_content, password)
                
                # Write encrypted content
                with open(path, 'w', encoding='utf-8') as file:
                    file.write(encrypted_content)
                    
                logger.info(f"Environment exported to encrypted JSON at {path}")
            else:
                # Write plain JSON
                with open(path, 'w', encoding='utf-8') as file:
                    file.write(json_content)
                    
                logger.info(f"Environment exported to JSON at {path}")
                
            return True
            
        except Exception as e:
            logger.error(f"Error exporting to JSON: {str(e)}")
            return False
            
    def import_from_json(self, path: str, override: bool = False, 
                         encrypted: bool = False, password: str = None) -> bool:
        """
        Import environment variables from a JSON file.
        
        Args:
            path: Path to the JSON file
            override: Whether to override existing values
            encrypted: Whether the JSON file is encrypted
            password: Password for decryption (required if encrypted is True)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if not os.path.isfile(path):
                logger.error(f"JSON file not found: {path}")
                return False
                
            # Read the file
            with open(path, 'r', encoding='utf-8') as file:
                content = file.read()
                
            # Decrypt if necessary
            if encrypted:
                if not password:
                    raise ValueError("Password is required for decrypting JSON")
                    
                try:
                    content = decrypt_with_quantum_resistant_hybrid(content, password)
                except Exception as e:
                    logger.error(f"Failed to decrypt JSON file: {str(e)}")
                    return False
            
            # Parse JSON
            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                logger.error("Invalid JSON format")
                return False
                
            # Handle both new format (with metadata) and old format
            values = data.get("values", data)
            
            # Import values
            imported_count = 0
            for key, value in values.items():
                if override or key not in self._values:
                    # Convert value to string
                    str_value = str(value)
                    self._values[key] = str_value
                    
                    # Check if key matches sensitive patterns
                    if any(re.match(pattern, key, re.IGNORECASE) for pattern in self.SENSITIVE_KEY_PATTERNS):
                        self._sensitive_keys.add(key)
                        
                    imported_count += 1
                    
            self._modified = True
            
            # Add to loaded files
            if path not in self._loaded_files:
                self._loaded_files.append(path)
                
            logger.info(f"Successfully imported {imported_count} variables from JSON file {path}")
            return True
            
        except Exception as e:
            logger.error(f"Error importing from JSON: {str(e)}")
            return False
            
    def validate_against_schema(self, schema: Dict[str, Dict[str, Any]]) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Validate environment variables against a schema with enhanced validation.
        
        Args:
            schema: Dictionary mapping key names to validation rules
                   Example: {
                       "PORT": {
                           "type": int, 
                           "required": True, 
                           "min": 1024, 
                           "max": 65535,
                           "description": "Port to run the server on"
                       }
                   }
                   
        Returns:
            Tuple of (is_valid, list_of_detailed_errors)
        """
        errors = []
        
        # First check all required keys are present
        missing_required = []
        for key, rules in schema.items():
            if rules.get('required', False) and key not in self._values:
                missing_required.append(key)
                
        if missing_required:
            for key in missing_required:
                errors.append({
                    "type": "missing_required",
                    "key": key,
                    "message": f"Required key '{key}' is missing",
                    "severity": "error",
                    "description": schema[key].get("description", "")
                })
                
        # Then validate all existing values
        for key, value in self._values.items():
            # Skip keys not in schema
            if key not in schema:
                continue
                
            rules = schema[key]
            
            # Type validation
            if 'type' in rules:
                expected_type = rules['type']
                try:
                    # Try to cast to expected type
                    casted_value = expected_type(value)
                    
                    # Range validation for numeric types
                    if expected_type in (int, float):
                        if 'min' in rules and casted_value < rules['min']:
                            errors.append({
                                "type": "value_below_minimum",
                                "key": key,
                                "value": casted_value,
                                "expected_minimum": rules['min'],
                                "message": f"Value of '{key}' is below minimum: {casted_value} < {rules['min']}",
                                "severity": "error",
                                "description": rules.get("description", "")
                            })
                        if 'max' in rules and casted_value > rules['max']:
                            errors.append({
                                "type": "value_above_maximum",
                                "key": key,
                                "value": casted_value,
                                "expected_maximum": rules['max'],
                                "message": f"Value of '{key}' is above maximum: {casted_value} > {rules['max']}",
                                "severity": "error",
                                "description": rules.get("description", "")
                            })
                            
                    # Length validation for string
                    if expected_type == str:
                        if 'min_length' in rules and len(value) < rules['min_length']:
                            errors.append({
                                "type": "value_too_short",
                                "key": key,
                                "length": len(value),
                                "expected_minimum": rules['min_length'],
                                "message": f"Value of '{key}' is too short: {len(value)} < {rules['min_length']}",
                                "severity": "error",
                                "description": rules.get("description", "")
                            })
                        if 'max_length' in rules and len(value) > rules['max_length']:
                            errors.append({
                                "type": "value_too_long",
                                "key": key,
                                "length": len(value),
                                "expected_maximum": rules['max_length'],
                                "message": f"Value of '{key}' is too long: {len(value)} > {rules['max_length']}",
                                "severity": "error",
                                "description": rules.get("description", "")
                            })
                            
                except (ValueError, TypeError):
                    errors.append({
                        "type": "type_mismatch",
                        "key": key,
                        "value": value,
                        "expected_type": expected_type.__name__,
                        "message": f"Value of '{key}' is not of type {expected_type.__name__}",
                        "severity": "error",
                        "description": rules.get("description", "")
                    })
                    
            # Pattern validation
            if 'pattern' in rules:
                pattern = rules['pattern']
                if not re.match(pattern, value):
                    errors.append({
                        "type": "pattern_mismatch",
                        "key": key,
                        "value": value if not key in self._sensitive_keys else "********",
                        "pattern": pattern,
                        "message": f"Value of '{key}' does not match required pattern",
                        "severity": "error",
                        "description": rules.get("description", "")
                    })
                    
            # Enum validation
            if 'enum' in rules and value not in rules['enum']:
                errors.append({
                    "type": "invalid_enum_value",
                    "key": key,
                    "value": value if not key in self._sensitive_keys else "********",
                    "allowed_values": rules['enum'],
                    "message": f"Value of '{key}' is not one of: {', '.join(map(str, rules['enum']))}",
                    "severity": "error",
                    "description": rules.get("description", "")
                })
                
            # Dependency validation
            if 'depends_on' in rules:
                dependency = rules['depends_on']
                if dependency not in self._values:
                    errors.append({
                        "type": "missing_dependency",
                        "key": key,
                        "depends_on": dependency,
                        "message": f"Key '{key}' depends on '{dependency}' which is missing",
                        "severity": "error",
                        "description": rules.get("description", "")
                    })
                    
            # Custom validation function
            if 'validator' in rules and callable(rules['validator']):
                validator = rules['validator']
                try:
                    is_valid, error_message = validator(value)
                    if not is_valid:
                        errors.append({
                            "type": "custom_validation_failed",
                            "key": key,
                            "value": value if not key in self._sensitive_keys else "********",
                            "message": error_message,
                            "severity": "error",
                            "description": rules.get("description", "")
                        })
                except Exception as e:
                    errors.append({
                        "type": "validator_error",
                        "key": key,
                        "message": f"Validator for '{key}' raised an exception: {str(e)}",
                        "severity": "error",
                        "description": rules.get("description", "")
                    })
                
        return (len(errors) == 0, errors)
        
    def enforce_security_policies(self, policies: Dict[str, Any]) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Enforce security policies on environment variables.
        
        Args:
            policies: Dictionary defining security policies to enforce
                    Example: {
                        "require_encryption": True,
                        "min_password_length": 10,
                        "disallow_unsafe_protocols": True,
                        "disallow_debug_in_production": True,
                        "environment": "production"
                    }
                    
        Returns:
            Tuple of (is_compliant, list_of_violations)
        """
        violations = []
        
        # Check if encryption is required for sensitive values
        if policies.get("require_encryption", False):
            for key in self._sensitive_keys:
                if key in self._values and not self._values[key].startswith('ENC:'):
                    violations.append({
                        "policy": "require_encryption",
                        "key": key,
                        "message": f"Sensitive key '{key}' is not encrypted",
                        "severity": "high",
                        "recommendation": "Use encrypt_sensitive_values() method to encrypt"
                    })
        
        # Check minimum password length
        if "min_password_length" in policies:
            min_length = policies["min_password_length"]
            for key in self._sensitive_keys:
                if key in self._values and ('pass' in key.lower() or 'pwd' in key.lower() or 'secret' in key.lower()):
                    value = self._values[key]
                    if not value.startswith('ENC:') and len(value) < min_length:
                        violations.append({
                            "policy": "min_password_length",
                            "key": key,
                            "actual_length": len(value),
                            "required_length": min_length,
                            "message": f"Password in '{key}' is too short ({len(value)} < {min_length})",
                            "severity": "high",
                            "recommendation": "Use a longer password"
                        })
        
        # Check for unsafe protocols
        if policies.get("disallow_unsafe_protocols", False):
            for key, value in self._values.items():
                if 'URL' in key.upper() and isinstance(value, str) and value.startswith('http:'):
                    violations.append({
                        "policy": "disallow_unsafe_protocols",
                        "key": key,
                        "message": f"URL in '{key}' uses insecure HTTP protocol",
                        "severity": "medium",
                        "recommendation": "Use HTTPS instead of HTTP"
                    })
        
        # Check for debug mode in production
        if (policies.get("disallow_debug_in_production", False) and 
            policies.get("environment", "").lower() == "production"):
            if 'DEBUG' in self._values and self._values['DEBUG'].lower() in ('true', 'yes', '1', 'on'):
                violations.append({
                    "policy": "disallow_debug_in_production",
                    "key": "DEBUG",
                    "message": "Debug mode is enabled in production environment",
                    "severity": "high",
                    "recommendation": "Set DEBUG to false in production"
                })
                
        # Check for hardcoded IP addresses
        if policies.get("disallow_hardcoded_ips", False):
            ip_pattern = r'\d+\.\d+\.\d+\.\d+'
            for key, value in self._values.items():
                if isinstance(value, str) and re.search(ip_pattern, value):
                    # Skip localhost and private networks if allowed
                    if (policies.get("allow_private_ips", True) and 
                        (value.startswith('127.') or value.startswith('10.') or 
                         value.startswith('192.168.') or re.match(r'172\.(1[6-9]|2[0-9]|3[0-1])\.', value))):
                        continue
                    
                    violations.append({
                        "policy": "disallow_hardcoded_ips",
                        "key": key,
                        "message": f"Hardcoded IP address found in '{key}'",
                        "severity": "medium",
                        "recommendation": "Use hostnames instead of IP addresses"
                    })
        
        # Check for sensitive environment variables in the global environment
        if policies.get("prevent_sensitive_env_leakage", False):
            for key in self._sensitive_keys:
                if key in os.environ:
                    violations.append({
                        "policy": "prevent_sensitive_env_leakage",
                        "key": key,
                        "message": f"Sensitive key '{key}' is in the global environment",
                        "severity": "high",
                        "recommendation": "Avoid exporting sensitive values to the global environment"
                    })
        
        return (len(violations) == 0, violations)
        
    def integrate_with_replit_secrets(self, keys_to_sync: Optional[List[str]] = None,
                                    override_existing: bool = False,
                                    delete_after_sync: bool = False) -> Tuple[int, int, int]:
        """
        Integrate with Replit Secrets for more secure environment variable storage.
        
        Args:
            keys_to_sync: Specific keys to sync, or None to sync all sensitive keys
            override_existing: Whether to override existing Replit Secrets
            delete_after_sync: Whether to delete the sensitive values from local env after sync
            
        Returns:
            Tuple of (synced_count, skipped_count, error_count)
        """
        try:
            synced = 0
            skipped = 0
            errors = 0
            
            # Determine which keys to sync
            if keys_to_sync is None:
                keys_to_sync = list(self._sensitive_keys)
                
            for key in keys_to_sync:
                if key not in self._values:
                    logger.warning(f"Key '{key}' not found in environment variables")
                    skipped += 1
                    continue
                    
                # Check if the key already exists in Replit Secrets
                exists_in_replit = key in os.environ
                
                if exists_in_replit and not override_existing:
                    logger.info(f"Key '{key}' already exists in Replit Secrets, skipped")
                    skipped += 1
                    continue
                
                # Get the value to sync
                value = self._values[key]
                
                # If the value is encrypted, decrypt it first
                if value.startswith('ENC:') and self._encryption_key:
                    try:
                        encrypted = value[4:]  # Remove 'ENC:' prefix
                        value = decrypt_value(encrypted, self._encryption_key)
                    except Exception as e:
                        logger.error(f"Failed to decrypt '{key}': {str(e)}")
                        errors += 1
                        continue
                
                # Log a message about using Replit Secrets - we can't directly modify 
                # Replit Secrets programmatically, so we'll just log a message
                logger.info(f"Please add key '{key}' with its value to Replit Secrets using the Secrets tool")
                
                synced += 1
                
                # Delete from local env if requested
                if delete_after_sync:
                    del self._values[key]
                    if key in self._sensitive_keys:
                        self._sensitive_keys.remove(key)
                    self._modified = True
                    
            return (synced, skipped, errors)
        except Exception as e:
            logger.error(f"Error integrating with Replit Secrets: {str(e)}")
            return (0, 0, 1)
            
    def load_from_replit_secrets(self, keys_to_load: Optional[List[str]] = None,
                               override_existing: bool = False) -> Tuple[int, int]:
        """
        Load environment variables from Replit Secrets.
        
        Args:
            keys_to_load: Specific keys to load, or None to load all available secrets
            override_existing: Whether to override existing values
            
        Returns:
            Tuple of (loaded_count, skipped_count)
        """
        loaded = 0
        skipped = 0
        
        try:
            # Determine which keys to load
            if keys_to_load is None:
                # Load all available secrets
                secrets = secure_load_from_replit_secrets()
                keys_to_load = list(secrets.keys())
            else:
                # Load only specified keys
                secrets = secure_load_from_replit_secrets(keys_to_load)
            
            # Import the secrets
            for key, value in secrets.items():
                if key in self._values and not override_existing:
                    logger.debug(f"Key '{key}' already exists, skipped")
                    skipped += 1
                    continue
                
                self._values[key] = value
                
                # Check if this is a sensitive key
                if any(re.match(pattern, key, re.IGNORECASE) for pattern in self.SENSITIVE_KEY_PATTERNS):
                    self._sensitive_keys.add(key)
                    
                loaded += 1
                
            self._modified = loaded > 0
            
            if loaded > 0:
                logger.info(f"Loaded {loaded} variables from Replit Secrets")
                
            return (loaded, skipped)
        except Exception as e:
            logger.error(f"Error loading from Replit Secrets: {str(e)}")
            return (0, 0)
            
    def check_environment_compliance(self, environment_type: str = "development") -> List[Dict[str, Any]]:
        """
        Check compliance of environment variables against best practices for the given environment.
        
        Args:
            environment_type: Type of environment (development, testing, staging, production)
            
        Returns:
            List of compliance issues
        """
        issues = []
        
        # Define environment-specific policies
        policies = {
            "development": {
                "allow_debug": True,
                "allow_local_urls": True,
                "require_encryption": False,
                "allow_weak_passwords": True
            },
            "testing": {
                "allow_debug": True,
                "allow_local_urls": True,
                "require_encryption": True,
                "allow_weak_passwords": False
            },
            "staging": {
                "allow_debug": False,
                "allow_local_urls": False,
                "require_encryption": True,
                "allow_weak_passwords": False
            },
            "production": {
                "allow_debug": False,
                "allow_local_urls": False,
                "require_encryption": True,
                "allow_weak_passwords": False
            }
        }
        
        # Use default policies if environment type is not recognized
        env_policies = policies.get(environment_type.lower(), policies["development"])
        
        # Debug mode check
        if not env_policies["allow_debug"]:
            if 'DEBUG' in self._values and self._values['DEBUG'].lower() in ('true', 'yes', '1', 'on'):
                issues.append({
                    "type": "compliance",
                    "key": "DEBUG",
                    "message": f"Debug mode should not be enabled in {environment_type} environment",
                    "severity": "high",
                    "recommendation": "Set DEBUG to false"
                })
        
        # Local URL check
        if not env_policies["allow_local_urls"]:
            local_patterns = [
                r'localhost', 
                r'127\.0\.0\.1', 
                r'0\.0\.0\.0',
                r'::1',
                r'10\.\d+\.\d+\.\d+',
                r'192\.168\.\d+\.\d+',
                r'172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+'
            ]
            
            for key, value in self._values.items():
                if isinstance(value, str):
                    for pattern in local_patterns:
                        if re.search(pattern, value):
                            issues.append({
                                "type": "compliance",
                                "key": key,
                                "message": f"Local URL/IP found in '{key}', not suitable for {environment_type}",
                                "severity": "medium",
                                "recommendation": "Use production hostnames and IPs"
                            })
                            break
        
        # Encryption check
        if env_policies["require_encryption"]:
            for key in self._sensitive_keys:
                if key in self._values and not self._values[key].startswith('ENC:'):
                    issues.append({
                        "type": "compliance",
                        "key": key,
                        "message": f"Sensitive key '{key}' should be encrypted in {environment_type}",
                        "severity": "high",
                        "recommendation": "Use encrypt_sensitive_values() method"
                    })
        
        # Password strength check
        if not env_policies["allow_weak_passwords"]:
            for key in self._sensitive_keys:
                if key in self._values and ('pass' in key.lower() or 'pwd' in key.lower() or 'secret' in key.lower()):
                    value = self._values[key]
                    if not value.startswith('ENC:'):
                        # Check password strength
                        has_upper = any(c.isupper() for c in value)
                        has_lower = any(c.islower() for c in value)
                        has_digit = any(c.isdigit() for c in value)
                        has_special = any(not c.isalnum() for c in value)
                        length_ok = len(value) >= 12
                        
                        strength_score = sum([has_upper, has_lower, has_digit, has_special, length_ok])
                        
                        if strength_score < 4:
                            issues.append({
                                "type": "compliance",
                                "key": key,
                                "message": f"Weak password in '{key}', not suitable for {environment_type}",
                                "severity": "high",
                                "recommendation": "Use a stronger password with mix of upper/lower/digits/special chars"
                            })
        
        return issues
        
    def auto_detect_environment(self) -> str:
        """
        Auto-detect the current environment based on environment variables.
        
        Returns:
            Detected environment type (development, testing, staging, production)
        """
        # Check for explicit environment variables
        for key in ['ENVIRONMENT', 'ENV', 'NODE_ENV', 'FLASK_ENV', 'APP_ENV']:
            if key in self._values:
                value = self._values[key].lower()
                
                if value in ['prod', 'production']:
                    return 'production'
                elif value in ['staging', 'stage']:
                    return 'staging'
                elif value in ['test', 'testing']:
                    return 'testing'
                elif value in ['dev', 'development']:
                    return 'development'
        
        # Check for clues in the values
        has_debug = 'DEBUG' in self._values and self._values['DEBUG'].lower() in ('true', 'yes', '1', 'on')
        has_local_urls = False
        
        for key, value in self._values.items():
            if isinstance(value, str) and ('localhost' in value or '127.0.0.1' in value):
                has_local_urls = True
                break
        
        # Make a best guess
        if has_debug and has_local_urls:
            return 'development'
        elif not has_debug and not has_local_urls:
            return 'production'
        elif has_debug and not has_local_urls:
            return 'staging'
        else:
            return 'development'  # Default to development for safety
            
    def apply_environment_variables(self, prefix: str = '') -> int:
        """
        Apply environment variables to the system environment with optional prefix.
        
        Args:
            prefix: Optional prefix to add to environment variable names
            
        Returns:
            Number of variables applied
        """
        count = 0
        for key, value in self._values.items():
            env_key = f"{prefix}{key}" if prefix else key
            os.environ[env_key] = value
            count += 1
            
        return count
        
    def require(self, *keys: str) -> bool:
        """
        Check if all required keys are present and raise an error if not.
        
        Args:
            *keys: Required keys
            
        Returns:
            True if all keys are present
            
        Raises:
            ValueError: If any key is missing
        """
        missing = []
        for key in keys:
            if key not in self._values:
                missing.append(key)
                
        if missing:
            raise ValueError(f"Missing required environment variables: {', '.join(missing)}")
            
        return True
        
    def apply_defaults(self, defaults: Dict[str, Any]) -> int:
        """
        Apply default values for missing keys.
        
        Args:
            defaults: Dictionary of default values
            
        Returns:
            Number of defaults applied
        """
        count = 0
        for key, value in defaults.items():
            if key not in self._values:
                self._values[key] = str(value)
                count += 1
                
        if count > 0:
            self._modified = True
            
        return count
        
    def watch_for_changes(self, callback: callable, interval: int = 5) -> None:
        """
        Watch for changes in loaded files and reload if necessary.
        
        Args:
            callback: Function to call when changes are detected, receives the changed keys
            interval: Check interval in seconds
            
        Note:
            This method starts a background thread that runs until the program exits.
        """
        import threading
        
        # Store file modification times
        file_mtimes = {}
        for file_path in self._loaded_files:
            if os.path.exists(file_path):
                file_mtimes[file_path] = os.path.getmtime(file_path)
                
        def watcher():
            while True:
                changed_files = []
                for file_path in self._loaded_files:
                    if os.path.exists(file_path):
                        current_mtime = os.path.getmtime(file_path)
                        if file_path in file_mtimes and current_mtime > file_mtimes[file_path]:
                            changed_files.append(file_path)
                            file_mtimes[file_path] = current_mtime
                            
                if changed_files:
                    # Remember old values to detect changes
                    old_values = self._values.copy()
                    
                    # Reload changed files
                    for file_path in changed_files:
                        self.import_env(file_path, override=True)
                        
                    # Determine changed keys
                    changed_keys = []
                    for key, value in self._values.items():
                        if key not in old_values or old_values[key] != value:
                            changed_keys.append(key)
                            
                    # Call the callback with changed keys
                    if changed_keys and callback:
                        try:
                            callback(changed_keys)
                        except Exception as e:
                            logger.error(f"Error in file change callback: {str(e)}")
                
                time.sleep(interval)
                
        # Start the watcher thread
        thread = threading.Thread(target=watcher, daemon=True)
        thread.start()
        
    def secure_delete(self, key: str) -> None:
        """
        Securely delete a key and overwrite its value in memory.
        
        Args:
            key: Key to delete
        """
        if key in self._values:
            # Overwrite the value with random data
            value_length = len(self._values[key])
            self._values[key] = ''.join(secrets.choice('0123456789abcdef') for _ in range(value_length))
            
            # Delete the key
            del self._values[key]
            
            if key in self._sensitive_keys:
                self._sensitive_keys.remove(key)
                
            if key in self._comment_map:
                del self._comment_map[key]
                
            self._modified = True
            
    def protect_against_timing_attacks(self) -> None:
        """
        Add protection against timing attacks for sensitive values by padding them.
        
        This helps mitigate timing attacks by ensuring all values have similar
        cryptographic processing time.
        """
        for key in self._sensitive_keys:
            if key in self._values and not self._values[key].startswith('ENC:'):
                # Add random padding to the value
                original_value = self._values[key]
                padding_length = secrets.randbelow(10) + 1  # Random padding of 1-10 characters
                padding = ''.join(secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789') 
                                 for _ in range(padding_length))
                
                # Format: original_value + "|PADDING:" + padding
                padded_value = f"{original_value}|PADDING:{padding}"
                self._values[key] = padded_value
                
    def remove_padding(self) -> None:
        """
        Remove padding from values that were protected against timing attacks.
        """
        for key in self._values:
            value = self._values[key]
            if "|PADDING:" in value:
                original_value = value.split("|PADDING:", 1)[0]
                self._values[key] = original_value
                
    def get_or_create(self, key: str, default_generator: callable = None) -> str:
        """
        Get a value by key or create it if it doesn't exist.
        
        Args:
            key: The key to retrieve
            default_generator: Function to generate a default value
            
        Returns:
            The value
        """
        if key in self._values:
            return self._values[key]
            
        # Generate a default value
        if default_generator:
            value = default_generator()
        else:
            value = ""
            
        # Store the value
        self._values[key] = str(value)
        self._modified = True
        
        return self._values[key]
        
    def escape_path_traversal(self, value: str) -> str:
        """
        Escape path traversal attempts in a value.
        
        Args:
            value: Value to escape
            
        Returns:
            Escaped value
        """
        # Remove path traversal patterns
        escaped = re.sub(r'\.\./', '', value)
        escaped = re.sub(r'\.\.\\', '', escaped)
        
        # Remove absolute path indicators
        escaped = re.sub(r'^/', '', escaped)
        escaped = re.sub(r'^\\', '', escaped)
        
        return escaped
        
    def audit_security(self) -> Dict[str, Any]:
        """
        Perform a comprehensive security audit of the environment.
        
        Returns:
            Audit report
        """
        report = {
            "timestamp": time.time(),
            "environment": self._environment,
            "total_variables": len(self._values),
            "sensitive_variables": len(self._sensitive_keys),
            "encrypted_variables": 0,
            "security_issues": [],
            "recommendations": [],
            "compliance": {
                "compliant": True,
                "issues": []
            }
        }
        
        # Check encryption status
        for key in self._sensitive_keys:
            if key in self._values:
                if self._values[key].startswith('ENC:'):
                    report["encrypted_variables"] += 1
                else:
                    report["security_issues"].append({
                        "severity": "high",
                        "type": "unencrypted_sensitive",
                        "key": key,
                        "recommendation": "Encrypt this sensitive value"
                    })
        
        # Check for dangerous patterns
        for key, value in self._values.items():
            for pattern in self.DANGEROUS_VALUE_PATTERNS:
                if re.search(pattern, value, re.IGNORECASE):
                    report["security_issues"].append({
                        "severity": "critical",
                        "type": "dangerous_value",
                        "key": key,
                        "pattern": pattern,
                        "recommendation": "Remove potentially dangerous code from this value"
                    })
        
        # Check for debug flags in production
        if self._environment == "production" and "DEBUG" in self._values and self._values["DEBUG"].lower() in ("true", "yes", "1", "on"):
            report["security_issues"].append({
                "severity": "high",
                "type": "debug_in_production",
                "key": "DEBUG",
                "recommendation": "Disable debug mode in production"
            })
            
        # Check for insecure URLs
        for key, value in self._values.items():
            if "URL" in key.upper() and value.startswith("http:"):
                report["security_issues"].append({
                    "severity": "medium",
                    "type": "insecure_url",
                    "key": key,
                    "recommendation": "Use HTTPS instead of HTTP"
                })
                
        # Check for hardcoded credentials
        for key in self._sensitive_keys:
            if key in self._values and not self._values[key].startswith('ENC:'):
                # Check if it looks like a hardcoded credential
                value = self._values[key]
                if len(value) > 8 and _calculate_entropy(value) > 3.0:
                    report["security_issues"].append({
                        "severity": "high",
                        "type": "hardcoded_credential",
                        "key": key,
                        "recommendation": "Store sensitive credentials in a secure vault or use encryption"
                    })
                    
        # Generate overall compliance status
        if report["security_issues"]:
            report["compliance"]["compliant"] = False
            for issue in report["security_issues"]:
                report["compliance"]["issues"].append({
                    "key": issue["key"],
                    "message": f"{issue['type']} ({issue['severity']})",
                    "recommendation": issue["recommendation"]
                })
                
        # Generate recommendations
        if report["encrypted_variables"] < len(self._sensitive_keys):
            report["recommendations"].append("Encrypt all sensitive variables with encrypt_sensitive_values()")
            
        if self._environment == "production" and report["security_issues"]:
            report["recommendations"].append("Fix all security issues before deploying to production")
            
        if not self._loaded_files:
            report["recommendations"].append("Load environment from files rather than setting variables manually")
            
        return report
            
    def generate_documentation(self, output_path: str = None, 
                             format: str = 'markdown',
                             include_sensitive: bool = False) -> str:
        """
        Generate documentation for the environment variables.
        
        Args:
            output_path: Path to save the documentation, or None to return as string
            format: Output format ('markdown', 'html', or 'json')
            include_sensitive: Whether to include sensitive values
            
        Returns:
            Documentation as a string if output_path is None, otherwise None
        """
        # Gather data about environment variables
        data = []
        for key in sorted(self._values.keys()):
            value = self._values[key]
            is_sensitive = key in self._sensitive_keys
            
            if is_sensitive and not include_sensitive:
                if value.startswith('ENC:'):
                    display_value = '[ENCRYPTED]'
                else:
                    display_value = '********'
            else:
                display_value = value
                
            # Try to determine the type
            if value.lower() in ('true', 'false', 'yes', 'no', 'on', 'off'):
                value_type = 'boolean'
            elif value.isdigit():
                value_type = 'integer'
            elif re.match(r'^-?\d+(\.\d+)?$', value):
                value_type = 'float'
            elif value.startswith('{') and value.endswith('}'):
                value_type = 'json'
            elif value.startswith('[') and value.endswith(']'):
                value_type = 'array'
            else:
                value_type = 'string'
                
            # Get comment if available
            comment = self._comment_map.get(key, '')
                
            data.append({
                'key': key,
                'value': display_value,
                'type': value_type,
                'sensitive': is_sensitive,
                'comment': comment
            })
            
        # Generate documentation in the specified format
        if format == 'markdown':
            doc = self._generate_markdown_docs(data)
        elif format == 'html':
            doc = self._generate_html_docs(data)
        elif format == 'json':
            doc = json.dumps({
                'variables': data,
                'metadata': {
                    'total_count': len(data),
                    'sensitive_count': sum(1 for item in data if item['sensitive']),
                    'generated_at': datetime.datetime.now().isoformat(),
                }
            }, indent=2)
        else:
            raise ValueError(f"Unsupported documentation format: {format}")
            
        # Write to file if output_path is provided
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as file:
                file.write(doc)
            logger.info(f"Documentation generated at {output_path}")
            return None
        else:
            return doc
            
    def _generate_markdown_docs(self, data: List[Dict[str, Any]]) -> str:
        """Generate Markdown documentation."""
        doc = "# Environment Variables Documentation\n\n"
        doc += f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        doc += f"Total variables: {len(data)}\n"
        doc += f"Sensitive variables: {sum(1 for item in data if item['sensitive'])}\n\n"
        
        doc += "## Variables\n\n"
        doc += "| Key | Type | Sensitive | Description |\n"
        doc += "|-----|------|-----------|-------------|\n"
        
        for item in data:
            doc += f"| `{item['key']}` | {item['type']} | {'Yes' if item['sensitive'] else 'No'} | {item['comment']} |\n"
            
        return doc
        
    def _generate_html_docs(self, data: List[Dict[str, Any]]) -> str:
        """Generate HTML documentation."""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Environment Variables Documentation</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; }}
        h1 {{ color: #333; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; }}
        th {{ background-color: #f2f2f2; text-align: left; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        .sensitive {{ color: #ff4500; }}
    </style>
</head>
<body>
    <h1>Environment Variables Documentation</h1>
    <p>Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p>Total variables: {len(data)}</p>
    <p>Sensitive variables: {sum(1 for item in data if item['sensitive'])}</p>
    
    <h2>Variables</h2>
    <table>
        <tr>
            <th>Key</th>
            <th>Value</th>
            <th>Type</th>
            <th>Sensitive</th>
            <th>Description</th>
        </tr>
"""
        
        for item in data:
            html += f"""        <tr>
            <td><code>{item['key']}</code></td>
            <td><code>{item['value']}</code></td>
            <td>{item['type']}</td>
            <td>{'<span class="sensitive">Yes</span>' if item['sensitive'] else 'No'}</td>
            <td>{item['comment']}</td>
        </tr>
"""
            
        html += """    </table>
</body>
</html>
"""
        return html
