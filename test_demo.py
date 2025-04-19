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
#!/usr/bin/env python3
"""
Comprehensive test and demonstration script for Envella library.
This script showcases the advanced security features and enhanced functionality.

Author: Mohammad Hosseini
License: GPL-3.0
"""
import os
import tempfile
import json
import time
from pathlib import Path
import base64
import sys
import hashlib

# Import the Envella library
from Envella import Envella
from Envella.utils import (
    generate_secure_key, encrypt_value, decrypt_value,
    encrypt_with_quantum_resistant_hybrid, decrypt_with_quantum_resistant_hybrid,
    vault_encrypt, vault_decrypt, generate_mfa_secret, verify_totp_code,
    assess_password_strength, generate_environment_integrity_signature,
    generate_recovery_codes
)

def print_header(title):
    """Print a formatted header."""
    print("\n" + "=" * 80)
    print(f" {title} ".center(80, "="))
    print("=" * 80)

def create_test_files():
    """Create test .env files for demonstration."""
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp()

    # Create example .env files
    env_path = os.path.join(temp_dir, ".env")
    with open(env_path, "w") as f:
        f.write("""# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=testdb
DB_USER=admin
DB_PASSWORD=s3cret123!

# Application Settings
DEBUG=true
LOG_LEVEL=info
API_URL=http://api.example.com
MAX_CONNECTIONS=100
""")

    # Create environment-specific .env file
    env_prod_path = os.path.join(temp_dir, ".env.production")
    with open(env_prod_path, "w") as f:
        f.write("""# Production Configuration
DB_HOST=db.example.com
DB_PORT=5432
DB_NAME=proddb
DB_USER=dbuser
DB_PASSWORD=ProdSecr3t!2023

# Application Settings
DEBUG=false
LOG_LEVEL=error
API_URL=https://api.example.com
MAX_CONNECTIONS=500
""")

    return temp_dir, env_path, env_prod_path

def demo_basic_usage(env_path):
    """Demonstrate basic Envella usage."""
    print_header("Basic Usage")

    # Create a new Envella instance
    env = Envella()

    # Import the environment from a file
    env.import_env(env_path)

    # Display loaded variables
    print(f"Loaded {len(env.keys())} variables from {env_path}")
    print(f"Keys: {', '.join(env.keys())}")

    # Access values
    print(f"\nDatabase Configuration:")
    print(f"  Host: {env.get('DB_HOST')}")
    print(f"  Port: {env.get('DB_PORT', cast_type=int)}")
    print(f"  Name: {env.get('DB_NAME')}")

    # Use with type casting
    debug_mode = env.get('DEBUG', cast_type=bool)
    max_connections = env.get('MAX_CONNECTIONS', cast_type=int)
    print(f"\nApplication Settings:")
    print(f"  Debug Mode: {debug_mode}")
    print(f"  Max Connections: {max_connections}")

    # Get all values as a dictionary
    config = env.as_dict(cast_types=True)
    print(f"\nAll values with automatic type casting:")
    for key, value in config.items():
        print(f"  {key}: {value} ({type(value).__name__})")

def demo_enhanced_security(env_path):
    """Demonstrate enhanced security features."""
    print_header("Enhanced Security Features")

    # Create a Envella instance with an encryption key
    encryption_key = generate_secure_key()
    print(f"Generated encryption key: {encryption_key[:10]}...{encryption_key[-10:]}")

    env = Envella(encryption_key=encryption_key)
    env.import_env(env_path)

    # Identify sensitive keys
    print(f"\nIdentified sensitive keys: {env._sensitive_keys}")

    # Encrypt sensitive values
    env.encrypt_sensitive_values()
    print("\nAfter encrypting sensitive values:")
    for key in env._sensitive_keys:
        print(f"  {key}: {env.get(key)}")

    # Decrypt sensitive values
    env.decrypt_sensitive_values()
    print("\nAfter decrypting sensitive values:")
    for key in env._sensitive_keys:
        print(f"  {key}: {env.get(key)}")

    # Generate environment integrity signature
    signature = generate_environment_integrity_signature(env.as_dict(), encryption_key)
    print(f"\nEnvironment integrity signature: {signature[:30]}...")

    # Advanced quantum-resistant encryption
    secret_data = "This is extremely sensitive data that must be protected"
    encrypted_data = encrypt_with_quantum_resistant_hybrid(secret_data, "secure-password")
    print(f"\nQuantum-resistant encrypted data: {encrypted_data[:50]}...")

    # Decrypt quantum-resistant data
    decrypted_data = decrypt_with_quantum_resistant_hybrid(encrypted_data, "secure-password")
    print(f"Decrypted data: {decrypted_data}")

    # Vault-style encryption
    vault_data = vault_encrypt("API-KEY-abcdef123456", "master-key")
    print(f"\nVault encrypted data: {json.dumps(vault_data, indent=2)[:100]}...")

    # Password strength assessment
    passwords = ["password123", "P@ssw0rd!", "8X*d2!9Zk$mLp7@qR"]
    print("\nPassword strength assessment:")
    for password in passwords:
        assessment = assess_password_strength(password)
        print(f"  '{password}': {assessment['strength']} (score: {assessment['score']}/5)")
        print(f"    - Time to crack: {assessment['time_to_crack']}")
        print(f"    - Feedback: {', '.join(assessment['feedback'])}")

def demo_multi_environment(temp_dir):
    """Demonstrate multi-environment configuration."""
    print_header("Multi-Environment Configuration")

    env = Envella(environment="development")

    # Load multiple environments
    loaded_files = env.load_dotenv_from_directory(temp_dir)
    print(f"Loaded files from directory: {loaded_files}")

    # Auto-detect environment
    detected_env = env.auto_detect_environment()
    print(f"Auto-detected environment: {detected_env}")

    # Check environment compliance
    env_report = env.check_environment_compliance("production")
    if env_report:
        print("\nCompliance issues for production environment:")
        for issue in env_report:
            print(f"  - {issue['message']}")
    else:
        print("\nNo compliance issues found for production environment")

    # Create a production environment
    prod_env = Envella(environment="production")
    prod_env.import_env(os.path.join(temp_dir, ".env.production"))

    print("\nProduction environment variables:")
    for key in prod_env.keys():
        print(f"  {key}: {prod_env.get(key)}")

def demo_advanced_features():
    """Demonstrate advanced features."""
    print_header("Advanced Features")

    # Create a Envella with custom configuration
    user_config = {
        "log_level": "info",
        "sensitive_patterns": [r".*api_token.*", r".*passphrase.*"],
        "allow_debug": False,
        "min_password_length": 14
    }

    env = Envella(user_config=user_config)

    # Set values manually
    env.set("API_TOKEN", "abcdef123456", comment="Token for external API")
    env.set("APP_NAME", "Envella Demo")
    env.set("DEBUG", "false")
    env.set("MAX_RETRY", "5")

    # Schema validation
    schema = {
        "API_TOKEN": {
            "type": str,
            "required": True,
            "min_length": 10,
            "description": "API authentication token"
        },
        "APP_NAME": {
            "type": str,
            "required": True,
            "description": "Application name"
        },
        "DEBUG": {
            "type": bool,
            "required": True,
            "description": "Debug mode flag"
        },
        "MAX_RETRY": {
            "type": int,
            "required": True,
            "min": 1,
            "max": 10,
            "description": "Maximum retry attempts"
        }
    }

    valid, errors = env.validate_against_schema(schema)
    print(f"Schema validation: {'Valid' if valid else 'Invalid'}")
    if not valid:
        print("Validation errors:")
        for error in errors:
            print(f"  - {error['message']}")

    # Generate documentation
    print("\nGenerating documentation...")
    docs = env.generate_documentation(format="markdown")
    print(docs[:500] + "...\n")

    # Perform security audit
    audit = env.audit_security()
    print("\nSecurity audit results:")
    print(f"  Environment: {audit['environment']}")
    print(f"  Total variables: {audit['total_variables']}")
    print(f"  Sensitive variables: {audit['sensitive_variables']}")
    print(f"  Encrypted variables: {audit['encrypted_variables']}")

    if audit['security_issues']:
        print("\n  Security issues found:")
        for issue in audit['security_issues']:
            print(f"    - [{issue['severity']}] {issue['type']} in '{issue['key']}'")
    else:
        print("\n  No security issues found")

    if audit['recommendations']:
        print("\n  Recommendations:")
        for rec in audit['recommendations']:
            print(f"    - {rec}")

def demo_mfa_features():
    """Demonstrate MFA and authentication features."""
    print_header("MFA and Authentication Features")

    # Generate MFA secret
    mfa_secret = generate_mfa_secret()
    print(f"Generated MFA secret: {mfa_secret}")

    # In a real application, you would use a TOTP app to generate a code
    # For demo purposes, we'll simulate generating and validating a code
    import hmac
    import hashlib
    import time
    import struct

    def generate_totp(secret, time_step=30):
        """Generate a TOTP code for demonstration."""
        # Get current timestamp and convert to time_step intervals
        timestamp = int(time.time()) // time_step

        # Convert timestamp to bytes
        time_bytes = struct.pack(">Q", timestamp)

        # Decode base32 secret
        secret_bytes = base64.b32decode(secret.upper())

        # Generate HMAC with SHA-256
        hmac_hash = hmac.new(secret_bytes, time_bytes, hashlib.sha256).digest()

        # Extract bytes
        offset = hmac_hash[-1] & 0x0F
        truncated_hash = hmac_hash[offset:offset+4]

        # Convert to integer and take last 6 digits
        totp_value = (struct.unpack('>I', truncated_hash)[0] & 0x7FFFFFFF) % 1000000

        # Format as 6-digit string
        return f"{totp_value:06d}"

    # Generate a TOTP code
    totp_code = generate_totp(mfa_secret)
    print(f"Generated TOTP code: {totp_code}")

    # Verify the TOTP code
    is_valid = verify_totp_code(mfa_secret, totp_code)
    print(f"TOTP code verification: {'Valid' if is_valid else 'Invalid'}")

    # Generate recovery codes
    recovery_codes = generate_recovery_codes(count=5)
    print("\nGenerated recovery codes:")
    for code in recovery_codes:
        print(f"  {code}")

def main():
    """Main function demonstrating Envella capabilities."""
    print_header("Envella Library Demonstration")
    print("Version: 1.0.0")
    print("Author: Mohammad Hosseini")
    print("License: GPL-3.0\n")

    print("Creating test environment files...")
    temp_dir, env_path, env_prod_path = create_test_files()

    try:
        # Run demos
        demo_basic_usage(env_path)
        demo_enhanced_security(env_path)
        demo_multi_environment(temp_dir)
        demo_advanced_features()
        demo_mfa_features()

        print_header("Demonstration Complete")
        print("Envella provides a comprehensive, secure, and highly advanced solution")
        print("for managing environment variables with a focus on security and ease of use.")

    finally:
        # Clean up
        import shutil
        shutil.rmtree(temp_dir)

if __name__ == "__main__":
    main()
