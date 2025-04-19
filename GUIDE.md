
# Envella Library Comprehensive Guide

## Table of Contents
- [Introduction](#introduction)
- [Installation](#installation)
- [Core Concepts](#core-concepts)
- [Basic Usage](#basic-usage)
- [Environment Management](#environment-management)
- [Security Features](#security-features)
- [Value Handling and Type Casting](#value-handling-and-type-casting)
- [Validation](#validation)
- [Advanced Encryption](#advanced-encryption)
- [Multi-Factor Authentication](#multi-factor-authentication)
- [Compliance and Auditing](#compliance-and-auditing)
- [Documentation Generation](#documentation-generation)
- [Utility Functions](#utility-functions)
- [Error Handling](#error-handling)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)
- [API Reference](#api-reference)

## Introduction

Envella is a comprehensive, secure, and advanced environment variable management library for Python applications. It goes far beyond basic `.env` file parsing to provide a robust security-focused solution for managing application configurations.

This guide provides in-depth coverage of all Envella features with practical examples to help you leverage the full capabilities of the library in your applications.

## Installation

### Standard Installation

```bash
pip install Envella
```

### Installation with Advanced Security Features

```bash
pip install Envella[advanced]
```

This installs additional dependencies for quantum-resistant encryption, password strength evaluation, and MFA functionality.

### Installation with Development Tools

```bash
pip install Envella[dev]
```

### Installation with Testing Tools

```bash
pip install Envella[test]
```

## Core Concepts

Envella revolves around several key concepts:

1. **Environment Variables**: Key-value pairs used for configuration
2. **Sensitive Data Protection**: Automatic identification and encryption of sensitive values
3. **Environment-Specific Configuration**: Support for different environments (development, testing, staging, production)
4. **Type Casting**: Automatic conversion of string values to appropriate Python types
5. **Validation**: Schema-based validation of environment variables
6. **Security Audit**: Tools to identify potential security issues

## Basic Usage

### Importing the Library

```python
from Envella import Envella
```

### Creating an Instance

```python
# Create a basic instance
env = Envella()

# Create an instance with an encryption key
encryption_key = "your-secure-encryption-key"
env = Envella(encryption_key=encryption_key)

# Create an instance for a specific environment
env = Envella(environment="production")

# Create an instance with custom configuration
user_config = {
    "log_level": "info",
    "sensitive_patterns": [r".*api_token.*", r".*passphrase.*"],
    "allow_debug": False,
    "min_password_length": 14
}
env = Envella(user_config=user_config)
```

### Loading Environment Variables

```python
# Load from a specific .env file
env.import_env(".env")

# Load with options
env.import_env(".env.production", override=True, export_globals=True)

# Load multiple files
env.load_multiple_env_files([".env", ".env.local", ".env.development"])

# Load from a directory (automatically finds appropriate files)
loaded_files = env.load_dotenv_from_directory("config/")
print(f"Loaded files: {loaded_files}")
```

### Accessing Values

```python
# Get a simple value
api_url = env.get("API_URL")

# Get with a default value
debug = env.get("DEBUG", default=False)

# Get with automatic type casting
port = env.get("PORT", cast_type=int)
debug_mode = env.get("DEBUG", cast_type=bool)
rate_limit = env.get("RATE_LIMIT", cast_type=float)

# Get a secure string (automatically marks it as sensitive)
password = env.get_secure_string("DB_PASSWORD")

# Get all values as a dictionary
all_values = env.as_dict()

# Get all values with automatic type casting
config = env.as_dict(cast_types=True)
```

## Environment Management

### Working with Multiple Environments

```python
# Creating environment-specific instances
dev_env = Envella(environment="development")
prod_env = Envella(environment="production")

# Loading environment-specific files
dev_env.import_env(".env.development")
prod_env.import_env(".env.production")

# Auto-detect the environment
current_env = Envella()
detected = current_env.auto_detect_environment()
print(f"Detected environment: {detected}")

# Load based on detected environment
current_env.import_env(f".env.{detected}")

# Check environment compliance
issues = prod_env.check_environment_compliance("production")
if issues:
    print("Compliance issues found:")
    for issue in issues:
        print(f"- {issue['message']}")
```

### Example: Environment-Specific Configuration

```python
import os
from Envella import Envella

# Determine the current environment
environment = os.getenv("APP_ENV", "development")

# Create an environment-specific instance
env = Envella(environment=environment)

# Load appropriate configuration
env.import_env(f".env.{environment}")

# Use the configuration
debug_mode = env.get("DEBUG", cast_type=bool)
db_url = env.get("DATABASE_URL")

print(f"Running in {environment} mode")
print(f"Debug mode: {debug_mode}")
print(f"Using database: {db_url}")
```

## Security Features

### Identifying Sensitive Keys

Envella automatically identifies sensitive keys based on patterns in the key names. These patterns include:

- `*pass*`, `*secret*`, `*key*`, `*token*`
- `*pwd*`, `*auth*`, `*credential*`
- `*private*`, `*certificate*`, `*salt*`
- `*hash*`, `*encrypt*`, `*cipher*`, etc.

You can access the identified sensitive keys:

```python
print(f"Sensitive keys: {env._sensitive_keys}")
```

### Encrypting Sensitive Values

```python
# Generate a secure encryption key
from Envella.utils import generate_secure_key
encryption_key = generate_secure_key()
print(f"Generated key: {encryption_key}")

# Create an instance with the key
env = Envella(encryption_key=encryption_key)
env.import_env(".env")

# Encrypt all sensitive values
env.encrypt_sensitive_values()

# Save the encrypted values
env.save(".env.encrypted")

# Later, decrypt the values
env.decrypt_sensitive_values()
```

### Security Audit

```python
# Perform a comprehensive security audit
audit = env.audit_security()

# Check the results
print(f"Environment: {audit['environment']}")
print(f"Total variables: {audit['total_variables']}")
print(f"Sensitive variables: {audit['sensitive_variables']}")
print(f"Encrypted variables: {audit['encrypted_variables']}")

# Check for security issues
if audit['security_issues']:
    print("\nSecurity issues found:")
    for issue in audit['security_issues']:
        print(f"[{issue['severity']}] {issue['type']} in '{issue['key']}'")
        print(f"  Recommendation: {issue['recommendation']}")

# Check recommendations
if audit['recommendations']:
    print("\nRecommendations:")
    for rec in audit['recommendations']:
        print(f"- {rec}")
```

### Key Rotation

```python
# Generate a new encryption key
new_key = generate_secure_key()

# Rotate the encryption key
# This will decrypt all values with the old key and re-encrypt with the new key
env.rotate_encryption_key(new_key)

# You can also specify a window during which the old key remains valid
env.rotate_encryption_key(new_key, rotation_window=86400)  # 24 hours
```

### Protection Against Timing Attacks

```python
# Add protection against timing attacks
env.protect_against_timing_attacks()

# Later, remove the padding
env.remove_padding()
```

### Securely Comparing Values

```python
from Envella.utils import secure_compare

# Compare two strings in constant time to prevent timing attacks
equal = secure_compare("secret-token-123", user_provided_token)
```

### Secure Deletion

```python
# Securely delete a sensitive key
env.secure_delete("API_SECRET")
```

## Value Handling and Type Casting

### Automatic Type Casting

Envella can automatically cast values to appropriate Python types:

```python
# Cast to specific types
port = env.get("PORT", cast_type=int)
debug = env.get("DEBUG", cast_type=bool)
rate_limit = env.get("RATE_LIMIT", cast_type=float)
config = env.get("CONFIG", cast_type=dict)  # Will attempt to parse as JSON

# Cast all values
all_values = env.as_dict(cast_types=True)
```

### Setting Values

```python
# Set a simple value
env.set("API_URL", "https://api.example.com")

# Set with a comment
env.set("TIMEOUT", "30", comment="Connection timeout in seconds")

# Set a value and automatically identify if it's sensitive
env.set("API_SECRET", "abc123xyz")  # Will be automatically marked as sensitive
```

### Value Interpolation

```python
# Given a .env file with:
# DB_HOST=localhost
# DB_PORT=5432
# DB_NAME=mydb
# DB_URL=${DB_HOST}:${DB_PORT}/${DB_NAME}

env.import_env(".env")
env.interpolate_values()

# Now env.get("DB_URL") will return "localhost:5432/mydb"
```

### Default Values

```python
# Apply default values for missing keys
defaults = {
    "PORT": 3000,
    "HOST": "localhost",
    "MAX_CONNECTIONS": 100
}

applied_count = env.apply_defaults(defaults)
print(f"Applied {applied_count} default values")
```

## Validation

### Required Keys

```python
# Check if required keys are present
valid, missing = env.validate_required_keys(["API_KEY", "DATABASE_URL", "SECRET_KEY"])

if not valid:
    print(f"Missing required keys: {', '.join(missing)}")
```

### Format Validation

```python
# Validate that a value matches a specific format
is_valid = env.validate_format("EMAIL", r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")

if not is_valid:
    print("Invalid email format")
```

### Schema Validation

```python
# Define a schema for validation
schema = {
    "PORT": {
        "type": int,
        "required": True,
        "min": 1024,
        "max": 65535,
        "description": "Port to run the server on"
    },
    "DEBUG": {
        "type": bool,
        "required": True,
        "description": "Enable debug mode"
    },
    "API_URL": {
        "type": str,
        "required": True,
        "pattern": r"^https://.*",
        "description": "API endpoint URL (must use HTTPS)"
    },
    "MAX_CONNECTIONS": {
        "type": int,
        "required": False,
        "min": 1,
        "max": 1000,
        "description": "Maximum number of connections"
    },
    "LOG_LEVEL": {
        "type": str,
        "enum": ["debug", "info", "warning", "error", "critical"],
        "description": "Logging level"
    },
    "API_VERSION": {
        "type": str,
        "depends_on": "API_URL",
        "description": "API version"
    },
    "TIMEOUT": {
        "type": float,
        "min": 0.1,
        "max": 300.0,
        "description": "Request timeout in seconds",
        # Custom validator function
        "validator": lambda val: (float(val) > 0, "Timeout must be positive")
    }
}

# Validate against the schema
valid, errors = env.validate_against_schema(schema)

if not valid:
    print("Validation errors:")
    for error in errors:
        print(f"- {error['key']}: {error['message']}")
```

### Enforcing Security Policies

```python
# Define security policies
policies = {
    "require_encryption": True,
    "min_password_length": 12,
    "disallow_unsafe_protocols": True,
    "disallow_debug_in_production": True,
    "disallow_hardcoded_ips": True,
    "allow_private_ips": True,
    "prevent_sensitive_env_leakage": True,
    "environment": "production"
}

# Enforce policies
compliant, violations = env.enforce_security_policies(policies)

if not compliant:
    print("Security policy violations:")
    for violation in violations:
        print(f"[{violation['risk']}] {violation['policy']} - {violation['key']}")
        print(f"  Recommendation: {violation['recommendation']}")
```

## Advanced Encryption

### Quantum-Resistant Hybrid Encryption

```python
from Envella.utils import encrypt_with_quantum_resistant_hybrid, decrypt_with_quantum_resistant_hybrid

# Encrypt sensitive configuration
config_data = '{"api_keys": {"service_a": "secret_key_123"}}'
encrypted = encrypt_with_quantum_resistant_hybrid(config_data, "master-password")

print(f"Encrypted data: {encrypted[:50]}...")

# Later, decrypt the configuration
decrypted = decrypt_with_quantum_resistant_hybrid(encrypted, "master-password")
print(f"Decrypted data: {decrypted}")
```

### Vault-Style Encryption

```python
from Envella.utils import vault_encrypt, vault_decrypt

# Encrypt a value using vault-style encryption
master_key = "master-encryption-key"
sensitive_value = "api-key-abcdef123456"

encrypted_data = vault_encrypt(sensitive_value, master_key)
print(f"Encrypted data: {encrypted_data}")

# Later, decrypt the value
decrypted_value = vault_decrypt(encrypted_data, master_key)
print(f"Decrypted value: {decrypted_value}")
```

### RSA Encryption

```python
from Envella.utils import generate_rsa_keypair, encrypt_with_public_key, decrypt_with_private_key

# Generate RSA key pair
private_key, public_key = generate_rsa_keypair()

# Encrypt with public key
message = "This is a secret message"
encrypted = encrypt_with_public_key(public_key, message)

# Decrypt with private key
decrypted = decrypt_with_private_key(private_key, encrypted)
print(f"Decrypted message: {decrypted}")
```

### Environment Integrity Verification

```python
from Envella.utils import generate_environment_integrity_signature, verify_environment_integrity

# Generate a signature for the environment
secret_key = "integrity-verification-key"
env_values = env.as_dict()

signature = generate_environment_integrity_signature(env_values, secret_key)
print(f"Environment signature: {signature[:30]}...")

# Later, verify the integrity
is_valid = verify_environment_integrity(env_values, signature, secret_key)
print(f"Environment integrity: {'Valid' if is_valid else 'Invalid'}")
```

## Multi-Factor Authentication

### Generating TOTP Secrets

```python
from Envella.utils import generate_mfa_secret

# Generate a secret for TOTP-based MFA
mfa_secret = generate_mfa_secret()
print(f"MFA Secret: {mfa_secret}")

# The secret can be shared with the user to set up an authenticator app
print(f"Set up this code in your authenticator app: {mfa_secret}")
```

### Verifying TOTP Codes

```python
from Envella.utils import verify_totp_code

# Verify a TOTP code provided by the user
user_code = "123456"  # Code from authenticator app
is_valid = verify_totp_code(mfa_secret, user_code)

if is_valid:
    print("MFA code verified successfully")
else:
    print("Invalid MFA code")
```

### Generating Recovery Codes

```python
from Envella.utils import generate_recovery_codes

# Generate recovery codes as a backup for MFA
recovery_codes = generate_recovery_codes(count=10)

print("Your recovery codes:")
for code in recovery_codes:
    print(code)
```

### Password Strength Assessment

```python
from Envella.utils import assess_password_strength

# Assess the strength of a password
passwords = ["password123", "P@ssw0rd!", "8X*d2!9Zk$mLp7@qR"]

for password in passwords:
    assessment = assess_password_strength(password)
    print(f"Password: {password}")
    print(f"Strength: {assessment['strength']} (Score: {assessment['score']}/5)")
    print(f"Time to crack: {assessment['time_to_crack']}")
    print(f"Feedback: {', '.join(assessment['feedback'])}")
    print()
```

## Compliance and Auditing

### Environment Compliance Check

```python
# Check compliance for a specific environment type
issues = env.check_environment_compliance("production")

if issues:
    print("Compliance issues for production environment:")
    for issue in issues:
        print(f"[{issue['severity']}] {issue['type']} - {issue['key']}")
        print(f"  Message: {issue['message']}")
        print(f"  Recommendation: {issue['recommendation']}")
else:
    print("Environment is compliant with production requirements")
```

### Detecting Secrets in Content

```python
from Envella.utils import detect_secrets_in_content

# Scan content for potential secrets
content = """
# Configuration
api_key=abcdef123456
# Database settings
db_password=s3cr3t!
"""

secrets = detect_secrets_in_content(content)

if secrets:
    print("Potential secrets detected:")
    for secret in secrets:
        print(f"[{secret['type']}] Line {secret['line']}: {secret['match']}")
        print(f"  Risk score: {secret['risk_score']}")
else:
    print("No secrets detected")
```

### Checking Security Vulnerabilities

```python
from Envella.utils import check_security_vulnerabilities

# Check for security vulnerabilities in environment values
env_values = env.as_dict()
vulnerabilities = check_security_vulnerabilities(env_values)

if vulnerabilities:
    print("Security vulnerabilities detected:")
    for vuln in vulnerabilities:
        print(f"[{vuln['risk']}] {vuln['type']} - {vuln['key']}")
        print(f"  Recommendation: {vuln['recommendation']}")
else:
    print("No security vulnerabilities detected")
```

## Documentation Generation

### Generating Markdown Documentation

```python
# Generate documentation in Markdown format
docs = env.generate_documentation(format="markdown")
print(docs)

# Save to a file
with open("env_documentation.md", "w") as f:
    f.write(docs)
```

### Generating HTML Documentation

```python
# Generate documentation in HTML format
html_docs = env.generate_documentation(format="html", output_path="env_documentation.html")
print("Documentation saved to env_documentation.html")
```

### Generating JSON Documentation

```python
# Generate documentation in JSON format
json_docs = env.generate_documentation(format="json")
print(json_docs)
```

### Generating a Template

```python
# Generate a template file with keys but empty values
env.generate_template(".env.template")
print("Template generated at .env.template")
```

## Utility Functions

### File Operations

```python
# Save the current environment to a file
env.save(".env.backup")

# Create a backup before making changes
from Envella.utils import auto_backup_env_file
backup_path = auto_backup_env_file(".env", backup_dir=".backups")
print(f"Backup created at {backup_path}")

# Export to Docker-compatible .env file
env.export_to_docker_env_file("docker.env")

# Export to JSON
env.export_to_json("env_config.json", include_sensitive=False)

# Export to JSON with encryption
env.export_to_json("env_config.enc.json", include_sensitive=True, 
                  encrypt_output=True, password="secure-password")

# Import from JSON
env.import_from_json("env_config.json")

# Import from encrypted JSON
env.import_from_json("env_config.enc.json", encrypted=True, password="secure-password")
```

### Watching for Changes

```python
# Define a callback function
def on_env_change(changed_keys):
    print(f"Environment changes detected in keys: {changed_keys}")
    # Reload configuration, restart services, etc.

# Watch for changes in loaded files
env.watch_for_changes(on_env_change, interval=5)  # Check every 5 seconds
```

### Working with Global Environment

```python
# Export environment variables to os.environ
env._export_to_globals(override=True)

# Apply environment variables with a prefix
count = env.apply_environment_variables(prefix="APP_")
print(f"Applied {count} environment variables with 'APP_' prefix")
```

### Secure Path Escaping

```python
from Envella.utils import escape_path_traversal

# Escape path traversal attempts
user_input = "../../../etc/passwd"
safe_path = escape_path_traversal(user_input)
print(f"Safe path: {safe_path}")  # Output: "etcpasswd"
```

### Secure String Representation

```python
from Envella.utils import format_secure_representation

# Format a sensitive value for display
api_key = "abcdef123456"
masked = format_secure_representation(api_key)
print(f"API Key: {masked}")  # Output: "ab****56"
```

## Error Handling

Envella provides custom exceptions for better error handling:

```python
from Envella.exceptions import DotEnvError, FileNotFoundError, ParseError, SecurityError

try:
    env.import_env("non_existent_file.env")
except FileNotFoundError as e:
    print(f"File not found: {e}")

try:
    # Attempt something that might cause a security error
    env.validate_required_keys(["SENSITIVE_KEY"])
except SecurityError as e:
    print(f"Security error: {e}")
    
try:
    # General error handling
    env.import_env("malformed.env")
except DotEnvError as e:
    print(f"Environment error: {e}")
```

## Best Practices

### Handling Sensitive Data

1. **Always use encryption for sensitive values**
   ```python
   env = Envella(encryption_key=secure_key)
   env.encrypt_sensitive_values()
   ```

2. **Never commit sensitive values to version control**
   ```python
   # Generate a template without sensitive values
   env.generate_template(".env.template")
   ```

3. **Use secure storage for encryption keys**
   ```python
   # Store encryption keys in a secure vault or environment variables
   encryption_key = os.getenv("ENVELLA_ENCRYPTION_KEY")
   ```

### Environment-Specific Configuration

1. **Use separate files for different environments**
   ```python
   env.import_env(f".env.{environment}")
   ```

2. **Apply appropriate security policies for each environment**
   ```python
   env.check_environment_compliance(environment)
   ```

3. **Validate schema for each environment**
   ```python
   # Load environment-specific schema
   schema = load_schema_for_environment(environment)
   env.validate_against_schema(schema)
   ```

### Security Auditing

1. **Regularly audit security**
   ```python
   audit = env.audit_security()
   ```

2. **Rotate encryption keys periodically**
   ```python
   env.rotate_encryption_key(new_key)
   ```

3. **Check for compliance issues**
   ```python
   env.check_environment_compliance("production")
   ```

## Troubleshooting

### Common Issues and Solutions

1. **Issue**: Values are not being cast to the correct types
   **Solution**: Specify the cast_type parameter explicitly
   ```python
   # Instead of:
   port = int(env.get("PORT"))
   
   # Use:
   port = env.get("PORT", cast_type=int)
   ```

2. **Issue**: Cannot decrypt sensitive values
   **Solution**: Ensure you're using the same encryption key
   ```python
   # Store encryption key safely
   with open('.key', 'w') as f:
       f.write(encryption_key)
       
   # Later, use the same key
   with open('.key', 'r') as f:
       encryption_key = f.read()
   env = Envella(encryption_key=encryption_key)
   ```

3. **Issue**: Environment validation fails
   **Solution**: Check the validation errors and fix the issues
   ```python
   valid, errors = env.validate_against_schema(schema)
   
   if not valid:
       for error in errors:
           print(f"{error['key']}: {error['message']}")
   ```

4. **Issue**: Security audit shows issues
   **Solution**: Address the recommendations from the audit
   ```python
   audit = env.audit_security()
   
   for issue in audit['security_issues']:
       print(f"Fix {issue['key']}: {issue['recommendation']}")
   ```

## API Reference

### Envella Class

#### Constructor

```python
Envella(encryption_key=None, environment="development", user_config=None)
```

- `encryption_key`: Optional encryption key for sensitive values
- `environment`: Environment type (development, testing, staging, production)
- `user_config`: Optional user configuration to override default settings

#### Core Methods

- `import_env(path, override=False, export_globals=False, safe_mode=True)`: Import environment variables from a file
- `get(key, default=None, cast_type=None)`: Get a value by key with optional default and type casting
- `set(key, value, comment=None)`: Set a value for a key
- `save(path=None, include_comments=True)`: Save environment variables to a file
- `keys()`: Get a list of all keys
- `as_dict(cast_types=False)`: Get all values as a dictionary

#### Security Methods

- `encrypt_sensitive_values()`: Encrypt all sensitive values
- `decrypt_sensitive_values()`: Decrypt all encrypted sensitive values
- `audit_security()`: Perform a security audit
- `get_secure_string(key)`: Get a sensitive value securely
- `rotate_encryption_key(new_key, rotation_window=0)`: Rotate the encryption key
- `authenticate_with_key(key)`: Authenticate using an encryption key
- `protect_against_timing_attacks()`: Add protection against timing attacks
- `remove_padding()`: Remove padding added for timing attack protection
- `secure_delete(key)`: Securely delete a key

#### Validation Methods

- `validate_required_keys(required_keys)`: Validate that all required keys are present
- `validate_format(key, pattern)`: Validate that a value matches a specific format
- `validate_against_schema(schema)`: Validate against a schema
- `enforce_security_policies(policies)`: Enforce security policies

#### Advanced Methods

- `load_dotenv_from_directory(path, filename=None, override=False)`: Load .env files from a directory
- `load_multiple_env_files(file_paths, override=False, ignore_missing=True)`: Load multiple .env files
- `generate_template(output_path)`: Generate a template file
- `merge(other, override=False)`: Merge another Envella instance
- `interpolate_values()`: Interpolate values that reference other environment variables
- `generate_checksum()`: Generate a checksum of all environment variables
- `obfuscate_sensitive_keys()`: Create an obfuscated representation of the environment
- `deep_security_scan(content, source)`: Perform a deep security scan
- `export_to_docker_env_file(path)`: Export to a Docker .env file
- `export_to_json(path, include_sensitive=False, encrypt_output=False, password=None)`: Export to JSON
- `import_from_json(path, override=False, encrypted=False, password=None)`: Import from JSON
- `check_environment_compliance(environment_type)`: Check environment compliance
- `auto_detect_environment()`: Auto-detect the current environment
- `apply_defaults(defaults)`: Apply default values for missing keys
- `watch_for_changes(callback, interval=5)`: Watch for changes in loaded files
- `require(*keys)`: Check if all required keys are present
- `get_or_create(key, default_generator=None)`: Get a value or create if it doesn't exist
- `generate_documentation(output_path=None, format='markdown', include_sensitive=False)`: Generate documentation

### Utility Functions

#### Encryption and Security

- `generate_secure_key(length=32)`: Generate a cryptographically secure random key
- `encrypt_value(value, password)`: Encrypt a value using Fernet symmetric encryption
- `decrypt_value(encrypted_value, password)`: Decrypt a value
- `encrypt_with_quantum_resistant_hybrid(message, password)`: Encrypt with quantum-resistant hybrid approach
- `decrypt_with_quantum_resistant_hybrid(encrypted_value, password)`: Decrypt quantum-resistant hybrid encryption
- `vault_encrypt(value, master_key, key_id=None)`: Encrypt a value using vault-style approach
- `vault_decrypt(encrypted_data, master_key)`: Decrypt a vault-encrypted value
- `generate_rsa_keypair()`: Generate an RSA key pair
- `encrypt_with_public_key(public_key_pem, message)`: Encrypt with RSA public key
- `decrypt_with_private_key(private_key_pem, encrypted_message)`: Decrypt with RSA private key
- `secure_compare(val1, val2)`: Compare two strings in constant time to prevent timing attacks
- `generate_environment_integrity_signature(env_values, secret_key)`: Generate an integrity signature
- `verify_environment_integrity(env_values, signature, secret_key)`: Verify integrity signature

#### Value Processing

- `cast_value(value)`: Cast a string value to an appropriate Python type
- `sanitize_value(value)`: Sanitize a value to prevent security issues
- `derive_key(password, salt=None)`: Derive a cryptographic key from a password
- `hash_sensitive_value(value, salt=None)`: Hash a sensitive value with salt
- `escape_path_traversal(value)`: Escape path traversal attempts
- `format_secure_representation(value, is_sensitive=True)`: Format a value for secure representation

#### Authentication and MFA

- `generate_mfa_secret(length=32)`: Generate a secure MFA secret
- `verify_totp_code(secret, code, time_step=30, window=1, hash_algorithm='sha256')`: Verify a TOTP code
- `generate_recovery_codes(count=10, length=16)`: Generate recovery codes
- `generate_zero_knowledge_proof(secret, challenge)`: Generate a zero-knowledge proof
- `verify_zero_knowledge_proof(proof, secret, max_age_seconds=300)`: Verify a zero-knowledge proof

#### Security Analysis

- `detect_secrets_in_content(content)`: Detect potential secrets in content
- `check_security_vulnerabilities(env_values)`: Check for security vulnerabilities
- `assess_password_strength(password)`: Assess password strength
- `_calculate_entropy(value)`: Calculate the entropy of a string

#### File Operations

- `auto_backup_env_file(path, backup_dir=".env_backups", max_backups=10)`: Automatically create backups

### Custom Exceptions

- `DotEnvError`: Base exception for all Envella errors
- `FileNotFoundError`: Raised when a .env file is not found
- `ParseError`: Raised when a .env file cannot be parsed
- `SecurityError`: Raised when a security issue is detected

---

This guide covers the comprehensive functionality of Envella. For specific use cases or advanced configurations, refer to the examples or the source code documentation.

For more information, visit the [Envella GitHub repository](https://github.com/mohammadamin382/Envella_library) or submit issues for support.
