
<p align="center">
  <img src="https://raw.githubusercontent.com/mohammadamin382/Senv_library/main/assets/senv_logo.png" alt="Senv Logo" width="200"/>
</p>

<h1 align="center">Senv</h1>

<p align="center">
  <strong>A comprehensive, secure, and highly advanced environment variable management library for Python</strong>
</p>

<p align="center">
  <a href="https://github.com/mohammadamin382/Senv_library/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-GPL--3.0-blue.svg" alt="License: GPL-3.0"></a>
  <a href="https://pypi.org/project/Senv/"><img src="https://img.shields.io/pypi/v/Senv.svg" alt="PyPI Version"></a>
  <a href="https://pypi.org/project/Senv/"><img src="https://img.shields.io/pypi/pyversions/Senv.svg" alt="Python Versions"></a>
  <a href="https://pypi.org/project/Senv/"><img src="https://img.shields.io/pypi/dm/Senv.svg" alt="PyPI Downloads"></a>
</p>

<p align="center">
  <a href="#key-features">Key Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#advanced-usage">Advanced Usage</a> •
  <a href="#security-features">Security Features</a> •
  <a href="#api-reference">API Reference</a> •
  <a href="#contributing">Contributing</a> •
  <a href="#license">License</a>
</p>

---

## 🌟 Key Features

- **Enhanced Security**: Robust encryption for sensitive values, protection against timing attacks, and more
- **Multi-Environment Support**: Easily manage configurations across development, testing, staging, and production
- **Rich Validation**: Advanced schema validation for type checking and value constraints
- **Advanced Encryption**: Support for quantum-resistant hybrid encryption
- **Extensive Utilities**: Comprehensive set of utility functions for security auditing and key management
- **Intuitive API**: Simple yet powerful interface for managing environment variables
- **Comprehensive Documentation**: Generate documentation in various formats (Markdown, HTML, JSON)
- **Intelligent Default Values**: Smart handling of missing values with sensible defaults
- **MFA Support**: Multi-factor authentication capabilities for enhanced security
- **Compliance Checking**: Verify environment variable compliance with best practices

<div align="center">
  <img src="https://raw.githubusercontent.com/mohammadamin382/Senv_library/main/assets/senv_flow.png" alt="Senv Flow Diagram" width="700"/>
</div>

## 📦 Installation

### Using pip

```bash
pip install Senv
```

### Advanced installation with optional dependencies

```bash
# Install with advanced security features
pip install Senv[advanced]

# Install with development tools
pip install Senv[dev]

# Install with testing tools
pip install Senv[test]
```

## 🚀 Quick Start

```python
from Senv import Senv

# Create a new Senv instance
env = Senv()

# Load environment variables from .env file
env.import_env(".env")

# Access values with optional type casting
debug_mode = env.get("DEBUG", cast_type=bool)
port = env.get("PORT", default=3000, cast_type=int)
api_url = env.get("API_URL")

# Use the values in your application
if debug_mode:
    print(f"Server running in debug mode on port {port}")
    print(f"API URL: {api_url}")
```

### Sample .env file

```
# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=myapp
DB_USER=app_user
DB_PASSWORD=secure_password

# Application Settings
DEBUG=true
LOG_LEVEL=info
PORT=8000
API_URL=https://api.example.com
```

## 🔍 Advanced Usage

### Encryption for Sensitive Values

```python
from Senv import Senv, generate_secure_key

# Generate a secure encryption key
encryption_key = generate_secure_key()

# Create a Senv instance with encryption support
env = Senv(encryption_key=encryption_key)

# Load environment variables
env.import_env(".env")

# Encrypt all sensitive values
env.encrypt_sensitive_values()

# Save the encrypted environment
env.save(".env.encrypted")

# Values like DB_PASSWORD will be stored as ENC:encrypted_data
```

### Multi-Environment Configuration

```python
from Senv import Senv

# Create environment-specific instances
dev_env = Senv(environment="development")
prod_env = Senv(environment="production")

# Load environment-specific configuration
dev_env.import_env(".env.development")
prod_env.import_env(".env.production")

# Use the appropriate environment based on deployment
current_env = prod_env if os.environ.get("ENVIRONMENT") == "production" else dev_env

# Access environment variables
debug = current_env.get("DEBUG", cast_type=bool)
```

### Schema Validation

```python
from Senv import Senv

env = Senv()
env.import_env(".env")

# Define a schema for validation
schema = {
    "PORT": {
        "type": int,
        "required": True,
        "min": 1024,
        "max": 65535,
        "description": "Port to run the server on"
    },
    "LOG_LEVEL": {
        "type": str,
        "enum": ["debug", "info", "warning", "error", "critical"],
        "description": "Logging level for the application"
    },
    "API_URL": {
        "type": str,
        "pattern": r"^https://.*",
        "required": True,
        "description": "API endpoint URL (must use HTTPS)"
    }
}

# Validate against the schema
valid, errors = env.validate_against_schema(schema)

if not valid:
    for error in errors:
        print(f"Validation error: {error['message']}")
```

<div align="center">
  <img src="https://raw.githubusercontent.com/mohammadamin382/Senv_library/main/assets/senv_security.png" alt="Senv Security Features" width="500"/>
</div>

## 🔒 Security Features

### Audit Environment Security

```python
from Senv import Senv

env = Senv()
env.import_env(".env.production")

# Perform a comprehensive security audit
audit = env.audit_security()

# Check audit results
if not audit["compliance"]["compliant"]:
    print("Security issues found:")
    for issue in audit["security_issues"]:
        print(f"- {issue['severity'].upper()}: {issue['recommendation']}")
```

### Quantum-Resistant Encryption

```python
from Senv.utils import encrypt_with_quantum_resistant_hybrid, decrypt_with_quantum_resistant_hybrid

# Encrypt sensitive configuration
config_data = json.dumps({"api_keys": {"service_a": "secret_key_123"}})
encrypted = encrypt_with_quantum_resistant_hybrid(config_data, "master-password")

# Later, decrypt the configuration
decrypted = decrypt_with_quantum_resistant_hybrid(encrypted, "master-password")
config = json.loads(decrypted)
```

### MFA Support

```python
from Senv import Senv
from Senv.utils import generate_mfa_secret, verify_totp_code

# Generate a secret for MFA
mfa_secret = generate_mfa_secret()
print(f"Secret: {mfa_secret}")

# Verify a TOTP code
code = "123456"  # Code from authenticator app
is_valid = verify_totp_code(code, mfa_secret)
```

## 📚 API Reference

### Main Class

| Method | Description |
|--------|-------------|
| `Senv(encryption_key=None, environment="development", user_config=None)` | Initialize a new Senv instance |
| `import_env(path=".env", override=False, export_globals=False, safe_mode=True)` | Import environment variables from a file |
| `get(key, default=None, cast_type=None)` | Get a value with optional default and type casting |
| `set(key, value, comment=None)` | Set a value for a key |
| `as_dict(cast_types=False)` | Return environment variables as a dictionary |
| `keys()` | Return list of all environment variable keys |
| `save(path=None, include_comments=True)` | Save environment variables to a file |

### Security Methods

| Method | Description |
|--------|-------------|
| `encrypt_sensitive_values()` | Encrypt all sensitive values |
| `decrypt_sensitive_values()` | Decrypt all encrypted sensitive values |
| `audit_security()` | Perform comprehensive security audit |
| `rotate_encryption_key(new_key, rotation_window=0)` | Rotate the encryption key |
| `enforce_security_policies(policies)` | Enforce security policies |

### Utility Functions

| Function | Description |
|----------|-------------|
| `generate_secure_key()` | Generate a secure encryption key |
| `encrypt_value(value, key)` | Encrypt a value using a key |
| `decrypt_value(encrypted, key)` | Decrypt a value using a key |
| `cast_value(value)` | Cast a string value to appropriate type |
| `generate_mfa_secret()` | Generate a secret for MFA |
| `verify_totp_code(code, secret)` | Verify a TOTP code |

## 🤝 Contributing

Contributions to Senv are welcome! Here's how you can contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please read [CONTRIBUTING.md](https://github.com/mohammadamin382/Senv_library/blob/main/CONTRIBUTING.md) for more details.

## 📝 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](https://github.com/mohammadamin382/Senv_library/blob/main/LICENSE) file for details.

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/mohammadamin382">Mohammad Hosseini</a>
</p>

<p align="center">
  <a href="https://github.com/mohammadamin382/Senv_library">GitHub</a> •
  <a href="https://pypi.org/project/Senv/">PyPI</a>
</p>
