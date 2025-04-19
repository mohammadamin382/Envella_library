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
Example script demonstrating Senv library functionality.

Author: Mohammad Hosseini
License: GPL-3.0
"""

from Senv import Senv
import os
import sys

def main():
    """Main function to demonstrate Senv functionality."""
    print("Senv Library Example")
    print("-------------------")
    
    # Create a test .env file if it doesn't exist
    if not os.path.exists(".env"):
        print("Creating test .env file...")
        with open(".env", "w") as f:
            f.write("""# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=testdb
DB_USER=admin
DB_PASSWORD=secret123

# Application Settings
DEBUG=true
LOG_LEVEL=info
MAX_CONNECTIONS=100
RATE_LIMIT=5.5
API_ENDPOINT=https://api.example.com
""")
    
    # Create a new Senv instance
    env = Senv()
    
    # Import environment variables from .env file
    print("Loading environment variables...")
    if env.import_env(".env"):
        print(f"Loaded {len(env.keys())} variables")
    else:
        print("Failed to load environment variables")
        sys.exit(1)
    
    # Display loaded variables
    print("\nLoaded Environment Variables:")
    print("-" * 30)
    for key in sorted(env.keys()):
        # Mask sensitive values
        if key in env._sensitive_keys:
            if env.get(key).startswith("ENC:"):
                display_value = "[ENCRYPTED]"
            else:
                display_value = "*" * len(env.get(key))
        else:
            display_value = env.get(key)
        print(f"{key}: {display_value}")
    
    # Use with automatic type casting
    print("\nWith Automatic Type Casting:")
    print("-" * 30)
    print(f"DEBUG (bool): {env.get('DEBUG', cast_type=bool)}")
    print(f"DB_PORT (int): {env.get('DB_PORT', cast_type=int)}")
    print(f"RATE_LIMIT (float): {env.get('RATE_LIMIT', cast_type=float)}")
    
    # Identify sensitive keys
    print("\nSensitive Keys:")
    print("-" * 30)
    print(', '.join(env._sensitive_keys))
    
    # Security scan
    print("\nSecurity Scan:")
    print("-" * 30)
    audit = env.audit_security()
    print(f"Environment: {audit['environment']}")
    print(f"Variables: {audit['total_variables']} total, {audit['sensitive_variables']} sensitive")
    
    if audit['security_issues']:
        print("\nSecurity Issues:")
        for issue in audit['security_issues']:
            print(f"- {issue['type']} ({issue['severity']}): {issue['recommendation']}")
    else:
        print("No security issues detected")
    
    print("\nTry the full demonstration by running: python test_demo.py")

if __name__ == "__main__":
    main()
