
"""
Comprehensive tests for SecureDotEnv.
"""
import os
import tempfile
import unittest
import shutil
from pathlib import Path

# Add parent directory to path
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from Senv import SecureDotEnv
from Senv.exceptions import SecurityError

class TestSecureDotEnv(unittest.TestCase):
    """Test suite for SecureDotEnv"""
    
    def setUp(self):
        """Create a temporary directory for test files"""
        self.test_dir = tempfile.mkdtemp()
        self.env_file = os.path.join(self.test_dir, '.env')
        
        # Create a sample .env file
        with open(self.env_file, 'w') as f:
            f.write("""# Test .env file
DB_HOST=localhost
DB_PORT=5432
DEBUG=true
MAX_CONNECTIONS=100
RATE_LIMIT=5.5
SECRET_KEY=super_secret # This is a sensitive value
EMPTY_VALUE=
""")
        
    def tearDown(self):
        """Clean up temporary directory"""
        shutil.rmtree(self.test_dir)
        
    def test_import_env(self):
        """Test basic env file import"""
        env = SecureDotEnv()
        result = env.import_env(self.env_file)
        
        self.assertTrue(result)
        self.assertEqual(len(env.keys()), 7)
        self.assertEqual(env.get("DB_HOST"), "localhost")
        
    def test_as_dict_with_casting(self):
        """Test as_dict with type casting"""
        env = SecureDotEnv()
        env.import_env(self.env_file)
        
        env_dict = env.as_dict(cast_types=True)
        self.assertEqual(env_dict["DB_PORT"], 5432)
        self.assertEqual(env_dict["DEBUG"], True)
        self.assertEqual(env_dict["RATE_LIMIT"], 5.5)
        
    def test_generate_template(self):
        """Test template generation"""
        env = SecureDotEnv()
        env.import_env(self.env_file)
        
        template_file = os.path.join(self.test_dir, '.env.template')
        result = env.generate_template(template_file)
        
        self.assertTrue(result)
        self.assertTrue(os.path.isfile(template_file))
        
        # Check template content
        with open(template_file, 'r') as f:
            content = f.read()
            self.assertIn("DB_HOST=", content)
            self.assertIn("SENSITIVE DATA", content.upper())
            
    def test_multiple_file_loading(self):
        """Test loading multiple .env files"""
        # Create a second .env file
        env_dev_file = os.path.join(self.test_dir, '.env.dev')
        with open(env_dev_file, 'w') as f:
            f.write("""
DEBUG=false
NEW_VAR=development
""")
        
        env = SecureDotEnv()
        loaded = env.load_multiple_env_files([self.env_file, env_dev_file], override=True)
        
        self.assertEqual(len(loaded), 2)
        self.assertEqual(env.get("DEBUG"), "false")  # Should be overridden
        self.assertEqual(env.get("NEW_VAR"), "development")  # Only in second file
        
    def test_directory_scanning(self):
        """Test scanning a directory for .env files"""
        env = SecureDotEnv()
        loaded = env.load_dotenv_from_directory(self.test_dir)
        
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0], self.env_file)
        
    def test_sensitive_values(self):
        """Test handling of sensitive values"""
        env = SecureDotEnv("test_encryption_key")
        env.import_env(self.env_file)
        
        # Ensure SECRET_KEY is detected as sensitive
        self.assertIn("SECRET_KEY", env._sensitive_keys)
        
        # Test encryption
        original_value = env.get("SECRET_KEY")
        env.encrypt_sensitive_values()
        encrypted_value = env.get("SECRET_KEY")
        
        self.assertNotEqual(original_value, encrypted_value)
        self.assertTrue(encrypted_value.startswith("ENC:"))
        
        # Test decryption
        env.decrypt_sensitive_values()
        decrypted_value = env.get("SECRET_KEY")
        self.assertEqual(original_value, decrypted_value)
        
    def test_validate_required_keys(self):
        """Test validation of required keys"""
        env = SecureDotEnv()
        env.import_env(self.env_file)
        
        valid, missing = env.validate_required_keys(["DB_HOST", "DB_PORT", "DEBUG"])
        self.assertTrue(valid)
        self.assertEqual(len(missing), 0)
        
        valid, missing = env.validate_required_keys(["DB_HOST", "MISSING_KEY"])
        self.assertFalse(valid)
        self.assertIn("MISSING_KEY", missing)
        
    def test_interpolation(self):
        """Test value interpolation"""
        # Create a file with references
        interp_file = os.path.join(self.test_dir, '.env.interp')
        with open(interp_file, 'w') as f:
            f.write("""
DB_HOST=localhost
DB_PORT=5432
DB_NAME=testdb
DB_URL=${DB_HOST}:${DB_PORT}/${DB_NAME}
NESTED=${DB_URL}/table
""")
        
        env = SecureDotEnv()
        env.import_env(interp_file)
        env.interpolate_values()
        
        self.assertEqual(env.get("DB_URL"), "localhost:5432/testdb")
        self.assertEqual(env.get("NESTED"), "localhost:5432/testdb/table")
        
    def test_security_scan(self):
        """Test security scanning for dangerous content"""
        # Create a file with command injection
        dangerous_file = os.path.join(self.test_dir, '.env.dangerous')
        with open(dangerous_file, 'w') as f:
            f.write("""
DB_HOST=localhost
DANGEROUS=`rm -rf /`
""")
        
        env = SecureDotEnv()
        
        # Should return False when detecting security issues
        result = env.import_env(dangerous_file)
        self.assertFalse(result)
            
    def test_checksum_generation(self):
        """Test environment checksum generation"""
        env1 = SecureDotEnv()
        env1.import_env(self.env_file)
        checksum1 = env1.generate_checksum()
        
        # Create a second instance with identical values
        env2 = SecureDotEnv()
        env2.import_env(self.env_file)
        checksum2 = env2.generate_checksum()
        
        # Checksums should match
        self.assertEqual(checksum1, checksum2)
        
        # Modify one value and checksum should differ
        env2.set("DB_HOST", "different-host")
        checksum3 = env2.generate_checksum()
        self.assertNotEqual(checksum1, checksum3)
        
    def test_merge(self):
        """Test merging two env instances"""
        # Create a second env file
        env2_file = os.path.join(self.test_dir, '.env2')
        with open(env2_file, 'w') as f:
            f.write("""
NEW_KEY=new_value
DB_HOST=different-host
""")
        
        env1 = SecureDotEnv()
        env1.import_env(self.env_file)
        
        env2 = SecureDotEnv()
        env2.import_env(env2_file)
        
        # Without override
        env1.merge(env2, override=False)
        self.assertEqual(env1.get("NEW_KEY"), "new_value")  # Should be added
        self.assertEqual(env1.get("DB_HOST"), "localhost")  # Should NOT be overridden
        
        # With override
        env1.merge(env2, override=True)
        self.assertEqual(env1.get("DB_HOST"), "different-host")  # Should be overridden


if __name__ == '__main__':
    unittest.main()
