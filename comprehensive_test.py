# comprehensive_test.py - File used for testing static analysis

# --- Placeholder definitions for modules ---
class Activity: pass
class BroadcastReceiver: pass
class prefs:
    @staticmethod
    def edit():
        return prefs()
    def putString(self, key, value):
        return self
    def apply(self):
        pass
MODE_WORLD_READABLE = 1


# --- Secrets Analysis Test Patterns ---
# HIGH Confidence API Key (Secrets and Crypto)
API_KEY = "pk_live_51M0KxJ7dE8g9v4Wp2hYt3Nf5G6jH8lI0oQ1rS3tU5vX7yZ9A" 
# HIGH Confidence AWS Key (Secrets and Crypto)
AWS_SECRET = "AKIAI44QH83M52OQ3GPL"
# Medium Confidence Credentials
DB_USER = "admin"
DB_PASS = "dev_password123"
ANDROID_PASS = "androidpasswordandroid"


# --- Component Analysis Test Patterns ---
# Component 1 (HIGH Risk - Explicitly Exported)
class SensitiveComponent(Activity):
    is_exported = True
    def handle_unauthenticated_request(self, params):
        pass

# Component 2 (MEDIUM Risk - Dangerous Permission)
class BootReceiver(BroadcastReceiver):
    permission = "android.permission.INTERACT_ACROSS_USERS"


# --- Cryptography Analysis Test Patterns ---
# Pattern 1: Weak hash algorithm (HIGH Risk)
def hash_data_insecurely(data):
    import hashlib
    return hashlib.md5(data).hexdigest()

# Pattern 2: Hardcoded key for AES (MEDIUM Risk)
class EncryptionModule:
    KEY = "THIS_IS_A_STATIC_AES_KEY_12345"
    SECRET = "ANOTHER_HARDCODED_SECRET_2025"
    def encrypt(self, data):
        pass


# --- Network Analysis Test Patterns ---
# Pattern 1: Insecure HTTP URL (HIGH Risk)
INSECURE_URL = "http://api.insecure.local/v1/auth" 

# Pattern 2: Hardcoded IP address (MEDIUM Risk)
STATIC_SERVER_IP = "10.0.0.50" 

# Pattern 3: Cleartext Traffic Flag (HIGH Risk)
ALLOW_CLEARTEXT_FLAG = "android:usesCleartextTraffic=\"true\"" 


# --- Storage Analysis Test Patterns ---
# Pattern 1: Saving sensitive data in SharedPreferences (HIGH Risk)
def save_auth_token(token):
    prefs.edit().putString("auth_token", token).apply()

# Pattern 2: Using World-Readable file permissions (MEDIUM Risk)
def create_insecure_file(filename):
    open(filename, "w", MODE_WORLD_READABLE)


# --- Deeplink Analysis Test Patterns ---
# Pattern 1: Unauthenticated Sensitive Deep Link (HIGH Risk)
class SensitiveDeeplinkActivity(Activity):
    INTENT_FILTER = {
        "scheme": "dlmap",
        "host": "password"
    }
    
# Pattern 2: Custom Insecure Scheme (MEDIUM Risk)
class CheckoutDeeplink(Activity):
    INTENT_FILTER = {
        "scheme": "custom_app_scheme",
        "host": "checkout"
    }

# Pattern 3: Secure App Link (INFO/Low Risk)
class SecureDeeplink(Activity):
    INTENT_FILTER = {
        "scheme": "https",
        "host": "secure.dlmap.com"
    }


# --- Integrity/Manifest Test Patterns ---
# Simulates old SDK versions (Integrity Check)
def set_sdk_versions():
    MIN_SDK_VERSION = 18    # Should trigger HIGH risk (below 23)
    TARGET_SDK_VERSION = 28 # Should trigger MEDIUM risk (below 31)
    pass

# Simulates dangerous manifest flag (Manifest Settings / Auto Vulnerability Detection)
DEBUG_FLAG = 'android:debuggable="true"' # Should trigger HIGH risk in manifest-settings


# --- Permissions Scan Test Patterns (DANGEROUS) ---
# Simulates requesting dangerous permissions (Permissions Scan)
DANGEROUS_PERMISSIONS = [
    "android.permission.READ_SMS",              # HIGH Risk
    "android.permission.ACCESS_FINE_LOCATION",  # MEDIUM Risk
    "android.permission.SYSTEM_ALERT_WINDOW"    # HIGH Risk
]


# A final placeholder for entropy check
def calculate_hash(data):
    return hash(data)

