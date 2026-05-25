# rules.py - Production-grade security rules database for Android/Mobile SAST
# Each rule contains a unique ID, risk level, title, description, pattern (regex or match),
# OWASP MASVS category, and CWE mapping.

RULES = {
    "manifest": [
        {
            "id": "M_DEBUGGABLE",
            "risk": "HIGH",
            "title": "Application is Debuggable",
            "pattern": r'android:debuggable\s*=\s*"true"',
            "desc": "The debuggable flag is enabled in the manifest. This allows attackers to attach a debugger, run arbitrary code under the app's context, and extract sensitive data.",
            "masvs": "MASVS-PLATFORM-1",
            "cwe": "CWE-489",
            "remediation": "Set android:debuggable=\"false\" in your AndroidManifest.xml before building the production release."
        },
        {
            "id": "M_BACKUP",
            "risk": "MEDIUM",
            "title": "Application Backup Enabled",
            "pattern": r'android:allowBackup\s*=\s*"true"',
            "desc": "Application data backup is enabled. Anyone with ADB access to the device can backup and extract private application data, even on non-rooted devices.",
            "masvs": "MASVS-STORAGE-1",
            "cwe": "CWE-921",
            "remediation": "Set android:allowBackup=\"false\" in your AndroidManifest.xml, or configure a secure BackupAgent."
        },
        {
            "id": "M_CLEARTEXT",
            "risk": "HIGH",
            "title": "Cleartext Network Traffic Allowed",
            "pattern": r'android:usesCleartextTraffic\s*=\s*"true"',
            "desc": "The application explicitly allows unencrypted HTTP traffic. This exposes user credentials and data to Man-In-The-Middle (MITM) sniffing and tampering.",
            "masvs": "MASVS-NETWORK-1",
            "cwe": "CWE-319",
            "remediation": "Remove android:usesCleartextTraffic or set it to \"false\". Enforce HTTPS globally."
        },
        {
            "id": "M_EXPORTED_COMP",
            "risk": "HIGH",
            "title": "Exported Component without Permissions",
            # We will use structural analysis in the analyzer to detect exported components without permissions,
            # but we also have a regex fallback.
            "pattern": r'<(activity|service|receiver|provider)[^>]*android:exported\s*=\s*"true"[^>]*>',
            "desc": "An Android component is publicly exported and visible to other apps on the device, but does not enforce any custom permissions, making it vulnerable to component hijacking or unauthorized intent invocation.",
            "masvs": "MASVS-PLATFORM-2",
            "cwe": "CWE-926",
            "remediation": "Ensure exported components are protected by custom permissions, or set android:exported=\"false\" if only internal invocation is intended."
        },
        {
            "id": "M_SCHEME_HIJACK",
            "risk": "HIGH",
            "title": "Insecure Deep Link Scheme",
            "pattern": r'<data[^>]*android:scheme\s*=\s*"http(?!s)"[^>]*>',
            "desc": "The app registers HTTP/non-SSL custom schemes for deep linking, which can be easily hijacked or intercepted by malicious apps on the same device.",
            "masvs": "MASVS-PLATFORM-3",
            "cwe": "CWE-939",
            "remediation": "Use App Links (HTTPS schemes with autoVerify=true) to prevent other apps from hijacking your deep links."
        },
        {
            "id": "M_TEST_ONLY",
            "risk": "MEDIUM",
            "title": "Test-Only Flag Enabled",
            "pattern": r'android:testOnly\s*=\s*"true"',
            "desc": "The application is marked as test-only, which may expose test endpoints, mock database configurations, or vulnerable backdoors.",
            "masvs": "MASVS-PLATFORM-1",
            "cwe": "CWE-489",
            "remediation": "Remove the android:testOnly flag before compiling the production build."
        },
        {
            "id": "M_SHARED_USER_ID",
            "risk": "HIGH",
            "title": "Deprecated sharedUserId Used",
            "pattern": r'android:sharedUserId\s*=\s*"[^"]+"',
            "desc": "Using sharedUserId is deprecated and dangerous. It allows multiple apps to run in the same process and share the same Linux UID, bypassing app sandboxing.",
            "masvs": "MASVS-PLATFORM-1",
            "cwe": "CWE-926",
            "remediation": "Remove android:sharedUserId and use standard Binder/ContentProvider mechanisms for secure IPC."
        }
    ],
    "code": [
        # --- Secrets & API Keys ---
        {
            "id": "C_AWS_KEY",
            "risk": "HIGH",
            "title": "Hardcoded AWS Access Key ID",
            "pattern": r'(?i)(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
            "desc": "A hardcoded AWS Access Key ID was detected in the code. Attackers can extract this key to compromise cloud infrastructure resources.",
            "masvs": "MASVS-STORAGE-2",
            "cwe": "CWE-798",
            "remediation": "Remove secrets from source code. Use AWS Secrets Manager or secure backend APIs to manage credentials dynamically."
        },
        {
            "id": "C_SLACK_TOKEN",
            "risk": "HIGH",
            "title": "Hardcoded Slack API Token",
            "pattern": r'xox[bapr]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24}',
            "desc": "A hardcoded Slack API/bot token was discovered. If leaked, attackers can read chats, hijack bots, or exfiltrate enterprise files.",
            "masvs": "MASVS-STORAGE-2",
            "cwe": "CWE-798",
            "remediation": "Immediately revoke the token and manage API communications on a secure server-side environment."
        },
        {
            "id": "C_GOOGLE_API",
            "risk": "HIGH",
            "title": "Hardcoded Google API/Firebase Key",
            "pattern": r'AIza[Sy][a-zA-Z0-9-_]{35}',
            "desc": "A Google API or Firebase API Key was found. While some keys are client-facing, leaking highly privileged keys can lead to service abuse and billing spikes.",
            "masvs": "MASVS-STORAGE-2",
            "cwe": "CWE-798",
            "remediation": "Restrict the API key to specific bundle IDs in the Google Cloud Console, and ensure it does not have administrative permissions."
        },
        {
            "id": "C_JWT_TOKEN",
            "risk": "MEDIUM",
            "title": "Potential Hardcoded JSON Web Token (JWT)",
            "pattern": r'ey[a-zA-Z0-9-_]{10,}\.ey[a-zA-Z0-9-_]{10,}\.[a-zA-Z0-9-_]{10,}',
            "desc": "A potential hardcoded JWT token was detected in the source code, which could grant unauthorized access to API endpoints.",
            "masvs": "MASVS-STORAGE-2",
            "cwe": "CWE-798",
            "remediation": "Avoid storing user session tokens or authorization tokens in static source code variables."
        },
        {
            "id": "C_GENERIC_SECRET",
            "risk": "MEDIUM",
            "title": "Generic Hardcoded Secret/Credential",
            "pattern": r'(?i)(password|secret|private_key|api_secret|client_secret|db_pass)\s*=\s*["\'][a-zA-Z0-9_!@#$%^&*()\-+=]{8,}["\']',
            "desc": "A hardcoded password, secret, or private key assignment was detected in the code.",
            "masvs": "MASVS-STORAGE-2",
            "cwe": "CWE-798",
            "remediation": "Do not store secrets in plaintext. Use secure storage components like the Android Keystore System."
        },
        
        # --- Cryptography ---
        {
            "id": "C_MD5_HASH",
            "risk": "MEDIUM",
            "title": "Weak Cryptographic Hash (MD5)",
            "pattern": r'(?i)(MessageDigest\.getInstance\(\s*["\']MD5["\']|hashlib\.md5)',
            "desc": "MD5 is a cryptographically broken hash function vulnerable to collision attacks. It should not be used for integrity checks or sensitive data hashing.",
            "masvs": "MASVS-CRYPTO-1",
            "cwe": "CWE-327",
            "remediation": "Upgrade to secure hashing algorithms such as SHA-256, SHA-512, or Argon2."
        },
        {
            "id": "C_SHA1_HASH",
            "risk": "MEDIUM",
            "title": "Weak Cryptographic Hash (SHA-1)",
            "pattern": r'(?i)(MessageDigest\.getInstance\(\s*["\']SHA-1["\']|hashlib\.sha1)',
            "desc": "SHA-1 is a weak cryptographic hashing function with proven collision vulnerabilities. It is no longer secure against well-funded attackers.",
            "masvs": "MASVS-CRYPTO-1",
            "cwe": "CWE-327",
            "remediation": "Use SHA-256 or SHA-512 instead."
        },
        {
            "id": "C_AES_ECB",
            "risk": "HIGH",
            "title": "Insecure AES Cipher Mode (ECB)",
            "pattern": r'(?i)(AES/ECB/PKCS5Padding|AES/ECB/NoPadding)',
            "desc": "Electronic Codebook (ECB) mode encrypts identical plaintext blocks into identical ciphertext blocks, leaking structural patterns of the encrypted data.",
            "masvs": "MASVS-CRYPTO-1",
            "cwe": "CWE-327",
            "remediation": "Use safer modes such as AES/GCM/NoPadding or AES/CBC/PKCS5Padding with a cryptographically secure, random Initialization Vector (IV)."
        },
        {
            "id": "C_WEAK_PRNG",
            "risk": "MEDIUM",
            "title": "Weak Pseudo-Random Number Generator (PRNG)",
            "pattern": r'(?i)(\bjava\.util\.Random\b|\bMath\.random\(\))',
            "desc": "Standard pseudo-random number generators are predictable and should not be used to generate cryptographic keys, salts, or session tokens.",
            "masvs": "MASVS-CRYPTO-1",
            "cwe": "CWE-338",
            "remediation": "Use SecureRandom (Java/Kotlin) or secrets module (Python) for cryptographically secure random values."
        },

        # --- Insecure Storage ---
        {
            "id": "C_WORLD_READ_WRITE",
            "risk": "HIGH",
            "title": "Insecure World-Readable/Writable Storage Flags",
            "pattern": r'(?i)(MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE)',
            "desc": "Creating files with World-Readable or World-Writable flags allows other malicious applications installed on the same device to read or overwrite sensitive application data.",
            "masvs": "MASVS-STORAGE-1",
            "cwe": "CWE-276",
            "remediation": "Use Context.MODE_PRIVATE for local file storage, preventing unauthorized application access."
        },
        {
            "id": "C_EXTERNAL_STORAGE",
            "risk": "MEDIUM",
            "title": "Potential Insecure External Storage Write",
            "pattern": r'(?i)(getExternalStorageDirectory|getExternalFilesDir|getExternalCacheDir)',
            "desc": "Writing sensitive information to external storage (SD card) makes it globally readable and writable by any app with STORAGE permissions, exposing data to theft or tampering.",
            "masvs": "MASVS-STORAGE-1",
            "cwe": "CWE-377",
            "remediation": "Store sensitive data exclusively in internal storage (`getFilesDir()`) or use EncryptedFile and EncryptedSharedPreferences."
        },
        
        # --- Network Security Bypass ---
        {
            "id": "C_TRUST_ALL_CERTS",
            "risk": "HIGH",
            "title": "SSL TrustManager Bypasses Certificate Verification",
            "pattern": r'(?i)(checkClientTrusted|checkServerTrusted)[^}]*\{\s*\}', # empty body
            "desc": "The application contains an empty implementation of trust managers. This explicitly accepts any SSL/TLS certificate, rendering the application fully vulnerable to Man-in-the-Middle (MITM) attacks.",
            "masvs": "MASVS-NETWORK-1",
            "cwe": "CWE-295",
            "remediation": "Implement proper trust validation using Android's Network Security Config or standard trusted Certificate Authorities."
        },
        {
            "id": "C_ALLOW_ALL_HOSTNAME",
            "risk": "HIGH",
            "title": "HostnameVerifier Bypassed (Allow All Hostnames)",
            "pattern": r'(?i)(ALLOW_ALL_HOSTNAME_VERIFIER|NullHostnameVerifier|verify\s*\(.*,\s*.*\)\s*\{\s*return\s*true)',
            "desc": "The app disables hostname verification. This allows an attacker to intercept HTTPS requests with an SSL certificate issued for a different domain.",
            "masvs": "MASVS-NETWORK-1",
            "cwe": "CWE-295",
            "remediation": "Remove custom HostnameVerifiers that unconditionally return true. Rely on the platform's default secure HTTPS validation."
        },
        {
            "id": "C_INSECURE_HTTP_URL",
            "risk": "MEDIUM",
            "title": "Hardcoded Insecure HTTP Endpoint",
            "pattern": r'http://(?!schemas\.android\.com/)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/[a-zA-Z0-9-._~:/?#\[\]@!$&\'()*+,;=]*)?',
            "desc": "The app contains hardcoded HTTP endpoints. Communication over HTTP is plaintext and vulnerable to interception.",
            "masvs": "MASVS-NETWORK-1",
            "cwe": "CWE-319",
            "remediation": "Migrate all HTTP endpoints to HTTPS."
        },
        
        # --- Code Execution & Injection ---
        {
            "id": "C_SQL_INJECTION",
            "risk": "HIGH",
            "title": "Potential SQLite SQL Injection",
            "pattern": r'(?i)(rawQuery\s*\(\s*["\'][^"\']*(\+|%s)[^"\']*["\']|\bexecSQL\s*\(\s*["\'][^"\']*(\+|%s))',
            "desc": "The app performs dynamic raw SQL query concatenation, making it vulnerable to local SQL injection attacks which can leak or corrupt offline app databases.",
            "masvs": "MASVS-PLATFORM-2",
            "cwe": "CWE-89",
            "remediation": "Use parameterized queries with selection arguments (`selectionArgs`) or modern ORMs like Room."
        },
        {
            "id": "C_DYN_CLASS_LOAD",
            "risk": "MEDIUM",
            "title": "Dynamic Class/Code Loading",
            "pattern": r'(?i)(DexClassLoader|PathClassLoader)',
            "desc": "The app dynamically loads executable code (DEX/JAR) at runtime. If an attacker can write to the loading path (e.g., in external storage), they can inject malicious code into the app's execution context.",
            "masvs": "MASVS-PLATFORM-1",
            "cwe": "CWE-94",
            "remediation": "Ensure dynamic code files are loaded only from highly secure internal storage paths and verified using cryptographic signatures."
        }
    ]
}

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": "Allows the app to read SMS messages, which could expose 2FA login codes.",
    "android.permission.RECEIVE_SMS": "Allows the app to intercept incoming SMS, posing a serious threat to OTP/2FA verification.",
    "android.permission.SEND_SMS": "Allows the app to send unauthorized premium rate SMS messages.",
    "android.permission.READ_CONTACTS": "Exposes the user's complete address book to the application.",
    "android.permission.ACCESS_FINE_LOCATION": "Exposes precise GPS coordinates of the user.",
    "android.permission.ACCESS_COARSE_LOCATION": "Exposes approximate location data based on network towers.",
    "android.permission.RECORD_AUDIO": "Allows the app to record environmental audio from the microphone at any time.",
    "android.permission.CAMERA": "Allows the app to take photos and record videos, risking privacy exposure.",
    "android.permission.READ_EXTERNAL_STORAGE": "Allows reading files on shared device storage (SD card).",
    "android.permission.WRITE_EXTERNAL_STORAGE": "Allows writing/modifying files on shared storage, risking data poisoning.",
    "android.permission.SYSTEM_ALERT_WINDOW": "Allows drawing overlays over other apps, commonly hijacked by malware for overlay/phishing attacks.",
    "android.permission.REQUEST_INSTALL_PACKAGES": "Allows the app to initiate installations of arbitrary APKs (dangerous sideloading)."
}
