import os

# NIST NVD API Key
NIST_API_KEY = os.environ.get("NIST_API_KEY", "your_nist_api_key_here")

# CVSS API Key
CVSS_API_KEY = os.environ.get("CVSS_API_KEY", "your_cvss_api_key_here")

# DefectDojo configuration
DEFECTDOJO_URL = os.environ.get("DEFECTDOJO_URL", "http://localhost:8080")
DEFECTDOJO_API_KEY = os.environ.get("DEFECTDOJO_API_KEY", "your_defectdojo_api_key_here")

# GVM configuration
GVM_HOST = os.environ.get("GVM_HOST", "127.0.0.1")
GVM_PORT = int(os.environ.get("GVM_PORT", 9390))
GVM_USER = os.environ.get("GVM_USER", "admin")
GVM_PASSWORD = os.environ.get("GVM_PASSWORD", "admin")

# OWASP ZAP configuration
ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "your_zap_api_key_here")
ZAP_ADDR = os.environ.get("ZAP_ADDR", "http://localhost")
ZAP_PORT = int(os.environ.get("ZAP_PORT", 8080))

# Wazuh API configuration
WAZUH_API_URL = os.environ.get("WAZUH_API_URL", "https://localhost:55000")
WAZUH_API_USER = os.environ.get("WAZUH_API_USER", "wazuh")
WAZUH_API_PASSWORD = os.environ.get("WAZUH_API_PASSWORD", "wazuh")
