import os
import logging

logger = logging.getLogger(__name__)

def get_env(key, default=None, required=False):
    value = os.environ.get(key, default)
    if required and not value:
        logger.error(f"Environment variable {key} is required but not set.")
    return value

# NIST NVD API Key
NIST_API_KEY = get_env("NIST_API_KEY")

# CVSS API Key
CVSS_API_KEY = get_env("CVSS_API_KEY")

# DefectDojo configuration
DEFECTDOJO_URL = get_env("DEFECTDOJO_URL", "http://localhost:8080")
DEFECTDOJO_API_KEY = get_env("DEFECTDOJO_API_KEY")

# GVM configuration
GVM_HOST = get_env("GVM_HOST", "127.0.0.1")
GVM_PORT = int(get_env("GVM_PORT", 9390))
GVM_USER = get_env("GVM_USER", "admin")
GVM_PASSWORD = get_env("GVM_PASSWORD")

# OWASP ZAP configuration
ZAP_API_KEY = get_env("ZAP_API_KEY")
ZAP_ADDR = get_env("ZAP_ADDR", "http://localhost")
ZAP_PORT = int(get_env("ZAP_PORT", 8080))

# Wazuh API configuration
WAZUH_API_URL = get_env("WAZUH_API_URL", "https://localhost:55000")
WAZUH_API_USER = get_env("WAZUH_API_USER", "wazuh")
WAZUH_API_PASSWORD = get_env("WAZUH_API_PASSWORD")
