from zapv2 import ZAPv2
import time
import logging
from .. import config

logger = logging.getLogger(__name__)

def run_zap_active_scan(target_url):
    """
    Runs an OWASP ZAP active scan on the specified target URL.

    Args:
        target_url (str): The URL to scan.

    Returns:
        list: A list of dictionaries, where each dictionary represents an alert.
    """
    try:
        zap = ZAPv2(proxies={
            'http': f'{config.ZAP_ADDR}:{config.ZAP_PORT}',
            'https': f'{config.ZAP_ADDR}:{config.ZAP_PORT}'
        }, apikey=config.ZAP_API_KEY)

        # Start an active scan
        logger.info(f"Starting ZAP active scan on {target_url}...")
        scan_id = zap.ascan.scan(target_url)

        # Wait for the scan to complete
        while int(zap.ascan.status(scan_id)) < 100:
            logger.info(f"ZAP Active Scan progress: {zap.ascan.status(scan_id)}%")
            time.sleep(5)
        logger.info("ZAP Active Scan complete.")

        # Retrieve alerts
        alerts = zap.core.alerts()
        
        # Format alerts into a more readable dictionary format
        formatted_alerts = []
        for alert in alerts:
            formatted_alerts.append({
                "alert": alert.get("alert"),
                "risk": alert.get("risk"),
                "confidence": alert.get("confidence"),
                "url": alert.get("url"),
                "description": alert.get("description"),
                "solution": alert.get("solution"),
                "reference": alert.get("reference")
            })
        return formatted_alerts
    except Exception as e:
        logger.exception("An error occurred during ZAP scan")
        return {"error": f"An error occurred during ZAP scan: {e}"}
