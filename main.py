from fastapi import FastAPI
from mcp_server.tools import masscan_scanner
from mcp_server.tools import cvss_scorer
from mcp_server.tools import nist_cve
from mcp_server.tools import cve_web_scraper
from mcp_server.tools import openvas_scanner
from mcp_server.tools import zap_scanner
from mcp_server.tools import bandit_scanner
from mcp_server.tools import wazuh_scanner
from mcp_server.tools import defectdojo_reporter
from mcp_server.tools import nikto_scanner
from mcp_server.tools import resolution_scraper

app = FastAPI()

@app.get("/")
async def root():
    return {"message": "MCP Vulnerability Scanner is running"}

@app.post("/scan/masscan")
async def run_masscan(target: str, ports: str = '0-65535', rate: int = 1000):
    """
    Run a masscan on the specified target.
    """
    return masscan_scanner.scan_target(target, ports, rate)

@app.post("/score/cvss")
async def get_cvss_score(vector: str):
    """
    Calculate CVSS scores for a given vector.
    """
    return cvss_scorer.get_cvss_scores(vector)

@app.get("/cve/{cve_id}")
async def get_cve(cve_id: str):
    """
    Fetch details for a given CVE ID from the NIST NVD.
    """
    return nist_cve.get_cve_details(cve_id)

@app.get("/cve/search/{keyword}")
async def search_cve(keyword: str):
    """
    Searches for CVEs on cve.mitre.org based on a keyword.
    """
    return cve_web_scraper.search_cve_mitre(keyword)

@app.post("/scan/openvas")
async def run_openvas(target: str):
    """
    Run an OpenVAS scan on the specified target.
    """
    return openvas_scanner.run_openvas_scan(target)

@app.post("/scan/zap")
async def run_zap_scan(target: str):
    """
    Run an OWASP ZAP active scan on the specified target URL.
    """
    return zap_scanner.run_zap_active_scan(target)

@app.post("/scan/bandit")
async def run_bandit(path: str):
    """
    Run a Bandit scan on the specified file or directory.
    """
    return bandit_scanner.run_bandit_scan(path)

@app.get("/scan/wazuh/{agent_id}")
async def get_wazuh_vulnerabilities(agent_id: str):
    """
    Retrieve vulnerability information for a given Wazuh agent ID.
    """
    return wazuh_scanner.get_agent_vulnerabilities(agent_id)

@app.post("/report/defectdojo")
async def upload_defectdojo_report(
    scan_file_path: str,
    product_name: str,
    engagement_name: str,
    scan_type: str
):
    """
    Uploads a scan result to DefectDojo.
    """
    return defectdojo_reporter.upload_scan_result(scan_file_path, product_name, engagement_name, scan_type)

@app.post("/scan/nikto")
async def run_nikto(target: str):
    """
    Run a Nikto scan on the specified target URL.
    """
    return nikto_scanner.run_nikto_scan(target)

@app.get("/search/resolution/{query}")
async def search_resolution(query: str):
    """
    Searches for resolutions to vulnerabilities based on a query (CVE ID or description).
    """
    return resolution_scraper.search_vulnerability_resolution(query)
