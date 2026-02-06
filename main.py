from fastapi import FastAPI, HTTPException, BackgroundTasks, Query, Path
from pydantic import BaseModel, Field, HttpUrl
from typing import Optional
import logging
import asyncio

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

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="MCP Vulnerability Scanner API")

# Models for Request Validation
class MasscanRequest(BaseModel):
    target: str = Field(..., description="Target IP or range", pattern=r"^[0-9./a-zA-Z_-]+$")
    ports: str = Field("0-65535", description="Ports to scan", pattern=r"^[0-9,-]+$")
    rate: int = Field(1000, ge=1, le=100000, description="Rate of scan")

class CVSSRequest(BaseModel):
    vector: str = Field(..., description="CVSS vector string", pattern=r"^CVSS:[23].*")

class OpenVASRequest(BaseModel):
    target: str = Field(..., description="Target IP or hostname", pattern=r"^[0-9./a-zA-Z_-]+$")

class ZAPRequest(BaseModel):
    target: HttpUrl = Field(..., description="Target URL for ZAP scan")

class BanditRequest(BaseModel):
    path: str = Field(..., description="Local path to scan", pattern=r"^[0-9./a-zA-Z_-]+$")

class DefectDojoRequest(BaseModel):
    scan_file_path: str = Field(..., description="Path to scan result file", pattern=r"^[0-9./a-zA-Z_-]+$")
    product_name: str = Field(..., description="Product name in DefectDojo", pattern=r"^[0-9./a-zA-Z _-]+$")
    engagement_name: str = Field(..., description="Engagement name in DefectDojo", pattern=r"^[0-9./a-zA-Z _-]+$")
    scan_type: str = Field(..., description="Type of scan result", pattern=r"^[a-zA-Z0-9 _-]+$")

class NiktoRequest(BaseModel):
    target: str = Field(..., description="Target host or URL", pattern=r"^[0-9./a-zA-Z_:-]+$")

@app.get("/")
async def root():
    return {"message": "MCP Vulnerability Scanner is running"}

@app.post("/scan/masscan")
async def run_masscan(request: MasscanRequest):
    """
    Run a masscan on the specified target.
    """
    return await asyncio.to_thread(masscan_scanner.scan_target, request.target, request.ports, request.rate)

@app.post("/score/cvss")
async def get_cvss_score(request: CVSSRequest):
    """
    Calculate CVSS scores for a given vector.
    """
    return await asyncio.to_thread(cvss_scorer.get_cvss_scores, request.vector)

@app.get("/cve/{cve_id}")
async def get_cve(
    cve_id: str = Path(..., pattern=r"^CVE-\d{4}-\d{4,}$")
):
    """
    Fetch details for a given CVE ID from the NIST NVD.
    """
    return await nist_cve.get_cve_details(cve_id)

@app.get("/cve/search/{keyword}")
async def search_cve(keyword: str = Path(..., min_length=2, pattern=r"^[a-zA-Z0-9_-]+$")):
    """
    Searches for CVEs on cve.mitre.org based on a keyword.
    """
    return await cve_web_scraper.search_cve_mitre(keyword)

@app.post("/scan/openvas")
async def run_openvas(request: OpenVASRequest):
    """
    Run an OpenVAS scan on the specified target.
    """
    return await asyncio.to_thread(openvas_scanner.run_openvas_scan, request.target)

@app.post("/scan/zap")
async def run_zap_scan(request: ZAPRequest):
    """
    Run an OWASP ZAP active scan on the specified target URL.
    """
    return await asyncio.to_thread(zap_scanner.run_zap_active_scan, str(request.target))

@app.post("/scan/bandit")
async def run_bandit(request: BanditRequest):
    """
    Run a Bandit scan on the specified file or directory.
    """
    return await asyncio.to_thread(bandit_scanner.run_bandit_scan, request.path)

@app.get("/scan/wazuh/{agent_id}")
async def get_wazuh_vulnerabilities(agent_id: str = Path(..., pattern=r"^[0-9]+$")):
    """
    Retrieve vulnerability information for a given Wazuh agent ID.
    """
    return await wazuh_scanner.get_agent_vulnerabilities(agent_id)

@app.post("/report/defectdojo")
async def upload_defectdojo_report(request: DefectDojoRequest):
    """
    Uploads a scan result to DefectDojo.
    """
    return await asyncio.to_thread(
        defectdojo_reporter.upload_scan_result,
        request.scan_file_path,
        request.product_name,
        request.engagement_name,
        request.scan_type
    )

@app.post("/scan/nikto")
async def run_nikto(request: NiktoRequest):
    """
    Run a Nikto scan on the specified target URL.
    """
    return await asyncio.to_thread(nikto_scanner.run_nikto_scan, request.target)

@app.get("/search/resolution/{query}")
async def search_resolution(query: str = Path(..., pattern=r"^[a-zA-Z0-9 ._-]+$")):
    """
    Searches for resolutions to vulnerabilities based on a query (CVE ID or description).
    """
    return await resolution_scraper.search_vulnerability_resolution(query)
