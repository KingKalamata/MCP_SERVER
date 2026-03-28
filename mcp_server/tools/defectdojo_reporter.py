from defectdojo_api.defectdojo import DefectDojoAPI
import logging
from .. import config

logger = logging.getLogger(__name__)

def upload_scan_result(scan_file_path, product_name, engagement_name, scan_type, auto_create_context=True):
    """
    Uploads a scan result to DefectDojo.

    Args:
        scan_file_path (str): The path to the scan result file.
        product_name (str): The name of the DefectDojo product.
        engagement_name (str): The name of the DefectDojo engagement.
        scan_type (str): The type of scan (e.g., 'Bandit Scan', 'OWASP ZAP Scan').
        auto_create_context (bool): Whether to automatically create product/engagement if not found.

    Returns:
        dict: A dictionary containing the upload response, or an error message.
    """
    try:
        dd = DefectDojoAPI(
            config.DEFECTDOJO_URL,
            config.DEFECTDOJO_API_KEY,
            api_version="v2",
            verify_ssl=False  # Set to True in production with proper certs
        )

        # Ensure product and engagement exist
        product_id = None
        products_response = dd.list_products(name=product_name)
        products = products_response.data.get('results') if products_response.success else None

        if products:
            product_id = products[0]['id']
        elif auto_create_context:
            product_response = dd.create_product(product_name, description=f"Product for {product_name}", prod_type=1)
            if product_response.success:
                product_id = product_response.data['id']

        if not product_id:
            return {"error": f"Product '{product_name}' not found and could not be created."}

        engagement_id = None
        engagements_response = dd.list_engagements(product=product_id, name=engagement_name)
        engagements = engagements_response.data.get('results') if engagements_response.success else None

        if engagements:
            engagement_id = engagements[0]['id']
        elif auto_create_context:
            engagement_response = dd.create_engagement(
                name=engagement_name,
                product=product_id,
                lead=1,
                status='In Progress',
                target_start='2024-01-01',
                target_end='2024-12-31'
            )
            if engagement_response.success:
                engagement_id = engagement_response.data['id']
        
        if not engagement_id:
            return {"error": f"Engagement '{engagement_name}' not found and could not be created."}

        # Upload the scan report
        with open(scan_file_path, 'rb') as scan_file:
            response = dd.upload_scan(
                engagement=engagement_id,
                scan_type=scan_type,
                file=scan_file,
                active=True,
                verified=False,
                tags=['mcp-scanner']
            )
        return response.data if response.success else {"error": response.message}
    except Exception as e:
        logger.exception("An error occurred during DefectDojo upload")
        return {"error": f"An error occurred during DefectDojo upload: {e}"}
