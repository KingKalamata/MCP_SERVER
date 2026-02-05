from defectdojo_api import DefectDojoAPI
from .. import config

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
        products = dd.list_products(name=product_name).get('results')
        if products:
            product_id = products[0]['id']
        elif auto_create_context:
            product = dd.create_product(product_name, description=f"Product for {product_name}")
            product_id = product['id']

        if not product_id:
            return {"error": f"Product '{product_name}' not found and auto_create_context is False."}

        engagement_id = None
        engagements = dd.list_engagements(product=product_id, name=engagement_name).get('results')
        if engagements:
            engagement_id = engagements[0]['id']
        elif auto_create_context:
            engagement = dd.create_engagement(
                name=engagement_name,
                product=product_id,
                lead=1,  # You might need to set a valid lead user ID
                status='In Progress',
                target_start='2024-01-01',  # Placeholder dates
                target_end='2024-12-31'
            )
            engagement_id = engagement['id']
        
        if not engagement_id:
            return {"error": f"Engagement '{engagement_name}' not found and auto_create_context is False."}

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
        return response
    except Exception as e:
        return {"error": f"An error occurred during DefectDojo upload: {e}"}

if __name__ == '__main__':
    # Example usage:
    # Requires a running DefectDojo instance and a valid API key.
    # Create a dummy scan file for testing
    # with open("dummy_bandit_scan.json", "w") as f:
    #     f.write('{"scan_type": "Bandit Scan", "findings": []}')

    # result = upload_scan_result(
    #     scan_file_path="dummy_bandit_scan.json",
    #     product_name="Test Product",
    #     engagement_name="Test Engagement",
    #     scan_type="Bandit Scan"
    # )
    # import json
    # print(json.dumps(result, indent=4))
    pass
