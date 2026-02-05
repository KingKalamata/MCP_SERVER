import subprocess
import json
import os

def run_nikto_scan(target_url, output_format='json'):
    """
    Runs a Nikto scan on the specified target URL.

    Args:
        target_url (str): The URL to scan.
        output_format (str): The desired output format ('json' or 'txt').

    Returns:
        dict or str: A dictionary containing the scan results if 'json' format,
                     or a string for 'txt' format, or an error message.
    """
    # Nikto does not natively support JSON output. We will run it to an XML file
    # and then convert the XML to JSON if requested.
    # Alternatively, we can use the HTML output and parse it, but XML is usually more structured.
    
    # Nikto's -Format (or -F) option is for output formats like HTML, CSV, XML, NBE (Nessus).
    # There is no direct JSON output.
    # For simplicity, we will capture the standard output, which is human-readable,
    # or direct to XML and then process it. Let's aim for XML output to a temp file
    # and then parse that into JSON.

    temp_output_file = f"nikto_scan_result_{os.urandom(8).hex()}.xml"
    
    try:
        # Command to run Nikto and output to XML
        command = ['nikto', '-h', target_url, '-o', temp_output_file, '-Format', 'xml']
        
        # Run Nikto. It might take some time.
        print(f"Starting Nikto scan on {target_url}...")
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print("Nikto scan finished.")

        if output_format == 'json':
            # Parse the XML output and convert to a dictionary (then JSON)
            # This requires an XML parsing library, e.g., xmltodict or manually parsing with ElementTree
            # For brevity, I'll return the XML content and suggest parsing it externally or
            # add a basic XML to dict conversion here.
            # Given the prompt, let's assume a simple parsing for now to demonstrate.
            
            # This is a very basic XML to dict conversion and might not handle all Nikto XML nuances
            import xml.etree.ElementTree as ET
            tree = ET.parse(temp_output_file)
            root = tree.getroot()
            
            findings = []
            for item in root.findall('.//item'):
                finding = {child.tag: child.text for child in item}
                findings.append(finding)
            
            return {"target": target_url, "findings": findings}
        else: # default to text output for simplicity if JSON parsing is complex
            with open(temp_output_file, 'r') as f:
                xml_content = f.read()
            return {"target": target_url, "raw_xml_output": xml_content}
            
    except subprocess.CalledProcessError as e:
        return {"error": f"Nikto scan failed with error: {e.stderr}"}
    except FileNotFoundError:
        return {"error": "Nikto command not found. Please ensure Nikto is installed and in your PATH."}
    except Exception as e:
        return {"error": f"An unexpected error occurred: {e}"}
    finally:
        # Clean up the temporary output file
        if os.path.exists(temp_output_file):
            os.remove(temp_output_file)

if __name__ == '__main__':
    # Example usage:
    # target = "http://testphp.vulnweb.com"  # Replace with a target you are authorized to scan
    # results = run_nikto_scan(target, output_format='json')
    # import json
    # print(json.dumps(results, indent=4))
    pass
