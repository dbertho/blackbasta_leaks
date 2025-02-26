import os
import requests
import json
import re
import argparse
from ares import CVESearch

# Regex pattern to match CVE
CVE_REGEX = r'CVE-\d{4}-\d{4,7}'

# Function to load CISA KEV catalog and extract vendor, prodyct and date of addition
# Returns a dictionary of all vulnerabilities in the catalog
def fetch_kev_catalog():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    response = requests.get(url)
    
    if response.status_code == 200:
        data = response.json()
        # Create a dictionary mapping CVE IDs to their details
        cve_details = {}
        for vuln in data.get('vulnerabilities', []):
            cve_id = vuln.get('cveID')
            if cve_id:
                cve_details[cve_id] = {
                    'vendor': vuln.get('vendorProject', ''),
                    'product': vuln.get('product', ''),
                    'dateAdded': vuln.get('dateAdded', '')
                }
        return cve_details
    else:
        print(f"Error fetching KEV catalog: {response.status_code}")
        return {}

# Extract CVE in messages
def extract_cve(text):
    if not text:
        return set()
    return set(re.findall(CVE_REGEX, text))  # Use set to remove duplicates

# Convert timestamps into dates (YYYY-MM-DD)
def extract_date(timestamp):
    if isinstance(timestamp, str) and len(timestamp) >= 10:
        return timestamp[:10]
    return "Unknown Date"

# Processes "clean" JSON files (file ends with clean.json)
# Selection of clean files is due to original json file that was improperly formatted
def process_json_files(input_folder, output_file):
    results = []

    # Ensure the folder exists
    if not os.path.exists(input_folder):
        print(f"Error: Folder '{input_folder}' does not exist.")
        return

    # Iterate over JSON files in the folder
    for filename in os.listdir(input_folder):
        if filename.endswith("clean.json"):
            file_path = os.path.join(input_folder, filename)

            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                # Ensure data is a list of messages
                if isinstance(data, list):
                    cve_json = CVESearch()
                    for item in data:
                        if isinstance(item, dict):
                            message = item.get("message", "")
                            timestamp = item.get("timestamp", "")

                            # Extract CVE and date
                            cve_numbers = extract_cve(message)
                            date = extract_date(timestamp)

                            # Store results if any CVE is found
                            for cve_number in cve_numbers:
                                results.append((date, cve_number))

            except Exception as e:
                print(f"Error processing {file_path}: {e}")

    if results:
        # Sort by date for better readability
        results.sort(key=lambda x: x[0])  

        with open(output_file, "w", encoding="utf-8") as csv:
            csv.write("Date;CVE;Vendor;Product;DateAddedKEV\n")
            
            # Parses all Date/CVE lines to extract context about vulnerable product and exploitation status
            for date, cve in results:
                
                # Exploitation status imported from KEV list
                kev_info = kev_catalog.get(cve, {})
                # product information imported from circl.lu
                cve_dump = json.dumps(cve_json.id(cve))
                
                # Sometimes the vulnerability has been rejected (false positive) and will not contain vendor or product information
                if json.loads(cve_dump)["cveMetadata"]["state"] != "REJECTED":
                    vendor = json.loads(cve_dump)["containers"]["cna"]["affected"][0]["vendor"]
                    product = json.loads(cve_dump)["containers"]["cna"]["affected"][0]["product"]
                else:
                    vendor = "REJECTED"
                    product = "REJECTED"
                
                date_added = kev_info.get("dateAdded", "none")
                if vendor == "n/a" and date_added != "none" :
                    vendor = kev_info.get("vendor", "none")
                if product == "n/a" and date_added != "none" :
                    product = kev_info.get("product", "none")
                csv.write(f'{date};{cve};"{vendor}";"{product}";{date_added}\n')

        print(f"Extraction complete. Data saved to {output_file}")
    else:
        print("No CVE found in the dataset.")

if __name__ == "__main__":
    # Argument parsing
    parser = argparse.ArgumentParser(description="Extract CVE numbers from JSON files and save as CSV.")
    parser.add_argument("input_folder", type=str, help="Path to the folder containing JSON files")
    parser.add_argument("output_file", type=str, help="Path to the output CSV file")

    args = parser.parse_args()
    
    # Fetch the KEV catalog
    kev_catalog = fetch_kev_catalog()

    # Run processing
    process_json_files(args.input_folder, args.output_file)
