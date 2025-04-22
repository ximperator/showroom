import requests
import time

def get_cve_details(cve_id):
    """
    Fetch CVE details from NVD API (English only)
    """
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        if not data.get('vulnerabilities'):
            return None, None, None
        
        cve_data = data['vulnerabilities'][0]['cve']
        
        # Get English description
        description = next((desc['value'] for desc in cve_data['descriptions'] 
                          if desc['lang'] == 'en'), None)
        
        # Get severity (CVSS v3 or v2)
        severity = "N/A"
        if 'metrics' in cve_data:
            for cvss_version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if cvss_version in cve_data['metrics']:
                    severity = cve_data['metrics'][cvss_version][0]['cvssData']['baseSeverity']
                    break
        
        return severity, description, cve_data.get('published', 'N/A')
    
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {cve_id}: {e}")
        return None, None, None

def process_cve_file(input_file, output_file):
    """
    Process CVE list from file and write results to output file
    """
    try:
        with open(input_file, 'r') as f:
            cve_list = [line.strip().upper() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found!")
        return
    
    if not cve_list:
        print("No CVEs found in input file!")
        return
    
    processed = 0
    with open(output_file, 'w', encoding='utf-8') as out_f:
        out_f.write("CVE Analysis Report\n")
        out_f.write("="*50 + "\n\n")
        
        for cve in cve_list:
            if processed > 0:  # Rate limiting
                time.sleep(6)
            
            severity, description, published = get_cve_details(cve)
            
            out_f.write(f"CVE-ID: {cve}\n")
            out_f.write(f"Published: {published}\n")
            out_f.write(f"Severity: {severity}\n")
            
            if description:
                out_f.write("\nDescription:\n")
                out_f.write(f"{description}\n")
            else:
                out_f.write("\nNo description available.\n")
            
            out_f.write("\n" + "="*50 + "\n\n")
            processed += 1
            print(f"Processed: {cve} ({processed}/{len(cve_list)})")
    
    print(f"\nDone! Results saved to '{output_file}'")

if __name__ == "__main__":
    print("CVE Severity Checker (File-based)")
    input_file = input("Path to input file with CVEs (one per line): ").strip()
    output_file = input("Path to output file [cve_results.txt]: ").strip() or "cve_results.txt"
    
    process_cve_file(input_file, output_file)
