API_KEY = "e972cbe11c92813d82c3c9798c5f31d365c2280303112548187a8b3eaca19503"
#Import the hash library
import hashlib
import requests
import argparse
from tabulate import tabulate
from colorama import Fore, Style
import json


def print_vts():
    green = "\033[92m"
    reset = "\033[0m"
    vts = [
        "VVVVVVVV           VVVVVVVVTTTTTTTTTTTTTTTTTTTTTTT        SSSSSSSSSSSSSSS",
        "V::::::V           V::::::VT:::::::::::::::::::::T      SS:::::::::::::::S",
        "V::::::V           V::::::VT:::::::::::::::::::::T     S:::::SSSSSS::::::S",
        "V::::::V           V::::::VT:::::TT:::::::TT:::::T     S:::::S     SSSSSSS",
        " V:::::V           V:::::V TTTTTT  T:::::T  TTTTTT     S:::::S",
        "  V:::::V         V:::::V          T:::::T              S:::::S",
        "   V:::::V       V:::::V           T:::::T               S::::SSSS",
        "    V:::::V     V:::::V            T:::::T                SS::::::SSSSS",
        "     V:::::V   V:::::V             T:::::T                  SSS::::::::SS",
        "      V:::::V V:::::V              T:::::T                     SSSSSS::::S",
        "       V:::::V:::::V               T:::::T                          S:::::S",
        "        V:::::::::V                T:::::T                          S:::::S",
        "         V:::::::V                 T:::::T              SSSSSSS     S:::::S",
        "          V:::::V                  T:::::T              S::::::SSSSSS:::::S",
        "           V:::V                   T:::::T              S:::::::::::::::SS",
        "            VVV                    TTTTTT               SSSSSSSSSSSSSSS"
    ]
    for line in vts:
        print(f"{green}{line}{reset}")





def calculate_file_hash(file_path, algorithm='md5'):
    hash_function = hashlib.new(algorithm)
    with open(file_path, "rb") as f:
        #read the file in chunks of 8192 bytes
        while chunk:= f.read(8192):
            hash_function.update(chunk)
    return hash_function.hexdigest()

#Function to query VirusTotal
def query_virustotal_file(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey" : API_KEY
    }
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        return{"error": "Hash not found in VirusTotal database"}
    else:
        return{"error": f"Unexpected error occured: {response.status_code}"}
    
    
def query_virustotal_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        return {"error": "IP address not found in VirusTotal database."}
    else:
        return {"error": f"Unexpected error: {response.status_code}"}
    

def query_virustotal_url(url):
    # URL encoding for VirusTotal
    from urllib.parse import urlencode
    url_id = urlencode({"url": url})[4:]  # Extract encoded portion after 'url='
    
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": API_KEY}
    response = requests.get(api_url, headers=headers)

    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        return {"error": "URL not found in VirusTotal database."}
    else:
        return {"error": f"Unexpected error: {response.status_code}"}
    
def format_results(result, scan_type, input_value):
    if "error" in result:
        print(Fore.RED + f"Error: {result['error']}" + Style.RESET_ALL)
        return

    data = result.get('data', {})
    attributes = data.get('attributes', {})

    print(Fore.GREEN + f"Scan Results for: {input_value}" + Style.RESET_ALL)
    print("---------------------------------------")

    if scan_type == "file":
        print(f"First Submission Date: {attributes.get('first_submission_date', 'N/A')}")
        print(f"Last Analysis Date: {attributes.get('last_analysis_date', 'N/A')}")
    elif scan_type == "url":
        print(f"Category: {attributes.get('category', 'N/A')}")
        print(f"Last Analysis Date: {attributes.get('last_analysis_date', 'N/A')}")
    elif scan_type == "ip":
        print(f"Country: {attributes.get('country', 'N/A')}")
        print(f"ISP: {attributes.get('as_owner', 'N/A')}")

    stats = attributes.get('last_analysis_stats', {})
    table = [
        ["Harmless", stats.get('harmless', 'N/A')],
        ["Malicious", stats.get('malicious', 'N/A')],
        ["Suspicious", stats.get('suspicious', 'N/A')],
    ]
    print(tabulate(table, headers=["Category", "Count"], tablefmt="pretty"))

    print("---------------------------------------")
    print("Tags:", attributes.get('tags', 'N/A'))
    print("---------------------------------------")

    if "last_analysis_results" in attributes:
        print("Top Detectors:")
        for vendor, details in attributes['last_analysis_results'].items():
            print(f"- {vendor}: {details['result']}")
    
    
#main function
def main():
    print_vts()
    print("by Aderinola")
    parser = argparse.ArgumentParser(
        description="Scan files, URLs, and IP addresses using VirusTotal API."
    )
    parser.add_argument(
        "-t", "--type", choices=["file", "url", "ip"], required=True,
        help="Type of object to scan: file, url, or ip."
    )
    parser.add_argument(
        "-i", "--input", required=True,
        help="Input to scan: file path (for files), URL string, or IP address."
    )
    parser.add_argument(
        "-a", "--algorithm", default="md5",
        help="Hash algorithm for files (default: md5)."
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose output."
    )
    parser.add_argument(
        "-o", "--output", help="Save output to a file (JSON format)."
    )

    args = parser.parse_args()

    try:
        if args.type == "file":
            file_hash = calculate_file_hash(args.input, args.algorithm)
            print(f"{args.algorithm.upper()} Hash: {file_hash}")
            print("Querying VirusTotal for file...")
            result = query_virustotal_file(file_hash)
        elif args.type == "url":
            print("Querying VirusTotal for URL...")
            result = query_virustotal_url(args.input)
        elif args.type == "ip":
            print("Querying VirusTotal for IP address...")
            result = query_virustotal_ip(args.input)
        else:
            result = {"error": "Invalid scan type."}

        if args.verbose:
            print(json.dumps(result, indent=4))
        else:
            format_results(result, args.type, args.input)

        if args.output:
            with open(args.output, "w") as f:
                json.dump(result, f, indent=4)
                print(Fore.YELLOW + f"Results saved to {args.output}" + Style.RESET_ALL)

    except FileNotFoundError:
        print(Fore.RED + "Error: File not found. Please check the path and try again." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"An error occurred: {e}" + Style.RESET_ALL)

if __name__ == "__main__":
    main()