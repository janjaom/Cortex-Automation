import requests
import json
import time
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def submit_ioc(api_key, ioc_data):
    api_url = "https://IP_CORTEXT/api/analyzer/ID_ANALYZER/run"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    payload = {
        "data": ioc_data["data"],
        "dataType": ioc_data["dataType"],
        "tlp": ioc_data.get("tlp", 0),
    }

    response = requests.post(api_url, json=payload, headers=headers, verify=False)

    if response.status_code == 200:
        print("(+) IOC submitted successfully.")
        time.sleep(15)
    else:
        print(f"Failed to submit IOC. Status code: {response.status_code}")
        print(response.text)

def fetch_analysis(api_key):
    url = 'https://IP_CORTEX/api/job/_search'
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json'
    }

    data = {
        "query": {
            "_and": [
                {"status": "Success"},
                {"_or": [
                    {"dataType": "ip"},
                    {"dataType": "hash"},
                    {"dataType": "domain"}
                ]}
            ]
        }
    }

    response = requests.post(url, headers=headers, json=data, verify=False)

    if response.status_code == 200:
        jobs = json.loads(response.text)

        job_id = 0
        created_at = 0

        for x in jobs:
            if x['createdAt'] > created_at:
                created_at = x['createdAt']
                job_id = x['id']

        url_detail = f'https://IP_CORTEX/api/job/{job_id}/report'

        # Use the json parameter to automatically set the Content-Type header to 'application/json'
        response_detail = requests.get(url_detail, headers=headers, verify=False)

        if response_detail.status_code == 200:
            details = json.loads(response_detail.text)
            print("Analysis Result:")
            print(json.dumps(details, indent=2))
        else:
            print(f"Failed to fetch analysis details. Status code: {response_detail.status_code}")
            print(response_detail.text)
    else:
        print(f"Failed to fetch analysis jobs. Status code: {response.status_code}")
        print(response.text)

# Get user input for IOC data
ioc_data = {
    "data": input("Enter IOC data: "),
    "dataType": input("Enter IOC type (e.g., domain, ip, hash): "),
    "tlp": int(input("Enter TLP (Traffic Light Protocol) level (default is 0): ") or 0),
}

api_key = "**API_CORTEX**"

# Submit IOC for analysis
submit_ioc(api_key, ioc_data)

# Fetch analysis results
fetch_analysis(api_key)
