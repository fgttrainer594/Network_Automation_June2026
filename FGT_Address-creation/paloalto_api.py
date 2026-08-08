import requests
import urllib3

urllib3.disable_warnings()

FIREWALL_IP = "192.168.1.1"
API_KEY = "LUFRPT1yV1FhdytuR2FLV0VmMnJaOFRVTHU0aXRNSXc9QlV0d3ljQjBRZHQzR1VMQzExeVNPdXJ0K2lDM2ZJdml0N0lkQndqS1ErT0ZEYWFVNm1NQlVLS0QwNlE0a3BNWA=="

ADDRESS_URL = f"https://{FIREWALL_IP}/restapi/v10.0/Objects/Addresses"

HEADERS = {
    "X-PAN-KEY": API_KEY,
    "Content-Type": "application/json"
}

GET_PARAMS = {
    "location": "vsys",
    "vsys": "vsys1"
}

TIMEOUT = 10

def explain_status_code(status_code):
    if status_code == 400:
        return "Bad Request - payload, query parameter, or object data may be wrong"
    elif status_code == 401:
        return "Unauthorized - API key may be wrong or missing"
    elif status_code == 403:
        return "Forbidden - admin role may not have permission"
    elif status_code == 404:
        return "Not Found - REST endpoint, PAN-OS version path, or object path may be wrong"
    elif status_code >= 500:
        return "Server Error - firewall returned internal error"
    else:
        return "Unexpected API response"

def get_paloalto_address_objects():
    try:
        response = requests.get(
            ADDRESS_URL,
            headers=HEADERS,
            params=GET_PARAMS,
            verify=False,
            timeout=TIMEOUT
        )

    except requests.exceptions.ConnectionError:
        return False, [], "Could not connect to Palo Alto. Check IP, routing, HTTPS, and reachability."

    except requests.exceptions.Timeout:
        return False, [], "Palo Alto API request timed out."

    except requests.exceptions.RequestException as error:
        return False, [], f"Palo Alto API request failed: {error}"

    if response.status_code != 200:
        reason = explain_status_code(response.status_code)
        return False, [], f"Palo Alto GET failed. Status: {response.status_code}. Reason: {reason}. Response: {response.text}"

    try:
        data = response.json()

    except ValueError:
        return False, [], f"Palo Alto GET response is not valid JSON. Raw response: {response.text}"

    entries = data.get("result", {}).get("entry", [])

    if isinstance(entries, dict):
        entries = [entries]

    return True, entries, "Palo Alto address objects loaded successfully"

def paloalto_object_exists(object_name, existing_objects):
    for obj in existing_objects:
        if obj.get("@name") == object_name:
            return True

    return False

def build_paloalto_address_payload(object_name, ip_netmask):
    payload = {
        "entry": [
            {
                "@location": "vsys",
                "@vsys": "vsys1",
                "@name": object_name,
                "ip-netmask": ip_netmask
            }
        ]
    }

    return payload

def create_paloalto_address_object(object_name, payload):
    create_params = {
        "location": "vsys",
        "vsys": "vsys1",
        "name": object_name
    }

    try:
        response = requests.post(
            ADDRESS_URL,
            headers=HEADERS,
            params=create_params,
            json=payload,
            verify=False,
            timeout=TIMEOUT
        )

    except requests.exceptions.ConnectionError:
        return False, "Could not connect to Palo Alto. Object was not created."

    except requests.exceptions.Timeout:
        return False, "Palo Alto API request timed out. Object creation status is unknown."

    except requests.exceptions.RequestException as error:
        return False, f"Palo Alto API request failed: {error}"

    if response.status_code in [200, 201]:
        return True, response.text

    reason = explain_status_code(response.status_code)

    return False, f"Palo Alto object creation failed. Status: {response.status_code}. Reason: {reason}. Response: {response.text}"

def verify_paloalto_address_object(object_name):
    success, existing_objects, message = get_paloalto_address_objects()

    if not success:
        return False, None, message

    for obj in existing_objects:
        if obj.get("@name") == object_name:
            return True, obj, "Object found"

    return False, None, "Object not found"