import requests
import urllib3
import ipaddress

urllib3.disable_warnings()

FORTIGATE_IP = "192.168.1.2"
API_TOKEN = "058hfmrxkQxs08rmtwhzj74ksGd8yh"
VDOM = "root"

ADDRESS_OBJECT_URL = f"http://{FORTIGATE_IP}/api/v2/cmdb/firewall/address" 
ADDRESS_GROUP_URL = f"http://{FORTIGATE_IP}/api/v2/cmdb/firewall/addrgrp"

HEADERS = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json"
}

PARAMS = {
    "vdom": VDOM
}

TIMEOUT = 10

def explain_status_code(status_code):
    if status_code == 400:
        return "Bad Request - payload, parameter, or syntax may be wrong"
    elif status_code == 401:
        return "Unauthorized - API token may be wrong or missing"
    elif status_code == 403:
        return "Forbidden - admin profile, trusted host, or VDOM permission issue"
    elif status_code == 404:
        return "Not Found - endpoint path or firewall IP may be wrong"
    elif status_code >= 500:
        return "Server Error - firewall returned internal error"
    else:
        return "Unexpected API response"

def get_fortigate_address_objects():
    try:
        response = requests.get(
            ADDRESS_OBJECT_URL,
            headers=HEADERS,
            params=PARAMS,
            verify=False,
            timeout=TIMEOUT
        )

    except requests.exceptions.ConnectionError:
        return False, [], "Could not connect to FortiGate. Check IP, routing, HTTPS, and reachability."

    except requests.exceptions.Timeout:
        return False, [], "FortiGate address object GET request timed out."

    except requests.exceptions.RequestException as error:
        return False, [], f"FortiGate address object GET request failed: {error}"

    if response.status_code != 200:
        reason = explain_status_code(response.status_code)
        return False, [], f"FortiGate address object GET failed. Status: {response.status_code}. Reason: {reason}. Response: {response.text}"

    try:
        data = response.json()

    except ValueError:
        return False, [], f"FortiGate address object GET response is not valid JSON. Raw response: {response.text}"

    results = data.get("results", [])

    if isinstance(results, dict):
        results = [results]

    return True, results, "FortiGate address objects loaded successfully"

def get_fortigate_address_object_names(existing_objects):
    object_names = set()

    for obj in existing_objects:
        object_name = obj.get("name")

        if object_name:
            object_names.add(object_name)

    return object_names

def get_fortigate_address_groups():
    try:
        response = requests.get(
            ADDRESS_GROUP_URL,
            headers=HEADERS,
            params=PARAMS,
            verify=False,
            timeout=TIMEOUT
        )

    except requests.exceptions.ConnectionError:
        return False, [], "Could not connect to FortiGate while loading address groups."

    except requests.exceptions.Timeout:
        return False, [], "FortiGate address group GET request timed out."

    except requests.exceptions.RequestException as error:
        return False, [], f"FortiGate address group GET request failed: {error}"

    if response.status_code != 200:
        reason = explain_status_code(response.status_code)
        return False, [], f"FortiGate address group GET failed. Status: {response.status_code}. Reason: {reason}. Response: {response.text}"

    try:
        data = response.json()

    except ValueError:
        return False, [], f"FortiGate address group GET response is not valid JSON. Raw response: {response.text}"

    results = data.get("results", [])

    if isinstance(results, dict):
        results = [results]

    return True, results, "FortiGate address groups loaded successfully"

def fortigate_group_exists(group_name, existing_groups):
    for group in existing_groups:
        if group.get("name") == group_name:
            return True

    return False

def find_missing_members(group_members, existing_object_names):
    missing_members = []

    for member in group_members:
        if member not in existing_object_names:
            missing_members.append(member)

    return missing_members

def build_fortigate_address_group_payload(group_name, members, description):
    member_payload = []

    for member in members:
        member_payload.append(
            {
                "name": member
            }
        )

    payload = {
        "name": group_name,
        "member": member_payload,
        "comment": description
    }

    return payload

def create_fortigate_address_group(payload):
    try:
        response = requests.post(
            ADDRESS_GROUP_URL,
            headers=HEADERS,
            params=PARAMS,
            json=payload,
            verify=False,
            timeout=TIMEOUT
        )

    except requests.exceptions.ConnectionError:
        return False, "Could not connect to FortiGate. Address group was not created."

    except requests.exceptions.Timeout:
        return False, "FortiGate address group create request timed out. Creation status is unknown."

    except requests.exceptions.RequestException as error:
        return False, f"FortiGate address group create request failed: {error}"

    if response.status_code in [200, 201]:
        return True, response.text

    reason = explain_status_code(response.status_code)

    return False, f"FortiGate address group creation failed. Status: {response.status_code}. Reason: {reason}. Response: {response.text}"

def verify_fortigate_address_group(group_name):
    success, existing_groups, message = get_fortigate_address_groups()

    if not success:
        return False, None, message

    for group in existing_groups:
        if group.get("name") == group_name:
            return True, group, "Address group found"

    return False, None, "Address group not found"