import requests
import urllib3

urllib3.disable_warnings()

FIREWALL_IP = "192.168.1.1"
API_KEY = "LUFRPT11cFpwek9zZ2JIL29QZnlqNmpxa2pKTzVOaW89QlV0d3ljQjBRZHQzR1VMQzExeVNPbFZNbDVKVmJRK0pHcEx1N3BMc1ZPZGVCMkdVSU5XdGh2TDhUQWhhZjZJLw=="
API_VERSION = "v10.0"
VSYS = "vsys1"

SERVICE_OBJECT_URL = f"https://{FIREWALL_IP}/restapi/{API_VERSION}/Objects/Services"
SERVICE_GROUP_URL = f"https://{FIREWALL_IP}/restapi/{API_VERSION}/Objects/ServiceGroups"

HEADERS = {
    "X-PAN-KEY": API_KEY,
    "Content-Type": "application/json"
}

GET_PARAMS = {
    "location": "vsys",
    "vsys": VSYS
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

def get_paloalto_service_objects():
    try:
        response = requests.get(
            SERVICE_OBJECT_URL,
            headers=HEADERS,
            params=GET_PARAMS,
            verify=False,
            timeout=TIMEOUT
        )

    except requests.exceptions.ConnectionError:
        return False, [], "Could not connect to Palo Alto while loading service objects."

    except requests.exceptions.Timeout:
        return False, [], "Palo Alto service object GET request timed out."

    except requests.exceptions.RequestException as error:
        return False, [], f"Palo Alto service object GET request failed: {error}"

    if response.status_code != 200:
        reason = explain_status_code(response.status_code)
        return False, [], f"Palo Alto service object GET failed. Status: {response.status_code}. Reason: {reason}. Response: {response.text}"

    try:
        data = response.json()

    except ValueError:
        return False, [], f"Palo Alto service object GET response is not valid JSON. Raw response: {response.text}"

    entries = data.get("result", {}).get("entry", [])

    if isinstance(entries, dict):
        entries = [entries]

    return True, entries, "Palo Alto service objects loaded successfully"

def get_paloalto_service_names(existing_services):
    service_names = set()

    for service in existing_services:
        service_name = service.get("@name")

        if service_name:
            service_names.add(service_name)

    return service_names

def paloalto_service_exists(service_name, existing_services):
    for service in existing_services:
        if service.get("@name") == service_name:
            return True

    return False

def build_paloalto_service_payload(
    service_name,
    protocol,
    destination_port,
    description
):
    protocol = protocol.strip().lower()
    destination_port = destination_port.strip()

    payload = {
        "entry": [
            {
                "@location": "vsys",
                "@vsys": VSYS,
                "@name": service_name,
                "protocol": {
                    protocol: {
                        "port": destination_port
                    }
                },
                "description": description
            }
        ]
    }

    return payload

def create_paloalto_service_object(service_name, payload):
    create_params = {
        "location": "vsys",
        "vsys": VSYS,
        "name": service_name
    }

    try:
        response = requests.post(
            SERVICE_OBJECT_URL,
            headers=HEADERS,
            params=create_params,
            json=payload,
            verify=False,
            timeout=TIMEOUT
        )

    except requests.exceptions.ConnectionError:
        return False, "Could not connect to Palo Alto. Service object was not created."

    except requests.exceptions.Timeout:
        return False, "Palo Alto service object create request timed out. Creation status is unknown."

    except requests.exceptions.RequestException as error:
        return False, f"Palo Alto service object create request failed: {error}"

    if response.status_code in [200, 201]:
        return True, response.text

    reason = explain_status_code(response.status_code)

    return False, f"Palo Alto service object creation failed. Status: {response.status_code}. Reason: {reason}. Response: {response.text}"

def verify_paloalto_service_object(service_name):
    success, existing_services, message = get_paloalto_service_objects()

    if not success:
        return False, None, message

    for service in existing_services:
        if service.get("@name") == service_name:
            return True, service, "Service object found"

    return False, None, "Service object not found"

def get_paloalto_service_groups():
    try:
        response = requests.get(
            SERVICE_GROUP_URL,
            headers=HEADERS,
            params=GET_PARAMS,
            verify=False,
            timeout=TIMEOUT
        )

    except requests.exceptions.ConnectionError:
        return False, [], "Could not connect to Palo Alto while loading service groups."

    except requests.exceptions.Timeout:
        return False, [], "Palo Alto service group GET request timed out."

    except requests.exceptions.RequestException as error:
        return False, [], f"Palo Alto service group GET request failed: {error}"

    if response.status_code != 200:
        reason = explain_status_code(response.status_code)
        return False, [], f"Palo Alto service group GET failed. Status: {response.status_code}. Reason: {reason}. Response: {response.text}"

    try:
        data = response.json()

    except ValueError:
        return False, [], f"Palo Alto service group GET response is not valid JSON. Raw response: {response.text}"

    entries = data.get("result", {}).get("entry", [])

    if isinstance(entries, dict):
        entries = [entries]

    return True, entries, "Palo Alto service groups loaded successfully"

def paloalto_service_group_exists(group_name, existing_groups):
    for group in existing_groups:
        if group.get("@name") == group_name:
            return True

    return False

def find_missing_service_members(group_members, existing_service_names):
    missing_members = []

    for member in group_members:
        if member not in existing_service_names:
            missing_members.append(member)

    return missing_members

def build_paloalto_service_group_payload(group_name, members, description):
    payload = {
        "entry": [
            {
                "@location": "vsys",
                "@vsys": VSYS,
                "@name": group_name,
                "members": {
                    "member": members
                },
                "description": description
            }
        ]
    }

    return payload

def create_paloalto_service_group(group_name, payload):
    create_params = {
        "location": "vsys",
        "vsys": VSYS,
        "name": group_name
    }

    try:
        response = requests.post(
            SERVICE_GROUP_URL,
            headers=HEADERS,
            params=create_params,
            json=payload,
            verify=False,
            timeout=TIMEOUT
        )

    except requests.exceptions.ConnectionError:
        return False, "Could not connect to Palo Alto. Service group was not created."

    except requests.exceptions.Timeout:
        return False, "Palo Alto service group create request timed out. Creation status is unknown."

    except requests.exceptions.RequestException as error:
        return False, f"Palo Alto service group create request failed: {error}"

    if response.status_code in [200, 201]:
        return True, response.text

    reason = explain_status_code(response.status_code)

    return False, f"Palo Alto service group creation failed. Status: {response.status_code}. Reason: {reason}. Response: {response.text}"

def verify_paloalto_service_group(group_name):
    success, existing_groups, message = get_paloalto_service_groups()

    if not success:
        return False, None, message

    for group in existing_groups:
        if group.get("@name") == group_name:
            return True, group, "Service group found"

    return False, None, "Service group not found"