import requests
import urllib3

urllib3.disable_warnings()

FORTIGATE_IP = "192.168.1.2"
API_TOKEN = "058hfmrxkQxs08rmtwhzj74ksGd8yh"
VDOM = "root"

SERVICE_OBJECT_URL = f"http://{FORTIGATE_IP}/api/v2/cmdb/firewall.service/custom"
SERVICE_GROUP_URL = f"http://{FORTIGATE_IP}/api/v2/cmdb/firewall.service/group"

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

def get_fortigate_service_objects():
    try:
        response = requests.get(
            SERVICE_OBJECT_URL,
            headers=HEADERS,
            params=PARAMS,
            verify=False,
            timeout=TIMEOUT
        )

    except requests.exceptions.ConnectionError:
        return False, [], "Could not connect to FortiGate while loading service objects."

    except requests.exceptions.Timeout:
        return False, [], "FortiGate service object GET request timed out."

    except requests.exceptions.RequestException as error:
        return False, [], f"FortiGate service object GET request failed: {error}"

    if response.status_code != 200:
        reason = explain_status_code(response.status_code)
        return False, [], f"FortiGate service object GET failed. Status: {response.status_code}. Reason: {reason}. Response: {response.text}"

    try:
        data = response.json()

    except ValueError:
        return False, [], f"FortiGate service object GET response is not valid JSON. Raw response: {response.text}"

    results = data.get("results", [])

    if isinstance(results, dict):
        results = [results]

    return True, results, "FortiGate service objects loaded successfully"

def get_fortigate_service_names(existing_services):
    service_names = set()

    for service in existing_services:
        service_name = service.get("name")

        if service_name:
            service_names.add(service_name)

    return service_names

def fortigate_service_exists(service_name, existing_services):
    for service in existing_services:
        if service.get("name") == service_name:
            return True

    return False

def build_fortigate_service_payload(
    service_name,
    protocol,
    destination_port,
    description
):
    protocol = protocol.strip().lower()
    destination_port = destination_port.strip()

    payload = {
        "name": service_name,
        "protocol": "TCP/UDP/SCTP",
        "comment": description
    }

    if protocol == "tcp":
        payload["tcp-portrange"] = destination_port

    elif protocol == "udp":
        payload["udp-portrange"] = destination_port

    return payload

def create_fortigate_service_object(payload):
    try:
        response = requests.post(
            SERVICE_OBJECT_URL,
            headers=HEADERS,
            params=PARAMS,
            json=payload,
            verify=False,
            timeout=TIMEOUT
        )

    except requests.exceptions.ConnectionError:
        return False, "Could not connect to FortiGate. Service object was not created."

    except requests.exceptions.Timeout:
        return False, "FortiGate service object create request timed out. Creation status is unknown."

    except requests.exceptions.RequestException as error:
        return False, f"FortiGate service object create request failed: {error}"

    if response.status_code in [200, 201]:
        return True, response.text

    reason = explain_status_code(response.status_code)

    return False, f"FortiGate service object creation failed. Status: {response.status_code}. Reason: {reason}. Response: {response.text}"

def verify_fortigate_service_object(service_name):
    success, existing_services, message = get_fortigate_service_objects()

    if not success:
        return False, None, message

    for service in existing_services:
        if service.get("name") == service_name:
            return True, service, "Service object found"

    return False, None, "Service object not found"

def get_fortigate_service_groups():
    try:
        response = requests.get(
            SERVICE_GROUP_URL,
            headers=HEADERS,
            params=PARAMS,
            verify=False,
            timeout=TIMEOUT
        )

    except requests.exceptions.ConnectionError:
        return False, [], "Could not connect to FortiGate while loading service groups."

    except requests.exceptions.Timeout:
        return False, [], "FortiGate service group GET request timed out."

    except requests.exceptions.RequestException as error:
        return False, [], f"FortiGate service group GET request failed: {error}"

    if response.status_code != 200:
        reason = explain_status_code(response.status_code)
        return False, [], f"FortiGate service group GET failed. Status: {response.status_code}. Reason: {reason}. Response: {response.text}"

    try:
        data = response.json()

    except ValueError:
        return False, [], f"FortiGate service group GET response is not valid JSON. Raw response: {response.text}"

    results = data.get("results", [])

    if isinstance(results, dict):
        results = [results]

    return True, results, "FortiGate service groups loaded successfully"

def fortigate_service_group_exists(group_name, existing_groups):
    for group in existing_groups:
        if group.get("name") == group_name:
            return True

    return False

def find_missing_service_members(group_members, existing_service_names):
    missing_members = []

    for member in group_members:
        if member not in existing_service_names:
            missing_members.append(member)

    return missing_members

def build_fortigate_service_group_payload(group_name, members, description):
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

def create_fortigate_service_group(payload):
    try:
        response = requests.post(
            SERVICE_GROUP_URL,
            headers=HEADERS,
            params=PARAMS,
            json=payload,
            verify=False,
            timeout=TIMEOUT
        )

    except requests.exceptions.ConnectionError:
        return False, "Could not connect to FortiGate. Service group was not created."

    except requests.exceptions.Timeout:
        return False, "FortiGate service group create request timed out. Creation status is unknown."

    except requests.exceptions.RequestException as error:
        return False, f"FortiGate service group create request failed: {error}"

    if response.status_code in [200, 201]:
        return True, response.text

    reason = explain_status_code(response.status_code)

    return False, f"FortiGate service group creation failed. Status: {response.status_code}. Reason: {reason}. Response: {response.text}"

def verify_fortigate_service_group(group_name):
    success, existing_groups, message = get_fortigate_service_groups()

    if not success:
        return False, None, message

    for group in existing_groups:
        if group.get("name") == group_name:
            return True, group, "Service group found"

    return False, None, "Service group not found"
