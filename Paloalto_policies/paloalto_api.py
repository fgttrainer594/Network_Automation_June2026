import requests
import urllib3

urllib3.disable_warnings()

FIREWALL_IP = "192.168.1.1"
API_KEY = "LUFRPT11cFpwek9zZ2JIL29QZnlqNmpxa2pKTzVOaW89QlV0d3ljQjBRZHQzR1VMQzExeVNPbFZNbDVKVmJRK0pHcEx1N3BMc1ZPZGVCMkdVSU5XdGh2TDhUQWhhZjZJLw=="
API_VERSION = "v10.0"
VSYS = "vsys1"

ZONE_URL = f"https://{FIREWALL_IP}/restapi/{API_VERSION}/Network/Zones"

ADDRESS_OBJECT_URL = f"https://{FIREWALL_IP}/restapi/{API_VERSION}/Objects/Addresses"
ADDRESS_GROUP_URL = f"https://{FIREWALL_IP}/restapi/{API_VERSION}/Objects/AddressGroups"

SERVICE_OBJECT_URL = f"https://{FIREWALL_IP}/restapi/{API_VERSION}/Objects/Services"
SERVICE_GROUP_URL = f"https://{FIREWALL_IP}/restapi/{API_VERSION}/Objects/ServiceGroups"

POLICY_URL = f"https://{FIREWALL_IP}/restapi/{API_VERSION}/Policies/SecurityRules"

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

def get_paloalto_objects(url, object_type):
    try:
        response = requests.get(
            url,
            headers=HEADERS,
            params=GET_PARAMS,
            verify=False,
            timeout=TIMEOUT
        )

    except requests.exceptions.ConnectionError:
        return False, [], f"Could not connect to Palo Alto while loading {object_type}."

    except requests.exceptions.Timeout:
        return False, [], f"Palo Alto {object_type} GET request timed out."

    except requests.exceptions.RequestException as error:
        return False, [], f"Palo Alto {object_type} GET request failed: {error}"

    if response.status_code != 200:
        reason = explain_status_code(response.status_code)
        return False, [], f"Palo Alto {object_type} GET failed. Status: {response.status_code}. Reason: {reason}. Response: {response.text}"

    try:
        data = response.json()

    except ValueError:
        return False, [], f"Palo Alto {object_type} GET response is not valid JSON. Raw response: {response.text}"

    entries = data.get("result", {}).get("entry", [])

    if isinstance(entries, dict):
        entries = [entries]

    return True, entries, f"Palo Alto {object_type} loaded successfully"

def get_name_set(items):
    names = set()

    for item in items:
        name = item.get("@name")

        if name:
            names.add(name)

    return names

def get_paloalto_zones():
    return get_paloalto_objects(ZONE_URL, "zones")

def get_paloalto_address_objects():
    return get_paloalto_objects(ADDRESS_OBJECT_URL, "address objects")

def get_paloalto_address_groups():
    return get_paloalto_objects(ADDRESS_GROUP_URL, "address groups")

def get_paloalto_service_objects():
    return get_paloalto_objects(SERVICE_OBJECT_URL, "service objects")

def get_paloalto_service_groups():
    return get_paloalto_objects(SERVICE_GROUP_URL, "service groups")

def get_paloalto_security_rules():
    return get_paloalto_objects(POLICY_URL, "security rules")

def paloalto_policy_exists(policy_name, existing_policies):
    for policy in existing_policies:
        if policy.get("@name") == policy_name:
            return True

    return False

def normalize_paloalto_address_reference(address_name):
    if address_name.strip().lower() in ["any", "all"]:
        return "any"

    return address_name.strip()

def normalize_paloalto_service_reference(service_name):
    if service_name.strip().lower() in ["any", "all"]:
        return "any"

    if service_name.strip().lower() == "application-default":
        return "application-default"

    return service_name.strip()

def map_log_traffic_for_paloalto(log_traffic):
    log_traffic = log_traffic.strip().lower()

    if log_traffic == "yes":
        return "yes"

    if log_traffic == "no":
        return "no"

    return "no"

def find_missing_policy_references(
    source_zone,
    destination_zone,
    source_address,
    destination_address,
    service,
    zone_names,
    address_names,
    service_names
):
    missing_references = []

    if source_zone not in zone_names:
        missing_references.append(f"source_zone/from zone missing: {source_zone}")

    if destination_zone not in zone_names:
        missing_references.append(f"destination_zone/to zone missing: {destination_zone}")

    normalized_source_address = normalize_paloalto_address_reference(source_address)
    normalized_destination_address = normalize_paloalto_address_reference(destination_address)

    if normalized_source_address not in address_names:
        missing_references.append(f"source_address missing: {normalized_source_address}")

    if normalized_destination_address not in address_names:
        missing_references.append(f"destination_address missing: {normalized_destination_address}")

    normalized_service = normalize_paloalto_service_reference(service)

    if normalized_service not in service_names:
        missing_references.append(f"service missing: {normalized_service}")

    return missing_references

def build_paloalto_security_rule_payload(
    policy_name,
    source_zone,
    destination_zone,
    source_address,
    destination_address,
    service,
    application,
    action,
    log_traffic,
    description
):
    normalized_source_address = normalize_paloalto_address_reference(source_address)
    normalized_destination_address = normalize_paloalto_address_reference(destination_address)
    normalized_service = normalize_paloalto_service_reference(service)

    log_end_value = map_log_traffic_for_paloalto(log_traffic)

    payload = {
        "entry": [
            {
                "@location": "vsys",
                "@vsys": VSYS,
                "@name": policy_name,
                "from": {
                    "member": [
                        source_zone
                    ]
                },
                "to": {
                    "member": [
                        destination_zone
                    ]
                },
                "source": {
                    "member": [
                        normalized_source_address
                    ]
                },
                "destination": {
                    "member": [
                        normalized_destination_address
                    ]
                },
                "source-user": {
                    "member": [
                        "any"
                    ]
                },
                "category": {
                    "member": [
                        "any"
                    ]
                },
                "application": {
                    "member": [
                        application
                    ]
                },
                "service": {
                    "member": [
                        normalized_service
                    ]
                },
                "action": action,
                "log-start": "no",
                "log-end": log_end_value,
                "description": description,
                "disabled": "no"
            }
        ]
    }

    return payload

def create_paloalto_security_rule(policy_name, payload):
    create_params = {
        "location": "vsys",
        "vsys": VSYS,
        "name": policy_name
    }

    try:
        response = requests.post(
            POLICY_URL,
            headers=HEADERS,
            params=create_params,
            json=payload,
            verify=False,
            timeout=TIMEOUT
        )

    except requests.exceptions.ConnectionError:
        return False, "Could not connect to Palo Alto. Security rule was not created."

    except requests.exceptions.Timeout:
        return False, "Palo Alto security rule create request timed out. Creation status is unknown."

    except requests.exceptions.RequestException as error:
        return False, f"Palo Alto security rule create request failed: {error}"

    if response.status_code in [200, 201]:
        return True, response.text

    reason = explain_status_code(response.status_code)

    return False, f"Palo Alto security rule creation failed. Status: {response.status_code}. Reason: {reason}. Response: {response.text}"

def verify_paloalto_security_rule(policy_name):
    success, existing_policies, message = get_paloalto_security_rules()

    if not success:
        return False, None, message

    for policy in existing_policies:
        if policy.get("@name") == policy_name:
            return True, policy, "Security rule found"

    return False, None, "Security rule not found"