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

NAT_RULE_URL = f"https://{FIREWALL_IP}/restapi/{API_VERSION}/Policies/NATRules"

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

def get_paloalto_nat_rules():
    return get_paloalto_objects(NAT_RULE_URL, "NAT rules")

def paloalto_nat_rule_exists(nat_name, existing_nat_rules):
    for rule in existing_nat_rules:
        if rule.get("@name") == nat_name:
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

def find_missing_nat_references(
    from_zone,
    to_zone,
    source_address,
    destination_address,
    service,
    zone_names,
    address_names,
    service_names
):
    missing_references = []

    if from_zone not in zone_names:
        missing_references.append(f"from_zone missing: {from_zone}")

    if to_zone not in zone_names:
        missing_references.append(f"to_zone missing: {to_zone}")

    normalized_source_address = normalize_paloalto_address_reference(source_address)
    normalized_destination_address = normalize_paloalto_address_reference(destination_address)
    normalized_service = normalize_paloalto_service_reference(service)

    if normalized_source_address not in address_names:
        missing_references.append(f"source_address missing: {normalized_source_address}")

    if normalized_destination_address not in address_names:
        missing_references.append(f"destination_address missing: {normalized_destination_address}")

    if normalized_service not in service_names:
        missing_references.append(f"service missing: {normalized_service}")

    return missing_references

def find_dnat_conflict(
    original_destination,
    service,
    existing_nat_rules
):
    conflicts = []

    for rule in existing_nat_rules:
        rule_destination = rule.get("destination", {})
        rule_service = str(rule.get("service", "")).strip()

        destination_members = rule_destination.get("member", [])

        if isinstance(destination_members, str):
            destination_members = [destination_members]

        if original_destination in destination_members and rule_service == service:
            conflicts.append(rule.get("@name"))

    return conflicts

def build_paloalto_source_nat_payload(
    nat_name,
    from_zone,
    to_zone,
    source_address,
    destination_address,
    service,
    translated_interface,
    description
):
    normalized_source_address = normalize_paloalto_address_reference(source_address)
    normalized_destination_address = normalize_paloalto_address_reference(destination_address)
    normalized_service = normalize_paloalto_service_reference(service)

    payload = {
        "entry": [
            {
                "@location": "vsys",
                "@vsys": VSYS,
                "@name": nat_name,
                "from": {
                    "member": [
                        from_zone
                    ]
                },
                "to": {
                    "member": [
                        to_zone
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
                "service": normalized_service,
                "source-translation": {
                    "dynamic-ip-and-port": {
                        "interface-address": {
                            "interface": translated_interface
                        }
                    }
                },
                "description": description,
                "disabled": "no"
            }
        ]
    }

    return payload

def build_paloalto_destination_nat_payload(
    nat_name,
    from_zone,
    to_zone,
    source_address,
    original_destination,
    service,
    translated_destination,
    translated_port,
    description
):
    normalized_source_address = normalize_paloalto_address_reference(source_address)
    normalized_service = normalize_paloalto_service_reference(service)

    payload = {
        "entry": [
            {
                "@location": "vsys",
                "@vsys": VSYS,
                "@name": nat_name,
                "from": {
                    "member": [
                        from_zone
                    ]
                },
                "to": {
                    "member": [
                        to_zone
                    ]
                },
                "source": {
                    "member": [
                        normalized_source_address
                    ]
                },
                "destination": {
                    "member": [
                        original_destination
                    ]
                },
                "service": normalized_service,
                "destination-translation": {
                    "translated-address": translated_destination,
                    "translated-port": translated_port
                },
                "description": description,
                "disabled": "no"
            }
        ]
    }

    return payload

def create_paloalto_nat_rule(nat_name, payload):
    create_params = {
        "location": "vsys",
        "vsys": VSYS,
        "name": nat_name
    }

    try:
        response = requests.post(
            NAT_RULE_URL,
            headers=HEADERS,
            params=create_params,
            json=payload,
            verify=False,
            timeout=TIMEOUT
        )

    except requests.exceptions.ConnectionError:
        return False, "Could not connect to Palo Alto. NAT rule was not created."

    except requests.exceptions.Timeout:
        return False, "Palo Alto NAT rule create request timed out. Creation status is unknown."

    except requests.exceptions.RequestException as error:
        return False, f"Palo Alto NAT rule create request failed: {error}"

    if response.status_code in [200, 201]:
        return True, response.text

    reason = explain_status_code(response.status_code)

    return False, f"Palo Alto NAT rule creation failed. Status: {response.status_code}. Reason: {reason}. Response: {response.text}"

def verify_paloalto_nat_rule(nat_name):
    success, existing_nat_rules, message = get_paloalto_nat_rules()

    if not success:
        return False, None, message

    for rule in existing_nat_rules:
        if rule.get("@name") == nat_name:
            return True, rule, "NAT rule found"

    return False, None, "NAT rule not found"