import requests
import urllib3

urllib3.disable_warnings()

FORTIGATE_IP = "192.168.1.2"
API_TOKEN = "058hfmrxkQxs08rmtwhzj74ksGd8yh"
VDOM = "root"

INTERFACE_URL = f"http://{FORTIGATE_IP}/api/v2/cmdb/system/interface"

ADDRESS_OBJECT_URL = f"http://{FORTIGATE_IP}/api/v2/cmdb/firewall/address"
ADDRESS_GROUP_URL = f"http://{FORTIGATE_IP}/api/v2/cmdb/firewall/addrgrp"

SERVICE_OBJECT_URL = f"http://{FORTIGATE_IP}/api/v2/cmdb/firewall.service/custom"
SERVICE_GROUP_URL = f"http://{FORTIGATE_IP}/api/v2/cmdb/firewall.service/group"

IPPOOL_URL = f"http://{FORTIGATE_IP}/api/v2/cmdb/firewall/ippool"
VIP_URL = f"http://{FORTIGATE_IP}/api/v2/cmdb/firewall/vip"
POLICY_URL = f"http://{FORTIGATE_IP}/api/v2/cmdb/firewall/policy"

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

def get_fortigate_objects(url, object_type):
    try:
        response = requests.get(
            url,
            headers=HEADERS,
            params=PARAMS,
            verify=False,
            timeout=TIMEOUT
        )

    except requests.exceptions.ConnectionError:
        return False, [], f"Could not connect to FortiGate while loading {object_type}."

    except requests.exceptions.Timeout:
        return False, [], f"FortiGate {object_type} GET request timed out."

    except requests.exceptions.RequestException as error:
        return False, [], f"FortiGate {object_type} GET request failed: {error}"

    if response.status_code != 200:
        reason = explain_status_code(response.status_code)
        return False, [], f"FortiGate {object_type} GET failed. Status: {response.status_code}. Reason: {reason}. Response: {response.text}"

    try:
        data = response.json()

    except ValueError:
        return False, [], f"FortiGate {object_type} GET response is not valid JSON. Raw response: {response.text}"

    results = data.get("results", [])

    if isinstance(results, dict):
        results = [results]

    return True, results, f"FortiGate {object_type} loaded successfully"

def get_name_set(items):
    names = set()

    for item in items:
        name = item.get("name")

        if name:
            names.add(name)

    return names

def get_fortigate_interfaces():
    return get_fortigate_objects(INTERFACE_URL, "interfaces")

def get_fortigate_address_objects():
    return get_fortigate_objects(ADDRESS_OBJECT_URL, "address objects")

def get_fortigate_address_groups():
    return get_fortigate_objects(ADDRESS_GROUP_URL, "address groups")

def get_fortigate_service_objects():
    return get_fortigate_objects(SERVICE_OBJECT_URL, "service objects")

def get_fortigate_service_groups():
    return get_fortigate_objects(SERVICE_GROUP_URL, "service groups")

def get_fortigate_ippools():
    return get_fortigate_objects(IPPOOL_URL, "IP pools")

def get_fortigate_vips():
    return get_fortigate_objects(VIP_URL, "VIPs")

def get_fortigate_policies():
    return get_fortigate_objects(POLICY_URL, "firewall policies")

def normalize_fortigate_address_reference(address_name):
    if address_name.strip().lower() in ["any", "all"]:
        return "all"

    return address_name.strip()

def normalize_fortigate_service_reference(service_name):
    if service_name.strip().lower() in ["any", "all"]:
        return "ALL"

    return service_name.strip()

def map_log_traffic_for_fortigate(log_traffic):
    log_traffic = log_traffic.strip().lower()

    if log_traffic == "yes":
        return "all"

    if log_traffic == "no":
        return "disable"

    return "disable"

def fortigate_policy_exists(policy_name, existing_policies):
    for policy in existing_policies:
        if policy.get("name") == policy_name:
            return True

    return False

def fortigate_vip_exists(vip_name, existing_vips):
    for vip in existing_vips:
        if vip.get("name") == vip_name:
            return True

    return False

def find_vip_port_conflict(
    external_ip,
    protocol,
    external_port,
    existing_vips
):
    conflicts = []

    for vip in existing_vips:
        vip_extip = str(vip.get("extip", "")).strip()
        vip_protocol = str(vip.get("protocol", "")).strip().lower()
        vip_extport = str(vip.get("extport", "")).strip()
        vip_portforward = str(vip.get("portforward", "")).strip().lower()

        if vip_extip == external_ip:
            if vip_portforward == "enable":
                if vip_protocol == protocol and vip_extport == external_port:
                    conflicts.append(vip.get("name"))
            else:
                conflicts.append(vip.get("name"))

    return conflicts

def find_missing_snat_references(
    source_interface,
    destination_interface,
    source_address,
    destination_address,
    service,
    translated_source,
    interface_names,
    address_names,
    service_names,
    ippool_names
):
    missing_references = []

    if source_interface not in interface_names:
        missing_references.append(f"source_interface missing: {source_interface}")

    if destination_interface not in interface_names:
        missing_references.append(f"destination_interface missing: {destination_interface}")

    normalized_source_address = normalize_fortigate_address_reference(source_address)
    normalized_destination_address = normalize_fortigate_address_reference(destination_address)
    normalized_service = normalize_fortigate_service_reference(service)

    if normalized_source_address not in address_names:
        missing_references.append(f"source_address missing: {normalized_source_address}")

    if normalized_destination_address not in address_names:
        missing_references.append(f"destination_address missing: {normalized_destination_address}")

    if normalized_service not in service_names:
        missing_references.append(f"service missing: {normalized_service}")

    if translated_source.strip().lower() != "egress-interface":
        if translated_source not in ippool_names:
            missing_references.append(f"IP pool missing: {translated_source}")

    return missing_references

def find_missing_dnat_references(
    external_interface,
    source_interface,
    destination_interface,
    source_address,
    policy_service,
    interface_names,
    address_names,
    service_names
):
    missing_references = []

    if external_interface not in interface_names:
        missing_references.append(f"external_interface missing: {external_interface}")

    if source_interface not in interface_names:
        missing_references.append(f"source_interface missing: {source_interface}")

    if destination_interface not in interface_names:
        missing_references.append(f"destination_interface missing: {destination_interface}")

    normalized_source_address = normalize_fortigate_address_reference(source_address)
    normalized_service = normalize_fortigate_service_reference(policy_service)

    if normalized_source_address not in address_names:
        missing_references.append(f"source_address missing: {normalized_source_address}")

    if normalized_service not in service_names:
        missing_references.append(f"policy_service missing: {normalized_service}")

    return missing_references

def build_fortigate_snat_policy_payload(
    policy_name,
    source_interface,
    destination_interface,
    source_address,
    destination_address,
    service,
    translated_source,
    log_traffic,
    description
):
    normalized_source_address = normalize_fortigate_address_reference(source_address)
    normalized_destination_address = normalize_fortigate_address_reference(destination_address)
    normalized_service = normalize_fortigate_service_reference(service)

    payload = {
        "name": policy_name,
        "srcintf": [
            {
                "name": source_interface
            }
        ],
        "dstintf": [
            {
                "name": destination_interface
            }
        ],
        "srcaddr": [
            {
                "name": normalized_source_address
            }
        ],
        "dstaddr": [
            {
                "name": normalized_destination_address
            }
        ],
        "action": "accept",
        "schedule": "always",
        "service": [
            {
                "name": normalized_service
            }
        ],
        "nat": "enable",
        "logtraffic": map_log_traffic_for_fortigate(log_traffic),
        "comments": description,
        "status": "enable"
    }

    if translated_source.strip().lower() == "egress-interface":
        payload["ippool"] = "disable"

    else:
        payload["ippool"] = "enable"
        payload["poolname"] = [
            {
                "name": translated_source
            }
        ]

    return payload

def build_fortigate_vip_payload(
    vip_name,
    external_interface,
    external_ip,
    mapped_ip,
    protocol,
    external_port,
    mapped_port,
    description
):
    payload = {
        "name": vip_name,
        "type": "static-nat",
        "extintf": external_interface,
        "extip": external_ip,
        "mappedip": [
            {
                "range": mapped_ip
            }
        ],
        "portforward": "enable",
        "protocol": protocol,
        "extport": external_port,
        "mappedport": mapped_port,
        "comment": description
    }

    return payload

def build_fortigate_dnat_policy_payload(
    policy_name,
    source_interface,
    destination_interface,
    source_address,
    vip_name,
    policy_service,
    log_traffic,
    description
):
    normalized_source_address = normalize_fortigate_address_reference(source_address)
    normalized_service = normalize_fortigate_service_reference(policy_service)

    payload = {
        "name": policy_name,
        "srcintf": [
            {
                "name": source_interface
            }
        ],
        "dstintf": [
            {
                "name": destination_interface
            }
        ],
        "srcaddr": [
            {
                "name": normalized_source_address
            }
        ],
        "dstaddr": [
            {
                "name": vip_name
            }
        ],
        "action": "accept",
        "schedule": "always",
        "service": [
            {
                "name": normalized_service
            }
        ],
        "nat": "disable",
        "logtraffic": map_log_traffic_for_fortigate(log_traffic),
        "comments": description,
        "status": "enable"
    }

    return payload

def create_fortigate_policy(payload):
    try:
        response = requests.post(
            POLICY_URL,
            headers=HEADERS,
            params=PARAMS,
            json=payload,
            verify=False,
            timeout=TIMEOUT
        )

    except requests.exceptions.ConnectionError:
        return False, "Could not connect to FortiGate. Policy was not created."

    except requests.exceptions.Timeout:
        return False, "FortiGate policy create request timed out. Creation status is unknown."

    except requests.exceptions.RequestException as error:
        return False, f"FortiGate policy create request failed: {error}"

    if response.status_code in [200, 201]:
        return True, response.text

    reason = explain_status_code(response.status_code)

    return False, f"FortiGate policy creation failed. Status: {response.status_code}. Reason: {reason}. Response: {response.text}"

def create_fortigate_vip(payload):
    try:
        response = requests.post(
            VIP_URL,
            headers=HEADERS,
            params=PARAMS,
            json=payload,
            verify=False,
            timeout=TIMEOUT
        )

    except requests.exceptions.ConnectionError:
        return False, "Could not connect to FortiGate. VIP was not created."

    except requests.exceptions.Timeout:
        return False, "FortiGate VIP create request timed out. Creation status is unknown."

    except requests.exceptions.RequestException as error:
        return False, f"FortiGate VIP create request failed: {error}"

    if response.status_code in [200, 201]:
        return True, response.text

    reason = explain_status_code(response.status_code)

    return False, f"FortiGate VIP creation failed. Status: {response.status_code}. Reason: {reason}. Response: {response.text}"

def verify_fortigate_policy(policy_name):
    success, existing_policies, message = get_fortigate_policies()

    if not success:
        return False, None, message

    for policy in existing_policies:
        if policy.get("name") == policy_name:
            return True, policy, "Firewall policy found"

    return False, None, "Firewall policy not found"

def verify_fortigate_vip(vip_name):
    success, existing_vips, message = get_fortigate_vips()

    if not success:
        return False, None, message

    for vip in existing_vips:
        if vip.get("name") == vip_name:
            return True, vip, "VIP found"

    return False, None, "VIP not found"