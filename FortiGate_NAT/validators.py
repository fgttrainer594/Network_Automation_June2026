import ipaddress

SOURCE_NAT_REQUIRED_COLUMNS = [
    "policy_name",
    "source_interface",
    "destination_interface",
    "source_address",
    "destination_address",
    "service",
    "translated_source",
    "log_traffic",
    "position_type",
    "anchor_rule",
    "description"
]

DESTINATION_NAT_REQUIRED_COLUMNS = [
    "vip_name",
    "policy_name",
    "external_interface",
    "source_interface",
    "destination_interface",
    "source_address",
    "external_ip",
    "mapped_ip",
    "protocol",
    "external_port",
    "mapped_port",
    "policy_service",
    "log_traffic",
    "position_type",
    "anchor_rule",
    "description"
]

def normalize_csv_row(row):
    normalized_row = {}

    for key, value in row.items():
        if key is None:
            continue

        clean_key = key.strip()

        if isinstance(value, str):
            clean_value = value.strip()
        else:
            clean_value = ""

        normalized_row[clean_key] = clean_value

    return normalized_row

def validate_csv_headers(fieldnames, required_columns):
    if fieldnames is None:
        return False, "CSV file is empty or header row is missing"

    cleaned_headers = []

    for header in fieldnames:
        if header is not None:
            cleaned_headers.append(header.strip())

    missing_columns = []

    for column in required_columns:
        if column not in cleaned_headers:
            missing_columns.append(column)

    if missing_columns:
        return False, f"Missing required CSV columns: {', '.join(missing_columns)}"

    return True, "CSV headers are valid"

def validate_source_nat_csv_headers(fieldnames):
    return validate_csv_headers(fieldnames, SOURCE_NAT_REQUIRED_COLUMNS)

def validate_destination_nat_csv_headers(fieldnames):
    return validate_csv_headers(fieldnames, DESTINATION_NAT_REQUIRED_COLUMNS)

def is_valid_log_traffic(log_traffic):
    log_traffic = log_traffic.strip().lower()

    if log_traffic in ["yes", "no"]:
        return True

    return False

def is_valid_position_type(position_type):
    position_type = position_type.strip().lower()

    if position_type in ["bottom", "before", "after"]:
        return True

    return False

def validate_position(position_type, anchor_rule):
    position_type = position_type.strip().lower()
    anchor_rule = anchor_rule.strip()

    if not is_valid_position_type(position_type):
        return False, "position_type must be bottom, before, or after"

    if position_type in ["before", "after"] and not anchor_rule:
        return False, "anchor_rule is required when position_type is before or after"

    return True, "valid position"

def is_valid_protocol(protocol):
    protocol = protocol.strip().lower()

    if protocol in ["tcp", "udp"]:
        return True

    return False

def is_valid_single_port(port):
    port = port.strip()

    if not port.isdigit():
        return False

    port_number = int(port)

    if port_number < 1:
        return False

    if port_number > 65535:
        return False

    return True

def is_valid_ip_address(ip_value):
    ip_value = ip_value.strip()

    try:
        ipaddress.ip_address(ip_value)
        return True

    except ValueError:
        return False

def validate_source_nat_row(
    policy_name,
    source_interface,
    destination_interface,
    source_address,
    destination_address,
    service,
    translated_source,
    log_traffic,
    position_type,
    anchor_rule
):
    policy_name = policy_name.strip()
    source_interface = source_interface.strip()
    destination_interface = destination_interface.strip()
    source_address = source_address.strip()
    destination_address = destination_address.strip()
    service = service.strip()
    translated_source = translated_source.strip()
    log_traffic = log_traffic.strip().lower()

    if not policy_name:
        return False, "policy_name is missing"

    if not source_interface:
        return False, "source_interface is missing"

    if not destination_interface:
        return False, "destination_interface is missing"

    if not source_address:
        return False, "source_address is missing"

    if not destination_address:
        return False, "destination_address is missing"

    if not service:
        return False, "service is missing"

    if not translated_source:
        return False, "translated_source is missing"

    if not is_valid_log_traffic(log_traffic):
        return False, "log_traffic must be yes or no"

    position_valid, position_message = validate_position(
        position_type,
        anchor_rule
    )

    if not position_valid:
        return False, position_message

    return True, "valid source NAT row"

def validate_destination_nat_row(
    vip_name,
    policy_name,
    external_interface,
    source_interface,
    destination_interface,
    source_address,
    external_ip,
    mapped_ip,
    protocol,
    external_port,
    mapped_port,
    policy_service,
    log_traffic,
    position_type,
    anchor_rule
):
    vip_name = vip_name.strip()
    policy_name = policy_name.strip()
    external_interface = external_interface.strip()
    source_interface = source_interface.strip()
    destination_interface = destination_interface.strip()
    source_address = source_address.strip()
    external_ip = external_ip.strip()
    mapped_ip = mapped_ip.strip()
    protocol = protocol.strip().lower()
    external_port = external_port.strip()
    mapped_port = mapped_port.strip()
    policy_service = policy_service.strip()
    log_traffic = log_traffic.strip().lower()

    if not vip_name:
        return False, "vip_name is missing"

    if not policy_name:
        return False, "policy_name is missing"

    if not external_interface:
        return False, "external_interface is missing"

    if not source_interface:
        return False, "source_interface is missing"

    if not destination_interface:
        return False, "destination_interface is missing"

    if not source_address:
        return False, "source_address is missing"

    if not external_ip:
        return False, "external_ip is missing"

    if not is_valid_ip_address(external_ip):
        return False, "external_ip must be a valid IP address"

    if not mapped_ip:
        return False, "mapped_ip is missing"

    if not is_valid_ip_address(mapped_ip):
        return False, "mapped_ip must be a valid IP address"

    if not protocol:
        return False, "protocol is missing"

    if not is_valid_protocol(protocol):
        return False, "protocol must be tcp or udp"

    if not external_port:
        return False, "external_port is missing"

    if not is_valid_single_port(external_port):
        return False, "external_port must be a valid port from 1 to 65535"

    if not mapped_port:
        return False, "mapped_port is missing"

    if not is_valid_single_port(mapped_port):
        return False, "mapped_port must be a valid port from 1 to 65535"

    if not policy_service:
        return False, "policy_service is missing"

    if not is_valid_log_traffic(log_traffic):
        return False, "log_traffic must be yes or no"

    position_valid, position_message = validate_position(
        position_type,
        anchor_rule
    )

    if not position_valid:
        return False, position_message

    return True, "valid destination NAT row"