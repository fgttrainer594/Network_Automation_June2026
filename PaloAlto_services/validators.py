SERVICE_REQUIRED_COLUMNS = [
    "service_name",
    "protocol",
    "destination_port",
    "description"
]

SERVICE_GROUP_REQUIRED_COLUMNS = [
    "group_name",
    "member_name",
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

def validate_service_csv_headers(fieldnames):
    if fieldnames is None:
        return False, "CSV file is empty or header row is missing"

    cleaned_headers = []

    for header in fieldnames:
        if header is not None:
            cleaned_headers.append(header.strip())

    missing_columns = []

    for column in SERVICE_REQUIRED_COLUMNS:
        if column not in cleaned_headers:
            missing_columns.append(column)

    if missing_columns:
        return False, f"Missing required CSV columns: {', '.join(missing_columns)}"

    return True, "Service CSV headers are valid"

def validate_service_group_csv_headers(fieldnames):
    if fieldnames is None:
        return False, "CSV file is empty or header row is missing"

    cleaned_headers = []

    for header in fieldnames:
        if header is not None:
            cleaned_headers.append(header.strip())

    missing_columns = []

    for column in SERVICE_GROUP_REQUIRED_COLUMNS:
        if column not in cleaned_headers:
            missing_columns.append(column)

    if missing_columns:
        return False, f"Missing required CSV columns: {', '.join(missing_columns)}"

    return True, "Service group CSV headers are valid"

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

def is_valid_port_or_range(destination_port):
    destination_port = destination_port.strip()

    if "-" not in destination_port:
        return is_valid_single_port(destination_port)

    parts = destination_port.split("-")

    if len(parts) != 2:
        return False

    start_port = parts[0].strip()
    end_port = parts[1].strip()

    if not is_valid_single_port(start_port):
        return False

    if not is_valid_single_port(end_port):
        return False

    if int(start_port) > int(end_port):
        return False

    return True

def validate_service_row(service_name, protocol, destination_port):
    service_name = service_name.strip()
    protocol = protocol.strip().lower()
    destination_port = destination_port.strip()

    if not service_name:
        return False, "service_name is missing"

    if not protocol:
        return False, "protocol is missing"

    if not is_valid_protocol(protocol):
        return False, "protocol must be tcp or udp"

    if not destination_port:
        return False, "destination_port is missing"

    if not is_valid_port_or_range(destination_port):
        return False, "destination_port must be a valid port or port range"

    return True, "valid row"

def validate_service_group_row(group_name, member_name):
    group_name = group_name.strip()
    member_name = member_name.strip()

    if not group_name:
        return False, "group_name is missing"

    if not member_name:
        return False, "member_name is missing"

    return True, "valid row"