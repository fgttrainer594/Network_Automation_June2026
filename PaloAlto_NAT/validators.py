import ipaddress

SOURCE_NAT_REQUIRED_COLUMNS = [
    "nat_name",
    "from_zone",
    "to_zone",
    "source_address",
    "destination_address",
    "service",
    "translated_source_type",
    "translated_interface",
    "log_note",
    "position_type",
    "anchor_rule",
    "description"
]

DESTINATION_NAT_REQUIRED_COLUMNS = [
    "nat_name",
    "from_zone",
    "to_zone",
    "source_address",
    "original_destination",
    "service",
    "translated_destination",
    "translated_port",
    "log_note",
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

def is_valid_ip_address_or_any(value):
    value = value.strip().lower()

    if value == "any":
        return True

    try:
        ipaddress.ip_address(value)
        return True

    except ValueError:
        return False

def is_valid_ip_address(value):
    value = value.strip()

    try:
        ipaddress.ip_address(value)
        return True

    except ValueError:
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

def validate_source_nat_row(
    nat_name,
    from_zone,
    to_zone,
    source_address,
    destination_address,
    service,
    translated_source_type,
    translated_interface,
    position_type,
    anchor_rule
):
    nat_name = nat_name.strip()
    from_zone = from_zone.strip()
    to_zone = to_zone.strip()
    source_address = source_address.strip()
    destination_address = destination_address.strip()
    service = service.strip()
    translated_source_type = translated_source_type.strip().lower()
    translated_interface = translated_interface.strip()

    if not nat_name:
        return False, "nat_name is missing"

    if not from_zone:
        return False, "from_zone is missing"

    if not to_zone:
        return False, "to_zone is missing"

    if not source_address:
        return False, "source_address is missing"

    if not destination_address:
        return False, "destination_address is missing"

    if not service:
        return False, "service is missing"

    if not translated_source_type:
        return False, "translated_source_type is missing"

    if translated_source_type != "interface-address":
        return False, "translated_source_type must be interface-address in beginner workflow"

    if not translated_interface:
        return False, "translated_interface is missing"

    position_valid, position_message = validate_position(
        position_type,
        anchor_rule
    )

    if not position_valid:
        return False, position_message

    return True, "valid source NAT row"

def validate_destination_nat_row(
    nat_name,
    from_zone,
    to_zone,
    source_address,
    original_destination,
    service,
    translated_destination,
    translated_port,
    position_type,
    anchor_rule
):
    nat_name = nat_name.strip()
    from_zone = from_zone.strip()
    to_zone = to_zone.strip()
    source_address = source_address.strip()
    original_destination = original_destination.strip()
    service = service.strip()
    translated_destination = translated_destination.strip()
    translated_port = translated_port.strip()

    if not nat_name:
        return False, "nat_name is missing"

    if not from_zone:
        return False, "from_zone is missing"

    if not to_zone:
        return False, "to_zone is missing"

    if not source_address:
        return False, "source_address is missing"

    if not original_destination:
        return False, "original_destination is missing"

    if not is_valid_ip_address(original_destination):
        return False, "original_destination must be a valid IP address"

    if not service:
        return False, "service is missing"

    if not translated_destination:
        return False, "translated_destination is missing"

    if not is_valid_ip_address(translated_destination):
        return False, "translated_destination must be a valid IP address"

    if not translated_port:
        return False, "translated_port is missing"

    if not is_valid_single_port(translated_port):
        return False, "translated_port must be a valid port from 1 to 65535"

    position_valid, position_message = validate_position(
        position_type,
        anchor_rule
    )

    if not position_valid:
        return False, position_message

    return True, "valid destination NAT row"