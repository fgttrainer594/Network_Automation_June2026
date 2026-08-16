import ipaddress

REQUIRED_COLUMNS = ["object_name", "ip_netmask", "description"]

def validate_csv_headers(fieldnames):
    if fieldnames is None:
        return False, "CSV file is empty or header row is missing"

    cleaned_headers = []

    for header in fieldnames:
        if header is not None:
            cleaned_headers.append(header.strip())

    missing_columns = []

    for column in REQUIRED_COLUMNS:
        if column not in cleaned_headers:
            missing_columns.append(column)

    if missing_columns:
        return False, f"Missing required CSV columns: {', '.join(missing_columns)}"

    return True, "CSV headers are valid"

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

def is_valid_ip_netmask(ip_netmask):
    ip_netmask = ip_netmask.strip()

    try:
        ipaddress.ip_network(ip_netmask, strict=False)
        return True
    except ValueError:
        return False

def validate_object_row(object_name, ip_netmask):
    object_name = object_name.strip()
    ip_netmask = ip_netmask.strip()

    if not object_name:
        return False, "object_name is missing"

    if not ip_netmask:
        return False, "ip_netmask is missing"

    if not is_valid_ip_netmask(ip_netmask):
        return False, "ip_netmask format is invalid"

    return True, "valid row"

GROUP_REQUIRED_COLUMNS = ["group_name", "member_name", "description"]

def validate_group_csv_headers(fieldnames):
    if fieldnames is None:
        return False, "CSV file is empty or header row is missing"

    cleaned_headers = []

    for header in fieldnames:
        if header is not None:
            cleaned_headers.append(header.strip())

    missing_columns = []

    for column in GROUP_REQUIRED_COLUMNS:
        if column not in cleaned_headers:
            missing_columns.append(column)

    if missing_columns:
        return False, f"Missing required CSV columns: {', '.join(missing_columns)}"

    return True, "CSV headers are valid"

def validate_group_row(group_name, member_name):
    group_name = group_name.strip()
    member_name = member_name.strip()

    if not group_name:
        return False, "group_name is missing"

    if not member_name:
        return False, "member_name is missing"

    return True, "valid row"

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
