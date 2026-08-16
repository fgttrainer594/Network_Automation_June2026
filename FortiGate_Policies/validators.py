POLICY_REQUIRED_COLUMNS = [
    "policy_name",
    "source_zone",
    "destination_zone",
    "source_address",
    "destination_address",
    "service",
    "application",
    "action",
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

def validate_policy_csv_headers(fieldnames):
    if fieldnames is None:
        return False, "CSV file is empty or header row is missing"

    cleaned_headers = []

    for header in fieldnames:
        if header is not None:
            cleaned_headers.append(header.strip())

    missing_columns = []

    for column in POLICY_REQUIRED_COLUMNS:
        if column not in cleaned_headers:
            missing_columns.append(column)

    if missing_columns:
        return False, f"Missing required CSV columns: {', '.join(missing_columns)}"

    return True, "Policy CSV headers are valid"

def is_valid_action(action):
    action = action.strip().lower()

    if action in ["allow", "deny"]:
        return True

    return False

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

def validate_policy_row(
    policy_name,
    source_zone,
    destination_zone,
    source_address,
    destination_address,
    service,
    application,
    action,
    log_traffic,
    position_type,
    anchor_rule
):
    policy_name = policy_name.strip()
    source_zone = source_zone.strip()
    destination_zone = destination_zone.strip()
    source_address = source_address.strip()
    destination_address = destination_address.strip()
    service = service.strip()
    application = application.strip()
    action = action.strip().lower()
    log_traffic = log_traffic.strip().lower()
    position_type = position_type.strip().lower()
    anchor_rule = anchor_rule.strip()

    if not policy_name:
        return False, "policy_name is missing"

    if not source_zone:
        return False, "source_zone is missing"

    if not destination_zone:
        return False, "destination_zone is missing"

    if not source_address:
        return False, "source_address is missing"

    if not destination_address:
        return False, "destination_address is missing"

    if not service:
        return False, "service is missing"

    if not application:
        return False, "application is missing"

    if not is_valid_action(action):
        return False, "action must be allow or deny"

    if not is_valid_log_traffic(log_traffic):
        return False, "log_traffic must be yes or no"

    if not is_valid_position_type(position_type):
        return False, "position_type must be bottom, before, or after"

    if position_type in ["before", "after"] and not anchor_rule:
        return False, "anchor_rule is required when position_type is before or after"

    return True, "valid row"