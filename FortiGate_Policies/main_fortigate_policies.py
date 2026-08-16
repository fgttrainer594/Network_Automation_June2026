import csv
import sys
import logging

from validators import (
    normalize_csv_row,
    validate_policy_csv_headers,
    validate_policy_row
)

from reporting import add_policy_result, write_policy_report

from fortigate_api import (
    get_fortigate_interfaces,
    get_fortigate_zones,
    get_fortigate_address_objects,
    get_fortigate_address_groups,
    get_fortigate_service_objects,
    get_fortigate_service_groups,
    get_fortigate_policies,
    get_name_set,
    fortigate_policy_exists,
    find_missing_policy_references,
    build_fortigate_policy_payload,
    create_fortigate_policy,
    verify_fortigate_policy,
    normalize_fortigate_address_reference,
    normalize_fortigate_service_reference
)

CSV_FILE = "security_policies.csv"
REPORT_FILE = "automation_report_fortigate_policies.csv"
LOG_FILE = "automation_fortigate_policies.log"
VENDOR = "FortiGate"

logging.basicConfig(
    filename=LOG_FILE,
    filemode="w",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def log_and_print(level, message):
    print(message)

    if level == "INFO":
        logging.info(message)
    elif level == "WARNING":
        logging.warning(message)
    elif level == "ERROR":
        logging.error(message)
    elif level == "CRITICAL":
        logging.critical(message)
    else:
        logging.info(message)

policy_results = []

policies_created = 0
policies_skipped = 0
policies_failed = 0
policy_rows_invalid = 0
policy_duplicates = 0
unsupported_positions = 0
unsupported_applications = 0

log_and_print("INFO", "Starting FortiGate firewall policy automation workflow")
log_and_print("INFO", f"Policy CSV file: {CSV_FILE}")
log_and_print("INFO", f"Report file: {REPORT_FILE}")
log_and_print("INFO", "-" * 60)

# ============================================================
# PHASE 1: LOAD FORTIGATE INTERFACES AND ZONES
# ============================================================

interface_success, interfaces, interface_message = get_fortigate_interfaces()

if not interface_success:
    log_and_print("CRITICAL", "Cannot continue. Failed to load FortiGate interfaces.")
    log_and_print("CRITICAL", interface_message)

    add_policy_result(
        policy_results,
        "N/A",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        VENDOR,
        "CRITICAL",
        "ERROR",
        interface_message
    )

    write_policy_report(policy_results, REPORT_FILE)
    sys.exit()

zone_success, zones, zone_message = get_fortigate_zones()

if not zone_success:
    log_and_print("WARNING", "Could not load FortiGate zones. Continuing with interface names only.")
    log_and_print("WARNING", zone_message)
    zones = []

interface_zone_names = get_name_set(interfaces)
interface_zone_names.update(get_name_set(zones))

log_and_print("INFO", interface_message)
log_and_print("INFO", f"Interfaces/zones loaded: {len(interface_zone_names)}")
log_and_print("INFO", "-" * 60)

# ============================================================
# PHASE 2: LOAD ADDRESS OBJECTS AND ADDRESS GROUPS
# ============================================================

addr_obj_success, address_objects, addr_obj_message = get_fortigate_address_objects()

if not addr_obj_success:
    log_and_print("CRITICAL", "Cannot continue. Failed to load FortiGate address objects.")
    log_and_print("CRITICAL", addr_obj_message)

    add_policy_result(
        policy_results,
        "N/A",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        VENDOR,
        "CRITICAL",
        "ERROR",
        addr_obj_message
    )

    write_policy_report(policy_results, REPORT_FILE)
    sys.exit()

addr_grp_success, address_groups, addr_grp_message = get_fortigate_address_groups()

if not addr_grp_success:
    log_and_print("CRITICAL", "Cannot continue. Failed to load FortiGate address groups.")
    log_and_print("CRITICAL", addr_grp_message)

    add_policy_result(
        policy_results,
        "N/A",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        VENDOR,
        "CRITICAL",
        "ERROR",
        addr_grp_message
    )

    write_policy_report(policy_results, REPORT_FILE)
    sys.exit()

address_names = get_name_set(address_objects)
address_names.update(get_name_set(address_groups))

# FortiGate built-in address object
address_names.add("all")

log_and_print("INFO", addr_obj_message)
log_and_print("INFO", addr_grp_message)
log_and_print("INFO", f"Address references loaded: {len(address_names)}")
log_and_print("INFO", "-" * 60)

# ============================================================
# PHASE 3: LOAD SERVICE OBJECTS AND SERVICE GROUPS
# ============================================================

svc_obj_success, service_objects, svc_obj_message = get_fortigate_service_objects()

if not svc_obj_success:
    log_and_print("CRITICAL", "Cannot continue. Failed to load FortiGate service objects.")
    log_and_print("CRITICAL", svc_obj_message)

    add_policy_result(
        policy_results,
        "N/A",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        VENDOR,
        "CRITICAL",
        "ERROR",
        svc_obj_message
    )

    write_policy_report(policy_results, REPORT_FILE)
    sys.exit()

svc_grp_success, service_groups, svc_grp_message = get_fortigate_service_groups()

if not svc_grp_success:
    log_and_print("CRITICAL", "Cannot continue. Failed to load FortiGate service groups.")
    log_and_print("CRITICAL", svc_grp_message)

    add_policy_result(
        policy_results,
        "N/A",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        VENDOR,
        "CRITICAL",
        "ERROR",
        svc_grp_message
    )

    write_policy_report(policy_results, REPORT_FILE)
    sys.exit()

service_names = get_name_set(service_objects)
service_names.update(get_name_set(service_groups))

# Common FortiGate built-in services
service_names.update({"ALL", "HTTP", "HTTPS", "SSH", "DNS", "PING"})

log_and_print("INFO", svc_obj_message)
log_and_print("INFO", svc_grp_message)
log_and_print("INFO", f"Service references loaded: {len(service_names)}")
log_and_print("INFO", "-" * 60)

# ============================================================
# PHASE 4: LOAD EXISTING FIREWALL POLICIES
# ============================================================

policy_success, existing_policies, policy_message = get_fortigate_policies()

if not policy_success:
    log_and_print("CRITICAL", "Cannot continue. Failed to load FortiGate policies.")
    log_and_print("CRITICAL", policy_message)

    add_policy_result(
        policy_results,
        "N/A",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        VENDOR,
        "CRITICAL",
        "ERROR",
        policy_message
    )

    write_policy_report(policy_results, REPORT_FILE)
    sys.exit()

log_and_print("INFO", policy_message)
log_and_print("INFO", f"Existing firewall policies loaded: {len(existing_policies)}")
log_and_print("INFO", "-" * 60)

# ============================================================
# PHASE 5: READ POLICY CSV AND CREATE POLICIES
# ============================================================

try:
    with open(CSV_FILE, mode="r", newline="") as file:
        reader = csv.DictReader(file)

        header_valid, header_message = validate_policy_csv_headers(reader.fieldnames)

        if not header_valid:
            log_and_print("CRITICAL", "Cannot continue. Policy CSV header validation failed.")
            log_and_print("CRITICAL", header_message)

            add_policy_result(
                policy_results,
                "N/A",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                VENDOR,
                "CRITICAL",
                "ERROR",
                header_message
            )

            write_policy_report(policy_results, REPORT_FILE)
            sys.exit()

        log_and_print("INFO", header_message)
        log_and_print("INFO", "-" * 60)

        seen_policies_in_csv = set()

        for line_number, row in enumerate(reader, start=2):
            row = normalize_csv_row(row)

            policy_name = row["policy_name"]
            source_zone = row["source_zone"]
            destination_zone = row["destination_zone"]
            source_address = row["source_address"]
            destination_address = row["destination_address"]
            service = row["service"]
            application = row["application"]
            action = row["action"].lower()
            log_traffic = row["log_traffic"].lower()
            position_type = row["position_type"].lower()
            anchor_rule = row["anchor_rule"]
            description = row["description"]

            is_valid, validation_message = validate_policy_row(
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
            )

            if not is_valid:
                log_and_print(
                    "WARNING",
                    f"Line {line_number}: INVALID - {validation_message}"
                )

                add_policy_result(
                    policy_results,
                    line_number,
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
                    anchor_rule,
                    description,
                    VENDOR,
                    "INVALID_ROW",
                    "ERROR",
                    validation_message
                )

                policy_rows_invalid += 1
                continue

            if policy_name in seen_policies_in_csv:
                log_and_print(
                    "WARNING",
                    f"Line {line_number}: DUPLICATE - policy already listed in CSV: {policy_name}"
                )

                add_policy_result(
                    policy_results,
                    line_number,
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
                    anchor_rule,
                    description,
                    VENDOR,
                    "DUPLICATE_IN_CSV",
                    "WARNING",
                    "Duplicate policy name in CSV skipped"
                )

                policy_duplicates += 1
                continue

            seen_policies_in_csv.add(policy_name)

            # FortiGate beginner workflow does not use application field.
            # We require application=any for this lab.
            if application.lower() != "any":
                message = "FortiGate beginner policy workflow supports application=any only"

                log_and_print(
                    "WARNING",
                    f"Line {line_number}: UNSUPPORTED APPLICATION - {policy_name}. {message}"
                )

                add_policy_result(
                    policy_results,
                    line_number,
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
                    anchor_rule,
                    description,
                    VENDOR,
                    "UNSUPPORTED_APPLICATION",
                    "WARNING",
                    message
                )

                unsupported_applications += 1
                continue

            # Beginner workflow creates at bottom only.
            if position_type != "bottom":
                message = "Only bottom position is supported in this beginner FortiGate workflow"

                log_and_print(
                    "WARNING",
                    f"Line {line_number}: UNSUPPORTED POSITION - {policy_name}. {message}"
                )

                add_policy_result(
                    policy_results,
                    line_number,
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
                    anchor_rule,
                    description,
                    VENDOR,
                    "UNSUPPORTED_POSITION",
                    "WARNING",
                    message
                )

                unsupported_positions += 1
                continue

            normalized_source_address = normalize_fortigate_address_reference(source_address)
            normalized_destination_address = normalize_fortigate_address_reference(destination_address)
            normalized_service = normalize_fortigate_service_reference(service)

            missing_references = find_missing_policy_references(
                source_zone,
                destination_zone,
                normalized_source_address,
                normalized_destination_address,
                normalized_service,
                interface_zone_names,
                address_names,
                service_names
            )

            if missing_references:
                message = "Missing references: " + "; ".join(missing_references)

                log_and_print(
                    "ERROR",
                    f"Line {line_number}: FAILED - {policy_name}. {message}"
                )

                add_policy_result(
                    policy_results,
                    line_number,
                    policy_name,
                    source_zone,
                    destination_zone,
                    normalized_source_address,
                    normalized_destination_address,
                    normalized_service,
                    application,
                    action,
                    log_traffic,
                    position_type,
                    anchor_rule,
                    description,
                    VENDOR,
                    "FAILED_MISSING_REFERENCE",
                    "ERROR",
                    message
                )

                policies_failed += 1
                continue

            if fortigate_policy_exists(policy_name, existing_policies):
                log_and_print(
                    "WARNING",
                    f"Line {line_number}: SKIPPED - policy already exists: {policy_name}"
                )

                add_policy_result(
                    policy_results,
                    line_number,
                    policy_name,
                    source_zone,
                    destination_zone,
                    normalized_source_address,
                    normalized_destination_address,
                    normalized_service,
                    application,
                    action,
                    log_traffic,
                    position_type,
                    anchor_rule,
                    description,
                    VENDOR,
                    "SKIPPED",
                    "WARNING",
                    "Firewall policy already exists"
                )

                policies_skipped += 1
                continue

            payload = build_fortigate_policy_payload(
                policy_name,
                source_zone,
                destination_zone,
                normalized_source_address,
                normalized_destination_address,
                normalized_service,
                action,
                log_traffic,
                description
            )

            create_success, create_message = create_fortigate_policy(payload)

            if not create_success:
                log_and_print(
                    "ERROR",
                    f"Line {line_number}: FAILED - could not create policy {policy_name}"
                )
                log_and_print("ERROR", create_message)

                add_policy_result(
                    policy_results,
                    line_number,
                    policy_name,
                    source_zone,
                    destination_zone,
                    normalized_source_address,
                    normalized_destination_address,
                    normalized_service,
                    application,
                    action,
                    log_traffic,
                    position_type,
                    anchor_rule,
                    description,
                    VENDOR,
                    "FAILED",
                    "ERROR",
                    create_message
                )

                policies_failed += 1
                continue

            verify_success, policy_obj, verify_message = verify_fortigate_policy(
                policy_name
            )

            if verify_success:
                log_and_print(
                    "INFO",
                    f"Line {line_number}: CREATED - firewall policy {policy_name}"
                )

                add_policy_result(
                    policy_results,
                    line_number,
                    policy_name,
                    source_zone,
                    destination_zone,
                    normalized_source_address,
                    normalized_destination_address,
                    normalized_service,
                    application,
                    action,
                    log_traffic,
                    position_type,
                    anchor_rule,
                    description,
                    VENDOR,
                    "CREATED",
                    "SUCCESS",
                    "Firewall policy created and verified successfully"
                )

                policies_created += 1

                # Update in-memory policy list so duplicate policies in same run are skipped later
                existing_policies.append({"name": policy_name})

            else:
                log_and_print(
                    "ERROR",
                    f"Line {line_number}: VERIFICATION FAILED - policy {policy_name}"
                )
                log_and_print("ERROR", verify_message)

                add_policy_result(
                    policy_results,
                    line_number,
                    policy_name,
                    source_zone,
                    destination_zone,
                    normalized_source_address,
                    normalized_destination_address,
                    normalized_service,
                    application,
                    action,
                    log_traffic,
                    position_type,
                    anchor_rule,
                    description,
                    VENDOR,
                    "VERIFICATION_FAILED",
                    "ERROR",
                    verify_message
                )

                policies_failed += 1

            log_and_print("INFO", "-" * 60)

except FileNotFoundError:
    message = f"Policy CSV file not found: {CSV_FILE}"

    log_and_print("CRITICAL", "Cannot continue. Policy CSV file is missing.")
    log_and_print("CRITICAL", message)

    add_policy_result(
        policy_results,
        "N/A",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        VENDOR,
        "CRITICAL",
        "ERROR",
        message
    )

    write_policy_report(policy_results, REPORT_FILE)
    sys.exit()

# ============================================================
# PHASE 6: WRITE FINAL REPORT
# ============================================================

report_success, report_message = write_policy_report(
    policy_results,
    REPORT_FILE
)

if report_success:
    log_and_print("INFO", report_message)
else:
    log_and_print("ERROR", report_message)

# Final summary
log_and_print("INFO", "")
log_and_print("INFO", "Final FortiGate Firewall Policy Automation Summary")
log_and_print("INFO", "-" * 60)
log_and_print("INFO", f"Policies created: {policies_created}")
log_and_print("INFO", f"Policies skipped: {policies_skipped}")
log_and_print("INFO", f"Policies failed: {policies_failed}")
log_and_print("INFO", f"Invalid policy rows: {policy_rows_invalid}")
log_and_print("INFO", f"Duplicate policy rows skipped: {policy_duplicates}")
log_and_print("INFO", f"Unsupported positions skipped: {unsupported_positions}")
log_and_print("INFO", f"Unsupported applications skipped: {unsupported_applications}")
log_and_print("INFO", "-" * 60)
log_and_print("INFO", f"Log file: {LOG_FILE}")
log_and_print("INFO", f"Policy report file: {REPORT_FILE}")
log_and_print("INFO", "-" * 60)
log_and_print("INFO", "FortiGate firewall policy automation workflow completed")