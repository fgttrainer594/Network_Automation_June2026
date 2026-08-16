import csv
import sys
import logging

from validators import (
    normalize_csv_row,
    validate_service_csv_headers,
    validate_service_row,
    validate_service_group_csv_headers,
    validate_service_group_row
)

from reporting import (
    add_service_result,
    write_service_report,
    add_service_group_result,
    write_service_group_report
)

from fortigate_api import (
    get_fortigate_service_objects,
    get_fortigate_service_names,
    fortigate_service_exists,
    build_fortigate_service_payload,
    create_fortigate_service_object,
    verify_fortigate_service_object,
    get_fortigate_service_groups,
    fortigate_service_group_exists,
    find_missing_service_members,
    build_fortigate_service_group_payload,
    create_fortigate_service_group,
    verify_fortigate_service_group
)

SERVICE_CSV_FILE = "service_objects.csv"
SERVICE_GROUP_CSV_FILE = "service_groups.csv"

SERVICE_REPORT_FILE = "automation_report_fortigate_services.csv"
SERVICE_GROUP_REPORT_FILE = "automation_report_fortigate_service_groups.csv"

LOG_FILE = "automation_fortigate_services.log"
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

service_results = []
service_group_results = []

services_created = 0
services_skipped = 0
services_failed = 0
service_rows_invalid = 0
service_duplicates = 0

groups_created = 0
groups_skipped = 0
groups_failed = 0
group_rows_invalid = 0
group_duplicate_members = 0

log_and_print("INFO", "Starting FortiGate service automation workflow")
log_and_print("INFO", f"Service CSV file: {SERVICE_CSV_FILE}")
log_and_print("INFO", f"Service group CSV file: {SERVICE_GROUP_CSV_FILE}")
log_and_print("INFO", "-" * 60)

# ============================================================
# PHASE 1: LOAD EXISTING FORTIGATE SERVICES
# ============================================================

service_success, existing_services, service_message = get_fortigate_service_objects()

if not service_success:
    log_and_print("CRITICAL", "Cannot continue. Failed to load FortiGate service objects.")
    log_and_print("CRITICAL", service_message)

    add_service_result(
        service_results,
        "N/A",
        "",
        "",
        "",
        "",
        VENDOR,
        "CRITICAL",
        "ERROR",
        service_message
    )

    write_service_report(service_results, SERVICE_REPORT_FILE)
    sys.exit()

existing_service_names = get_fortigate_service_names(existing_services)

log_and_print("INFO", service_message)
log_and_print("INFO", f"Existing service objects loaded: {len(existing_service_names)}")
log_and_print("INFO", "-" * 60)

# ============================================================
# PHASE 2: READ SERVICE OBJECT CSV AND CREATE SERVICES
# ============================================================

try:
    with open(SERVICE_CSV_FILE, mode="r", newline="") as file:
        reader = csv.DictReader(file)

        header_valid, header_message = validate_service_csv_headers(reader.fieldnames)

        if not header_valid:
            log_and_print("CRITICAL", "Cannot continue. Service CSV header validation failed.")
            log_and_print("CRITICAL", header_message)

            add_service_result(
                service_results,
                "N/A",
                "",
                "",
                "",
                "",
                VENDOR,
                "CRITICAL",
                "ERROR",
                header_message
            )

            write_service_report(service_results, SERVICE_REPORT_FILE)
            sys.exit()

        log_and_print("INFO", header_message)
        log_and_print("INFO", "-" * 60)

        seen_services_in_csv = set()

        for line_number, row in enumerate(reader, start=2):
            row = normalize_csv_row(row)

            service_name = row["service_name"]
            protocol = row["protocol"].lower()
            destination_port = row["destination_port"]
            description = row["description"]

            is_valid, validation_message = validate_service_row(
                service_name,
                protocol,
                destination_port
            )

            if not is_valid:
                log_and_print(
                    "WARNING",
                    f"Line {line_number}: INVALID - {validation_message}"
                )

                add_service_result(
                    service_results,
                    line_number,
                    service_name,
                    protocol,
                    destination_port,
                    description,
                    VENDOR,
                    "INVALID_ROW",
                    "ERROR",
                    validation_message
                )

                service_rows_invalid += 1
                continue

            if service_name in seen_services_in_csv:
                log_and_print(
                    "WARNING",
                    f"Line {line_number}: DUPLICATE - {service_name} already listed in CSV"
                )

                add_service_result(
                    service_results,
                    line_number,
                    service_name,
                    protocol,
                    destination_port,
                    description,
                    VENDOR,
                    "DUPLICATE_IN_CSV",
                    "WARNING",
                    "Duplicate service name in CSV skipped"
                )

                service_duplicates += 1
                continue

            seen_services_in_csv.add(service_name)

            if fortigate_service_exists(service_name, existing_services):
                log_and_print(
                    "WARNING",
                    f"Line {line_number}: SKIPPED - service already exists: {service_name}"
                )

                add_service_result(
                    service_results,
                    line_number,
                    service_name,
                    protocol,
                    destination_port,
                    description,
                    VENDOR,
                    "SKIPPED",
                    "WARNING",
                    "Service object already exists"
                )

                services_skipped += 1
                continue

            payload = build_fortigate_service_payload(
                service_name,
                protocol,
                destination_port,
                description
            )

            create_success, create_message = create_fortigate_service_object(payload)

            if not create_success:
                log_and_print(
                    "ERROR",
                    f"Line {line_number}: FAILED - could not create service {service_name}"
                )
                log_and_print("ERROR", create_message)

                add_service_result(
                    service_results,
                    line_number,
                    service_name,
                    protocol,
                    destination_port,
                    description,
                    VENDOR,
                    "FAILED",
                    "ERROR",
                    create_message
                )

                services_failed += 1
                continue

            verify_success, service_obj, verify_message = verify_fortigate_service_object(
                service_name
            )

            if verify_success:
                log_and_print(
                    "INFO",
                    f"Line {line_number}: CREATED - service object {service_name}"
                )

                add_service_result(
                    service_results,
                    line_number,
                    service_name,
                    protocol,
                    destination_port,
                    description,
                    VENDOR,
                    "CREATED",
                    "SUCCESS",
                    "Service object created and verified successfully"
                )

                services_created += 1

                # Update in-memory list and name set for later service group validation
                existing_services.append({"name": service_name})
                existing_service_names.add(service_name)

            else:
                log_and_print(
                    "ERROR",
                    f"Line {line_number}: VERIFICATION FAILED - service {service_name}"
                )
                log_and_print("ERROR", verify_message)

                add_service_result(
                    service_results,
                    line_number,
                    service_name,
                    protocol,
                    destination_port,
                    description,
                    VENDOR,
                    "VERIFICATION_FAILED",
                    "ERROR",
                    verify_message
                )

                services_failed += 1

except FileNotFoundError:
    message = f"Service CSV file not found: {SERVICE_CSV_FILE}"

    log_and_print("CRITICAL", "Cannot continue. Service CSV file is missing.")
    log_and_print("CRITICAL", message)

    add_service_result(
        service_results,
        "N/A",
        "",
        "",
        "",
        "",
        VENDOR,
        "CRITICAL",
        "ERROR",
        message
    )

    write_service_report(service_results, SERVICE_REPORT_FILE)
    sys.exit()

# Write service object report
service_report_success, service_report_message = write_service_report(
    service_results,
    SERVICE_REPORT_FILE
)

if service_report_success:
    log_and_print("INFO", service_report_message)
else:
    log_and_print("ERROR", service_report_message)

log_and_print("INFO", "-" * 60)
log_and_print("INFO", "Service object phase completed")
log_and_print("INFO", "-" * 60)

# ============================================================
# PHASE 3: LOAD EXISTING FORTIGATE SERVICE GROUPS
# ============================================================

group_success, existing_groups, group_message = get_fortigate_service_groups()

if not group_success:
    log_and_print("CRITICAL", "Cannot continue. Failed to load FortiGate service groups.")
    log_and_print("CRITICAL", group_message)

    add_service_group_result(
        service_group_results,
        "N/A",
        "",
        [],
        "",
        VENDOR,
        "CRITICAL",
        "ERROR",
        group_message
    )

    write_service_group_report(service_group_results, SERVICE_GROUP_REPORT_FILE)
    sys.exit()

log_and_print("INFO", group_message)
log_and_print("INFO", f"Existing service groups loaded: {len(existing_groups)}")
log_and_print("INFO", "-" * 60)

# ============================================================
# PHASE 4: READ SERVICE GROUP CSV AND BUILD GROUP DICTIONARY
# ============================================================

service_groups = {}

try:
    with open(SERVICE_GROUP_CSV_FILE, mode="r", newline="") as file:
        reader = csv.DictReader(file)

        header_valid, header_message = validate_service_group_csv_headers(
            reader.fieldnames
        )

        if not header_valid:
            log_and_print("CRITICAL", "Cannot continue. Service group CSV header validation failed.")
            log_and_print("CRITICAL", header_message)

            add_service_group_result(
                service_group_results,
                "N/A",
                "",
                [],
                "",
                VENDOR,
                "CRITICAL",
                "ERROR",
                header_message
            )

            write_service_group_report(service_group_results, SERVICE_GROUP_REPORT_FILE)
            sys.exit()

        log_and_print("INFO", header_message)
        log_and_print("INFO", "-" * 60)

        for line_number, row in enumerate(reader, start=2):
            row = normalize_csv_row(row)

            group_name = row["group_name"]
            member_name = row["member_name"]
            description = row["description"]

            is_valid, validation_message = validate_service_group_row(
                group_name,
                member_name
            )

            if not is_valid:
                log_and_print(
                    "WARNING",
                    f"Line {line_number}: INVALID - {validation_message}"
                )

                add_service_group_result(
                    service_group_results,
                    str(line_number),
                    group_name,
                    [member_name] if member_name else [],
                    description,
                    VENDOR,
                    "INVALID_ROW",
                    "ERROR",
                    validation_message
                )

                group_rows_invalid += 1
                continue

            if group_name not in service_groups:
                service_groups[group_name] = {
                    "description": description,
                    "members": [],
                    "line_numbers": []
                }

            if member_name in service_groups[group_name]["members"]:
                log_and_print(
                    "WARNING",
                    f"Line {line_number}: DUPLICATE - {member_name} already listed in {group_name}"
                )

                add_service_group_result(
                    service_group_results,
                    str(line_number),
                    group_name,
                    [member_name],
                    description,
                    VENDOR,
                    "DUPLICATE_MEMBER",
                    "WARNING",
                    "Duplicate service group member skipped"
                )

                group_duplicate_members += 1
                continue

            service_groups[group_name]["members"].append(member_name)
            service_groups[group_name]["line_numbers"].append(str(line_number))

            log_and_print(
                "INFO",
                f"Line {line_number}: ADDED - {member_name} to {group_name}"
            )

except FileNotFoundError:
    message = f"Service group CSV file not found: {SERVICE_GROUP_CSV_FILE}"

    log_and_print("CRITICAL", "Cannot continue. Service group CSV file is missing.")
    log_and_print("CRITICAL", message)

    add_service_group_result(
        service_group_results,
        "N/A",
        "",
        [],
        "",
        VENDOR,
        "CRITICAL",
        "ERROR",
        message
    )

    write_service_group_report(service_group_results, SERVICE_GROUP_REPORT_FILE)
    sys.exit()

log_and_print("INFO", "-" * 60)
log_and_print("INFO", f"Service groups prepared from CSV: {len(service_groups)}")
log_and_print("INFO", "-" * 60)

# ============================================================
# PHASE 5: CREATE SERVICE GROUPS
# ============================================================

for group_name, group_data in service_groups.items():
    description = group_data["description"]
    members = group_data["members"]
    line_numbers = ";".join(group_data["line_numbers"])

    log_and_print("INFO", f"Processing service group: {group_name}")

    if fortigate_service_group_exists(group_name, existing_groups):
        log_and_print(
            "WARNING",
            f"SKIPPED - service group already exists: {group_name}"
        )

        add_service_group_result(
            service_group_results,
            line_numbers,
            group_name,
            members,
            description,
            VENDOR,
            "SKIPPED",
            "WARNING",
            "Service group already exists"
        )

        groups_skipped += 1
        continue

    missing_members = find_missing_service_members(
        members,
        existing_service_names
    )

    if missing_members:
        message = "Missing service objects: " + ", ".join(missing_members)

        log_and_print(
            "ERROR",
            f"FAILED - {group_name}. {message}"
        )

        add_service_group_result(
            service_group_results,
            line_numbers,
            group_name,
            members,
            description,
            VENDOR,
            "FAILED_MISSING_MEMBERS",
            "ERROR",
            message
        )

        groups_failed += 1
        continue

    payload = build_fortigate_service_group_payload(
        group_name,
        members,
        description
    )

    create_success, create_message = create_fortigate_service_group(payload)

    if not create_success:
        log_and_print(
            "ERROR",
            f"FAILED - could not create service group: {group_name}"
        )
        log_and_print("ERROR", create_message)

        add_service_group_result(
            service_group_results,
            line_numbers,
            group_name,
            members,
            description,
            VENDOR,
            "FAILED",
            "ERROR",
            create_message
        )

        groups_failed += 1
        continue

    verify_success, group_obj, verify_message = verify_fortigate_service_group(
        group_name
    )

    if verify_success:
        log_and_print(
            "INFO",
            f"CREATED - service group created and verified: {group_name}"
        )

        add_service_group_result(
            service_group_results,
            line_numbers,
            group_name,
            members,
            description,
            VENDOR,
            "CREATED",
            "SUCCESS",
            "Service group created and verified successfully"
        )

        groups_created += 1

        # Update in-memory group list so duplicate groups in same run are skipped later
        existing_groups.append({"name": group_name})

    else:
        log_and_print(
            "ERROR",
            f"VERIFICATION FAILED - service group {group_name}"
        )
        log_and_print("ERROR", verify_message)

        add_service_group_result(
            service_group_results,
            line_numbers,
            group_name,
            members,
            description,
            VENDOR,
            "VERIFICATION_FAILED",
            "ERROR",
            verify_message
        )

        groups_failed += 1

    log_and_print("INFO", "-" * 60)

# Write service group report
group_report_success, group_report_message = write_service_group_report(
    service_group_results,
    SERVICE_GROUP_REPORT_FILE
)

if group_report_success:
    log_and_print("INFO", group_report_message)
else:
    log_and_print("ERROR", group_report_message)

# Final summary
log_and_print("INFO", "")
log_and_print("INFO", "Final FortiGate Service Automation Summary")
log_and_print("INFO", "-" * 60)
log_and_print("INFO", f"Services created: {services_created}")
log_and_print("INFO", f"Services skipped: {services_skipped}")
log_and_print("INFO", f"Services failed: {services_failed}")
log_and_print("INFO", f"Invalid service rows: {service_rows_invalid}")
log_and_print("INFO", f"Duplicate service rows skipped: {service_duplicates}")
log_and_print("INFO", "-" * 60)
log_and_print("INFO", f"Service groups created: {groups_created}")
log_and_print("INFO", f"Service groups skipped: {groups_skipped}")
log_and_print("INFO", f"Service groups failed: {groups_failed}")
log_and_print("INFO", f"Invalid service group rows: {group_rows_invalid}")
log_and_print("INFO", f"Duplicate group members skipped: {group_duplicate_members}")
log_and_print("INFO", "-" * 60)
log_and_print("INFO", f"Log file: {LOG_FILE}")
log_and_print("INFO", f"Service report file: {SERVICE_REPORT_FILE}")
log_and_print("INFO", f"Service group report file: {SERVICE_GROUP_REPORT_FILE}")
log_and_print("INFO", "-" * 60)
log_and_print("INFO", "FortiGate service automation workflow completed")
