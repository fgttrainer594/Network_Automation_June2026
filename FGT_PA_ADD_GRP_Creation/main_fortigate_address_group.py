import csv
import sys
import logging

from validators import (
    validate_group_csv_headers,
    validate_group_row,
    normalize_csv_row
)

from reporting import add_group_result, write_group_report

from fortigate_api import (
    get_fortigate_address_objects,
    get_fortigate_address_object_names,
    get_fortigate_address_groups,
    fortigate_group_exists,
    find_missing_members,
    build_fortigate_address_group_payload,
    create_fortigate_address_group,
    verify_fortigate_address_group
)

CSV_FILE = "address_groups.csv"
REPORT_FILE = "automation_report_fortigate_groups.csv"
LOG_FILE = "automation_fortigate_groups.log"
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

results = []

groups_created = 0
groups_skipped = 0
groups_failed = 0
rows_invalid = 0
duplicate_members = 0

log_and_print("INFO", "Starting FortiGate address group automation")
log_and_print("INFO", f"Input CSV file: {CSV_FILE}")
log_and_print("INFO", f"Report file: {REPORT_FILE}")
log_and_print("INFO", "-" * 60)

# Critical pre-check 1: load existing address objects
object_success, existing_objects, object_message = get_fortigate_address_objects()

if not object_success:
    log_and_print("CRITICAL", "Cannot continue. Failed to load FortiGate address objects.")
    log_and_print("CRITICAL", object_message)

    add_group_result(
        results,
        "N/A",
        "",
        [],
        "",
        VENDOR,
        "CRITICAL",
        "ERROR",
        object_message
    )

    write_group_report(results, REPORT_FILE)
    sys.exit()

existing_object_names = get_fortigate_address_object_names(existing_objects)

log_and_print("INFO", object_message)
log_and_print("INFO", f"Existing address objects loaded: {len(existing_object_names)}")
log_and_print("INFO", "-" * 60)

# Critical pre-check 2: load existing address groups
group_success, existing_groups, group_message = get_fortigate_address_groups()

if not group_success:
    log_and_print("CRITICAL", "Cannot continue. Failed to load FortiGate address groups.")
    log_and_print("CRITICAL", group_message)

    add_group_result(
        results,
        "N/A",
        "",
        [],
        "",
        VENDOR,
        "CRITICAL",
        "ERROR",
        group_message
    )

    write_group_report(results, REPORT_FILE)
    sys.exit()

log_and_print("INFO", group_message)
log_and_print("INFO", f"Existing address groups loaded: {len(existing_groups)}")
log_and_print("INFO", "-" * 60)

groups = {}

try:
    with open(CSV_FILE, mode="r", newline="") as file:
        reader = csv.DictReader(file)

        header_valid, header_message = validate_group_csv_headers(reader.fieldnames)

        if not header_valid:
            log_and_print("CRITICAL", "Cannot continue. CSV header validation failed.")
            log_and_print("CRITICAL", header_message)

            add_group_result(
                results,
                "N/A",
                "",
                [],
                "",
                VENDOR,
                "CRITICAL",
                "ERROR",
                header_message
            )

            write_group_report(results, REPORT_FILE)
            sys.exit()

        log_and_print("INFO", header_message)
        log_and_print("INFO", "-" * 60)

        # Build group dictionary from CSV rows
        for line_number, row in enumerate(reader, start=2):
            row = normalize_csv_row(row)

            group_name = row["group_name"]
            member_name = row["member_name"]
            description = row["description"]

            is_valid, validation_message = validate_group_row(
                group_name,
                member_name
            )

            if not is_valid:
                log_and_print(
                    "WARNING",
                    f"Line {line_number}: INVALID - {validation_message}"
                )

                add_group_result(
                    results,
                    str(line_number),
                    group_name,
                    [member_name] if member_name else [],
                    description,
                    VENDOR,
                    "INVALID_ROW",
                    "ERROR",
                    validation_message
                )

                rows_invalid += 1
                continue

            if group_name not in groups:
                groups[group_name] = {
                    "description": description,
                    "members": [],
                    "line_numbers": []
                }

            if member_name in groups[group_name]["members"]:
                log_and_print(
                    "WARNING",
                    f"Line {line_number}: DUPLICATE - {member_name} already listed in {group_name}"
                )

                add_group_result(
                    results,
                    str(line_number),
                    group_name,
                    [member_name],
                    description,
                    VENDOR,
                    "DUPLICATE_MEMBER",
                    "WARNING",
                    "Duplicate member skipped"
                )

                duplicate_members += 1
                continue

            groups[group_name]["members"].append(member_name)
            groups[group_name]["line_numbers"].append(str(line_number))

            log_and_print(
                "INFO",
                f"Line {line_number}: ADDED - {member_name} to {group_name}"
            )

except FileNotFoundError:
    message = f"CSV file not found: {CSV_FILE}"

    log_and_print("CRITICAL", "Cannot continue. CSV file is missing.")
    log_and_print("CRITICAL", message)

    add_group_result(
        results,
        "N/A",
        "",
        [],
        "",
        VENDOR,
        "CRITICAL",
        "ERROR",
        message
    )

    write_group_report(results, REPORT_FILE)
    sys.exit()

log_and_print("INFO", "-" * 60)
log_and_print("INFO", f"Groups prepared from CSV: {len(groups)}")
log_and_print("INFO", "-" * 60)

# Process each prepared group
for group_name, group_data in groups.items():
    description = group_data["description"]
    members = group_data["members"]
    line_numbers = ";".join(group_data["line_numbers"])

    log_and_print("INFO", f"Processing group: {group_name}")

    if fortigate_group_exists(group_name, existing_groups):
        log_and_print(
            "WARNING",
            f"SKIPPED - Address group already exists: {group_name}"
        )

        add_group_result(
            results,
            line_numbers,
            group_name,
            members,
            description,
            VENDOR,
            "SKIPPED",
            "WARNING",
            "Address group already exists"
        )

        groups_skipped += 1
        continue

    missing_members = find_missing_members(
        members,
        existing_object_names
    )

    if missing_members:
        message = "Missing member objects: " + ", ".join(missing_members)

        log_and_print(
            "ERROR",
            f"FAILED - {group_name}. {message}"
        )

        add_group_result(
            results,
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

    payload = build_fortigate_address_group_payload(
        group_name,
        members,
        description
    )

    create_success, create_message = create_fortigate_address_group(payload)

    if not create_success:
        log_and_print(
            "ERROR",
            f"FAILED - Could not create address group: {group_name}"
        )
        log_and_print("ERROR", create_message)

        add_group_result(
            results,
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

    verify_success, group_obj, verify_message = verify_fortigate_address_group(
        group_name
    )

    if verify_success:
        log_and_print(
            "INFO",
            f"CREATED - Address group created and verified: {group_name}"
        )

        add_group_result(
            results,
            line_numbers,
            group_name,
            members,
            description,
            VENDOR,
            "CREATED",
            "SUCCESS",
            "Address group created and verified successfully"
        )

        groups_created += 1

        # Update in-memory group list so duplicate groups in same run are skipped later
        existing_groups.append({"name": group_name})

    else:
        log_and_print(
            "ERROR",
            f"VERIFICATION FAILED - {group_name}"
        )
        log_and_print("ERROR", verify_message)

        add_group_result(
            results,
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

# Write report
report_success, report_message = write_group_report(results, REPORT_FILE)

if report_success:
    log_and_print("INFO", report_message)
else:
    log_and_print("ERROR", report_message)

# Final summary
log_and_print("INFO", "")
log_and_print("INFO", "Final FortiGate Address Group Summary")
log_and_print("INFO", "-" * 60)
log_and_print("INFO", f"Groups created: {groups_created}")
log_and_print("INFO", f"Groups skipped: {groups_skipped}")
log_and_print("INFO", f"Groups failed: {groups_failed}")
log_and_print("INFO", f"Invalid rows: {rows_invalid}")
log_and_print("INFO", f"Duplicate members skipped: {duplicate_members}")
log_and_print("INFO", f"Log file: {LOG_FILE}")
log_and_print("INFO", f"Report file: {REPORT_FILE}")
log_and_print("INFO", "-" * 60)
log_and_print("INFO", "FortiGate address group automation completed")