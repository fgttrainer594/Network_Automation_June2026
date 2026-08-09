import csv
import sys
import logging

from validators import (
    validate_csv_headers,
    normalize_csv_row,
    validate_object_row,
    validate_group_csv_header,
    validate_group_row
)

from reporting import add_result, write_report

from fortigate_api import (
    get_fortigate_address_objects,
    fortigate_object_exists,
    build_fortigate_address_payload,
    create_fortigate_address_object,
    verify_fortigate_address_object,
    get_fortigate_address_groups,
    fortigate_group_exits,
    find_missing_members,
    build_fortigate_address_group_payload,
    create_fortigate_address_group,
    verify_fortigate_address_group,
    get_fortigate_address_object_names
)


CSV_FILE = "group_objects.csv"
REPORT_FILE = "automation_AddGroup_report_fortigate.csv"
LOG_FILE = "automation_fortigate_addgroup.log"
VENDOR = "FortiGate"


# ---------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------

logging.basicConfig(
    filename=LOG_FILE,
    filemode="w",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
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


# ---------------------------------------------------------
# Result storage and counters
# ---------------------------------------------------------

results = []

created_count = 0
skipped_count = 0
invalid_count = 0
failed_count = 0
groups_created=0
groups_skipped=0
groups_failed=0
groups_invalid=0
duplicate_members=0

# ---------------------------------------------------------
# Start workflow
# ---------------------------------------------------------

log_and_print(
    "INFO",
    "Starting FortiGate address group automation workflow",
)

log_and_print(
    "INFO",
    f"Input CSV file: {CSV_FILE}",
)

log_and_print(
    "INFO",
    f"Report file: {REPORT_FILE}",
)

log_and_print(
    "INFO",
    "-" * 60,
)


# ---------------------------------------------------------
# Critical pre-check:
# Load existing FortiGate address objects
# ---------------------------------------------------------

success, existing_objects, message = (
    get_fortigate_address_objects()
)

if not success:
    log_and_print(
        "CRITICAL",
        "Cannot continue. Failed to load FortiGate address objects.",
    )

    log_and_print(
        "CRITICAL",
        message,
    )

    add_result(
        results,
        "N/A",
        "",
        "",
        "",
        VENDOR,
        "CRITICAL",
        "ERROR",
        message,
    )

    write_report(
        results,
        REPORT_FILE,
    )

    sys.exit(1)


log_and_print(
    "INFO",
    message,
)

log_and_print(
    "INFO",
    f"Existing FortiGate objects loaded: {len(existing_objects)}",
)

log_and_print(
    "INFO",
    "-" * 60,
)


group_success, existing_groups, group_message = (
    get_fortigate_address_groups()
)

if not group_success:
    log_and_print(
        "CRITICAL",
        "Cannot continue. Failed to load FortiGate address groups.",
    )

    log_and_print(
        "CRITICAL",
        message,
    )

    add_result(
        results,
        "N/A",
        "",
        "",
        "",
        VENDOR,
        "CRITICAL",
        "ERROR",
        message,
    )

    write_report(
        results,
        REPORT_FILE,
    )

    sys.exit(1)


log_and_print(
    "INFO",
    group_message,
)

log_and_print(
    "INFO",
    f"Existing FortiGate objects loaded: {len(existing_groups)}",
)

log_and_print(
    "INFO",
    "-" * 60,
)

groups ={}
# ---------------------------------------------------------
# Open and process CSV file
# ---------------------------------------------------------

try:
    with open(
        CSV_FILE,
        mode="r",
        newline="",
        encoding="utf-8-sig",
    ) as file:

        reader = csv.DictReader(file)

        # -------------------------------------------------
        # Validate CSV headers
        # -------------------------------------------------

        header_valid, header_message = validate_group_csv_header(
            reader.fieldnames
        )

        if not header_valid:
            log_and_print(
                "CRITICAL",
                "Cannot continue. CSV header validation failed.",
            )

            log_and_print(
                "CRITICAL",
                header_message,
            )

            add_result(
                results,
                "N/A",
                "",
                "",
                "",
                VENDOR,
                "CRITICAL",
                "ERROR",
                header_message,
            )

            write_report(
                results,
                REPORT_FILE,
            )

            sys.exit(1)

        log_and_print(
            "INFO",
            header_message,
        )

        log_and_print(
            "INFO",
            "-" * 60,
        )


        # -------------------------------------------------
        # Process each CSV row
        # -------------------------------------------------

        for line_number, row in enumerate(
            reader,
            start=2,
        ):

            # ---------------------------------------------
            # Normalize CSV row
            # ---------------------------------------------

            row = normalize_csv_row(row)

            group_name = row["group_name"]
            member_name = row["member_name"]
            description = row["description"]


            # ---------------------------------------------
            # Validate row
            # ---------------------------------------------

            is_valid, validation_message = (
                validate_group_row(
                    group_name,
                    member_name
                )
            )

            if not is_valid:
                log_and_print(
                    "WARNING",
                    (
                        f"Line {line_number}: "
                        f"INVALID - {validation_message}"
                    ),
                )

                add_result(
                    results,
                    str(line_number),
                    group_name,
                    [member_name] if member_name else [],
                    description,
                    VENDOR,
                    "INVALID",
                    "ERROR",
                    validation_message,
                )

                invalid_count += 1
                continue

            if group_name not in groups:
                groups[group_name]= {
                    "members": [],
                    "line_numbers":[]
                }

            if member_name in groups[group_name]["members"]:
                log_and_print("INFO", f"Line {line_number}: Added - {member_name} to {group_name}")

                add_result(
                    results,
                    "N/A",
                    "",
                    VENDOR,
                    "CRITICAL",
                    "ERROR",
                    message  
                )
                duplicate_members+=1
                continue
            groups[group_name]["members"].append(member_name)
            groups[group_name]["line_numbers"].append(str(line_number))

            log_and_print("INFO", f"Line {line_number}: ADDED- {member_name} to {group_name}")

except  FileNotFoundError:
            message= f"CSV file not found: {CSV_FILE}"

            log_and_print("CRITICAL", "cannot continue. CSV file is missing")
            log_and_print("CRITICAL", message)

            add_result(
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
            write_report(results, REPORT_FILE)
            sys.exit()

log_and_print("INFO", f"Groups prepated from CSV: {len(groups)}")
log_and_print("INFO", "-"*60)

for group_name, group_data in groups.items():
            description = group_data["description"]
            members=group_data["members"]
            line_numbers= ";".join(group_data["line_numbers"])

            if fortigate_group_exits(group_name, existing_groups):
                 log_and_print("Warning", f"SKIPPED-Address group already exists:{group_name}")

                 add_result(
                      results,
                      line_number,
                      group_name,
                      members,
                      description,
                      VENDOR,
                      "SKIPPED",
                      "WARNING",
                      "Address group already exists"
                 )
                 groups_skipped+=1
                 continue

            missing_members=find_missing_members(members, existing_objects)

            if missing_members:
                 message="Missing member objects: "+", ".join(missing_members)

                 log_and_print("ERROR", f"Failed-{group_name}.{message}")

                 add_result(
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
                 groups_failed+=1
                 continue

            payload =build_fortigate_address_group_payload(group_name, members)
            create_success, create_message = create_fortigate_address_group(payload)

            if not create_success:
                 log_and_print("ERROR", f"Failed-Could not create address group: {group_name}")
                 log_and_print("ERROR", create_message)

                 add_result(
                      results,
                      line_numbers,
                      group_name,
                      members,
                      description,
                      VENDOR,
                      "FAILED",
                      "ERROR",
                      message                      
                 )
                 groups_failed +=1
                 continue

            verify_success, group_obj, verify_message= verify_fortigate_address_group(group_name)
            if verify_success:
                 log_and_print("INFO", f"Created Address group and verified: {group_name}")

                 add_result(
                      results,
                      line_numbers,
                      group_name,
                      members,
                      description,
                      VENDOR,
                      "CREATED",
                      "SUCCESS",
                      message                        
                 )
                 groups_created+=1

                 existing_groups.append({"name": group_name})

            else:
                 log_and_print("ERROR", f"Verification Failed: {group_name}")
                 log_and_print("ERROR", verify_message)

                 add_result(
                      results,
                      line_numbers,
                      group_name,
                      members,
                      description,
                      VENDOR,
                      "VERIFICATION_FAILED",
                      "ERROR",
                      message                       
                 )
                 groups_failed+=1
            log_and_print("INFO", "-" * 60)

report_success, report_message = write_report(
    results,
    REPORT_FILE,
)

if report_success:
    log_and_print(
        "INFO",
        report_message,
    )

else:
    log_and_print(
        "ERROR",
        report_message,
    )


# ---------------------------------------------------------
# Final summary
# ---------------------------------------------------------

log_and_print(
    "INFO",
    "",
)

log_and_print(
    "INFO",
    "Final FortiGate Summary",
)

log_and_print(
    "INFO",
    "-" * 60,
)

log_and_print(
    "INFO",
    f"Created: {groups_created}",
)

log_and_print(
    "INFO",
    f"Skipped: {groups_skipped}",
)

log_and_print(
    "INFO",
    f"Invalid rows: {invalid_count}",
)

log_and_print(
    "INFO",
    f"Failed: {groups_failed}",
)

log_and_print(
    "INFO",
    f"Log file: {LOG_FILE}",
)

log_and_print(
    "INFO",
    f"Report file: {REPORT_FILE}",
)

log_and_print(
    "INFO",
    "-" * 60,
)

log_and_print(
    "INFO",
    "FortiGate integrated automation workflow completed",
)