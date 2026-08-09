import csv
import sys
import logging

from validators import (
    validate_csv_headers,
    normalize_csv_row,
    validate_object_row,
)

from reporting import add_result, write_report

from paloalto_api import (
    get_paloalto_address_objects,
    paloalto_object_exists,
    build_paloalto_address_payload,
    create_paloalto_address_object,
    verify_paloalto_address_object,
)


CSV_FILE = "objects.csv"
REPORT_FILE = "automation_report_paloalto.csv"
LOG_FILE = "automation_paloalto.log"
VENDOR = "Palo Alto"


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


# ---------------------------------------------------------
# Start workflow
# ---------------------------------------------------------

log_and_print(
    "INFO",
    "Starting Palo Alto integrated automation workflow",
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
# Load existing Palo Alto address objects
# ---------------------------------------------------------

success, existing_objects, message = (
    get_paloalto_address_objects()
)

if not success:
    log_and_print(
        "CRITICAL",
        "Cannot continue. Failed to load Palo Alto address objects.",
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
    f"Existing Palo Alto objects loaded: {len(existing_objects)}",
)

log_and_print(
    "INFO",
    "-" * 60,
)


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

        header_valid, header_message = validate_csv_headers(
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

            object_name = row["object_name"]
            ip_netmask = row["ip_netmask"]
            description = row["description"]


            # ---------------------------------------------
            # Validate row
            # ---------------------------------------------

            is_valid, validation_message = (
                validate_object_row(
                    object_name,
                    ip_netmask,
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
                    line_number,
                    object_name,
                    ip_netmask,
                    description,
                    VENDOR,
                    "INVALID",
                    "ERROR",
                    validation_message,
                )

                invalid_count += 1
                continue


            # ---------------------------------------------
            # Check whether object already exists
            # ---------------------------------------------

            if paloalto_object_exists(
                object_name,
                existing_objects,
            ):
                log_and_print(
                    "WARNING",
                    (
                        f"Line {line_number}: "
                        f"SKIPPED - {object_name} already exists"
                    ),
                )

                add_result(
                    results,
                    line_number,
                    object_name,
                    ip_netmask,
                    description,
                    VENDOR,
                    "SKIPPED",
                    "WARNING",
                    "Object already exists",
                )

                skipped_count += 1
                continue


            # ---------------------------------------------
            # Build Palo Alto API payload
            # ---------------------------------------------

            payload = build_paloalto_address_payload(
                object_name,
                ip_netmask
            )


            # ---------------------------------------------
            # Create address object
            # ---------------------------------------------

            create_success, create_message = (
                create_paloalto_address_object(
                    object_name,
                    payload,
                )
            )

            if not create_success:
                log_and_print(
                    "ERROR",
                    (
                        f"Line {line_number}: "
                        f"FAILED - {object_name}"
                    ),
                )

                log_and_print(
                    "ERROR",
                    create_message,
                )

                add_result(
                    results,
                    line_number,
                    object_name,
                    ip_netmask,
                    description,
                    VENDOR,
                    "FAILED",
                    "ERROR",
                    create_message,
                )

                failed_count += 1
                continue


            # ---------------------------------------------
            # Verify created object
            # ---------------------------------------------

            verify_success, obj, verify_message = (
                verify_paloalto_address_object(
                    object_name
                )
            )

            if verify_success:
                log_and_print(
                    "INFO",
                    (
                        f"Line {line_number}: "
                        f"CREATED - {object_name}"
                    ),
                )

                log_and_print(
                    "INFO",
                    (
                        "Verification SUCCESS - "
                        f"{obj.get('@name')} "
                        f"-> {obj.get('ip-netmask')}"
                    ),
                )

                add_result(
                    results,
                    line_number,
                    object_name,
                    ip_netmask,
                    description,
                    VENDOR,
                    "CREATED",
                    "SUCCESS",
                    "Object created and verified successfully",
                )

                created_count += 1

                # -----------------------------------------
                # Update in-memory object list
                #
                # This prevents duplicate object names
                # later in the same CSV from being created.
                # -----------------------------------------

                existing_objects.append(
                    {
                        "@name": object_name
                    }
                )

            else:
                log_and_print(
                    "ERROR",
                    (
                        f"Line {line_number}: "
                        f"VERIFICATION FAILED - {object_name}"
                    ),
                )

                log_and_print(
                    "ERROR",
                    verify_message,
                )

                add_result(
                    results,
                    line_number,
                    object_name,
                    ip_netmask,
                    description,
                    VENDOR,
                    "VERIFICATION_FAILED",
                    "ERROR",
                    verify_message,
                )

                failed_count += 1


            log_and_print(
                "INFO",
                "-" * 60,
            )


# ---------------------------------------------------------
# CSV file does not exist
# ---------------------------------------------------------

except FileNotFoundError:

    message = f"CSV file not found: {CSV_FILE}"

    log_and_print(
        "CRITICAL",
        "Cannot continue. CSV file is missing.",
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


# ---------------------------------------------------------
# Write final CSV report
# ---------------------------------------------------------

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
    "Final Palo Alto Summary",
)

log_and_print(
    "INFO",
    "-" * 60,
)

log_and_print(
    "INFO",
    f"Created: {created_count}",
)

log_and_print(
    "INFO",
    f"Skipped: {skipped_count}",
)

log_and_print(
    "INFO",
    f"Invalid rows: {invalid_count}",
)

log_and_print(
    "INFO",
    f"Failed: {failed_count}",
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
    "Palo Alto integrated automation workflow completed",
)