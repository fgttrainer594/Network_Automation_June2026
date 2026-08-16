import csv
import sys
import logging

from validators import (
    normalize_csv_row,
    validate_source_nat_csv_headers,
    validate_destination_nat_csv_headers,
    validate_source_nat_row,
    validate_destination_nat_row
)

from reporting import add_nat_result, write_nat_report

from paloalto_api import (
    get_paloalto_zones,
    get_paloalto_address_objects,
    get_paloalto_address_groups,
    get_paloalto_service_objects,
    get_paloalto_service_groups,
    get_paloalto_nat_rules,
    get_name_set,
    normalize_paloalto_address_reference,
    normalize_paloalto_service_reference,
    paloalto_nat_rule_exists,
    find_missing_nat_references,
    find_dnat_conflict,
    build_paloalto_source_nat_payload,
    build_paloalto_destination_nat_payload,
    create_paloalto_nat_rule,
    verify_paloalto_nat_rule
)

SOURCE_NAT_CSV_FILE = "source_nat_rules.csv"
DESTINATION_NAT_CSV_FILE = "destination_nat_rules.csv"

REPORT_FILE = "automation_report_paloalto_nat.csv"
LOG_FILE = "automation_paloalto_nat.log"
VENDOR = "Palo Alto"

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

nat_results = []

snat_created = 0
snat_skipped = 0
snat_failed = 0
snat_invalid = 0
snat_duplicates = 0

dnat_created = 0
dnat_skipped = 0
dnat_failed = 0
dnat_invalid = 0
dnat_duplicates = 0
dnat_conflicts = 0

unsupported_positions = 0

log_and_print("INFO", "Starting Palo Alto NAT automation workflow")
log_and_print("INFO", f"Source NAT CSV file: {SOURCE_NAT_CSV_FILE}")
log_and_print("INFO", f"Destination NAT CSV file: {DESTINATION_NAT_CSV_FILE}")
log_and_print("INFO", f"Report file: {REPORT_FILE}")
log_and_print("INFO", "-" * 60)

# ============================================================
# PHASE 1: LOAD PALO ALTO REFERENCES
# ============================================================

zone_success, zones, zone_message = get_paloalto_zones()

if not zone_success:
    log_and_print("CRITICAL", "Cannot continue. Failed to load Palo Alto zones.")
    log_and_print("CRITICAL", zone_message)
    write_nat_report(nat_results, REPORT_FILE)
    sys.exit(1)

zone_names = get_name_set(zones)
zone_names.add("any")

log_and_print("INFO", zone_message)
log_and_print("INFO", f"Zones loaded: {len(zone_names)}")
log_and_print("INFO", "-" * 60)

addr_obj_success, address_objects, addr_obj_message = get_paloalto_address_objects()

if not addr_obj_success:
    log_and_print("CRITICAL", "Cannot continue. Failed to load address objects.")
    log_and_print("CRITICAL", addr_obj_message)
    write_nat_report(nat_results, REPORT_FILE)
    sys.exit(1)

addr_grp_success, address_groups, addr_grp_message = get_paloalto_address_groups()

if not addr_grp_success:
    log_and_print("CRITICAL", "Cannot continue. Failed to load address groups.")
    log_and_print("CRITICAL", addr_grp_message)
    write_nat_report(nat_results, REPORT_FILE)
    sys.exit(1)

address_names = get_name_set(address_objects)
address_names.update(get_name_set(address_groups))
address_names.add("any")

log_and_print("INFO", addr_obj_message)
log_and_print("INFO", addr_grp_message)
log_and_print("INFO", f"Address references loaded: {len(address_names)}")
log_and_print("INFO", "-" * 60)

svc_obj_success, service_objects, svc_obj_message = get_paloalto_service_objects()

if not svc_obj_success:
    log_and_print("CRITICAL", "Cannot continue. Failed to load service objects.")
    log_and_print("CRITICAL", svc_obj_message)
    write_nat_report(nat_results, REPORT_FILE)
    sys.exit(1)

svc_grp_success, service_groups, svc_grp_message = get_paloalto_service_groups()

if not svc_grp_success:
    log_and_print("CRITICAL", "Cannot continue. Failed to load service groups.")
    log_and_print("CRITICAL", svc_grp_message)
    write_nat_report(nat_results, REPORT_FILE)
    sys.exit(1)

service_names = get_name_set(service_objects)
service_names.update(get_name_set(service_groups))
service_names.update({"any", "application-default"})

log_and_print("INFO", svc_obj_message)
log_and_print("INFO", svc_grp_message)
log_and_print("INFO", f"Service references loaded: {len(service_names)}")
log_and_print("INFO", "-" * 60)

nat_success, existing_nat_rules, nat_message = get_paloalto_nat_rules()

if not nat_success:
    log_and_print("CRITICAL", "Cannot continue. Failed to load NAT rules.")
    log_and_print("CRITICAL", nat_message)
    write_nat_report(nat_results, REPORT_FILE)
    sys.exit(1)

log_and_print("INFO", nat_message)
log_and_print("INFO", f"Existing NAT rules loaded: {len(existing_nat_rules)}")
log_and_print("INFO", "-" * 60)

# ============================================================
# PHASE 2: PROCESS SOURCE NAT RULES
# ============================================================

seen_snat_rules_in_csv = set()

try:
    with open(SOURCE_NAT_CSV_FILE, mode="r", newline="") as file:
        reader = csv.DictReader(file)

        header_valid, header_message = validate_source_nat_csv_headers(
            reader.fieldnames
        )

        if not header_valid:
            log_and_print("CRITICAL", "Cannot continue. Source NAT CSV header validation failed.")
            log_and_print("CRITICAL", header_message)
            write_nat_report(nat_results, REPORT_FILE)
            sys.exit(1)

        log_and_print("INFO", header_message)
        log_and_print("INFO", "-" * 60)

        for line_number, row in enumerate(reader, start=2):
            row = normalize_csv_row(row)

            nat_name = row["nat_name"]
            from_zone = row["from_zone"]
            to_zone = row["to_zone"]
            source_address = row["source_address"]
            destination_address = row["destination_address"]
            service = row["service"]
            translated_source_type = row["translated_source_type"].lower()
            translated_interface = row["translated_interface"]
            position_type = row["position_type"].lower()
            anchor_rule = row["anchor_rule"]
            description = row["description"]

            is_valid, validation_message = validate_source_nat_row(
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
            )

            if not is_valid:
                log_and_print("WARNING", f"Line {line_number}: INVALID SNAT - {validation_message}")

                add_nat_result(
                    nat_results,
                    line_number,
                    "SNAT",
                    nat_name,
                    from_zone,
                    to_zone,
                    source_address,
                    destination_address,
                    service,
                    translated_source_type,
                    translated_interface,
                    "",
                    "",
                    "",
                    position_type,
                    anchor_rule,
                    description,
                    VENDOR,
                    "INVALID_ROW",
                    "ERROR",
                    validation_message
                )

                snat_invalid += 1
                continue

            if nat_name in seen_snat_rules_in_csv:
                message = "Duplicate SNAT NAT rule name in CSV skipped"

                log_and_print("WARNING", f"Line {line_number}: DUPLICATE - {nat_name}")

                add_nat_result(
                    nat_results,
                    line_number,
                    "SNAT",
                    nat_name,
                    from_zone,
                    to_zone,
                    source_address,
                    destination_address,
                    service,
                    translated_source_type,
                    translated_interface,
                    "",
                    "",
                    "",
                    position_type,
                    anchor_rule,
                    description,
                    VENDOR,
                    "DUPLICATE_IN_CSV",
                    "WARNING",
                    message
                )

                snat_duplicates += 1
                continue

            seen_snat_rules_in_csv.add(nat_name)

            if position_type != "bottom":
                message = "Only bottom position is supported in beginner Palo Alto NAT workflow"

                log_and_print("WARNING", f"Line {line_number}: UNSUPPORTED POSITION - {nat_name}")

                add_nat_result(
                    nat_results,
                    line_number,
                    "SNAT",
                    nat_name,
                    from_zone,
                    to_zone,
                    source_address,
                    destination_address,
                    service,
                    translated_source_type,
                    translated_interface,
                    "",
                    "",
                    "",
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

            normalized_source_address = normalize_paloalto_address_reference(source_address)
            normalized_destination_address = normalize_paloalto_address_reference(destination_address)
            normalized_service = normalize_paloalto_service_reference(service)

            missing_references = find_missing_nat_references(
                from_zone,
                to_zone,
                normalized_source_address,
                normalized_destination_address,
                normalized_service,
                zone_names,
                address_names,
                service_names
            )

            if missing_references:
                message = "Missing references: " + "; ".join(missing_references)

                log_and_print("ERROR", f"Line {line_number}: FAILED SNAT - {nat_name}. {message}")

                add_nat_result(
                    nat_results,
                    line_number,
                    "SNAT",
                    nat_name,
                    from_zone,
                    to_zone,
                    normalized_source_address,
                    normalized_destination_address,
                    normalized_service,
                    translated_source_type,
                    translated_interface,
                    "",
                    "",
                    "",
                    position_type,
                    anchor_rule,
                    description,
                    VENDOR,
                    "FAILED_MISSING_REFERENCE",
                    "ERROR",
                    message
                )

                snat_failed += 1
                continue

            if paloalto_nat_rule_exists(nat_name, existing_nat_rules):
                message = "Source NAT rule already exists"

                log_and_print("WARNING", f"Line {line_number}: SKIPPED - {nat_name}")

                add_nat_result(
                    nat_results,
                    line_number,
                    "SNAT",
                    nat_name,
                    from_zone,
                    to_zone,
                    normalized_source_address,
                    normalized_destination_address,
                    normalized_service,
                    translated_source_type,
                    translated_interface,
                    "",
                    "",
                    "",
                    position_type,
                    anchor_rule,
                    description,
                    VENDOR,
                    "SKIPPED",
                    "WARNING",
                    message
                )

                snat_skipped += 1
                continue

            payload = build_paloalto_source_nat_payload(
                nat_name,
                from_zone,
                to_zone,
                normalized_source_address,
                normalized_destination_address,
                normalized_service,
                translated_interface,
                description
            )

            create_success, create_message = create_paloalto_nat_rule(
                nat_name,
                payload
            )

            if not create_success:
                log_and_print("ERROR", f"Line {line_number}: FAILED - could not create SNAT rule {nat_name}")
                log_and_print("ERROR", create_message)

                add_nat_result(
                    nat_results,
                    line_number,
                    "SNAT",
                    nat_name,
                    from_zone,
                    to_zone,
                    normalized_source_address,
                    normalized_destination_address,
                    normalized_service,
                    translated_source_type,
                    translated_interface,
                    "",
                    "",
                    "",
                    position_type,
                    anchor_rule,
                    description,
                    VENDOR,
                    "FAILED",
                    "ERROR",
                    create_message
                )

                snat_failed += 1
                continue

            verify_success, nat_obj, verify_message = verify_paloalto_nat_rule(nat_name)

            if verify_success:
                log_and_print("INFO", f"Line {line_number}: CREATED - SNAT rule {nat_name}")

                add_nat_result(
                    nat_results,
                    line_number,
                    "SNAT",
                    nat_name,
                    from_zone,
                    to_zone,
                    normalized_source_address,
                    normalized_destination_address,
                    normalized_service,
                    translated_source_type,
                    translated_interface,
                    "",
                    "",
                    "",
                    position_type,
                    anchor_rule,
                    description,
                    VENDOR,
                    "CREATED",
                    "SUCCESS",
                    "Source NAT rule created and verified successfully. Commit may still be required."
                )

                snat_created += 1
                existing_nat_rules.append({"@name": nat_name})

            else:
                log_and_print("ERROR", f"Line {line_number}: VERIFICATION FAILED - SNAT rule {nat_name}")
                log_and_print("ERROR", verify_message)

                add_nat_result(
                    nat_results,
                    line_number,
                    "SNAT",
                    nat_name,
                    from_zone,
                    to_zone,
                    normalized_source_address,
                    normalized_destination_address,
                    normalized_service,
                    translated_source_type,
                    translated_interface,
                    "",
                    "",
                    "",
                    position_type,
                    anchor_rule,
                    description,
                    VENDOR,
                    "VERIFICATION_FAILED",
                    "ERROR",
                    verify_message
                )

                snat_failed += 1

            log_and_print("INFO", "-" * 60)

except FileNotFoundError:
    message = f"Source NAT CSV file not found: {SOURCE_NAT_CSV_FILE}"

    log_and_print("CRITICAL", message)
    write_nat_report(nat_results, REPORT_FILE)
    sys.exit(1)

# ============================================================
# PHASE 3: PROCESS DESTINATION NAT RULES
# ============================================================

seen_dnat_rules_in_csv = set()

try:
    with open(DESTINATION_NAT_CSV_FILE, mode="r", newline="") as file:
        reader = csv.DictReader(file)

        header_valid, header_message = validate_destination_nat_csv_headers(
            reader.fieldnames
        )

        if not header_valid:
            log_and_print("CRITICAL", "Cannot continue. Destination NAT CSV header validation failed.")
            log_and_print("CRITICAL", header_message)
            write_nat_report(nat_results, REPORT_FILE)
            sys.exit(1)

        log_and_print("INFO", header_message)
        log_and_print("INFO", "-" * 60)

        for line_number, row in enumerate(reader, start=2):
            row = normalize_csv_row(row)

            nat_name = row["nat_name"]
            from_zone = row["from_zone"]
            to_zone = row["to_zone"]
            source_address = row["source_address"]
            original_destination = row["original_destination"]
            service = row["service"]
            translated_destination = row["translated_destination"]
            translated_port = row["translated_port"]
            position_type = row["position_type"].lower()
            anchor_rule = row["anchor_rule"]
            description = row["description"]

            is_valid, validation_message = validate_destination_nat_row(
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
            )

            if not is_valid:
                log_and_print("WARNING", f"Line {line_number}: INVALID DNAT - {validation_message}")

                add_nat_result(
                    nat_results,
                    line_number,
                    "DNAT",
                    nat_name,
                    from_zone,
                    to_zone,
                    source_address,
                    original_destination,
                    service,
                    "",
                    "",
                    original_destination,
                    translated_destination,
                    translated_port,
                    position_type,
                    anchor_rule,
                    description,
                    VENDOR,
                    "INVALID_ROW",
                    "ERROR",
                    validation_message
                )

                dnat_invalid += 1
                continue

            if nat_name in seen_dnat_rules_in_csv:
                message = "Duplicate DNAT NAT rule name in CSV skipped"

                log_and_print("WARNING", f"Line {line_number}: DUPLICATE - {nat_name}")

                add_nat_result(
                    nat_results,
                    line_number,
                    "DNAT",
                    nat_name,
                    from_zone,
                    to_zone,
                    source_address,
                    original_destination,
                    service,
                    "",
                    "",
                    original_destination,
                    translated_destination,
                    translated_port,
                    position_type,
                    anchor_rule,
                    description,
                    VENDOR,
                    "DUPLICATE_IN_CSV",
                    "WARNING",
                    message
                )

                dnat_duplicates += 1
                continue

            seen_dnat_rules_in_csv.add(nat_name)

            if position_type != "bottom":
                message = "Only bottom position is supported in beginner Palo Alto NAT workflow"

                log_and_print("WARNING", f"Line {line_number}: UNSUPPORTED POSITION - {nat_name}")

                add_nat_result(
                    nat_results,
                    line_number,
                    "DNAT",
                    nat_name,
                    from_zone,
                    to_zone,
                    source_address,
                    original_destination,
                    service,
                    "",
                    "",
                    original_destination,
                    translated_destination,
                    translated_port,
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

            normalized_source_address = normalize_paloalto_address_reference(source_address)
            normalized_service = normalize_paloalto_service_reference(service)

            # For DNAT original destination is an IP value, so add it temporarily as valid after IP validation.
            dnat_address_names = set(address_names)
            dnat_address_names.add(original_destination)

            missing_references = find_missing_nat_references(
                from_zone,
                to_zone,
                normalized_source_address,
                original_destination,
                normalized_service,
                zone_names,
                dnat_address_names,
                service_names
            )

            if missing_references:
                message = "Missing references: " + "; ".join(missing_references)

                log_and_print("ERROR", f"Line {line_number}: FAILED DNAT - {nat_name}. {message}")

                add_nat_result(
                    nat_results,
                    line_number,
                    "DNAT",
                    nat_name,
                    from_zone,
                    to_zone,
                    normalized_source_address,
                    original_destination,
                    normalized_service,
                    "",
                    "",
                    original_destination,
                    translated_destination,
                    translated_port,
                    position_type,
                    anchor_rule,
                    description,
                    VENDOR,
                    "FAILED_MISSING_REFERENCE",
                    "ERROR",
                    message
                )

                dnat_failed += 1
                continue

            conflicts = find_dnat_conflict(
                original_destination,
                normalized_service,
                existing_nat_rules
            )

            if conflicts:
                message = "DNAT original destination/service conflict with existing NAT rules: " + ", ".join(conflicts)

                log_and_print("ERROR", f"Line {line_number}: CONFLICT - {nat_name}. {message}")

                add_nat_result(
                    nat_results,
                    line_number,
                    "DNAT",
                    nat_name,
                    from_zone,
                    to_zone,
                    normalized_source_address,
                    original_destination,
                    normalized_service,
                    "",
                    "",
                    original_destination,
                    translated_destination,
                    translated_port,
                    position_type,
                    anchor_rule,
                    description,
                    VENDOR,
                    "FAILED_DNAT_CONFLICT",
                    "ERROR",
                    message
                )

                dnat_conflicts += 1
                continue

            if paloalto_nat_rule_exists(nat_name, existing_nat_rules):
                message = "Destination NAT rule already exists"

                log_and_print("WARNING", f"Line {line_number}: SKIPPED - {nat_name}")

                add_nat_result(
                    nat_results,
                    line_number,
                    "DNAT",
                    nat_name,
                    from_zone,
                    to_zone,
                    normalized_source_address,
                    original_destination,
                    normalized_service,
                    "",
                    "",
                    original_destination,
                    translated_destination,
                    translated_port,
                    position_type,
                    anchor_rule,
                    description,
                    VENDOR,
                    "SKIPPED",
                    "WARNING",
                    message
                )

                dnat_skipped += 1
                continue

            payload = build_paloalto_destination_nat_payload(
                nat_name,
                from_zone,
                to_zone,
                normalized_source_address,
                original_destination,
                normalized_service,
                translated_destination,
                translated_port,
                description
            )

            create_success, create_message = create_paloalto_nat_rule(
                nat_name,
                payload
            )

            if not create_success:
                log_and_print("ERROR", f"Line {line_number}: FAILED - could not create DNAT rule {nat_name}")
                log_and_print("ERROR", create_message)

                add_nat_result(
                    nat_results,
                    line_number,
                    "DNAT",
                    nat_name,
                    from_zone,
                    to_zone,
                    normalized_source_address,
                    original_destination,
                    normalized_service,
                    "",
                    "",
                    original_destination,
                    translated_destination,
                    translated_port,
                    position_type,
                    anchor_rule,
                    description,
                    VENDOR,
                    "FAILED",
                    "ERROR",
                    create_message
                )

                dnat_failed += 1
                continue

            verify_success, nat_obj, verify_message = verify_paloalto_nat_rule(nat_name)

            if verify_success:
                log_and_print("INFO", f"Line {line_number}: CREATED - DNAT rule {nat_name}")

                add_nat_result(
                    nat_results,
                    line_number,
                    "DNAT",
                    nat_name,
                    from_zone,
                    to_zone,
                    normalized_source_address,
                    original_destination,
                    normalized_service,
                    "",
                    "",
                    original_destination,
                    translated_destination,
                    translated_port,
                    position_type,
                    anchor_rule,
                    description,
                    VENDOR,
                    "CREATED",
                    "SUCCESS",
                    "Destination NAT rule created and verified successfully. Commit may still be required."
                )

                dnat_created += 1
                existing_nat_rules.append(
                    {
                        "@name": nat_name,
                        "destination": {
                            "member": [
                                original_destination
                            ]
                        },
                        "service": normalized_service
                    }
                )

            else:
                log_and_print("ERROR", f"Line {line_number}: VERIFICATION FAILED - DNAT rule {nat_name}")
                log_and_print("ERROR", verify_message)

                add_nat_result(
                    nat_results,
                    line_number,
                    "DNAT",
                    nat_name,
                    from_zone,
                    to_zone,
                    normalized_source_address,
                    original_destination,
                    normalized_service,
                    "",
                    "",
                    original_destination,
                    translated_destination,
                    translated_port,
                    position_type,
                    anchor_rule,
                    description,
                    VENDOR,
                    "VERIFICATION_FAILED",
                    "ERROR",
                    verify_message
                )

                dnat_failed += 1

            log_and_print("INFO", "-" * 60)

except FileNotFoundError:
    message = f"Destination NAT CSV file not found: {DESTINATION_NAT_CSV_FILE}"

    log_and_print("CRITICAL", message)
    write_nat_report(nat_results, REPORT_FILE)
    sys.exit(1)

# ============================================================
# PHASE 4: WRITE REPORT AND SUMMARY
# ============================================================

report_success, report_message = write_nat_report(nat_results, REPORT_FILE)

if report_success:
    log_and_print("INFO", report_message)
else:
    log_and_print("ERROR", report_message)

log_and_print("INFO", "")
log_and_print("INFO", "Final Palo Alto NAT Automation Summary")
log_and_print("INFO", "-" * 60)
log_and_print("INFO", f"SNAT rules created: {snat_created}")
log_and_print("INFO", f"SNAT rules skipped: {snat_skipped}")
log_and_print("INFO", f"SNAT rules failed: {snat_failed}")
log_and_print("INFO", f"Invalid SNAT rows: {snat_invalid}")
log_and_print("INFO", f"Duplicate SNAT rows skipped: {snat_duplicates}")
log_and_print("INFO", "-" * 60)
log_and_print("INFO", f"DNAT rules created: {dnat_created}")
log_and_print("INFO", f"DNAT rules skipped: {dnat_skipped}")
log_and_print("INFO", f"DNAT rules failed: {dnat_failed}")
log_and_print("INFO", f"Invalid DNAT rows: {dnat_invalid}")
log_and_print("INFO", f"Duplicate DNAT rows skipped: {dnat_duplicates}")
log_and_print("INFO", f"DNAT conflicts detected: {dnat_conflicts}")
log_and_print("INFO", "-" * 60)
log_and_print("INFO", f"Unsupported positions skipped: {unsupported_positions}")
log_and_print("INFO", f"Log file: {LOG_FILE}")
log_and_print("INFO", f"Report file: {REPORT_FILE}")
log_and_print("INFO", "Commit reminder: Palo Alto NAT changes may require commit before becoming active.")
log_and_print("INFO", "-" * 60)
log_and_print("INFO", "Palo Alto NAT automation workflow completed")