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

from fortigate_api import (
    get_fortigate_interfaces,
    get_fortigate_address_objects,
    get_fortigate_address_groups,
    get_fortigate_service_objects,
    get_fortigate_service_groups,
    get_fortigate_ippools,
    get_fortigate_vips,
    get_fortigate_policies,
    get_name_set,
    normalize_fortigate_address_reference,
    normalize_fortigate_service_reference,
    fortigate_policy_exists,
    fortigate_vip_exists,
    find_vip_port_conflict,
    find_missing_snat_references,
    find_missing_dnat_references,
    build_fortigate_snat_policy_payload,
    build_fortigate_vip_payload,
    build_fortigate_dnat_policy_payload,
    create_fortigate_policy,
    create_fortigate_vip,
    verify_fortigate_policy,
    verify_fortigate_vip
)

SOURCE_NAT_CSV_FILE = "source_nat_rules.csv"
DESTINATION_NAT_CSV_FILE = "destination_nat_rules.csv"

REPORT_FILE = "automation_report_fortigate_nat.csv"
LOG_FILE = "automation_fortigate_nat.log"
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

nat_results = []

snat_created = 0
snat_skipped = 0
snat_failed = 0
snat_invalid = 0
snat_duplicates = 0

vip_created = 0
vip_skipped = 0
vip_failed = 0

dnat_policy_created = 0
dnat_policy_skipped = 0
dnat_policy_failed = 0
dnat_invalid = 0
dnat_duplicates = 0
dnat_conflicts = 0

unsupported_positions = 0

log_and_print("INFO", "Starting FortiGate NAT automation workflow")
log_and_print("INFO", f"Source NAT CSV file: {SOURCE_NAT_CSV_FILE}")
log_and_print("INFO", f"Destination NAT CSV file: {DESTINATION_NAT_CSV_FILE}")
log_and_print("INFO", f"Report file: {REPORT_FILE}")
log_and_print("INFO", "-" * 60)

# ============================================================
# PHASE 1: LOAD FORTIGATE REFERENCES
# ============================================================

interface_success, interfaces, interface_message = get_fortigate_interfaces()

if not interface_success:
    log_and_print("CRITICAL", "Cannot continue. Failed to load FortiGate interfaces.")
    log_and_print("CRITICAL", interface_message)

    add_nat_result(
        nat_results,
        "N/A",
        "SYSTEM",
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

    write_nat_report(nat_results, REPORT_FILE)
    sys.exit(1)

interface_names = get_name_set(interfaces)

log_and_print("INFO", interface_message)
log_and_print("INFO", f"Interfaces loaded: {len(interface_names)}")
log_and_print("INFO", "-" * 60)

addr_obj_success, address_objects, addr_obj_message = get_fortigate_address_objects()

if not addr_obj_success:
    log_and_print("CRITICAL", "Cannot continue. Failed to load address objects.")
    log_and_print("CRITICAL", addr_obj_message)
    write_nat_report(nat_results, REPORT_FILE)
    sys.exit(1)

addr_grp_success, address_groups, addr_grp_message = get_fortigate_address_groups()

if not addr_grp_success:
    log_and_print("CRITICAL", "Cannot continue. Failed to load address groups.")
    log_and_print("CRITICAL", addr_grp_message)
    write_nat_report(nat_results, REPORT_FILE)
    sys.exit(1)

address_names = get_name_set(address_objects)
address_names.update(get_name_set(address_groups))
address_names.add("all")

log_and_print("INFO", addr_obj_message)
log_and_print("INFO", addr_grp_message)
log_and_print("INFO", f"Address references loaded: {len(address_names)}")
log_and_print("INFO", "-" * 60)

svc_obj_success, service_objects, svc_obj_message = get_fortigate_service_objects()

if not svc_obj_success:
    log_and_print("CRITICAL", "Cannot continue. Failed to load service objects.")
    log_and_print("CRITICAL", svc_obj_message)
    write_nat_report(nat_results, REPORT_FILE)
    sys.exit(1)

svc_grp_success, service_groups, svc_grp_message = get_fortigate_service_groups()

if not svc_grp_success:
    log_and_print("CRITICAL", "Cannot continue. Failed to load service groups.")
    log_and_print("CRITICAL", svc_grp_message)
    write_nat_report(nat_results, REPORT_FILE)
    sys.exit(1)

service_names = get_name_set(service_objects)
service_names.update(get_name_set(service_groups))
service_names.update({"ALL", "HTTP", "HTTPS", "SSH", "DNS", "PING"})

log_and_print("INFO", svc_obj_message)
log_and_print("INFO", svc_grp_message)
log_and_print("INFO", f"Service references loaded: {len(service_names)}")
log_and_print("INFO", "-" * 60)

ippool_success, ippools, ippool_message = get_fortigate_ippools()

if not ippool_success:
    log_and_print("CRITICAL", "Cannot continue. Failed to load IP pools.")
    log_and_print("CRITICAL", ippool_message)
    write_nat_report(nat_results, REPORT_FILE)
    sys.exit(1)

ippool_names = get_name_set(ippools)

log_and_print("INFO", ippool_message)
log_and_print("INFO", f"IP pools loaded: {len(ippool_names)}")
log_and_print("INFO", "-" * 60)

vip_success, existing_vips, vip_message = get_fortigate_vips()

if not vip_success:
    log_and_print("CRITICAL", "Cannot continue. Failed to load VIPs.")
    log_and_print("CRITICAL", vip_message)
    write_nat_report(nat_results, REPORT_FILE)
    sys.exit(1)

log_and_print("INFO", vip_message)
log_and_print("INFO", f"VIPs loaded: {len(existing_vips)}")
log_and_print("INFO", "-" * 60)

policy_success, existing_policies, policy_message = get_fortigate_policies()

if not policy_success:
    log_and_print("CRITICAL", "Cannot continue. Failed to load firewall policies.")
    log_and_print("CRITICAL", policy_message)
    write_nat_report(nat_results, REPORT_FILE)
    sys.exit(1)

log_and_print("INFO", policy_message)
log_and_print("INFO", f"Firewall policies loaded: {len(existing_policies)}")
log_and_print("INFO", "-" * 60)

# ============================================================
# PHASE 2: PROCESS SOURCE NAT POLICIES
# ============================================================

seen_snat_policies_in_csv = set()

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

            policy_name = row["policy_name"]
            source_interface = row["source_interface"]
            destination_interface = row["destination_interface"]
            source_address = row["source_address"]
            destination_address = row["destination_address"]
            service = row["service"]
            translated_source = row["translated_source"]
            log_traffic = row["log_traffic"].lower()
            position_type = row["position_type"].lower()
            anchor_rule = row["anchor_rule"]
            description = row["description"]

            is_valid, validation_message = validate_source_nat_row(
                policy_name,
                source_interface,
                destination_interface,
                source_address,
                destination_address,
                service,
                translated_source,
                log_traffic,
                position_type,
                anchor_rule
            )

            if not is_valid:
                log_and_print("WARNING", f"Line {line_number}: INVALID SNAT - {validation_message}")

                add_nat_result(
                    nat_results,
                    line_number,
                    "SNAT",
                    policy_name,
                    policy_name,
                    source_interface,
                    destination_interface,
                    source_address,
                    destination_address,
                    service,
                    translated_source,
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    log_traffic,
                    description,
                    VENDOR,
                    "INVALID_ROW",
                    "ERROR",
                    validation_message
                )

                snat_invalid += 1
                continue

            if policy_name in seen_snat_policies_in_csv:
                message = "Duplicate SNAT policy name in CSV skipped"

                log_and_print("WARNING", f"Line {line_number}: DUPLICATE - {policy_name}")

                add_nat_result(
                    nat_results,
                    line_number,
                    "SNAT",
                    policy_name,
                    policy_name,
                    source_interface,
                    destination_interface,
                    source_address,
                    destination_address,
                    service,
                    translated_source,
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    log_traffic,
                    description,
                    VENDOR,
                    "DUPLICATE_IN_CSV",
                    "WARNING",
                    message
                )

                snat_duplicates += 1
                continue

            seen_snat_policies_in_csv.add(policy_name)

            if position_type != "bottom":
                message = "Only bottom position is supported in beginner NAT workflow"

                log_and_print("WARNING", f"Line {line_number}: UNSUPPORTED POSITION - {policy_name}")

                add_nat_result(
                    nat_results,
                    line_number,
                    "SNAT",
                    policy_name,
                    policy_name,
                    source_interface,
                    destination_interface,
                    source_address,
                    destination_address,
                    service,
                    translated_source,
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    log_traffic,
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

            missing_references = find_missing_snat_references(
                source_interface,
                destination_interface,
                normalized_source_address,
                normalized_destination_address,
                normalized_service,
                translated_source,
                interface_names,
                address_names,
                service_names,
                ippool_names
            )

            if missing_references:
                message = "Missing references: " + "; ".join(missing_references)

                log_and_print("ERROR", f"Line {line_number}: FAILED SNAT - {policy_name}. {message}")

                add_nat_result(
                    nat_results,
                    line_number,
                    "SNAT",
                    policy_name,
                    policy_name,
                    source_interface,
                    destination_interface,
                    normalized_source_address,
                    normalized_destination_address,
                    normalized_service,
                    translated_source,
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    log_traffic,
                    description,
                    VENDOR,
                    "FAILED_MISSING_REFERENCE",
                    "ERROR",
                    message
                )

                snat_failed += 1
                continue

            if fortigate_policy_exists(policy_name, existing_policies):
                message = "SNAT firewall policy already exists"

                log_and_print("WARNING", f"Line {line_number}: SKIPPED - {policy_name}")

                add_nat_result(
                    nat_results,
                    line_number,
                    "SNAT",
                    policy_name,
                    policy_name,
                    source_interface,
                    destination_interface,
                    normalized_source_address,
                    normalized_destination_address,
                    normalized_service,
                    translated_source,
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    log_traffic,
                    description,
                    VENDOR,
                    "SKIPPED",
                    "WARNING",
                    message
                )

                snat_skipped += 1
                continue

            payload = build_fortigate_snat_policy_payload(
                policy_name,
                source_interface,
                destination_interface,
                normalized_source_address,
                normalized_destination_address,
                normalized_service,
                translated_source,
                log_traffic,
                description
            )

            create_success, create_message = create_fortigate_policy(payload)

            if not create_success:
                log_and_print("ERROR", f"Line {line_number}: FAILED - could not create SNAT policy {policy_name}")
                log_and_print("ERROR", create_message)

                add_nat_result(
                    nat_results,
                    line_number,
                    "SNAT",
                    policy_name,
                    policy_name,
                    source_interface,
                    destination_interface,
                    normalized_source_address,
                    normalized_destination_address,
                    normalized_service,
                    translated_source,
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    log_traffic,
                    description,
                    VENDOR,
                    "FAILED",
                    "ERROR",
                    create_message
                )

                snat_failed += 1
                continue

            verify_success, policy_obj, verify_message = verify_fortigate_policy(policy_name)

            if verify_success:
                log_and_print("INFO", f"Line {line_number}: CREATED - SNAT policy {policy_name}")

                add_nat_result(
                    nat_results,
                    line_number,
                    "SNAT",
                    policy_name,
                    policy_name,
                    source_interface,
                    destination_interface,
                    normalized_source_address,
                    normalized_destination_address,
                    normalized_service,
                    translated_source,
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    log_traffic,
                    description,
                    VENDOR,
                    "CREATED",
                    "SUCCESS",
                    "SNAT firewall policy created and verified successfully"
                )

                snat_created += 1
                existing_policies.append({"name": policy_name})

            else:
                log_and_print("ERROR", f"Line {line_number}: VERIFICATION FAILED - SNAT policy {policy_name}")
                log_and_print("ERROR", verify_message)

                add_nat_result(
                    nat_results,
                    line_number,
                    "SNAT",
                    policy_name,
                    policy_name,
                    source_interface,
                    destination_interface,
                    normalized_source_address,
                    normalized_destination_address,
                    normalized_service,
                    translated_source,
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    log_traffic,
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
# PHASE 3: PROCESS DESTINATION NAT / VIP RULES
# ============================================================

seen_vips_in_csv = set()
seen_dnat_policies_in_csv = set()

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

            vip_name = row["vip_name"]
            policy_name = row["policy_name"]
            external_interface = row["external_interface"]
            source_interface = row["source_interface"]
            destination_interface = row["destination_interface"]
            source_address = row["source_address"]
            external_ip = row["external_ip"]
            mapped_ip = row["mapped_ip"]
            protocol = row["protocol"].lower()
            external_port = row["external_port"]
            mapped_port = row["mapped_port"]
            policy_service = row["policy_service"]
            log_traffic = row["log_traffic"].lower()
            position_type = row["position_type"].lower()
            anchor_rule = row["anchor_rule"]
            description = row["description"]

            is_valid, validation_message = validate_destination_nat_row(
                vip_name,
                policy_name,
                external_interface,
                source_interface,
                destination_interface,
                source_address,
                external_ip,
                mapped_ip,
                protocol,
                external_port,
                mapped_port,
                policy_service,
                log_traffic,
                position_type,
                anchor_rule
            )

            if not is_valid:
                log_and_print("WARNING", f"Line {line_number}: INVALID DNAT - {validation_message}")

                add_nat_result(
                    nat_results,
                    line_number,
                    "DNAT",
                    vip_name,
                    policy_name,
                    source_interface,
                    destination_interface,
                    source_address,
                    "",
                    "",
                    "",
                    vip_name,
                    external_ip,
                    mapped_ip,
                    protocol,
                    external_port,
                    mapped_port,
                    policy_service,
                    log_traffic,
                    description,
                    VENDOR,
                    "INVALID_ROW",
                    "ERROR",
                    validation_message
                )

                dnat_invalid += 1
                continue

            if vip_name in seen_vips_in_csv or policy_name in seen_dnat_policies_in_csv:
                message = "Duplicate VIP name or DNAT policy name in CSV skipped"

                log_and_print("WARNING", f"Line {line_number}: DUPLICATE - {vip_name} or {policy_name}")

                add_nat_result(
                    nat_results,
                    line_number,
                    "DNAT",
                    vip_name,
                    policy_name,
                    source_interface,
                    destination_interface,
                    source_address,
                    "",
                    "",
                    "",
                    vip_name,
                    external_ip,
                    mapped_ip,
                    protocol,
                    external_port,
                    mapped_port,
                    policy_service,
                    log_traffic,
                    description,
                    VENDOR,
                    "DUPLICATE_IN_CSV",
                    "WARNING",
                    message
                )

                dnat_duplicates += 1
                continue

            seen_vips_in_csv.add(vip_name)
            seen_dnat_policies_in_csv.add(policy_name)

            if position_type != "bottom":
                message = "Only bottom position is supported in beginner NAT workflow"

                log_and_print("WARNING", f"Line {line_number}: UNSUPPORTED POSITION - {policy_name}")

                add_nat_result(
                    nat_results,
                    line_number,
                    "DNAT",
                    vip_name,
                    policy_name,
                    source_interface,
                    destination_interface,
                    source_address,
                    "",
                    "",
                    "",
                    vip_name,
                    external_ip,
                    mapped_ip,
                    protocol,
                    external_port,
                    mapped_port,
                    policy_service,
                    log_traffic,
                    description,
                    VENDOR,
                    "UNSUPPORTED_POSITION",
                    "WARNING",
                    message
                )

                unsupported_positions += 1
                continue

            normalized_source_address = normalize_fortigate_address_reference(source_address)
            normalized_policy_service = normalize_fortigate_service_reference(policy_service)

            missing_references = find_missing_dnat_references(
                external_interface,
                source_interface,
                destination_interface,
                normalized_source_address,
                normalized_policy_service,
                interface_names,
                address_names,
                service_names
            )

            if missing_references:
                message = "Missing references: " + "; ".join(missing_references)

                log_and_print("ERROR", f"Line {line_number}: FAILED DNAT - {vip_name}. {message}")

                add_nat_result(
                    nat_results,
                    line_number,
                    "DNAT",
                    vip_name,
                    policy_name,
                    source_interface,
                    destination_interface,
                    normalized_source_address,
                    "",
                    "",
                    "",
                    vip_name,
                    external_ip,
                    mapped_ip,
                    protocol,
                    external_port,
                    mapped_port,
                    normalized_policy_service,
                    log_traffic,
                    description,
                    VENDOR,
                    "FAILED_MISSING_REFERENCE",
                    "ERROR",
                    message
                )

                dnat_policy_failed += 1
                continue

            conflicts = find_vip_port_conflict(
                external_ip,
                protocol,
                external_port,
                existing_vips
            )

            if conflicts:
                message = "VIP public IP/port conflict with existing VIPs: " + ", ".join(conflicts)

                log_and_print("ERROR", f"Line {line_number}: CONFLICT - {vip_name}. {message}")

                add_nat_result(
                    nat_results,
                    line_number,
                    "DNAT",
                    vip_name,
                    policy_name,
                    source_interface,
                    destination_interface,
                    normalized_source_address,
                    "",
                    "",
                    "",
                    vip_name,
                    external_ip,
                    mapped_ip,
                    protocol,
                    external_port,
                    mapped_port,
                    normalized_policy_service,
                    log_traffic,
                    description,
                    VENDOR,
                    "FAILED_VIP_CONFLICT",
                    "ERROR",
                    message
                )

                dnat_conflicts += 1
                continue

            vip_already_exists = fortigate_vip_exists(vip_name, existing_vips)
            policy_already_exists = fortigate_policy_exists(policy_name, existing_policies)

            if vip_already_exists:
                message = "VIP already exists. Beginner workflow will not update existing VIP."

                log_and_print("WARNING", f"Line {line_number}: SKIPPED VIP - {vip_name}")

                add_nat_result(
                    nat_results,
                    line_number,
                    "DNAT",
                    vip_name,
                    policy_name,
                    source_interface,
                    destination_interface,
                    normalized_source_address,
                    "",
                    "",
                    "",
                    vip_name,
                    external_ip,
                    mapped_ip,
                    protocol,
                    external_port,
                    mapped_port,
                    normalized_policy_service,
                    log_traffic,
                    description,
                    VENDOR,
                    "SKIPPED_VIP",
                    "WARNING",
                    message
                )

                vip_skipped += 1

            else:
                vip_payload = build_fortigate_vip_payload(
                    vip_name,
                    external_interface,
                    external_ip,
                    mapped_ip,
                    protocol,
                    external_port,
                    mapped_port,
                    description
                )

                vip_create_success, vip_create_message = create_fortigate_vip(vip_payload)

                if not vip_create_success:
                    log_and_print("ERROR", f"Line {line_number}: FAILED - could not create VIP {vip_name}")
                    log_and_print("ERROR", vip_create_message)

                    add_nat_result(
                        nat_results,
                        line_number,
                        "DNAT",
                        vip_name,
                        policy_name,
                        source_interface,
                        destination_interface,
                        normalized_source_address,
                        "",
                        "",
                        "",
                        vip_name,
                        external_ip,
                        mapped_ip,
                        protocol,
                        external_port,
                        mapped_port,
                        normalized_policy_service,
                        log_traffic,
                        description,
                        VENDOR,
                        "FAILED_VIP_CREATE",
                        "ERROR",
                        vip_create_message
                    )

                    vip_failed += 1
                    dnat_policy_failed += 1
                    continue

                vip_verify_success, vip_obj, vip_verify_message = verify_fortigate_vip(vip_name)

                if vip_verify_success:
                    log_and_print("INFO", f"Line {line_number}: CREATED - VIP {vip_name}")

                    add_nat_result(
                        nat_results,
                        line_number,
                        "DNAT",
                        vip_name,
                        policy_name,
                        source_interface,
                        destination_interface,
                        normalized_source_address,
                        "",
                        "",
                        "",
                        vip_name,
                        external_ip,
                        mapped_ip,
                        protocol,
                        external_port,
                        mapped_port,
                        normalized_policy_service,
                        log_traffic,
                        description,
                        VENDOR,
                        "CREATED_VIP",
                        "SUCCESS",
                        "VIP created and verified successfully"
                    )

                    vip_created += 1
                    existing_vips.append(
                        {
                            "name": vip_name,
                            "extip": external_ip,
                            "protocol": protocol,
                            "extport": external_port,
                            "portforward": "enable"
                        }
                    )

                    # VIP can now be referenced as a destination address
                    address_names.add(vip_name)

                else:
                    log_and_print("ERROR", f"Line {line_number}: VERIFICATION FAILED - VIP {vip_name}")
                    log_and_print("ERROR", vip_verify_message)

                    add_nat_result(
                        nat_results,
                        line_number,
                        "DNAT",
                        vip_name,
                        policy_name,
                        source_interface,
                        destination_interface,
                        normalized_source_address,
                        "",
                        "",
                        "",
                        vip_name,
                        external_ip,
                        mapped_ip,
                        protocol,
                        external_port,
                        mapped_port,
                        normalized_policy_service,
                        log_traffic,
                        description,
                        VENDOR,
                        "VERIFICATION_FAILED_VIP",
                        "ERROR",
                        vip_verify_message
                    )

                    vip_failed += 1
                    dnat_policy_failed += 1
                    continue

            if policy_already_exists:
                message = "DNAT firewall policy already exists"

                log_and_print("WARNING", f"Line {line_number}: SKIPPED POLICY - {policy_name}")

                add_nat_result(
                    nat_results,
                    line_number,
                    "DNAT",
                    vip_name,
                    policy_name,
                    source_interface,
                    destination_interface,
                    normalized_source_address,
                    vip_name,
                    normalized_policy_service,
                    "",
                    vip_name,
                    external_ip,
                    mapped_ip,
                    protocol,
                    external_port,
                    mapped_port,
                    normalized_policy_service,
                    log_traffic,
                    description,
                    VENDOR,
                    "SKIPPED_POLICY",
                    "WARNING",
                    message
                )

                dnat_policy_skipped += 1
                continue

            dnat_policy_payload = build_fortigate_dnat_policy_payload(
                policy_name,
                source_interface,
                destination_interface,
                normalized_source_address,
                vip_name,
                normalized_policy_service,
                log_traffic,
                description
            )

            policy_create_success, policy_create_message = create_fortigate_policy(
                dnat_policy_payload
            )

            if not policy_create_success:
                log_and_print("ERROR", f"Line {line_number}: FAILED - could not create DNAT policy {policy_name}")
                log_and_print("ERROR", policy_create_message)

                add_nat_result(
                    nat_results,
                    line_number,
                    "DNAT",
                    vip_name,
                    policy_name,
                    source_interface,
                    destination_interface,
                    normalized_source_address,
                    vip_name,
                    normalized_policy_service,
                    "",
                    vip_name,
                    external_ip,
                    mapped_ip,
                    protocol,
                    external_port,
                    mapped_port,
                    normalized_policy_service,
                    log_traffic,
                    description,
                    VENDOR,
                    "FAILED_POLICY_CREATE",
                    "ERROR",
                    policy_create_message
                )

                dnat_policy_failed += 1
                continue

            policy_verify_success, policy_obj, policy_verify_message = verify_fortigate_policy(
                policy_name
            )

            if policy_verify_success:
                log_and_print("INFO", f"Line {line_number}: CREATED - DNAT policy {policy_name}")

                add_nat_result(
                    nat_results,
                    line_number,
                    "DNAT",
                    vip_name,
                    policy_name,
                    source_interface,
                    destination_interface,
                    normalized_source_address,
                    vip_name,
                    normalized_policy_service,
                    "",
                    vip_name,
                    external_ip,
                    mapped_ip,
                    protocol,
                    external_port,
                    mapped_port,
                    normalized_policy_service,
                    log_traffic,
                    description,
                    VENDOR,
                    "CREATED_POLICY",
                    "SUCCESS",
                    "DNAT VIP and firewall policy created/verified successfully"
                )

                dnat_policy_created += 1
                existing_policies.append({"name": policy_name})

            else:
                log_and_print("ERROR", f"Line {line_number}: VERIFICATION FAILED - DNAT policy {policy_name}")
                log_and_print("ERROR", policy_verify_message)

                add_nat_result(
                    nat_results,
                    line_number,
                    "DNAT",
                    vip_name,
                    policy_name,
                    source_interface,
                    destination_interface,
                    normalized_source_address,
                    vip_name,
                    normalized_policy_service,
                    "",
                    vip_name,
                    external_ip,
                    mapped_ip,
                    protocol,
                    external_port,
                    mapped_port,
                    normalized_policy_service,
                    log_traffic,
                    description,
                    VENDOR,
                    "VERIFICATION_FAILED_POLICY",
                    "ERROR",
                    policy_verify_message
                )

                dnat_policy_failed += 1

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
log_and_print("INFO", "Final FortiGate NAT Automation Summary")
log_and_print("INFO", "-" * 60)
log_and_print("INFO", f"SNAT policies created: {snat_created}")
log_and_print("INFO", f"SNAT policies skipped: {snat_skipped}")
log_and_print("INFO", f"SNAT policies failed: {snat_failed}")
log_and_print("INFO", f"Invalid SNAT rows: {snat_invalid}")
log_and_print("INFO", f"Duplicate SNAT rows skipped: {snat_duplicates}")
log_and_print("INFO", "-" * 60)
log_and_print("INFO", f"VIPs created: {vip_created}")
log_and_print("INFO", f"VIPs skipped: {vip_skipped}")
log_and_print("INFO", f"VIPs failed: {vip_failed}")
log_and_print("INFO", f"DNAT policies created: {dnat_policy_created}")
log_and_print("INFO", f"DNAT policies skipped: {dnat_policy_skipped}")
log_and_print("INFO", f"DNAT policies failed: {dnat_policy_failed}")
log_and_print("INFO", f"Invalid DNAT rows: {dnat_invalid}")
log_and_print("INFO", f"Duplicate DNAT rows skipped: {dnat_duplicates}")
log_and_print("INFO", f"VIP conflicts detected: {dnat_conflicts}")
log_and_print("INFO", "-" * 60)
log_and_print("INFO", f"Unsupported positions skipped: {unsupported_positions}")
log_and_print("INFO", f"Log file: {LOG_FILE}")
log_and_print("INFO", f"Report file: {REPORT_FILE}")
log_and_print("INFO", "-" * 60)
log_and_print("INFO", "FortiGate NAT automation workflow completed")