import csv

NAT_REPORT_FIELDNAMES = [
    "line_number",
    "nat_type",
    "nat_name",
    "policy_name",
    "source_interface",
    "destination_interface",
    "source_address",
    "destination_address",
    "service",
    "translated_source",
    "vip_name",
    "external_ip",
    "mapped_ip",
    "protocol",
    "external_port",
    "mapped_port",
    "policy_service",
    "log_traffic",
    "description",
    "vendor",
    "result_action",
    "status",
    "message"
]

def add_nat_result(
    results,
    line_number,
    nat_type,
    nat_name,
    policy_name,
    source_interface,
    destination_interface,
    source_address,
    destination_address,
    service,
    translated_source,
    vip_name,
    external_ip,
    mapped_ip,
    protocol,
    external_port,
    mapped_port,
    policy_service,
    log_traffic,
    description,
    vendor,
    result_action,
    status,
    message
):
    results.append(
        {
            "line_number": line_number,
            "nat_type": nat_type,
            "nat_name": nat_name,
            "policy_name": policy_name,
            "source_interface": source_interface,
            "destination_interface": destination_interface,
            "source_address": source_address,
            "destination_address": destination_address,
            "service": service,
            "translated_source": translated_source,
            "vip_name": vip_name,
            "external_ip": external_ip,
            "mapped_ip": mapped_ip,
            "protocol": protocol,
            "external_port": external_port,
            "mapped_port": mapped_port,
            "policy_service": policy_service,
            "log_traffic": log_traffic,
            "description": description,
            "vendor": vendor,
            "result_action": result_action,
            "status": status,
            "message": message
        }
    )

def write_nat_report(results, report_file):
    try:
        with open(report_file, mode="w", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=NAT_REPORT_FIELDNAMES)

            writer.writeheader()

            for result in results:
                writer.writerow(result)

        return True, f"Report created: {report_file}"

    except PermissionError:
        return False, f"Permission denied while writing report: {report_file}"

    except OSError as error:
        return False, f"Report write failed: {error}"