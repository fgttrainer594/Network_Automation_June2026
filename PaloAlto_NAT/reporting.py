import csv

NAT_REPORT_FIELDNAMES = [
    "line_number",
    "nat_type",
    "nat_name",
    "from_zone",
    "to_zone",
    "source_address",
    "destination_address",
    "service",
    "translated_source_type",
    "translated_interface",
    "original_destination",
    "translated_destination",
    "translated_port",
    "position_type",
    "anchor_rule",
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
    from_zone,
    to_zone,
    source_address,
    destination_address,
    service,
    translated_source_type,
    translated_interface,
    original_destination,
    translated_destination,
    translated_port,
    position_type,
    anchor_rule,
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
            "from_zone": from_zone,
            "to_zone": to_zone,
            "source_address": source_address,
            "destination_address": destination_address,
            "service": service,
            "translated_source_type": translated_source_type,
            "translated_interface": translated_interface,
            "original_destination": original_destination,
            "translated_destination": translated_destination,
            "translated_port": translated_port,
            "position_type": position_type,
            "anchor_rule": anchor_rule,
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