import csv

POLICY_REPORT_FIELDNAMES = [
    "line_number",
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
    "description",
    "vendor",
    "result_action",
    "status",
    "message"
]

def add_policy_result(
    results,
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
    vendor,
    result_action,
    status,
    message
):
    results.append(
        {
            "line_number": line_number,
            "policy_name": policy_name,
            "source_zone": source_zone,
            "destination_zone": destination_zone,
            "source_address": source_address,
            "destination_address": destination_address,
            "service": service,
            "application": application,
            "action": action,
            "log_traffic": log_traffic,
            "position_type": position_type,
            "anchor_rule": anchor_rule,
            "description": description,
            "vendor": vendor,
            "result_action": result_action,
            "status": status,
            "message": message
        }
    )

def write_policy_report(results, report_file):
    try:
        with open(report_file, mode="w", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=POLICY_REPORT_FIELDNAMES)

            writer.writeheader()

            for result in results:
                writer.writerow(result)

        return True, f"Report created: {report_file}"

    except PermissionError:
        return False, f"Permission denied while writing report: {report_file}"

    except OSError as error:
        return False, f"Report write failed: {error}"
    