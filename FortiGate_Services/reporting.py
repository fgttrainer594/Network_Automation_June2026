import csv

SERVICE_REPORT_FIELDNAMES = [
    "line_number",
    "service_name",
    "protocol",
    "destination_port",
    "description",
    "vendor",
    "action",
    "status",
    "message"
]

SERVICE_GROUP_REPORT_FIELDNAMES = [
    "line_numbers",
    "group_name",
    "members",
    "member_count",
    "description",
    "vendor",
    "action",
    "status",
    "message"
]

def add_service_result(
    results,
    line_number,
    service_name,
    protocol,
    destination_port,
    description,
    vendor,
    action,
    status,
    message
):
    results.append(
        {
            "line_number": line_number,
            "service_name": service_name,
            "protocol": protocol,
            "destination_port": destination_port,
            "description": description,
            "vendor": vendor,
            "action": action,
            "status": status,
            "message": message
        }
    )

def write_service_report(results, report_file):
    try:
        with open(report_file, mode="w", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=SERVICE_REPORT_FIELDNAMES)

            writer.writeheader()

            for result in results:
                writer.writerow(result)

        return True, f"Report created: {report_file}"

    except PermissionError:
        return False, f"Permission denied while writing report: {report_file}"

    except OSError as error:
        return False, f"Report write failed: {error}"

def add_service_group_result(
    results,
    line_numbers,
    group_name,
    members,
    description,
    vendor,
    action,
    status,
    message
):
    if isinstance(members, list):
        members_text = ";".join(members)
        member_count = len(members)
    else:
        members_text = str(members)
        member_count = 0

    results.append(
        {
            "line_numbers": line_numbers,
            "group_name": group_name,
            "members": members_text,
            "member_count": member_count,
            "description": description,
            "vendor": vendor,
            "action": action,
            "status": status,
            "message": message
        }
    )

def write_service_group_report(results, report_file):
    try:
        with open(report_file, mode="w", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=SERVICE_GROUP_REPORT_FIELDNAMES)

            writer.writeheader()

            for result in results:
                writer.writerow(result)

        return True, f"Report created: {report_file}"

    except PermissionError:
        return False, f"Permission denied while writing report: {report_file}"

    except OSError as error:
        return False, f"Report write failed: {error}"