import csv


REPORT_FIELDNAMES = [
    "line_number",
    "object_name",
    "ip_netmask",
    "description",
    "vendor",
    "action",
    "status",
    "message",
]


def add_result(
    results,
    line_number,
    object_name,
    ip_netmask,
    description,
    vendor,
    action,
    status,
    message,
):
    results.append(
        {
            "line_number": line_number,
            "object_name": object_name,
            "ip_netmask": ip_netmask,
            "description": description,
            "vendor": vendor,
            "action": action,
            "status": status,
            "message": message,
        }
    )


def write_report(results, report_file):
    try:
        with open(
            report_file,
            mode="w",
            newline="",
            encoding="utf-8",
        ) as file:

            writer = csv.DictWriter(
                file,
                fieldnames=REPORT_FIELDNAMES,
            )

            writer.writeheader()

            for result in results:
                writer.writerow(result)

        return True, f"Report created: {report_file}"

    except PermissionError:
        return (
            False,
            f"Permission denied while writing report: {report_file}",
        )

    except OSError as error:
        return False, f"Report write failed: {error}"