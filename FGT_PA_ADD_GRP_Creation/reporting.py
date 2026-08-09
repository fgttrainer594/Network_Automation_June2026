import csv


GROUP_REPORT_FIELDNAMES = [
    "line_number",
    "group_name",
    "members",
    "member_count",
    "description",
    "vendor",
    "action",
    "status",
    "message",
]


def add_result(
    results,
    line_number,
    group_name,
    members,
    description,
    vendor,
    action,
    status,
    message
):
    if isinstance(members, list):
        members_name= ";".join(members)
        member_count= len(members)
    else:
        members_name= str(members)
        member_count=0

    results.append(
        {
            "line_number": line_number,
            "group_name": group_name,
            "members": members_name,
            "member_count": member_count,
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
            newline=""
        ) as file:

            writer = csv.DictWriter(
                file,
                fieldnames=GROUP_REPORT_FIELDNAMES,
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