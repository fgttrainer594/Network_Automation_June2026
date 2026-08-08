import ipaddress
import csv 
import logging
import sys

CSV_File = "objectss.csv"

REQUIRED_COLUMNS = [
    "object_name",
    "ip_netmask"
]

logging.basicConfig(
    level=logging.DEBUG,
    filename="logging.log",
    format="%(asctime)s, %(levelname)s, %(message)s"
)

def log_and_print(level,message):
    print (message)
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

def validate_csv_headers(fieldnames):
    if fieldnames is None:
        return False, "CSV file is empty or header row is missing"

    cleaned_headers = []

    for header in fieldnames:
        cleaned_headers.append(header.strip())

    missing_columns = []

    for column in REQUIRED_COLUMNS:
        if column not in cleaned_headers:
            missing_columns.append(column)

    if missing_columns:
        return (
            False,
            f"Missing required CSV columns: {', '.join(missing_columns)}",
        )

    return True, "CSV headers are valid"


def is_valid_ip_netmask(ip_netmask):
    ip_netmask = ip_netmask.strip()

    try:
        ipaddress.ip_network(ip_netmask, strict=False)
        return True

    except ValueError:
        return False


def validate_object_row(object_name, ip_netmask):
    object_name = object_name.strip()
    ip_netmask = ip_netmask.strip()

    if not object_name:
        return False, "object_name is missing"

    if not ip_netmask:
        return False, "ip_netmask is missing"

    if not is_valid_ip_netmask(ip_netmask):
        return False, "ip_netmask format is invalid"

    return True, "valid row"

log_and_print("INFO", "CSV logging workflow started")

try:
    with open(CSV_File, mode="r", newline="") as file:
        reader = csv.DictReader(file)

        for line_number, row in enumerate(reader, start=2):
            object_name = row["object_name"].strip()
            ip_netmask= row["ip_netmask"].strip()

            is_valid, message = validate_object_row(object_name, ip_netmask)

            if not is_valid:
                log_and_print(
                    "WARNING", f"Line {line_number}: INVALID - {message}"
                )
                continue
            log_and_print(
                "INFO", f"Line {line_number}: VALID - {object_name}"
            )
except FileNotFoundError:
    log_and_print(
        "CRITICAL", f"CSV file not found: {CSV_File}. Cannot Continue."
    )
    sys.exit()
except KeyError as error:
    log_and_print(
        "CRITICAL", f"Missing Colom: {error}. Cannot Continue."
    )
    sys.exit()






