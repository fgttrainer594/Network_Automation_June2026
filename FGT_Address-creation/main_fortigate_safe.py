import csv
import sys

from validators import validate_csv_headers, validate_object_row

from fortigate_api import (
    get_fortigate_address_objects,
    fortigate_object_exists,
    build_fortigate_address_payload,
    create_fortigate_address_object,
    verify_fortigate_address_object
)

CSV_FILE = "objects.csv"

created_count = 0
skipped_count = 0
failed_count = 0
invalid_count = 0

print("Starting FortiGate production-safe workflow...")
print("-" * 60)

success, existing_objects, message = get_fortigate_address_objects()

if not success:
    print("CRITICAL ERROR - Cannot continue.")
    print(message)
    sys.exit()

print(message)
print("Existing objects loaded:", len(existing_objects))
print("-" * 60)


try:
    with open(CSV_FILE, mode="r", newline="") as file:
        reader = csv.DictReader(file)

        header_valid, header_message = validate_csv_headers(reader.fieldnames)

        if not header_valid:
            print("CRITICAL ERROR - Cannot continue.")
            print(header_message)
            sys.exit()

        print(header_message)
        print("-" * 60)

        for line_number, row in enumerate(reader, start=2):
            object_name = row["object_name"].strip()
            ip_netmask = row["ip_netmask"].strip()

            
            is_valid, validation_message = validate_object_row(
                object_name,
                ip_netmask
            )

            if not is_valid:
                print(f"Line {line_number}: INVALID - {validation_message}")
                invalid_count += 1
                continue

            
            if fortigate_object_exists(object_name, existing_objects):
                print(f"Line {line_number}: SKIPPED - {object_name} already exists")
                skipped_count += 1
                continue

            payload = build_fortigate_address_payload(
                object_name,
                ip_netmask               
            )

            
            create_success, create_message = create_fortigate_address_object(payload)

            if not create_success:
                print(f"Line {line_number}: FAILED - {object_name}")
                print(create_message)
                failed_count += 1
                continue

            print(f"Line {line_number}: CREATED - {object_name}")
            created_count += 1

            
            verify_success, obj, verify_message = verify_fortigate_address_object(
                object_name
            )

            if verify_success:
                print("Verification: SUCCESS")
                print(obj.get("name"), "->", obj.get("subnet"))
            else:
                print("Verification: FAILED")
                print(verify_message)
                failed_count += 1

            print("-" * 60)

except FileNotFoundError:
    print("CRITICAL ERROR - Cannot continue.")
    print(f"CSV file not found: {CSV_FILE}")
    print("Keep objects.csv in the same folder as main_fortigate_safe.py.")
    sys.exit()

print("\nFinal Summary")
print("-" * 60)
print("Created:", created_count)
print("Skipped:", skipped_count)
print("Invalid rows:", invalid_count)
print("Failed:", failed_count)
print("-" * 60)
print("FortiGate workflow completed.")