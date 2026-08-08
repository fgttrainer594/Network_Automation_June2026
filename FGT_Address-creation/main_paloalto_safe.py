import csv
import sys

from validators import validate_csv_headers, validate_object_row

from paloalto_api import (
    get_paloalto_address_objects,
    paloalto_object_exists,
    build_paloalto_address_payload,
    create_paloalto_address_object,
    verify_paloalto_address_object,
)


CSV_FILE = "objects.csv"

created_count = 0
skipped_count = 0
failed_count = 0
invalid_count = 0


print("Starting Palo Alto production-safe workflow...")
print("-" * 60)

success, existing_objects, message = get_paloalto_address_objects()

if not success:
    print("CRITICAL ERROR - Cannot continue.")
    print(message)
    sys.exit(1)

print(message)
print("Existing objects loaded:", len(existing_objects))
print("-" * 60)


try:
    with open(
        CSV_FILE,
        mode="r",
        newline="",
        encoding="utf-8-sig",
    ) as file:

        reader = csv.DictReader(file)

        # Validate CSV headers
        header_valid, header_message = validate_csv_headers(
            reader.fieldnames
        )

        if not header_valid:
            print("CRITICAL ERROR - Cannot continue.")
            print(header_message)
            sys.exit(1)

        print(header_message)
        print("-" * 60)


        for line_number, row in enumerate(reader, start=2):

            object_name = row["object_name"].strip()
            ip_netmask = row["ip_netmask"].strip()
            description = row["description"].strip()


            is_valid, validation_message = validate_object_row(
                object_name,
                ip_netmask,
            )

            if not is_valid:
                print(
                    f"Line {line_number}: "
                    f"INVALID - {validation_message}"
                )

                invalid_count += 1
                continue


            if paloalto_object_exists(
                object_name,
                existing_objects,
            ):
                print(
                    f"Line {line_number}: "
                    f"SKIPPED - {object_name} already exists"
                )

                skipped_count += 1
                continue


            payload = build_paloalto_address_payload(
                object_name,
                ip_netmask,
                description,
            )


            create_success, create_message = (
                create_paloalto_address_object(
                    object_name,
                    payload,
                )
            )

            if not create_success:
                print(
                    f"Line {line_number}: "
                    f"FAILED - {object_name}"
                )
                print(create_message)

                failed_count += 1
                continue

            print(
                f"Line {line_number}: "
                f"CREATED - {object_name}"
            )

            created_count += 1


            verify_success, obj, verify_message = (
                verify_paloalto_address_object(
                    object_name
                )
            )

            if verify_success:
                print("Verification: SUCCESS")
                print(
                    obj.get("@name"),
                    "->",
                    obj.get("ip-netmask"),
                )

                existing_objects.append(obj)

            else:
                print("Verification: FAILED")
                print(verify_message)

                failed_count += 1

            print("-" * 60)


except FileNotFoundError:
    print("CRITICAL ERROR - Cannot continue.")
    print(f"CSV file not found: {CSV_FILE}")
    print(
        "Keep objects.csv in the same folder as "
        "main_paloalto_safe.py."
    )
    sys.exit(1)



print("\nFinal Summary")
print("-" * 60)
print("Created:", created_count)
print("Skipped:", skipped_count)
print("Invalid rows:", invalid_count)
print("Failed:", failed_count)
print("-" * 60)
print("Palo Alto workflow completed.")