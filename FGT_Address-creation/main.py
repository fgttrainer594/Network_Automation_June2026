import csv

from validators import validate_csv_row

from fgt_api import (
    get_fortigate_address_objects,
    fortigate_object_exists,
    build_fortigate_address_payload,
    create_fortigate_address_object,
    verify_fortigate_addresss_object    
)

CSV_File="objects.csv"

existing_objects = get_fortigate_address_objects()

with open (CSV_File, mode="r") as file:
    reader=csv.DictReader(file)
    for line_number, row in enumerate(reader, start=2):
        object_name= row["object_name"].strip()
        ip_netmask= row["ip_netmask"].strip()

        is_valid, message = validate_csv_row(object_name, ip_netmask)
        if not is_valid:
            print(f"Row {line_number}: Error: {message}")
            continue
        if fortigate_object_exists(object_name, existing_objects):
            print(f"Line {line_number}: Object '{object_name}' already exists. Skipping creation.")
            continue
        payload = build_fortigate_address_payload(object_name, ip_netmask)
        response= create_fortigate_address_object(payload)


        print(f"Line {line_number}: Object: {object_name} with IP/Netmask: {ip_netmask}. Response Status Code: {response.status_code}")
        is_found, obj = verify_fortigate_addresss_object(object_name)
        print(is_found)
        if is_found:
            print("Verification: Success")
            print("Object:", obj.get("name"), "-->", obj.get("subnet"))
        else:
            print("Verification: Failed. Object not found.")
        print("--------------------------------------------------")