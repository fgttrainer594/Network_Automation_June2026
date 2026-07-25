import ipaddress

def is_valid_ip_netmask(ip_netmask):
    ip_netmask=ip_netmask.strip()

    try:
        ipaddress.ip_network(ip_netmask)
        return True
    except ValueError:
        return False

def validate_csv_row(object_name, ip_netmask):
    object_name = object_name.strip()
    ip_netmask= ip_netmask.strip()

    if not object_name:
        return False, "Object Name is Missing"
    if not ip_netmask:
        return False, "IP is missing"
    if not is_valid_ip_netmask(ip_netmask):
        return False, "IP is not is correct format"
    return True, "valid row"

