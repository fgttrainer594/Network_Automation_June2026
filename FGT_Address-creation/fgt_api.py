import requests
import urllib3
import ipaddress

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

Fortigate_IP="192.168.1.2"
API_Token= "QGHQrszQrwk8px7pm8ywtkdx7sftxw"
VDOM="root"

URL = f"http://{Fortigate_IP}/api/v2/cmdb/firewall/address/"

headers={
    "Authorization": f"Bearer {API_Token}",
    "Content-Type": "application/json"
}
params={
    "vdom": VDOM
}

def get_fortigate_address_objects():
        response = requests.get(URL, headers=headers, params=params, verify=False)
        data= response.json()
        results = data.get("results", [])

        if isinstance(results, dict):
            results = [results]

        return results
     
     
def fortigate_object_exists(object_name, existing_objects):
      for obj in existing_objects:
            if obj.get("name") == object_name:
                return True
            return False

def build_fortigate_address_payload(object_name, ip_netmask):
    payload = {
        "name": object_name,
        "subnet": ip_netmask,
        "type": "ipmask"
    }
    return payload

def create_fortigate_address_object(payload):
     response= requests.post(URL, headers=headers, params=params, json=payload, verify=False)
     return response

def verify_fortigate_addresss_object(object_name):
     existing_objects = get_fortigate_address_objects()
     print("CSV Object Name:", object_name)
     for obj in existing_objects:
           # print("Fortigate Object Name:", object_name)
           # print("Existing Objects:", obj.get("name"))
            if obj.get("name")== object_name:
               return True, obj  
            
     return False, None 







    