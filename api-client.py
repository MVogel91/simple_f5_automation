import datetime
import json
import requests
import yaml
import argparse
import getpass
import urllib3
import os
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class BIGIP:
    def __init__(self, name:str, port:int=443, verifyCert=True):
        self.name = name.lower()
        self.port = port
        self.verifyCert = verifyCert

class APIClient:
    http_sessions = dict()

    def __init__(self, username:str, password:str):
        self.__username = username
        self.__password = password
    
    def __authenticate(self, system:BIGIP, session:requests.Session=requests.Session()):
        uri = f'https://{system.name}/mgmt/shared/authn/login'
        body = {
            "username":self.__username,
            "password":self.__password,
            "loginProviderName":"tmos"
            }
        response = session.post(url=uri, json=body, verify=system.verifyCert)

        if response.status_code == 200:
            response_json = json.loads(response.text)
            APIClient.http_sessions[system] = {
                "token" : {
                    "value": response_json['token']['token'],
                    "expires": response_json['token']['expirationMicros']
                }
            }
        else:
            raise Exception (f'Authentication failed!\r\n{response.text}')
        

    def __get_or_create_session(self, system:BIGIP):
        if system in APIClient.http_sessions:
            if APIClient.http_sessions[system]['token']['expires'] > datetime.datetime.now().microsecond:
                return APIClient.http_sessions[system]

        self.__create_session(system)
        return APIClient.http_sessions[system]

    def __create_session(self, system:BIGIP):
        session = requests.Session()
        self.__authenticate(system=system, session=session)

    def __api_call(self, system:BIGIP, method:str, uri:str, headers:dict(), data:dict=dict(), json:bool=True):
        if system is None:
            raise Exception ('No system specified!')
        if method == '':
            raise Exception ('No Method specified')
        if method in ['post', 'patch'] and data == {}:
            raise Exception ('No Payload specified for POST/PATCH')
        if uri == '':
            raise Exception ('No URI specified')

        token = self.__get_or_create_session(system=system)["token"]["value"]
        default_headers = {
            'Accept-Encoding': 'application/json',
            'X-F5-Auth-Token': token
        }
        for header in default_headers:
            if header not in headers:
                headers[header] = default_headers[header]

        session = requests.Session()
        match method:
            case 'get':
                response = session.get(url=f'https://{system.name}:{system.port}{uri}', headers=headers, verify=bigip.verifyCert)
                return response
            case 'post':
                if json == True:
                    response = session.post(url=f'https://{system.name}:{system.port}{uri}', headers=headers, json=data, verify=bigip.verifyCert)
                else:
                    response = session.post(url=f'https://{system.name}:{system.port}{uri}', headers=headers, data=data, verify=bigip.verifyCert)
                return response
            case 'put':
                response = session.put(url=f'https://{system.name}:{system.port}{uri}', headers=headers, json=data, verify=bigip.verifyCert)
                return response
            case 'patch':
                response = session.patch(url=f'https://{system.name}:{system.port}{uri}', headers=headers, json=data, verify=bigip.verifyCert)
                return response
            case 'delete':
                response = session.delete(url=f'https://{system.name}:{system.port}{uri}', headers=headers, verify=bigip.verifyCert)
                return response 

    def get(self, system:BIGIP, uri:str, headers:dict):
        return self.__api_call(system=system, method='get', uri=uri, headers=headers)
    
    def delete(self, system:BIGIP, uri:str, headers:dict):
        return self.__api_call(system=system, method='delete', uri=uri, headers=headers)
    
    def post(self, system:BIGIP, uri:str, headers:dict, data:dict=dict(), json:bool=True):
        return self.__api_call(system=system, method='post', uri=uri, headers=headers, data=data, json=json)

    def put(self, system:BIGIP, uri:str, headers:dict, data:dict=dict()):
        return self.__api_call(system=system, method='put', uri=uri, headers=headers, data=data)
    
    def patch(self, system:BIGIP, uri:str, headers:dict, data:dict=dict()):
        return self.__api_call(system=system, method='patch', uri=uri, headers=headers, data=data)

'''
Supported features
'''
def backup_and_update_iRule(bigip:BIGIP, client:dict, rule:str, new_rule:str):
    '''
    Create a backup for an iRule before deploying a new version on the existing object
    '''
    response = client.get(system=bigip, uri=f'/mgmt/tm/ltm/rule/{rule}')
    if response.status_code == 200:
        irule_definition = response.json()['apiAnonymous']
        if irule_definition == new_rule:
            # Requirement already satisfied
            print(f'{bigip.name}: {rule}: iRule already up to date')
            return

        response = client.post(system=bigip, uri=f'/mgmt/tm/ltm/rule', data={'name': f'{rule}_backup', 'apiAnonymous': f'{irule_definition}'})
        if response.status_code == 409:
            # Backup exists
            response = client.put(system=bigip, uri=f'/mgmt/tm/ltm/rule/{rule}_backup', data={'apiAnonymous': f'{irule_definition}'})
            if response.status_code == 200:
                print(f'{bigip.name}: {rule}: Older Backup existed, overwritten')
        elif response.status_code == 200:
            # Backup created
            print(f'{bigip.name}: {rule}: Backup successfully created')

        response = client.put(system=bigip, uri=f'/mgmt/tm/ltm/rule/{rule}', data={'apiAnonymous': f'{new_rule}'})
        if response.status_code == 200:
            # iRule updated
            print(f'{bigip.name}: {rule}: iRule successfully updated')
    elif response.status_code == 404:
        print(f'{bigip.name}: {rule}: iRule non-existant on system')

def find_unused_pools(bigip:BIGIP, client:dict):
    '''
    pool references
    '''
    pool_references = {
        "virtual": {
            "uri": "/ltm/virtual",
            "property": "pool"
        },
        "access_ldap": {
            "uri": "/apm/aaa/ldap",
            "property": "pool"
        },
        "access_active_directory": {
            "uri": "/apm/aaa/active-directory",
            "property": "pool"
        },
        "access_radius": {
            "uri": "/apm/aaa/radius",
            "property": "pool"
        },
        "access_crldp": {
            "uri": "/apm/aaa/crldp",
            "property": "pool"
        },
        "access_tacacs": {
            "uri": "/apm/aaa/tacacsplus",
            "property": "pool"
        },
        "access_policy": {
            "uri": "/apm/policy/agent/resource-assign/",
            "property": "pool",
            "property_array": "rules"
        },
        "sys_log_destination": {
            "uri": "/sys/log-config/destination/remote-high-speed-log",
            "property": "poolName"
        }
    }
    pool_names_response = client.get(system=bigip, uri=f'/mgmt/tm/ltm/pool/?$select=name')
    unused_pools = list()
    if pool_names_response.status_code == 200:
        for pool in pool_names_response.json()['items']:
            unused_pools.append(pool['name'])
        
        used_pools = list()
        for reference in pool_references:
            ref = pool_references[reference]
            attr = ref["property"]
            uri = ref["uri"]
            if "property_array" in ref:
                ref_array = ref["property_array"]
                ref_response = client.get(system=bigip, uri=f'/mgmt/tm{uri}?$select={attr},{ref_array}')
            else:    
                ref_response = client.get(system=bigip, uri=f'/mgmt/tm{uri}?$select={attr}')
            if ref_response.status_code == 200:
                for item in ref_response.json()['items']:
                    if attr in item:
                        for pool in unused_pools:
                            if pool == item[attr]:
                                unused_pools.remove(pool)
                                continue
                            elif f'/Common/{pool}' == item[attr]:
                                unused_pools.remove(pool)
                                continue
                    elif "property_array" in ref and ref_array in item:
                        for sub_item in item[ref_array]:
                            if attr in sub_item:
                                for pool in unused_pools:
                                    if pool == sub_item[attr]:
                                        unused_pools.remove(pool)
                                        continue
                                    elif f'/Common/{pool}' == sub_item[attr]:
                                        unused_pools.remove(pool)
                                        continue
                    else:
                        pass
            for pool in used_pools:
                if pool in unused_pools:
                    unused_pools.remove(pool)
        if unused_pools == []:
            print(f'{bigip.name}: No possibly unsused Pools identified.')
        else:
            print(f'{bigip.name}: Possibly unused Pools: {unused_pools}')
            
            # Double-Verify usage of pools in config files:
            grep_pools = [s + "$" for s in unused_pools]
            cmd_args = f"-c 'grep -P \"^\\S+|{'|'.join(grep_pools)}\" /config/bigip.conf | grep -v \"ltm pool\" | grep -B1 -P \"{'|'.join(grep_pools)}\"'"
            verify_response = client.post(system=bigip, uri=f'/mgmt/tm/util/bash', data={"command":"run", "utilCmdArgs":cmd_args})
            if verify_response.status_code == 200:
                if "commandResult" in verify_response.json():
                    print(f'{bigip.name}: possible conflicts:\n{verify_response.json()["commandResult"]}')

    elif pool_names_response.status_code == 404:
        print(f'{bigip.name}: No pools found on system. Probably a vCMP host')

def upload_file(bigip:BIGIP, client:dict, file, location:str, filename:str, size:int):
    chunk_size = 1000000
    headers = {
        'Content-Type': 'application/octet-stream'
    }
    
    basename = os.path.basename(filename)
    if os.path.splitext(basename)[-1] == '.iso':
        uri = f'/mgmt/cm/autodeploy/software-image-uploads/{basename}'
    else:
        uri = f'/mgmt/shared/file-transfer/uploads/{basename}'

    start = 0

    while True:
        file_slice = file.read(chunk_size)
        if not file_slice:
            break

        current_bytes = len(file_slice)
        end = min(start+current_bytes, size)

        headers['Content-Range'] = f"{start}-{end-1}/{size}"
        client.post(system=bigip, uri=uri, data=file_slice, headers=headers, json=False)

        print (f"Progress {int(round(1000*end/size,3))/10}% ({end} / {size})", end="\r")
        start += current_bytes

'''
Arguments Parser
'''
parser = argparse.ArgumentParser(
                    prog='F5 API Automation Client',
                    description='Automate simple F5 BIG-IP tasks',
                    epilog='With great power comes great responsibility.')
parser.add_argument('action', help='Action to perform', choices=['update_irule','show_bigips','unused_pools','upload_file'])
parser.add_argument('-b', '--bigips', help='Select a category of hosts to apply the task to', required=True)
parser.add_argument('-u', '--username', help='BIG-IP username')
parser.add_argument('-p', '--password', help='BIG-IP password')
parser.add_argument('-i', '--inventory_file', help='YAML inventory file or directory', default='inventory/hosts.yaml')
parser.add_argument('-k', '--ignore_cert', help='completely ignore Certificate issues on BIG-IP', action='store_true', default=False)
parser.add_argument('--ca_file', help='CA file to trust for BIG-IP certificates')
parser.add_argument('--irule_name', help='Name of iRule to update. Required for update_irule action')
parser.add_argument('--irule_content', help='File with content for iRule update. Required for update_irule action')
parser.add_argument('--file_name', help='File to upload')
parser.add_argument('--file_location', help='Location where to upload the file')
args = parser.parse_args()


'''
Applicable hosts
'''
try:
    f = open(args.inventory_file)
except FileNotFoundError:
    print(f'{args.inventory_file} not found.')
    exit(1)
else:
    with open(args.inventory_file) as hosts:
        yaml_content = yaml.safe_load(hosts)

'''
Credentials
'''
if args.action != 'show_bigips':
    if args.username == None:
        username = input("BIG-IP Username: ")
    else:
        username = args.username

    if args.password == None:
        password = getpass.getpass("BIG-IP Password: ")
    else:
        password = args.password

    if args.ignore_cert == True:
        ca = False
    elif args.ca_file == None:
        ca = True
    else:
        ca = args.ca_file

    client = APIClient(username=username,password=password)

'''
Actions
'''
match args.action:
    case 'update_irule':
        if args.irule_name == None or args.irule_content == None:
            raise Exception('update_irule module requires flags --irule_name and --irule_content')
        irule_content = open(args.irule_content).read().rstrip() # Remove trailing whitespaces / EOF, ...
        
        for host in yaml_content[args.bigips]['hosts']:
            bigip = BIGIP(name=host, verifyCert=ca)
            backup_and_update_iRule(bigip=bigip, client=client, rule=args.irule_name, new_rule=irule_content)
    case 'show_bigips':
        for host in yaml_content[args.bigips]['hosts']:
            print(host)
    case 'unused_pools':
        for host in yaml_content[args.bigips]['hosts']:
            bigip = BIGIP(name=host, verifyCert=ca)
            find_unused_pools(bigip=bigip, client=client)
    case 'upload_file':
        if args.file_name == None or args.file_location == None:
            raise Exception('upload_file module requires flags --file_name and --file_location')
        file = open(args.file_name, 'rb')
        size = os.path.getsize(args.file_name)

        for host in yaml_content[args.bigips]['hosts']:
            bigip = BIGIP(name=host, verifyCert=ca)
            upload_file(bigip=bigip, client=client, file=file, location=args.file_location, filename=args.file_name, size=size)
