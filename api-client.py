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

    def __init__(self, username:str, password:str, proxies:dict={}):
        self.__username = username
        self.__password = password
        self.__proxies = proxies
    
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
        if self.__proxies is not {}:
            session.proxies.update(self.__proxies)
        self.__authenticate(system=system, session=session)

    def __api_call(self, system:BIGIP, method:str, uri:str, headers:dict, data:dict=dict(), json:bool=True):
        if system is None:
            raise Exception ('No system specified!')
        if method == '':
            raise Exception ('No Method specified')
        if method in ['post', 'patch'] and data == {}:
            raise Exception ('No Payload specified for POST/PATCH')
        if uri == '':
            raise Exception ('No URI specified')

        session = requests.Session()
        if self.__proxies is not {}:
            session.proxies.update(self.__proxies)

        token = self.__get_or_create_session(system=system)["token"]["value"]
        headers['X-F5-Auth-Token'] = token

        default_headers = {
            'Accept-Encoding': 'application/json'
									
        }
        for header in default_headers:
            if header not in headers:
                headers[header] = default_headers[header]

									
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

    def get(self, system:BIGIP, uri:str, headers:dict=dict()):
        return self.__api_call(system=system, method='get', uri=uri, headers=headers)
    
    def delete(self, system:BIGIP, uri:str, headers:dict=dict()):
        return self.__api_call(system=system, method='delete', uri=uri, headers=headers)
    
    def post(self, system:BIGIP, uri:str, headers:dict=dict(), data:dict=dict(), json:bool=True):
        return self.__api_call(system=system, method='post', uri=uri, headers=headers, data=data, json=json)

    def put(self, system:BIGIP, uri:str, headers:dict=dict(), data:dict=dict()):
        return self.__api_call(system=system, method='put', uri=uri, headers=headers, data=data)
    
    def patch(self, system:BIGIP, uri:str, headers:dict=dict(), data:dict=dict()):
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
        else:
            response = client.post(system=bigip, uri=f'/mgmt/tm/ltm/rule', data={'name': f'{rule}_backup', 'apiAnonymous': f'{irule_definition}'})
            if response.status_code == 409:
                # Backup exists
                response = client.put(system=bigip, uri=f'/mgmt/tm/ltm/rule/{rule}_backup', data={'apiAnonymous': f'{irule_definition}'})
                if response.status_code == 200:
                    print(f'{bigip.name}: {rule}: Older Backup existed, overwritten')
            elif response.status_code == 200:
                # Backup created
                print(f'{bigip.name}: {rule}: Backup successfully created')
            else:
                print(f'{bigip.name}: {rule}: Status: {response.status_code} Content: {response.content}')

																																			  
									   
						   
            response = client.put(system=bigip, uri=f'/mgmt/tm/ltm/rule/{rule}', data={'apiAnonymous': f'{new_rule}'})
            if response.status_code == 200:
                # iRule updated
                print(f'{bigip.name}: {rule}: iRule successfully updated')
            else:
                print(f'{bigip.name}: {rule}: Status: {response.status_code} Content: {response.content}')
																	   

																												  
									   
						   
																	  
    elif response.status_code == 404:
        print(f'{bigip.name}: {rule}: iRule non-existant on system')
    else:
        print(f'{bigip.name}: {rule}: Status: {response.status_code} Content: {response.content}')

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

def upload_file(bigip:BIGIP, client:dict, filename:str):
    chunk_size = 1000000
    headers = {
        'Content-Type': 'application/octet-stream'
    }
    
    file = open(filename, 'rb')
    size = os.path.getsize(filename)
    if size > 1024*1024*1024:
        total = f'{int(size/1024/1024):,} MB'
    else:
        total = f'{int(size/1024):,} KB'

    basename = os.path.basename(filename)
    if os.path.splitext(basename)[-1] == '.iso':
        uri = f'/mgmt/cm/autodeploy/software-image-uploads/{basename}'
    else:
        uri = f'/mgmt/shared/file-transfer/uploads/{basename}'

    start = 0

    while start < size:
        file_slice = file.read(chunk_size)

        current_bytes = len(file_slice)
        end = min(start+current_bytes, size)

        headers['Content-Range'] = f"{start}-{end-1}/{size}"
        response = client.post(system=bigip, uri=uri, data=file_slice, headers=headers, json=False)

        if response.status_code != 200:
            return False
        
        if size > 1024*1024*1024:
            current = f'{int(end/1024/1024):,} MB'
        else:
            current = f'{int(end/1024):,} KB'
        print (f"Progress {int(round(1000*end/size,3))/10}% ({current} / {total})", end="\r")
        start += current_bytes
    file.close()

    return True

def move_file(bigip:BIGIP, client:dict, source:str, destination:str):
    '''
    Move file to a different location on the BIG-IP
    '''
    payload = {
        "command": "run",
        "utilCmdArgs": f"{source} {destination}"
    }
    headers = { "Content-Type": "application/json" }
    resp = client.post(system=bigip, uri="/mgmt/tm/util/unix-mv", data=payload, headers=headers)
    if resp.status_code != 200:
        return False
    
    return True

def linux_command(bigip:BIGIP, client:dict, command:str):
    '''
    Execute a Linux command on the BIG-IP
    '''
    payload = {
        "command": "run",
        "utilCmdArgs": f"-c '{command}'"
    }
    headers = { "Content-Type": "application/json" }
    resp = client.post(system=bigip, uri="/mgmt/tm/util/bash", data=payload, headers=headers)
    if resp.status_code != 200:
        return False
    
    return True

def test_connectivity(bigip:BIGIP, client:dict):
    '''
    Test connectivity to a given BIG-IP
    '''
    resp = client.get(system=bigip, uri="/mgmt/tm/sys/version")
    if resp.status_code in [200, 401]:
        return True
    return False

'''
Arguments Parser
'''
parser = argparse.ArgumentParser(
                    prog='F5 API Automation Client',
                    description='Automate simple F5 BIG-IP tasks',
                    epilog='With great power comes great responsibility.')
parser.add_argument('action', choices=['update_irule','show_bigips','unused_pools','upload_file','move_file','linux_command','test_connectivity'], help='Action to perform. upload_file supports for changing permissions and moving files.')
parser.add_argument('-b', '--bigips', help='Select a category of hosts to apply the task to', required=True)
parser.add_argument('-u', '--username', help='BIG-IP username')
parser.add_argument('-p', '--password', help='BIG-IP password')
parser.add_argument('-i', '--inventory_file', help='YAML inventory file or directory', default='inventory/hosts.yaml')
parser.add_argument('-k', '--ignore_cert', help='completely ignore Certificate issues on BIG-IP', action='store_true', default=False)
parser.add_argument('-x', '--proxy', help='Specify a proxy to make the connections', default=None)
parser.add_argument('--ca_file', help='CA file to trust for BIG-IP certificates')
parser.add_argument('--irule_name', help='Name of iRule to update. Required for update_irule action')
parser.add_argument('--irule_content', help='File with content for iRule update. Required for update_irule action')
parser.add_argument('--file_name', help='File to upload')
parser.add_argument('--file_location', help='Location where to upload the file')
parser.add_argument('--file_permissions', help='Permissions to set on the uploaded file (e.g. 644)')
parser.add_argument('--linux_command', help='Linux command to execute on the BIG-IP.')
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

    if args.proxy is not None:
        if 'http' in args.proxy:
            proxies = {
                'http': args.proxy,
                'https': args.proxy
            }
        else:
            proxies = {
                'http': f'http://{args.proxy}',
                'https': f'http://{args.proxy}'
            }
    else:
        proxies={}
    
    client = APIClient(username=username,password=password,proxies=proxies)

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
        if args.file_name == None:
            raise Exception('upload_file module requires flag --file_name')

        for host in yaml_content[args.bigips]['hosts']:
            bigip = BIGIP(name=host, verifyCert=ca)
            upload_success = upload_file(bigip=bigip, client=client, location=args.file_location, filename=args.file_name)
            if upload_success:
                print(f'{bigip.name}: upload successful')
            else:
                print(f'{bigip.name}: upload failed')

            if args.file_name[-4:] != '.iso':
                '''
                ISO Files are already in the right location, no need to change permissions or move them
                '''
                if args.permissions != None and args.permissions != '':
                    chmod_success = linux_command(bigip=bigip, client=client, command=f'chmod {args.permissions} /var/config/rest/downloads/{args.file_name}')
                    if chmod_success:
                        print(f'{bigip.name}: {args.file_name} permissions set to {args.permissions}')
                    else:
                        print(f'{bigip.name}: setting permissions failed')

                if args.file_location != None and args.file_location != '':
                    move_success = move_file(bigip=bigip, client=client, source=f'/var/config/rest/downloads/{args.file_name}', destination=args.file_location)
                    if move_success:
                        print(f'{bigip.name}: {args.file_name} moved to {args.file_location}')
                    else:
                        print(f'{bigip.name}: moving file failed')
    case 'move_file':
        if args.file_name == None or args.file_location == None:
            raise Exception('move_file module requires flags --file_name and --file_location')
        for host in yaml_content[args.bigips]['hosts']:
            bigip = BIGIP(name=host, verifyCert=ca)
            move_success = move_file(bigip=bigip, client=client, source=args.file_name, destination=args.file_location)
            if move_success:
                print(f'{bigip.name}: {args.file_name} moved to {args.file_location}')
            else:
                print(f'{bigip.name}: moving file failed')
    case 'linux_command':
        if args.linux_command == None:
            raise Exception('linux_command module requires flag --command')
        for host in yaml_content[args.bigips]['hosts']:
            bigip = BIGIP(name=host, verifyCert=ca)
            command_success = linux_command(bigip=bigip, client=client, command=args.linux_command)
            if command_success:
                print(f'{bigip.name}: Command executed successfully')
            else:
                print(f'{bigip.name}: Command execution failed')
    case 'test_connectivity':
        for host in yaml_content[args.bigips]['hosts']:
            bigip = BIGIP(name=host, verifyCert=ca)
            connectivity = test_connectivity(bigip=bigip, client=client)
            if connectivity:
                print(f'{bigip.name}: Connectivity successful')
