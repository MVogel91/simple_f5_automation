import datetime
import json
import requests
import yaml
import argparse
import getpass
import urllib3
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

    def __api_call(self, system:BIGIP, method:str, uri:str, data:dict=dict()):
        if system is None:
            raise Exception ('No system specified!')
        if method == '':
            raise Exception ('No Method specified')
        if method in ['post', 'patch'] and data == {}:
            raise Exception ('No Payload specified for POST/PATCH')
        if uri == '':
            raise Exception ('No URI specified')
        
        token = self.__get_or_create_session(system=system)["token"]["value"]
        session = requests.Session()
        match method:
            case 'get':
                response = session.get(url=f'https://{system.name}:{system.port}{uri}', headers={'Accept-Encoding': 'application/json', 'X-F5-Auth-Token': token}, verify=bigip.verifyCert)
                return response
            case 'post':
                response = session.post(url=f'https://{system.name}:{system.port}{uri}', headers={'Content-Type': 'application/json', 'X-F5-Auth-Token': token}, json=data, verify=bigip.verifyCert)
                return response
            case 'put':
                response = session.put(url=f'https://{system.name}:{system.port}{uri}', headers={'Content-Type': 'application/json', 'X-F5-Auth-Token': token}, json=data, verify=bigip.verifyCert)
                return response
            case 'patch':
                response = session.patch(url=f'https://{system.name}:{system.port}{uri}', headers={'Content-Type': 'application/json', 'X-F5-Auth-Token': token}, json=data, verify=bigip.verifyCert)
                return response
            case 'delete':
                response = session.delete(url=f'https://{system.name}:{system.port}{uri}', headers={'Content-Type': 'application/json', 'X-F5-Auth-Token': token}, verify=bigip.verifyCert)
                return response 

    def get(self, system:BIGIP, uri:str):
        return self.__api_call(system=system, method='get', uri=uri)
    
    def delete(self, system:BIGIP, uri:str):
        return self.__api_call(system=system, method='delete', uri=uri)
    
    def post(self, system:BIGIP, uri:str, data:dict=dict()):
        return self.__api_call(system=system, method='post', uri=uri, data=data)

    def put(self, system:BIGIP, uri:str, data:dict=dict()):
        return self.__api_call(system=system, method='put', uri=uri, data=data)
    
    def patch(self, system:BIGIP, uri:str, data:dict=dict()):
        return self.__api_call(system=system, method='patch', uri=uri, data=data)

'''
Supported features
'''
def backup_and_update_iRule(bigip:BIGIP, client:dict, rule:str, new_rule:str):
    '''
    Create a backup for an iRule before deploying a new version on the existing object
    '''
    response = client.get(system=bigip, uri=f'/mgmt/tm/ltm/rule/{rule}')
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


'''
Arguments Parser
'''
parser = argparse.ArgumentParser(
                    prog='F5 API Automation Client',
                    description='Automate simple F5 BIG-IP tasks',
                    epilog='With great power comes great responsibility.')
parser.add_argument('action', help='Action to perform', choices=['update_irule','show_bigips'])
parser.add_argument('-b', '--bigips', help='Select a category of hosts to apply the task to', required=True)
parser.add_argument('-u', '--username', help='BIG-IP username')
parser.add_argument('-p', '--password', help='BIG-IP password')
parser.add_argument('-i', '--inventory_file', help='YAML inventory file or directory', default='inventory/hosts.yaml')
parser.add_argument('-k', '--ignore_cert', help='completely ignore Certificate issues on BIG-IP', action='store_true', default=False)
parser.add_argument('--ca_file', help='CA file to trust for BIG-IP certificates')
parser.add_argument('--irule_name', help='Name of iRule to update. Required for update_irule action')
parser.add_argument('--irule_content', help='File with content for iRule update. Required for update_irule action')
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
        for host in yaml_content[args.bigips]['hosts']:
            bigip = BIGIP(name=host, verifyCert=ca)

            if args.irule_name == None or args.irule_content == None:
                raise Exception('update_irule module requires flags --irule_name and --irule_content')
            irule_content = open(args.irule_content).read().rstrip() # Remove trailing whitespaces / EOF, ...
            backup_and_update_iRule(bigip=bigip, client=client, rule=args.irule_name, new_rule=irule_content)
    case 'show_bigips':
        for host in yaml_content[args.bigips]['hosts']:
            print(host)