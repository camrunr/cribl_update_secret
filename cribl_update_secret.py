#!/usr/bin/python

import requests
import json
import os
import sys
import argparse
import getpass

# don't care about insecure certs (maybe you do, comment out if so)
requests.urllib3.disable_warnings(requests.urllib3.exceptions.InsecureRequestWarning)

# where we login to get a bearer token
auth_uri = '/api/v1/auth/login'
cloud_token_url = 'https://login.cribl.cloud/oauth/token'

# define the secrets URI
secrets_uri  = '/api/v1/m/<WG>/system/secrets'

# commit / deploy uris
commit_uri = '/api/v1/version/commit'
deploy_uri = '/api/v1/master/groups/<WG>/deploy'

# secrets file path
secrets_file_path = 'groups/<WG>/local/cribl/secrets.yml'

#############################
# prompt for password if one is not supplied
class Password:
    # if password is provided, use it. otherwise prompt
    DEFAULT = 'Prompt if not specified'

    def __init__(self, value):
        if value == self.DEFAULT:
            value = getpass.getpass('Password: ')
        self.value = value

    def __str__(self):
        return self.value

#############################
# parse the command args
def parse_args():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-D', '--debug', help='extra output',action='store_true')
    parser.add_argument('-l', '--leader', help='Leader URL, http(s)://leader:port',required=True)
    parser.add_argument('-g', '--group', type=str, help="Target worker group", required=True)
    parser.add_argument('-s', '--secretid', type=str, help="Target secret ID", required=True) 
    parser.add_argument('-S', '--secretvalue', type=str, help="Target secret value", required=True) 
    parser.add_argument('-u', '--username', help='API token id (cloud) or user id (self-managed)',required=True)
    parser.add_argument('-P', '--password', type=Password, help='Specify password or secret, or get prompted for it',default=Password.DEFAULT)
    args = parser.parse_args()
    return args

# some debug notes
def debug_log(log_str):
    if args.debug:
        print("DEBUG: {}".format(log_str))

#############################
#############################
# only one of the auth functions will fire
# either self-managed or SaaS
#############################
# get logged in for self-managed instances
def auth(leader_url,un,pw):
    # get logged in and grab a token
    header = {'accept': 'application/json', 'Content-Type': 'application/json'}
    login = '{"username": "' + un + '", "password": "' + pw + '"}'
    r = requests.post(leader_url+auth_uri,headers=header,data=login,verify=False)
    if (r.status_code == 200):
        res = r.json()
        return res["token"]
    else:
        print("Login failed, terminating")
        print(str(r.json()))
        sys.exit()

#############################
# get logged in for Cribl SaaS
def cloud_auth(client_id,client_secret):
    # get logged in and grab a token
    header = {'accept': 'application/json', 'Content-Type': 'application/json'}
    login = '{"grant_type": "client_credentials","client_id": "' + client_id + '", "client_secret": "' + client_secret + '","audience":"https://api.cribl.cloud"}'
    r = requests.post(cloud_token_url,headers=header,data=login,verify=False)
    if (r.status_code == 200):
        res = r.json()
        debug_log("Bearer token: " + res["access_token"])
        return res["access_token"]
    else:
        print("Login failed, terminating")
        print(str(r.json()))
        sys.exit()

#############################
# update the secret on the leader (patch)
def patch_secret(leader,group,token, sid, sv):
    url = leader + secrets_uri.replace("<WG>",group) + "/" + sid
    header = {'Authorization': "Bearer " + token, 'Accept': 'application/json', 'Content-type': 'application/json'}
    configs =  {'secretType':'credentials','id': sid, 'password': sv}
    r = requests.patch(url,headers=header,json=configs)
    debug_log("PATCHing to: " + url)
    debug_log("with data: " + json.dumps(configs))
    
    if (r.status_code == 200):
        return(r)
    else:
        print("PATCH failed with returned status {}\nexiting!".format(r.status_code))
        sys.exit(1)

#############################
# commit the change
def commit(leader, group, token, msg):
    url = leader + commit_uri
    data = {'message': msg, 'group': args.group, 'files': [secrets_file_path.replace('<WG>',group)]}
    header = {'Authorization': 'Bearer ' + token, 'accept': 'application/json', 'Content-Type': 'application/json'}
    r = requests.post(url,headers=header,json=data)
    debug_log("POSTing to: " + url)
    debug_log("with data: " + json.dumps(data))

    if (r.status_code == 200):
        return(r)
    else:
        print("PATCH failed with returned status {}\nexiting!".format(r.status_code))
        print("details:\nurl: {}\nheaders: {}\ndata: {}\n".format(url,header,json.dumps(data)))
        sys.exit(1)

#############################
# deploy this specific commit
def deploy(leader, group, token, commit_id):
    url = leader + deploy_uri.replace("<WG>",group)
    data = {'version': commit_id}
    header = {'Authorization': 'Bearer ' + token, 'accept': 'application/json', 'Content-Type': 'application/json'}
    r = requests.patch(url,headers=header,data=json.dumps(data))
    debug_log("PATCHing to: " + url)
    debug_log("with data: " + json.dumps(data))
    return(r)


#############################
#############################
# main 
if __name__ == "__main__":
    args = parse_args()
    
    # get logged in
    if args.leader.find('cribl.cloud') > 0:
        bearer_token = cloud_auth(args.username,str(args.password))
    else:
        bearer_token = auth(args.leader,args.username, str(args.password))
    
    # send the payload
    debug_log("sending update to secrets endpoint")
    results = patch_secret(args.leader, args.group, bearer_token, args.secretid, args.secretvalue)
    debug_log(results)

    # commit the changes
    debug_log("commit the changes")
    results = commit(args.leader, args.group, bearer_token,"updated secret: {}".format(args.secretid))
    debug_log(results.status_code)
    commit_id = results.json()['items'][0]['commit']
    debug_log("commit ID: " + commit_id)
    
    # deploy
    debug_log("deploy the changes from " + commit_id)
    results = commit(args.leader, args.group, bearer_token,commit_id)
    debug_log(results.status_code)
    debug_log(results.text)
    
    if results.status_code == 200:
        print("bueno")
    else:
        print("something happened")
    