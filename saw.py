# TODO: Find a better way to pass pillar data to cmd.run, if there is one
from getpass import getpass
import re
import requests

base_url = 'http://salt-master'


class user_session:
    def __init__(self, user_name=None):
        '''
        Initializer. Optionally takes user_name(str).
        '''
        self.auth_token = None

        if not user_name:
            self.user_name = raw_input('Username: ')
        else:
            self.user_name = user_name

    def set_auth_token(self, user_pass=None, url=base_url):
        '''
        sets instance variable for auth_token that allows x-auth-token header
        authentication with salt-api. Optionally takes user_pass(str).
        '''
        url += '/login'
        data = {}
        data['username'] = self.user_name
        data['eauth']    = 'pam'

        if not user_pass:
            data['password'] = get_pw()
        else:
            data['password'] = user_pass

        r = requests.post(url, data=data, verify=False)

        try:
            self.auth_token = r.headers['x-auth-token']
            self.auth_expiry = re.search(
                r'expires=(.*);',
                r.headers['set-cookie']).group(1)
        except:
            print('Auth error.')


def get_pw():
    '''
    prompt for password as needed
    '''
    return getpass('Enter password: ')


def cmd_run(user, target, cmd, url=base_url, user_pass=None):
    '''
    Runs cmd.run from cmd parameter. Takes user(str), target(str),
    cmd(str). Optionally takes user_pass(str).
    Returns dict of results per minion.
    '''
    url = base_url + '/run'
    data = {}
    data['username'] = user
    data['tgt']      = target
    data['client']   = 'local'
    data['eauth']    = 'pam'
    data['password'] = None
    data['fun']      = 'cmd.run'
    data['arg']      = cmd
    if not user_pass:
        data['password'] = get_pw()
    else:
        data['password'] = user_pass

    r = requests.post(url, data=data, verify=False)

    if r.status_code != 200:
        return 'Status code ' + str(r.status_code) + ', something went wrong.\n'
    else:
        return r.json()['return'][0]


def token_cmd_run(auth_token, target, cmd, url=base_url):
    '''
    Runs cmd.run from state parameter. Takes user(str), target(str),
    cmd(str). Returns dict of results per minion.
    '''
    headers = {'Accept': 'application/x-yaml', 'X-Auth-Token': auth_token}
    data = {'tgt': target, 'client': 'local', 'fun': 'cmd.run', 'arg': cmd}

    r = requests.post(url, headers=headers, data=data, verify=False)

    if r.status_code != 200:
        return 'Status code ' + str(r.status_code) + ', something went wrong.\n'
    else:
        return r.text


def print_cmd_run(cmd):
    '''
    prints returned dict from cmd_run function
    '''
    if type(cmd) == str or type(cmd) == unicode:
        print(cmd)
    else:
        for minion in cmd:
            print('*** ' + minion + ' ***\n')
            print(cmd[minion] + '\n')
            print('-' * 10 + '\n')


def get_minions(auth_token, url=base_url):
    '''
    returns dict of minions that were connected when function was run, uses
    x-auth-token header value for authentication.
    '''
    url += '/minions'
    headers = {'X-Auth-Token': auth_token}
    r = requests.get(url, headers=headers, verify=False)
    minions = r.json()['return'][0]
    return minions


def print_minions(minions):
    '''
    prints dict of minions from get_minions function.
    '''
    print('Registered minions:\n')
    for minion in minions:
        print('* ' + minion)
        print('  Kernel release: %s\n') % minions[minion]['kernelrelease']
    print('-' * 10 + '\n')


def run_state(user, target, state, url=base_url, pillar=None, user_pass=None):
    '''
    runs a state.sls where target is the path to the state. pillar can be a
string in the form of pillar='pillar={"value1": "string"}'. returns dict with
return information from the salt-api about the states run from the state file
specified.
    '''
    url += '/run'
    data = {}
    data['username'] = user
    data['tgt']      = target
    data['client']   = 'local'
    data['eauth']    = 'pam'
    data['password'] = None
    data['fun']      = 'cmd.run'
    data['arg']      = None

    if not user_pass:
        data['password'] = get_pw()
    else:
        data['password'] = user_pass

    if pillar:
        data['arg'] = [state, pillar]
    else:
        data['arg'] = [state]

    r = requests.post(url, data=data, verify=False)

    if r.status_code != 200:
        return 'Status code ' + str(r.status_code) + ', something went wrong.\n'
    else:
        results = r.json()['return'][0]
        return results


def token_run_state(auth_token, target, state, url=base_url, pillar=None):
    '''
    runs a state.sls where target is the path to the state. pillar can be a
string in the form of pillar='pillar={"value1": "string"}'.  returns dict with
return information from the salt-api about the states run from the state file
specified.
    '''
    headers = {'Accept': 'application/x-yaml', 'X-Auth-Token': auth_token}
    data = {}
    data['tgt']    = target
    data['client'] = 'local'
    data['fun']    = 'state.sls'
    data['arg']    = None

    if pillar:
        data['arg'] = [state, pillar]
    else:
        data['arg'] = [state]

    r = requests.post(url, headers=headers, data=data, verify=False)

    if r.status_code != 200:
        return 'Status code ' + str(r.status_code) + ', something went wrong.\n'
    else:
        return r.text


def print_run_state(state):
    '''
    prints dict from run_state function
    '''
    if type(state) == str or type(state) == unicode:
        print(state)
    else:
        for minion in state:
            print('*** ' + minion + ' ***\n')
            for item in state[minion]:
                try:
                    comment = state[minion][item]['comment']
                    result = str(state[minion][item]['result'])
                    print('State: ' + item)
                    print('Comment: ' + comment)
                    print('Result: ' + result + '\n')
                except:
                    print(state[minion][0] + '\n')


def test_target(auth_token, target, url=base_url):
    '''
    tests which minions will match a target expression
    '''
    headers = {'Accept': 'application/x-yaml', 'X-Auth-Token': auth_token}
    data = {'client': 'local', 'tgt': target, 'fun': 'test.ping'}
    r = requests.post(url, headers=headers, data=data, verify=False)
    return r.text
