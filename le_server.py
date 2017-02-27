import argparse
import base64
import json
import os
import pem
import requests
import six
import shutil
import subprocess32
import sys
import time
import uuid

from flask import Flask, send_from_directory, request, jsonify

ERROR_MESSAGES = {
    'auth': 'A required credential was incorrect or missing. Please provide ' +
            'the correct plotly api domain, username along with an api_key ' +
            'or access_token in the request body. Such as ' +
            '{credentials: {username: name, access_token: 123456abcdef, ' +
            'plotly_api_domain: "https://api.plot.ly"}}',
    'cert': 'An error occured during the creation of certificates'
}

DEFAULTS = {
    'port': 8080,
    'path_to_config': './config',
    'path_to_certs': './certs',  # relative or absolute
    'processes': 5
}

# Max time allowed in seconds. Usually takes between 40 and 60 seconds.
MAX_TIME = 120


class Server():
    """
    Server class that provides endpoints to generate certificates
    using Let's Encrypt's service.

        Usage - as command line:

        !le_server.py [-h] [--port PORT] [--path_to_config PATH_TO_CONFIG]
                [--path_to_certs PATH_TO_CERTS] [--processes PROCESSES]

        optional arguments:
            -h, --help
                show this help message and exit

            --port PORT, -p PORT
                Port for the Flask server. Defaults to 8080

            --path_to_config PATH_TO_CONFIG, -c PATH_TO_CONFIG
                Location of the config file for the dehydrated.sh
                LetsEncrypt client. Defaults to ./config

            --path_to_certs PATH_TO_CERTS, -s PATH_TO_CERTS
                Location of temporarily stored certificates. Relative
                or absolute path. Defaults to certs/

            --processes PROCESSES, -n PROCESSES
                Number of processes for the Flask server. Defaults to 5

        Usage - as module import:

            import le_server
            le_bot = le_server.Server(args)
            le_bot.start()

            where `args` is a dict with these possible keys:
                `port`
                    Port for the Flask server. Defaults to 8080

                `path_to_config`
                    Location of the config file for the dehydrated.sh
                    LetsEncrypt client. Defaults to ./config

                `path_to_certs`
                    Location of temporarily stored certificates. Relative
                    or absolute path. Defaults to certs/
                `processes`
                    Number of processes for the Flask server.
                    Defaults to 5


        Available routes:
            GET /ping
                response.data: 'pong'
            POST /certificate
                response.data: {
                    cert: "-----BEGIN CERTIFICATE----- ...",
                    key: "-----BEGIN RSA PRIVATE KEY----- ...",
                    subdomain: "user12-VeRy123LonG456HaSh.yourdomain.com"
                }

    """
    def __init__(self, args):
        if (not os.environ.get('DNS_DOMAIN')):
            print('Please set your DNS_DOMAIN environment variable. \n' +
                  'See credentials-example.sh file.')
            exit(1)
        if (not os.environ.get('ZONE_NAME')):
            print('Please set your ZONE_NAME environment variable. \n' +
                  'See credentials-example.sh file.')
            exit(1)

        # Regarding following logic gate,
        # see comment in self.build_subdomain() function.
        if len(os.environ.get('DNS_DOMAIN')) > 25:
            print('The domain can not be longer than 25 characters.')
            exit(1)
        else:
            self.domain = os.environ.get('DNS_DOMAIN')

        app = Flask(__name__, static_folder='www')
        self.app = app

        # Assign input arguments
        self.port = int(os.environ.get('PORT', args.get('port')))

        self.path_to_certs = os.path.join(
            os.getcwd(),
            os.path.relpath(args.get('path_to_certs')) + os.sep)

        self.path_to_config = os.path.join(
            os.getcwd(),
            os.path.relpath(args.get('path_to_config')))

        self.processes = args.get('processes')

        # Setup some other properties for ease of access.
        self.dehydrated_command = [
            os.getcwd() + '/dehydrated-0.3.1/dehydrated',
            '-c',
            '-n',
            '-f',
            self.path_to_config]

        @app.route('/')
        def greetings():
            return 'Greetings! Looking for a Cert are we? '

        @app.route('/ping')
        def pong():
            return 'pong'

        @app.route('/certificate', methods=['POST'])
        def create_cert():
            credentials = json.loads(request.data).get('credentials', {})
            if self.user_is_verified(credentials) is False:
                return jsonify(error=ERROR_MESSAGES['auth']), 400
            # NOTE The above `user_is_verified` check requires a username
            # to be part of credentials, it also checks provided username and
            # token/key against Plotly's database.

            # Continue knowing that `username` exists in credentials.
            subdomain = self.build_subdomain(credentials.get('username'))
            host = self.build_host(subdomain)
            status = self.execute_letsencrypt_client(
                ['-d', host] + ['-o', self.path_to_certs])

            if (status == 0):
                try:
                    cert, key, subdomain = self.get_cert_and_key(subdomain)

                    return jsonify(subdomain=subdomain, cert=cert, key=key), 201
                except ValueError:
                    return jsonify(error=error), 500
            else:
                return jsonify(error=ERROR_MESSAGES['cert']), 500

    def build_host(self, subdomain):
        return subdomain + '.' + self.domain

    def build_subdomain(self, username):
        # Consider the intended resulting string from this function:
        # {username}-{hash}.{domain}
        #
        # There is a maximal host length of 64 characters.
        # ASN1_mbstring_ncopy:string -> a_mbstr.c:154:maxsize=64
        #
        # Hash is 36 characters long but to lengthen the username.
        # We need a '-' between the username and Hash and a '.'
        # before the domain.
        # We're left with
        #   usrname_length = 64 - 1 (the '-') - 1 (the '.') - 36 - domain_length
        # In the case of
        #   domain = 'plotly-connector-test.com' (25 chars),
        #   usrname_length = 1
        #
        # Thus, in method get_hash() we truncate the hash to 30 chars to
        # increase the length of the username.
        # Thus, calculation becomes 64 - 1 - len(hash) - len(domain) = 7
        # Let's set minimal username length to 7; which thus sets the max domain
        # length to 25.
        # Domain length is limited in the __init__ method.
        hash_string = self.get_hash()
        max_usr_len = 64 - 2 - len(hash_string) - len(self.domain)
        return username.replace('.', '_')[:max_usr_len] + '-' + hash_string

    def get_key_path(self, subdomain):
        return self.path_to_certs + self.build_host(subdomain) + '/privkey.pem'

    def get_cert_path(self, subdomain):
        return self.path_to_certs + self.build_host(subdomain) + '/fullchain.pem'

    def cert_and_key_exist(self, subdomain):
        key_exists = os.path.exists(self.get_key_path(subdomain))
        cert_exists = os.path.exists(self.get_cert_path(subdomain))
        return key_exists and cert_exists

    def get_cert_and_key(self, subdomain):
        cert = ''
        key = ''
        if self.cert_and_key_exist(subdomain):
            cert = str(pem.parse_file(self.get_cert_path(subdomain))[0])
            key = str(pem.parse_file(self.get_key_path(subdomain))[0])
        else:
            raise ValueError('Certificates were not found.')

        # Delete certs to hold no state and reduce risk of a hacker
        # retrieving someone else's certificate.
        self.delete_certs_folder_if_exists(subdomain)

        return cert, key, subdomain

    def encode_api_key(self, username, api_key):
        encode = base64.b64encode
        return encode(six.b('{0}:{1}'.format(username, api_key))).decode('utf8')

    def get_headers(self, credentials):
        headers = {}
        username = credentials.get('username')
        if 'api_key' in credentials:
            api_key = credentials.get('api_key')
            encoded_api_auth = self.encode_api_key(username, api_key)
            headers['authorization'] = 'Basic ' + encoded_api_auth
            headers['plotly-client-platform'] = 'plotly-le'
        elif 'access_token' in credentials:
            access_token = credentials.get('access_token')
            headers['authorization'] = 'Bearer ' + access_token
        return headers

    def get_hash(self):
        # -{hash}.plotly-connector-test.com is 63 characters.
        # Which leaves 1 character for username.
        # To include some more of the username (max 30 chars.)
        # I'm truncating the hash to 30 chars which gives the user min 7 chars.
        # See method build_subdomain() for more details.
        return str(uuid.uuid4())[:30]

    def call_plotly_api(self, endpoint, credentials):
        headers = self.get_headers(credentials)
        plotly_api_domain = credentials.get('plotly_api_domain')
        return requests.get(plotly_api_domain + endpoint, headers=headers)

    def credentials_are_valid(self, credentials):
        if 'username' not in credentials.keys():
            return False
        if 'plotly_api_domain' not in credentials.keys():
            return False
        return True

    def user_is_verified(self, credentials):
        if not self.credentials_are_valid(credentials):
            return False
        # TODO: Decide verification method for on-prem.
        # https://github.com/plotly/le-bot/issues/2
        if credentials.get('plotly_api_domain') != 'https://api.plot.ly':
            return True
        # Continue on knowing there is a username in credentials.
        response = self.call_plotly_api('/v2/users/current', credentials)
        # Requests with either existing or non-existing both return a
        # status_code of 200.
        # but non-existing user returns "falsey" values for all parameters.
        content = json.loads(response.content)
        if (response.status_code != 200):
            return False
        # Continue on knowing the status code was a 200 but username still
        # may not exist.
        res_usr = content.get('username')
        if (res_usr is not '' and res_usr == credentials.get('username')):
            return True
        else:
            return False

    def delete_certs_folder_if_exists(self, subdomain):
        host = self.build_host(subdomain)
        folder_to_delete = self.path_to_certs + host
        if os.path.exists(folder_to_delete):
            shutil.rmtree(folder_to_delete, ignore_errors=False)

    def execute_letsencrypt_client(self, additional_parameters=''):
        # Returns status code of dehydrated.sh client execution.
        # Disable all shell based features with shell=False
        # https://docs.python.org/2/library/subprocess.html#frequently-used-arguments
        start_time = time.time()
        try:
            execution = subprocess32.check_output(
                self.dehydrated_command + additional_parameters,
                timeout=MAX_TIME,
                shell=False)
        except subprocess32.CalledProcessError as err:
            print "Execution error. ", err.returncode, err.output
            self.remove_lock_file()
            return 1
        except subprocess32.TimeoutExpired as err:
            print "Timeout error. ", err.output, err.stderr
            self.remove_lock_file()
            return 124  # Timeout exit code.
        else:
            print execution
            print("--- %s seconds ---" % (time.time() - start_time))
            return 0

    def remove_lock_file(self):
        # Deletes Lockfile if process was interrupted.
        # https://github.com/lukas2511/dehydrated/issues/31
        try:
            os.remove('lock')
        except:
            pass

    def start(self):
        if (int(self.port) == 443):
            self.app.run(
                host='0.0.0.0',
                port=self.port,
                processes=self.processes,
                ssl_context=self.ssl_context)
        else:
            self.app.run(
                host='0.0.0.0',
                port=self.port,
                processes=self.processes)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--port',
        '-p',
        type=int,
        default=DEFAULTS['port'],
        help="Port for the Flask server. " +
             "Defaults to " + str(DEFAULTS['port']))
    parser.add_argument(
        '--path_to_config',
        '-c',
        default=DEFAULTS['path_to_config'],
        help="Location of the config file for the dehydrated.sh " +
             "LetsEncrypt client. Defaults to " +
             DEFAULTS['path_to_config'])
    parser.add_argument(
        '--path_to_certs',
        '-s',
        default=DEFAULTS['path_to_certs'],
        help="Location of temporarily stored certificates. " +
             "Relative or absolute path. Defaults to " +
             DEFAULTS['path_to_certs'])
    parser.add_argument(
        '--processes',
        '-n',
        type=int,
        default=DEFAULTS['processes'],
        help="Number of processes for the Flask server. " +
             "Defaults to " + str(DEFAULTS['processes']))
    args = parser.parse_args()
    server = Server(vars(args))
    server.start()