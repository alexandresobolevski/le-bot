import unittest

from M2Crypto import RSA
import base64
import json
import os
import shutil
import six
import time
import uuid

# Under test
from le_server import Server

#
# These are the same as current defaults (see DEFAULTS in le_server.py)
# but let's specify them here as inputs and use them in case the prod
# defaults change but we want to keep them different from the test
# inputs.
#
user_input_port = 9999
user_input_path_to_certs = './certs'
# This config file sets the Let's Encrypt CA to a staging server.
user_input_path_to_config = './config_staging'
user_input_processes = 1

#
# The domain and successful credentials are set as an environment variables
# in prod as well as local (by sourcing a hidden credentials file before running tests)
# as well as on Circle CI and Heroku through environment variables in the service's
# settings.
#
test_domain = os.environ.get('DNS_DOMAIN')
test_plotly_api_domain = os.environ.get('PLOTLY_API_DOMAIN')

#
# Successful credentials are set as environment variables in prod as well as local
# (by sourcing a hidden credentials file before running tests) as well as
# on Circle CI and Heroku through environment variables in the service's
# settings.
#
correct_access_token = os.environ['PLOTLY_ACCESS_TOKEN']
correct_api_key = os.environ['PLOTLY_API_KEY']
correct_username = os.environ['PLOTLY_USERNAME']

#
# These are some fake inputs for our tests.
# Test with max username length (30 chars) to make sure it works.
#
fake_username = 'NananaNananaNananaNananaBatman'
fake_api_key = 'f4K3-4Pi-k3Y'
fake_access_token = 'f4K3-4CC355-t0k3N'

#
# Quick Mocks to avoid using other functions than those under test per test
#
mocked_path_to_certs = os.path.join(
    os.getcwd(), os.path.relpath(user_input_path_to_certs) + os.sep)
mocked_path_to_config = os.path.join(
    os.getcwd(),os.path.relpath(user_input_path_to_config))
mocked_get_hash = str(uuid.uuid4())[:30]
mocked_build_subdomain = fake_username[:(32-len(test_domain))] + '-' + mocked_get_hash
mocked_build_host = mocked_build_subdomain + '.' + test_domain
mocked_encoded_api_key = base64.b64encode(
    six.b('{0}:{1}'.format(fake_username, fake_api_key))).decode('utf8')

def mock_create_certs():
    # Make empty directories for certs
    os.mkdir(user_input_path_to_certs)
    domain_cert_folder = os.path.join(
        os.getcwd(), user_input_path_to_certs, mocked_build_host)
    os.mkdir(domain_cert_folder)

    # Create fake certs
    key=RSA.gen_key(2048, 65537)
    test_key = os.path.join(domain_cert_folder, 'privkey.pem')
    test_cert = os.path.join(domain_cert_folder, 'fullchain.pem')
    key.save_pem(test_cert, cipher=None)
    key.save_pub_key(test_key)
    return test_key, test_cert

#
# Constants
#
CURRENT = '/v2/users/current'

# # #
# Integration tests that test the full flow when hitting a route.
#
class TestServerRoutes(unittest.TestCase):
    def setUp(self):
        self.server = Server({'port': user_input_port,
            'path_to_config': user_input_path_to_config,
            'path_to_certs': user_input_path_to_certs,
            'processes': user_input_processes})

    def test_ping(self):
        with self.server.app.test_client() as app_under_test:
            res = app_under_test.get('/ping')
            self.assertEqual(res.data, 'pong')

    # Successful case: access_token
    def test_certificate_post_success_with_token(self):
        with self.server.app.test_client() as app_under_test:
            start_time = time.time()
            res = app_under_test.post('/certificate', data=json.dumps({
                'credentials': {
                    'username': correct_username,
                    'access_token': correct_access_token,
                    'plotly_api_domain': test_plotly_api_domain
                }
            }))
            self.assertTrue((time.time() - start_time) < 120)
            response_object = json.loads(res.data)
            # Returns the certificate, the key and the subdomain used.
            self.assertIn('cert', response_object)
            self.assertIn('key', response_object)
            self.assertIn('subdomain', response_object)
            self.assertIsNotNone(response_object.get('cert'))
            self.assertIsNotNone(response_object.get('key'))
            self.assertIn(correct_username[:7], response_object.get('subdomain'))

    # Successful case: api_key
    def test_certificate_post_success_with_key(self):
        with self.server.app.test_client() as app_under_test:
            start_time = time.time()
            res = app_under_test.post('/certificate', data=json.dumps({
                'credentials': {
                    'username': correct_username,
                    'api_key': correct_api_key,
                    'plotly_api_domain': test_plotly_api_domain
                }
            }))
            self.assertTrue((time.time() - start_time) < 120)
            response_object = json.loads(res.data)
            # Returns the certificate, the key and the subdomain used.
            self.assertIn('cert', response_object)
            self.assertIn('key', response_object)
            self.assertIn('subdomain', response_object)
            self.assertIsNotNone(response_object.get('cert'))
            self.assertIsNotNone(response_object.get('key'))
            self.assertIn(correct_username[:7], response_object.get('subdomain'))

    # Failing case: no username
    def test_certificate_post_error_no_username(self):
        with self.server.app.test_client() as app_under_test:
            res = app_under_test.post('/certificate', data=json.dumps({
                'credentials':
                    {'access_token': correct_access_token,
                    'plotly_api_domain': test_plotly_api_domain}
            }))
            self.assertTrue('error' in json.loads(res.data))

    # Failing case: bad authorization
    def test_certificate_post_error_bad_token(self):
        with self.server.app.test_client() as app_under_test:
            res = app_under_test.post('/certificate', data=json.dumps({
                'credentials': {
                    'username': correct_username,
                    'access_token': fake_access_token,
                    'plotly_api_domain': test_plotly_api_domain
                }
            }))
            self.assertTrue('error' in json.loads(res.data))

    # Delete certificates folder after each test to start from a clean state.
    def tearDown(self):
        try:
            shutil.rmtree(os.path.join(os.getcwd(), user_input_path_to_certs))
        except:
            pass


# # #
# Functional tests that test specific functions of the server.
#
class TestServerFunctions(unittest.TestCase):

    def setUp(self):
        self.server = Server({'port': user_input_port,
            'path_to_config': user_input_path_to_config,
            'path_to_certs': user_input_path_to_certs,
            'processes': user_input_processes})

    def test_constructor(self):
        self.assertEqual(self.server.port, user_input_port)
        self.assertEqual(self.server.domain, test_domain)
        self.assertEqual(self.server.processes, user_input_processes)
        self.assertEqual(self.server.path_to_certs, mocked_path_to_certs)
        self.assertEqual(
            self.server.dehydrated_command,
            [os.getcwd() + '/dehydrated/dehydrated',
            '-c',
            '-f',
            mocked_path_to_config])

    def test_build_host(self):
        self.assertEqual(
            self.server.build_host(mocked_build_subdomain),
            mocked_build_subdomain + '.' + test_domain)

    def test_build_subdomain(self):
        build_subdomain_under_test = self.server.build_subdomain(fake_username)

        self.assertEqual(
            len(mocked_build_subdomain), len(build_subdomain_under_test))

    def test_get_key_path(self):
        expected_path = os.path.join(
            mocked_path_to_certs + mocked_build_host + '/privkey.pem')

        self.assertEqual(
            self.server.get_key_path(mocked_build_subdomain),
            expected_path)

    def test_get_cert_path(self):
        expected_path =  os.path.join(
            mocked_path_to_certs + mocked_build_host + '/fullchain.pem')

        self.assertEqual(
            self.server.get_cert_path(mocked_build_subdomain), expected_path)

    def test_cert_and_key_exist(self):
        # Check certs do not exist
        self.assertEqual(
            self.server.cert_and_key_exist(mocked_build_subdomain),
            False)

        # Create fake certs
        test_key, test_cert = mock_create_certs()

        # Check certs exist
        self.assertEqual(
            self.server.cert_and_key_exist(mocked_build_subdomain),
            True)

        # Clean up
        os.remove(test_key)
        os.remove(test_cert)
        os.removedirs(os.path.join(
            os.getcwd(),
            user_input_path_to_certs,
            mocked_build_host))

    def test_get_cert_and_key(self):
        with self.assertRaises(Exception) as context:
            certs = self.server.get_cert_and_key(mocked_build_subdomain)
        print(context.exception)
        self.assertTrue('Certificates were not found.' in context.exception)

    def test_delete_certs_folder_if_exists(self):
        # Create fake certs
        test_key, test_cert = mock_create_certs()

        # Delete them
        self.server.delete_certs_folder_if_exists(mocked_build_subdomain)
        self.assertFalse(os.path.exists(test_key))
        self.assertFalse(os.path.exists(test_cert))

        # Clean up
        os.removedirs(user_input_path_to_certs)

    def test_encode_api_key(self):
        expected_key = base64.b64encode(
            six.b('{0}:{1}'.format(fake_username, fake_api_key))).decode('utf8')
        encoded_key = self.server.encode_api_key(fake_username, fake_api_key)

        self.assertNotEqual(encoded_key, fake_api_key)
        self.assertIsNotNone(encoded_key)
        self.assertEqual(expected_key, encoded_key)

    def test_get_headers(self):
        # Correct credentials with api_key
        credentials = {'username': fake_username, 'api_key': fake_api_key}
        headers_under_test = self.server.get_headers(credentials)
        self.assertTrue('authorization' in headers_under_test)
        self.assertEqual('Basic ' + self.server.encode_api_key(
            fake_username, fake_api_key), headers_under_test['authorization'])

        # Correct credentials with access_token
        credentials = {
            'username': fake_username,
            'access_token': fake_access_token}
        headers_under_test = self.server.get_headers(credentials)
        self.assertTrue('authorization' in headers_under_test)
        self.assertEqual('Bearer ' + fake_access_token,
            headers_under_test['authorization'])

        # No key or token
        credentials = {'username': fake_username}
        self.assertFalse(
            'authorization' in self.server.get_headers(credentials))

    def test_get_hash(self):
        self.assertEqual(len(self.server.get_hash()), len(mocked_get_hash))
        # Make sure it's not always returning the same hash
        self.assertNotEqual(self.server.get_hash(), self.server.get_hash())

    def test_call_plotly_api(self):
        # Failing case: access_token
        credentials = {
            'username': fake_username,
            'access_token': fake_access_token,
            'plotly_api_domain': test_plotly_api_domain
        }
        response = self.server.call_plotly_api(CURRENT, credentials)
        content = json.loads(response.content)
        self.assertFalse(bool(content.get('username')),
            'Expected to fail with fake access token.')

        # Failing case: api_key
        credentials = {
            'username': fake_username,
            'api_key': fake_api_key,
            'plotly_api_domain': test_plotly_api_domain
        }
        response = self.server.call_plotly_api(CURRENT, credentials)
        content = json.loads(response.content)
        self.assertFalse(bool(content.get('username')),
            'Expected to fail with fake api key.')

        # Successful case: access_token
        credentials = {
            'username': correct_username,
            'access_token': correct_access_token,
            'plotly_api_domain': test_plotly_api_domain
        }
        response = self.server.call_plotly_api(CURRENT, credentials)
        content = json.loads(response.content)
        self.assertEqual(
            content.get('username'), 'alexandres', 'Failed with access token.')

        # Successful case: api_key
        credentials = {
            'username': correct_username,
            'api_key': correct_api_key,
            'plotly_api_domain': test_plotly_api_domain
        }
        response = self.server.call_plotly_api(CURRENT, credentials)
        content = json.loads(response.content)
        self.assertEqual(
            content.get('username'), 'alexandres', 'Failed with api key.')

    def test_user_is_verified(self):
        # Failing case: no plotly domain
        credentials = {
            'username': fake_username,
            'api_key': fake_api_key
        }
        self.assertFalse(self.server.user_is_verified(credentials))

        # Failing case: no username
        credentials = {
            'api_key': fake_api_key,
            'plotly_api_domain': test_plotly_api_domain
        }
        self.assertFalse(self.server.user_is_verified(credentials))

        # Failing case: bad api_key
        credentials = {
            'username': fake_username,
            'api_key': fake_api_key,
            'plotly_api_domain': test_plotly_api_domain
        }
        self.assertFalse(self.server.user_is_verified(credentials))

        # Failing case: bad access_token
        credentials = {
            'username': fake_username,
            'access_token': fake_access_token,
            'plotly_api_domain': test_plotly_api_domain
        }
        self.assertFalse(self.server.user_is_verified(credentials))

        # Failing case: good access_token but wrong username
        credentials = {
            'username': fake_username,
            'access_token': correct_access_token,
            'plotly_api_domain': test_plotly_api_domain
        }
        self.assertFalse(self.server.user_is_verified(credentials))

        # Successful case
        credentials = {
            'username': correct_username,
            'access_token': correct_access_token,
            'plotly_api_domain': test_plotly_api_domain
        }
        self.assertTrue(self.server.user_is_verified(credentials))

    # TODO: Add a tests for catching TimtoutError and ProcessError in
    # server.execute_letsencrypt_client()

    # Delete certificates folder after each test to start from a clean state.
    def tearDown(self):
        try:
            shutil.rmtree(os.path.join(os.getcwd(), user_input_path_to_certs))
        except:
            pass

if __name__ == '__main__':
    unittest.main()
