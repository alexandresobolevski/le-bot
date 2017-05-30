#!/usr/bin/env python

import unittest

from M2Crypto import RSA
import base64
import json
import grequests
import os
import shutil
import six
import subprocess
import tempfile
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
correct_username = os.environ['PLOTLY_USERNAME']

#
# These are some fake inputs for our tests.
# Test with max username length (25 chars) to make sure it works.
#
fake_username = 'NananaNananaNananaNananaBatman'
fake_api_key = 'f4K3-4Pi-k3Y'
fake_access_token = 'f4K3-4CC355-t0k3N'

#
# Quick Mocks to avoid using other functions than those under test per test
#
mocked_path_to_config = os.path.join(
    os.getcwd(), os.path.relpath(user_input_path_to_config))
mocked_get_hash = str(uuid.uuid4())
mocked_build_subdomain = fake_username[:7] + '-' + mocked_get_hash[:25]
mocked_build_host = mocked_build_subdomain + '.' + test_domain
mocked_encoded_api_key = base64.b64encode(
    six.b('{0}:{1}'.format(fake_username, fake_api_key))).decode('utf8')


def mock_create_certs(cert_dir):
    domain_cert_folder = os.path.join(os.getcwd(), cert_dir, mocked_build_host)
    os.mkdir(domain_cert_folder)

    # Create fake certs.  Note that the "cert" is actually a key for ease
    # of implementation.  This works because get_cert_and_key() doesn't
    # actually check the type of the item it extracted.  If get_cert_and_key()
    # is ever improved, this function will need to be improved too.
    key = RSA.gen_key(2048, 65537)
    test_key = os.path.join(domain_cert_folder, 'privkey.pem')
    test_cert = os.path.join(domain_cert_folder, 'fullchain.pem')
    key.save_key(test_key, cipher=None)
    key.save_key(test_cert, cipher=None)
    return test_key, test_cert

#
# Constants
#
CURRENT = '/v2/users/current'


class TestServerPerformance(unittest.TestCase):

    def setUp(self):
        self.server_process = subprocess.Popen(['python', 'le_server.py', '--path_to_config', './config_staging'], stdout=subprocess.PIPE)
        # Let the server start up.
        time.sleep(5)

    @unittest.skip('This test has too many intermittent failures. Need to improve this.')
    def test_concurrent_requests(self):
        start_time = time.time()
        # A simple task to do to each response object
        def verify_response(res):
            self.assertTrue((time.time() - start_time) < 120)
            response_object = json.loads(res.content)
            # Returns the certificate, the key and the subdomain used.
            self.assertIn('cert', response_object)
            self.assertIn('key', response_object)
            self.assertIn('subdomain', response_object)
            self.assertIsNotNone(response_object.get('cert'))
            self.assertIsNotNone(response_object.get('key'))
            self.assertIn(correct_username[:7], response_object.get('subdomain'))
            print 'All good.'


        N = 2
        async_requests = (grequests.post('http://localhost:8080/certificate', data=json.dumps({
            'credentials': {
                'username': correct_username,
                'api_key': correct_api_key,
                'plotly_api_domain': test_plotly_api_domain
            }
        })) for _ in range(N))

        async_responses = grequests.map(async_requests)
        print async_responses
        for res in async_responses:
            verify_response(res)


class TestServerRoutes(unittest.TestCase):
    """
    # # #
    # Integration tests that test the full flow when hitting a route.
    #
    """
    def setUp(self):
        self.path_to_logs = tempfile.mkdtemp()

        self.server = Server({
            'port': user_input_port,
            'path_to_config': user_input_path_to_config,
            'path_to_certs': user_input_path_to_certs,
            'processes': user_input_processes,
            'path_to_logs': self.path_to_logs})

    # Delete certificates folder after each test to start from a clean state.
    def tearDown(self):
        try:
            shutil.rmtree(os.path.join(os.getcwd(), user_input_path_to_certs))
        except:
            pass
        shutil.rmtree(self.path_to_logs)

    def test_ping(self):
        with self.server.app.test_client() as app_under_test:
            res = app_under_test.get('/ping')
            self.assertEqual(res.data, 'pong')

    def test_certificate_post_success(self):
        with self.server.app.test_client() as app_under_test:
            start_time = time.time()
            res = app_under_test.post('/certificate', data=json.dumps({
                'credentials': {
                    'username': correct_username,
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
                'credentials': {}
            }))
            self.assertTrue('error' in json.loads(res.data))


class TestServerFunctions(unittest.TestCase):
    """
    # # #
    # Functional tests that test specific functions of the server.
    #
    """
    def setUp(self):
        self.path_to_logs = tempfile.mkdtemp()
        self.path_to_certs = tempfile.mkdtemp()

        self.server = Server({
            'port': user_input_port,
            'path_to_config': user_input_path_to_config,
            'path_to_certs': self.path_to_certs,
            'processes': user_input_processes,
            'path_to_logs': self.path_to_logs})

    def tearDown(self):
        shutil.rmtree(self.path_to_logs)
        shutil.rmtree(self.path_to_certs)

    def test_constructor(self):
        self.assertEqual(self.server.port, user_input_port)
        self.assertEqual(self.server.domain, test_domain)
        self.assertEqual(self.server.processes, user_input_processes)
        self.assertEqual(self.server.path_to_certs, mocked_path_to_certs)
        self.assertEqual(
            self.server.dehydrated_command, [
                os.getcwd() + '/dehydrated-0.3.1/dehydrated',
                '-c',
                '-n',
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
        expected_path = os.path.join(
            mocked_path_to_certs + mocked_build_host + '/fullchain.pem')

        self.assertEqual(
            self.server.get_cert_path(mocked_build_subdomain), expected_path)

    def test_cert_and_key_exist(self):
        # Check certs do not exist
        self.assertEqual(
            self.server.cert_and_key_exist(mocked_build_subdomain),
            False)

        # Create fake certs
        test_key, test_cert = mock_create_certs(self.path_to_certs)

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
        test_key, test_cert = mock_create_certs(self.path_to_certs)

        # Delete them
        self.server.delete_certs_folder_if_exists(mocked_build_subdomain)
        self.assertFalse(os.path.exists(test_key))
        self.assertFalse(os.path.exists(test_cert))

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
        self.assertEqual(
            'Bearer ' + fake_access_token,
            headers_under_test['authorization'])

        # No key or token
        credentials = {'username': fake_username}
        self.assertFalse(
            'authorization' in self.server.get_headers(credentials))

    def test_get_hash(self):
        self.assertEqual(len(self.server.get_hash()), len(mocked_get_hash))
        # Make sure it's not always returning the same hash
        self.assertNotEqual(self.server.get_hash(), self.server.get_hash())

    def test_user_is_verified(self):
        # Failing case: no username
        credentials = {
            'api_key': fake_api_key,
            'plotly_api_domain': test_plotly_api_domain
        }
        self.assertFalse(self.server.user_is_verified(credentials))

        # Successful case
        credentials = {
            'username': correct_username,
        }
        self.assertTrue(self.server.user_is_verified(credentials))

    # TODO: Add a tests for catching TimtoutError and ProcessError in
    # server.execute_letsencrypt_client()


if __name__ == '__main__':
    unittest.main()
