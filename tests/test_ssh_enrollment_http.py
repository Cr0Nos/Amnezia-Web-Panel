"""HTTP authorization and explicit confirmation, without loading real state."""
import ast
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from pydantic import BaseModel, StrictBool, constr
from managers import ssh_trust


class EnrollmentHTTPTests(unittest.TestCase):
    def setUp(self):
        tree = ast.parse((Path(__file__).resolve().parents[1] / 'app.py').read_text(encoding='utf-8'))
        names = {'SSHTrustConfirmation', '_ssh_trust_admin', 'api_ssh_trust_inspect', 'api_ssh_trust_confirm'}
        nodes = [n for n in tree.body if getattr(n, 'name', '') in names]
        self.assertEqual(len(nodes), 4, 'SSH trust routes and request model must exist')
        self.user = {'role': 'admin'}
        self.server = {'host': 'example.test', 'ssh_port': 22, 'uid': 'a'}
        self.trust = mock.Mock()
        self.trust.inspect.return_value = {'status': 'unknown', 'token': 'abc'}
        self.trust.enroll.return_value = {'status': 'success'}
        self.drop = mock.Mock()
        app = FastAPI()
        self.data_lock = threading.RLock()
        ns = dict(app=app, Request=Request, JSONResponse=JSONResponse, BaseModel=BaseModel,
                  StrictBool=StrictBool, constr=constr, ssh_trust=self.trust,
                  _check_admin=lambda request: self.user, load_data=lambda: {'servers': [self.server]},
                  drop_ssh=self.drop, data_manager=SimpleNamespace(lock=self.data_lock))
        exec(compile(ast.Module(body=nodes, type_ignores=[]), '<trust routes>', 'exec'), ns)
        self.client = TestClient(app)

    def test_admin_only(self):
        for user in [None, {'role': 'support'}, {'role': 'user'}]:
            self.user = user
            for action in ['inspect', 'confirm']:
                response = self.client.post('/api/servers/0/ssh-trust/' + action,
                                            json={'token': 'abc', 'confirmed': True})
                self.assertEqual(response.status_code, 403)
        self.trust.inspect.assert_not_called()
        self.trust.enroll.assert_not_called()

    def test_confirmation_and_reset(self):
        self.assertEqual(self.client.post('/api/servers/0/ssh-trust/inspect').status_code, 200)
        self.assertEqual(self.client.post('/api/servers/0/ssh-trust/confirm', json={'token': 'abc', 'confirmed': False}).status_code, 400)
        self.trust.enroll.assert_not_called()
        self.assertEqual(self.client.post('/api/servers/0/ssh-trust/confirm', json={'token': 'abc', 'confirmed': True}).status_code, 200)
        self.drop.assert_called_once_with(self.server)

    def test_confirmation_serializes_endpoint_mutations(self):
        def enroll(*args, **kwargs):
            self.assertTrue(self.data_lock._is_owned())
            return {'status': 'success'}
        self.trust.enroll.side_effect = enroll
        response = self.client.post('/api/servers/0/ssh-trust/confirm',
                                    json={'token': 'abc', 'confirmed': True})
        self.assertEqual(response.status_code, 200, response.text)

    def test_errors(self):
        # Browser Fetch Metadata is not script-settable. TLS termination may
        # leave request.base_url as HTTP while the browser origin is HTTPS.
        response = self.client.post('/api/servers/0/ssh-trust/inspect',
                                    headers={'Origin': 'https://testserver', 'Sec-Fetch-Site': 'same-origin'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.post('/api/servers/0/ssh-trust/inspect', headers={'Origin': 'https://evil.example'}).status_code, 403)
        self.assertEqual(self.client.post('/api/servers/-1/ssh-trust/inspect').status_code, 404)
        for body in [{}, {'token': '', 'confirmed': True}, {'token': 'abc', 'confirmed': 'yes'}]:
            self.assertEqual(self.client.post('/api/servers/0/ssh-trust/confirm', json=body).status_code, 422)
        self.trust.enroll.side_effect = ValueError('candidate changed')
        response = self.client.post('/api/servers/0/ssh-trust/confirm', json={'token': 'abc', 'confirmed': True})
        self.assertEqual(response.status_code, 409)
        self.drop.assert_not_called()
