"""Run the real unlink handler and atomic JSON storage without SSH/startup."""
import ast
import asyncio
import copy
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from fastapi.responses import JSONResponse


SOURCE = Path(__file__).resolve().parents[1] / 'app.py'
GIB = 1024 ** 3


class UnlinkAccountingGuard(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='panel-unlink-accounting-')
        self.addAsyncCleanup(self.cleanup)
        self.file = Path(self.temp.name) / 'data.json'
        names = {'load_data', 'save_data', 'api_unlink_user_connection',
                 '_traffic_removal_guard'}
        nodes = [n for n in ast.parse(SOURCE.read_text(encoding='utf-8')).body
                 if getattr(n, 'name', '') in names]
        self.assertEqual({n.name for n in nodes}, names)
        for node in nodes:
            node.decorator_list = []
        self.ns = dict(
            asyncio=asyncio, os=os, json=json, tempfile=tempfile,
            DATA_FILE=str(self.file), DATA_LOCK=asyncio.Lock(),
            DEFAULT_MAIL_SETTINGS={}, DEFAULT_SELF_SERVICE_SETTINGS={},
            Request=object, UnlinkConnectionRequest=object,
            JSONResponse=JSONResponse, _check_admin=lambda request: request.admin,
        )
        exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])),
                     str(SOURCE), 'exec'), self.ns)
        self.data = {
            'users': [dict(id='user-a', enabled=True, traffic_limit=500*GIB,
                           traffic_used=450*GIB, traffic_total=700*GIB),
                      dict(id='user-b', enabled=True)],
            'servers': [dict(uid='server-a'), dict(uid='server-b')],
            'user_connections': [dict(id='conn-a', user_id='user-a', server_id=0,
                                      protocol='awg3', client_id='peer-a', last_bytes=10*GIB),
                                 dict(id='conn-b', user_id='user-b', server_id=0,
                                      protocol='awg3', client_id='peer-b', last_bytes=4*GIB)],
        }
        self.ns['save_data'](copy.deepcopy(self.data))
        self.request = SimpleNamespace(admin=True)
        self.req = SimpleNamespace(server_id=0, protocol='awg3', client_id='peer-a')

    async def cleanup(self):
        self.temp.cleanup()

    async def unlink(self, user='user-a', **changes):
        req = SimpleNamespace(**(vars(self.req) | changes))
        return await self.ns['api_unlink_user_connection'](self.request, user, req)

    async def test_active_peer_retains_owner_and_unpolled_traffic_baseline(self):
        before = self.file.read_bytes()
        result = await self.unlink()
        self.assertEqual(result.status_code, 409)
        self.assertEqual(json.loads(result.body)['code'], 'traffic_finalization_required')
        self.assertEqual(self.file.read_bytes(), before)
        self.assertEqual(self.ns['load_data']()['user_connections'][0]['last_bytes'], 10*GIB)

    async def test_disabled_metadata_is_not_finalization_proof(self):
        for reasons in (None, ['manual'], ['quota'], ['expired'], ['legacy']):
            with self.subTest(reasons=reasons):
                data = copy.deepcopy(self.data)
                data['users'][0].update(enabled=False, access_sync_pending=True)
                if reasons is not None:
                    data['users'][0]['disable_reasons'] = reasons
                self.ns['save_data'](data)
                before = self.file.read_bytes()
                self.assertEqual((await self.unlink()).status_code, 409)
                self.assertEqual(self.file.read_bytes(), before)

    async def test_unlimited_quota_still_retains_lifetime_accounting(self):
        data = copy.deepcopy(self.data)
        data['users'][0]['traffic_limit'] = 0
        self.ns['save_data'](data)
        before = self.file.read_bytes()
        self.assertEqual((await self.unlink()).status_code, 409)
        self.assertEqual(self.file.read_bytes(), before)

    async def test_repeated_and_concurrent_unlink_are_non_destructive(self):
        before = self.file.read_bytes()
        results = await asyncio.gather(self.unlink(), self.unlink())
        self.assertEqual([r.status_code for r in results], [409, 409])
        self.assertEqual((await self.unlink()).status_code, 409)
        self.assertEqual(self.file.read_bytes(), before)

    async def test_target_is_resolved_after_waiting_for_current_data(self):
        lock = self.ns['DATA_LOCK']
        await lock.acquire()
        entered = asyncio.Event()

        async def queued():
            entered.set()
            return await self.unlink()

        task = asyncio.create_task(queued())
        await entered.wait()
        try:
            self.assertFalse(task.done())
            data = copy.deepcopy(self.data)
            data['user_connections'][0]['user_id'] = 'user-b'
            self.ns['save_data'](data)
            before = self.file.read_bytes()
        finally:
            lock.release()
        self.assertEqual((await task).status_code, 404)
        self.assertEqual(self.file.read_bytes(), before)

    async def test_wrong_user_server_protocol_or_client_cannot_touch_links(self):
        for user, change in [('user-b', {}), ('user-a', {'server_id': 1}),
                             ('user-a', {'protocol': 'wireguard'}),
                             ('user-a', {'client_id': 'unknown'})]:
            with self.subTest(user=user, change=change):
                before = self.file.read_bytes()
                self.assertEqual((await self.unlink(user, **change)).status_code, 404)
                self.assertEqual(self.file.read_bytes(), before)

    async def test_anonymous_or_nonadmin_is_rejected_without_mutation(self):
        self.request.admin = False
        before = self.file.read_bytes()
        self.assertEqual((await self.unlink()).status_code, 403)
        self.assertEqual(self.file.read_bytes(), before)

    async def test_cancellation_while_waiting_cannot_commit_a_late_unlink(self):
        lock = self.ns['DATA_LOCK']
        await lock.acquire()
        entered = asyncio.Event()

        async def queued():
            entered.set()
            return await self.unlink()

        task = asyncio.create_task(queued())
        await entered.wait()
        before = self.file.read_bytes()
        task.cancel()
        try:
            with self.assertRaises(asyncio.CancelledError):
                await task
        finally:
            lock.release()
        self.assertEqual(self.file.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
