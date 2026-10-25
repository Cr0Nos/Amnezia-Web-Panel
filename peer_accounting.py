"""Conservative preconditions until a stopped-peer accounting receipt exists.

Neither enabled=False nor a successful SSH scrape proves that a peer can no
longer transfer traffic. Keep its owner and baselines even for unlimited users.
"""
from peer_lifecycle_lock import serialize_peer_lifecycle
import functools


FINALIZATION_MESSAGE = (
    'Final traffic accounting is required before removing a user-linked peer. '
    'Keep the connection linked until a verified final counter receipt is available.'
)


class TrafficFinalizationRequired(RuntimeError):
    code = 'traffic_finalization_required'

    def __init__(self):
        super().__init__(FINALIZATION_MESSAGE)


def require_unowned(data, *, server_id=None, protocol=None, client_id=None,
                    user_ids=None):
    """Reject a destructive scope containing any accounting ownership record.

    Match the exact protocol instance, not its base name. A dangling user ID is
    still ownership: deleting a user elsewhere is not finalization evidence.
    """
    for conn in data.get('user_connections', []):
        if server_id is not None and conn.get('server_id') != server_id:
            continue
        if protocol is not None and conn.get('protocol') != protocol:
            continue
        if client_id is not None and conn.get('client_id') != client_id:
            continue
        if user_ids is not None and conn.get('user_id') not in user_ids:
            continue
        raise TrafficFinalizationRequired()


def guard_user_deletions(load_data):
    """Preflight a whole mixed batch before its toggle/create phases run."""
    def decorate(function):
        @functools.wraps(function)
        async def guarded(delete_uids=None, toggle_uids=None, create_conns=None):
            if delete_uids:
                require_unowned(load_data(), user_ids=set(delete_uids))
            return await function(delete_uids, toggle_uids, create_conns)
        return guarded
    return decorate
