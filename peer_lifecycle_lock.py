"""Serialize peer/inventory mutations without holding the data lock over SSH."""
import asyncio
import contextvars
import functools
import inspect
import weakref


_mutation_locks = weakref.WeakKeyDictionary()
_active = contextvars.ContextVar('peer_lifecycle_active', default=False)


def serialize_peer_lifecycle(function):
    """Interlock ownership changes with destructive network operations.

    This is separate from DATA_LOCK: reads, traffic commits and access intent
    updates continue while SSH runs. As with DATA_LOCK, one panel process is
    required. A cancelled waiter never runs; an already-started worker keeps
    the interlock until its external effects and local commit have finished.
    """
    @functools.wraps(function)
    async def wrapped(*args, **kwargs):
        async def invoke():
            if inspect.iscoroutinefunction(function):
                return await function(*args, **kwargs)
            return await asyncio.to_thread(function, *args, **kwargs)
        if _active.get():
            return await invoke()
        loop = asyncio.get_running_loop()
        lock = _mutation_locks.setdefault(loop, asyncio.Lock())
        started = asyncio.Event()

        async def work():
            async with lock:
                started.set()
                token = _active.set(True)
                try:
                    return await invoke()
                finally:
                    _active.reset(token)

        task = asyncio.create_task(work())
        def finished(done):
            if not done.cancelled():
                done.exception()
        task.add_done_callback(finished)
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            if not started.is_set():
                task.cancel()
            raise
    return wrapped

