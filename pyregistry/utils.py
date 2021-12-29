import asyncio
from typing import Any


async def async_generator_buffer(gen, buffer_size):
    """
    Automatically buffer a few elements of an async generator and yield
    the buffered results as another async generator.
    """

    cond = asyncio.Condition()

    output_pos = 0
    output_size = 0
    output_complete = False
    outputs = [None for _ in range(buffer_size)]

    async def _fill_buffer():
        nonlocal output_pos, output_size, output_complete
        try:
            async for value in gen:
                async with cond:
                    while output_size == buffer_size:
                        await cond.wait()
                    outputs[(output_pos + output_size) % buffer_size] = value
                    output_size += 1
                    cond.notify()
        finally:
            async with cond:
                output_complete = True
                cond.notify()

    fill_buffer_task = asyncio.create_task(_fill_buffer())

    while True:
        async with cond:
            while not output_complete and output_size == 0:
                await cond.wait()

            if output_complete and output_size == 0:
                break

            value = outputs[output_pos]
            output_pos = (output_pos + 1) % buffer_size
            output_size -= 1
            cond.notify()
        yield value

    # Make sure task has completed, propagate any failure
    await fill_buffer_task


class ReleaseableAsyncContextManager:
    """
    A context manager that allows for a context to be released and then
    re-entered. This is useful when you want to explicitly return a context
    manager that you already entered back to the client and leave them
    responsible for closing the context.
    """

    NO_ENTRY_VALUE = object()

    def __init__(
        self,
        acm,
        *,
        value: Any = NO_ENTRY_VALUE,
    ) -> None:
        self.acm = acm
        self.value = value

    async def __aenter__(self):
        if self.value is self.NO_ENTRY_VALUE:
            self.value = await self.acm.__aenter__()
        return self.value

    async def __aexit__(self, exc_typ, exc_val, exc_tb) -> None:
        if self.acm is not None:
            await self.acm.__aexit__(exc_typ, exc_val, exc_tb)

    def release(self):
        """
        Create a new context manager that wraps the currently wrapped
        context manager in a way that the caller is now responsible for
        releasing the resources of the wrapped context manager.
        """
        acm = self.acm
        self.acm = None
        return ReleaseableAsyncContextManager(acm, value=self.value)
