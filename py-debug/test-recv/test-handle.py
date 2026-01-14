from aiohttp import web
import json
import asyncio


class Handler():
    def __init__(self):
        self.app = web.Application()
        self.app.add_routes([

            web.get('/', self.handle)

                             ])

    async def handle(self, request):
        sender = request.remote
        data = request.json

        print(f"New packet for {sender}. Data: {data};") # Change for logger

        return web.Response(status=200)


    async def run(self):
        web.run_app(self.app)