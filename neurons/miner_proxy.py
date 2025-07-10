# credit: https://github.com/BitMind-AI/bitmind-subnet
from fastapi import FastAPI, Depends, Request
from concurrent.futures import ThreadPoolExecutor
from uvicorn import Config, Server
import bittensor as bt
import uvicorn
import asyncio

class MinerProxy:
    def __init__(
        self,
        miner,
    ):
        self.miner = miner
        self.executor: ThreadPoolExecutor | None = None
        # self.dendrite = bt.dendrite(wallet=miner.wallet)

        self.app = FastAPI()
        self.app.add_api_route(
            "/",
            self.healthcheck,
            methods=["GET"],
            dependencies=[Depends(self.get_self)],
        )
        self.app.add_api_route(
            "/healthcheck",
            self.healthcheck,
            methods=["GET"],
            dependencies=[Depends(self.get_self)],
        )

        self.loop = asyncio.get_event_loop()
        if self.miner.config.proxy.port:
            self.start_server()
            port = self.miner.config.proxy.port
            bt.logging.info(f"Miner proxy server up! Port {port} e.g.\n\tGET http://localhost:{port}/healthcheck")

    def start_server(self):
        config = Config(
            app=self.app,
            host="0.0.0.0",
            port=self.miner.config.proxy.port,
            log_level="info",
        )
        self.uvicorn_server = Server(config)

        def run_uvicorn():
            asyncio.run(self.uvicorn_server.serve())

        self.executor = ThreadPoolExecutor(max_workers=1)
        self.executor.submit(run_uvicorn)

    async def stop_server(self):
        if self.uvicorn_server and self.uvicorn_server.started:
            self.uvicorn_server.should_exit = True

        self.executor.shutdown(wait=True)

    async def healthcheck(self, request: Request):
        return {'status': 'healthy'}

    async def get_self(self):
        return self
