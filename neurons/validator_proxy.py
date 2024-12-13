# credit: https://github.com/BitMind-AI/bitmind-subnet
from fastapi import FastAPI, HTTPException, Depends, Request
from concurrent.futures import ThreadPoolExecutor
from starlette.concurrency import run_in_threadpool
import bittensor as bt
import uvicorn
import os
import asyncio
import random
import numpy as np
import socket

from bitsec.protocol import prepare_code_synapse, TaskCategory
from bitsec.utils.uids import get_random_uids
from bitsec.validator.proxy import ProxyCounter

class ValidatorProxy:
    def __init__(
        self,
        validator,
    ):
        self.validator = validator
        self.get_credentials()
        self.miner_request_counter = {}
        self.dendrite = bt.dendrite(wallet=validator.wallet)
        self.app = FastAPI()
        self.app.add_api_route(
            "/validator_proxy",
            self.forward,
            methods=["POST"],
            dependencies=[Depends(self.get_self)],
        )
        self.app.add_api_route(
            "/healthcheck",
            self.healthcheck,
            methods=["GET"],
            dependencies=[Depends(self.get_self)],
        )
        self.app.add_api_route(
            "/metagraph",
            self.get_metagraph,
            methods=["GET"],
            dependencies=[Depends(self.get_self)],
        )

        self.loop = asyncio.get_event_loop()
        self.proxy_counter = ProxyCounter(
            os.path.join(self.validator.config.neuron.full_path, "proxy_counter.json")
        )
        if self.validator.config.proxy.port:
            self.start_server()

    def get_credentials(self):
        # with httpx.Client(timeout=httpx.Timeout(30)) as client:
        #     response = client.post(
        #         f"{self.validator.config.proxy.proxy_client_url}/get-credentials",
        #         json={
        #             "postfix": (
        #                 f":{self.validator.config.proxy.port}/validator_proxy"
        #                 if self.validator.config.proxy.port
        #                 else ""
        #             ),
        #             "uid": self.validator.uid,
        #         },
        #     )
        # response.raise_for_status()
        # response = response.json()
        # message = response["message"]
        # signature = response["signature"]
        # signature = base64.b64decode(signature)
        
        ## 9/24/24 stub signature
        signature = "IS+hUytiJyVZkt3FvQPHvj+4RudYM0mUKEh+GXWQbAVQHgON2EzHnYk0xbgezS0Rq7HBbFyWKISB7AIoQzA/AA=="

        def verify_credentials(public_key_bytes):
            # public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            # try:
            #     public_key.verify(signature, message.encode("utf-8"))
            # except InvalidSignature:
            #     raise Exception("Invalid signature")
            ## 9/24/24 stub verification
            return True

        self.verify_credentials = verify_credentials

    def start_server(self):
        self.executor = ThreadPoolExecutor(max_workers=1)
        self.executor.submit(
            uvicorn.run, self.app, host="0.0.0.0", port=self.validator.config.proxy.port
        )

    # def authenticate_token(self, public_key_bytes):
    #     public_key_bytes = base64.b64decode(public_key_bytes)
    #     try:
    #         self.verify_credentials(public_key_bytes)
    #         bt.logging.info("Successfully authenticated token")
    #         return public_key_bytes
    #     except Exception as e:
    #         bt.logging.error(f"Exception occured in authenticating token: {e}")
    #         bt.logging.error(traceback.print_exc())
    #         raise HTTPException(
    #             status_code=401, detail="Error getting authentication token"
    #         )

    async def healthcheck(self, request: Request):
        # authorization: str = request.headers.get("authorization")

        # if not authorization:
        #     raise HTTPException(status_code=401, detail="Authorization header missing")

        # self.authenticate_token(authorization)
        ## 9/24/24 stub healthcheck
        return {'status': 'healthy'}

    async def get_metagraph(self, request: Request):
        # authorization: str = request.headers.get("authorization")

        # if not authorization:
        #     raise HTTPException(status_code=401, detail="Authorization header missing")

        # self.authenticate_token(authorization)


        metagraph = self.validator.metagraph
        return {
            'uids': [str(uid) for uid in metagraph.uids],
            'ranks': [float(r) for r in metagraph.R],
            'incentives': [float(i) for i in metagraph.I],
            'emissions': [float(e) for e in metagraph.E]
        }

    async def forward(self, request: Request):
        # authorization: str = request.headers.get("authorization")

        # if not authorization:
        #     raise HTTPException(status_code=401, detail="Authorization header missing")

        # self.authenticate_token(authorization)

        bt.logging.info("Received an organic request!")

        payload = await request.json()
        task_category = TaskCategory.from_string(payload.get("task_category"))

        if "seed" not in payload:
            payload["seed"] = random.randint(0, 1e9)

        metagraph = self.validator.metagraph
        bt.logging.info(f"metagraph: {metagraph}")

        miner_uids = self.validator.last_responding_miner_uids
        if len(miner_uids) == 0:
            bt.logging.warning("[ORGANIC] No recent miner uids found, sampling random uids")
            miner_uids = get_random_uids(self.validator, k=self.validator.config.neuron.sample_size)

        bt.logging.info(f"[ORGANIC] Querying {len(miner_uids)} miners...")
        responses = await self.dendrite(
            # Send the query to selected miner axons in the network.
            axons=[metagraph.axons[uid] for uid in miner_uids],
            synapse=prepare_code_synapse(code=payload['code'], task_category=task_category),
            deserialize=True,
        )
        
        bt.logging.info(f"[ORGANIC] {responses}")

        # return predictions from miners
        valid_pred_idx = np.array([i for i, v in enumerate(responses) if v.prediction != -1.])
        if len(valid_pred_idx) > 0:
            valid_preds = np.array(responses)[valid_pred_idx]
            valid_pred_uids = np.array(miner_uids)[valid_pred_idx]
            if len(valid_preds) > 0:
                self.proxy_counter.update(is_success=True)
                self.proxy_counter.save()
                data = {
                    'uids': [int(uid) for uid in valid_pred_uids],
                    'preds': [pred.to_tuple() for pred in valid_preds],
                    'ranks': [float(self.validator.metagraph.R[uid]) for uid in valid_pred_uids],
                    'incentives': [float(self.validator.metagraph.I[uid]) for uid in valid_pred_uids],
                    'emissions': [float(self.validator.metagraph.E[uid]) for uid in valid_pred_uids],
                    'fqdn': socket.getfqdn()
                }
                return data

        self.proxy_counter.update(is_success=False)
        self.proxy_counter.save()
        return HTTPException(status_code=500, detail="No valid response received")

    async def get_self(self):
        return self
