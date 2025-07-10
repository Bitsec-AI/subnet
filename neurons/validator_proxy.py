# credit: https://github.com/BitMind-AI/bitmind-subnet
import traceback
from fastapi import FastAPI, HTTPException, Depends, Request
from concurrent.futures import ThreadPoolExecutor
from starlette.concurrency import run_in_threadpool
from uvicorn import Config, Server
import bittensor as bt
import uvicorn
import os
import asyncio
import random
import numpy as np
import socket

from bitsec.protocol import prepare_code_synapse, PredictionResponse, Vulnerability, VulnerabilityByMiner
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
            "/",
            self.healthcheck,
            methods=["GET"],
            dependencies=[Depends(self.get_self)],
        )
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
            port = self.validator.config.proxy.port
            bt.logging.info(f"Validator proxy server up! Port {port} e.g.\n\tGET http://localhost:{port}/healthcheck\n\tPOST http://localhost:{port}/validator_proxy")

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
        config = Config(
            app=self.app,
            host="0.0.0.0",
            port=self.validator.config.proxy.port,
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

        if "seed" not in payload:
            payload["seed"] = random.randint(0, 1e9)

        metagraph = self.validator.metagraph
        bt.logging.info(f"metagraph: {metagraph}")

        miner_uids = self.validator.last_responding_miner_uids
        if len(miner_uids) == 0:
            bt.logging.warning("[ORGANIC] No recent miner uids found, sampling random uids")
            miner_uids = get_random_uids(self.validator, k=self.validator.config.neuron.sample_size)

        bt.logging.info(f"[ORGANIC] Querying {len(miner_uids)} miners: {miner_uids}")
        for uid in miner_uids:
            bt.logging.info(f"[ORGANIC] {uid} axon: {metagraph.axons[uid]}")

        responses = await self.dendrite(
            # Send the query to selected miner axons in the network.
            axons=[metagraph.axons[uid] for uid in miner_uids],
            synapse=prepare_code_synapse(code=payload['code']),
            deserialize=True,
        )
        
        bt.logging.info(f"[ORGANIC] raw responses: {responses}")

        # return predictions from miners
        bt.logging.info(f"[ORGANIC] Checking predictions: {[(i, v.prediction, len(v.vulnerabilities) if v.vulnerabilities else 0) for i, v in enumerate(responses)]}")
        
        # Filter valid responses and keep track of their corresponding UIDs
        valid_responses = []
        for uid, response in zip(miner_uids, responses):
            if response is not None and isinstance(response, PredictionResponse):
                valid_responses.append((uid, response))
        
        bt.logging.info(f"[ORGANIC] Found {len(valid_responses)} valid responses")
        
        if valid_responses:
            vulnerabilities_by_miner = []

            # Process each valid response
            for uid, pred in valid_responses:
                vuln = None  # Initialize vuln here
                try:
                    # bt.logging.info(f"[ORGANIC] uid: {uid}, pred: {pred}")
                    # bt.logging.info(f"[ORGANIC] pred.vulnerabilities: {pred.vulnerabilities}") # Add this log

                    for vuln in pred.vulnerabilities:
                        parts = None
                        if isinstance(vuln, Vulnerability):
                            parts = vuln.model_dump()
                        elif isinstance(vuln, dict):
                            # Convert dict to Vulnerability object first
                            vuln_obj = Vulnerability.model_validate(vuln)
                            parts = vuln_obj.model_dump()
                        else:
                            bt.logging.error(f"[ORGANIC] Invalid vulnerability type: {type(vuln)}, value: {vuln} for UID: {uid}")
                            continue # Skip to the next vulnerability if type is invalid

                        if parts is None:
                            bt.logging.error(f"[ORGANIC] Failed to process vulnerability: {vuln} from miner {uid}")
                            continue

                        bt.logging.info(f"[ORGANIC] vuln {vuln}, parts {parts}")
                        vulnerabilities_by_miner.append(
                            VulnerabilityByMiner(
                                miner_id=str(uid),  # Convert to string as required by the model
                                **parts
                            )
                        )
                except Exception as e:
                    bt.logging.error(f"Error processing uid: {uid}, vulnerability: {vuln}, error: {e}")
                    bt.logging.error(traceback.print_exc())
            
            data = {
                'uids': [int(uid) for uid, _ in valid_responses],
                'vulnerabilities': [v.model_dump() for v in vulnerabilities_by_miner],
                'predictions_from_miners': {str(uid): pred.model_dump() for uid, pred in valid_responses},
                'ranks': [float(self.validator.metagraph.R[uid]) for uid, _ in valid_responses],
                'incentives': [float(self.validator.metagraph.I[uid]) for uid, _ in valid_responses],
                'emissions': [float(self.validator.metagraph.E[uid]) for uid, _ in valid_responses],
                'num_summary': {
                    'miners_queried': len(miner_uids),
                    'miners_responded': len(responses),
                    'valid_responses': len(valid_responses),
                    'responses_with_vulnerabilities': len([(uid, pred) for uid, pred in valid_responses if pred.vulnerabilities]),
                    'vulnerabilities_found': len(vulnerabilities_by_miner)
                },
                'fqdn': socket.getfqdn()
            }

            self.proxy_counter.update(is_success=True)
            self.proxy_counter.save()

            bt.logging.info(f"[ORGANIC] request complete, response: {data}")

            # write data to database
            return data

        self.proxy_counter.update(is_success=False)
        self.proxy_counter.save()
        return HTTPException(status_code=500, detail="No valid response received")

    async def get_self(self):
        return self
