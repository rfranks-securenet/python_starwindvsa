"""
vsa.vsa_client
~~~~~~~~~~~~

This module implements the VSA client.

:copyright: (c) 2024 by Richard Franks.
:license: Apache2, see LICENSE for more details.
"""
import base64
import json
import logging
import requests

logger = logging.getLogger(__name__)


class VsaClient:
    """Instance of a VSA client.

    This class allows interaction with the VSA via its HTTP API.
    """
    def __init__(self, base: str, ignore_certs: bool = True) -> None:
        self._base = base
        self._token = None
        self._refresh_token_value = None
        self._verify = not ignore_certs

    def login(self, username: str, password: str) -> bool:
        """ Logs in to the VSA """
        logger.info("Logging into VSA %s", self._base)
        logger.debug("Using username %s", username)
        b64_password = bytes.decode(base64.b64encode(bytes(password, "UTF-8")))
        request = {
            "userName": username,
            "password": b64_password,
            "autologin": False
        }
        req = requests.post(
            f"{self._base}/api/v2/account/login",
            json=request,
            verify=self._verify,
            timeout=15)
        logger.debug("Got response %d: %s", req.status_code, req.text)
        if req.status_code == 200:
            logger.info("Successfully logged in")
            self._process_token(req.json())
            return True
        logger.critical("Failed login")
        return False

    def _refresh_token(self) -> bool:
        """ Refreshes a token """
        request = {
            "refreshToken": self._refresh_token_value
        }
        logger.info("Refreshing token")
        logger.debug("Using refresh token: %s", self._refresh_token_value)
        req = requests.post(
            f"{self._base}/api/v2/account/renewToken",
            json=request,
            verify=self._verify,
            timeout=15)
        logger.debug("Got response %d: %s", req.status_code, req.text)
        if req.status_code == 201:
            logger.info("Successfully refreshed token")
            self._process_token(req.json())
            return True
        logger.critical("Failed refreshing token")
        return False

    def _process_token(self, response: object) -> None:
        """ Processes a received token """
        logger.info("Processing a received token")
        logger.debug("Received: %s", response)
        self._token = response["accessToken"]
        logger.debug("Accesss token: %s", response["accessToken"])
        self._refresh_token_value = response["refreshToken"]
        logger.debug("Refresh token: %s", response["refreshToken"])

    def post(self, url: str,
             body: object,
             headers: object = None,
             try_refresh: bool = True) -> requests.Response|None:
        """ Posts a request to the VSA """
        if headers is None:
            headers = {}
        headers["Authorization"] = self._token
        logger.info("Posting a request to %s/%s", self._base, url)
        logger.debug("Body: %s", json.dumps(body, indent=2))
        logger.debug("Headers: %s", json.dumps(headers, indent=2))
        resp =  requests.post(
            f"{self._base}/{url}",
            json=body,
            verify=self._verify,
            headers=headers,
            timeout=15)
        logger.debug("Got response %d: %s", resp.status_code, resp.text)
        if resp.status_code == 401:
            logger.info("Authorization denied")
            if try_refresh:
                # Try re-authenticating
                if self._refresh_token():
                    return self.post(url=url, body=body, headers=headers, try_refresh=False)
            else:
                return None
        else:
            return resp

    def get(self,
            url: str,
            headers: object = None,
            try_refresh: bool = True) -> requests.Response|None:
        """ Gets a request to the VSA """
        if headers is None:
            headers = {}
        headers["Authorization"] = self._token
        logger.info("Getting a request from %s/%s", self._base, url)
        logger.debug("Headers: %s", json.dumps(headers, indent=2))
        resp = requests.get(
            f"{self._base}/{url}",
            verify=self._verify,
            headers=headers,
            timeout=15)
        logger.debug("Got response %d: %s", resp.status_code, resp.text)
        if resp.status_code == 401:
            logger.info("Authorization denied")
            if try_refresh:
                # Try re-authenticating
                if self._refresh_token():
                    return self.get(url=url, headers=headers, try_refresh=False)
            else:
                return None
        else:
            return resp
        