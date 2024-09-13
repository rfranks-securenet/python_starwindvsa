"""
vsa.vsa_client
~~~~~~~~~~~~

This module implements the VSA client.

:copyright: (c) 2024 by Richard Franks.
:license: Apache2, see LICENSE for more details.
"""
import base64
import requests

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
        if req.status_code == 200:
            self._process_token(req.json())
            return True
        return False

    def _refresh_token(self) -> bool:
        """ Refreshes a token """
        request = {
            "refreshToken": self._refresh_token_value
        }
        req = requests.post(
            f"{self._base}/api/v2/account/renewToken",
            json=request,
            verify=self._verify,
            timeout=15)
        if req.status_code == 201:
            self._process_token(req.json())
            return True
        return False

    def _process_token(self, response: object) -> None:
        """ Processes a received token """
        self._token = response["accessToken"]
        self._refresh_token_value = response["refreshToken"]

    def post(self, url: str,
             body: object,
             headers: object = None,
             try_refresh: bool = True) -> requests.Response|None:
        """ Posts a request to the VSA """
        if headers is None:
            headers = {}
        headers["Authorization"] = self._token
        resp =  requests.post(
            f"{self._base}/{url}",
            json=body,
            verify=self._verify,
            headers=headers,
            timeout=15)
        if resp.status_code == 401:
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
        resp = requests.get(
            f"{self._base}/{url}",
            verify=self._verify,
            headers=headers,
            timeout=15)
        if resp.status_code == 401:
            if try_refresh:
                # Try re-authenticating
                if self._refresh_token():
                    return self.get(url=url, headers=headers, try_refresh=False)
            else:
                return None
        else:
            return resp
        