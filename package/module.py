import hashlib
import aiohttp
import pycftools
from functools import wraps
from fake_useragent import UserAgent

class CFToolsClient:

    def __init__(self, *, login: str = None, password: str = None, application_id: str = None, application_secret: str = None):

        self.login = login
        self.password = password
        self.application_id = application_id
        self.application_secret = application_secret

        self.token_link = "https://api.cftools.cloud/olymp/v1/@me/acsrf-token"
        self.native_login_link = "https://api.cftools.cloud/olymp/v1/@me/native-login"
        self.login_status_url = "https://api.cftools.cloud/app/v1/@me/status"
        self.vanil_profile_data_url = "https://api.cftools.cloud/app/v1/profile/"
        
        self._session = aiohttp.ClientSession() 
        self._headers = {'user-agent': UserAgent().chrome}

        if self.application_id and self.application_secret:
            self._cf = pycftools.CfToolsApi(self.application_id, self.application_secret, "1", "1", "1", "1", "1")

    @staticmethod
    def check_login(func):
        @wraps(func)
        async def wrapper(self, *args, **kwargs):
            async with self._session.get(self.login_status_url, headers=self._headers) as response:
                data = await response.json()
                state = data.get('state', {})

                if state and state['login'] == 1:
                    return await func(self, *args, **kwargs)
                else:
                   raise Exception()

        return wrapper

    async def __get_acsrf_token(self) -> str:
        acsrf_token_request = await self._session.get(self.token_link, headers=self._headers)
        acsrf_token = await acsrf_token_request.json()
        return acsrf_token["acsrf_token"]

    async def run(self):
        acsrf_token = await self.__get_acsrf_token()
        
        if not self.login or not self.password:
            raise Exception()
        
        password_bytes = self.password.encode('utf-8')
        sha256_hash = hashlib.sha256()
        sha256_hash.update(password_bytes)
        encrypted_password = sha256_hash.hexdigest()

        data = {
            "acsrf_token": acsrf_token,
            "identifier": self.login,
            "password": encrypted_password
        }

        return await self._session.post(self.native_login_link, data=data, headers=self._headers)

    async def close(self):
        if self._session:
            await self._session.close()

    async def get_cftools_id_by_steam(self, steam_profile: str) -> str | None:
        if not self.application_secret or not self.application_id:
            return None
        
        cftools_id = self._cf.server_lookup_user(steam_profile).json().get("cftools_id")
        return cftools_id

    def parse_param(param: str):
        if "app.cftools.cloud/" in param:
            split = param.split("/");

            if split[-1] == "":
                split.pop()

            return split[-1];

        return param;

    async def request(self, url: str):
        async with self._session.get(url, headers=self._headers) as response:
            data = await response.json()
            return data

    @check_login
    async def __get_steam_data(self, cftools_id: str) -> dict:
        return await self.request(f"{self.vanil_profile_data_url}{cftools_id}/steam")

    @check_login
    async def get_nicknames_history(self, cftools_id: str) -> list:
        return await self.request(f"{self.vanil_profile_data_url}{cftools_id}/overview")
    
    @check_login
    async def get_user_bans(self, cftools_id: str):
        return await self.request(f"{self.vanil_profile_data_url}{cftools_id}/bans")

    @check_login
    async def get_user_anticheat_status(self, cftools_id: str):
        return await self.request(f"{self.vanil_profile_data_url}{cftools_id}/ac-status")

    @check_login
    async def get_play_state(self, cftools_id: str):
        return await self.request(f"{self.vanil_profile_data_url}{cftools_id}/playState")

    @check_login
    async def get_intelligence(self, cftools_id: str):
        return await self.request(f"{self.vanil_profile_data_url}{cftools_id}/intelligence/title/dayz")

    @check_login
    async def get_alternative_accounts(self, cftools_id: str):
        return await self.request(f"{self.vanil_profile_data_url}{cftools_id}/overview")
