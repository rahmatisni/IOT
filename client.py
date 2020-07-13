import requests

def sendapi():

    url = "http://localhost:3000/asd"

    payload = 'jarak1=3.2323232&jarak2=8.4141414141&jarak3=6.234242424&mac=0c%3Aa8%3Aa7%3A69%3Aa1%3A8c'
    headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
    }

    response = requests.request("POST", url, headers=headers, data = payload)

    print(response.text.encode('utf8'))

sendapi()