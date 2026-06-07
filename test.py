import requests 

r = requests.get("http://127.0.0.1:8000/recon/comar.tn?active=true")
data = r.json()

print(data["domain"])