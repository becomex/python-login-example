import json
import jwt
import pytz
import requests
import uuid

from argparse import ArgumentParser
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta
from filemod import reader

api_base_url = r'https://takeout-api.becomex.com.br'
login_url = r'https://login.becomex.com.br/auth/realms/becomex'

parser = ArgumentParser(description='Handle data from Becomex Takeout API.')

# Authentication parameters

parser.add_argument("-c", "--client", dest="client_id", help="The client identificator given by the Becomex.")
parser.add_argument("-k", "--private-key", dest="private_key_path", help="The path for private key PEM file.")
parser.add_argument("-p", "--password", dest="passphrase", help="The private key passphrase.")

# API parameters

parser.add_argument("-t", "--type", dest="type", help="The document's type: DUE = 1, DILI = 2, CeMercante = 3, Atos = 4, Catalogos = 5, Duimp = 6, Lpco = 7.")
parser.add_argument("-s", "--sub-type", dest="sub_type", help="The table name (example=TB_DI).")
parser.add_argument("-d", "--start-date", dest="start_date", help="The start date in format YYYY-MM-DD.")
parser.add_argument("-e", "--end-date", dest="end_date", help="The end date in format YYYY-MM-DD.")
parser.add_argument("-r", "--results-per-page", dest="take", nargs='?', type=str, const=10, default=10, help="Number of registries per page.")
parser.add_argument("-g", "--page", dest="page", nargs='?', type=str, const=1, default=1, help="The page number.")

args = parser.parse_args()

pem_bytes = str.encode(reader(args.private_key_path))

private_key = serialization.load_pem_private_key(
    pem_bytes, password=str.encode(args.passphrase), backend=default_backend()
)

payload = {
    "sub": args.client_id,
    "jti": str(uuid.uuid4()),
    "iss": args.client_id,
    "aud": login_url,
    "nbf": datetime.now(pytz.utc) - timedelta(minutes=5),
    "exp": datetime.now(pytz.utc) + timedelta(hours=3)
}

assertionToken = jwt.encode(payload, private_key, algorithm="RS256")

form_data = {
    'client_id': args.client_id, 
    'grant_type': 'client_credentials',
    'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    'client_assertion': assertionToken
}

response = requests.post(login_url + "/protocol/openid-connect/token", data=form_data)

token = json.loads(response.content)

url = api_base_url + '/api/v1/files?Type=' + args.type + '&SubType=' + args.sub_type + '&StartDate=' + args.start_date + '&EndDate=' + args.end_date + '&Take=' + args.take + '&Page=' + args.page

headers = {
  'Authorization': 'Bearer ' + token['access_token'],
}

response = requests.request("GET", url, headers=headers)

results = json.loads(response.content)

for element in results["items"]:
    url = api_base_url + "/api/v1/files/" + element["id"] + "/download"
    response = requests.request("GET", url, headers=headers)

    # TODO: Handle the results.
    print(response.text)