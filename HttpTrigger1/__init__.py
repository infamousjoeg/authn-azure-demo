import logging
import azure.functions as func
import os
import requests
import json
from base64 import b64encode

identity_endpoint = os.environ["IDENTITY_ENDPOINT"]
identity_header = os.environ["IDENTITY_HEADER"]

def get_azure_ad_token(resource_uri):
    token_auth_uri = f"{identity_endpoint}?resource={resource_uri}&api-version=2017-09-01"
    head_msi = {'secret':identity_header}

    resp = requests.get(token_auth_uri, headers=head_msi)
    access_token = resp.json()['access_token']

    return access_token


def get_conjur_access_token(azure_ad_token):
    conjur_auth_uri = f"https://conjur.joegarcia.dev/authn-azure/conjur-demo/cyberarkdemo/host%2Fcloud%2Fazure%2Ffunction%2Fconjur-demo/authenticate"
    req_headers = {'Content-Type':"application/x-www-form-urlencoded"}

    resp = requests.post(conjur_auth_uri, headers=req_headers, data={'jwt':azure_ad_token})
    access_token = resp.json()

    base64_encoded_token = b64encode(bytes(json.dumps(access_token), "utf-8")).decode("utf-8")
    return base64_encoded_token


def get_conjur_secret(conjur_access_token):
    uri = f"https://conjur.joegarcia.dev/secrets/cyberarkdemo/variable/cloud%2Fazure%2Ffunction%2Ftest-variable"
    req_headers = {'Authorization':f"Token token=\"{conjur_access_token}\""}

    resp = requests.get(uri, headers=req_headers)
    secret = resp.text

    return secret


def main(req: func.HttpRequest) -> func.HttpResponse:
    azure_ad_token = get_azure_ad_token("https://management.azure.com")
    conjur_access_token = get_conjur_access_token(azure_ad_token)
    conjur_secret = get_conjur_secret(conjur_access_token)

    return func.HttpResponse(f"Retrieved Conjur secret: {conjur_secret}")