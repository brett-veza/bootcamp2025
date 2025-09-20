#!/usr/bin/env python3

import base64
import json
import os
import sys
from dotenv import load_dotenv
load_dotenv()

import oaaclient.utils as oaautils
from oaaclient.client import OAAClient, OAAClientError

#! veza_url = "https://example.vezacloud.com"
#! veza_api_key = os.getenv("VEZA_API_KEY")

veza_url = os.getenv('VEZA_URL')
veza_api_key = os.getenv('VEZA_API_KEY')

#! provider_id = "UUID of Provider"
#! data_source_id = "UUID of Data Source"

data_source_id = os.getenv('VEZA_Id')
provider_id = os.getenv('VEZA_Provider_id')

source_csv = "sample.csv"

print("Connecting to Veza")
try:
    veza_con = OAAClient(veza_url, veza_api_key)
except OAAClientError as e:
    print("Error connecting to Veza tenant")
    print(e)
    sys.exit(1)

print("Loading CSV file")
with open(source_csv, "rb") as f:
    encoded_csv = base64.b64encode(f.read())

print("Pushing data to Veza")
try:
    push_request = {"id": provider_id, "data_source_id": data_source_id, "csv_data": encoded_csv.decode()}
    veza_con.api_post(f"/api/v1/providers/custom/{provider_id}/datasources/{data_source_id}:push_csv", push_request)
    print("Push succeeded")
except OAAClientError as e:
    log.error(f"{e.error}: {e.message} ({e.status_code})")
    if hasattr(e, "details"):
        for d in e.details:
            log.error(d)
    sys.exit(3)

