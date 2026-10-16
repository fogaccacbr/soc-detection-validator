import os

from dotenv import load_dotenv
from elasticsearch import Elasticsearch

# Loads the variables from the .env archive
load_dotenv()

# Creates the connection with the Elasticsearch
es = Elasticsearch(
    os.getenv("ES_URL"),
    api_key=os.getenv("ES_API_KEY"),
    ca_certs=os.getenv("ES_CA_CERT"),
)

# Searches the 10 most recent alerts
answer = es.search(
    index=".alerts-security.alerts-*",
    size=25,
    sort=[{"@timestamp": {"order": "desc"}}],
)

total = answer["hits"]["total"]["value"]
print(f"Total alerts in SIEM: {total}\n")

for alert in answer["hits"]["hits"]:
    data = alert["_source"]
    time = data["@timestamp"]
    rule = data["kibana.alert.rule.name"]
    severity = data["kibana.alert.rule.severity"]
    print(f"{time} | {severity:<8} | {rule}")
