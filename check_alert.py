import os

from dotenv import load_dotenv
from elasticsearch import Elasticsearch

load_dotenv()

es = Elasticsearch(
    os.getenv("ES_URL"),
    api_key=os.getenv("ES_API_KEY"),
    ca_certs=os.getenv("ES_CA_CERT"),
)


def find_alerts(rule_name, since):
    """Searches alerts of the rule `rule_name` created since `since` (UTC)."""
    response = es.search(
        index=".alerts-security.alerts-*",
        size=1,
        sort=[{"@timestamp": {"order": "asc"}}],
        query={
            "bool": {
                "filter": [
                    {"term": {"kibana.alert.rule.name": rule_name}},
                    {"range": {"@timestamp": {"gte": since}}},
                ]
            }
        },
    )
    return response["hits"]


if __name__ == "__main__":
    rule = "Brute-force SMB success"
    since = "2026-10-16T22:23:54Z"

    hits = find_alerts(rule, since)
    count = hits["total"]["value"]

    if count > 0:
        first = hits["hits"][0]["_source"]["@timestamp"]
        print(f"DETECTED: '{rule}' fired {count} time(s), first at {first}")
    else:
        print(f"NOT DETECTED: no '{rule}' alert since {since}")
