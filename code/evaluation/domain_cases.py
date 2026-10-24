"""Actual-engine synthetic domain cases; no organizer labels or model calls."""
import sys,collections
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]));import main
C={"case_id":"synthetic_case","email":"prior@example.test","audit_at":"2026-01-03T00:00:00Z","reported_at":"2026-01-01T12:00:00Z","request_text":"Please delete my account and personal data."}
def obs(resource,category,raw,state,at="2026-01-02T00:00:00Z",system="analytics_platform",source="primary"):
 return dict(system_id=system,resource_id=resource,category=category,raw=raw,text="",state_hint=state,observed_at=at,capture_at=at,evidence_id="evidence_synthetic",source_kind="json_record",source_path=source,source_priority=90,relations=[])
def index(items):
 d=main.DatasetIndex.__new__(main.DatasetIndex)
 d.rules=[dict(data_category=c,required_action=a) for c,a in [("ANALYTICS_PROFILE","ANONYMIZE"),("USER_PROFILE","DELETE"),("ACCOUNT_TOMBSTONE","REDACT"),("SUPPORT_ATTACHMENT","DELETE"),("SECURITY_AUDIT_LOG","RETAIN")]]
 d.users={"user_demo":{"user_demo","prior@example.test","current@example.test"}}
 d.alias={"prior@example.test":{"user_demo"}};d.name_pattern=None
 d.activities=[];d.scopes=[];d.by_resource=collections.defaultdict(list);d.subject_resources=collections.defaultdict(set);d.resource_links=collections.defaultdict(list);d.resource_keys=collections.defaultdict(set)
 for x in items:d._index(x)
 return d
tests=[]
old=obs("analytics_10","ANALYTICS_PROFILE",{"email":"prior@example.test"},"PRESENT","2026-01-01T00:00:00Z")
clean=obs("analytics_10","ANALYTICS_PROFILE",{"email":None,"customer_reference":None},"ANONYMIZED")
s,z=main.audit_case(C,index([old,clean]));tests.append(("historical identity reaches later anonymous row",s=="COMPLETE"and z[0]["operation"]=="VERIFY_RECORD_ANONYMIZED"))
flow=obs("data_flow_10","DATA_FLOW",{"customer_email":"prior@example.test","enabled":True},"ACTIVE",system="integration_service")
future=dict(flow,observed_at="2026-01-04T00:00:00Z",capture_at="2026-01-04T00:00:00Z",raw={"enabled":False,"customer_reference":"user_demo"},state_hint="DISABLED")
s,z=main.audit_case(C,index([flow,future]));tests.append(("future disable cannot fix active flow",s=="INCOMPLETE"and z[0]["operation"]=="REPORT_ACTIVE_DATA_FLOW" and all(not x["evidence_id"] for x in z if x["phase"]!="FINDING")))
tomb=obs("tombstone_10","ACCOUNT_TOMBSTONE",{"customer_reference":"user_demo","email":None,"name":None},"REDACTED",system="identity_service")
s,z=main.audit_case(C,index([tomb]));tests.append(("stable tombstone reference may remain",s=="COMPLETE"and z[0]["operation"]=="VERIFY_RECORD_REDACTED"))
attachment=obs("attachment_10","SUPPORT_ATTACHMENT",{"email":"prior@example.test"},"PRESENT",system="support_platform")
s,z=main.audit_case(C,index([attachment]));tests.append(("solo support attachment is deleted not redacted",s=="INCOMPLETE"and z[1]["operation"]=="DELETE_RECORD"))
primary=obs("account_10","USER_PROFILE",{"email":"prior@example.test"},"ABSENT",system="account_service")
replica=obs("account_10","USER_PROFILE",{"email":"prior@example.test"},"PRESENT","2026-01-01T00:00:00Z",system="account_service",source="customer_data_failover_replica.sql")
s,z=main.audit_case(C,index([primary,replica]));tests.append(("clean primary does not hide failover copy",s=="INCOMPLETE"and z[0]["operation"]=="REPORT_REMAINING_RECORD"))
tests.append(("negated deletion remains unauthorized",main.audit_case(dict(C,request_text="Please send a copy. Do not close or delete the account."),index([primary]))==("NOT_APPLICABLE",[])))
old_absent=obs("account_20","USER_PROFILE",{"email":"prior@example.test"},"ABSENT","2026-01-01T00:00:00Z",system="account_service")
new_audit=obs("audit_record_20","SECURITY_AUDIT_LOG",{"subject_reference":"user_demo"},"PRESENT",system="security_service")
s,z=main.audit_case(dict(C,requested_at="2026-01-02T00:00:00Z"),index([old_absent,new_audit]))
tests.append(("repeated deletion retains sole already-absent account proof",s=="COMPLETE" and any(x["operation"]=="VERIFY_RECORD_ABSENT" and x["resource_id"]=="account_20" for x in z)))
for name,result in tests:print(("PASS" if result else "FAIL"),name)
assert all(result for _,result in tests)
print("actual engine synthetic cases",sum(x[1] for x in tests),"/",len(tests))
