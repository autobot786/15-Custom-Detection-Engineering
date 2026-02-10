# -*- coding: utf-8 -*-
"""
Splunk SOAR Playbook: CDE_Universal_Containment
Author: <YOUR_NAME>

This is a scaffold. Replace asset names and action names with those in your Splunk SOAR environment.
"""

import phantom.rules as phantom
import json

def on_start(container):
    phantom.debug("Playbook started: CDE_Universal_Containment")
    collect_entities(container=container)
    return

def collect_entities(container=None, **kwargs):
    # Pull common artifacts
    artifacts = phantom.collect2(container=container, datapath=["artifact:*.cef"])
    entities = []
    for row in artifacts:
        cef = row[0] or {}
        # Common CEF keys
        user = cef.get("user") or cef.get("UserPrincipalName") or cef.get("destinationUserName")
        host = cef.get("dest_host") or cef.get("DeviceName") or cef.get("destinationHostName")
        ip = cef.get("src_ip") or cef.get("IPAddress") or cef.get("sourceAddress")
        sha256 = cef.get("fileHash") or cef.get("sha256") or cef.get("fileHashSha256")
        if user: entities.append({"type":"user","value":user})
        if host: entities.append({"type":"host","value":host})
        if ip: entities.append({"type":"ip","value":ip})
        if sha256: entities.append({"type":"sha256","value":sha256})

    phantom.save_run_data(key="cde.entities", value=json.dumps(entities))
    phantom.add_note(container=container, note_title="Extracted Entities", note_content=json.dumps(entities, indent=2))

    enrich_entities(container=container)
    return

def enrich_entities(container=None, **kwargs):
    entities = json.loads(phantom.get_run_data("cde.entities") or "[]")

    # Example: Threat Intel lookup for IP/domain/hash
    # phantom.act("lookup ip", parameters=[{"ip": e["value"]}], assets=["threat_intel"]) ...
    phantom.debug(f"Enrichment stub. Entities={entities}")

    # Example: Graph user lookup
    # phantom.act("get user", parameters=[{"user": "<upn>"}], assets=["microsoft_graph"])

    decide_containment(container=container, entities=entities)
    return

def decide_containment(container=None, entities=None, **kwargs):
    # Simple confidence heuristic (customize)
    confidence = 0
    if any(e["type"]=="sha256" for e in entities): confidence += 40
    if any(e["type"]=="ip" for e in entities): confidence += 20
    if any(e["type"]=="user" for e in entities): confidence += 20
    if any(e["type"]=="host" for e in entities): confidence += 20

    phantom.add_note(container=container, note_title="Confidence Score", note_content=str(confidence))
    phantom.save_run_data("cde.confidence", str(confidence))

    if confidence >= 60:
        contain(container=container, entities=entities)
    else:
        notify_only(container=container, entities=entities)

def contain(container=None, entities=None, **kwargs):
    phantom.debug("Containment path selected")

    # Examples (adapt to your installed apps/actions)
    # 1) Revoke tokens / disable user
    # phantom.act("revoke tokens", parameters=[{"user": "<upn>"}], assets=["microsoft_graph"])
    # phantom.act("disable user", parameters=[{"username": "<user>"}], assets=["active_directory"])

    # 2) Isolate device
    # phantom.act("isolate device", parameters=[{"device": "<hostname>"}], assets=["mde"])

    # 3) Block IP
    # phantom.act("block ip", parameters=[{"ip": "<ip>"}], assets=["firewall"])

    phantom.add_note(container=container, note_title="Containment", note_content="Containment actions executed (scaffold).")
    notify_only(container=container, entities=entities)
    return

def notify_only(container=None, entities=None, **kwargs):
    phantom.debug("Notify-only path selected")
    message = f"CDE Alert handled. Entities: {json.dumps(entities)}"
    # phantom.act("send message", parameters=[{"message": message, "channel": "#soc"}], assets=["slack"])
    # phantom.act("create ticket", parameters=[{"short_description": "CDE Alert", "description": message}], assets=["servicenow"])
    phantom.add_note(container=container, note_title="Notification", note_content=message)
    return

def on_finish(container, summary):
    phantom.debug("Playbook finished")
    return
