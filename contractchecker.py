#!/usr/bin/env python3
# To create Virtual ENV
# python3 -m venv contractchecker_env
# source contractchecker_env/bin/activate
# **********************************************************************************
# **********************************************************************************
# Script desarrollado por Pablo Gomez - Regional Solutions Architect in OCP TECH
# (https://ocp.tech) pablo.gomez@ocp.tech
# **********************************************************************************
# **********************************************************************************

import json
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import warnings
import collections.abc
import sys
import os
import re
from numpy import transpose
from itertools import cycle
import inspect
from itertools import groupby

warnings.simplefilter('ignore', InsecureRequestWarning)

# **********************************************************************************
# MODIFIABLE DEFINITIONS
# **********************************************************************************
verify_https = False  # Validate https certificate
page_size = 2000  # Elements per page

# ----------------------------------------------------------------------

priorities = {"class-eq-filter": 1,
              "class-eq-deny": 2,
              "class-eq-allow": 3,
              "prov-nonshared-to-cons": 4,
              "black_list": 5,
              "fabric_infra": 6,
              "fully_qual": 7,
              "system_incomplete": 8,
              "src_dst_any": 9,
              "shsrc_any_filt_perm": 10,
              "shsrc_any_any_perm": 11,
              "shsrc_any_any_deny": 12,
              "src_any_filter": 13,
              "any_dest_filter": 14,
              "src_any_any": 15,
              "any_dest_any": 16,
              "any_any_filter": 17,
              "grp_src_any_any_deny": 18,
              "grp_any_dest_any_deny": 19,
              "grp_any_any_any_permit": 20,
              "any_any_any": 21,
              "any_vrf_any_deny": 22
              }

# **********************************************************************************
# System Reserved pcTag - This pcTag is used for system internal rules (1-15).
# Globally scoped pcTag - This pcTag is used for shared service (16-16385).
# Locally scoped pcTag - This pcTag is locally used per VRF (range from 16386-65535).
# **********************************************************************************
pctags = {
    "0": "any",
    "1": "ignore",  # Ignore in Spine-Proxy, ARP, Multicast, etc.
    "10": "pctag10-unknown",
    "13": "ext-shrsvc",
    "14": "int-shrsvc",
    "15": "ext-0.0.0.0/0"  # External EPG 0.0.0.0/0
}

# ----------------------------------------------------------------------

cache_vrf = []

# ----------------------------------------------------------------------

_debug = 0
_debugLog = False
_color_i = "\033[0;33;40m"
_color_f = "\033[0m"


def debug(obj, msj="debug msj", level=3):
    if _debug >= level:
        print(
            _color_i +
            str(msj) +
            "\n{}".format(
                json.dumps(
                    obj,
                    indent=4)) +
            _color_f)
        if _debugLog:
            with open(os.path.join(sys.path[0], "debuglog.json"), "a") as debugfile:
                debugfile.write(str(msj) + "\n")
                json.dump(obj, indent=4, sort_keys=True, fp=debugfile)
                debugfile.write("\n")

# --------


def printt(string=None):
    if string:
        print(str(string))
    if _debugLog:
        with open(os.path.join(sys.path[0], "debuglog.json"), "a") as debugfile:
            debugfile.write(str(string) + "\n")

# --------


def update(d, u):
    for k, v in u.items():
        if isinstance(v, collections.abc.Mapping):
            d[k] = update(d.get(k, {}), v)
        else:
            d[k] = v
    return d


# --------


def count_elem(l):
    return sum([len(list(group))
                for key, group in groupby([elem.keys() for elem in l])])


# ---------------------------------------------------------------------------------------------------------------------------------------------


# Login to APIC #
w = cycle(("|", "/", "-", "\\"))


def apic_login():
    print('Working: (%s)\r' % next(w), end="")
    token = ""
    err = ""
    try:
        response = requests.post(
            url=APIC_URL + "/api/aaaLogin.json",
            headers={
                "Content-obj": "application/json; charset=utf-8",
            },
            data=json.dumps(
                {
                    "aaaUser": {
                        "attributes": {
                            "name": USERNAME,
                            "pwd": PASS
                        }
                    }
                }
            ),
            verify=False)
        json_response = json.loads(response.content)
        token = json_response['imdata'][0]['aaaLogin']['attributes']['token']
    except requests.exceptions.RequestException as err:
        debug(
            "HTTP Request failed, Status Code: {status_code}".format(
                status_code=response.status_code))
    return token

# ---------------------------------------------------------------------------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------------------------------------------------------------------------


def printable(d):
    if not bool(d):
        printt("No matching criteria -> empty output")
        return None
# ------------------------------------
    try:
        printt(
            "\n################### Contract: {} ###################\n".format(
                d["dn"]))
        printt("Consumers: ")
        for i in d["Consumers"]:
            printt(i)
        printt("----------------------------------------")
        printt("Providers: ")
        for i in d["Providers"]:
            printt(i)
        printt("----------------------------------------")
        printt("Subjects: ")
        for k, v in d["Subjects"].items():
            printt("{}:{}".format(k, v))
        printt("----------------------------------------")
    except KeyError:
        pass
# ------------------------------------
    i = 0
    table = []
    keys = d.keys()
    for key in keys:
        node = re.findall("rules.*", key)
    printt(
        "\n################### Rules in node: {} ###################\n".format(
            node[0]))
    if not bool(d[node[0]]):
        printt("No rules match\n")
        return
    #TODO: optimize
    for k1, v1 in d[node[0]].items():
        table.append([i])
        table[i].append(v1["id"])
        table[i].append(re.sub("uni/", "", v1["sPcTag"]))
        table[i].append(re.sub("uni/", "", v1["dPcTag"]))
        table[i].append(v1["direction"])
        table[i].append(v1["operSt"])
        table[i].append(re.sub("uni/", "", v1["scopeId"]))
        table[i].append(v1["action"])
        table[i].append(v1["prio"])
        table[i].append(v1["fltName"])
        table[i].append(v1["fltId"])
        i = i + 1
    ttable = transpose(table)
    lenSource = len(max(ttable[2], key=len))
    lenSource = lenSource if lenSource > 6 else 8
    lenSource = lenSource if lenSource < 70 else 57
    lenDest = len(max(ttable[3], key=len))
    lenDest = lenDest if lenDest > 11 else 13
    lenDest = lenDest if lenDest < 70 else 57
    lenVRF = len(max(ttable[6], key=len))
    lenVRF = lenVRF if lenVRF > 3 else 5
    lenVRF = lenVRF if lenVRF < 70 else 57
    lenPrio = len(max(ttable[8], key=len))
    lenPrio = lenPrio if lenPrio > 4 else 10
    lenFilter = len(max(ttable[9], key=len))
    lenFilter = lenFilter if lenFilter > 15 else 15
    # id     #Src   #Dst  #Dir   #sts  #VRF   #Act   #Prio  #F-C
    printt(
        "{:<4} {:<{}} {:<{}} {:<14} {:<7} {:<{}} {:<15} {:<{}} {:<{}}".format(
            'id',
            'Source',
            lenSource,
            'Destination',
            lenDest,
            'Direction',
            "State",
            "VRF",
            lenVRF,
            "Action",
            "Prio",
            lenPrio,
            "    Filter-Contract",
            lenFilter))
    printt(
        "-" * len(
            "{:<4} {:<{}} {:<{}} {:<14} {:<7} {:<{}} {:<15} ({}){:<{}} ({}){:<{}}".format(
                'id',
                'Source',
                lenSource,
                'Destination',
                lenDest,
                'Direction',
                "State",
                "VRF",
                lenVRF,
                "Action",
                "XX",
                "Prio",
                lenPrio,
                "default",
                "Filter-Contract",
                lenFilter)))
    for line in table:
        index, iD, sPcTag, dPcTag, direction, operSt, scopeId, action, prio, fltName, fltId = line
        printt(
            "{:<4} {:<{}} {:<{}} {:<14} {:<7} {:<{}} {:<15} ({:02d}){:<{}} ({}){:<{}}".format(
                iD,
                sPcTag,
                lenSource,
                dPcTag,
                lenDest,
                direction,
                operSt,
                scopeId,
                lenVRF,
                action,
                priorities[prio],
                prio,
                lenPrio,
                fltId,
                fltName,
                lenFilter))
    printt("\n")

# ---------------------------------------------------------------------------------------------------------------------------------------------
# API Calls
# ---------------------------------------------------------------------------------------------------------------------------------------------


def get_method(
        url,
        query_target=None,
        target_subtree_class=None,
        query_target_filter=None,
        page=0):
    token = apic_login()
    try:
        response = requests.get(
            url,
            headers={
                "Cookie": "APIC-cookie=" + token,
                "Content-obj": "application/json; charset=utf-8",
            },
            params={
                "query-target": query_target,
                "target-subtree-class": target_subtree_class,
                "query-target-filter": query_target_filter,
                "page-size": page_size,
                "page": page},
            verify=verify_https)
        debug(
            response.status_code,
            "Debug output CODE {} -> (url={}, query_target={}, target-subtree-class={}, query-target-filter={}, page-size={}, page={}): ".format(
                inspect.stack()[1][3],
                url,
                query_target,
                target_subtree_class,
                query_target_filter,
                page_size,
                page),
            1)
        if response.status_code == requests.codes.ok:
            debug(
                response.json(),
                "Debug output {} -> (url={}, query_target={}, target-subtree-class={}, query-target-filter={}, page-size={}, page={}): ".format(
                    inspect.stack()[1][3],
                    url,
                    query_target,
                    target_subtree_class,
                    query_target_filter,
                    page_size,
                    page))
            debug(response.json()["totalCount"], "totalCount: ", 1)
            return response
        else:
            return None
    except requests.exceptions.RequestException:
        debug(
            "HTTP Request failed, Status Code: {status_code}".format(
                status_code=response.status_code))
        return None

# ---------------------------------------------------------------------------------------------------------------------------------------------

# Get EPGs or VRFs#


def get_node_objs(obj, filters=None) -> dict:
    url = APIC_URL + "/api/node/class/{}.json".format(obj)
    response = get_method(url, query_target_filter=filters)
    if response is not None:
        aux = response.json()["imdata"]
        i = 1
        while count_elem(aux) < int(response.json()["totalCount"]):  # len(aux)
            # while response.json()["imdata"]!=[]:
            response = get_method(url, query_target_filter=filters, page=i)
            aux = aux + response.json()["imdata"]
            i = i + 1
        debug(len(aux), "get_node_objs response lenght:", 1)
        return aux
    else:
        return []

# ---------------------------------------------------------------------------------------------------------------------------------------------

# Get Filters IDs


def get_filterid(filterdn):
    url = APIC_URL + "/api/node/mo/{}".format(filterdn)
    response = get_method(
        url,
        query_target="children",
        target_subtree_class="vzRsRFltPOwner")
    if response is not None:
        aux = response.json()["imdata"]
        i = 1
        while count_elem(aux) < int(response.json()["totalCount"]):  # len(aux)
            # while response.json()["imdata"]!=[]:
            response = get_method(
                url,
                query_target="children",
                target_subtree_class="vzRsRFltPOwner",
                page=i)
            aux = aux + response.json()["imdata"]
            i = i + 1
        debug(len(aux), "get_filterid response lenght:", 1)
        return aux
    else:
        return []

# ---------------------------------------------------------------------------------------------------------------------------------------------

# Get zonin-rule from APIC of the desired switch


def get_zoningrule(pod_id, node_id, query=None, subtree=None, filters=None):
    url = APIC_URL + \
        "/api/node/class/topology/pod-{}/node-{}/actrlRule.json".format(pod_id, node_id)
    response = get_method(
        url,
        query_target=query,
        target_subtree_class=subtree,
        query_target_filter=filters)
    if response is not None:
        aux = response.json()["imdata"]
        i = 1
        while count_elem(aux) < int(response.json()["totalCount"]):  # len(aux)
            # while response.json()["imdata"]!=[]:
            response = get_method(
                url,
                query_target=query,
                target_subtree_class=subtree,
                query_target_filter=filters,
                page=i)
            aux = aux + response.json()["imdata"]
            i = i + 1
        debug(len(aux), "get_zoningrule response lenght:", 1)
        return aux
    else:
        return []

# ---------------------------------------------------------------------------------------------------------------------------------------------

# Get contract info


def get_contracts_info(
        tenant,
        contract,
        query=None,
        subtree=None,
        filters=None) -> dict:
    url = APIC_URL + \
        "/api/node/mo/uni/tn-{}/brc-{}.json".format(tenant, contract)
    response = get_method(
        url,
        query_target=query,
        target_subtree_class=subtree,
        query_target_filter=filters)
    if response is not None:
        aux = response.json()["imdata"]
        i = 1
        while count_elem(aux) < int(response.json()["totalCount"]):  # len(aux)
            # while response.json()["imdata"]!=[]:
            response = get_method(
                url,
                query_target=query,
                target_subtree_class=subtree,
                query_target_filter=filters,
                page=i)
            aux = aux + response.json()["imdata"]
            i = i + 1
        debug(len(aux), "get_contracts_info response lenght:", 1)
        return aux
    else:
        return []

# ---------------------------------------------------------------------------------------------------------------------------------------------

# Get info of the subjects


def get_subject_info(
        tenant,
        contract,
        subject,
        query=None,
        filters=None) -> dict:
    url = APIC_URL + \
        "/api/node/mo/uni/tn-{}/brc-{}/subj-{}.json".format(tenant, contract, subject)
    response = get_method(
        url,
        query_target="children",
        target_subtree_class="vzRsSubjFiltAtt",
        query_target_filter=filters)
    if response is not None:
        aux = response.json()["imdata"]
        i = 1
        while count_elem(aux) < int(response.json()["totalCount"]):  # len(aux)
            # while response.json()["imdata"]!=[]:
            response = get_method(
                url,
                query_target="children",
                target_subtree_class="vzRsSubjFiltAtt",
                query_target_filter=filters,
                page=i)
            aux = aux + response.json()["imdata"]
            i = i + 1
        debug(len(aux), "get_subject_info response lenght:", 1)
        return aux
    else:
        return []

# ---------------------------------------------------------------------------------------------------------------------------------------------
# EPGs functions
# ---------------------------------------------------------------------------------------------------------------------------------------------


def mapping_epg_pctag(obj, filters=None) -> dict:
    epgs = get_node_objs(obj, filters)
    if epgs is None:
        return None
    d_vrfs = get_vrf()  # TODO: filters
    if not bool(d_vrfs):  # Check empty dict
        return None
    d_epgs = {}
    for epg in epgs:
        if "fvEpP" in epg:
            obj_id = "fvEpP"
            ctx_id = "scopeId"
            epg_id = "epgPKey"
        elif "vzToEPg" in epg:
            obj_id = "vzToEPg"
            ctx_id = "scopeId"
            epg_id = "epgDn"
        elif "fvRtdEpP" in epg:
            obj_id = "fvRtdEpP"
            ctx_id = "scopeId"
            epg_id = "epgPKey"
        elif "fvInBEpP" in epg:
            obj_id = "fvInBEpP"
            ctx_id = "scopeId"
            epg_id = "epgPKey"
        elif "fvOoBEpP" in epg:
            obj_id = "fvOoBEpP"
            ctx_id = "scopeId"
            epg_id = "epgPKey"
        elif "fvBD" in epg:
            obj_id = "fvBD"
            ctx_id = "scope"
            epg_id = "dn"
        elif "fvBDDef" in epg:
            obj_id = "fvBDDef"
            ctx_id = "scope"
            epg_id = "bdDn"
        elif "fvAEPg" in epg:
            obj_id = "fvAEPg"
            ctx_id = "scope"
            epg_id = "dn"
        else:
            continue
        try:
            d_epgs.update({epg[obj_id]["attributes"][ctx_id]                           : d_vrfs[epg[obj_id]["attributes"][ctx_id]]})
            if d_vrfs[epg[obj_id]["attributes"][ctx_id]] in d_epgs:
                d_epgs[d_vrfs[epg[obj_id]["attributes"][ctx_id]]].update(
                    {epg[obj_id]["attributes"]["pcTag"]: epg[obj_id]["attributes"][epg_id]})
            else:
                d_epgs[d_vrfs[epg[obj_id]["attributes"][ctx_id]]] = {
                    epg[obj_id]["attributes"]["pcTag"]: epg[obj_id]["attributes"][epg_id]}
                d_epgs[d_vrfs[epg[obj_id]["attributes"][ctx_id]]].update({d_vrfs["{}-pctag".format(
                    d_vrfs[epg[obj_id]["attributes"][ctx_id]])]: d_vrfs[epg[obj_id]["attributes"][ctx_id]]}
                )
        except KeyError:
            printt(
                "Undef scope:{} -> epg: {} ".format(
                    epg[obj_id]["attributes"][ctx_id],
                    epg[obj_id]["attributes"][epg_id]))
    d_epgs.update({"16777200": d_vrfs["16777200"]})  # black-hole
    return d_epgs

# ---------------------------------------------------------------------------------------------------------------------------------------------

# Get VRF #


def get_vrf(filters=None) -> dict:
    global cache_vrf
    if len(cache_vrf) == 0 or filters is not None:
        vrfs = get_node_objs("fvCtx", filters)  # fvACtx
        if vrfs is None:
            return None
        d_vrfs = {}
        for vrf in vrfs:
            if "fvCtx" in vrf:
                obj_id = "fvCtx"
                ctx_id = "dn"
                scope_id = "scope"
                pctag = "pcTag"
            elif "fvCtxDef" in vrf:
                obj_id = "fvCtxDef"
                ctx_id = "ctxDn"
                scope_id = "scope"
                pctag = "pcTag"
            elif "fvTnlCtx" in vrf:
                obj_id = "fvTnlCtx"
                ctx_id = "dn"
                scope_id = "scope"
                pctag = "pcTag"
            else:
                continue
            d_vrfs.update({vrf[obj_id]["attributes"][scope_id]                           : vrf[obj_id]["attributes"][ctx_id]})
            d_vrfs.update(
                {"{}-pctag".format(vrf[obj_id]["attributes"][ctx_id]): vrf[obj_id]["attributes"][pctag]})
        d_vrfs.update({"16777200": "uni/tn-infra/black-hole"})
        debug(d_vrfs, "VRFs: ", 2)
        cache_vrf = d_vrfs.copy()
        return d_vrfs
    return cache_vrf

# ---------------------------------------------------------------------------------------------------------------------------------------------


def EPGs(filters=None) -> dict:
    #epg_type = ("fvEpP.epgPKey","vzToEPg.epgPKey","fvAREpP.epgPKey","fvOoBEpP.epgPKey","fvInBEpP.epgPKey","fvABD.dn","fvAEPg.dn")
    filter_type = {
        "ctx": "ctxDefDn",
        "epg": "epgPKey",
        "scope": "scopeId",
        "bd": "dn"}
    epg_type = ("fvAREpP", "vzToEPg", "fvBD")  # fvABD
    d_epgs = {}
    if filters:
        f = filters.split("/")
        f = f[-1].split("-")[0]
        if f == "scope":
            filters = filters[6:]
        for epg_t in epg_type:
            aux = mapping_epg_pctag(
                epg_t, "wcard({}.{}, \"{}\")".format(
                    epg_t, filter_type[f], filters))
            if aux is not None:
                update(d_epgs, aux)
    else:
        for epg_t in epg_type:
            aux = mapping_epg_pctag(epg_t)
            if aux is not None:
                update(d_epgs, aux)
    return d_epgs

# ---------------------------------------------------------------------------------------------------------------------------------------------
# Contracts & rules functions
# ---------------------------------------------------------------------------------------------------------------------------------------------


def get_contract(tenant, contract):
    contracts = get_contracts_info(tenant, contract)
    if not bool(contracts):
        return None
    d_contract = {"dn": contracts[0]["vzBrCP"]["attributes"]["dn"]}
    d_contract.update({"Consumers": []})
    for c in get_contracts_info(tenant, contract, "children", "vzRtCons"):
        d_contract["Consumers"].append(c["vzRtCons"]["attributes"]["tDn"])
    d_contract.update({"Providers": []})
    for c in get_contracts_info(tenant, contract, "children", "vzRtProv"):
        d_contract["Providers"].append(c["vzRtProv"]["attributes"]["tDn"])
    d_contract.update({"Subjects": {}})
    for c in get_contracts_info(tenant, contract, "children", "vzSubj"):
        d_contract["Subjects"].update({c["vzSubj"]["attributes"]["dn"]: []})
        for s in get_subject_info(
                tenant,
                contract,
                c["vzSubj"]["attributes"]["name"]):
            d_contract["Subjects"][c["vzSubj"]["attributes"]["dn"]].append(
                s["vzRsSubjFiltAtt"]["attributes"]["tDn"])
    return d_contract

# ---------------------------------------------------------------------------------------------------------------------------------------------


def mapping_zoningrule_contract(pod_id, node_id, tenant, contract):
    rule_type = (
        "id",
        "sPcTag",
        "dPcTag",
        "fltId",
        "direction",
        "operSt",
        "scopeId",
        "action",
        "prio")
    rules = {}

    if tenant is None or contract is None:  # All filters in the switch
        zoningrules = get_zoningrule(pod_id, node_id)
        d_contract = {}
        for zoningrule in zoningrules:
            rule = zoningrule["actrlRule"]["attributes"]["dn"]
            rules.update({rule: {}})
            for t in rule_type:
                rules[rule].update(
                    {t: zoningrule["actrlRule"]["attributes"][t]})
                if zoningrule["actrlRule"]["attributes"]["ctrctName"] != "":
                    rules[rule].update(
                        {"fltName": zoningrule["actrlRule"]["attributes"]["ctrctName"]})
                else:
                    rules[rule].update(
                        {"fltName": zoningrule["actrlRule"]["attributes"]["fltId"]})
        d_contract.update(
            {"rules/pod-{}/node-{}".format(pod_id, node_id): rules})

    else:  # Filters matching the tenant/contract
        d_contract = get_contract(tenant, contract)
        if not bool(d_contract):
            return None
        zoningrules = get_zoningrule(
            pod_id,
            node_id,
            filters="wcard(actrlRule.ctrctName,\"{}:{}\")".format(
                tenant,
                contract))
        if zoningrules != []:
            for zoningrule in zoningrules:
                rule = zoningrule["actrlRule"]["attributes"]["dn"]
                rules.update({rule: {}})
                for t in rule_type:
                    rules[rule].update(
                        {t: zoningrule["actrlRule"]["attributes"][t]})
                    if zoningrule["actrlRule"]["attributes"]["ctrctName"] != "":
                        rules[rule].update(
                            {"fltName": zoningrule["actrlRule"]["attributes"]["ctrctName"]})
                    else:
                        rules[rule].update(
                            {"fltName": zoningrule["actrlRule"]["attributes"]["fltId"]})
                d_contract.update(
                    {"rules/pod-{}/node-{}".format(pod_id, node_id): rules})
        else:
            d_contract.update(
                {"rules/pod-{}/node-{}".format(pod_id, node_id): {}})

    return d_contract

# ---------------------------------------------------------------------------------------------------------------------------------------------


def contract_rules(pod_id, node_id, tenant=None, contract=None):  # prettify
    d_contract = mapping_zoningrule_contract(pod_id, node_id, tenant, contract)
    node = "rules/pod-{}/node-{}".format(pod_id, node_id)
    if not bool(d_contract):
        return None
    d_epgs = {}
    scopes = []
    for i in d_contract[node]:
        scopes.append(d_contract[node][i]["scopeId"])
    scopes = set(scopes)
    if tenant is None or contract is None:
        update(d_epgs, EPGs())
    else:
        for scope in scopes:
            update(d_epgs, EPGs("scope-{}".format(scope)))
    debug(d_epgs, "EPGs: ", 2)
    debug(d_contract, "Contracts: ", 2)
    for i in d_contract[node]:
        d_contract[node][i]["scopeId"] = d_epgs[d_contract[node][i]["scopeId"]]
        if d_contract[node][i]["sPcTag"] != "any":
            try:
                if d_contract[node][i]["sPcTag"] in pctags:
                    d_contract[node][i]["sPcTag"] = pctags[d_contract[node][i]["sPcTag"]]
                else:
                    d_contract[node][i]["sPcTag"] = d_epgs[d_contract[node][
                        i]["scopeId"]][d_contract[node][i]["sPcTag"]]
            except KeyError:
                printt(
                    "Key not found scopeId={} sPcTag={}".format(
                        d_contract[node][i]["scopeId"],
                        d_contract[node][i]["sPcTag"]))
        if d_contract[node][i]["dPcTag"] != "any":
            try:
                if d_contract[node][i]["dPcTag"] in pctags:
                    d_contract[node][i]["dPcTag"] = pctags[d_contract[node][i]["dPcTag"]]
                else:
                    d_contract[node][i]["dPcTag"] = d_epgs[d_contract[node][
                        i]["scopeId"]][d_contract[node][i]["dPcTag"]]
            except KeyError:
                printt(
                    "Key not found scopeId={} dPcTag={}".format(
                        d_contract[node][i]["scopeId"],
                        d_contract[node][i]["dPcTag"]))
        #del d_contract[node][i]["fltId"]
    return d_contract

# ---------------------------------------------------------------------------------------------------------------------------------------------
# MAIN args parser
# ---------------------------------------------------------------------------------------------------------------------------------------------
# **********************************************************************************
# Create an envs.py file with (eg):
# URL="https://sandboxapicdc.cisco.com"
#USERNAME = "admin"
#PASS = "ciscopsdt"
# If there isn't a envs.py you can introduce the values in runtime
# **********************************************************************************


if __name__ == "__main__":
    import argparse
    from getpass import getpass
    no_envs = False
    try:
        import envs
    except ModuleNotFoundError:
        printt("No envs file located")
        no_envs = True

    separator = "-" * 110
    desc = separator + \
        """\nThis script generates a correlated output from the zoning-rule in the desired leaf switch, it runs locally
and using the APIC's APIs. It also has the posibility to filter the tenant/contract construct to validate
the correct renderization of the policy.
    """

    debugmsg = """Optional argument: debug level:
-d 1 = Response codes
-d 2 = Internal objs
-d 3 = Verbose"""

    def indent_formatter(prog): return argparse.RawTextHelpFormatter(
        prog, max_help_position=50)
    parser = argparse.ArgumentParser(
        prog="contract-checker",
        description=desc,
        formatter_class=indent_formatter,
        epilog=separator)

    parser.add_argument(
        'pod',
        metavar='podID',
        help='Pod ID number, eg: 1',
        type=int)
    parser.add_argument(
        'node',
        metavar='nodeID',
        help='Node ID number, eg: 101',
        type=int)
    parser.add_argument(
        '-t',
        '--tenant',
        action='store',
        help='Optional argument: Tenant of the contract to filter',
        metavar='Tenant Name')
    parser.add_argument(
        '-c',
        '--contract',
        action='store',
        help='Optional argument: contract to filter',
        metavar='Contract Name')
    parser.add_argument(
        '-d',
        '--debug',
        action='store',
        help=debugmsg,
        metavar='debug',
        type=int)
    parser.add_argument(
        '-l',
        '--logfile',
        action='store_true',
        help='Optional argument: log in a file')

    args = parser.parse_args()

    if no_envs:
        APIC_URL = str(input("APIC's URL: "))
        APIC_URL = "https://{}".format(URL) if URL[0:4] != "https://" else URL
        USERNAME = str(input("Username: "))
        PASS = getpass("Password: ")
    else:
        try:
            APIC_URL = envs.URL
        except AttributeError:
            APIC_URL = str(input("APIC's URL: "))
            APIC_URL = "https://{}".format(
                URL) if URL[0:4] != "https://" else URL
        try:
            USERNAME = envs.USERNAME
        except AttributeError:
            USERNAME = str(input("Username: "))
        try:
            PASS = envs.PASS
        except AttributeError:
            PASS = getpass("Password: ")

    _debug = args.debug if args.debug else _debug
    _debugLog = args.logfile

    try:
        if args.tenant is None and args.contract is None:
            printable(contract_rules(args.pod, args.node))
        else:
            printable(
                contract_rules(
                    args.pod,
                    args.node,
                    args.tenant,
                    args.contract))
    except KeyboardInterrupt:
        printt("KeyboardInterrupt -> Goodbye!")
