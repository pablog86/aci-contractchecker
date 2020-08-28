# ACI Contract Checker :white_check_mark:
[![published](https://static.production.devnetcloud.com/codeexchange/assets/images/devnet-published.svg)](https://developer.cisco.com/codeexchange/github/repo/pablog86/aci-contractchecker)

## Description

This script generates a correlated output from the zoning-rule in the desired leaf switch, it runs locally and using the APIC's APIs. It also has the possibility to filter the tenant/contract construct to validate the correct renderization of the policy on the leaf.

The script can log in a file the outputs executed for analysis in the same folder of the script.


## Requirements

***Tested on ACI 4.1 and 5.0***

### Clone the repository

```text
git clone https://github.com/pablog86/aci-contractchecker
cd aci-contractchecker

chmod 755 contractchecker.py
```

### Python environment

Create virtual environment and activate it (optional)

```text
python3 -m venv contractchecker_env  
source contractchecker_env/bin/activate
Install required modules
```

Install required modules

```text
pip install -r requirements.txt
```


## Usage & examples

For simplicity the script is prepared to read the APIC information from a file in the same directory with the name ***envs.py***

```text
URL="https://sandboxapicdc.cisco.com"
USERNAME = "admin"
PASS = "ciscopsdt"
```

In the case that the file doesn't exist or a parameter is absent, the script will ask the parameter in runtime.

### Get all zoning rules in the leaf 

Get the zoning rules in the desired leaf using the APIC APIs, and orders it by priority.

:computer: Example for pod-1 node-102:
```text
python contractchecker.py 1 102
```

**The output will be a table with the followin header**
- id: Rule ID
- Source: Source EPG
- Destination: Destination EPG
- Direction: Direction of the rule
- State: State of the rule in the switch
- VRF: Context of the rule
- Action: Action taken by the rule
- Prio: Priority of the rule (1 to 22)
- Filter-Contract: Filter ID / Contract name


#### Output example
```text
################### Rules in node: rules/pod-1/node-102 ###################

id   Source                                             Destination                                        Direction      State   VRF                                         Action          Prio                   Filter-Contract             
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
4172 tn-mgmt/mgmtp-default/inb-default                  tn-common/out-Tetration_L3Out/instP-Tetration-Mgmt bi-dir         enabled tn-common/ctx-VRF_Common                    permit          (09)src_dst_any        (default)uni/tn-common/brc-L3_Out_default
4124 tn-common/out-Tetration_L3Out/instP-Tetration-Mgmt tn-common/out-L3_Out/instP-Outside(0.0.0.0/0)      uni-dir        enabled tn-common/ctx-VRF_Common                    permit          (09)src_dst_any        (default)uni/tn-common/brc-L3_Out_default
4150 tn-common/out-Tetration_L3Out/instP-Tetration-Mgmt tn-common/out-L3_Out/instP-Outside(0.0.0.0/0)      uni-dir        enabled tn-common/ctx-VRF_Common                    permit_override (09)src_dst_any        (implicit)implicit                        
4169 tn-common/ap-dcp/epg-ops                           tn-mgmt/mgmtp-default/inb-default                  bi-dir         enabled tn-mgmt/ctx-inb                             permit          (09)src_dst_any        (default)uni/tn-common/brc-L3_Out_default
4134 tn-mgmt/mgmtp-default/inb-default                  tn-common/ap-dcp/epg-ops                           uni-dir-ignore enabled tn-mgmt/ctx-inb                             permit          (09)src_dst_any        (default)uni/tn-common/brc-L3_Out_default
4133 tn-common/ctx-VRF_Common                           tn-common/out-Tetration_L3Out/instP-Tetration-Mgmt uni-dir        enabled tn-common/ctx-VRF_Common                    permit          (09)src_dst_any        (default)default                         
4179 tn-common/out-L3_Out/instP-Outside                 tn-mgmt/mgmtp-default/inb-default                  uni-dir-ignore enabled tn-mgmt/ctx-inb                             permit          (09)src_dst_any        (default)uni/tn-common/brc-L3_Out_default
4178 tn-mgmt/mgmtp-default/inb-default                  tn-common/out-L3_Out/instP-Outside                 bi-dir         enabled tn-mgmt/ctx-inb                             permit          (09)src_dst_any        (default)uni/tn-common/brc-L3_Out_default
4132 tn-mgmt/ap-se-data-ap/epg-se-data-epg              tn-mgmt/mgmtp-default/inb-default                  uni-dir-ignore enabled tn-mgmt/ctx-inb                             permit          (09)src_dst_any        (default)uni/tn-mgmt/brc-SE-INB          
4158 tn-mgmt/mgmtp-default/inb-default                  tn-mgmt/ap-se-data-ap/epg-se-data-epg              bi-dir         enabled tn-mgmt/ctx-inb                             permit          (09)src_dst_any        (default)uni/tn-mgmt/brc-SE-INB          
4160 tn-DHCP/ap-dhcp_servers/epg-subnet-198.19.193.0_24 tn-mgmt/mgmtp-default/inb-default                  uni-dir-ignore enabled tn-mgmt/ctx-inb                             permit          (09)src_dst_any        (default)uni/tn-common/brc-L3_Out_default
4159 tn-mgmt/mgmtp-default/inb-default                  tn-DHCP/ap-dhcp_servers/epg-subnet-198.19.193.0_24 bi-dir         enabled tn-mgmt/ctx-inb                             permit          (09)src_dst_any        (default)uni/tn-common/brc-L3_Out_default
4151 tn-CWP-demo/ap-CWP-AP/epg-cwp-epg                  tn-mgmt/mgmtp-default/inb-default                  uni-dir-ignore enabled tn-mgmt/ctx-inb                             permit          (09)src_dst_any        (default)uni/tn-common/brc-L3_Out_default
4168 tn-common/out-Tetration_L3Out/instP-Tetration-Mgmt tn-mgmt/mgmtp-default/inb-default                  uni-dir-ignore enabled tn-common/ctx-VRF_Common                    permit          (09)src_dst_any        (default)uni/tn-common/brc-L3_Out_default
4144 tn-common/ap-shared_pat/epg-csr_pat                tn-mgmt/mgmtp-default/inb-default                  uni-dir-ignore enabled tn-mgmt/ctx-inb                             permit          (09)src_dst_any        (default)uni/tn-common/brc-L3_Out_default
4130 tn-mgmt/mgmtp-default/inb-default                  tn-CWP-demo/ap-CWP-AP/epg-cwp-epg                  bi-dir         enabled tn-mgmt/ctx-inb                             permit          (09)src_dst_any        (default)uni/tn-common/brc-L3_Out_default
4148 tn-mgmt/mgmtp-default/inb-default                  tn-mgmt/out-SE/instP-SE_ExtEPG(0.0.0.0/0)          uni-dir        enabled tn-mgmt/ctx-inb                             permit_override (09)src_dst_any        (implicit)implicit                        
4157 tn-mgmt/mgmtp-default/inb-default                  tn-common/out-Tetration_L3Out/instP-Tetration-Mgmt bi-dir         enabled tn-mgmt/ctx-inb                             permit          (09)src_dst_any        (default)uni/tn-common/brc-L3_Out_default
4141 tn-common/out-Tetration_L3Out/instP-Tetration-Mgmt tn-mgmt/mgmtp-default/inb-default                  uni-dir-ignore enabled tn-mgmt/ctx-inb                             permit          (09)src_dst_any        (default)uni/tn-common/brc-L3_Out_default
4135 tn-mgmt/mgmtp-default/inb-default                  tn-common/ap-shared_pat/epg-csr_pat                bi-dir         enabled tn-mgmt/ctx-inb                             permit          (09)src_dst_any        (default)uni/tn-common/brc-L3_Out_default
4137 tn-mgmt/mgmtp-default/inb-default                  tn-common/ap-securedc-inbound/epg-securedc-inbound bi-dir         enabled tn-mgmt/ctx-inb                             permit          (09)src_dst_any        (default)uni/tn-common/brc-L3_Out_default
4161 tn-common/ap-securedc-inbound/epg-securedc-inbound tn-mgmt/mgmtp-default/inb-default                  uni-dir-ignore enabled tn-mgmt/ctx-inb                             permit          (09)src_dst_any        (default)uni/tn-common/brc-L3_Out_default
4180 tn-common/ap-dcp/epg-ops                           any                                                uni-dir        enabled tn-mgmt/ctx-inb                             deny,log        (12)shsrc_any_any_deny (implicit)implicit                        
4154 tn-common/ap-shared_pat/epg-csr_pat                any                                                uni-dir        enabled tn-mgmt/ctx-inb                             deny,log        (12)shsrc_any_any_deny (implicit)implicit                        
4139 tn-DHCP/ap-dhcp_servers/epg-subnet-198.19.193.0_24 any                                                uni-dir        enabled tn-mgmt/ctx-inb                             deny,log        (12)shsrc_any_any_deny (implicit)implicit                        
4138 tn-common/out-Tetration_L3Out/instP-Tetration-Mgmt any                                                uni-dir        enabled tn-mgmt/ctx-inb                             deny,log        (12)shsrc_any_any_deny (implicit)implicit                        
4176 tn-CWP-demo/ap-CWP-AP/epg-cwp-epg                  any                                                uni-dir        enabled tn-mgmt/ctx-inb                             deny,log        (12)shsrc_any_any_deny (implicit)implicit                        
4153 tn-common/ap-securedc-inbound/epg-securedc-inbound any                                                uni-dir        enabled tn-mgmt/ctx-inb                             deny,log        (12)shsrc_any_any_deny (implicit)implicit                        
4165 tn-mgmt/mgmtp-default/inb-default                  any                                                uni-dir        enabled tn-common/ctx-VRF_Common                    deny,log        (12)shsrc_any_any_deny (implicit)implicit                        
4102 any                                                tn-common/BD-useg-inbound                          uni-dir        enabled tn-common/ctx-VRF_Common                    permit          (16)any_dest_any       (implicit)implicit                        
4110 any                                                tn-iSCSI/BD-iSCSI-A                                uni-dir        enabled tn-iSCSI/ctx-iSCSI                          permit          (16)any_dest_any       (implicit)implicit                        
4111 any                                                tn-ACI-Security-Integration/BD-CCL3-4              uni-dir        enabled tn-ACI-Security-Integration/ctx-Device-Mgmt permit          (16)any_dest_any       (implicit)implicit                        
4109 any                                                tn-ACI-Security-Integration/BD-CCL1-2              uni-dir        enabled tn-ACI-Security-Integration/ctx-Device-Mgmt permit          (16)any_dest_any       (implicit)implicit                        
4116 any                                                tn-vivdalvi511131/BD-opencart_bd                   uni-dir        enabled tn-vivdalvi511131/ctx-opencart_vrf          permit          (16)any_dest_any       (implicit)implicit                        
4101 any                                                tn-common/BD-tetration-pods                        uni-dir        enabled tn-common/ctx-VRF_Common                    permit          (16)any_dest_any       (implicit)implicit                        
4123 any                                                tn-iSCSI/BD-iSCSI-B                                uni-dir        enabled tn-iSCSI/ctx-iSCSI                          permit          (16)any_dest_any       (implicit)implicit                        
4115 any                                                tn-ms/BD-Live_Migration                            uni-dir        enabled tn-ms/ctx-Live_Migration                    permit          (16)any_dest_any       (implicit)implicit                        
4167 any                                                tn-mgmt/BD-inb                                     uni-dir        enabled tn-mgmt/ctx-inb                             permit          (16)any_dest_any       (implicit)implicit                        
4099 any                                                any                                                uni-dir        enabled tn-common/ctx-VRF_Common                    permit          (17)any_any_filter     (implarp)implarp                         
4121 any                                                any                                                uni-dir        enabled tn-vivdalvi511131/ctx-opencart_vrf          permit          (17)any_any_filter     (implarp)implarp                         
4104 any                                                any                                                uni-dir        enabled tn-mgmt/ctx-oob                             permit          (17)any_any_filter     (implarp)implarp                         
4118 any                                                any                                                uni-dir        enabled tn-ms/ctx-Live_Migration                    permit          (17)any_any_filter     (implarp)implarp                         
4107 any                                                any                                                uni-dir        enabled tn-iSCSI/ctx-iSCSI                          permit          (17)any_any_filter     (implarp)implarp                         
4097 any                                                any                                                uni-dir        enabled tn-infra/black-hole                         permit          (17)any_any_filter     (implarp)implarp                         
4143 any                                                any                                                uni-dir        enabled tn-mgmt/ctx-inb                             permit          (17)any_any_filter     (implarp)implarp                         
4113 any                                                any                                                uni-dir        enabled tn-ACI-Security-Integration/ctx-Device-Mgmt permit          (17)any_any_filter     (implarp)implarp                         
4117 any                                                any                                                uni-dir        enabled tn-ms/ctx-Live_Migration                    deny,log        (21)any_any_any        (implicit)implicit                        
4120 any                                                any                                                uni-dir        enabled tn-vivdalvi511131/ctx-opencart_vrf          deny,log        (21)any_any_any        (implicit)implicit                        
4103 any                                                any                                                uni-dir        enabled tn-mgmt/ctx-oob                             deny,log        (21)any_any_any        (implicit)implicit                        
4112 any                                                any                                                uni-dir        enabled tn-ACI-Security-Integration/ctx-Device-Mgmt deny,log        (21)any_any_any        (implicit)implicit                        
4106 any                                                any                                                uni-dir        enabled tn-iSCSI/ctx-iSCSI                          deny,log        (21)any_any_any        (implicit)implicit                        
4098 any                                                any                                                uni-dir        enabled tn-common/ctx-VRF_Common                    deny,log        (21)any_any_any        (implicit)implicit                        
4146 any                                                any                                                uni-dir        enabled tn-mgmt/ctx-inb                             deny,log        (21)any_any_any        (implicit)implicit                        
4096 any                                                any                                                uni-dir        enabled tn-infra/black-hole                         deny,log        (21)any_any_any        (implicit)implicit                        
4108 any                                                ext-0.0.0.0/0                                      uni-dir        enabled tn-iSCSI/ctx-iSCSI                          deny,log        (22)any_vrf_any_deny   (implicit)implicit                        
4105 any                                                ext-0.0.0.0/0                                      uni-dir        enabled tn-mgmt/ctx-oob                             deny,log        (22)any_vrf_any_deny   (implicit)implicit                        
4119 any                                                ext-0.0.0.0/0                                      uni-dir        enabled tn-ms/ctx-Live_Migration                    deny,log        (22)any_vrf_any_deny   (implicit)implicit                        
4100 any                                                tn-common/out-L3_Out/instP-Outside(0.0.0.0/0)      uni-dir        enabled tn-common/ctx-VRF_Common                    deny,log        (22)any_vrf_any_deny   (implicit)implicit                        
4122 any                                                ext-0.0.0.0/0                                      uni-dir        enabled tn-vivdalvi511131/ctx-opencart_vrf          deny,log        (22)any_vrf_any_deny   (implicit)implicit                        
4140 any                                                tn-mgmt/out-SE/instP-SE_ExtEPG(0.0.0.0/0)          uni-dir        enabled tn-mgmt/ctx-inb                             deny,log        (22)any_vrf_any_deny   (implicit)implicit                        
4114 any                                                ext-0.0.0.0/0                                      uni-dir        enabled tn-ACI-Security-Integration/ctx-Device-Mgmt deny,log        (22)any_vrf_any_deny   (implicit)implicit                        


2020-08-28 15:42:44.118545
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
```

### Get Contract information

Get the tenant/contract information and correlate the information running on the desired leaf using the APIC APIs.

:computer: Example for tenant Tenant1 and contract C1 in the pod-1/node-101:
```text
python contractchecker.py -t Tenant1 -c C1 1 101
```

#### Output example
```text
% python contractchecker.py 1 102 -t mgmt -c SE-INB
################### Contract: uni/tn-mgmt/brc-SE-INB ###################

Consumers: 
uni/tn-mgmt/mgmtp-default/inb-default
uni/tn-mgmt/out-SE/instP-SE_ExtEPG
----------------------------------------
Providers: 
uni/tn-mgmt/ap-se-data-ap/epg-se-data-epg
----------------------------------------
Subjects: 
uni/tn-mgmt/brc-SE-INB/subj-SE-INB:['uni/tn-common/flt-default']
----------------------------------------

################### Rules in node: rules/pod-1/node-102 ###################

id   Source                                Destination                           Direction      State   VRF             Action          Prio            Filter-Contract   
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
4158 tn-mgmt/mgmtp-default/inb-default     tn-mgmt/ap-se-data-ap/epg-se-data-epg bi-dir         enabled tn-mgmt/ctx-inb permit          (09)src_dst_any (default)uni/tn-mgmt/brc-SE-INB
4132 tn-mgmt/ap-se-data-ap/epg-se-data-epg tn-mgmt/mgmtp-default/inb-default     uni-dir-ignore enabled tn-mgmt/ctx-inb permit          (09)src_dst_any (default)uni/tn-mgmt/brc-SE-INB


2020-08-27 13:18:23.903802
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
```

##### Notes
*In the priority level Prio: lower is better (01) to (22)*

### Script Help
```text
% python contractchecker.py -h                        
usage: contract-checker [-h] [-t Tenant Name] [-c Contract Name] [-d debug]
                        [-l]
                        podID nodeID

--------------------------------------------------------------------------------------------------------------
This script generates a correlated output from the zoning-rule in the desired leaf switch, it runs locally 
and using the APIC's APIs. It also has the posibility to filter the tenant/contract construct to validate 
the correct renderization of the policy.
    

positional arguments:
  podID                                       Pod ID number, eg: 1
  nodeID                                      Node ID number, eg: 101

optional arguments:
  -h, --help                                  show this help message and exit
  -t Tenant Name, --tenant Tenant Name        Optional argument: Tenant of the contract to filter
  -c Contract Name, --contract Contract Name  Optional argument: contract to filter
  -d debug, --debug debug                     Optional argument: debug level: 
                                              -d 1 = Response codes
                                              -d 2 = Internal objs 
                                              -d 3 = Verbose
  -l, --logfile                               Optional argument: log in a file

--------------------------------------------------------------------------------------------------------------
```

(-l) -> Log file in the same folder with the name ***"debuglog.json"*** :open_file_folder:

(-d 1)	-> debug level 1 (lowest)
##### Output example
```text
Debug output CODE get_contracts_info -> (url=https://sandboxapicdc.cisco.com/api/node/mo/uni/tn-common/brc-sql.json, query_target=None, target-subtree-class=None, query-target-filter=None, page-size=2000, page=0): 
200
totalCount: 
"1"
Debug output CODE get_contracts_info -> (url=https://sandboxapicdc.cisco.com/api/node/mo/uni/tn-common/brc-sql.json, query_target=children, target-subtree-class=vzRtCons, query-target-filter=None, page-size=2000, page=0): 
200
totalCount: 
"7"
Debug output CODE get_contracts_info -> (url=https://sandboxapicdc.cisco.com/api/node/mo/uni/tn-common/brc-sql.json, query_target=children, target-subtree-class=vzRtProv, query-target-filter=None, page-size=2000, page=0): 
200
totalCount: 
"6"
Debug output CODE get_contracts_info -> (url=https://sandboxapicdc.cisco.com/api/node/mo/uni/tn-common/brc-sql.json, query_target=children, target-subtree-class=vzSubj, query-target-filter=None, page-size=2000, page=0): 
200
totalCount: 
"2"
Debug output CODE get_subject_info -> (url=https://sandboxapicdc.cisco.com/api/node/mo/uni/tn-common/brc-sql/subj-sql-browser.json, query_target=children, target-subtree-class=vzRsSubjFiltAtt, query-target-filter=None, page-size=2000, page=0): 
200
totalCount: 
"1"
Debug output CODE get_subject_info -> (url=https://sandboxapicdc.cisco.com/api/node/mo/uni/tn-common/brc-sql/subj-sql-server.json, query_target=children, target-subtree-class=vzRsSubjFiltAtt, query-target-filter=None, page-size=2000, page=0): 
200
totalCount: 
"1"
```

(-d 2) -> debug level 2 
##### Output example
```text
Debug output CODE get_contracts_info -> (url=https://apic.svpod.dc-01.com/api/node/mo/uni/tn-mgmt/brc-SE-INB.json, query_target=None, target-subtree-class=None, query-target-filter=None, page-size=2000, page=0): 
200
totalCount: 
"1"
get_contracts_info response aggregated lenght:
1
get_contracts_info response lenght:
1
get_contracts_info response aggregated lenght:
1
Debug output CODE get_contracts_info -> (url=https://apic.svpod.dc-01.com/api/node/mo/uni/tn-mgmt/brc-SE-INB.json, query_target=children, target-subtree-class=vzRtCons, query-target-filter=None, page-size=2000, page=0): 
200
totalCount: 
"2"
get_contracts_info response aggregated lenght:
2
get_contracts_info response lenght:
2
get_contracts_info response aggregated lenght:
2
Debug output CODE get_contracts_info -> (url=https://apic.svpod.dc-01.com/api/node/mo/uni/tn-mgmt/brc-SE-INB.json, query_target=children, target-subtree-class=vzRtProv, query-target-filter=None, page-size=2000, page=0): 
200

<..omitted..>

VRFs: 
{
<..omitted..>
    "2981888": "uni/tn-mgmt/ctx-inb",
    "uni/tn-mgmt/ctx-inb-pctag": "49153",
<..omitted..>
}
EPGs: 
{
    "2981888": "uni/tn-mgmt/ctx-inb",
    "uni/tn-mgmt/ctx-inb": {
        "32771": "uni/tn-mgmt/ap-se-data-ap/epg-se-data-epg",
        "49153": "uni/tn-mgmt/ctx-inb",
        "32772": "uni/tn-mgmt/out-SE/instP-SE_ExtEPG",
        "11112": "uni/tn-mgmt/mgmtp-default/inb-default"
    },
    "16777200": "uni/tn-infra/black-hole"
}
Contracts: 
{
    "dn": "uni/tn-mgmt/brc-SE-INB",
    "Consumers": [
        "uni/tn-mgmt/mgmtp-default/inb-default",
        "uni/tn-mgmt/out-SE/instP-SE_ExtEPG"
    ],
    "Providers": [
        "uni/tn-mgmt/ap-se-data-ap/epg-se-data-epg"
    ],
    "Subjects": {
        "uni/tn-mgmt/brc-SE-INB/subj-SE-INB": [
            "uni/tn-common/flt-default"
        ]
    },
    "rules/pod-1/node-102": {
        "topology/pod-1/node-102/sys/actrl/scope-2981888/rule-2981888-s-11112-d-32771-f-default": {
            "id": "4158",
            "fltName": "mgmt:SE-INB",
            "sPcTag": "11112",
            "dPcTag": "32771",
            "fltId": "default",
            "direction": "bi-dir",
            "operSt": "enabled",
            "scopeId": "2981888",
            "action": "permit",
            "prio": "src_dst_any"
        },
        "topology/pod-1/node-102/sys/actrl/scope-2981888/rule-2981888-s-32771-d-11112-f-default": {
            "id": "4132",
            "fltName": "mgmt:SE-INB",
            "sPcTag": "32771",
            "dPcTag": "11112",
            "fltId": "default",
            "direction": "uni-dir-ignore",
            "operSt": "enabled",
            "scopeId": "2981888",
            "action": "permit",
            "prio": "src_dst_any"
        }
    }
}
Filter Info: 
[
    {
        "vzRsRFltAtt": {
            "attributes": {
                "action": "permit",
                "childAction": "",
                "direction": "bidir",
                "dn": "topology/pod-1/node-102/local/svc-policyelem-id-0/cdef-[uni/tn-mgmt/brc-SE-INB]/epgCont-[uni/tn-mgmt/mgmtp-default/inb-default]/fr-[uni/tn-mgmt/brc-SE-INB/dirass/cons-[uni/tn-mgmt/mgmtp-default/inb-default]-any-no]/to-[uni/tn-mgmt/brc-SE-INB/dirass/prov-[uni/tn-mgmt/ap-se-data-ap/epg-se-data-epg]-any-no]/rsrFltAtt-[uni/tn-common/fp-default]",
                "forceResolve": "yes",
                "isGraph": "no",
                "lcOwn": "policy",
                "markDscp": "unspecified",
                "modTs": "2020-06-26T07:11:18.315+00:00",
                "monPolDn": "",
                "prio": "unspecified",
                "priorityOverride": "default",
                "rType": "mo",
                "remoteMarkDscp": "unspecified",
                "remotePrio": "unspecified",
                "sdwanSlaDn": "",
                "state": "formed",
                "stateQual": "none",
                "status": "",
                "tCl": "vzAFilterableUnit",
                "tDn": "uni/tn-common/fp-default",
                "tType": "mo"
            }
        }
    }
]
```

(-d 3) -> The json output of every response.
