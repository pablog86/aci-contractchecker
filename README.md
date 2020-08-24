# ACI Contract Checker

## Description

This script generates a correlated output from the zoning-rule in the desired leaf switch, it runs locally and using the APIC's APIs. It also has the posibility to filter the tenant/contract construct to validate the correct renderization of the policy on the leaf.

The script can log in a file the outputs executed for analysis in the same folder of the script.

### Clone the repository

```text
git clone https://github.com/pablog86/aci-contractchecker.py
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

### Usage examples

For simplicity the script is prepared to read the APIC information from a file in the same directory with the name envs.py

```text
URL="https://sandboxapicdc.cisco.com"
USERNAME = "admin"
PASS = "ciscopsdt"
```

In the case that the file doesn't exist o a parameter is absent, the script will ask the parameter in runtime.

### Get all zoning rules in the leaf

Get using the APIC APIs the zoning rules in the desired leaf.

Example for pod-1 node-101

```text
python contractchecker.py 1 101
```

#### Output example
```text
################### Rules in node: rules/pod-1/node-102 ###################

id   Source                                             Destination                                        Direction      State   VRF                                         Action          Prio                   Filter-Contract
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
4172 11112                                              tn-common/out-Tetration_L3Out/instP-Tetration-Mgmt bi-dir         enabled tn-common/ctx-VRF_Common                    permit          (09)src_dst_any        (default)default        
4165 11112                                              any                                                uni-dir        enabled tn-common/ctx-VRF_Common                    deny,log        (12)shsrc_any_any_deny (implicit)implicit       
4146 any                                                any                                                uni-dir        enabled tn-mgmt/ctx-inb                             deny,log        (21)any_any_any        (implicit)implicit       
4148 tn-mgmt/mgmtp-default/inb-default                  int-shrsvc                                         uni-dir        enabled tn-mgmt/ctx-inb                             permit_override (09)src_dst_any        (implicit)implicit       
4157 tn-mgmt/mgmtp-default/inb-default                  11102                                              bi-dir         enabled tn-mgmt/ctx-inb                             permit          (09)src_dst_any        (default)default        
4141 11102                                              tn-mgmt/mgmtp-default/inb-default                  uni-dir-ignore enabled tn-mgmt/ctx-inb                             permit          (09)src_dst_any        (default)default        
4135 tn-mgmt/mgmtp-default/inb-default                  10997                                              bi-dir         enabled tn-mgmt/ctx-inb                             permit          (09)src_dst_any        (default)default        
4144 10997                                              tn-mgmt/mgmtp-default/inb-default                  uni-dir-ignore enabled tn-mgmt/ctx-inb                             permit          (09)src_dst_any        (default)default        
4137 tn-mgmt/mgmtp-default/inb-default                  75                                                 bi-dir         enabled tn-mgmt/ctx-inb                             permit          (09)src_dst_any        (default)default        
4161 75                                                 tn-mgmt/mgmtp-default/inb-default                  uni-dir-ignore enabled tn-mgmt/ctx-inb                             permit          (09)src_dst_any        (default)default        
4167 any                                                tn-mgmt/BD-inb                                     uni-dir        enabled tn-mgmt/ctx-inb                             permit          (16)any_dest_any       (implicit)implicit       
4153 75                                                 any                                                uni-dir        enabled tn-mgmt/ctx-inb                             deny,log        (12)shsrc_any_any_deny (implicit)implicit       
4130 tn-mgmt/mgmtp-default/inb-default                  5546                                               bi-dir         enabled tn-mgmt/ctx-inb                             permit          (09)src_dst_any        (default)default        
4151 5546                                               tn-mgmt/mgmtp-default/inb-default                  uni-dir-ignore enabled tn-mgmt/ctx-inb                             permit          (09)src_dst_any        (default)default        
4154 10997                                              any                                                uni-dir        enabled tn-mgmt/ctx-inb                             deny,log        (12)shsrc_any_any_deny (implicit)implicit       
4159 tn-mgmt/mgmtp-default/inb-default                  10932                                              bi-dir         enabled tn-mgmt/ctx-inb                             permit          (09)src_dst_any        (default)default        
4160 10932                                              tn-mgmt/mgmtp-default/inb-default                  uni-dir-ignore enabled tn-mgmt/ctx-inb                             permit          (09)src_dst_any        (default)default        
4176 5546                                               any                                                uni-dir        enabled tn-mgmt/ctx-inb                             deny,log        (12)shsrc_any_any_deny (implicit)implicit       
4138 11102                                              any                                                uni-dir        enabled tn-mgmt/ctx-inb                             deny,log        (12)shsrc_any_any_deny (implicit)implicit       
4139 10932                                              any                                                uni-dir        enabled tn-mgmt/ctx-inb                             deny,log        (12)shsrc_any_any_deny (implicit)implicit       
4143 any                                                any                                                uni-dir        enabled tn-mgmt/ctx-inb                             permit          (17)any_any_filter     (implarp)implarp        
4140 any                                                ext-0.0.0.0/0                                      uni-dir        enabled tn-mgmt/ctx-inb                             deny,log        (22)any_vrf_any_deny   (implicit)implicit       
4158 tn-mgmt/mgmtp-default/inb-default                  tn-mgmt/ap-se-data-ap/epg-se-data-epg              bi-dir         enabled tn-mgmt/ctx-inb                             permit          (09)src_dst_any        (default)mgmt:SE-INB    
4132 tn-mgmt/ap-se-data-ap/epg-se-data-epg              tn-mgmt/mgmtp-default/inb-default                  uni-dir-ignore enabled tn-mgmt/ctx-inb                             permit          (09)src_dst_any        (default)mgmt:SE-INB    
4178 tn-mgmt/mgmtp-default/inb-default                  5529                                               bi-dir         enabled tn-mgmt/ctx-inb                             permit          (09)src_dst_any        (default)default        
4179 5529                                               tn-mgmt/mgmtp-default/inb-default                  uni-dir-ignore enabled tn-mgmt/ctx-inb                             permit          (09)src_dst_any        (default)default        
4133 tn-common/ctx-VRF_Common                           tn-common/out-Tetration_L3Out/instP-Tetration-Mgmt uni-dir        enabled tn-common/ctx-VRF_Common                    permit          (09)src_dst_any        (default)default        
4134 tn-mgmt/mgmtp-default/inb-default                  5557                                               uni-dir-ignore enabled tn-mgmt/ctx-inb                             permit          (09)src_dst_any        (default)default        
4169 5557                                               tn-mgmt/mgmtp-default/inb-default                  bi-dir         enabled tn-mgmt/ctx-inb                             permit          (09)src_dst_any        (default)default        
4180 5557                                               any                                                uni-dir        enabled tn-mgmt/ctx-inb                             deny,log        (12)shsrc_any_any_deny (implicit)implicit       
4096 any                                                any                                                uni-dir        enabled tn-infra/black-hole                         deny,log        (21)any_any_any        (implicit)implicit       
4097 any                                                any                                                uni-dir        enabled tn-infra/black-hole                         permit          (17)any_any_filter     (implarp)implarp        
4098 any                                                any                                                uni-dir        enabled tn-common/ctx-VRF_Common                    deny,log        (21)any_any_any        (implicit)implicit       
4099 any                                                any                                                uni-dir        enabled tn-common/ctx-VRF_Common                    permit          (17)any_any_filter     (implarp)implarp        
4100 any                                                ext-0.0.0.0/0                                      uni-dir        enabled tn-common/ctx-VRF_Common                    deny,log        (22)any_vrf_any_deny   (implicit)implicit       
4101 any                                                tn-common/BD-tetration-pods                        uni-dir        enabled tn-common/ctx-VRF_Common                    permit          (16)any_dest_any       (implicit)implicit       
4102 any                                                tn-common/BD-useg-inbound                          uni-dir        enabled tn-common/ctx-VRF_Common                    permit          (16)any_dest_any       (implicit)implicit       
4103 any                                                any                                                uni-dir        enabled tn-mgmt/ctx-oob                             deny,log        (21)any_any_any        (implicit)implicit       
4104 any                                                any                                                uni-dir        enabled tn-mgmt/ctx-oob                             permit          (17)any_any_filter     (implarp)implarp        
4105 any                                                ext-0.0.0.0/0                                      uni-dir        enabled tn-mgmt/ctx-oob                             deny,log        (22)any_vrf_any_deny   (implicit)implicit       
4106 any                                                any                                                uni-dir        enabled tn-iSCSI/ctx-iSCSI                          deny,log        (21)any_any_any        (implicit)implicit       
4107 any                                                any                                                uni-dir        enabled tn-iSCSI/ctx-iSCSI                          permit          (17)any_any_filter     (implarp)implarp        
4108 any                                                ext-0.0.0.0/0                                      uni-dir        enabled tn-iSCSI/ctx-iSCSI                          deny,log        (22)any_vrf_any_deny   (implicit)implicit       
4109 any                                                tn-ACI-Security-Integration/BD-CCL1-2              uni-dir        enabled tn-ACI-Security-Integration/ctx-Device-Mgmt permit          (16)any_dest_any       (implicit)implicit       
4110 any                                                tn-iSCSI/BD-iSCSI-A                                uni-dir        enabled tn-iSCSI/ctx-iSCSI                          permit          (16)any_dest_any       (implicit)implicit       
4111 any                                                tn-ACI-Security-Integration/BD-CCL3-4              uni-dir        enabled tn-ACI-Security-Integration/ctx-Device-Mgmt permit          (16)any_dest_any       (implicit)implicit       
4112 any                                                any                                                uni-dir        enabled tn-ACI-Security-Integration/ctx-Device-Mgmt deny,log        (21)any_any_any        (implicit)implicit       
4113 any                                                any                                                uni-dir        enabled tn-ACI-Security-Integration/ctx-Device-Mgmt permit          (17)any_any_filter     (implarp)implarp        
4114 any                                                ext-0.0.0.0/0                                      uni-dir        enabled tn-ACI-Security-Integration/ctx-Device-Mgmt deny,log        (22)any_vrf_any_deny   (implicit)implicit       
4115 any                                                tn-ms/BD-Live_Migration                            uni-dir        enabled tn-ms/ctx-Live_Migration                    permit          (16)any_dest_any       (implicit)implicit       
4116 any                                                tn-vivdalvi511131/BD-opencart_bd                   uni-dir        enabled tn-vivdalvi511131/ctx-opencart_vrf          permit          (16)any_dest_any       (implicit)implicit       
4117 any                                                any                                                uni-dir        enabled tn-ms/ctx-Live_Migration                    deny,log        (21)any_any_any        (implicit)implicit       
4118 any                                                any                                                uni-dir        enabled tn-ms/ctx-Live_Migration                    permit          (17)any_any_filter     (implarp)implarp        
4119 any                                                ext-0.0.0.0/0                                      uni-dir        enabled tn-ms/ctx-Live_Migration                    deny,log        (22)any_vrf_any_deny   (implicit)implicit       
4120 any                                                any                                                uni-dir        enabled tn-vivdalvi511131/ctx-opencart_vrf          deny,log        (21)any_any_any        (implicit)implicit       
4121 any                                                any                                                uni-dir        enabled tn-vivdalvi511131/ctx-opencart_vrf          permit          (17)any_any_filter     (implarp)implarp        
4122 any                                                ext-0.0.0.0/0                                      uni-dir        enabled tn-vivdalvi511131/ctx-opencart_vrf          deny,log        (22)any_vrf_any_deny   (implicit)implicit       
4123 any                                                tn-iSCSI/BD-iSCSI-B                                uni-dir        enabled tn-iSCSI/ctx-iSCSI                          permit          (16)any_dest_any       (implicit)implicit       
4124 tn-common/out-Tetration_L3Out/instP-Tetration-Mgmt ext-0.0.0.0/0                                      uni-dir        enabled tn-common/ctx-VRF_Common                    permit          (09)src_dst_any        (default)default        
4150 tn-common/out-Tetration_L3Out/instP-Tetration-Mgmt int-shrsvc                                         uni-dir        enabled tn-common/ctx-VRF_Common                    permit_override (09)src_dst_any        (implicit)implicit       
4168 tn-common/out-Tetration_L3Out/instP-Tetration-Mgmt 11112                                              uni-dir-ignore enabled tn-common/ctx-VRF_Common                    permit          (09)src_dst_any        (default)default        
```

### Get Contract information

Get using the APIC APIs the tenant/contract information and correlate the information running on the desired leaf.

Example for tenant Tenant1 and contract C1 in the pod-1/node-101

```text
python contractchecker.py -t Tenant1 -c C1 1 101
```

#### Output example
```text
% python contractchecker.py 1 102 -t mgmt -c SE-INB
Working: (-)
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
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
4158 tn-mgmt/mgmtp-default/inb-default     tn-mgmt/ap-se-data-ap/epg-se-data-epg bi-dir         enabled tn-mgmt/ctx-inb permit          (09)src_dst_any (default)mgmt:SE-INB    
4132 tn-mgmt/ap-se-data-ap/epg-se-data-epg tn-mgmt/mgmtp-default/inb-default     uni-dir-ignore enabled tn-mgmt/ctx-inb permit          (09)src_dst_any (default)mgmt:SE-INB 
```

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
