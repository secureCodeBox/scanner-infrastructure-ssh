---
title: "SSH"
path: "scanner/SSH"
category: "scanner"
usecase: "SSH Configuration and Policy Scanner"
release: "https://img.shields.io/github/release/secureCodeBox/scanner-infrastructure-ssh.svg"

---
SSH_scan is an easy-to-use prototype SSH configuration and policy scanner, inspired by Mozilla OpenSSH Security Guide, which provides a reasonable baseline policy recommendation for SSH configuration parameters such as Ciphers, MACs, and KexAlgos and much more.

<!-- end -->

# About

This repository contains a self contained µService utilizing the Mozilla SSH Scanner for the secureCodeBox project. To learn more about the ssh_scan scanner itself visit [wpscan.org] or [wpscan.io].

## ssh_scan parameters

To hand over supported parameters through api usage, you can set following attributes:

```json
[
  {
    "name": "some Name",
    "context": "some Context",
    "target": {
      "name": "targetName",
      "location": "http://your-target.com/",
      "attributes": {
        "SSH_TIMEOUT_SECONDS": "[seconds]",
        "SSH_POLICY_FILE": "[filepath/cutsom-policy-file]"
      }
    }
  }
]
``` 
## Example
Example configuration:

```json
[
  {
    "name": "ssh",
    "context": "Example Test",
    "target": {
      "name": "BodgeIT on OpenShift",
      "location": "bodgeit-scb.cloudapps.iterashift.com",
      "attributes": {}
    }
  }
]
```

Example Output:

```json
{
"findings":[  
        {  
            "id":"15571571-c578-4a22-8416-0c54cd05829c",
            "name":"SSH Compliance",
            "description":"SSH Compliance Information",
            "category":"SSH Service",
            "osi_layer":"NETWORK",
            "severity":"INFORMATIONAL",
            "reference":{  

            },
            "hint":"",
            "location":"52.58.225.89",
            "attributes":{  
                "hostname":"bodgeit-scb.cloudapps.iterashift.com",
                "server_banner":"",
                "ssh_version":"unknown",
                "os_cpe":"o:unknown",
                "ssh_lib_cpe":"a:unknown",
                "compliance_policy":null,
                "compliant":null,
                "grade":null,
                "start_time":"2019-09-11 11:41:48 +0000",
                "end_time":"2019-09-11 11:41:54 +0000",
                "scan_duration_seconds":5.017572203,
                "references":null
            }
        }
    ]
}
```

## Development

### Configuration Options

To configure this service specify the following environment variables:

| Environment Variable       | Value Example |
| -------------------------- | ------------- |
| ENGINE_ADDRESS             | http://engine |
| ENGINE_BASIC_AUTH_USER     | username      |
| ENGINE_BASIC_AUTH_PASSWORD | 123456        |

### Local setup

1. Clone the repository
2. You might need to install some dependencies `gem install sinatra rest-client`
3. Run locally `ruby src/main.rb`

### Test

To run the testsuite run:

`rake test`

## Build with docker

To build the docker container run:

`docker build -t IMAGE_NAME:LABEL .`

[![Build Status](https://travis-ci.com/secureCodeBox/scanner-infrastructure-ssh.svg?branch=master)](https://travis-ci.com/secureCodeBox/scanner-infrastructure-ssh)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![GitHub release](https://img.shields.io/github/release/secureCodeBox/scanner-infrastructure-ssh.svg)](https://github.com/secureCodeBox/scanner-infrastructure-ssh/releases/latest)


[ssh_scan]: https://github.com/mozilla/ssh_scan
