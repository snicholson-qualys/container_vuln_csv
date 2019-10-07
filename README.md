# Image and Container Vulnerability CSV creation

This is an example script on creating two CSV files from the Qualys Container Security API for both images and containers respectively.

*Info* : Python script creates CSV files for vulnerability data from Qualys Cloud Security w.r.t details provided in `./config.yml`.
       Script debug info will be logged in ./debug/debug_file.txt

CSV File Info
*Vulnerability Image Report headers*
> Registry,Repository,ImageID,Tag,Hostname,Vulnerabiltiy ID,Severity,CVE Number,Published Date,Description,Patch Available

*Vulnerability Container Report headers*
>Registry,Repository,ImageID,Tag,Container,Hostname,Vulnerabiltiy ID,Severity,CVE Number,Published Date,Description,Patch Available

## Configuration
Two configuration settings will need to be made by the user before using this script: Updating the config.yml with appropriate information, and setting API username and password in environment variables.

*config.yml* provides script configuration information for vulnerability severity ratings and Qualys API URL

  `vulnerabilities_to_report`: string value of severity ratings to include (**acceptable entries 54321, 5432, 543, 54, or 5**)

  `apiURL`: Qualys API URL base (https:// - > .com, without a trailing '/'. e.g. `https://qualysapi.qg2.apps.qualys.com` )

  `pageSize`: Maximum number of records to return for container and image lists. Default value is 1000, maximum is 10000.

  `exitOnError`: Boolean. If set to *True* script will exit on failed API calls during script. If *False*, script will attempt to gracefully continue.

  `threadCount`: Thread count, used with --thread. Default value set to 4 - Acceptable Thread values for performance increase [2-8]

  `imageReportHeaders`: Set headers for Image Vuln CSV - Default List set to -- ['registry', 'repository', 'imageId', 'tag', 'hostname', 'severity', 'qid', 'firstFound', 'cveids', 'title', 'typeDetected', 'patchAvailable' ]

  `containerReportHeaders`: Set headers for Container Vuln CSV - Default List set to -- ['registry','registry', 'repository', 'imageId', 'containerId', 'name', 'hostname', 'ipAddress', 'qid', 'severity', 'cves', 'firstFound', 'title', 'typeDetected', 'patchAvailable']

### Qualys API Username and Password
This script is configured to read the Qualys User name and Password from OS Environment Variables:
  `QUALYS_API_USERNAME`: Qualys API Username

  `QUALYS_API_PASSWORD`: Qualys API Password

These can be set on a mac/linux system with commands such as:
```
export QUALYS_API_USERNAME=frank
export QUALYS_API_PASSWORD=frankspassword
```

The Script is configured to read in a base64 encoded password via a base64.decode

*note*: We recommend you consider ramifications of leaving credentials in environment variables or shell history. Potential improvements to this script would include reading these credentials from more secure locations.

## Script Requirements
This script is tested on Python 3.

This script requires the following PIP modules to run:
  requests, datetime, pyyaml

These modules can be installed with:
```
pip install -r requirements.txt
```

You may wish to use a [python virtual environment](https://docs.python.org/3/library/venv.html) as to not pollute your host system.


# Logging
Logging configuration files is located in ./config/logging.yml. To change logging behavior, make changes in this file. For information on Python 3 logging visit https://docs.python.org/3/library/logging.html
Logging configuration
File Handler writes to log/container-vuln-csv.log
Maximum Log size = 10 MB ( logging.yml line 18 - maxBytes: 10485760 # 10MB)
Backup file count = 5 (logging.yml line 19 - backupCount: 5)
Log Level = DEBUG (Change to WARNING or higher for production - logging.yml line 15 - level: INFO)


## Running the script

No threading, serialized iterations, no software package details
>> python3 container_vuln_csv.py

Threading, async processing of list iteration for singular calls to Qualys API for images and containers lists. Must configure ./config.yml['defaults']['threads'] for 2 to 8 threads, default value is 4
>> python3 container_vuln_csv.py --thread

Create report with one row per vulnerable software package per image/container instead of one row per CVE.
>> python3 container_vuln_csv.py --software

# License
*THIS SCRIPT IS PROVIDED TO YOU "AS IS." TO THE EXTENT PERMITTED BY LAW, QUALYS HEREBY DISCLAIMS ALL WARRANTIES AND LIABILITY FOR THE PROVISION OR USE OF THIS SCRIPT. IN NO EVENT SHALL THESE SCRIPTS BE DEEMED TO BE CLOUD SERVICES AS PROVIDED BY QUALYS*
