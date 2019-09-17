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

  `pageSize`: Maximum number of records to return for container and image lists. Default value is 50, maximum is 10000.

  `exitOnError`: Boolean. If set to *True* script will exit on failed API calls during script. If *False*, script will attempt to gracefully continue.

### Qualys API Username and Password
This script is configured to read the Qualys User name and Password from OS Environment Variables:
  `QUALYS_API_USERNAME`: Qualys API Username

  `QUALYS_API_PASSWORD`: Qualys API Password

These can be set on a mac/linux system with commands such as:
```
export QUALYS_API_USERNAME=frank
export QUALYS_API_USERNAME=frankspassword
```

*note*: We recommend you consider rammifications of leaving credentials in environment variables or shell history. Potential improvements to this script would include reading these credentials from more secure locations.

## Script Requirements
This script is tested on Python 3.

This script requires the following PIP modules to run:
  requests, datetime, pyyaml

These modules can be installed with:
```
pip install -r requirements.txt
```

You may wish to use a [python virtual environment](https://docs.python.org/3/library/venv.html) as to not pollute your host system.

## Debug
Debug file for script run, located in `debug` folder with time/date stamp per line. To disable debug, comment out all lines containing `debug` in the script.

# License
*THIS SCRIPT IS PROVIDED TO YOU "AS IS." TO THE EXTENT PERMITTED BY LAW, QUALYS HEREBY DISCLAIMS ALL WARRANTIES AND LIABILITY FOR THE PROVISION OR USE OF THIS SCRIPT. IN NO EVENT SHALL THESE SCRIPTS BE DEEMED TO BE CLOUD SERVICES AS PROVIDED BY QUALYS*

