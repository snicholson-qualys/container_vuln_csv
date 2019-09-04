# License
*THIS SCRIPT IS PROVIDED TO YOU "AS IS." TO THE EXTENT PERMITTED BY LAW, QUALYS HEREBY DISCLAIMS ALL WARRANTIES AND LIABILITY FOR THE PROVISION OR USE OF THIS SCRIPT. IN NO EVENT SHALL THESE SCRIPTS BE DEEMED TO BE CLOUD SERVICES AS PROVIDED BY QUALYS*

# Image and Container Vulnerability CSV creation

This is an example script on creating two CSV files from the Qualys Container Security API for both images and containers respectively.
This script is provided with no warrantee and is provided as an example on how to accomplish making these files in Python 2.7.x

*Info* : Python script creates CSV files for vulnerability data from Qualys Cloud Security w.r.t details provided in "./config.yml".
       Script debug info will be logged in ./debug/debug_file.txt

CSV File Info
*Vulnerability Image Report headers*
> Registry,Repository,ImageID,Tag,Hostname,Vulnerabiltiy ID,Severity,CVE Number,Published Date,Description,Patch Available

*Vulnerability Container Report headers*
>Registry,Repository,ImageID,Tag,Container,Hostname,Vulnerabiltiy ID,Severity,CVE Number,Published Date,Description,Patch Available

#Qualys API Username and Password
This script is configured to read the Qualys User name and Password from OS Environment Variables
QUALYS_API_USERNAME = Qualys API Username
QUALYS_API_PASSWORD = Base64 encoded Password

> QUALYS_API_USERNAME stores the Qualys API User Name

> QUALYS_API_PASSWORD stores the base64 encoded password for Qualys API
to encode the password using base64 encoding execute the following command substituting the API Account Password for "APIpassword" - make sure the password is in '' or ""

export $QUALYS_API_PASSWORD = `echo -n "APIpassword" | base64`


# Script configuration
*config.yml*
Provide script configuration information for vulnerability severity ratings and Qualys API URL

  vulnerabilities_to_report: string value of severity ratings to include (**acceptable entries 54321, 5432, 543, 54, or 5**)
  apiURL: "Qualys API URL base (https:// - > .com, no trailing '/')"

# Script Requirements
This script is written in Python 2.7.x (X > 10)
This script requires the following PIP modules to run
Modules: sys, requests, datetime, os, time, pyyaml, json, base64

Example Python module install
MAC/Linux "pip install requests"
Windows "python -m pip install requests"

# Debug
Debug file for script run, located in ./debug folder with time/date stamp per line. To disable debug, comment out all lines containing "debug"
