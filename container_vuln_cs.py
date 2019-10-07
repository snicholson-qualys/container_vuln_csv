#!/usr/bin/env python
#
# Author: Sean Nicholson
# Purpose: To iterate the Container Security API and export a CSV of image and container vulns
# version: 1.1.2
# date: 10.07.2019
# 07.23.2019 - Added Loader=yaml.SafeLoader to address yaml warning
# 09.04.2019 - Changed API U/P to read from env variables instead of config file
# 09.12.2019 - v1.1 Added some logging
# 09.27.2019 - v1.1.1 Added threading, error handling, and multiple performance improvements
# 10.07.2019 - v1.1.2 Add software package information to report softwarePackage, currentVersion, fixVersion
#              added --software argument to create report with one row per vuln software package, per image/container

from __future__ import print_function
from builtins import str
import sys, requests, datetime, os, time, logging, csv
import yaml
import json
import base64
import logging.config
import math
import concurrent.futures
import argparse


# setup_http_session sets up global http session variable for HTTP connection sharing
def setup_http_session():
    global httpSession

    httpSession = requests.Session()

# setup_credentials builds HTTP auth string and base64 encodes it to minimize recalculation
def setup_credentials(username, password):
    global httpCredentials

    usrPass = str(username)+':'+str(password)
    usrPassBytes = bytes(usrPass, "utf-8")
    httpCredentials = base64.b64encode(usrPassBytes).decode("utf-8")

def setup_logging(default_path='./config/logging.yml',default_level=logging.INFO,env_key='LOG_CFG'):
    """Setup logging configuration"""
    if not os.path.exists("log"):
        os.makedirs("log")
    path = default_path
    value = os.getenv(env_key, None)
    if value:
        path = value
    if os.path.exists(path):
        with open(path, 'rt') as f:
            config = yaml.safe_load(f.read())
        logging.config.dictConfig(config)
    else:
        logging.basicConfig(level=default_level)


# Called to read in ./config.yml
def config():
    with open('config.yml', 'r') as config_settings:
        config_info = yaml.load(config_settings, Loader=yaml.SafeLoader)
        try:
            username = os.environ["QUALYS_API_USERNAME"]
            #password = base64.b64decode(os.environ["QUALYS_API_PASSWORD"])
            password = os.environ["QUALYS_API_PASSWORD"]
        except KeyError as e:
            logger.critical("Critical Env Variable Key Error - missing configuration item {0}".format(str(e)))
            logger.critical("Please review README for required configuration to run script")
            sys.exit(1)
        try:
            vuln_severity = str(config_info['defaults']['vulnerabilities_to_report']).rstrip()
            threadCount = str(config_info['defaults']['threadCount']).rstrip()
            imageReportHeaders = config_info['defaults']['imageReportHeaders']
            containerReportHeaders = config_info['defaults']['containerReportHeaders']
            URL = str(config_info['defaults']['apiURL']).rstrip()
            if "pageSize" in config_info['defaults']:
                pageSize = config_info['defaults']['pageSize']
            else:
                pageSize = 50

            if "exitOnError" in config_info['defaults']:
                exitOnError = config_info['defaults']['exitOnError']
            else:
                exitOnError = True
        except KeyError as e:
            logger.critical("Critical ./config.yml Key Error - missing configuration item {0}".format(str(e)))
            logger.critical("Please review README for required configuration to run script")
            sys.exit(1)
        if URL == "<QUALYS_API_URL>":
            logger.critical("Critical ./config.yml Key Error - missing configuration item Qualys API URL")
            logger.critical("Please check for https://www.qualys.com/docs/qualys-container-security-api-guide.pdf for the correct Qualys API URL for your subscription")
            logger.critical("Please review README for required configuration to run script")
            sys.exit(1)
        if username == '' or password == '' or URL == '':
            logger.critical("Config information in ./config.yml not configured correctly. Exiting...")
            sys.exit(1)
    return username, password, vuln_severity, URL, pageSize, exitOnError, threadCount, imageReportHeaders, containerReportHeaders

# Get call for API queries to return json data and status code
def Get_Call(username,password,URL):
    global httpSession
    global httpCredentials

    headers = {
        'Accept': '*/*',
        'content-type': 'application/json',
        'Authorization': "Basic %s" % httpCredentials
    }

    r = httpSession.get(URL, headers=headers, verify=True)
    logger.debug("Repsonse code for GET to {0} - Response Code {1}".format(str(URL),str(r.status_code)))
    logger.debug("API Data for Response \n {}".format(str(r.text[:100])))
    image_list_json = json.loads(r.text)

    return image_list_json,r.status_code

#write CSV Report
def writeCsv(findings, reportType, csvHeaders):
    if not os.path.exists("reports"):
            os.makedirs("reports")
    out_file = "reports/Vulnerability_" + str(reportType) + "_Report_" + time.strftime("%Y%m%d-%H%M%S") + ".csv"
    ofile = open(out_file, "w")
    writer = csv.DictWriter(ofile, fieldnames=csvHeaders)
    writer.writeheader()
    row = {}
    for item in findings:
        for header in csvHeaders:
            if str(header) in item.keys():
                row[header] = item[header]
            else:
                logger.error("CSV Column Header not in finding keys -- {}".format(str(header)))
                logger.error("Please update csvHeaders with API Response key values only".format(str(header)))

        writer.writerow(row)
    logger.debug("Done writing data to CSV for: {}".format(str(csvHeaders)))
    ofile.close()


# API Call to /csapi/v1.1/images to get list of all images
def image_vuln_csv():

    username, password, vuln_rating, URL, pageSize, exitOnError, threadCount, imageReportHeaders, containerReportHeaders = config()
    setup_http_session()
    setup_credentials(username, password)
    pageNo = 0
    logger.debug("Starting image_vuln_csv")
    logger.debug('------------------------------Begin Image Debug Log {0} --------------------------------\n'.format(datetime.datetime.utcnow()))


    counter = 0

    full_image_list = []
    allResults = False
    while allResults == False:
        image_list_pull_URL = URL + "/csapi/v1.1/images?pageSize=" + str(pageSize) + "&pageNo={}".format(str(pageNo))
        logger.debug("Image Pull URL {}".format(image_list_pull_URL))
        logger.debug('{0} - Calling {1} \n'.format(datetime.datetime.utcnow(), image_list_pull_URL))
        counter = 0
        while counter < 5:

            image_list_data, image_list_status = Get_Call(username,password,image_list_pull_URL)
            logger.debug("int(image_list_data[\'count\'] {0} // pageSize {1}) = {2}".format(str(image_list_data['count']), str(pageSize), str(int(image_list_data['count'] // pageSize))))
            #logger.debug("Called {0} and got reponse code {1} with data: \n {2}".format(str(image_list_pull_URL),str(image_list_status),str(image_list_data)))
            logger.debug("image list \n {}".format(list(image_list_data)))
            logger.debug('{0} - API URL {1} response status: {2} \n'.format(datetime.datetime.utcnow(), image_list_pull_URL, image_list_status))
            if image_list_status != 200:
                logger.debug('{0} - API URL {1} error details: {2} \n'.format(datetime.datetime.utcnow(),image_list_pull_URL, image_list_data))
            if image_list_status == 200:
                logger.debug("pageNo {0} < int(image_list_data[\'count\'] {1} // pageSize {2}) = {3}".format(str(pageNo), str(image_list_data['count']), str(pageSize), str(int(image_list_data['count'] // pageSize))))
                pageNo +=1
                full_image_list.extend(image_list_data['data'])

                if pageNo > int(image_list_data['count'] // pageSize):
                    allResults = True
                counter = 6

            else:
                logger.debug('{0} - API URL {1} error encountered retry number {2}\n'.format(datetime.datetime.utcnow(),image_list_pull_URL, counter))
                logger.debug("Not feeling well...sleeping 10 secs\n")
                logger.warning("Not feeling well - sleeping 10 secs")
                time.sleep(10)
                counter += 1
                if counter == 5:
                    logger.debug('{0} - API URL {1} retry limit exceeded\n'.format(datetime.datetime.utcnow(),image_list_pull_URL))
                    # Not gating this first exit() on exitOnError. If this doesn't succeed, no reason to go further.
                    sys.exit(1)

    logger.debug('{0} - Image list count: {1} \n'.format(datetime.datetime.utcnow(), str(len(full_image_list))))
    if len(full_image_list) > 0:
        imageDataShare = imageDetails(full_image_list)
    return imageDataShare

# Parse image list for Images with Vulns
def imageDetails(full_image_list):
    reportData=[]
    username, password, vuln_rating, URL, pageSize, exitOnError, threadCount, imageReportHeaders, containerReportHeaders = config()
    setup_http_session()
    setup_credentials(username, password)
    imageWithVulns=[]
    for image in full_image_list:
        image_detail_list = ''
        image_details_url_status = ''
        image_details_url = ''
        if vuln_rating == '54321':
            if image['vulnerabilities']['severity1Count'] > 0 or image['vulnerabilities']['severity2Count'] > 0 or image['vulnerabilities']['severity3Count'] > 0 or image['vulnerabilities']['severity4Count'] > 0 or image['vulnerabilities']['severity5Count'] > 0:
                image_details_url = URL + "/csapi/v1.1/images/" + str(image['imageId'])
        elif vuln_rating == '5432':
            if image['vulnerabilities']['severity2Count'] > 0 or image['vulnerabilities']['severity3Count'] > 0 or image['vulnerabilities']['severity4Count'] > 0 or image['vulnerabilities']['severity5Count'] > 0:
                image_details_url = URL + "/csapi/v1.1/images/" + str(image['imageId'])
        elif vuln_rating == '543':
            if image['vulnerabilities']['severity3Count'] > 0 or image['vulnerabilities']['severity4Count'] > 0 or image['vulnerabilities']['severity5Count'] > 0:
                image_details_url = URL + "/csapi/v1.1/images/" + str(image['imageId'])
        elif vuln_rating == '54':
            if image['vulnerabilities']['severity4Count'] > 0 or image['vulnerabilities']['severity5Count'] > 0:
                image_details_url = URL + "/csapi/v1.1/images/" + str(image['imageId'])
        elif vuln_rating == '5':
            if image['vulnerabilities']['severity5Count'] > 0:
                image_details_url = URL + "/csapi/v1.1/images/" + str(image['imageId'])
        else:
            logger.warning('{0} - **** Exception - no vulnerbility inclusion limit set \n'.format(datetime.datetime.utcnow()))
            logger.debug('------------------------------End Image Debug Log {0} --------------------------------\n'.format(datetime.datetime.utcnow()))
            sys.exit(1)
        vuln_counts = image['vulnerabilities']['severity5Count'] + image['vulnerabilities']['severity4Count'] + image['vulnerabilities']['severity3Count'] + image['vulnerabilities']['severity2Count'] + image['vulnerabilities']['severity1Count']
        if image_details_url and vuln_counts >= 1 and image_details_url not in imageWithVulns:
            imageWithVulns.append(str(image_details_url))
        else:
            logger.debug('{0} - *** {1} *** - *** No image vulnerabilities reported \n'.format(datetime.datetime.utcnow(), str(image['imageId'])))
    if len(imageWithVulns) > 0:
        logger.debug("Length of imageWithVulns = {}".format(len(imageWithVulns)))
        #input("Press Enter to continue...")
        reportData = {"report": [], "imageDataShare": {}}

        if args.thread:
            with concurrent.futures.ThreadPoolExecutor(max_workers=int(threadCount)) as executor:
                future_to_url = {executor.submit(imageVulns, url): url for url in imageWithVulns}
                for future in concurrent.futures.as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        data = future.result()
                        logger.debug("data is type {}".format(type(data)))
                        logger.debug("data is length {}".format(len(data)))
                        if len(data) > 0:
                            logger.debug("data is \n {}".format(str(data)[:100]))
                            reportData['report'].extend(data['report'])
                            reportData['imageDataShare'].update(data['imageDataShare'])
                    except Exception as exc:
                        print('%r generated an exception: %s' % (url, exc))
                    else:
                        #reportDataTrial.extend(data)
                        logger.debug("data is type {}".format(type(data)))
                        logger.debug("data is \n {}".format(str(data)[:100]))
        else:
            ### Thread troubleshooting single thread linear iteration of containers
            for imageURL in imageWithVuln:
                data = containerVulnDetails(imageURL)
                reportData.extend(data)


        logger.debug("reportData[report] is type {}".format(type(reportData['report'])))
        logger.debug("reportData[report] is length = {}".format(len(reportData['report'])))
        #input("Press Enter to continue...")
        logger.debug("reportData[imageDataShare] is type {}".format(type(reportData['imageDataShare'])))
        logger.debug("reportData[imageDataShare] is length = {}".format(len(reportData['imageDataShare'])))
        #input("Press Enter to continue...")
        logger.info("*** Threading Report Data is complete *** \n\n\n\n {}".format(str(reportData['report'])[:10000]))
        #input("Press Enter to continue...")

        #input("Press Enter to continue...")
        writeCsv(reportData['report'], "Image", imageReportHeaders)

    return reportData['imageDataShare']

# API Call to /csapi/v1.1/images/imageId to get Image and Vuln details
def imageVulns(image_details_url):
    imageReport = {"report": [], "imageDataShare": {}}
    username, password, vuln_rating, URL, pageSize, exitOnError, threadCount, imageReportHeaders, containerReportHeaders = config()
    setup_http_session()
    setup_credentials(username, password)

    if image_details_url:
        counter = 0
        while counter < 5:

            image_detail_list, image_details_url_status = Get_Call(username,password,image_details_url)
            logger.debug('{0} - API URL {1} response status: {2} \n'.format(datetime.datetime.utcnow(),image_details_url, image_details_url_status))
            if image_details_url_status != 200:
                logger.debug('{0} - API URL {1} error details: {2} \n'.format(datetime.datetime.utcnow(),image_details_url, image_detail_list))
            if image_details_url_status == 200:
                counter = 6

            else:
                logger.debug('{0} - API URL {1} error encountered retry number {2}\n'.format(datetime.datetime.utcnow(),image_details_url, counter))
                logger.debug("Not feeling well...sleeping 10 secs\n")
                print("Not feeling well - sleeping 10 secs")
                time.sleep(10)
                counter += 1
                if counter == 5:
                    logger.debug('{0} - API URL {1} retry limit exceeded\n'.format(datetime.datetime.utcnow(),image_details_url))
                    if exitOnError:
                        logger.debug('{0} - Exiting\n'.format(datetime.datetime.utcnow()))
                        sys.exit(1)
                    else:
                        logger.debug('{0} - Continuing\n'.format(datetime.datetime.utcnow()))
                        continue


        registry = ''
        tags = ''
        repository = ''
        if image_detail_list['repo']:
            repos = image_detail_list['repo']
            for repo in repos:
                if repo['registry'] not in registry:
                    registry += repo['registry'] + ";"
                if repo['tag']:
                    if repo['tag'] not in tags:
                        tags += repo['tag'] + ";"
                if repo['repository'] not in repository:
                    repository += repo['repository'] + ";"
        try:
            if image_detail_list['host']:
                hostname = ""
                for host in image_detail_list['host']:
                    if host['hostname'] not in hostname:
                        hostname += (host['hostname'] + ";")

            else:
                hostname = ""
        except KeyError:
            hostname = ""
            pass
        imageReport['imageDataShare'].update({image_detail_list['imageId']: {'registry': str(registry), 'repository': str(repository)}})
        for vulns in image_detail_list['vulnerabilities']:
            if vulns['patchAvailable']:
                patchable = vulns['patchAvailable']
            else:
                patchable = 'False'
            #print vulns['firstFound']
            #print vulns['firstFound'][0:10]
            firstFound = vulns['firstFound'][0:10]
            #print datetime.datetime.utcfromtimestamp(float(firstFound)).strftime('%Y-%m-%d %H:%M:%S')
            firstDate = str(datetime.datetime.utcfromtimestamp(float(firstFound)).strftime('%Y-%m-%d %H:%M:%S'))
            #print firstDate
            row = {}
            softwarePackage = []
            currentVersion = []
            fixVersion = []
            cves = []
            if args.software:
                if vulns['cveids']:
                    for cve in vulns['cveids']:
                        cves.append(str(cve))
                    logger.debug("CVEs found: {}".format(str(cves)))
                if vulns['software']:
                    for software in vulns['software']:
                        row.update({"registry": registry, "repository": repository, "imageId": image_detail_list['imageId'], "tag": tags, "hostname": hostname, "qid": vulns['qid'], "severity": vulns['severity'], "cveids": str(cves).strip('[]'), "firstFound": firstDate, "title": vulns['title'], "typeDetected":vulns['typeDetected'],"patchAvailable": str(patchable), 'softwarePackage': software['name'], 'currentVersion': software['version'], 'fixVersion': software['fixVersion']})
                        imageReport['report'].append(dict(row))
                else:
                    row.update({"registry": registry, "repository": repository, "imageId": image_detail_list['imageId'], "tag": tags, "hostname": hostname, "qid": vulns['qid'], "severity": vulns['severity'], "cveids": str(cves).strip('[]'), "firstFound": firstDate, "title": vulns['title'], "typeDetected":vulns['typeDetected'],"patchAvailable": str(patchable), 'softwarePackage': '', 'currentVersion': '', 'fixVersion': ''})
                    imageReport['report'].append(dict(row))
            else:
                if vulns['software']:
                    for software in vulns['software']:
                        softwarePackage.append(str(software['name']))
                        currentVersion.append(str(software['version']))
                        fixVersion.append(str(software['fixVersion']))
                if vulns['cveids']:
                    for cve in vulns['cveids']:
                        row.update({"registry": registry, "repository": repository, "imageId": image_detail_list['imageId'], "tag": tags, "hostname": hostname, "qid": vulns['qid'], "severity": vulns['severity'], "cveids": str(cve), "firstFound": firstDate, "title": vulns['title'], "typeDetected":vulns['typeDetected'],"patchAvailable": str(patchable), 'softwarePackage': str(softwarePackage).strip('[]'), 'currentVersion': str(currentVersion).strip('[]'), 'fixVersion': str(fixVersion).strip('[]')})
                        imageReport['report'].append(dict(row))
                else:
                    row.update({"registry": registry, "repository": repository, "imageId": image_detail_list['imageId'], "tag": tags, "hostname": hostname, "qid": vulns['qid'], "severity": vulns['severity'], "cveids": "", "firstFound": firstDate, "title": vulns['title'], "typeDetected":vulns['typeDetected'],"patchAvailable": str(patchable), 'softwarePackage': str(softwarePackage).strip('[]'), 'currentVersion': str(currentVersion).strip('[]'), 'fixVersion': str(fixVersion).strip('[]')})
                    imageReport['report'].append(dict(row))

    return imageReport

    logger.debug('------------------------------End Image Debug Log {0} --------------------------------\n'.format(datetime.datetime.utcnow()))


# Get API call for /csapi/v1.1/containers/ to pull list of all containers
def container_vuln_csv(imageShareData):
    username, password, vuln_rating, URL, pageSize, exitOnError, threadCount, imageReportHeaders, containerReportHeaders = config()
    setup_http_session()
    setup_credentials(username, password)
    pageNo=1
    containersWithVuln = []
    full_container_list = []
    containerList = []
    logger.debug('------------------------------Begin Container Debug Log {0} --------------------------------\n'.format(datetime.datetime.utcnow()))
    counter = 0
    allResults = False
    while allResults == False:
        container_list_pull_URL = URL + "/csapi/v1.1/containers?pageSize=" + str(pageSize) + "&pageNo={}".format(str(pageNo))
        logger.debug("Container Pull URL {}".format(container_list_pull_URL))
        logger.debug('{0} - Calling {1} \n'.format(datetime.datetime.utcnow(), container_list_pull_URL))
        counter = 0
        while counter <= 5:
            container_list_data, container_list_status = Get_Call(username,password,container_list_pull_URL)
            logger.debug('{0} - API URL {1} response status: {2} \n'.format(datetime.datetime.utcnow(), container_list_pull_URL, container_list_status))
            if container_list_status != 200:
                logger.debug('{0} - API URL {1} error details: {2} \n'.format(datetime.datetime.utcnow(),container_list_pull_URL, container_list_data))
            if container_list_status == 200:
                full_container_list.extend(container_list_data['data'])
                logger.debug("pageNo {0} <= int(image_list_data[\'count\'] {1} // pageSize {2}) = {3}".format(str(pageNo), str(container_list_data['count']), str(pageSize), str(int(container_list_data['count'] // pageSize))))
                pageNo +=1

                if pageNo >= (int(container_list_data['count'] // pageSize) + 1):
                    allResults = True
                counter = 6

            else:
                logger.error('{0} - API URL {1} error encountered retry number {2}\n'.format(datetime.datetime.utcnow(),container_list_pull_URL, counter))
                logger.warning("Not feeling well...sleeping 10 secs\n")
                logger.info("Not feeling well - sleeping 10 secs")
                time.sleep(10)
                counter += 1
                if counter == 5:
                    logger.error('{0} - API URL {1} retry limit exceeded\n'.format(datetime.datetime.utcnow(),container_list_pull_URL))
                    # Not gating this first exit() on exitOnError. If this doesn't succeed, no reason to go further.
                    sys.exit(1)

    logger.debug('{0} - Container list count: {1} \n'.format(datetime.datetime.utcnow(), len(full_container_list)))
    testData = []

    if len(full_container_list) > 0:
        if not os.path.exists("reports"):
            os.makedirs("reports")
        containerApiError = []
        #out_file = "reports/Vulnerability_Container_Report_"+ time.strftime("%Y%m%d-%H%M%S") + ".csv"
        #ofile  = open(out_file, "w")
        #ofile.write("Registry,Repository,ImageID,Container,Container Name,Hostname,IP,Vulnerabiltiy ID,Severity,CVE Number,First Found Date,Description,Type,Patch Available\n")
        for container in full_container_list:
            container_detail_list = ''
            container_details_url_status = ''
            container_details_url = ''
            containerList.append(str(container['containerId']))
            if str(container['containerId']) == 'None':
                containerApiError.append(container)
            else:
                if vuln_rating == '54321':
                    if container['vulnerabilities']['severity1Count'] > 0 or container['vulnerabilities']['severity2Count'] > 0 or container['vulnerabilities']['severity3Count'] > 0 or container['vulnerabilities']['severity4Count'] > 0 or container['vulnerabilities']['severity5Count'] > 0:
                        container_details_url = URL + "/csapi/v1.1/containers/" + str(container['containerId'])
                        testData.append(str(container['containerId']))
                elif vuln_rating == '5432':
                    if container['vulnerabilities']['severity2Count'] > 0 or container['vulnerabilities']['severity3Count'] > 0 or container['vulnerabilities']['severity4Count'] > 0 or container['vulnerabilities']['severity5Count'] > 0:
                        container_details_url = URL + "/csapi/v1.1/containers/" + str(container['containerId'])
                        testData.append(str(container['containerId']))
                elif vuln_rating == '543':
                    if container['vulnerabilities']['severity3Count'] > 0 or container['vulnerabilities']['severity4Count'] > 0 or container['vulnerabilities']['severity5Count'] > 0:
                        container_details_url = URL + "/csapi/v1.1/containers/" + str(container['containerId'])
                        testData.append(str(container['containerId']))
                elif vuln_rating == '54':
                    if container['vulnerabilities']['severity4Count'] > 0 or container['vulnerabilities']['severity5Count'] > 0:
                        container_details_url = URL + "/csapi/v1.1/containers/" + str(container['containerId'])
                        testData.append(str(container['containerId']))
                elif vuln_rating == '5':
                    if container['vulnerabilities']['severity5Count'] > 0:
                        container_details_url = URL + "/csapi/v1.1/containers/" + str(container['containerId'])
                        testData.append(str(container['containerId']))
                else:
                    logger.error('{0} - **** Exception - no vulnerbility inclusion limit set \n'.format(datetime.datetime.utcnow()))
                    logger.debug('------------------------------Container End Debug Log {0} --------------------------------\n'.format(datetime.datetime.utcnow()))
                    sys.exit(1)

            if container_details_url and container_details_url not in containersWithVuln and "None" not in container_details_url:
                containersWithVuln.append(container_details_url)
            container_vuln_counts = container['vulnerabilities']['severity5Count'] + container['vulnerabilities']['severity4Count'] + container['vulnerabilities']['severity3Count'] + container['vulnerabilities']['severity2Count'] + container['vulnerabilities']['severity1Count']
            #print container_vuln_counts
        reportData = []

        #Debug Logging Area
        logger.debug("Full Container containerId List")
        logger.debug("Full containerId List \n\n\n {} \n\n\n\n".format(str(containerList)))
        logger.debug("Full containerId List Length \n\n\n {} \n\n\n\n".format(len(containerList)))
        logger.debug("Vulnerable container containerId List")
        logger.debug("containerId List \n\n\n {} \n\n\n\n".format(str(testData)))
        logger.debug("Container API Error list")
        logger.debug("Container Error List \n\n\n {} \n\n\n\n".format(str(containerApiError)))
        logger.debug("Container URL List \n\n\n {} \n\n\n\n".format(str(containersWithVuln)))
        logger.debug("Container URL List Length {}".format(len(containersWithVuln)))

        if args.thread:
            with concurrent.futures.ThreadPoolExecutor(max_workers=int(threadCount)) as executor:
                future_to_url = {executor.submit(containerVulnDetails, url, imageShareData): url for url in containersWithVuln}
                for future in concurrent.futures.as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        data = future.result()
                        logger.debug("data is type {}".format(type(data)))
                        logger.debug("data is length {}".format(len(data)))
                        if len(data) > 0:
                            logger.debug("data is \n {}".format(str(data)[:100]))
                            reportData.extend(data)
                    except Exception as exc:
                        print('%r generated an exception: %s' % (url, exc))
                    else:
                        logger.debug("data is type {}".format(type(data)))
                        logger.debug("data is \n {}".format(str(data)[:100]))


        else:
            ### Thread troubleshooting single thread linear iteration of containers
            for containerURL in containersWithVuln:
                data = containerVulnDetails(containerURL,imageShareData)
                reportData.extend(data)
        logger.debug("reportData is type {}".format(type(reportData)))
        logger.debug("reportData is length = {}".format(len(reportData)))
        logger.debug("*** Threading Report Data is complete *** \n\n\n\n {}".format(str(reportData)[:1000]))
        writeCsv(reportData, "Container", containerReportHeaders)

# Get API call for container details for vuln info parsing /csapi/v1.1/containers/containerId
def containerVulnDetails(containerWithVuln, imageShareData):
    username, password, vuln_rating, URL, pageSize, exitOnError, threadCount, imageReportHeaders, containerReportHeaders = config()
    setup_http_session()
    setup_credentials(username, password)
    #image_details_url = ""


    repository = ''
    registry = ''
    counter = 0
    while counter <= 5:
        #container_detail_list, container_details_url_status = Get_Call(username,password,container_details_url)
        container_detail_list, container_details_url_status = Get_Call(username,password,containerWithVuln)
        logger.debug('{0} - API URL {1} response status: {2} \n'.format(datetime.datetime.utcnow(),containerWithVuln,container_details_url_status))
        if container_details_url_status == 200:
            counter = 6
        else:
            logger.debug('{0} - API URL {1} error details: {2} \n'.format(datetime.datetime.utcnow(),containerWithVuln, container_detail_list))
            logger.error('{0} - API URL {1} error encountered retry number {2}\n'.format(datetime.datetime.utcnow(),containerWithVuln, counter))
            logger.info("Not feeling well - sleeping 10 secs")
            time.sleep(10)
            counter += 1
            if counter == 5:
                logger.error('{0} - API URL {1} retry limit exceeded\n'.format(datetime.datetime.utcnow(),containerWithVuln))
                if exitOnError:
                    logger.critical('{0} - Exiting\n'.format(datetime.datetime.utcnow()))
                    sys.exit(1)
                else:
                    logger.warning('{0} - Continuing\n'.format(datetime.datetime.utcnow()))
                    continue

    logger.debug("container_detail_list[imageId] = {}".format(str(container_detail_list['imageId'])))
    logger.debug("Variable passed to containerVulnDetails imageShareData = {}".format(str(imageShareData)[:200]))
    logger.debug("imageShareData[{0}] type is {1}".format(str(container_detail_list['imageId']), type(imageShareData[str(container_detail_list['imageId'])])))
    if str(container_detail_list['imageId']) in imageShareData.keys():
        logger.debug("*** Container imageId is in imageShareData --- {}".format(str(imageShareData[str(container_detail_list['imageId'])])))
        logger.debug("str(imageShareData[str(container_detail_list['imageId'])]['registry']) == {}".format(str(imageShareData[str(container_detail_list['imageId'])]['registry'])))
        logger.debug("str(imageShareData[str(container_detail_list['imageId'])]['repository']) == {}".format(str(imageShareData[str(container_detail_list['imageId'])]['repository'])))

        logger.debug("imageShareData = {}".format(str(imageShareData)[:1000]))

        registry = str(imageShareData[str(container_detail_list['imageId'])]['registry'])
        repository = str(imageShareData[str(container_detail_list['imageId'])]['repository'])

    logger.debug("Container Image Registry = {}".format(registry))
    logger.debug("Container Image Repository = {}".format(repository))

    if container_detail_list['host']:
        hostname = container_detail_list['host']['hostname']
    else:
        hostname = ""
    containerVulnData = []

    #Iterate through Vulnerabilities

    if container_detail_list['vulnerabilities']:
        for vulns in container_detail_list['vulnerabilities']:
            if vulns['patchAvailable']:
                patchable = vulns['patchAvailable']
            else:
                patchable = 'False'

            firstFound = vulns['firstFound'][0:10]
            firstDate = str(datetime.datetime.utcfromtimestamp(float(firstFound)).strftime('%Y-%m-%d %H:%M:%S'))
            softwarePackage = []
            currentVersion = []
            fixVersion = []
            cves = []
            if args.software:
                if vulns['cveids']:
                    for cve in vulns['cveids']:
                        cves.append(str(cve))
                    logger.debug("CVEs found: {}".format(str(cves)))
                if vulns['software']:
                    for software in vulns['software']:
                        row = {"registry": registry, "repository": repository, "imageId": container_detail_list['imageId'], "containerId": container_detail_list['containerId'], "name": container_detail_list['name'], "hostname": hostname, "ipAddress": container_detail_list['host']['ipAddress'], "qid": vulns['qid'], "severity": vulns['severity'], "cves": str(cves).strip('[]'), "firstFound": firstDate, "title": vulns['title'], "typeDetected": vulns['typeDetected'], "patchAvailable": str(patchable), 'softwarePackage': str(software['name']), 'currentVersion': str(software['version']), 'fixVersion': str(software['fixVersion'])}
                        containerVulnData.append(dict(row))
                else:
                    row = {"registry": registry, "repository": repository, "imageId": container_detail_list['imageId'], "containerId": container_detail_list['containerId'], "name": container_detail_list['name'], "hostname": hostname, "ipAddress": container_detail_list['host']['ipAddress'], "qid": vulns['qid'], "severity": vulns['severity'], "cves": str(cves).strip('[]'), "firstFound": firstDate, "title": vulns['title'], "typeDetected": vulns['typeDetected'], "patchAvailable": str(patchable), 'softwarePackage': '', 'currentVersion': '', 'fixVersion': ''}
                    containerVulnData.append(dict(row))

            else:
                if vulns['software']:
                    for software in vulns['software']:
                        softwarePackage.append(str(software['name']))
                        currentVersion.append(str(software['version']))
                        fixVersion.append(str(software['fixVersion']))
                if vulns['cveids']:
                    for cve in vulns['cveids']:
                        # old code for previous version writing out to CSV directly
                        #row = "{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13}\n".format(registry,repository,container['imageId'],container['containerId'],container['name'],hostname,container['host']['ipAddress'],vulns['qid'],vulns['severity'],str(cves),firstDate,vulns['title'],vulns['typeDetected'],str(patchable))
                        row = {"registry": registry, "repository": repository, "imageId": container_detail_list['imageId'], "containerId": container_detail_list['containerId'], "name": container_detail_list['name'], "hostname": hostname, "ipAddress": container_detail_list['host']['ipAddress'], "qid": vulns['qid'], "severity": vulns['severity'], "cves": str(cve), "firstFound": firstDate, "title": vulns['title'], "typeDetected": vulns['typeDetected'], "patchAvailable": str(patchable), 'softwarePackage': str(softwarePackage).strip('[]'), 'currentVersion': str(currentVersion).strip('[]'), 'fixVersion': str(fixVersion).strip('[]') }
                        containerVulnData.append(dict(row))
                        #ofile.write(row)
                else:
                    # old code for previous version writing out to CSV directly
                    #row = "{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13}\n".format(registry,repository,container['imageId'],container['containerId'],container['name'],hostname,container['host']['ipAddress'],vulns['qid'],vulns['severity'],"",firstDate,vulns['title'],vulns['typeDetected'],str(patchable))

                    row = {"registry": registry, "repository": repository, "imageId": container_detail_list['imageId'], "containerId": container_detail_list['containerId'], "name": container_detail_list['name'], "hostname": hostname, "ipAddress": container_detail_list['host']['ipAddress'], "qid": vulns['qid'], "severity": vulns['severity'], "cves": "", "firstFound": firstDate, "title": vulns['title'], "typeDetected": vulns['typeDetected'], "patchAvailable": str(patchable), 'softwarePackage': str(softwarePackage).strip('[]'), 'currentVersion': str(currentVersion).strip('[]'), 'fixVersion': str(fixVersion).strip('[]')}
                    containerVulnData.append(dict(row))
                    #ofile.write(row)
    else:
        logger.info('{0} - *** No container vulnerabilities reported \n'.format(datetime.datetime.utcnow()))
    logger.debug("containerVulnData == \n {}".format(str(containerVulnData)[:100]))
    logger.debug('------------------------------Container End Debug Log {0} --------------------------------\n'.format(datetime.datetime.utcnow()))
    return containerVulnData

parser = argparse.ArgumentParser()
parser.add_argument("--thread", "-t", help="Run report generation via Python ThreadPoolExecutor with number of threads defined in ./config.yml", action="store_true")
parser.add_argument("--software", "-s", help="Create report with row per software package in the CSV report", action="store_true")
args = parser.parse_args()

if __name__ == '__main__':
    setup_logging()
    logger = logging.getLogger(__name__)
    imageShareData = image_vuln_csv()
    container_vuln_csv(imageShareData)
