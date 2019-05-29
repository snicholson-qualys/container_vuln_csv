#
# Author: Sean Nicholson
# Purpose: To iterate the Container Security API and export a CSV of image and container vulns
# version: 1.0.0
# date: 10.1.2018
#
#
#

import sys, requests, datetime, os, time
import yaml
import json
import base64

def config():
    with open('config.yml', 'r') as config_settings:
        config_info = yaml.load(config_settings)
        username = str(config_info['defaults']['username']).rstrip()
        password = str(config_info['defaults']['password']).rstrip()
        vuln_severity = str(config_info['defaults']['vulnerabilities_to_report']).rstrip()
        URL = str(config_info['defaults']['apiURL']).rstrip()
        if username == '' or password == '' or URL == '':
            print "Config information in ./config.yml not configured correctly. Exiting..."
            sys.exit(1)
    return username, password, vuln_severity, URL


def Get_Call(username,password,URL):

    usrPass = str(username)+':'+str(password)
    b64Val = base64.b64encode(usrPass)
    headers = {
        'Accept': '*/*',
        'content-type': 'application/json',
        'Authorization': "Basic %s" % b64Val
    }

    r = requests.get(URL, headers=headers, verify=True)
    #print r.text
    image_list_json = json.loads(r.text)
    return image_list_json,r.status_code

def image_vuln_csv():

    username, password, vuln_rating, URL = config()
    if not os.path.exists("debug"):
        os.makedirs("debug")

    debug_file = open("./debug/debug_file.txt", "a")
    debug_file.write('------------------------------Begin Image Debug Log {0} --------------------------------\n'.format(datetime.datetime.utcnow()))
    image_list_pull_URL = URL + "/csapi/v1.1/images"
    debug_file.write('{0} - Calling {1} \n'.format(datetime.datetime.utcnow(), image_list_pull_URL))
    counter = 0
    while counter < 5:

        image_list, image_list_status = Get_Call(username,password,image_list_pull_URL)
        debug_file.write('{0} - API URL {1} response status: {2} \n'.format(datetime.datetime.utcnow(), image_list_pull_URL, image_list_status))
        if image_list_status != 200:
            debug_file.write('{0} - API URL {1} error details: {2} \n'.format(datetime.datetime.utcnow(),image_list_pull_URL, image_list))
        if image_list_status == 200:
            counter = 6

        else:
            debug_file.write('{0} - API URL {1} error encountered retry number {2}\n'.format(datetime.datetime.utcnow(),image_list_pull_URL, counter))
            debug_file.write("Not feeling well...sleeping 10 secs\n")
            print "Not feeling well - sleeping 10 secs"
            time.sleep(10)
            counter += 1
            if counter == 5:
                debug_file.write('{0} - API URL {1} retry limit exceeded\n'.format(datetime.datetime.utcnow(),image_list_pull_URL))
                sys.exit(1)

    #print image_list_status
    # #print image_list
    debug_file.write('{0} - Image list count: {1} \n'.format(datetime.datetime.utcnow(), image_list['count']))
    if image_list['count'] > 0:
        if not os.path.exists("reports"):
            os.makedirs("reports")
        out_file = "reports/Vulnerability_Image_Report_"+ time.strftime("%Y%m%d-%H%M%S") + ".csv"
        ofile  = open(out_file, "w")
        ofile.write("Registry,Repository,ImageID,Tag,Hostname,Vulnerabiltiy ID,Severity,CVE Number,First Found Date,Description,Type,Patch Available\n")
        for image in image_list['data']:
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
                debug_file.write('{0} - **** Exception - no vulnerbility inclusion limit set \n'.format(datetime.datetime.utcnow()))
                debug_file.write('------------------------------End Image Debug Log {0} --------------------------------\n'.format(datetime.datetime.utcnow()))
                sys.exit(1)
            vuln_counts = image['vulnerabilities']['severity5Count'] + image['vulnerabilities']['severity4Count'] + image['vulnerabilities']['severity3Count'] + image['vulnerabilities']['severity2Count'] + image['vulnerabilities']['severity1Count']
            #print vuln_counts
            registry = ''
            tags = ''
            repository = ''
            if image['repo']:
                repos = image['repo']
                for repo in repos:
                    if repo['registry'] not in registry:
                        registry += repo['registry'] + ";"
                    if repo['tag']:
                        if repo['tag'] not in tags:
                            tags += repo['tag'] + ";"
                    if repo['repository'] not in repository:
                        repository += repo['repository'] + ";"

            try:
                if image['host']:
                    #print image['host']
                    hostname = ""
                    for host in image['host']:
                        if host['hostname'] not in hostname:
                            hostname += (host['hostname'] + ";")
                else:
                    hostname = ""
            except KeyError:
                hostname = ""
                pass
            if image_details_url:
                counter = 0
                while counter < 5:

                    image_detail_list, image_details_url_status = Get_Call(username,password,image_details_url)
                    debug_file.write('{0} - API URL {1} response status: {2} \n'.format(datetime.datetime.utcnow(),image_details_url, image_details_url_status))
                    if image_details_url_status != 200:
                        debug_file.write('{0} - API URL {1} error details: {2} \n'.format(datetime.datetime.utcnow(),image_details_url, image_detail_list))
                    if image_details_url_status == 200:
                        counter = 6

                    else:
                        debug_file.write('{0} - API URL {1} error encountered retry number {2}\n'.format(datetime.datetime.utcnow(),image_details_url, counter))
                        debug_file.write("Not feeling well...sleeping 10 secs\n")
                        print "Not feeling well - sleeping 10 secs"
                        time.sleep(10)
                        counter += 1
                        if counter == 5:
                            debug_file.write('{0} - API URL {1} retry limit exceeded\n'.format(datetime.datetime.utcnow(),image_details_url))
                            sys.exit(1)

                #print str(image['imageId'])
                #print image
                #print image_detail_list
                if vuln_counts >= 1:
                    for vulns in image_detail_list['vulnerabilities']:
                        #print vulns
                        #image_vuln = software['vulnerabilities']
                        #print type(vulns['patchAvailable'])
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

                        if vulns['cveids']:
                            for cves in vulns['cveids']:
                                row = "{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11}\n".format(registry,repository,image['imageId'],tags,hostname,vulns['qid'],vulns['severity'],str(cves),firstDate,vulns['title'],vulns['typeDetected'],str(patchable))
                                ofile.write(row)
                        else:
                            row = "{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11}\n".format(registry,repository,image['imageId'],tags,hostname,vulns['qid'],vulns['severity'],"",firstDate,vulns['title'],vulns['typeDetected'],str(patchable))
                            ofile.write(row)
                else:
                    debug_file.write('{0} - *** No image vulnerabilities reported \n'.format(datetime.datetime.utcnow()))

    debug_file.write('------------------------------End Image Debug Log {0} --------------------------------\n'.format(datetime.datetime.utcnow()))
    debug_file.close()

def container_vuln_csv():
    username, password, vuln_rating, URL = config()
    if not os.path.exists("debug"):
        os.makedirs("debug")


    debug_file = open("./debug/debug_file.txt", "a")
    debug_file.write('------------------------------Begin Container Debug Log {0} --------------------------------\n'.format(datetime.datetime.utcnow()))
    container_list_pull_URL = URL + "/csapi/v1.1/containers"
    debug_file.write('{0} - Calling {1} \n'.format(datetime.datetime.utcnow(), container_list_pull_URL))
    counter = 0
    while counter < 5:
        container_list, container_list_status = Get_Call(username,password,container_list_pull_URL)
        debug_file.write('{0} - API URL {1} response status: {2} \n'.format(datetime.datetime.utcnow(), container_list_pull_URL, container_list_status))
        if container_list_status != 200:
            debug_file.write('{0} - API URL {1} error details: {2} \n'.format(datetime.datetime.utcnow(),container_list_pull_URL, container_list))
        if container_list_status == 200:
            counter = 6

        else:
            debug_file.write('{0} - API URL {1} error encountered retry number {2}\n'.format(datetime.datetime.utcnow(),container_list_pull_URL, counter))
            debug_file.write("Not feeling well...sleeping 10 secs\n")
            print "Not feeling well - sleeping 10 secs"
            time.sleep(10)
            counter += 1
            if counter == 5:
                debug_file.write('{0} - API URL {1} retry limit exceeded\n'.format(datetime.datetime.utcnow(),container_list_pull_URL))
                sys.exit(1)
        #print container_list_status
        # #print image_list
    debug_file.write('{0} - Container list count: {1} \n'.format(datetime.datetime.utcnow(), container_list['count']))

    if container_list['count'] > 0:
        if not os.path.exists("reports"):
            os.makedirs("reports")
        out_file = "reports/Vulnerability_Container_Report_"+ time.strftime("%Y%m%d-%H%M%S") + ".csv"
        ofile  = open(out_file, "w")
        ofile.write("Registry,Repository,ImageID,Container,Container Name,Hostname,IP,Vulnerabiltiy ID,Severity,CVE Number,First Found Date,Description,Type,Patch Available\n")
        for container in container_list['data']:
            container_detail_list = ''
            container_details_url_status = ''
            container_details_url = ''
            if vuln_rating == '54321':
                if container['vulnerabilities']['severity1Count'] > 0 or container['vulnerabilities']['severity2Count'] > 0 or container['vulnerabilities']['severity3Count'] > 0 or container['vulnerabilities']['severity4Count'] > 0 or container['vulnerabilities']['severity5Count'] > 0:
                    container_details_url = URL + "/csapi/v1.1/containers/" + str(container['containerId'])
            elif vuln_rating == '5432':
                if container['vulnerabilities']['severity2Count'] > 0 or container['vulnerabilities']['severity3Count'] > 0 or container['vulnerabilities']['severity4Count'] > 0 or container['vulnerabilities']['severity5Count'] > 0:
                    container_details_url = URL + "/csapi/v1.1/containers/" + str(container['containerId'])
            elif vuln_rating == '543':
                if container['vulnerabilities']['severity3Count'] > 0 or container['vulnerabilities']['severity4Count'] > 0 or container['vulnerabilities']['severity5Count'] > 0:
                    container_details_url = URL + "/csapi/v1.1/containers/" + str(container['containerId'])
            elif vuln_rating == '54':
                if container['vulnerabilities']['severity4Count'] > 0 or container['vulnerabilities']['severity5Count'] > 0:
                    container_details_url = URL + "/csapi/v1.1/containers/" + str(container['containerId'])
            elif vuln_rating == '5':
                if container['vulnerabilities']['severity5Count'] > 0:
                    container_details_url = URL + "/csapi/v1.1/containers/" + str(container['containerId'])
            else:
                debug_file.write('{0} - **** Exception - no vulnerbility inclusion limit set \n'.format(datetime.datetime.utcnow()))
                debug_file.write('------------------------------Container End Debug Log {0} --------------------------------\n'.format(datetime.datetime.utcnow()))
                sys.exit(1)
            container_vuln_counts = container['vulnerabilities']['severity5Count'] + container['vulnerabilities']['severity4Count'] + container['vulnerabilities']['severity3Count'] + container['vulnerabilities']['severity2Count'] + container['vulnerabilities']['severity1Count']
            #print container_vuln_counts
            image_details_url = ""
            if container_details_url:
                counter = 0
                while counter < 5:
                    container_detail_list, container_details_url_status = Get_Call(username,password,container_details_url)
                    debug_file.write('{0} - API URL {1} response status: {2} \n'.format(datetime.datetime.utcnow(),container_details_url,container_details_url_status))
                    if container_details_url_status != 200:
                        debug_file.write('{0} - API URL {1} error details: {2} \n'.format(datetime.datetime.utcnow(),container_details_url, container_detail_list))
                    if container_details_url_status == 200:
                        counter = 6


                    else:
                        debug_file.write('{0} - API URL {1} error encountered retry number {2}\n'.format(datetime.datetime.utcnow(),container_details_url, counter))
                        debug_file.write("Not feeling well...sleeping 10 secs\n")
                        print "Not feeling well - sleeping 10 secs"
                        time.sleep(10)
                        counter += 1
                        if counter == 5:
                            debug_file.write('{0} - API URL {1} retry limit exceeded\n'.format(datetime.datetime.utcnow(),container_details_url))
                            sys.exit(1)


                image_details_url = URL + '/csapi/v1.1/images/' + container['imageId']
                image_detail_list, image_details_url_status = Get_Call(username,password,image_details_url)
                counter = 0
                while counter < 5:
                    image_detail_list, image_details_url_status = Get_Call(username,password,image_details_url)
                    debug_file.write('{0} - API URL {1} response status: {2} \n'.format(datetime.datetime.utcnow(),image_details_url,image_details_url_status))
                    if image_details_url_status != 200:
                        debug_file.write('{0} - API URL {1} error details: {2} \n'.format(datetime.datetime.utcnow(),image_details_url, image_detail_list))
                    if image_details_url_status == 200:
                        counter = 6

                    else:
                        debug_file.write('{0} - API URL {1} error encountered retry number {2}\n'.format(datetime.datetime.utcnow(),image_details_url, counter))
                        debug_file.write("Not feeling well...sleeping 10 secs\n")
                        print "Not feeling well - sleeping 10 secs"
                        time.sleep(10)
                        counter += 1
                        if counter == 5:
                            debug_file.write('{0} - API URL {1} retry limit exceeded\n'.format(datetime.datetime.utcnow(),image_details_url))
                            sys.exit(1)
                registry = ''
                #tags = ''
                repository = ''
                repos = image_detail_list['repo']
                for repo in repos:
                    if repo['registry'] not in registry:
                        registry += repo['registry'] + ";"
                    #print repo['tag']
                    #if repo['tag'] not in tags:
                        #tags += repo['tag'] + ";"
                    if repo['repository'] not in repository:
                        repository += repo['repository'] + ";"
                if container['host']:
                    hostname = container['host']['hostname']
                else:
                    hostname = ""

                #Iterate through Vulnerabilities
                if container_vuln_counts >= 1:
                    if container_detail_list['vulnerabilities']:
                        for vulns in container_detail_list['vulnerabilities']:
                            if vulns['patchAvailable']:
                                patchable = vulns['patchAvailable']
                            else:
                                patchable = 'False'

                            firstFound = vulns['firstFound'][0:10]
                            firstDate = str(datetime.datetime.utcfromtimestamp(float(firstFound)).strftime('%Y-%m-%d %H:%M:%S'))

                            if vulns['cveids']:
                                for cves in vulns['cveids']:
                                    row = "{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13}\n".format(registry,repository,container['imageId'],container['containerId'],container['name'],hostname,container['host']['ipAddress'],vulns['qid'],vulns['severity'],str(cves),firstDate,vulns['title'],vulns['typeDetected'],str(patchable))
                                    ofile.write(row)
                            else:
                                row = "{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13}\n".format(registry,repository,container['imageId'],container['containerId'],container['name'],hostname,container['host']['ipAddress'],vulns['qid'],vulns['severity'],"",firstDate,vulns['title'],vulns['typeDetected'],str(patchable))
                                ofile.write(row)
                else:
                    debug_file.write('{0} - *** No container vulnerabilities reported \n'.format(datetime.datetime.utcnow()))

    debug_file.write('------------------------------Container End Debug Log {0} --------------------------------\n'.format(datetime.datetime.utcnow()))
    debug_file.close()




if __name__ == '__main__':
    image_vuln_csv()
    container_vuln_csv()
