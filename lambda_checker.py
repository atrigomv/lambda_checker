#!/usr/bin/python3

##############################################################################################################################################

##	Description: Security scanner for Lambda functions. It executes additional security checks if Lambda is a Python function

##	Version: 1.0

##	Basic usage: ./lambda_checker.py -f NAME_OF_LAMBDA -v

##	Author: Alvaro Trigo

#############################################################################################################################################


import boto3
import botocore
import json
import argparse
import sys
import os
import subprocess
import datetime
import time
import urllib3
import zipfile
import tarfile
import re
import csv
import shutil
from os import listdir
from os.path import isfile

##	Defining arguments

parser = argparse.ArgumentParser()
parser.add_argument('-f', '--function', help='Lambda function which will be checked')
parser.add_argument('-d', '--download', help='Lambda function will be downloaded to local storage', action='store_true')
parser.add_argument('-j', '--json', help='If is checked json files will be reviewed', action='store_true')
parser.add_argument('-p', '--piidata', help='Not find for personal data (spanish)', action='store_true')
parser.add_argument('-a', '--all', help='Analyze all the Lambda functions in the AWS account', action='store_true')
parser.add_argument('-v', '--verbose', help='Verbose mode', action='store_true')
parser.add_argument('-n', '--nonreport', help='If is checked no report will be generated', action='store_true')
args = parser.parse_args()

##	Creating Lambda client

client_lambda = boto3.client('lambda')

##	Creating variables

inf_vuln = 0
low_vuln = 0
med_vuln = 0
hig_vuln = 0

inf_vuln_total = 0
low_vuln_total = 0
med_vuln_total = 0
hig_vuln_total = 0

cont_func = 1

inf_list = []
low_list = []
med_list = []
hig_list = []

hig_list_total = []

perm_list = []
function_list = []

flag_exit = 0
flag_full = 0

timestamp = str(time.time())
timestamp = timestamp[:(len(timestamp))-3]

libraries = ['TELNETLIB','FTPLIB','PICKLE','SUBPROCESS','XML_ETREE','XML_SAX','XML_PULLDOM','XMLRPCLIB']
ciphers = ['RC2','RC4','DES','BLOWFISH']
hashes = ['GOST','MD2','MD4','MD5','SHA1','SHA-1','SHA128','SHA-128']
names = [' abel ', ' adolfo ', ' aida ', ' alba ', ' alberto ', ' alejandro ', ' alex ', ' alfonso ', ' alfredo ', ' alicia ', ' almudena ', ' alvaro ', ' amaya ', ' amparo ', ' angel ', ' anton ', ' araceli ', ' armando ', ' barbara ', ' beatriz ', ' belen ', ' benjamin ', ' bernardo ', ' borja ', ' bruno ', ' carlos ', ' carmen ', ' cecilia ', ' celia ', ' clara ', ' claudia ', ' claudio ', ' cristina ', ' cristobal ', ' damian ', ' dario ', ' david ', ' diego ', ' edgar ', ' eduardo ', ' elena ', ' elisa ', ' eloy ', ' elvira ', ' emilia ', ' emilio ', ' emma ', ' enrique ', ' ernesto ', ' esteban ', ' ester ', ' esther ', ' eugenia ', ' eugenio ', ' eusebio ', ' ezequiel ', ' fabian ', ' fabio ', ' federico ', ' felipe ', ' felix ', ' fermin ', ' fidel ', ' fernanda ', ' fernando ', ' flavio ', ' francisca ', ' francisco ', ' gabriel ', ' gaspar ', ' gema ', ' gemma ', ' genoveva ', ' georgina ', ' gerardo ', ' german ', ' gilberto ', ' gisela ', ' gonzalo ', ' guadalupe ', ' guillermo ', ' gustavo ', ' hector ', ' helena ', ' ignacio ', ' isaac ', ' isidro ', ' ismael ', ' ivan ', ' jacinto ', ' jacob ', ' jaime ', ' javier ', ' jesus ', ' joaquin ', ' jose ', ' julian ', ' laura ', ' laureano ', ' lazaro ', ' leandro ', ' leticia ', ' lorena ', ' loreto ', ' lourdes ', ' luis ', ' macarena ', ' marcelo ', ' marcos ', ' margarita ', ' mariano ', ' maria ', ' mario ', ' mateo ', ' mauricio ', ' mauro ', ' melania ', ' mercedes ', ' jorge ', ' juan ', ' lucas ', ' manuel ', ' marta ', ' matias ', ' pablo ', ' patricia ', ' rodrigo ', ' sandra ', ' sofia ', ' antonio ', ' diana ', ' estefania ', ' gines ', ' lucia ', ' martin ', ' miriam ', ' moises ', ' nadia ', ' natalia ', ' nazaret ', ' nestor ', ' nicasio ', ' nieves ', ' noelia ', ' noemi ', ' paula ', ' zaira ', ' olga ', ' omar ', ' oscar ', ' paloma ', ' pamela ', ' pammela ', ' pedro ', ' peter ', ' jonh ', ' pilar ', ' quique ', ' rafael ', ' raimundo ', ' ramiro ', ' raquel ', ' raul ', ' rebeca ', ' reyes ', ' ricardo ', ' roman ', ' rosa ', ' ruben ', ' sabrina ', ' sagrario ', ' salvador ', ' samuel ', ' santi ', ' sebastian ', ' severino ', ' simon ', ' tania ', ' valentin ', ' vanesa ', ' vanessa ', ' veronica ', ' vicenta ', ' vicente ', ' victor ', ' virginia ', ' ximena ', ' jimena ', ' yolanda ', ' zacarias ', ' zulema ', ' william ', ' noah ', ' joshua ', ' michael ', ' liam ', ' alice ', ' isabel ']

##	Creating regex

patron_pass = re.compile(r"(?<![\w\d])(PASSWORD|SECRET|PASS|SECRET)[\s]*\=[\s]*[\'\"\`](?P<secret>[\w@$!%*#?&\s\-]+)[\'\"\`]")
patron_tmp = re.compile(r"[\s]*\=[\s]*[\'\"\`](/TMP|/VAR/TMP|/DEV/SHM)[\'\"\`]")
patron_lib = re.compile(r"(^IMPORT{1}\s)")
patron_crypto = re.compile(r'(^FROM [\w]*CRYPTO[\w\s]*)')
patron_assert = re.compile(r'(?<![\w\d])(ASSERT)(?![\w\d])')
patron_comment = re.compile(r'[\s]*\#')

##	Defining addional functions

def write_vuln(funcion, id, title, details, risk, confidence):
    global inf_vuln
    global inf_list
    global low_vuln
    global low_list
    global med_vuln
    global med_list
    global hig_vuln
    global hig_list
    global hig_list_total
    args.all= True
    if(risk == 'INFO'):
        inf_vuln = inf_vuln + 1
        inf_list.append(details)
    if(risk == 'LOW'):
        low_vuln = low_vuln + 1
        low_list.append(details)
    if(risk == 'MEDIUM'):
        med_vuln = med_vuln + 1
        med_list.append(details)
    if(risk == 'HIGH'):
        hig_vuln = hig_vuln + 1
        hig_list.append(details)
        if(args.all):
            hig_list_total.append('FUNCTION: ' + funcion + '. DETAILS: ' + details)
    if(args.nonreport is False):
        myData = [[id,title,details,risk,confidence]]
        myFile = open('lambda_checker_' + funcion + '_' + timestamp + '.csv', 'a')
        with myFile:
            writer = csv.writer(myFile)
            writer.writerows(myData)

def lambda_checker(lambda_function):
    global timestamp
    global flag_exit
    global client_lambda

    flag_vpc = 0
    flag_runtime='none'

    try:
        try:
            data = client_lambda.get_function(FunctionName=lambda_function)
        except:
            print('[-] Function ' + lambda_function + ' not found')
            flag_exit = 1
            sys.exit()
        #print(json.dumps(data, indent=4))

        #      Initializing CSV
        if(args.nonreport is False):
            myData = [['num_vuln','title','details','risk','confidence']]
            myFile = open('lambda_checker_' + lambda_function + '_' + timestamp + '.csv', 'w')
            with myFile:
                writer = csv.writer(myFile)
                writer.writerows(myData)

        # 	Check if the Lambda funcion is storaged without european region

        if((data['Configuration']['FunctionArn'].split(':')[3].split('-')[0]) != 'eu'):
            write_vuln(lambda_function,'I1','Lambda function is storaged without EU','INFO - The lambda function is storaged without EU: '+ data['Configuration']['FunctionArn'].split(':')[3],'INFO','High')

        #	Check the X-Ray tracing mode configured

        if((data['Configuration']['TracingConfig']['Mode']).upper().find('PASSTHROUGH') != -1):
            write_vuln(lambda_function,'I2','AWS X-Ray is set to default mode','INFO - AWS X-Ray tracing mode is set to ' + (data['Configuration']['TracingConfig']['Mode']) + ' (default mode). Lambda will only trace requests with header with sampled = 1','INFO','High')
        else:
            write_vuln(lambda_function,'V1','Billing alert: AWS-Ray tracing mode is set to no default mode','LOW - AWS X-Ray tracing mode is set to ' + (data['Configuration']['TracingConfig']['Mode']) + '. With this configuration additional costs could be charged ','LOW','Low')

        # 	Check if the funcion is written in Python or not

        if((data['Configuration']['Runtime']).upper().find('PYTHON') != -1):
            if(args.verbose):
                print('[+] The runtime language used by the function is ' + (data['Configuration']['Runtime']))
            flag_runtime = 'python'
        else:
            write_vuln(lambda_function,'I3','The runtime language used by the function is ' + data['Configuration']['Runtime'],'INFO - The runtime language used by the function is ' + data['Configuration']['Runtime'] + ', some validations had not been checked','INFO','High')

        #	Check if Lambda function is within a VPC
        try:
            if not(data['Configuration']['VpcConfig']['VpcId']):
                write_vuln(lambda_function,'I4','Lambda function is not within a VPC','INFO - The Lambda function is not within a VPC. It is recommend that do not put Lambda functions in a VPC unless you have to','INFO','High')
            else:
                write_vuln(lambda_function,'V4','Lambda function put in a VPC','LOW - Lambda function put in a VPC. It is recommend that do not put Lambda functions in a VPC unless you have to','LOW','Medium')
                flag_vpc = 1
        except:
            write_vuln(lambda_function,'I4','Lambda function is not within a VPC','INFO - The Lambda function is not within a VPC. It is recommend that do not put Lambda functions in a VPC unless you have to','INFO','High')

        #	Checking the last time in which the Lambda was modified

        date_time_obj = datetime.datetime.strptime((data['Configuration']['LastModified'])[:10] + ' 00:00:00.000000', '%Y-%m-%d %H:%M:%S.%f')
        if(((datetime.datetime.now()) - date_time_obj).days >= 10):
            write_vuln(lambda_function,'I5','Possible old version of Lambda function','INFO - The last modification on Lambda function was done long time ago ('+ (data['Configuration']['LastModified'])+ ')','INFO','Low')

        # 	Checking the IAM role used

        #	#	Checking if role has a AdministratorAccess or FullAcess policies attached
        try:
            client_iam = boto3.client('iam')
            role_name = ''
            pol_full = ''
            list_role_name = str(data['Configuration']['Role']).split('/')
            role_name = list_role_name[len(list_role_name)-1]
            data_role = client_iam.list_attached_role_policies(RoleName=role_name)
            for policies in data_role['AttachedPolicies']:
                for p in policies:
                    if(p == 'PolicyName'):
                        if(policies[p] == 'AdministratorAccess'):
                            write_vuln(lambda_function,'V8','Lambda function is executed with Admin rights','HIGH - Lambda function is executed with Admin rights: (POLICY: ' + str(policies[p]) + ', ROLE: ' + role_name + ')','HIGH','High')
                        else:
                            if(str(policies[p].upper()).find('FULLACCESS') != -1):
                                flag_full = 1
                                if(pol_full == ''):
                                    pol_full = str(policies[p])
                                else:
                                    pol_full = pol_full + ', ' + str(policies[p])
            if(flag_full == 1 and pol_full != ''):
                if(flag_vpc == 1):
                    write_vuln(lambda_function,'V9','Lambda function has FullAccess rights associated within a VPC','MEDIUM - Lambda function has FullAccess rights associated within a VPC: (POLICY: ' + pol_full + ', ROLE: ' + role_name + ')','MEDIUM','High')
                else:
                    write_vuln(lambda_function,'V9','Lambda function has FullAccess rights associated','LOW - Lambda function has FullAccess rights associated: (POLICY: ' + pol_full + ', ROLE: ' + role_name + ')','LOW','High')
        except:
            if(args.verbose):
                print('[-] Can not be checked if the role has admin rights')
        #	#	Checking if role is a default role
        if((data['Configuration']['Role'].find('role/service-role') and data['Configuration']['Role'].find(lambda_function))!= -1):
            write_vuln(lambda_function,'V2','The function is using the default IAM role','LOW - The function is using the default IAM role','LOW','Medium')
        else:
            try:
                for policies in data_role['AttachedPolicies']:
                    for p in policies:
                        if(p == 'PolicyArn'):
                            arn = policies[p]
            except:
                pass
            try:
                response = client_iam.list_policy_versions(PolicyArn=arn)
                for r in response['Versions']:
                        if(r['IsDefaultVersion']):
                                versionId = r['VersionId']
                response = client_iam.get_policy_version(PolicyArn = arn, VersionId = versionId)
        #	#	Checking if the Policy has as resource *
                for r in response['PolicyVersion']['Document']['Statement']:
                    if(r['Resource'] == '*'):
                        cadena = ''
                        for perm in r['Action']:
                            perm_list.append(perm)
                        for permiso in perm_list:
                            cadena = permiso + ', ' + cadena
                        cadena = cadena[:len(cadena)-2]
                        write_vuln(lambda_function,'V3','The permissions associated to Lambda function has not been limited','MEDIUM - The permissions associated to Lambda function has not been limited. The policy associated to the Lambda function has the parameter "Resource" to "*". The next permissions could be executed with no resource limitation: ' + cadena,'MEDIUM','Medium')
            except:
                if(role_name != ''):
                    if(args.verbose):
                        print('[?] The role seems to have inline policies. Trying to get permissions...')
                    try:
                        data_role = client_iam.list_role_policies(RoleName=role_name)
                    except botocore.exceptions.ClientError as e:
                        print('[-] Error in the access of Lambda function: ' + e.response['Error']['Message'])
                        pass
                    for policy_name in data_role['PolicyNames']:
                        response = client_iam.get_role_policy(RoleName=role_name,PolicyName=policy_name)
                        for statement in response['PolicyDocument']['Statement']:
                            if(statement['Resource'] == '*'):
                                cadena = ''
                                perm_list= []
                                try:
                                    write_vuln(lambda_function,'V3','The permissions associated to Lambda function has not been limited','MEDIUM- The permissions associated to Lambda function has not been limited. The policy associated to the Lambda function (POLICY: ' + policy_name + ') has the parameter "Resource" to "*". The next permissions could be executed with no resource limitation: ' + statement['Action'],'MEDIUM','Medium')
                                except:
                                    try:
                                        for perm in statement['Action']:
                                            perm_list.append(perm)
                                        for permiso in perm_list:
                                            cadena = permiso + ', ' + cadena
                                        cadena = cadena[:len(cadena)-2]
                                        write_vuln(lambda_function,'V3','The permissions associated to Lambda function has not been limited','MEDIUM- The permissions associated to Lambda function has not been limited. The policy associated to the Lambda function (POLICY: ' + policy_name + ') has the parameter "Resource" to "*". The next permissions could be executed with no resource limitation: ' + cadena,'MEDIUM','Medium')
                                    except:
                                        write_vuln(lambda_function,'V3','The permissions associated to Lambda function has not been limited','MEDIUM- The permissions associated to Lambda function has not been limited. The policy associated to the Lambda function (POLICY: ' + policy_name + ') has the parameter "Resource" to "*".','MEDIUM','Medium')
                else:
                    print('[-] It was impossible to retrieve permissions of the Lambda. Some checks will not be verified')
        #	#	Checking if the role is associated to other Lambda functions:
            response = client_lambda.list_functions(MaxItems=50)
            for function in response['Functions']:
                if((str(function['Role']) == str(data['Configuration']['Role'])) and (function['FunctionName'] != lambda_function)):
                    function_list.append(str(function['FunctionName']))
            if(len(function_list) > 0):
                cadena = ''
                for funcion in function_list:
                    cadena = funcion + ', ' + cadena
                cadena = cadena[:len(cadena)-2]
                write_vuln(lambda_function,'V7','The role used in the Lambda function is used in additional Lambda function','LOW - The role used in the Lambda function is used in additional functions: (Role: ' + str(data['Configuration']['Role']) + ')  (Functions: ' + cadena + ')','LOW','Medium')

        #	Downloading the lambda function if it is a python function
        url = urllib3.PoolManager()
        download = url.request('GET',(data['Code']['Location']))
        function = open('lambda_checker_' + lambda_function + '_' + timestamp + '.zip', 'wb')
        function.write(download.data)
        function.close()
        if(zipfile.is_zipfile('lambda_checker_' + lambda_function + '_' + timestamp + '.zip')):
            zip_ref = zipfile.ZipFile(os.getcwd() + '/lambda_checker_' + lambda_function + '_' + timestamp + '.zip','r')
            zip_ref.extractall(os.getcwd() + '/lambda_checker_' + lambda_function + '_' + timestamp)
            zip_ref.close()
        if(tarfile.is_tarfile('lambda_checker_' + lambda_function + '_' + timestamp + '.zip')):
                           tar_ref = tarfile.open(os.getcwd() + '/lambda_checker_' + lambda_function + '_' + timestamp + '.zip')
                           tar_ref.extractall(os.getcwd() + '/lambda_checker_' + lambda_function + '_' + timestamp)
                           tar_ref.close()
        os.remove(os.getcwd() + '/lambda_checker_' + lambda_function + '_' + timestamp + '.zip')
        for obj in listdir(os.getcwd() + '/lambda_checker_' + lambda_function + '_' + timestamp):
            if(str(obj).find('.') != -1):
                if(((str(obj).split('.')[1]).upper() == 'MD') or ((str(obj).split('.')[1]).upper() == 'PYC') or ((str(obj).split('.')[1]).upper() == 'TXT') or ((str(obj).split('.')[1]).upper() == 'HTML') or ((str(obj).split('.')[1]).upper() == 'TYPES') or ((str(obj).split('.')[1]).upper() == 'SO')):
                    continue
                else:
                    if((str(obj).split('.')[1]).upper() == 'JSON'):
                        if(args.json is False):
                            continue
            else:
                continue
            try:
                f = open(os.getcwd() + '/lambda_checker_' + lambda_function + '_' + timestamp + '/' + str(obj))
            except:
                continue
            num_line = 0
            while True:
                num_line = num_line + 1
                linea = f.readline()
                linea_mayus = linea.strip().upper()
                if not linea:
                    break
        #		# If line is a comment, continue
                fa = patron_comment.findall(linea)
                if fa:
                    continue
        #		# Searching for personal data (spanish)
                if(args.piidata is False):
                    for name in names:
                        if(linea_mayus.find(name.upper()) != -1):
                            write_vuln(lambda_function,'VA8','Personal data found','LOW - Personal data found (' + name.upper() + ') in line ' + str(num_line) + ' of ' + str(obj) + ' file. (' + linea.strip() + ')','LOW','Medium')
                            break
        #		# Searching for internet requests from the Lambda function:
                if(linea_mayus.find('HTTPS://') != -1 or linea_mayus.find('HTTP://') != -1):
                    if(flag_vpc == 1):
                        write_vuln(lambda_function,'V5','Dangerous external HTTP request detected','HIGH - Dangerous external HTTP request detected in line ' + str(num_line) + ' of ' + str(obj) + ' file. The risk is high due to the Lambda function is configured within a VPC so, if the website is compromised, it could put in dangerous the VPC. (' + linea.strip() + ')','HIGH','Medium')
                    else:
                        #print(linea[0])
                        write_vuln(lambda_function,'V6','External HTTP request detected','LOW - External HTTP request detected in line ' + str(num_line) + ' of ' + str(obj) + ' file: (' + linea.strip() + ')','LOW','Medium')
        #		# Searching for hardcoded credentials:
                fa = patron_pass.findall(linea_mayus)
                if fa:
                    write_vuln(lambda_function,'VA1','Possible hardcoded password found','HIGH - Possible hardcoded password found in line ' + str(num_line) + ' of ' + str(obj) +' file: (' + linea.strip() + ')','HIGH','Medium')
        #		# Searching for hardcoded tmp directory
                fa = patron_tmp.findall(linea_mayus)
                if fa:
                    write_vuln(lambda_function,'VA2','Possible hardcoded tmp directory found','MEDIUM - Possible hardcoded tmp directory found in line ' + str(num_line) + ' of ' + str(obj) + ' file: (' + linea.strip() + ')','MEDIUM','Medium')
                if(flag_runtime == 'python'):
        #		# Searching for insecure libraries used
                    fa = patron_lib.findall(linea_mayus)
                    if fa:
                        for library in libraries:
                            if(linea_mayus.find(library) != -1):
                                write_vuln(lambda_function,'VA3','Insecure python library used: ' + library.lower(),'MEDIUM - Insecure python library declared in line ' + str(num_line) + ' of ' + str(obj) +' file: (' + linea.strip() + ')','MEDIUM','Medium')
        #		# Searching for insecure ciphers and hashing algorithms:
                    fa = patron_crypto.findall(linea_mayus)
                    if fa:
                        for cipher in ciphers:
                            if(linea_mayus.find(cipher) != -1):
                                write_vuln(lambda_function,'VA4','Possible use of insecure cipher','MEDIUM - Possible use of insecure cipher in line ' + str(num_line) + ' of ' + str(obj) +' file: (' + linea.strip() + ')','MEDIUM','Low')
                        for hash in hashes:
                            if(linea_mayus.find(hash) != -1):
                                write_vuln(lambda_function,'VA5','Possible use of insecure hash algorithm: ' + hash.lower(),'MEDIUM - Possible use of insecure hash algorithm (' + hash.lower() + ') in line ' + str(num_line) + ' of ' + str(obj) +' file: (' + linea.strip() + ')','MEDIUM','Low')
        #		# Searching for execution of OS commands within Python code:
                    if((linea_mayus.find('OS.SYSTEM(') != -1) or (linea_mayus.find('SUBPROCESS.CALL(') != -1) or (linea_mayus.find('SUBPROCESS.CHECK_OUTPUT(') != -1)):
                        write_vuln(lambda_function,'VA6', 'Execution of OS commands through python libraries', 'MEDIUM - An OS command execution is detected in line ' + str(num_line) + ' of ' + str(obj) +' file: (' + linea.strip() + '). If the parameters are not sanitized, could cause a remote code execution in the host','MEDIUM','High')
        #		# Searching for use of assert conditions:
                    fa = patron_assert.findall(linea_mayus)
                    if fa:
                        write_vuln(lambda_function,'VA7', 'Use of assertion clauses', 'LOW - Use of assertion clauses in line ' + str(num_line) + ' of ' + str(obj) +' file. An assertion condition can be bypassed setting the debug mode to false which can execute non-expected situations in the code: (' + linea.strip() + ')','LOW','Medium')
            f.close()

        #	Remove folder if option 'd' is not selected:
        if(args.download is False):
            shutil.rmtree(os.getcwd() + '/lambda_checker_' + lambda_function + '_' + timestamp + '/')

        if(flag_exit == 0):
            if(args.nonreport is False):
                print('[+] Scan successful. A new report has been created with title lambda_checker_' + lambda_function + '_' + timestamp + '.csv')
            else:
                print('[+] Scan succesful.')
            print('')
            print(' [-] TOTAL vulnerabilities found:        ' + str(inf_vuln+low_vuln+med_vuln+hig_vuln))
            print('')
            print(' [-] INFO vulnerabilities found:         ' + str(inf_vuln))
            print(' [-] LOW vulnerabilities found:          ' + str(low_vuln))
            print(' [-] MEDIUM vulnerabilities found:       ' + str(med_vuln))
            print(' [-] HIGH vulnerabilities found:         ' + str(hig_vuln))
            print('')
            print('')
            if(args.verbose):
                print('[+] Detailed results:')
                print('')
                print(' [-] INFO vulnerabilities found:         ' + str(inf_vuln))
                if(inf_vuln > 0):
                    for vulnerability in inf_list:
                        print('                 [-] ' + vulnerability)
                print('')
                print(' [-] LOW vulnerabilities found:          ' + str(low_vuln))
                if(low_vuln > 0):
                    for vulnerability in low_list:
                        print('                 [-] ' + vulnerability)
                print('')
                print(' [-] MEDIUM vulnerabilities found:       ' + str(med_vuln))
                if(med_vuln > 0):
                    for vulnerability in med_list:
                        print('                 [-] ' + vulnerability)
                print('')
                print(' [-] HIGH vulnerabilities found:         ' + str(hig_vuln))
                if(hig_vuln > 0):
                    for vulnerability in hig_list:
                        print('                 [-] ' + vulnerability)
                print('')
    except:
               print('[-] Generic error: ' + str(sys.exc_info()[0]))

##	MAIN FUNCTION

##      Printing banner

print('')
print(".-.                   .-.      .-.          .--. .-.               .-.              ")
print(": :                   : :      : :         : .--': :               : :.-.           ")
print(": :    .--.  ,-.,-.,-.: `-.  .-' : .--.    : :   : `-.  .--.  .--. : `'.' .--. .--. ")
print(": :__ ' .; ; : ,. ,. :' .; :' .; :' .; ;   : :__ : .. :' '_.''  ..': . `.' '_.': ..'")
print(":___.'`.__,_;:_;:_;:_;`.__.'`.__.'`.__,_;  `.__.':_;:_;`.__.'`.__.':_;:_;`.__.':_;  ")
print('')
print('by Alvaro Trigo')
print('')
print('')

##	Executing function

if(args.function is not None):
    lambda_checker(args.function)
else:
    if(args.all is True):
        marker = None
        while True:
            paginator = client_lambda.get_paginator('list_functions')
            response_iterator = paginator.paginate(PaginationConfig={
                'PageSize': 10,
                'StartingToken': marker
            })
            for page in response_iterator:
                for functions in page['Functions']:
                    print('[+] [' + str(cont_func) + '] Results for function: ' + functions['FunctionName'])
                    lambda_checker(functions['FunctionName'])
                    inf_vuln_total = inf_vuln_total + inf_vuln
                    low_vuln_total = low_vuln_total + low_vuln
                    med_vuln_total = med_vuln_total + med_vuln
                    hig_vuln_total = hig_vuln_total + hig_vuln

                    inf_vuln = 0
                    low_vuln = 0
                    med_vuln = 0
                    hig_vuln = 0

                    inf_list = []
                    low_list = []
                    med_list = []
                    hig_list = []

                    cont_func = cont_func + 1

                    perm_list = []
                    function_list = []
            try:
                marker = page['Marker']
            except:
                print('')
                print('**************************************************************************************************************')
                print('**************************************************************************************************************')
                print('')
                print('[+] TOTAL VULNERABILITIES FOUND IN THE AWS ACCOUNT:')
                print('')
                print(' [-] TOTAL vulnerabilities found:        ' + str(inf_vuln_total+low_vuln_total+med_vuln_total+hig_vuln_total))
                print('')
                print(' [-] INFO vulnerabilities found:         ' + str(inf_vuln_total))
                print(' [-] LOW vulnerabilities found:          ' + str(low_vuln_total))
                print(' [-] MEDIUM vulnerabilities found:       ' + str(med_vuln_total))
                print(' [-] HIGH vulnerabilities found:         ' + str(hig_vuln_total))
                print('')
                print('[+] Functions analyzed: ' + str(cont_func - 1))
                if(hig_vuln_total > 0):
                    print('[+] High vulnerabilities detected in some functions:')
                    for vulnerability in hig_list_total:
                                                print('  [-] ' + vulnerability)
                print('')
                print('**************************************************************************************************************')
                print('**************************************************************************************************************')
                print('')
                sys.exit()
    else:
        subprocess.call([sys.argv[0], '-h'])
        sys.exit()
