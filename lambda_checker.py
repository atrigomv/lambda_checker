#!/usr/bin/python

##############################################################################################################################################

##	Description: Security scanner for Lambda functions. It executes additional security checks if Lambda is a Python function

##	Version: 1.0

##	Basic usage: ./lambda_checker.py -f NAME_OF_LAMBDA

##	Author: Alvaro Trigo

#############################################################################################################################################


import boto3
import json
import argparse
import sys
import os
import subprocess
import datetime
import time
import urllib2
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
parser.add_argument('-d', '--download', help='If is checked the Lambda function will be downloaded to local storage', action='store_true')
parser.add_argument('-j', '--json', help='If is checked json files will be reviewed', action='store_true')
args = parser.parse_args()

##	If the script is executed without paremeters, show help

if(len(sys.argv)==1):
	subprocess.call([sys.argv[0], '-h'])
	sys.exit()

##	Creating variables

inf_vuln = 0
low_vuln = 0
med_vuln = 0
hig_vuln = 0

inf_list = []
low_list = []
med_list = []
hig_list = []

perm_list = []
function_list = []

flag_vpc = 0
flag_runtime='none'

timestamp = str(time.time())
timestamp = timestamp[:(len(timestamp))-3]

libraries = ['TELNETLIB','FTPLIB','PICKLE','SUBPROCESS','XML_ETREE','XML_SAX','XML_PULLDOM','XMLRPCLIB']
ciphers = ['RC2','RC4','DES','BLOWFISH']
hashes = ['GOST','MD2','MD4','MD5','SHA1','SHA-1','SHA128','SHA-128']

##	Creating regex

patron_pass = re.compile(r"(?<![\w\d])(PASSWORD|SECRET|PASS|SECRET)[\s]*\=[\s]*[\'\"\`](?P<secret>[\w@$!%*#?&\s\-]+)[\'\"\`]")
patron_tmp = re.compile(r"[\s]*\=[\s]*[\'\"\`](/TMP|/VAR/TMP|/DEV/SHM)[\'\"\`]")
patron_lib = re.compile(r"(^IMPORT{1}\s)")
patron_crypto = re.compile(r'(^FROM [\w]*CRYPTO[\w\s]*)')
patron_assert = re.compile(r'(?<![\w\d])(ASSERT)(?![\w\d])')

##	Defining addional functions

def write_vuln(id, title, details, risk, confidence):
	global inf_vuln
	global inf_list
	global low_vuln
	global low_list
	global med_vuln
	global hig_vuln

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
	myData = [[id,title,details,risk,confidence]]
	myFile = open('lambda_checker_' + str(args.function) + '_' + timestamp + '.csv', 'a')
	with myFile:
		writer = csv.writer(myFile)
		writer.writerows(myData)

##	Printing banner

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

if(args.function is not None):
	print('[?] Checking the configuration of the Lambda...')
	try:
		client_lambda = boto3.client('lambda')
		try:
			data = client_lambda.get_function(FunctionName=args.function)
		except:
			print('[-] Function ' + str(args.function) + ' not found')
			sys.exit()
		#print(json.dumps(data, indent=4))

		#      Initializing CSV

		myData = [['num_vuln','title','details','risk','confidence']]
		myFile = open('lambda_checker_' + str(args.function) + '_' + timestamp + '.csv', 'w')
		with myFile:
			writer = csv.writer(myFile)
			writer.writerows(myData)
		
		# 	Check if the Lambda funcion is storaged without european region
		
		if((data['Configuration']['FunctionArn'].split(':')[3].split('-')[0]) == 'eu'):
			print('[+] The lambda function is storaged within EU: ' + data['Configuration']['FunctionArn'].split(':')[3])
		else:
			write_vuln('I1','Lambda function is storaged without EU','INFO - The lambda function is storaged without EU: '+ data['Configuration']['FunctionArn'].split(':')[3],'INFO','High')

		#	Check the X-Ray tracing mode configured

		if((data['Configuration']['TracingConfig']['Mode']).upper().find('PASSTHROUGH') != -1):
			write_vuln('I2','AWS X-Ray is set to default mode','INFO - AWS X-Ray tracing mode is set to ' + (data['Configuration']['TracingConfig']['Mode']) + ' (default mode). Lambda will only trace requests with header with sampled = 1','INFO','High')
		else:
			write_vuln('V1','Billing alert: AWS-Ray tracing mode is set to no default mode','LOW - AWS X-Ray tracing mode is set to ' + (data['Configuration']['TracingConfig']['Mode']) + '. With this configuration additional costs could be charged ','LOW','Low')

		# 	Check if the funcion is written in Python or not

		if((data['Configuration']['Runtime']).upper().find('PYTHON') != -1):
			print('[+] The runtime language used by the function is ' + (data['Configuration']['Runtime']))
			flag_runtime = 'python'
		else:
			write_vuln('I3','The runtime language used by the function is ' + data['Configuration']['Runtime'],'INFO - The runtime language used by the function is ' + data['Configuration']['Runtime'] + ', some validations had not been checked','INFO','High')

		#	Check if Lambda function is within a VPC
		try:
			if not(data['Configuration']['VpcConfig']['VpcId']):
				write_vuln('I4','Lambda function is not within a VPC','INFO - The Lambda function is not within a VPC. It is recommend that do not put Lambda functions in a VPC unless you have to','INFO','High')
			else:
				write_vuln('V4','Lambda function put in a VPC','LOW - Lambda function put in a VPC. It is recommend that do not put Lambda functions in a VPC unless you have to','LOW','Medium')
				flag_vpc = 1
		except:
			write_vuln('I4','Lambda function is not within a VPC','INFO - The Lambda function is not within a VPC. It is recommend that do not put Lambda functions in a VPC unless you have to','INFO','High')

		#	Checking the last time in which the Lambda was modified

		date_time_obj = datetime.datetime.strptime((data['Configuration']['LastModified'])[:10] + ' 00:00:00.000000', '%Y-%m-%d %H:%M:%S.%f')
		if(((datetime.datetime.now()) - date_time_obj).days >= 10):
			write_vuln('I5','Possible old version of Lambda function','INFO - The last modification on Lambda function was done long time ago ('+ (data['Configuration']['LastModified'])+ ')','INFO','Low')

		# 	Checking the IAM role used
		if((data['Configuration']['Role'].find('role/service-role') and data['Configuration']['Role'].find(args.function))!= -1):
			write_vuln('V2','The function is using the default IAM role','LOW - The function is using the default IAM role','LOW','Medium')
		else:
			try:
				client_iam = boto3.client('iam')
				list_role_name = str(data['Configuration']['Role']).split('/')
				role_name = list_role_name[len(list_role_name)-1]
				data_role = client_iam.list_attached_role_policies(RoleName=role_name)
			except:
				print('[-] It was impossible to retrieve the policies associated to the role. Some checks will not be verified')
			for policies in data_role['AttachedPolicies']:
				for p in policies:
					if(p == 'PolicyArn'):
						arn = policies[p]
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
						write_vuln('V3','The permissions associated to Lambda function has not been limited','MEDIUM - The permissions associated to Lambda function has not been limited. The policy associated to the Lambda function has the parameter "Resource" to "*". The next permissions could be executed with no resource limitation: ' + cadena,'MEDIUM','Medium')
			except:
				if(data_role != ''):
					print('[-] The Lambda has the role ' + role_name + ' but it was impossible to retrieve their permissions. Some checks will be not verified. Manually review it is recommended')
				else:
					print('[-] It was impossible to retrieve permissions of the Lambda. Some checks will not be verified')
		#	#	Checking if the role is associated to other Lambda functions:
			response = client_lambda.list_functions(MaxItems=50)
			for function in response['Functions']:
				if((str(function['Role']) == str(data['Configuration']['Role'])) and (function['FunctionName'] != str(args.function))):
					function_list.append(str(function['FunctionName']))
			if(len(function_list) > 0):
				cadena = ''
				for funcion in function_list:
					cadena = funcion + ', ' + cadena
				cadena = cadena[:len(cadena)-2]
				write_vuln('V7','The role used in the Lambda function is used in additional Lambda function','LOW - The role used in the Lambda function is used in additional functions: (Role: ' + str(data['Configuration']['Role']) + ')  (Functions: ' + cadena + ')','LOW','Medium')

		#	Downloading the lambda function if it is a python function

		print('[?] Downloading the Lambda function...')
		download = urllib2.urlopen(data['Code']['Location'])
		function = file('lambda_checker_' + str(args.function) + '_' + timestamp + '.zip', 'w')
		function.write(download.read())
		function.close()
		if(zipfile.is_zipfile('lambda_checker_' + str(args.function) + '_' + timestamp + '.zip')):
			zip_ref = zipfile.ZipFile(os.getcwd() + '/lambda_checker_' + str(args.function) + '_' + timestamp + '.zip','r')
			zip_ref.extractall(os.getcwd() + '/lambda_checker_' + str(args.function) + '_' + timestamp)
			zip_ref.close()
		if(tarfile.is_tarfile('lambda_checker_' + str(args.function) + '_' + timestamp + '.zip')):
                       	tar_ref = tarfile.open(os.getcwd() + '/lambda_checker_' + str(args.function) + '_' + timestamp + '.zip')
                       	tar_ref.extractall(os.getcwd() + '/lambda_checker_' + str(args.function) + '_' + timestamp)
                       	tar_ref.close()
		os.remove(os.getcwd() + '/lambda_checker_' + str(args.function) + '_' + timestamp + '.zip')
		for obj in listdir(os.getcwd() + '/lambda_checker_' + str(args.function) + '_' + timestamp):
			if(str(obj).find('.') != -1):
				if((str(obj).split('.')[1]).upper() == 'MD'):
					continue
				else:
					if((str(obj).split('.')[1]).upper() == 'JSON'):
						if(args.json is False):
							continue
			else:
				continue
			try:
				f = open(os.getcwd() + '/lambda_checker_' + str(args.function) + '_' + timestamp + '/' + str(obj))
			except:
				continue
			num_line = 0
			while True:
				num_line = num_line + 1
				linea = f.readline()
				linea_mayus = linea.strip().upper()
				if not linea:
					break
		#		# Searching for internet requests from the Lambda function:
				if((linea_mayus.find('HTTPS://') != -1 or linea_mayus.find('HTTP://') != -1 or linea_mayus.find('URLLIB') != -1) and (linea_mayus.find('IMPORT'))):
					if(flag_vpc == 1):
						write_vuln('V5','Dangerous external HTTP request detected','HIGH - Dangerous external HTTP request detected in line ' + str(num_line) + ' of ' + str(obj) + ' file. The risk is high due to the Lambda function is configured within a VPC so, if the website is compromised, it could put in dangerous the VPC. (' + linea.strip() + ')','HIGH','Medium')
					else:
						write_vuln('V6','External HTTP request detected','LOW - External HTTP request detected in line ' + str(num_line) + ' of ' + str(obj) + ' file: (' + linea.strip() + ')','LOW','Medium')
				if(flag_runtime == 'python'):
		#		# Searching for hardcoded credentials:
					fa = patron_pass.findall(linea_mayus)
					if fa:
						write_vuln('VA1','Possible hardcoded password found','HIGH - Possible hardcoded password found in line ' + str(num_line) + ' of ' + str(obj) +' file: (' + linea.strip() + ')','HIGH','Medium')
		#		# Searching for hardcoded tmp directory
					fa = patron_tmp.findall(linea_mayus)
					if fa:
						write_vuln('VA2','Possible hardcoded tmp directory found','MEDIUM - Possible hardcoded tmp directory found in line ' + str(num_line) + ' of ' + str(obj) + ' file: (' + linea.strip() + ')','MEDIUM','Medium')
		#		# Searching for insecure libraries used
					fa = patron_lib.findall(linea_mayus)
					if fa:
						for library in libraries:
							if(linea_mayus.find(library) != -1):
								write_vuln('VA3','Insecure python library used: ' + library.lower(),'MEDIUM - Insecure python library declared in line ' + str(num_line) + ' of ' + str(obj) +' file: (' + linea.strip() + ')','MEDIUM','Medium')
		#		# Searching for insecure ciphers and hashing algorithms:
					fa = patron_crypto.findall(linea_mayus)
					if fa:
						for cipher in ciphers:
							if(linea_mayus.find(cipher) != -1):
								write_vuln('VA4','Possible use of insecure cipher','MEDIUM - Possible use of insecure cipher in line ' + str(num_line) + ' of ' + str(obj) +' file: (' + linea.strip() + ')','MEDIUM','Low')
						for hash in hashes:
							if(linea_mayus.find(hash) != -1):
								write_vuln('VA5','Possible use of insecure hash algorithm: ' + hash.lower(),'MEDIUM - Possible use of insecure hash algorithm (' + hash.lower() + ') in line ' + str(num_line) + ' of ' + str(obj) +' file: (' + linea.strip() + ')','MEDIUM','Low')
		#		# Searching for execution of OS commands within Python code:
					if((linea_mayus.find('OS.SYSTEM(') != -1) or (linea_mayus.find('SUBPROCESS.CALL(') != -1) or (linea_mayus.find('SUBPROCESS.CHECK_OUTPUT(') != -1)):
						write_vuln('VA6', 'Execution of OS commands through python libraries', 'MEDIUM - An OS command execution is detected in line ' + str(num_line) + ' of ' + str(obj) +' file: (' + linea.strip() + '). If the parameters are not sanitized, could cause a remote code execution in the host','MEDIUM','High')
		#		# Searching for use of assert conditions:
					fa = patron_assert.findall(linea_mayus)
					if fa:
						write_vuln('VA7', 'Use of assertion clauses', 'LOW - Use of assertion clauses in line ' + str(num_line) + ' of ' + str(obj) +' file: (' + linea.strip() + '). An assertion condition can be bypassed setting the debug mode to false which can execute non-expected situations in the code (for example, authorization issues)','LOW','Medium')
			f.close()

		#	Remove folder if option 'd' is not selected:
		if(args.download is False):
			shutil.rmtree(os.getcwd() + '/lambda_checker_' + str(args.function) + '_' + timestamp + '/')

		#	Printing results:
		print('[+] Scan successful. A new report has been created with title lambda_checker_' + str(args.function) + '_' + timestamp + '.csv')
		print('')
		print('	[-] TOTAL vulnerabilities found:	' + str(inf_vuln+low_vuln+med_vuln+hig_vuln))
		print('')
		print('	[-] INFO vulnerabilities found:		' + str(inf_vuln))
		print('	[-] LOW vulnerabilities found:		' + str(low_vuln))
		print('	[-] MEDIUM vulnerabilities found: 	' + str(med_vuln))
		print('	[-] HIGH vulnerabilities found: 	' + str(hig_vuln))
		print('')
		print('')
		print('[+] Detailed results:')
		print('')
		print('	[-] INFO vulnerabilities found:		' + str(inf_vuln))
		if(inf_vuln > 0):
			for vulnerability in inf_list:
				print('			[-] ' + vulnerability)
		print('')
		print('	[-] LOW vulnerabilities found:		' + str(low_vuln))
                if(low_vuln > 0):
                        for vulnerability in low_list:
                                print('			[-] ' + vulnerability)
		print('')
		print('	[-] MEDIUM vulnerabilities found:	' + str(med_vuln))
                if(med_vuln > 0):
                        for vulnerability in med_list:
                                print('			[-] ' + vulnerability)
                print('')
		print('	[-] HIGH vulnerabilities found:		' + str(hig_vuln))
                if(hig_vuln > 0):
                        for vulnerability in hig_list:
                                print('			[-] ' + vulnerability)
                print('')
	except:
		print('[-] Generic error: ' + str(sys.exc_info()[0]))