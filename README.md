# Lambda Checker

### Introduction
Lambda Checker is a simple script tool which executes some security checks to detect misconfigurations issues on Lambda functions that could be automated in the security review of CI/CD pipelines. In addition to this, if the function is written in Python it performs additional security checks such as hardcoded credentials checks, use of assertion clauses and so on. Here is the list with the checks done by the tool:

* Configuration issues:
  * _Detection of AWS EU region use_
  * _Configuration of X-Ray debug module_
  * _VPC Lambda's configuration_
  * _Permissions and configuration of the role associated to the Lambda_
  * _Insecure HTTP requests_

* Code Security issues (only for Python functions):
  * _Hardcoded credentials_
  * _Hardcoded directories_
  * _Use of insecure libraries_
  * _Use of insecure ciphers used_
  * _Use of insecure algorithms used_
  * _Use of assertion clauses_
  * _OS Command execution (manual check required if it is detected)_

The results are shown as CSV report and command-line. The use of this tool is complementary to the use of others and it is highly recommended the use of pure SAST solutions too which can gives widest results.

### Installation and environment configuration
In order to install the tool, you can clone the git repository or download the [Python script](https://github.com/atrigomv/lambda_checker/blob/master/lambda_checker.py):
```
git clone git://github.com/atrigomv/lambda_checker.git
```
To execute the tool it is necessary to cover the steps below:
* Download the tool
* Create a programmatic user in AWS with fullaccess permissions into Lambda
* Install Python
* Install [Boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/quickstart.html) for Python:
```
pip install boto3
```
* Install [AWS CLI](https://aws.amazon.com/cli/?nc1=h_ls) and configure it with the access key and the secret access key of the user previously created:
```
pip install awscli
```
* Put execution permissions:
```
chmod +x lambda_checker.py
```
* Enjoy ;)

### Basic usage
```
./lambda_checker.py -f <LAMBDA_FUNCTION_NAME>
```

### Output
![Image01](/image01.PNG)
