# Lambda Checker

### Introduction
Lambda Checker is a simple Python script, based on official AWS Boto3 Python SDK, which executes some security checks to detect misconfigurations issues on Lambda functions. The tool has been developed in order to be automated within CI/CD pipelines or to be executed on demand. In addition to security configuration checks, if the function is written in Python it performs additional security checks such as hardcoded credentials checks, use of assertion clauses and so on. Here is the list with the checks done by the tool:

* Configuration issues:
  * _Detection of AWS EU region use_
  * _Configuration of X-Ray debug module_
  * _VPC Lambda's configuration_
  * _Permissions and configuration of the role associated to the Lambda_
  * _Insecure HTTP requests_
  * _Detection of personal data (spanish)_

* Code Security issues (all languages):
  * _Hardcoded credentials_
  * _Hardcoded directories_
  
* Code Security issues (only for Python functions):
  * _Use of insecure libraries_
  * _Use of insecure ciphers_
  * _Use of insecure algorithms_
  * _Use of assertion clauses_
  * _OS Command execution detection (manual check required if it is detected)_

The results are shown as CSV report and command-line and they are classified as "Info", "Low", "Medium" or "High" risk severity. The use of this tool is complementary to the use of others and it is highly recommended the use of pure SAST solutions which can gives widest results.

### Installation and environment configuration
In order to install the tool, you can clone the git repository or download the [Python script](https://github.com/atrigomv/lambda_checker/blob/master/lambda_checker.py):
```
git clone git://github.com/atrigomv/lambda_checker.git
```
To execute the tool it is necessary to cover the steps below:
* Download the tool
* Create a programmatic user in AWS account in which Lambda functions are storaged. The [permissions](https://github.com/atrigomv/lambda_checker/blob/master/README.md#permissions-of-the-aws-user) of this user are described below.
* Install Python
* Install [Boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/quickstart.html) for Python:
```
pip install boto3
```
* Install [AWS CLI](https://aws.amazon.com/cli/?nc1=h_ls) and configure it with the access key and the secret access key of the user previously created:
```
pip install awscli
aws configure
```
* Put execution permissions:
```
chmod +x lambda_checker.py
```
* Enjoy ;)

### Permissions of the AWS user
#### Basic usage
If you chose the easy way, it is enough if the programmatic user has the next policies selected: AWSLambdaFullAccess and IAMFullAccess.
#### Policy ad-hoc (recommended)
In order to give the exact permissions to the script, it is needed to create a new policy with the next statement:
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "iam:GetPolicyVersion",
                "lambda:ListFunctions",
                "iam:ListPolicyVersions",
                "lambda:GetFunction",
                "iam:ListAttachedRolePolicies"
            ],
            "Resource": "*"
        }
    ]
}
```

### Basic usage
```
./lambda_checker.py -f <LAMBDA_FUNCTION_NAME>
```

### Output
![Image01](/image01.PNG)

### About the author
[Alvaro Trigo](https://atrigomv.github.io/)
