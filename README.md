# Lambda Checker

### Introduction
Lambda Checker is a simple script tool which executes some security checks to detect misconfigurations points on Lambda functions that could be automated in the security review of CI/CD pipelines. In addition to this, if the function is written in Python it performs additional security checks such as hardcoded credentials checks, use of assertion clauses and so on. Here is the list with the checks done by the tool:

* Configuration issues:
  * _Lambda EU region_
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
