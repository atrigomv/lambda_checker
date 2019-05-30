# Lambda Checker

### Introduction
Lambda Checker is a simple script tool which executes some security checks to detect misconfigurations points on Lambda functions that could be automated in the security review of CI/CD pipelines. In addition to this, if the function is written in Python it performs additional security checks such as hardcoded credentials checks, use of assertion clauses and so on. Here is the list with the checks passed by the tool:

* Configuration issues:
** Lambda EU region
** Configuration of X-Ray debug module
** VPC Lambda's configuration
** Permissions and configuration of the role associated to the Lambda
** Insecure HTTP requests

* Code Security issues (only for Python functions):
** Hardcoded credentials
** Hardcoded directories
** Use of insecure libraries
** Use of insecure ciphers used
** Use of insecure algorithms used
** Use of assertion clauses
** OS Command execution (manual check required if it is detected)

The results are shown as CSV report and command-line. The use of this tool is complementary to the use of others and it is highly recommended the use of pure SAST solutions which can gives widest results.
