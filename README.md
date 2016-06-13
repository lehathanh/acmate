# ACMate-Lite

ACMate is a framework for testing and reverse-engineering access control (AC) policies. It is developed by the SVV Laboratory, SnT, University of Luxembourg.

Here you can download the light weight version of the ACMate tool with the basic functions for access control testing.

ACMate-Lite is a Java-based extension module for Burp Suite (http://protswigger.net/burp/) that can be loaded and run seamlessly with Burp Suite proxy and spider. ACMate-Lite provides hand-on testing functions to support the Web application developers to test the access control implemented in their web-based products.
ACMate-Lite contains the following key components:
* Mining input specification from logs
* Smartly generating AC requests using pairwise combination strategy
* Executing AC tests, taking into account contextual parameters

## Install

### Binary 

You can download the binary file <a href="https://github.com/lehathanh/acmate/blob/master/acmate-lite.jar">here</a>.

### Source

... or from source:
``` 
git clone https://github.com/lehathanh/acmate.git
```
and build the binary file in Eclipse using Ant.

### Import to Burp Suite

ACMate-Lite works as an extension in Burp Suite. Please refer to <a href="https://support.portswigger.net/customer/portal/articles/1965930-how-to-install-an-extension-in-burp-suite">this instruction</a> for its installation.

## User Guide

User guide is available <a href="https://github.com/lehathanh/acmate/blob/master/docs/ACMate-Lite%20Documentation%20Short.pdf">here</a>.

# ACMate Full version

ACMate provides additional features to assist AC testing as following: 
* AC policy inference, where AC policies are learned after the AC logs are obtained and analysed from the AC tests
* Assessment and Issues detection: ACMate highlights the inferred AC policies in three categories: "allowed", "denied" and "unclassified". This feature assissts the tester to quickly locate and assess the AC policies that may relate to potential AC issues in the tested web application.

If you are interested in the ACMate, please contact us: <a href="mailto:hathanh.le@uni.lu?Subject=ACMate" target="_top">hathanh.le@uni.lu</a>

#Bibliography

* H. T. Le, C. D. Nguyen, L. Briand, and B. Hourte. Automated inference of access control policies for web applications. In Proceedings of the 20th ACM Symposium on Access Control Models and Technologies, SACMAT ’15, pages 27–37, New York, NY, USA, 2015. ACM. (<a href="https://publications.uni.lu/handle/10993/20786">download</a>)