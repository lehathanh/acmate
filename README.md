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
