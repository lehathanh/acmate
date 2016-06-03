package org.svv;

public class GlobalConstants {
	
	// option for BurpSuite callback to use https or https
	public static boolean USE_HTTPS = false;
	
	// option to ask acmate to follow server redirections 
	public static boolean FOLLOW_REDIRECTION = true;

	// option to group requests to a web page based on their set of parameters
	public static boolean GROUP_REQUEST_TO_RESOURCE = false;

	
	// option to remove the ending forward slash from URL, this makes URL/folder/ equals URL/folder 
	public static boolean REMOVE_ENDING_SLASH = true;

	// J48 binary splitting: true to reduce the number of leave nodes  
	public static boolean J48_BINARY_SPLITTING = true;

	// AC Inferrer, convert numeric to nomnial before runing J48
	public static boolean J48_CONVERT_NOMINAL = true;
	
	// option to ask acmate to send administrative command to the remote SUT's server and
	// restore the SUT/server state before testing AC for each user
	// Disable SERVER RESTORE in ACMate-Lite version
	public static boolean USE_SERVER_RESTORE_CMD = false;
	public static String SERVER_RESTORE_CMD = "";
	
	// option to ask acmate to ignore the failed logged-in and keep sending AC test requests to SUT.
	// This is useful when test AC of anonymous users and blocked/limited access users' accounts
	public static boolean IGNORE_FAILED_LOGIN = true;
}
