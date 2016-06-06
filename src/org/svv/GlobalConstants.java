/*******************************************************************************
 * Copyright (c) 2016, SVV Lab, University of Luxembourg
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * 3. Neither the name of acmate nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/
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
