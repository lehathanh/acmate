package org.svv.acmate.executor;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;

import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.svv.GlobalConstants;
import org.svv.acmate.burpsuite.BurpCookie;
import org.svv.acmate.burpsuite.BurpCookieParam;
import org.svv.acmate.burpsuite.BurpParameter;
import org.svv.acmate.exception.SessionException;
import org.svv.acmate.model.Request;
import org.svv.acmate.model.TargetAppModel;
import org.svv.acmate.model.config.Authentication;
import org.svv.acmate.model.config.User;
import org.svv.acmate.utils.PermissionUtil;
import org.svv.html.HtmlUtil;
import org.svv.html.WebInputElement;

import burp.IBurpExtenderCallbacks;
import burp.ICookie;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IResponseInfo;

public class Session implements Callable<Session> {
	
	private List<BurpCookie> cookies;
	private List<String> loginHeaders;
	
	private List<BurpParameter> serverDynamicParameters;
	
	private String globalId;
	
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helper;
	private TargetAppModel appModel;
	
	private User currentUser;

	// list of requests to send
	private List<Request> requests;
	
	private IHttpService service;
	
	// to store session results
	private Map<Request, AccessResponse> sessionResults;
	
	private ISessionListener listener;

	/**
	 * Constructor 
	 * @param selectedPaths 
	 * @param u 
	 * 
	 * @param userName
	 * @param password
	 * @param callbacks
	 * @param appModel 
	 * @param siteMap 
	 */
	public Session(User user, List<Request> selectedRequest, IBurpExtenderCallbacks callbacks
			, TargetAppModel appModel) {
		this.callbacks = callbacks;
		
		if (callbacks != null)
			this.helper = callbacks.getHelpers();
		
		this.currentUser = user;
		this.requests = selectedRequest;
		this.appModel = appModel;
		
		cookies = new ArrayList<BurpCookie>();
		sessionResults = new HashMap<Request, AccessResponse>();
		
//		initDynamicParam();
		
		globalId = UUID.randomUUID().toString();
	}
	
	/**
	 * 
	 */
	private void initDynamicParam(){
		serverDynamicParameters = new ArrayList<BurpParameter>();
		for (Request r : requests){
			if (r.hasServerParam())
				for (IParameter p : r.getServerParams()){
					boolean alreadyIncluded = false;
					for (IParameter q : serverDynamicParameters){
						if (p.getName().equals(q.getName())){
							alreadyIncluded = true;
							break;
						}
					}
					if (!alreadyIncluded){
						serverDynamicParameters.add(new BurpParameter(p.getName(), "to-get-at-runtime"));
					}
				}
		}
	}
	
	
	/**
	 * Extract or render the original request in byte[] 
	 * @param r
	 * @return
	 */
	public byte[] getOriginalRequest(Request r) {
		
		if (r.getOriginalSource().equals(Request.REQUEST_SOURCE_PROXY)){
			if (r.getBurpRR()!= null) return r.getBurpRR().getRequest();
		} else if (r.getOriginalSource().equals(Request.REQUEST_SOURCE_COMBIGEN)){
			byte[] requestInBytes = helper.buildHttpRequest(r.getUrl());
			
			if ("POST".equals(r.getMethod())){
				requestInBytes = helper.toggleRequestMethod(requestInBytes);
			}
			
			// add parameters 
			for (BurpParameter p : r.getParameters()){
				requestInBytes = helper.addParameter(requestInBytes, p);
			}
			
			return requestInBytes;
		}
		return null;
	}
	


	public List<BurpCookie> getCookies() {
		return cookies;
	}


	public void setCookies(List<BurpCookie> cookies) {
		this.cookies = cookies;
	}


	public String getGlobalId() {
		return globalId;
	}


	public void setGlobalId(String globalId) {
		this.globalId = globalId;
	}


	/**
	 * get the current user
	 * @return
	 */
	public User getCurrentUser() {
		return currentUser;
	}
	
	public void setListener(ISessionListener listener) {
		this.listener = listener;
	}
	

	/**
	 * get list of request that have been executed
	 * @return
	 */
	public List<Request> getRequests() {
		return requests;
	}
	
	public Map<Request, AccessResponse> getSessionResults() {
		return sessionResults;
	}
	
	
	/**
	 * Initiate a session with login process, only call after startACTest 
	 */
	private boolean initSession() throws SessionException{

		// Restore remote server state using backup database.
		// Applicable if remote server can be accessed with ssh.
		//
		// CRITICAL WARNING: administrative credentials to remote server may be disclosed!!!
		//	 This method uses sshpass and the administrative credential(s) for secure login 
		// and remote execution will be explicitly written in the shell script for 
		// automatic log in. Use with care!
		System.out.println("restore sever before requesting...");
		if(GlobalConstants.USE_SERVER_RESTORE_CMD) {
			String cmd = GlobalConstants.SERVER_RESTORE_CMD; // "/Users/hathanh.le/tmp/wordpress382/./restorewpdb.sh";
			Process serverRestoreProcess = null;
			try {
				serverRestoreProcess = Runtime.getRuntime().exec(cmd);
			} catch (IOException e1) {
				e1.printStackTrace();
			}
			try {
				serverRestoreProcess.waitFor();
			} catch (InterruptedException e1) {
				e1.printStackTrace();
			}
		}

		try {
			
			Authentication auth = appModel.getConfigModel().getAuthentication();
			URL loginURL = new URL(auth.getLogInURL());
			
			
			// build request
			byte[] request = helper.buildHttpRequest(loginURL);
			
			IParameter userNameParam = helper.buildParameter(auth.getUserFieldName()
						, currentUser.getUsername()
						, IParameter.PARAM_BODY);
			IParameter passwordParam = helper.buildParameter(auth.getPasswordFieldName()
					, currentUser.getPassword()
					, IParameter.PARAM_BODY);
			
			byte[] postRequest = helper.toggleRequestMethod(request); // change to POST request
			postRequest = helper.addParameter(postRequest, userNameParam);
			postRequest = helper.addParameter(postRequest, passwordParam);
			
			// build a http service
			int port = loginURL.getPort();
			if (port == -1) port = 80; // default port
			
			service = helper.buildHttpService(loginURL.getHost(), port, GlobalConstants.USE_HTTPS);
			
	
			// request the server for login
			IHttpRequestResponse rr;
			if (GlobalConstants.FOLLOW_REDIRECTION)
				rr = makeAndFollowHttpRequest(postRequest);
			else
				rr = callbacks.makeHttpRequest(service, postRequest);
				
			
			// XXX removed this if necessary
			// add the call to the sitemap
			asyncAddToSiteMap(rr);
			
			// Check response
			if (rr.getResponse() == null)
				throw new SessionException("Cannot login, received an empty response!");
				
			String baseResponse = helper.bytesToString(rr.getResponse());
			IResponseInfo resInfo = helper.analyzeResponse(rr.getResponse());
			
			updateSessionCookie(resInfo);
			
			loginHeaders = resInfo.getHeaders();
			
			if (isLoggedIn(loginURL, resInfo, baseResponse, auth.getUserFieldName())){
				return true;
			} else {
				// now try to analyse the response of the first call, usually when
				// login is failed, the target system redirects to a login page 
				// with login form. Now try to get the form and guess which field is
				// for username and which one is for password
				
				HtmlUtil htmlUtil = new HtmlUtil();
				htmlUtil.parse(baseResponse);
				
				Elements forms = htmlUtil.getForms();
				
				
				String loginActionPage = "";
				List<WebInputElement> inputs = null;
				
				// if no "login" form is available in the response,
				// need to GET the login page
				if (forms == null){
					// rr = callbacks.makeHttpRequest(service, postRequest);
					if (GlobalConstants.FOLLOW_REDIRECTION)
						rr = makeAndFollowHttpRequest(postRequest);
					else
						rr = callbacks.makeHttpRequest(service, postRequest);
					
					asyncAddToSiteMap(rr);
					
					// Check response
					if (rr.getResponse() == null)
						throw new SessionException("Cannot login, received an empty response!");
					resInfo = helper.analyzeResponse(rr.getResponse());
					baseResponse = helper.bytesToString(rr.getResponse());
					
					if (isLoggedIn(loginURL, resInfo, baseResponse, auth.getUserFieldName())){
//						for (ICookie c : resInfo.getCookies()){
//							cookies.add(new BurpCookie(c)); 
//						}
						updateSessionCookie(resInfo);
						loginHeaders = resInfo.getHeaders();
						return true;
					}
					if (GlobalConstants.IGNORE_FAILED_LOGIN)
						return true;
					
				}
				
				if (forms != null){
					boolean foundForm = false;
					for (Element f : forms){
						inputs = htmlUtil.getParameters(f);
						if (inputs != null){
							// find a field name of the type "password"
							for (WebInputElement input : inputs){
								if (input.getType().equals(WebInputElement.INPUT_TYPE_PASSWORD)){
									// found, stop
									loginActionPage =  f.attr("action"); 
									foundForm = true;
									break;
								}
							}
							if (foundForm) break; // don't try other forms
						}
					}
					
					if (foundForm){
						// removed the previous parameters
						if (!loginActionPage.isEmpty() && !loginURL.getPath().endsWith(loginActionPage)){
							
							URL newLoginPage;
							if (loginActionPage.contains("http://"))
								newLoginPage = new URL(loginActionPage);
							else {
								String tmp = loginURL.getProtocol() + "://" + loginURL.getHost();
								if (port != 80){
									tmp = tmp + ":" + loginURL.getPort();
								}
								
								newLoginPage = new URL(tmp + loginActionPage);
							}
							
							request = helper.buildHttpRequest(newLoginPage);
							postRequest = helper.toggleRequestMethod(request); // change to POST request
						} else {
							postRequest = helper.removeParameter(postRequest, userNameParam);
							postRequest = helper.removeParameter(postRequest, passwordParam);
						}
						// add previous cookies
						for (ICookie c : resInfo.getCookies()){
							postRequest = helper.addParameter(postRequest, new BurpCookieParam(c));
						}
						
						String userFieldName = null;
						for (WebInputElement input : inputs){
							if (input.getType().equals(WebInputElement.INPUT_TYPE_HIDDEN) || input.getType().equals(WebInputElement.INPUT_TYPE_SUBMIT)){
								// hidden form value
								IParameter p = helper.buildParameter(input.getName()
										, input.getValue()
										, IParameter.PARAM_BODY);
								postRequest = helper.addParameter(postRequest, p);

							} else if (input.getType().equals(WebInputElement.INPUT_TYPE_PASSWORD)){
								// password
								IParameter p = helper.buildParameter(input.getName()
										, currentUser.getPassword()
										, IParameter.PARAM_BODY);
								postRequest = helper.addParameter(postRequest, p);
							} else if (input.getType().equals(WebInputElement.INPUT_TYPE_TEXT)){
								// username ?
								IParameter p = helper.buildParameter(input.getName()
										, currentUser.getUsername()
										, IParameter.PARAM_BODY);
								userFieldName = input.getName();
								postRequest = helper.addParameter(postRequest, p);
							}
						}
						
						// make a second call
						if (GlobalConstants.FOLLOW_REDIRECTION)
//							rr = HttpUtil.makeAndFollowHttpRequest(callbacks, service, postRequest);
							rr = makeAndFollowHttpRequest(postRequest);
						else
							rr = callbacks.makeHttpRequest(service, postRequest);
						
						asyncAddToSiteMap(rr);
						
						// Check response
						if (rr.getResponse() == null)
							throw new SessionException("Cannot login, received an empty response!");
						resInfo = helper.analyzeResponse(rr.getResponse());
						baseResponse = helper.bytesToString(rr.getResponse());
						
						if (isLoggedIn(loginURL, resInfo, baseResponse, userFieldName)){
//							for (ICookie c : resInfo.getCookies()){
//								cookies.add(new BurpCookie(c)); 
//							}
							updateSessionCookie(resInfo);
							loginHeaders = resInfo.getHeaders();
							return true;
						}
						if (GlobalConstants.IGNORE_FAILED_LOGIN)
							return true;
						
					}
					
				}
				
				throw new SessionException("Cannot login for user: " + currentUser.getUsername());
			}
			
		} catch (MalformedURLException e){
			throw new SessionException("Login URL is not welformed! Pls correct it!");
		}
		
	}
	
	/**
	 * Add a request-response to site map, use a separate threat to avoid blocking 
	 * @param rr
	 */
	private void asyncAddToSiteMap(IHttpRequestResponse rr){
//		SwingUtilities.invokeLater(new Runnable() {
//			
//			@Override
//			public void run() {
				callbacks.addToSiteMap(rr);
//			}
//		});
	}

	
	
	/**
	 * Check if logging in is successful, to update the check if needed to make
	 * it applicable to more applications
	 *  
	 * @param resInfo
	 * @param baseResponse
	 * @return
	 */
	protected boolean isLoggedIn(URL loginURL, IResponseInfo resInfo, String baseResponse, String userFieldName) {
		if (resInfo.getStatusCode() == 302 || resInfo.getStatusCode() == 200){
			// 1. client redirection with location
			for (String header : resInfo.getHeaders()){
				if (header.startsWith("Location:")){
					// check if the location is new
					String[] tmp = header.split(" ");
					if (tmp.length == 2){
						try {
							URL newLoc = new URL(tmp[1]);
							if (loginURL.getPath().equals(newLoc.getPath())){
								return false; // been redirected to the same page
							}
						} catch (MalformedURLException e) {
							if (loginURL.getPath().equals(tmp[1])){
								return false; // been redirected to the same page
							}
						}
					}
					return true; // has been redirected to other page, sign of logged in
				}
			}
			
			// 1. client redirection with location
//			if (!isRedirectedTo(resInfo, loginURL))
//				return true;
			
			// 2. Check the content of baseResponse to see if there is a password field
			HtmlUtil htmlHelper = new HtmlUtil();
			htmlHelper.parse(baseResponse);
			
			Elements forms = htmlHelper.getForms();
			if (forms != null){
				for (Element f : forms){
					List<WebInputElement> inputs = htmlHelper.getParameters(f);
					if (inputs != null){
						// find a field name of the type "password"
						// NOTE: to prevent incorrectly detecting "profile" page with password reset function as login page, 
						//    need to detect and count the number of "password" fields in the response.
						//    - The login page contains only one "password" field
						//    - The "profile" page with password reset function contains at least two "password" fields
						//    - The normal page, after logged in, contains no "password" field
						int passwordFieldCount = 0;
						for (WebInputElement input : inputs){
							if (input.getType().equals(WebInputElement.INPUT_TYPE_PASSWORD)){
								passwordFieldCount += 1;
							}
							if (passwordFieldCount >= 2) {
								break;
							}
							/*
							if (input.getType().equals(WebInputElement.INPUT_TYPE_PASSWORD)){
								// found, stop
								return false; // not yet loggin
							}
							*/
						}
						// if there is ONLY one "password" field, this is log in page
						// NOT LOGGED IN YET!
						if (passwordFieldCount == 1) {
							return false;
						}
							
					}
				}
			}
			// find no form or no login form, ok.
			return true;
			
		}
		
		// NOTE: If SUT==WordPress returns 500 "Access Denied" after logged in,
		// it means that the user is successfully logged in but not allowed to access the page
		// he is directed to.
		if (resInfo.getStatusCode() == 500){
			return true;
		}
		
		// If SUT==iTrust returns 404 "Your page wasn't found" after logged in, 
		// it means that the user is successfully logged in but not allowed to access the page 
		// he is directed to.
		if (resInfo.getStatusCode() == 404){
			return true;
		}
		
		// other http code
		return false;
	}


	/**
	 * Run this particular session for all selected pages and their requests  
	 * with the credential of the current user.
	 * 
	 */
	@Override
	public Session call() throws Exception {
		try {
			if (initSession()){
				
				if (listener != null){
					int load =  requests.size();
					listener.sessionStart(this, load);
				}
					
				int progress= 0;
				
				for (Request request :  requests){
					
					// Restore remote server state using backup database.
					// Applicable if remote server can be accessed with ssh.
					// NOTE: Server should be restore before each request
//					System.out.println("restore sever before requesting");
//					if(GlobalConstants.USE_SERVER_RESTORE_CMD) {
//						String cmd = GlobalConstants.SERVER_RESTORE_CMD; // "/Users/hathanh.le/tmp/wordpress382/./restorewpdb.sh";
//						Process serverRestoreProcess = null;
//						try {
//							serverRestoreProcess = Runtime.getRuntime().exec(cmd);
//						} catch (IOException e1) {
//							e1.printStackTrace();
//						}
//						try {
//							serverRestoreProcess.waitFor();
//						} catch (InterruptedException e1) {
//							e1.printStackTrace();
//						}
//					}

					
					progress++;
					
					byte[] origRequest = getOriginalRequest(request);
					
					if (origRequest != null){
						
						byte[] newRequest;
						if (request.getOriginalSource().equals(Request.REQUEST_SOURCE_PROXY))
							newRequest = updateRequestToCurrentSession(origRequest);
						else
							newRequest = addMissingParamsNUpdateRequestToCurrentSession(request, origRequest);
						
						newRequest = adjustHeaders(newRequest);
						
						IHttpRequestResponse rr;
						if (GlobalConstants.FOLLOW_REDIRECTION)
							rr = makeAndFollowHttpRequest(newRequest);
						else
							rr = callbacks.makeHttpRequest(service, newRequest);
						
						rr.setComment("Session: " + currentUser.getUsername());
						
						IResponseInfo resInfo = helper.analyzeResponse(rr.getResponse());
						String baseResponse = helper.bytesToString(rr.getResponse());

						// TODO: make this code generic to all SUTs,
						//   If the server status changes due to reset/busy/delay, it will reply with
						// specific codes and contents. Then the resource request must redo accordingly!
						// * iTrust, if response is 200 and "Server Reboot!", user has been forced to log out
						//	due to: (1) user requested reboot.jsp or (2) server is reset.
						if(resInfo.getStatusCode() == 200 && baseResponse.contains("Server Reboot")) {
							// logging in
							initSession();
							
							// if server is reset, then the request needs to be resent after logged in
							if (GlobalConstants.FOLLOW_REDIRECTION)
								rr = makeAndFollowHttpRequest(newRequest);
							else
								rr = callbacks.makeHttpRequest(service, newRequest);
							
							rr.setComment("Session: " + currentUser.getUsername());
						}
						
						// update cookie
						updateSessionCookie(resInfo);
						
						// XXX adding new request to sitemap
						asyncAddToSiteMap(rr);
						
						
						String color = PermissionUtil.getColor(appModel.getFilterModel(), rr, helper);
			        	if (color.equals(PermissionUtil.COLOR_GREEN)){
			        		rr.setHighlight("green");
			        	} else if (color.equals(PermissionUtil.COLOR_RED)){
			        		rr.setHighlight("red");
			        	} else if (color.equals(PermissionUtil.COLOR_ORANGE)){
		        			// multiple conflicting rules have been applied applied
		        			rr.setHighlight("orange");
			        	}
						
			        	// TODO: should update siteMap with this new IHttpRequestResponse?
			        	// siteMap.add(path, rr)
						
						// store session result
			        	String acResponseContent = helper.bytesToString(rr.getResponse()); 
			        	AccessResponse ar = new AccessResponse(color, String.valueOf(resInfo.getStatusCode()), acResponseContent);
						sessionResults.put(request, ar);
						
						// if the user has been logged out due to authorization error, then user needs to re-login
						// * In iTrust, if response is 403 and "Authorization Error!", user has been forced to log out
						// In stead of checking this, we disable invalid session checking in iTrust source code
//						if(resInfo.getStatusCode() == 403) {
//							if(baseResponse.contains("Authorization Error!")) {
//								initSession();
//							}
//						}
					}
					
					if (listener != null){
						listener.sessionProgress(this, progress);
					}
				}
				if (listener != null){
					listener.sessionDone(this);
				}
			}
		} catch (SessionException e) {
			throw new Exception(e.getMessage());
		}
		return this; 
	}


	/**
	 * Adjust header to add user-agent and Connection: close 
	 * @param currentRequest
	 * @return
	 */
	private byte[] adjustHeaders(byte[] currentRequest) {
		// add a header to make the request faster
		IRequestInfo reqInfo = helper.analyzeRequest(currentRequest);
		
		List<String> headers =  reqInfo.getHeaders();
		
		List<String> updatedHeaders = new ArrayList<String>();
		boolean connectionUpdated = false;
		for (String h : headers){
			if (h.startsWith("Connection:")){
				updatedHeaders.add("Connection: close");
				connectionUpdated = true;
			} else if (!h.startsWith("User-Agent:"))
				updatedHeaders.add(h);
			else if (h.startsWith("User-Agent:") && !h.contains("ACMate"))
				updatedHeaders.add(h + " ACMate/" + currentUser.getUsername());
		}
		
		if (!connectionUpdated){
			updatedHeaders.add("Connection: close");
		}
		byte[] body = Arrays.copyOfRange(currentRequest, reqInfo.getBodyOffset(), currentRequest.length);
		byte[] updatedRequest = helper.buildHttpMessage(updatedHeaders, body);
		
		return updatedRequest;
	}


	



	/**
	 * Update the session cookies
	 * @param resInfo
	 */
	private void updateSessionCookie(IResponseInfo resInfo) {
		List<ICookie> toRemove = new ArrayList<ICookie>();
		for (ICookie c: resInfo.getCookies()){
			boolean found = false;
			for (BurpCookie storedCookie : cookies){
				if (storedCookie.getName().equals(c.getName())){
					found = true;
					// store for update
					toRemove.add(storedCookie);
					break;
				}
			}
			if (found)
				break;
		}
		for (ICookie c : toRemove){
			cookies.remove(c);
		}
		
		for (ICookie c: resInfo.getCookies()){
			cookies.add(new BurpCookie(c));
		}
	}
	
	/**
	 * Add contextual or hidden parameters
	 * @param request
	 * @param origRequest
	 * @return
	 */
	private byte[] addMissingParamsNUpdateRequestToCurrentSession(
			Request request, byte[] origRequest) {
		byte[] updatedRequest = Arrays.copyOf(origRequest, origRequest.length);
		
		// adding all cookies
		for (ICookie cookie : cookies){
			updatedRequest = helper.addParameter(updatedRequest, new BurpCookieParam(cookie));
		}
		
		if (request.hasServerParam()){
			List<BurpParameter> serverParam = request.getServerParams();
			
			// now make a GET request just to get 
			byte[] getRequest = helper.buildHttpRequest(request.getUrl());
			for (ICookie c : cookies){
				getRequest = helper.addParameter(getRequest, new BurpCookieParam(c));
			}
			
			getRequest = adjustHeaders(getRequest);
			
			IHttpRequestResponse getRR = callbacks.makeHttpRequest(service, getRequest);
			if (getRR != null && getRR.getResponse() != null){
				HtmlUtil htmlHelper = new HtmlUtil();
				htmlHelper.parse(helper.bytesToString(getRR.getResponse()));
				
				for (BurpParameter p : serverParam){
					List<String> values = htmlHelper.extractValues(request.getURLPath(), p.getName());
					if (values.size() > 0){
						p.setValue(values.get(0));
						updatedRequest = helper.updateParameter(updatedRequest, p);
					}
				}
			}
		}
		
		return updatedRequest;
	}

	/**
	 * Update the request to the current user by replacing cookie & header
	 * 
	 * @param binaRequest
	 * @return
	 */
	private byte[] updateRequestToCurrentSession(byte[] binaRequest) {
		byte[] request = Arrays.copyOf(binaRequest, binaRequest.length);
		IRequestInfo requestInfo = helper.analyzeRequest(request);
		
		List<IParameter> allParams = requestInfo.getParameters();
		
		for (IParameter param : allParams){
			if (param.getType() == IParameter.PARAM_COOKIE){
				request = helper.removeParameter(request, param);
			}
		}
		
		for (ICookie cookie : cookies){
			request = helper.addParameter(request, new BurpCookieParam(cookie));
		}

		return request;
	}

	/**
	 * Call makeHttpRequest to send a request and following redirections until a code #302 is returned.
	 *   
	 * @param callbacks
	 * @param service
	 * @param initRequest
	 * @return
	 * @throws SessionException 
	 */
	private IHttpRequestResponse makeAndFollowHttpRequest(byte[] initRequest) throws SessionException{
		if (callbacks == null || service == null)
			return null;
		
		IExtensionHelpers helper = callbacks.getHelpers();
		
		// make the first request
		IHttpRequestResponse rr = callbacks.makeHttpRequest(service, initRequest);
		
		IResponseInfo resInfo = helper.analyzeResponse(rr.getResponse());
				
		// server does not redirect, return. 
		if (resInfo.getStatusCode() != 302)
			return rr;
		else {
			
			IRequestInfo reqInfo = helper.analyzeRequest(initRequest);
			
			List<String> requestHeaders = reqInfo.getHeaders();
			String[] tmps = requestHeaders.get(0).split(" ");
			String relativeURL = tmps[1];

			while (resInfo.getStatusCode() == 302) {
				List<String> headers = resInfo.getHeaders();
				String newLocation = "";
				for (String header : headers){
					if (header.startsWith("Location:")){
						String[] tmp = header.split(" ");
						if (tmp.length == 2){
							newLocation = tmp[1];
						}
						break;
					}
				}
				
				if (newLocation.isEmpty())
					break;
				else {
					
					// update session cookies
					updateSessionCookie(resInfo);
					
					try {
						
						if (!newLocation.startsWith(service.getProtocol())){
							// relative new location, need to be updated 
							int lastIndex = relativeURL.lastIndexOf("/");
							if (lastIndex == -1)
								newLocation = getServiceURL() + "/" + newLocation;
							else {
								relativeURL = relativeURL.substring(0, lastIndex) + "/" + newLocation;
								newLocation = getServiceURL() + relativeURL;
							}
								
						}
						
						URL newLoc = new URL(newLocation);
						
					 	byte[] newRequest = helper.buildHttpRequest(newLoc);
					 	for (ICookie c : cookies){
					 		newRequest = helper.addParameter(newRequest, new BurpCookieParam(c));
					 	}
					 	
					 	IHttpRequestResponse newRR = callbacks.makeHttpRequest(service, newRequest);

					 	rr.setResponse(newRR.getResponse());
					 	resInfo = helper.analyzeResponse(newRR.getResponse());
					 	
					} catch (MalformedURLException e) {
						break;
					}
				}
				
			}
			return rr;
		}
	}
	
	
	private String getServiceURL() throws SessionException {
		if (service == null)
			throw new SessionException("HTTP Service is null, cannot get URL");
		
		String tmp = service.getProtocol() + "://" + service.getHost();
		if (service.getPort() != 80){
			tmp = tmp + ":" + service.getPort();
		}
		
		return tmp;
		
	}


	@Override
	public boolean equals(Object obj) {
		if (obj instanceof Session){
			if (globalId.equals(((Session) obj).getGlobalId()))
				return true;
		}
		return false;
	}

	
}
