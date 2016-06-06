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
package org.svv.acmate.utils;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.svv.acmate.burpsuite.BurpCookie;
import org.svv.acmate.burpsuite.BurpParameter;
import org.svv.acmate.executor.AccessResponse;
import org.svv.acmate.executor.Session;
import org.svv.acmate.model.Request;
import org.svv.acmate.model.TargetAppModel;
import org.svv.acmate.model.config.User;
import org.svv.acmate.model.sessions.ACTest;
import org.svv.acmate.model.sessions.Cookie;
import org.svv.acmate.model.sessions.Parameter;
import org.svv.acmate.model.sessions.Response;
import org.svv.acmate.model.sessions.Sessions;

import burp.IParameter;

public class SessionUtil {
	
	
	/**
	 * Save test results to xml files 
	 * @param testResults
	 */
	public boolean saveTestResult(List<Session> testResults, String filePath){
		Sessions obj = new Sessions();
		for (Session s : testResults){
			obj.getSession().add(marshalSession(s));
		}
		
		// save to file
		return JAXBUtil.saveSessions(obj, filePath);
	}
	
	
	/**
	 * Load test results to XML files
	 * @param filePath
	 * @param callbacks
	 * @param appModel
	 * @return
	 */
	public List<Session> loadTestResult(String filePath
//			, IBurpExtenderCallbacks callbacks
			, TargetAppModel appModel){
		
		if (appModel== null)
			return null;

		Sessions obj = JAXBUtil.loadSessions(filePath);
		if (obj == null)
			return null;
		
		List<Session> ret = new ArrayList<Session>();
		for (org.svv.acmate.model.sessions.Session storedSession : obj.getSession()){
			Session s = unmarshalSession(storedSession, appModel);
			ret.add(s);
		}
		
		return ret;
	}
	

	/**
	 * unmarshal a session, load stored session to create executable session 
	 * 
	 * @param s
	 * @param callbacks
	 * @param appModel
	 * @return
	 */
	public Session unmarshalSession(org.svv.acmate.model.sessions.Session s
//			, IBurpExtenderCallbacks callbacks
			, TargetAppModel appModel){
		
		User user = null;
		for (User u : appModel.getConfigModel().getUser()){
			if (u.getUsername().equals(s.getUser()) &&
					u.getRole().equals(s.getRole())){
				user = u;
				break;
			}
		}
		
		if (user == null){
			user = new User();
			user.setRole(s.getRole());
			user.setUsername(s.getUser());
		}
		
		List<Request> requests = new ArrayList<Request>();
		Map<Request, AccessResponse> sessionResults = new HashMap<Request, AccessResponse>();
		for (ACTest t : s.getACTest()){
			Request r = unmarshalRequest(t.getRequest());
			requests.add(r);
			sessionResults.put(r, unmarshalAccessResponse(t.getAccessResponse()));
		}
		
		Session execSession =  new Session(user, requests, null, appModel);
		execSession.setGlobalId(s.getId());
		for (Request r : sessionResults.keySet()){
			execSession.getSessionResults().put(r, sessionResults.get(r));
		}
		
		return execSession;
	}
	
	
	/**
	 * marshal/store a session
	 * @param s
	 * @return
	 */
	public org.svv.acmate.model.sessions.Session marshalSession(Session s){
		
		org.svv.acmate.model.sessions.Session db = new org.svv.acmate.model.sessions.Session();
		db.setId(s.getGlobalId());
		db.setRole(s.getCurrentUser().getRole());
		db.setUser(s.getCurrentUser().getUsername());
		db.setTimestamp(getCurrentTimestamp());
		
		Map<Request, AccessResponse> results = s.getSessionResults();
		for (Request r : results.keySet()){
			ACTest test = new ACTest();
			test.setRequest(marshalRequest(r));
			test.setAccessResponse(marshalAccessResponse(results.get(r)));
			db.getACTest().add(test);
		}
		
		Cookie cookie = new Cookie();
		List<BurpCookie> cookies = s.getCookies();
		for (BurpCookie cb : cookies){
			Parameter p = new Parameter();
			p.setName(cb.getName());
			p.setValue(cb.getValue());
			p.setType(IParameter.PARAM_COOKIE);
			cookie.getParameter().add(p);
		}
		
		db.setCookie(cookie);
		
		return db;
	}
	

	private org.svv.acmate.model.sessions.AccessResponse marshalAccessResponse(
			AccessResponse ar) {
		org.svv.acmate.model.sessions.AccessResponse ret = new org.svv.acmate.model.sessions.AccessResponse();
		ret.setPermissionColor(ar.getPermissionColor());
		ret.setResponseCode(ar.getResponseCode());
		
		Response resContent = new Response();
		resContent.setBase64(false);
		resContent.setValue(ar.getResponseContent());
		ret.setResponse(resContent);
		return ret;
	}

	private AccessResponse unmarshalAccessResponse(
			org.svv.acmate.model.sessions.AccessResponse ar) {
		
		String responseContent = "";
		if (ar.getResponse() != null)
			responseContent = ar.getResponse().getValue();
		AccessResponse ret = new AccessResponse(ar.getPermissionColor(), ar.getResponseCode(), responseContent);
		return ret;
	}



	/**
	 * get the system timestamp
	 * @return
	 */
	private String getCurrentTimestamp() {
		SimpleDateFormat dformater = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
		return dformater.format(new Date());
	}

	/**
	 * marshall a request
	 * @param r
	 * @return
	 */
	private org.svv.acmate.model.sessions.Request marshalRequest(Request r) {
		org.svv.acmate.model.sessions.Request ret  = new org.svv.acmate.model.sessions.Request();
		ret.setMethod(r.getMethod());
		ret.setUrl(r.getUrl().toString());
		
		for (IParameter p : r.getParameters()){
			if (p.getType() != IParameter.PARAM_COOKIE)
			{
				Parameter sp = new Parameter();
				sp.setName(p.getName());
				sp.setValue(p.getValue());
				sp.setType(p.getType());
				ret.getParameter().add(sp);
			}
		}
		
		return ret;
	}

	/**
	 * unmarshal a request
	 * @param r
	 * @return
	 */
	private Request unmarshalRequest(
			org.svv.acmate.model.sessions.Request r) {
		Request ret = new Request();
		ret.setMethod(r.getMethod());
		try {
			ret.setUrl(new URL(r.getUrl()));
		} catch (MalformedURLException e) {
			e.printStackTrace();
		}
		
		for (Parameter sp : r.getParameter()){
			BurpParameter p = new BurpParameter(sp.getName(), sp.getValue(), sp.getType());
			ret.getParameters().add(p);
		}
		
		return ret;
	}
}
