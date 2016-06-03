package org.svv.acmate.model;

import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import org.svv.GlobalConstants;
import org.svv.acmate.burpsuite.BurpParameter;
import org.svv.acmate.utils.PermissionUtil;

import burp.IHttpRequestResponse;
import burp.IParameter;

public class Request {
	
	public static final String REQUEST_SOURCE_PROXY = "REQUEST_SOURCE_PROXY"; 		// request extracted from BurpSuite proxy
	public static final String REQUEST_SOURCE_COMBIGEN = "REQUEST_SOURCE_COMBIGEN"; // request generated from combinatorial testing
	
	public static final byte PARAM_SOURCE_USER = 0;
	public static final byte PARAM_SOURCE_SERVER = 1;
	
	private String originalSource; // can receive only one of the two values REQUEST_SOURCE_PROXY and REQUEST_SOURCE_COMBIGEN
	
	private URL url = null;
	private RequestHeader header = null;
	private String method;
	private IHttpRequestResponse burpRR;
	
	List<BurpParameter> parameters;
	List<Request> predecesors;
	
	private byte[] paramSource;
	private static final int DEFAULT_LIMIT_PARAMS = 20;
	
	private String color = PermissionUtil.COLOR_WHITE;  // assigned with filters are applied, default = WHITE
	
	public Request() {
		parameters = new ArrayList<BurpParameter>();
		predecesors = new ArrayList<Request>();
		
		paramSource = new byte[DEFAULT_LIMIT_PARAMS]; // default 50 bytes for 50 parameters, will reside when needed
		Arrays.fill(paramSource, PARAM_SOURCE_USER); // default all are user inputs
	}
	
	public String getOriginalSource() {
		return originalSource;
	}

	public void setOriginalSource(String originalSource) {
		if (REQUEST_SOURCE_COMBIGEN.equals(originalSource))
			this.originalSource = REQUEST_SOURCE_COMBIGEN;
		else if (REQUEST_SOURCE_PROXY.equals(originalSource))
			this.originalSource = REQUEST_SOURCE_PROXY;
		else 
			this.originalSource = "";
	}

	public IHttpRequestResponse getBurpRR() {
		return burpRR;
	}

	public void setBurpRR(IHttpRequestResponse burpRR) {
		this.burpRR = burpRR;
	}
	
	public URL getUrl() {
		return url;
	}

	public void setUrl(URL url) {
		this.url = url;
	}

	public RequestHeader getHeader() {
		return header;
	}

	public void setHeader(RequestHeader header) {
		this.header = header;
	}

	public void addParam(BurpParameter kv){
		parameters.add(kv);
		if (parameters.size() > paramSource.length){
			paramSource = Arrays.copyOf(paramSource, paramSource.length + 10); //add 10 more places with 0 as default param source type
		}
	}

	public void addParam(BurpParameter kv, byte sourceType){
		parameters.add(kv);
		if (parameters.size() > paramSource.length){
			paramSource = Arrays.copyOf(paramSource, paramSource.length + 10); //add 10 more places
		}
		// last index 
		paramSource[parameters.size() - 1] = sourceType;
	}
	
	/**
	 * 
	 * @param p
	 * @param sourceType
	 */
	public void setParamSourceType(BurpParameter p, byte sourceType){
		for (int i= 0; i < parameters.size(); i++){
			if (parameters.get(i).equals(p)){
				paramSource[i] = sourceType;
				break;
			}
		}
	}
	
	public byte getParamSourceType(BurpParameter p){
		for (int i= 0; i < parameters.size(); i++){
			if (parameters.get(i).equals(p)){
				return paramSource[i];
			}
		}
		return PARAM_SOURCE_USER; // default 
	}
	
	
	/** 
	 * Check if Request has a parameter whose values are generated 
	 * by the server
	 * 
	 * @return
	 */
	public boolean hasServerParam(){
		for (int i= 0; i < parameters.size(); i++){
			if (paramSource[i] == PARAM_SOURCE_SERVER) {
				return true;
			}
		}
		
		return false;
	}
	
	/**
	 * get all parameters whose values are updated at runtime
	 * by the server
	 * 
	 * @return
	 */
	public List<BurpParameter> getServerParams(){
		List<BurpParameter> serverParam = new ArrayList<BurpParameter>();
		for (BurpParameter p : getParameters()){
			if (getParamSourceType(p) == Request.PARAM_SOURCE_SERVER){
				serverParam.add(p);
			}
		}	
		
		return serverParam;
	}
	

	public void addPredecesor(Request request){
		predecesors.add(request);
	}


	public void setMethod(String method) {
		this.method = method;
	}
	

	/**
	 * Get the list of predecesor
	 * @return
	 */
	public List<Request> getPredecesors() {
		return predecesors;
	}
	
	public String getMethod() {
		return method;
	}

	public String getURLPath(){
		
		String tmp = this.getUrl().getPath();
		if (GlobalConstants.REMOVE_ENDING_SLASH && tmp.endsWith("/"))
			tmp = tmp.substring(0, tmp.length() - 1);
		return tmp;
	}

	public List<BurpParameter> getParameters() {
		return parameters;
	}

	
	/**
	 * Compare if two requests have the same path and set of parameters
	 * @param other
	 * @return
	 */
	public boolean metaEquals(Request other) {
		if (other == null)
			return false;
		else {
			if (!this.getURLPath().equals(other.getURLPath())){
				return false;
			} else if (!GlobalConstants.GROUP_REQUEST_TO_RESOURCE)
					return true;
			else {
				Set<String> setParamName1 = new HashSet<String>();
				Set<String> setParamName2 = new HashSet<String>();
				
				for (IParameter p : this.getParameters()){
					if (p.getType() != IParameter.PARAM_COOKIE)
						setParamName1.add(p.getName());
				}

				for (IParameter p : other.getParameters()){
					if (p.getType() != IParameter.PARAM_COOKIE)
						setParamName2.add(p.getName());
				}
				
				if (setParamName1.size() != setParamName2.size()){
					return false;
				} else {
					if (!setParamName1.containsAll(setParamName2)){
						return false;
					}
					
					if (!setParamName2.containsAll(setParamName1)){
						return false;
					}
				}
			}
		}
		
		return true;
	}
	
	/**
	 * return resourceID: URL?<list_of_params>
	 * Parameters in list is shorted alphabetically.
	 * 
	 * @return
	 */
	public String getResourceId() {
		String id = this.getURLPath() + "?";
		
		Set<String> setParamName = new TreeSet<String>();
		
		for (IParameter p : this.getParameters()) {
			if (p.getType() != IParameter.PARAM_COOKIE) 
				setParamName.add(p.getName());
		}
		
		for (String paramName : setParamName) {
			id += paramName + "=&";
		}
		
		return id;
		
	}

	public String getColor() {
		return color;
	}

	public void setColor(String color) {
		this.color = color;
	}
	
}
