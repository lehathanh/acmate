package org.svv.acmate.utils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.svv.acmate.model.filters.Filter;
import org.svv.acmate.model.filters.Filters;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;

public class PermissionUtil {
	
	public static final String COLOR_GREEN = "green";	// allowed
	public static final String COLOR_RED = "red";		// denied
	public static final String COLOR_ORANGE = "orange"; // conflicting filter rules
	public static final String COLOR_WHITE = "white"; // unclassified
	
	public static final String PERMISSION_ALLOWED = "allowed";	// allowed
	public static final String PERMISSION_DENIED = "denied";		// denied
	public static final String PERMISSION_F_CONFLICT = "filter_conflict"; // conflicting filter rules
	public static final String PERMISSION_UNKNOWN = "unclassified"; // unclassified
	
	public static final String[] ALL_PERMISIONS = {PERMISSION_ALLOWED, PERMISSION_DENIED, PERMISSION_F_CONFLICT, PERMISSION_UNKNOWN};
 	

	/**
	 * Get a color 
	 * @param filters
	 * @param rr
	 * @param helper
	 * @return
	 */
	public static String getColor(Filters filters, IHttpRequestResponse rr, IExtensionHelpers helper){
    	
    	if (rr.getResponse() != null){
        	List<String> colors = new ArrayList<String>();
        	
        	for (Filter filter : filters.getFilter()){
        		String c = getColor(filter, rr, helper);
        		if (c != null){
        			colors.add(c);
        		}
        	}
        	// check colors
        	if (colors.size() > 0){
        		boolean allGreen = true;
        		boolean allRed = true;
        		for (String c: colors){
        			allGreen = allGreen & (c.equals(COLOR_GREEN));
        			allRed = allRed & (c.equals(COLOR_RED));
        		}
        		
        		if (allGreen){
        			return COLOR_GREEN;
        		} else if (allRed){
        			return COLOR_RED;
        		} else {
        			// multiple conflicting rules have been applied applied
        			return COLOR_ORANGE;
        		}
        	}
    	}
		return COLOR_WHITE;
	}

	
    /**
     * Apply a filter to a request/response
     * 
     * @param filter
     * @param rr
     * @return 
     */
	public static String getColor(Filter filter, IHttpRequestResponse rr, IExtensionHelpers helper) {
		
		if (rr == null || rr.getResponse() == null)
			return null;
		
		IResponseInfo responseInfo = helper.analyzeResponse(rr.getResponse());
		IRequestInfo requestInfo = helper.analyzeRequest(rr.getRequest());
		
		try {
			Pattern methodPattern = null;
			if (filter.getMethodPattern() != null && !filter.getMethodPattern().getValue().isEmpty())
				methodPattern = Pattern.compile(filter.getMethodPattern().getValue());

			Pattern statusCodePattern = null;
			if (filter.getStatusCodePattern() != null && !filter.getStatusCodePattern().getValue().isEmpty())
				statusCodePattern = Pattern.compile(filter.getStatusCodePattern().getValue());
			
			Pattern urlPattern = null;
			if (filter.getURLPattern() != null && !filter.getURLPattern().getValue().isEmpty())
				urlPattern = Pattern.compile(filter.getURLPattern().getValue());
			
			
			Pattern contentPattern = null;
			if (filter.getContentPattern() != null && !filter.getContentPattern().getValue().isEmpty()) 
				contentPattern = Pattern.compile(filter.getContentPattern().getValue());

			// start matching
			boolean status = true;
			
			// method - match all
			if (status && methodPattern != null){
				boolean patternVal = methodPattern.matcher(requestInfo.getMethod()).matches();
				if (!getTruthValue(patternVal, filter.getMethodPattern().isMatched()))
					status  = false;
			}
			
			// status code - match all
			if (status && statusCodePattern != null){
				String statusCode = String.valueOf(responseInfo.getStatusCode());
				boolean patternVal = statusCodePattern.matcher(statusCode).matches();
				if (!getTruthValue(patternVal, filter.getStatusCodePattern().isMatched())){
					status  = false;
				}
			}
			
			// url - partial matching 
			if (status && urlPattern != null){
				String url = "";
				try {
					url = requestInfo.getUrl().toString();
				} catch (Exception e){
//					java.lang.UnsupportedOperationException: This IRequestInfo object was created without any HTTP service details, so the full request URL is not available. To obtain the full URL, use one of the other overloaded methods in IExtensionHelpers to analyze the request.
//					at burp.zug.getUrl(Unknown Source)
					if (requestInfo.getHeaders().size() > 0){
						String firstLine = requestInfo.getHeaders().get(0); //first line
						String[] tmp = firstLine.split(" ");
						if (tmp.length == 3)
							url = tmp[1];
					}
				}
				if (!url.isEmpty()){
					boolean patternVal = urlPattern.matcher(url).find();
					
					if (!getTruthValue(patternVal, filter.getURLPattern().isMatched())){
						status = false;
					}
				}
			}
			
			// content - partial matching
			if (status && contentPattern != null){
				int contentIndex = responseInfo.getBodyOffset();
				if (contentIndex > 0){
					// 
					byte[] body = Arrays.copyOfRange(rr.getResponse(), contentIndex, rr.getResponse().length);
					String content = helper.bytesToString(body);
					boolean patternVal = contentPattern.matcher(content).find();
					if (!getTruthValue(patternVal, filter.getContentPattern().isMatched())){
						status = false;
					}
//				} else if (".*".equals(filter.getContentPattern().getValue())) {
//					// special pattern for all content
//					status = true;
				} else {
					status = false;
				}
			}
			
			// !!! matched
			if (status){
				if (filter.getPermission().equals(Filter.FILTER_PERMISSION_ALLOWED))
					return COLOR_GREEN;
				else 
					return COLOR_RED;
			}
			
			return null;
		
		} catch (PatternSyntaxException psEx){
			psEx.printStackTrace();
		} catch (Exception e){
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * Get the truth value:
	 * patternValue matchedValue
	 * 0 0 1
	 * 0 1 0
	 * 1 0 0
	 * 1 1 1
	 * @param patternValue
	 * @param matchedValue
	 * @return
	 */
	private static boolean getTruthValue(boolean patternValue, boolean matchedValue){
		if (!patternValue && !matchedValue)
			return true;
		
		return patternValue && matchedValue;
	}

	public static String toPermission(String color) {
		if (color.equals(COLOR_GREEN)) {
			return PERMISSION_ALLOWED;
		} else if (color.equals(COLOR_RED)) {
			return PERMISSION_DENIED;
		} else if (color.equals(COLOR_ORANGE)) {
			return PERMISSION_F_CONFLICT;
		} else if (color.equals(COLOR_WHITE)) {
			return PERMISSION_UNKNOWN;
		}
		return null;
	}
}
