package org.svv.acmate.model;

import java.util.List;

public class RequestHeader {
	
	List<String> headers;
	
	public RequestHeader(List<String> headers) {
		this.headers = headers;
	}

	public String getReferer() {
		for (String header : headers){
			if (header.startsWith("Referer: ")){
				return header.split(" ")[1];
			}
		}
	
		return null;
	}

}
