package org.svv.acmate.executor;

public class AccessResponse {
	private String permissionColor;
	private String responseCode;
	private String responseContent;
	
	public String getPermissionColor() {
		return permissionColor;
	}
	public void setPermissionColor(String permissionColor) {
		this.permissionColor = permissionColor;
	}
	public String getResponseCode() {
		return responseCode;
	}
	public void setResponseCode(String responseCode) {
		this.responseCode = responseCode;
	}
	
	public AccessResponse(String permissionColor, String responseCode, String responseContent) {
		this.permissionColor = permissionColor;
		this.responseCode = responseCode;
		this.responseContent = responseContent;
	}
	public String getResponseContent() {
		return responseContent;
	}
	public void setResponseContent(String responseContent) {
		this.responseContent = responseContent;
	}
	
	
	
}
