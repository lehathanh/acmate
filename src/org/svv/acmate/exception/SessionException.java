package org.svv.acmate.exception;

public class SessionException extends Exception {
	
	String message;

	public SessionException(String str) {
		super(str);
		message = str;
	}

	@Override
	public String getMessage() {
		return message;
	}

	
}
