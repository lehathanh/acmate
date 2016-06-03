package org.svv.acmate.burpsuite;

import java.util.Date;

import burp.ICookie;

public class BurpCookie implements ICookie {
	
	private String domain;
	private Date expiration;
	private String name;
	private String value;
	
	@Override
	public String getDomain() {
		return domain;
	}

	@Override
	public Date getExpiration() {
		return expiration;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getValue() {
		return value;
	}

	public BurpCookie(String domain, Date expiration, String name, String value) {
		super();
		this.domain = domain;
		this.expiration = expiration;
		this.name = name;
		this.value = value;
	}
	
	public BurpCookie(ICookie cookie){
		this.domain = cookie.getDomain();
		this.expiration = cookie.getExpiration();
		this.name = cookie.getName();
		this.value = cookie.getValue();
	}
	
	public void update(ICookie cookie){
		this.domain = cookie.getDomain();
		this.expiration = cookie.getExpiration();
		this.name = cookie.getName();
	}
}
