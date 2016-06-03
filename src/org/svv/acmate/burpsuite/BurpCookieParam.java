package org.svv.acmate.burpsuite;

import org.svv.acmate.model.KeyValue;

import burp.ICookie;
import burp.IParameter;

public class BurpCookieParam implements IParameter {
	
	private KeyValue keyvalue;
	

	@Override
	public byte getType() {
		return PARAM_COOKIE;
	}

	@Override
	public String getName() {
		return keyvalue.key;
	}

	@Override
	public String getValue() {
		return keyvalue.value;
	}

	@Override
	public int getNameStart() {
		return -1;
	}

	@Override
	public int getNameEnd() {
		return -1;
	}

	@Override
	public int getValueStart() {
		return -1;
	}

	@Override
	public int getValueEnd() {
		return -1;
	}
	
	public void setValue(String newValue){
		this.keyvalue.value = newValue;
	}

	public BurpCookieParam(KeyValue keyvalue) {
		this.keyvalue = keyvalue;
	}

	public BurpCookieParam(ICookie cookie) {
		this.keyvalue = new KeyValue(cookie.getName(), cookie.getValue());
	}

}
