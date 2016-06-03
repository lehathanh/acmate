package org.svv.acmate.burpsuite;

import burp.IParameter;

public class BurpParameter implements IParameter {
	
	private String name;
	private String value;
	private byte type;
	
	private int nameStart;
	private int nameEnd;
	private int valueStart;
	private int valueEnd;

	@Override
	public byte getType() {
		return type;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getValue() {
		return value;
	}

	@Override
	public int getNameStart() {
		return nameStart;
	}

	@Override
	public int getNameEnd() {
		return nameEnd;
	}

	@Override
	public int getValueStart() {
		return valueStart;
	}

	@Override
	public int getValueEnd() {
		return valueEnd;
	}
	
	public BurpParameter(String name, String value, byte type) {
		this.name = name;
		this.value = value;
		this.type = type;
		
		this.nameStart = -1;
		this.nameEnd = -1;
		this.valueStart = -1;
		this.valueEnd = -1;
	}

	public BurpParameter(String name, String value) {
		this.name = name;
		this.value = value;
		
		this.type = IParameter.PARAM_BODY; //default
		
		this.nameStart = -1;
		this.nameEnd = -1;
		this.valueStart = -1;
		this.valueEnd = -1;
	}

	
	public void setValue(String value) {
		this.value = value;
	}
	
}
