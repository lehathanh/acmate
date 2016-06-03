package org.svv.html;

public class WebInputElement {
	
	public static final String INPUT_TYPE_TEXT = "text";
	public static final String INPUT_TYPE_HIDDEN = "hidden";
	public static final String INPUT_TYPE_PASSWORD = "password";
	public static final String INPUT_TYPE_SUBMIT = "submit";
	
	
	private String id;
	private String name;
	private String value;
	private String type;
	
	public WebInputElement(String name, String value) {
		this.name = name;
		this.value = value;
		this.type = INPUT_TYPE_TEXT;
	}

	public WebInputElement(String name, String value, String type) {
		this.name = name;
		this.value = value;
		this.type = type;
	}

	public WebInputElement(String id, String name, String value, String type) {
		this.id = id;
		this.name = name;
		this.value = value;
		this.type = type;
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getValue() {
		return value;
	}

	public void setValue(String value) {
		this.value = value;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	
}
