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
