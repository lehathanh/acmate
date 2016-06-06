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
package org.svv.datagenerator;

import org.svv.xinput.ComplexDataSpecType;


public interface IDataGenerator {
	
	public static final String DOMAIN_CONSTRAINT_MINEXCLUSIVE = "minExclusive";
	public static final String DOMAIN_CONSTRAINT_MININCLUSIVE = "minInclusive";
	public static final String DOMAIN_CONSTRAINT_MAXEXCLUSIVE = "maxExclusive";
	public static final String DOMAIN_CONSTRAINT_MAXINCLUSIVE = "maxInclusive";
	public static final String DOMAIN_CONSTRAINT_TOTALDIGITS = "totalDigits";
	public static final String DOMAIN_CONSTRAINT_FRACTIONDIGITS = "fractionDigits";
	public static final String DOMAIN_CONSTRAINT_LENGTH = "length";
	public static final String DOMAIN_CONSTRAINT_MINLENGTH = "minLength";
	public static final String DOMAIN_CONSTRAINT_MAXLENGTH = "maxLength";
	public static final String DOMAIN_CONSTRAINT_ENUMERATION = "enumeration";
	public static final String DOMAIN_CONSTRAINT_WHITESPACE = "whiteSpace";
	public static final String DOMAIN_CONSTRAINT_PATTERN = "pattern";
	
	
	public static final String[] DOMAIN_CONSTRAINT_TYPES = {
		DOMAIN_CONSTRAINT_MINEXCLUSIVE,
		DOMAIN_CONSTRAINT_MININCLUSIVE,
		DOMAIN_CONSTRAINT_MAXEXCLUSIVE,
		DOMAIN_CONSTRAINT_MAXINCLUSIVE,
		DOMAIN_CONSTRAINT_TOTALDIGITS,
		DOMAIN_CONSTRAINT_FRACTIONDIGITS,
		DOMAIN_CONSTRAINT_LENGTH,
		DOMAIN_CONSTRAINT_MINLENGTH,
		DOMAIN_CONSTRAINT_MAXLENGTH,
		DOMAIN_CONSTRAINT_ENUMERATION,
		DOMAIN_CONSTRAINT_WHITESPACE,
		DOMAIN_CONSTRAINT_PATTERN
	};
	
	public String generate(ComplexDataSpecType dataClz);
}
