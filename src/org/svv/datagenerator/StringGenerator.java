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

import java.util.List;
import java.util.Random;

import javax.xml.bind.JAXBElement;

import org.svv.xinput.ComplexDataSpecType;
import org.svv.xinput.Facet;
import org.svv.xinput.Pattern;

import nl.flotsam.xeger.Xeger;


public class StringGenerator implements IDataGenerator {

	private static String TOKENS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	private static Random ranGenerator = new Random();
	
	/**
	 * Generate randomly a string of length: len
	 * @param len
	 * @return
	 */
	private String generateString(int len){
		String ret = "";//= Constants.STRING_QUOTE;
		for (int i = 0; i < len; i++) {
			ret += TOKENS.charAt(ranGenerator.nextInt(TOKENS.length()));
		}
		return ret; // + Constants.STRING_QUOTE;
	}
	
	@Override
	public String generate(ComplexDataSpecType dataClz) {
		List<Object> facets =  dataClz.getFacets();
		
		for (Object o : facets) {
			// Find the facet that specify the min, max, or len, or pattern value
			if (o instanceof JAXBElement) {
				JAXBElement tmp = (JAXBElement)o;
				String constraintType = tmp.getName().getLocalPart();
				if (constraintType.equals(IDataGenerator.DOMAIN_CONSTRAINT_MINLENGTH)) {
					// treat these two type equally
					Facet valueFacet = (Facet) tmp.getValue();
					String value = valueFacet.getValue();
					try {
						int min = Integer.valueOf(value).intValue();
						return generateString(min + 1);
					} catch (NumberFormatException e) {
						e.printStackTrace();
					}
				}

				if (constraintType.equals(IDataGenerator.DOMAIN_CONSTRAINT_MAXLENGTH)
						|| constraintType.equals(IDataGenerator.DOMAIN_CONSTRAINT_LENGTH)) {
					// treat these two type equally
					Facet valueFacet = (Facet) tmp.getValue();
					String value = valueFacet.getValue();
					try {
						int max = Integer.valueOf(value).intValue();
						return generateString(max);
					} catch (NumberFormatException e) {
						e.printStackTrace();
					}
				}
			}
			
			if (o instanceof Pattern){
				Pattern pattern = (Pattern) o;
				String regex = pattern.getValue();

				// generate a new string that satisfies the RegEx
				return generateRegexString(regex);
			}
		}
		
		return dataClz.getName();
	}

	
	/**
	 * Generate a string that matches a regular expression
	 * @param regex
	 * @return
	 */
	private String generateRegexString(String regex){
		Xeger generator = new Xeger(regex);
		String result = generator.generate();
		return result;
	}
}
