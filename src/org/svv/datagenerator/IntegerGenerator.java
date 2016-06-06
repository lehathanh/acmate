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

public class IntegerGenerator implements IDataGenerator {
	private static Random ranGenerator = new Random();
	
	@Override
	public String generate(ComplexDataSpecType dataClz) {
		List<Object> facets =  dataClz.getFacets();
		
		Long min = Long.MIN_VALUE;
		Long max = Long.MAX_VALUE;
		boolean minPresent = false;
		boolean maxPresent = false;
		
		for (Object o : facets) {
			// Find the facet that specify the min/max inclusive value
			if (o instanceof JAXBElement) {
				JAXBElement tmp = (JAXBElement)o;
				String constraintType = tmp.getName().getLocalPart();
				if (constraintType.equals(IDataGenerator.DOMAIN_CONSTRAINT_MINEXCLUSIVE)
						|| constraintType.equals(IDataGenerator.DOMAIN_CONSTRAINT_MININCLUSIVE)) {
					// treat these two type equally
					Facet valueFacet = (Facet) tmp.getValue();
					String value = valueFacet.getValue();
					try {
						min = Long.valueOf(value);
						minPresent = true;
					} catch (NumberFormatException e) {
						e.printStackTrace();
					}
				}

				if (constraintType.equals(IDataGenerator.DOMAIN_CONSTRAINT_MAXEXCLUSIVE)
						|| constraintType.equals(IDataGenerator.DOMAIN_CONSTRAINT_MAXINCLUSIVE)) {
					// treat these two type equally
					Facet valueFacet = (Facet) tmp.getValue();
					String value = valueFacet.getValue();
					try {
						max = Long.valueOf(value);
						maxPresent = true;
					} catch (NumberFormatException e) {
						e.printStackTrace();
					}
				}
			}
			
			if (minPresent && maxPresent){
				return String.valueOf(min.longValue() + (long)(ranGenerator.nextDouble() 
							* (max.doubleValue() - min.doubleValue())));
			}
		}
		
		double DELTA = 1;
		
		if (minPresent){
			return String.valueOf(min.longValue() + (long)(ranGenerator.nextDouble() * min.doubleValue()) + DELTA);
		} 
		
		if (maxPresent){
			return String.valueOf((long)(ranGenerator.nextDouble() * max.doubleValue()) - DELTA); 
		}
					
		return "0";
	}

}
