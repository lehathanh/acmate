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

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Random;

import javax.xml.bind.JAXBElement;

import org.svv.xinput.ComplexDataSpecType;
import org.svv.xinput.Facet;


public class DateGenerator implements IDataGenerator {
	private static Random ranGenerator = new Random();

	@Override
	public String generate(ComplexDataSpecType dataClz) {
		DateFormat formatter = new SimpleDateFormat("dd/MM/yyyy");
		
		List<Object> facets =  dataClz.getFacets();
		
		Date min = new Date();
		Date max = new Date();
		try {
			min = formatter.parse("01/01/1900");
			max = formatter.parse("31/12/2999");
		} catch (ParseException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
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
						min = formatter.parse(value);
						minPresent = true;
					} catch (ParseException e) {
						e.printStackTrace();
					}
				}

				if (constraintType.equals(IDataGenerator.DOMAIN_CONSTRAINT_MAXEXCLUSIVE)
						|| constraintType.equals(IDataGenerator.DOMAIN_CONSTRAINT_MAXINCLUSIVE)) {
					// treat these two type equally
					Facet valueFacet = (Facet) tmp.getValue();
					String value = valueFacet.getValue();
					try {
						max = formatter.parse(value);
						maxPresent = true;
					} catch (ParseException e) {
						e.printStackTrace();
					}
				}
			}
			
			if (minPresent && maxPresent){
				long distance = max.getTime() - min.getTime();
				if (distance > 0){
					double d = ranGenerator.nextDouble();
					Date genDate = new Date(min.getTime() + (long)(d * distance));
					return formatter.format(genDate);
				}
			}
		}
		
		long DELTA = 86398; // 2 days
		
		if (minPresent){
			Date genDate = new Date(min.getTime() + DELTA);
			return formatter.format(genDate);		
		} 
		
		if (maxPresent){
			Date genDate = new Date(max.getTime() - DELTA);
			return formatter.format(genDate);		 
		}
					
		Date currentDate = new Date();
		return formatter.format(currentDate);
	}

}
