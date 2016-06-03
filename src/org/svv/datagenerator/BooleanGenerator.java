package org.svv.datagenerator;

import java.util.Random;

import org.svv.xinput.ComplexDataSpecType;


public class BooleanGenerator implements IDataGenerator {
	private static Random ranGenerator = new Random();

	@Override
	public String generate(ComplexDataSpecType dataClz) {
		return String.valueOf(ranGenerator.nextBoolean());
	}

}
