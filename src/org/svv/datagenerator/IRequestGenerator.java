package org.svv.datagenerator;

import java.util.List;

import org.svv.acmate.model.Request;
import org.svv.xinput.Page;

public interface IRequestGenerator {
	public List<Request> generate(Page page, String basedURL);
}
