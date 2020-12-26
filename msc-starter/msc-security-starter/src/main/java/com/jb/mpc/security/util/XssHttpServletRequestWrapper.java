/*
 * Copyright (C), 北京中恒博瑞数字电力技术有限公司，保留所有权利.
 * FileName: XssHttpServletRequestWrapper.java
 * History：
 * <author>         <time>             <version>      <desc>
 *   GHZ     2017年8月1日下午6:30:10        V1.0         TODO
 */
package com.jb.mpc.security.util;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

/**
 * 
 * @Package: com.jb.f1.security.xss<br>
 * @ClassName: XssHttpServletRequestWrapper<br>
 * @Description: xss处理sql包装类<br>
 */
public class XssHttpServletRequestWrapper extends HttpServletRequestWrapper {

	public XssHttpServletRequestWrapper(HttpServletRequest servletRequest) {
		super(servletRequest);
	}

	public String[] getParameterValues(String parameter) {
		String[] values = super.getParameterValues(parameter);
		if (values == null) {
			return null;
		}
		int count = values.length;
		String[] encodedValues = new String[count];
		for (int i = 0; i < count; i++) {
			encodedValues[i] = cleanXSS(values[i]);
		}
		return encodedValues;
	}

	public String getParameter(String parameter) {
		String value = super.getParameter(parameter);
		if (value == null) {
			return null;
		}
		return cleanXSS(value);
	}

	public String getHeader(String name) {
		String value = super.getHeader(name);
		if (value == null)
			return null;
		if(!"Accept".equals(name)){
			return cleanXSS(value);
		}else{
			return value;
		}

	}

	private String cleanXSS(String value) {
		// You'll need to remove the spaces from the html entities below
		value = value.replaceAll("<", "& lt;").replaceAll(">", "& gt;");
//		value = value.replaceAll("\\(", "& #40;").replaceAll("\\)", "& #41;");
//		value = value.replaceAll("'", "& #39;");
		value = value.replaceAll("eval\\((.*)\\)", "");
		value = value.replaceAll("[\\\"\\\'][\\s]*javascript:(.*)[\\\"\\\']", "\"\"");
		value = value.replaceAll("javascript", "");
		value = value.replaceAll("script", "");
		value = value.replaceAll("alert", "");
		value = value.replaceAll("iframe", "");
//
//		value = MatcherUtil.replaceBlank(value);
		return value;
	}
	
}