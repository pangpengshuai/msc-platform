package com.jb.mpc.security.util;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;

public class FilterUtil {

	public static boolean isInterService(ServletRequest request) {
		HttpServletRequest req=(HttpServletRequest) request;
		String isInterService=req.getHeader("isInterService");
		if(null!=isInterService && isInterService.equals("true")) {
			return true;
		}
		return false;
	}

}