package com.jb.mpc.security.util;

import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class ResponseUtil {

	public static void returnResponse(ServletResponse response, String responseText, int status) throws IOException {
		HttpServletResponse servletResponse = (HttpServletResponse) response;
		servletResponse.setStatus(status);
		servletResponse.setContentType("text/html;charset=UTF-8");
		PrintWriter out = response.getWriter();
		out.print(responseText);
		out.flush();
		out.close();
	}

}
