package com.jb.mpc.security.util;

import com.jb.mpc.security.config.DBConfig;
import org.springframework.beans.factory.annotation.Autowired;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * 授权过滤器提供对于建模工具请求过滤的忽略
 * 
 * @author ghz
 *
 */
public abstract class SecurityFilter implements Filter {

	/**
	 * 建模工具请求的参数标志
	 */
	private static final String MODELANGENT_PARAM_FLAG = "sendByAngent";

	@Autowired
	private DBConfig dBConfig;

	/*
	 * (non-Javadoc)
	 * 
	 * @see javax.servlet.Filter#doFilter(javax.servlet.ServletRequest,
	 * javax.servlet.ServletResponse, javax.servlet.FilterChain)
	 */
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		if (!isNeedFilter(request)) {
			chain.doFilter(request, response);
		} else {
			this.filter(request, response, chain);
		}

	}

	/**
	 * 
	 * @param request
	 *            请求request
	 * @param response
	 *            响应response
	 * @param chain
	 *            调用链
	 */
	public abstract void filter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException;

	/**
	 * 判断是否需要进行过滤
	 * 
	 * @param request
	 *            请求request
	 * @return
	 */
	private boolean isNeedFilter(ServletRequest request) {
		String content_Type = ((HttpServletRequest) request).getHeader("Content-Type");
		if (content_Type != null && content_Type.contains("multipart/form-data")) {
			return false;
		}
		String isSafe = dBConfig.getIsTransSafe();//是否通信数据传输安全模式
		if ( !"T".equals(isSafe)) {
			return false;
		}
		return true;
	}

}
