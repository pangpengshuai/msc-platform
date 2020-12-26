/*
 * Copyright (C), 北京中恒博瑞数字电力技术有限公司，保留所有权利.
 * FileName: XssFilter.java
 * History：
 * <author>         <time>             <version>      <desc>
 *   GHZ     2017年8月1日下午3:29:37        V1.0         TODO
 */
package com.jb.mpc.security.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.jb.mpc.security.config.DBConfig;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * 
 * @Package: com.jb.f1.security.filter<br>
 * @ClassName: XssFilter<br>
 * @Description: 防范xss攻击，敏感字符过滤器<br>
 */
@Component("xssFilter")
public class XssFilter implements Filter{


	@Autowired
	private DBConfig dBConfig;
	/**
	 * 日志
	 */
	private final Logger log = LoggerFactory.getLogger(this.getClass());  


	FilterConfig filterConfig = null;

    public void init(FilterConfig filterConfig) throws ServletException {
        this.filterConfig = filterConfig;
    }

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		if (!isNeedFilter(request)) {
			chain.doFilter(request, response);
		} else {
			this.filter(request, response, chain);
		}

	}

	public void destroy() {
        this.filterConfig = null;
    }

    public void filter(ServletRequest request, ServletResponse response,
            FilterChain chain) throws IOException, ServletException {
    	
    	log.info("进行xss过滤操作");
		//判断是否是服务间调用
		if(FilterUtil.isInterService(request)) {
			chain.doFilter(request, response);
			return;
		}
    	HttpServletRequest servletRequest = (HttpServletRequest) request;
    	String sendByAngent = servletRequest.getParameter("sendByAngent") == null ? "false"
				: servletRequest.getParameter("sendByAngent");
    	//如果是模型工具过来的就不走过滤器
    	if ("true".equals(sendByAngent)) {
    		log.info("进行xss过滤完成");
			chain.doFilter(request, response);
			return;
		}
    	StringBuffer urlFist =  ((HttpServletRequest) request).getRequestURL();
    	 if(urlFist != null){
    		 String url = cleanXSS(urlFist.toString());
    		 boolean isXss = isXss(urlFist.toString());
    		 if(urlFist.toString().length() != url.length() || isXss == true){
    			HttpServletResponse respons = (HttpServletResponse)response;
    			respons.setStatus(607);
    			response.setContentType("text/html;charset=UTF-8");
				PrintWriter out = respons.getWriter();
				out.print("存在xss注入风险");
				out.flush();
				out.close();
    			((HttpServletResponse) response).sendError(607,"存在xss注入风险");
    		 }
    	 }
    	log.info("进行xss过滤完成");
        chain.doFilter(new XssHttpServletRequestWrapper(
                (HttpServletRequest) request), response);
//        chain.doFilter(request, response);
       
    }
    private boolean isXss(String value){
    	String[] values =  value.split("alter");
    	if(values.length > 1){
    		return true;
    	}
    	values = value.split("iframe");
    	if(values.length > 1){
    		return true;
    	}
    	values = value.split("<");
    	if(values.length > 1){
    		return true;
    	}
    	values = value.split(">");
    	if(values.length > 1){
    		return true;
    	}
    	return false;
    	
    }
    private String cleanXSS(String value) {
//    	value = circleClear(value,Pattern.compile("%20"),"");
    	value = circleClear(value,Pattern.compile("%3Cscript%3E"),"");
    	value = circleClear(value,Pattern.compile("%3C/script%3"),"");
    	value = circleClear(value,Pattern.compile("%3Ciframe"),"");
		value = circleClear(value,Pattern.compile("<"),"");
		value = circleClear(value,Pattern.compile(">"),"");
		value = circleClear(value,Pattern.compile("eval\\((.*)\\)"),"");
		value = circleClear(value,Pattern.compile("[\\\"\\\'][\\s]*javascript:(.*)[\\\"\\\']"),"");
		value = circleClear(value,Pattern.compile("javascript"),"");
		value = circleClear(value,Pattern.compile("alter"),"");
		value = circleClear(value,Pattern.compile("iframe"),"");
		return value;
	}
    private String circleClear(String value,Pattern pattern, String replace) {
		// Pattern taskUserPattern = Pattern.compile(EXCUTED_TASK_USER);
		if (StringUtils.isEmpty(value)) {
			return value;
		} else {
			Matcher matcher = pattern.matcher(value);
			boolean isHave = false;
			while (matcher.find()) {
				String param = matcher.group();
				value = value.replaceAll(param, replace);
				isHave = true;
			}
			if (!isHave) {
				return value;
			} else {
				return circleClear(value,pattern, replace);
			}
		}
	}

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
		//		return false;
		}
		String isSafe = dBConfig.getIsXssSafe();// 是否xss安全模式
		if ( !"T".equals(isSafe) ) {
			return false;
		}
		return true;
	}

	/**
	 * 过滤json类型的
	 * @param builder
	 * @return
	 */
	@Bean
	@Primary
	public ObjectMapper xssObjectMapper(Jackson2ObjectMapperBuilder builder) {
		//解析器
		ObjectMapper objectMapper = builder.createXmlMapper(false).build();
		//注册xss解析器
		SimpleModule xssModule = new SimpleModule("XssStringJsonSerializer");
		xssModule.addSerializer(new XssStringJsonSerializer());
		objectMapper.registerModule(xssModule);
		//返回
		return objectMapper;
	}

}
