/*
 * Copyright (C), 北京中恒博瑞数字电力技术有限公司，保留所有权利.
 * FileName: DecryptionFilter.java
 * History：
 * <author>         <time>             <version>      <desc>
 *   Ghz     2013-11-7下午07:10:09        V1.0         TODO
 */
package com.jb.mpc.security.util;

import com.jb.mpc.security.config.DBConfig;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.BufferedReader;
import java.io.IOException;
import java.net.URLDecoder;
import java.util.*;



/**
 * @Package: com.jb.sys.security.filter.impl<br>
 * @ClassName: DecryptionFilter<br>
 * @Description: DecryptionFilter过滤类，用来校验是否完整性及保密性<br>
 */
@Component("decryptionFilter")
public class DecryptionFilter  extends SecurityFilter {

	/**
	 * 请求加密
	 */
	private static final String SSL_LINK = "SSL_LINK";

	/**
	 * 数据
	 */
	private static final String SSL_DATA = "SSL_PA1";

	/**
	 * 公钥
	 */
	private static final String SSL_KEY = "SSL_PA3";

	/**
	 * 完整性保护算法
	 */
	private static final String SSL_PROTECT = "SSL_PA2";

	/**
	 * 请求类型
	 */
	private static final String REQUEST_TYPE = "REQUEST_TYPE";

	@Autowired
	private DBConfig dBConfig;

	private final Logger log = LoggerFactory.getLogger(getClass());

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.jb.sys.security.filter.Order#getOrder()
	 */
	public Integer getOrder() {
		return 2;
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.jb.security.filter.BaseFilter#doFilter(javax.servlet.ServletRequest,
	 * javax.servlet.ServletResponse, com.jb.security.filter.data.FilterParams)
	 */
	@SuppressWarnings("unchecked")
	public void filter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		log.info("DecryptionFilter开始");
		// 判断是否是服务间调用
		if (FilterUtil.isInterService(request)) {
			chain.doFilter(request, response);
			return;
		}
		HttpServletRequest req = (HttpServletRequest) request;
		String header = req.getHeader("Content-Type");

		// 一般请求头
		Map<String, String[]> map = null;
		boolean SSL = false;
		String[] params = null;
		if (header == null || header.contains("application/x-www-form-urlencoded")) {
			map = request.getParameterMap();
			String[] _SSL = map.get(SSL_LINK);
			SSL = _SSL == null ? false : Boolean.parseBoolean(_SSL[0]);
		} else {
			String str = getRequestPayload(req);
			str = URLDecoder.decode(str, "UTF-8");
			params = str.split("&");
			if ("SSL_LINK=true".equals(params[0])){
				SSL = true;
			}
		}

		// 是否应用加密
		if (SSL) {
			HttpServletRequest servletRequest = (HttpServletRequest) request;
			Map<String, String[]> target = new HashMap<String, String[]>();
			Enumeration<String> names = servletRequest.getParameterNames();
			InvokeResult result = new InvokeResult();
			if (params != null) {
				//进行原始参数的转换
				conversionParam(params, target);
				result = getTransformRequest(names, target);
			} else {
				target = servletRequest.getParameterMap();
				result = getTransformRequest(names, target);
			}
			int i = 5;
			Map<String, String[]> returnValues = (Map<String, String[]>) result.getResultValue();
			if (result.getSuccessful()) {
				servletRequest = new Request((HttpServletRequest) request, returnValues);
				log.info("DecryptionFilter结束");
				chain.doFilter(servletRequest, response);
				return;
			} else {
				// 返回信息
				ResponseUtil.returnResponse(response, SecurityConstant.DESCYPT_INVALIDATION_MESSAGE, SecurityConstant.DESCYPT_INVALIDATION);
				log.info("DecryptionFilter结束");
				return;
			}
		} else {
			log.info("DecryptionFilter结束");
			chain.doFilter(request, response);
			return;
		}

	}

	/**
	 * 提取转换参数为map
	 * @param params 传输的区间参数
	 * @param target 转化到的map
	 */
	private void conversionParam(String[] params, Map<String, String[]> target) {
		String[] SSL_LINK = new String[1];// 是否进行请求加密
		String[] SSL_PA3 = new String[1];// 公钥
		String[] SSL_PA1 = new String[1];// 数据
		String[] REQUEST_TYPE = new String[1];

		SSL_LINK[0] = "true";

		/* 转换参数 */
		// sm3对应的asc密钥
		String pa3Value = getSegmentValue(params, "SSL_PA3=");
		if (pa3Value != null) {
			SSL_PA3[0] = pa3Value.split("SSL_PA3=")[1];
		}

		// 加密数据
		String pa1Value = getSegmentValue(params, "SSL_PA1=");
		if (pa1Value != null) {
			SSL_PA1[0] = pa1Value.split("SSL_PA1=")[1];
		}

		// 请求类型
		String reqTypeValue = getSegmentValue(params, "REQUEST_TYPE=");
		if (reqTypeValue != null) {
			REQUEST_TYPE[0] = reqTypeValue.split("REQUEST_TYPE=")[1];
		}

		target.put("SSL_PA3", SSL_PA3);
		target.put("SSL_PA1", SSL_PA1);
		target.put("REQUEST_TYPE", REQUEST_TYPE);
		target.put("SSL_LINK", SSL_LINK);
	}

	/**
	 * 获取区间值
	 * 
	 * @param segmentParams
	 *            前台区间参数数组
	 * @param segmentFlag
	 *            区间标志
	 * @return
	 */
	private String getSegmentValue(String[] segmentParams, String segmentFlag) {
		for (String param : segmentParams) {
			if (param.indexOf(segmentFlag) > -1) {
				return param;
			}
		}
		return null;
	}

	/**
	 * @Title: getTransformRequest @Description: 取得转换方法 @param @return
	 *         InvokeResult @throws
	 */
	private InvokeResult getTransformRequest(Enumeration<String> names, Map<String, String[]> params) {
		log.info("获取参数开始");
		InvokeResult result =new InvokeResult();
		result.setSuccessful(true);

		String[] requestType = params.get(REQUEST_TYPE);// 请求类型

		log.info("获取参数结束");

		// 对于请求后拼接参数的做特殊处理
		Iterator<String> iter = params.keySet().iterator();
		Map<String, String> mapbase = new HashMap<String, String>();
		while (iter.hasNext()) {
			String keybase = iter.next();
			mapbase.put(keybase, params.get(keybase)[0]);
		}
		mapbase.remove(SSL_KEY);
		mapbase.remove(SSL_DATA);
		mapbase.remove(REQUEST_TYPE);
		mapbase.remove(SSL_LINK);

		// 解密结果获取原始数据
		String allData;
		try {
			allData = getDecryptData(params);
		} catch (Exception e) {
			log.error("数据解析失败。", e);
			result.setSuccessful(false);
			result.setResultHint("数据解析失败。");
			e.printStackTrace();
			return result;
		}

		/* 获取原始数据以及sm加密的对照数据 */
		String protect = "";// sm3对原始数据进行加密的保护数据
		String decodeData = null;// 解密后的數據
//		Map<String, String> subDataMap = binder.toMap(allData, HashMap.class);

		Map<String, String> subDataMap = null;
		try {
			subDataMap = JsonXMLUtil.json2obj(allData, HashMap.class);
		} catch (Exception e) {
			e.printStackTrace();
		}
		decodeData = subDataMap.get(SSL_DATA);
		protect = subDataMap.get(SSL_PROTECT);
		// 重新进行编码
		String decodeData2 = decodeData;
		try {
			decodeData2 = new String(decodeData.getBytes(), "UTF-8");
		} catch (Exception e) {
			log.error("SSL_DATA数据校验完整性失败。", e);
			result.setSuccessful(false);
			result.setResultHint("SSL_DATA数据校验完整性失败。");
			return result;
		}

		// 解密进行完整性校验
		String dates = "";
		try {
			Map<String, String> map = JsonXMLUtil.json2obj(decodeData2, Map.class);
			map.putAll(mapbase);
			ThreadLocalUtils.setObjectToThreadLocal(SecurityConstant.SSL_DECODE_DATA, map);
//			dates = JsonBinder.getJsonBinder().toJson(map);
			dates = JsonXMLUtil.obj2json(map);
		} catch (Exception e) {
			log.error("SSL_DATA数据校验完整性失败。", e);
			result.setSuccessful(false);
			result.setResultHint("SSL_DATA数据校验完整性失败。");
			return result;
		}

		// 校验通过
		if (decodeData2 != null && validate(decodeData2, protect)) {
			log.info("校验数据完整性成功");
			if (null != dates && !dates.isEmpty()) {
				result.setResultValue(restoreRequestData(dates, requestType[0]));
			}
		} else {
			log.info("校验数据完整性失败");
			result.setSuccessful(false);
			result.setResultHint("SSL_DATA数据校验完整性失败。");
		}
		return result;
	}

	/**
	 * 获取解密数据
	 * 
	 * @param params
	 *            参数信息
	 * @return
	 * @throws Exception
	 */
	private String getDecryptData(Map<String, String[]> params) throws Exception {
		String allData = null;
		/* 分别对sm4方式以及sm2方式进行解密 */
		String[] data = params.get(SSL_DATA);// 数据域
//		加密类型
		if (SecurityConstant.CRYPTTYPE_SM2.equals(dBConfig.getCryptType())) {
			String cipherMode = dBConfig.getCipherMode();// 加密模式
			allData = new String(SM2Utils.decrypt(Util.hexToByte(SM2Utils.DEFAULT_PRIK), Util.hexToByte(data[0]), cipherMode));
		} else {
			String[] key = params.get(SSL_KEY);// rsa密钥
			String _key = getKey(key[0]);
			SM4MatchJS sm4 = new SM4MatchJS();
			try {
				allData = sm4.decode(data[0], _key);
			} catch (Exception e) {
				log.error("sm4解密出现异常", e);
				throw e;
			}
		}
		return allData;
	}

	/**
	 * @Title: getKey @Description: 取得AES的key @param @return String @throws
	 */
	private String getKey(String value) {
		String key = "";
		try {
			key = new RSAUtils().decrypttoStr(value);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return key;
	}

	/**
	 * @Title: restoreRequestData @Description: 还原请求数据 @param @return
	 *         Map<String,String[]> @throws
	 */
	@SuppressWarnings("unchecked")
	private Map<String, String[]> restoreRequestData(String data, String requestType) {
		Map<String, String[]> returnValues = new HashMap<String, String[]>();
//		Map<String, Object> params = binder.toMap(data, Map.class);
		Map<String, Object> params = null;
		try {
			params = JsonXMLUtil.json2obj(data, HashMap.class);
		} catch (Exception e) {
			e.printStackTrace();
		}

		for (Map.Entry<String, Object> entry : params.entrySet()) {
			String key = entry.getKey();
			Object value = entry.getValue();
			if ("STRUTS2".equals(requestType))
				returnValues.put("workDTO." + key, new String[] { value.toString() });
			else
				returnValues.put(key, new String[] { value != null ? value.toString() : "" });
		}
		return returnValues;
	}

	/**
	 * @Title: validate @Description: 校验数据完整性函数，进行密文解密+MD5校验 @param @return
	 *         boolean @throws
	 */
	private boolean validate(String data, String md5) {

		byte[] md = new byte[32];
		byte[] msg1 = data.getBytes();
		SM3Digest sm3 = new SM3Digest();
		sm3.update(msg1, 0, msg1.length);
		sm3.doFinal(md, 0);
		String sm3Data = new String(Hex.encode(md));

		// 校验字符串完整性和正确性
		if ((sm3Data.toUpperCase().trim()).equals(md5.toUpperCase().trim())) {
			return true;
		} else {
			return false;
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.jb.sys.security.filter.BaseFilter#isFilte(java.lang.String)
	 */
	public boolean isFilte(String requestPath) {
		if (requestPath.lastIndexOf(".do") != -1 || requestPath.lastIndexOf(".action") != -1)
			return true;
		else
			return false;
	}

	/**
	 * 内部类重写HttpServletRequestWrapper
	 * 
	 * @author Hubery
	 */
	class Request extends HttpServletRequestWrapper {
		/** 集合值 */
		private Map<String, String[]> decrypValue = null;

		/**
		 * 
		 * @param request
		 * @param decrypValue
		 */
		public Request(HttpServletRequest request, Map<String, String[]> decrypValue) {
			super(request);
			this.decrypValue = decrypValue;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * javax.servlet.ServletRequestWrapper#getParameter(java.lang.String)
		 */
		public String getParameter(String str) {
			if (decrypValue.get(str) != null) {
				String[] value = decrypValue.get(str);
				return value[0];
			} else {
				return super.getRequest().getParameter(str);
			}
		}

		public Enumeration getParameterNames() {
			if (decrypValue != null) {
				return Collections.enumeration(decrypValue.keySet());
			} else {
				return super.getRequest().getParameterNames();
			}
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * javax.servlet.ServletRequestWrapper#getParameterValues(java.lang.
		 * String)
		 */
		public String[] getParameterValues(String str) {
			// 获取所有参数
			String[] values = decrypValue.get(str);
			// 返回过滤后的参数
			return values;
		}
	}

	/**
	 * 
	 * @Title: getRequestPayload @Description:当header.contains("application/x-www-form-urlencoded")，获取加密信息 @param @return
	 *         String @throws
	 */
	protected String getRequestPayload(HttpServletRequest req) {
		StringBuilder sb = new StringBuilder();
		try {
			BufferedReader reader = req.getReader();
			char[] buff = new char[1024];
			int len;
			while ((len = reader.read(buff)) != -1) {
				sb.append(buff, 0, len);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		return sb.toString();
	}

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {

	}


	@Override
	public void destroy() {

	}

}
