package com.jb.mpc.security.util;

import java.io.Serializable;

/**
 * @author hxw E-mail:
 * @version 创建时间：2009-5-20 下午02:01:38 类说明
 */
public class InvokeResult<T> implements Serializable, Cloneable {

	/** TODO */
	private static final long serialVersionUID = -5593722400156206443L;

	/**
	 * 业务调用是否成功。
	 */
	private boolean successful = true;

	/**
	 * 业务调用的返回提示信息。
	 */
	private String resultHint;

	/** 操作内容 */
	private String operContent;

	/**
	 * 业务调用的返回值。
	 */
	private T resultValue;

	/**
	 * 业务层返回的错误代码
	 */
	private String errorCode;

	/**
	 * 默认构造函数。
	 */
	public InvokeResult() {
		clear();
	}

	/**
	 * 初始化返回信息。
	 */
	public void clear() {
		setSuccessful(false);
		setResultHint(null);
		setResultValue(null);
	}

	/**
	 * @param successful
	 *            the isSuccessful to set
	 */
	public void setSuccessful(boolean successful) {
		this.successful = successful;
	}

	/**
	 * @return the isSuccessful
	 */
	public boolean getSuccessful() {
		return successful;
	}

	/**
	 * @param resultHint
	 *            the resultHint to set
	 */
	public void setResultHint(String resultHint) {
		this.resultHint = resultHint;
	}

	/**
	 * @return the resultHint
	 */
	public String getResultHint() {
		return resultHint;
	}

	/**
	 * @param resultValue
	 *            the resultValue to set
	 */
	public void setResultValue(T resultValue) {
		this.resultValue = resultValue;
	}

	/**
	 * @return the resultValue
	 */
	public T getResultValue() {
		return resultValue;
	}

	public String getErrorCode() {
		return errorCode;
	}

	public void setErrorCode(String errorCode) {
		this.errorCode = errorCode;
	}

	/**
	 * @return the operContent
	 */
	public String getOperContent() {
		return operContent;
	}

	/**
	 * @param operContent
	 *            the operContent to set
	 */
	public void setOperContent(String operContent) {
		this.operContent = operContent;
	}



}
