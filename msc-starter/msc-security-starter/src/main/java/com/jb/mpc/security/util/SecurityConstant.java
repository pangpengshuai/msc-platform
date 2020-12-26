package com.jb.mpc.security.util;

/**
 * @Package: com.jb.sys.security.constant<br>
 * @ClassName: SecurityConstant<br>
 * @Description: 加密常量接口<br>
 */
public interface SecurityConstant {
	
	/**
	 * 加密内容指数
	 */
	public static final String EXPONENT = "010001";
	/**
	 * 加密内容模
	 */
	public static final String MODULUS ="008475c577d5c5a366c924d18468d866af0e174b8f51bf3e37cfef3cc1ab5292c854495b11d37c3240bbb7d338ccd3d74908456922b4bae653d0b046075a1e3a9f";

	/** 一天的毫秒数 */
	public static final long DAY = 1000 * 24 * 60 * 60;

	/** 一小时的毫秒数 */
	public static final long HOUR = 1000 * 60 * 60;

	/** 一分钟的毫秒数 */
	public static final long MIN = 1000 * 60;

	/** 一秒钟的毫秒数 */
	public static final long SEC = 1000;

	/** 初始密码 */
	public final static String CSMM = "CSMM";

	/** 秘密时间 */
	public final static String MMSJ = "MMSJ";

	/** 锁定时间 */
	public final static String SDSJ = "SDSJ";

	/** 最大会话数量 */
	public final static String ZDHHSL = "ZDHHSL";

	/** 最大错误次数 */
	public final static String CWCS = "CWCS";

	/** 原始密码未修改 */
	public final static String YSMMWXG = "001";

	/** 默认密码修改时间为空 */
	public final static String MMWXG = "002";

	/** 密码超过有效期 */
	public final static String MMCGYXQ = "003";

	/** 密码锁定日期未超期 */
	public final static String MMSDRQWCQ = "004";

	/** 密码已锁定 */
	public final static String MMYSD = "005";

	/** 校验密码失败 */
	public final static String XYMMSB = "006";

	/** 配置为空 */
	public final static String ATTR_NULL = "000";

	/** 会话数量已满 */
	public final static String HHSLYY = "007";

	/** 代理标识 */
	public final static String[] AGENTS = new String[] { "web", "mobile",
			"ios", "android" };
	/** 会话超时或者无效 */
	public static final int SESSION_INVALIDATION = 601;

	/** 越权访问 */
	public static final int UNAUTHORIZED_ACCESS = 602;

	/** IP地址无效或受限 */
	public static final int FORBIDDEN_IP = 603;

	/** 访问时段无效或受限 */
	public static final int FORBIDDEN_TIME = 604;

	/** 传输解密错误 */
	public static final int DESCYPT_INVALIDATION = 605;

	/** 用户登录冲突 */
	public static final int USER_LOGIN_REPEAT = 606;
	
	/** 无效字符 */
	public static final int INVALID_CHARACTER = 607;
	
	/** 无效字符 错误信息 */
	public static final String INVALID_CHARACTER_MESSAGE = "请求中含有系统不允许的非法字符";

	/** 用户登录冲突 错误信息 */
	public static final String USER_LOGIN_REPEAT_MESSAGE = "访问错误！该账号已经在其它地方登录";

	/** 回话超时无效时错误信息 */
	public static final String SESSION_INVALIDATION_MESSAGE = "访问错误！session超时或无效，请登录主页面访问";

	/** ip段无权访问错误信息 */
	public static final String FORBIDDEN_IP_MESSAGE = "登录IP段无权登录系统！";

	/** 时间段无权访问错误信息 */
	public static final String FORBIDDEN_TIME_MESSAGE = "当前时间无权登录系统";

	/** 用户模块无权访问错误信息 */
	public static final String UNAUTHORIZED_ACCESS_MESSAGE = "当前登录用户没有对该模块的访问权限";

	/** 传输数据密钥异常 */
	public static final String DESCYPT_INVALIDATION_MESSAGE = "传输数据密钥异常！";

	/** 证书过期 **/
	public static final String LICENCE_TIME_OUT = "证书授权已过期！";
	/** 重复登录 */
	public static final String LOGIN_REPEAT = "loginRepeat";

	/** session缓存 */
	public static final String SESSION_CACHE = "sessionCache";

	/** ssl解密信息 */
	public static final String SSL_DECODE_DATA = "sslDecodeData";
	
	/**
	 * 是否安全模式
	 */
	public static final String ISSAFE = "isSafe";
	
	/** 会话配置 */
	public static enum SessionConfig {
		// 是否进行登录限制
		SFDLXZ
	};
	

	/**
	 * 加密类型
	 */
	public static final String CRYPTTYPE = "cryptType";
	
	
	/**
	 * 加密类型-SM4
	 */
	public static final String CRYPTTYPE_SM4 = "0";
	
	/**
	 * 加密类型-SM2
	 */
	public static final String CRYPTTYPE_SM2 = "1";
	
	/**
	 * sm2加密模式
	 */
	public static final String SM2_CIPHERMODE = "cipherMode";

}
