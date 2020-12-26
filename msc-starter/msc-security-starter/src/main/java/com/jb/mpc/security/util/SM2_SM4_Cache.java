package com.jb.mpc.security.util;

import javax.script.*;
import java.io.FileReader;
import java.net.URL;
import java.util.HashMap;

/**
 * SM2_SM4的私钥的后半部分, 用于sm2解密的javascript engine
 * @author zhaobao
 *
 */
public class SM2_SM4_Cache {
	/**
	 * SM2_SM4的私钥的后半部分
	 */
	private static HashMap<String, String> privateKeyParts = new HashMap<String, String>();
	
	private static Invocable invocable = null;
	

	/**
	 * 从数据库中得到SM2_SM4的私钥的部分
	 * @param SM2_SM4  SM2KEY或SM4KEY
	 * @return
	 */
	public static String getPrivateKeyPart(String SM2_SM4) {
		if(privateKeyParts.get(SM2_SM4)!=null) {
			return privateKeyParts.get(SM2_SM4);
		} else {
			String partKey = getPartKey(SM2_SM4);
			privateKeyParts.put(SM2_SM4, partKey);
			return partKey;
		}
	}
	
	public static Invocable getInvocable() throws Exception {
		if(invocable !=null) return invocable;
		/*mimeType为传输的文件类型,如 application/javascript*/  
        /*获取执行JavaScript的执行引擎*/  
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("javascript");  
        /*为文件注入全局变量*/  
        Bindings bindings = engine.createBindings();  
        bindings.put("factor", 2);  
        /*设置绑定参数的作用域*/  
        engine.setBindings(bindings,ScriptContext.ENGINE_SCOPE);
		/*执行js文件代码*/  
        URL url = Thread.currentThread().getContextClassLoader().getResource("");  
        String path;  
        if (url!=null){  
            path = url.getPath().replace("classes", "sm2js");
            String fileName = "SM2.min.js";
            engine.eval(new FileReader(path+"/"+fileName));  
            /*查看是否可以调用方法*/  
            if (engine instanceof Invocable){  
            	invocable = (Invocable) engine;  
            }  
        } else {
        	throw new RuntimeException("没有找到sm2的js");
        }
		return invocable;
	}
	

	/**
	 * 获取部分key
	 * @return
	 */
	@SuppressWarnings({ "unchecked", "rawtypes" })
	private static String getPartKey(final String SM2_SM4) {
		// 获取数据库的加密密钥信息
		/*GenericDao genericDao = SpringBeanHelper.getBean(GenericDao.class,
				"genericDao");
		//获取加密key
		String partKye = null;
		String sql = "select "+SM2_SM4+" from us_sys.tb_sys_smkey";
		try {
			List<Map<String, Object>> ms = DbUtil.execQueryList(sql, new Object[]{});
			if (!ms.isEmpty() && ms.get(0).get(SM2_SM4.toUpperCase())!=null) {
				partKye = (String) ms.get(0).get(SM2_SM4.toUpperCase());
				if("".equals(partKye)){
					throw new ServiceException("获取数据库存储的sm私钥出现错误");
				}
			} else {
				throw new ServiceException("获取数据库存储的sm私钥出现错误");
			}
		} catch (Exception e) {
//			throw new ServiceException("获取数据库存储的sm私钥出现错误", e);
		}*/
		String partKye = "qw";
		return partKye;
	}
}
