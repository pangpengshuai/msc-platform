package com.jb.mpc.security.util;

import com.jb.mpc.security.config.DBConfig;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;

/**
* @author Qiusx
* 安全加密参数处理工具
*/
public class SecurityUtil {

	/**
	 * 解密模型id
	 * @return
	 */
	public static String sm4ModelDecode(String str, DBConfig dBConfig) {
		if("T".equals(dBConfig.getIsModelSafe())){
			try {
				if(str.contains("fanxiegang")){
					str = str.replaceAll("fanxiegang","\\/");
				}
				if(str.contains("jiahao")){
					str = str.replaceAll("jiahao","\\+");
				}
				str = new SM4MatchJS().decode(str, dBConfig.getDecKey());
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return str;
	}
	/**
	 * 加密模型id
	 * @return
	 */
	public static String sm4ModelEncode(String str, DBConfig dBConfig) {
		if("T".equals(dBConfig.getIsModelSafe())){
			try {
				str = new SM4MatchJS().encode(str, dBConfig.getDecKey());
				if(str.contains("/")){
					str = str.replaceAll("\\/","fanxiegang");
				}
				if(str.contains("+")){
					str = str.replaceAll("\\+","jiahao");
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return str;
	}

	/**
	 * 解密密码
	 * @return
	 */
	public static String sm4DbPdwDecode(String str, DBConfig dBConfig) {
		if("T".equals(dBConfig.getEncryptionDatasource())){
			try {
				if(str.contains("fanxiegang")){
					str = str.replaceAll("fanxiegang","\\/");
				}
				if(str.contains("jiahao")){
					str = str.replaceAll("jiahao","\\+");
				}
				str = new SM4MatchJS().decode(str, dBConfig.getDecKey());
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return str;
	}

	/**
	 * SM3加密
	 * @return
	 */
	public static String sm3Encode(String str) {
		SM3Digest sm3 = new SM3Digest();
		//System.out.println("明文："+str);
		byte[] md = new byte[32];
		byte[] msg1 = str.getBytes();
		sm3.update(msg1, 0, msg1.length);
		sm3.doFinal(md, 0);
		str = new String(Hex.encode(md));
		//System.out.println("加密密文："+s.toUpperCase());
		return str.toUpperCase();
	}

}
