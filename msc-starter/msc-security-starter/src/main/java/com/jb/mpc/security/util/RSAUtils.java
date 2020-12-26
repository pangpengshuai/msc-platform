package com.jb.mpc.security.util;
import org.apache.commons.lang.StringUtils;

import javax.crypto.Cipher;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.HashMap;
import java.util.Map;

public class RSAUtils {
	
	/**
	 * rsa模
	 */
	private static final String RSA_MODULUS_COLUMN_NAME = "RSAMODULUS";
	
	
	/**
	 * rsa指数
	 */
	private static final String RSA_EXPONENT_COLUMN_NAME = "RSAEXPONENT";
	
	/**
	 * rsa模部分内容
	 */
	private static final String RSA_MODULUS_PART = "693749544281466586157482823340458450464212345316376462339025065109418768";
	
	/**
	 * rsa指数部分内容
	 */
	private static final String RSA_EXPONENT_PART = "3678607567225421568817413917924877796066625450064757075048210940021272202";
	

	/**
	 * 初始化私钥
	 */
	private RSAPrivateKey prkey = null;
	/**
	 * 构造方法进行数据的初始化操作
	 */
	public RSAUtils()
	{
		//获取数据库中部分私钥内容
		String partModulus = SM2_SM4_Cache.getPrivateKeyPart(RSA_MODULUS_COLUMN_NAME);
		String partExponent = SM2_SM4_Cache.getPrivateKeyPart(RSA_EXPONENT_COLUMN_NAME);

		/*获取完整的私钥*/
		String	rsaModulus = RSA_MODULUS_PART + partModulus;
		String	rsaExponent = RSA_EXPONENT_PART + partExponent;
		prkey = getPrivateKey(rsaModulus,rsaExponent);
	}


	public static final int KEYSIZE = 512;



	/**
	 * 加密
	 * @param publicKey 公钥
	 * @param content 需要加密的内容
	 * @return
	 * @throws Exception
	 */
	public String encrypttoStr(Key publicKey,String content) throws Exception{
		RandUtil rand = new RandUtil();
		String endata = rand.parseByte2HexStr(publicEnrypy(publicKey,content));
		return endata;
	}

	/**
	 * 解密
	 * @param privateKey 私钥
	 * @param endata 需要解密的内容
	 * @return
	 * @throws Exception
	 */
	public String decrypttoStr(Key privateKey,String endata) throws Exception{
		RandUtil rand = new RandUtil();
		String data = new String(privateEncode(privateKey,rand.parseHexStr2Byte(endata)));
		return data;
	}


	/**
	 * 解密
	 * @param endata 需要解密的内容
	 * @return
	 * @throws Exception
	 */
	public String decrypttoStr(String endata) throws Exception{
		RandUtil rand = new RandUtil();
		String data = new String(privateEncode(prkey,rand.parseHexStr2Byte(endata)));
		return StringUtils.reverse(data);
	}
	
	
	
	public String decrypttoStr_normal(Key privateKey,String endata) throws Exception{
		String data = new String(privateEncode(privateKey,endata.getBytes()));
		return data;
	}
	
	
	public String decrypttoStr_normal(String endata) throws Exception{
		String data = new String(privateEncode(prkey,endata.getBytes()));
		return data;
	}
	
	
	 /**
	  * 加密的方法,使用公钥进行加密
	  * @param publicKey 公钥
	  * @param data 需要加密的数据
	  * @throws Exception
	  */
    public static byte[] publicEnrypy(Key publicKey,String data) throws Exception {
 
        Cipher cipher = Cipher.getInstance("RSA",new org.bouncycastle.jce.provider.BouncyCastleProvider());
 
        // 设置为加密模式
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
 
        // 对数据进行加密
        byte[] result = cipher.doFinal(data.getBytes());

        
        return result;
    }
 
    /**
     * 解密的方法，使用私钥进行解密
     * privateKey  私钥
     * encoData 需要解密的数据
     * @throws Exception
     */
    public static byte[]  privateEncode(Key privateKey,byte[] encoData) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA",new org.bouncycastle.jce.provider.BouncyCastleProvider());
          
        //设置为解密模式，用私钥解密
         cipher.init(Cipher.DECRYPT_MODE, privateKey);
         //解密
         byte[] data = cipher.doFinal(encoData);
//         System.out.println("解密后的数据："+data);
         return data;
    }
    
    
    
    /**
	 * 自动生成密钥对
	 * @throws Exception
	 */
	public  Map<String,Object> createKey(){
		
		 	try {
//				Cipher cipher = Cipher.getInstance("RSA");
		        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", new org.bouncycastle.jce.provider.BouncyCastleProvider());
				
		        SecureRandom random = new SecureRandom();  
		        keyPairGenerator.initialize(RSAUtils.KEYSIZE, random);
		 
		        // 生成钥匙对
		        KeyPair keyPair = keyPairGenerator.generateKeyPair();
		 
		        // 得到公钥
		        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		        // 得到私钥
		        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		        
		        Map<String,Object> map = new HashMap<String, Object>();
		        map.put("publicKey", publicKey);
		        map.put("privateKey", privateKey);
		 
		        return map;
		        //把私钥保存到硬盘上
	//	        saveKey(privateKey,"E://private_key");
		      //把公钥保存到硬盘上
	//	        saveKey(publicKey,"E://public_key");
		 	} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return null;
			} 
		
	}
     
      
    /**
     * 从硬盘中加载私钥
     * @return
     * @throws IOException
     * @throws FileNotFoundException
     * @throws ClassNotFoundException
     */
    public  KeyPair loadKey(String keyUrl) throws IOException, FileNotFoundException,
            ClassNotFoundException {
        ObjectInputStream inputStream = new ObjectInputStream(
                new FileInputStream(new File(keyUrl)));
        KeyPair key = (KeyPair) inputStream.readObject();
        return key;
    }
   
     
    /**
     * 把私钥或则公钥保存到硬盘上
     * @param key
     * @throws IOException
     * @throws FileNotFoundException
     */
    private  void saveKey(Key key,String saveUrl) throws IOException,
            FileNotFoundException {
        ObjectOutputStream outputStream = new ObjectOutputStream(
                new FileOutputStream(new File(saveUrl)));
        outputStream.writeObject(key);
    }
    
    /**  
     * 使用模和指数生成RSA公钥  
     *   
     *   
     * @param modulus  
     *            模  
     * @param exponent  
     *            指数  
     * @return  
     */    
    public static RSAPublicKey getPublicKey(String modulus, String exponent) {    
        try {    
            BigInteger b1 = new BigInteger(modulus);    
            BigInteger b2 = new BigInteger(exponent);    
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", new org.bouncycastle.jce.provider.BouncyCastleProvider());    
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(b1, b2);    
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);    
        } catch (Exception e) {    
            e.printStackTrace();    
            return null;    
        }    
    }  
    
    /**  
     * 使用模和指数生成RSA私钥  
      
     * /None/NoPadding】  
     *   
     * @param modulus  
     *            模  
     * @param exponent  
     *            指数  
     * @return  
     */    
    public static RSAPrivateKey getPrivateKey(String modulus, String exponent) {    
        try {    
            BigInteger b1 = new BigInteger(modulus);    
            BigInteger b2 = new BigInteger(exponent);    
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", new org.bouncycastle.jce.provider.BouncyCastleProvider());    
            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(b1, b2);    
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);    
        } catch (Exception e) {    
            e.printStackTrace();    
            return null;    
        }    
    } 

}