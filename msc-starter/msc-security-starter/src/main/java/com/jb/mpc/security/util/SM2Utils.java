package com.jb.mpc.security.util;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

import javax.script.Invocable;
import java.io.IOException;
import java.math.BigInteger;

public class SM2Utils {
	/**
	 * 加密模式-C1C2C3
	 */
	public static final String CIPHERMODE_1 = "0";

	/**
	 * 加密模式-C1C3C2
	 */
	public static final String CIPHERMODE_2 = "1";


	/**
	 * 默认私钥
	 */
	public static final String DEFAULT_PRIK = "fd581152fdc6040be721bd4ddbabc7069c51e6b8e40b39dcc6aa83e03173e5e7";



	/**
	 * 默认公钥
	 */
	public static final String DEFAULT_pubk = "04a8fc0eae0ce63be3280e05d7e96c66be4a31de21a432b74dd30bbeb0c2fe1aede5c432ea9d0b68149ba549959c4b63b6a69ca52522b346b4b5690010a3618a09";



	/**
	 * SM2私钥的前半部分
	 * ce9134f0a3515628be776cd761e2e500fed838b5b07016d103c0cf5a14cb58e1
	 * 04cf6def7afbf1ac50d1f90bca7ecae753550f01fbd441d467ca4bdc16cdbeb7765273ec5f06242e08d7582c0fc0cf0ab0be0805d3e9d7b102b40038f623dd9f06
	 */
	private static String SM2KEYFRONT = "ce9134f0a3515628be776cd761e2e";


	public static String decryptUseJs(String first) throws Exception {
		Invocable in = SM2_SM4_Cache.getInvocable();
		String prik = SM2KEYFRONT + SM2_SM4_Cache.getPrivateKeyPart("SM2KEY");

//		log.info("开始解密");
		String result = (String) in.invokeFunction("sm2Decrypt", first, prik, true);
//		log.info("结束解密");
		return result;
	}

	// 生成随机秘钥对
	public static void generateKeyPair() {
		SM2 sm2 = SM2.Instance();
		AsymmetricCipherKeyPair key = sm2.ecc_key_pair_generator.generateKeyPair();
		ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) key.getPrivate();
		ECPublicKeyParameters ecpub = (ECPublicKeyParameters) key.getPublic();
		BigInteger privateKey = ecpriv.getD();
		ECPoint publicKey = ecpub.getQ();

		System.out.println("公钥: " + Util.byteToHex(publicKey.getEncoded()));
		System.out.println("私钥: " + Util.byteToHex(privateKey.toByteArray()));
	}

	/**
	 * 数据加密
	 *
	 * @param publicKey
	 *            公钥
	 * @param data
	 *            待加密数据
	 * @param cipherMode
	 *            加解密模式
	 * @return
	 * @throws IOException
	 */
	public static String encrypt(byte[] publicKey, byte[] data, String cipherMode) throws IOException {
		if (publicKey == null || publicKey.length == 0) {
			return null;
		}

		if (data == null || data.length == 0) {
			return null;
		}

		byte[] source = new byte[data.length];
		System.arraycopy(data, 0, source, 0, data.length);

		Cipher cipher = new Cipher();
		SM2 sm2 = SM2.Instance();
		ECPoint userKey = sm2.ecc_curve.decodePoint(publicKey);

		ECPoint c1 = cipher.Init_enc(sm2, userKey);
		cipher.Encrypt(source);
		byte[] c3 = new byte[32];
		cipher.Dofinal(c3);

		// System.out.println("C1 " + Util.byteToHex(c1.getEncoded()));
		// System.out.println("C2 " + Util.byteToHex(source));
		// System.out.println("C3 " + Util.byteToHex(c3));
		// 拼装成加密字串
		if (CIPHERMODE_2.equals(cipherMode)) {
			return Util.byteToHex(c1.getEncoded()) + Util.byteToHex(c3) + Util.byteToHex(source);
		} // C1C3C2
		else {
			return Util.byteToHex(c1.getEncoded()) + Util.byteToHex(source) + Util.byteToHex(c3);
		} // C1C2C3
			// return Util.byteToHex(c1.getEncoded()) + Util.byteToHex(source) +
			// Util.byteToHex(c3);
			// return Util.byteToHex(c1.getEncoded())+ Util.byteToHex(c3) +
			// Util.byteToHex(source) ;

	}

	/**
	 * 数据解密
	 *
	 * @param privateKey
	 *            私钥
	 * @param encryptedData
	 *            界面数据
	 * @param cipherMode
	 *            加解密模式
	 * @return
	 * @throws IOException
	 */
	public static byte[] decrypt(byte[] privateKey, byte[] encryptedData, String cipherMode) throws IOException {
		if (privateKey == null || privateKey.length == 0) {
			return null;
		}

		if (encryptedData == null || encryptedData.length == 0) {
			return null;
		}
		// 加密字节数组转换为十六进制的字符串 长度变为encryptedData.length * 2
		String data = Util.byteToHex(encryptedData);
		/***
		 * 分解加密字串 （C1 = C1标志位2位 + C1实体部分128位 = 130） （C3 = C3实体部分64位 = 64） （C2 =
		 * encryptedData.length * 2 - C1长度 - C2长度）
		 */
		byte[] c1Bytes = Util.hexToByte(data.substring(0, 130));
		int c2Len = encryptedData.length - 97;
		byte[] c3, c2;
		if (CIPHERMODE_2.equals(cipherMode)) {
			c3 = Util.hexToByte(data.substring(130, 130 + 64));
			c2 = Util.hexToByte(data.substring(194, 194 + 2 * c2Len));
		} else {
			c2 = Util.hexToByte(data.substring(130, 130 + 2 * c2Len));
			c3 = Util.hexToByte(data.substring(130 + 2 * c2Len, 194 + 2 * c2Len));
		}
		// byte[] c2 = Util.hexToByte(data.substring(130,130 + 2 * c2Len));
		// byte[] c3 = Util.hexToByte(data.substring(130 + 2 * c2Len,194 + 2 *
		// c2Len));
		// byte[] c3 = Util.hexToByte(data.substring(130, 130 + 64));
		// byte[] c2 = Util.hexToByte(data.substring(194, 194 + 2 * c2Len));

		SM2 sm2 = SM2.Instance();
		BigInteger userD = new BigInteger(1, privateKey);

		// 通过C1实体字节来生成ECPoint
		ECPoint c1 = sm2.ecc_curve.decodePoint(c1Bytes);
		Cipher cipher = new Cipher();
		cipher.Init_dec(userD, c1);
		cipher.Decrypt(c2);
		cipher.Dofinal(c3);

		// 返回解密结果
		return c2;
	}

	public static void main(String[] args) throws Exception {
        SM2Utils.generateKeyPair();

	    String plainText = "jonllen";
        System.out.println("明文: "+plainText);
        byte[] sourceData = plainText.getBytes();

        // 下面的秘钥可以使用generateKeyPair()生成的秘钥内容
        // 国密规范正式私钥
        String prik = "00FB235694C1632B213FF51B091C2002342D7D0B4349B6D03CF425F150F7083542";
        // 国密规范正式公钥
        String pubk = "04D4F5EF1EA6550B6DAFFE0C5679B8EB44E5CA12667E61BFE077EF34CDC2B52A9CFC58FDB0BDAED54DDE66A4A52D85587ACD407D11ACDCB3C45098038FB03B78F8";

        //加密
        String cipherText = SM2Utils.encrypt(Util.hexToByte(pubk), sourceData,CIPHERMODE_1);
        System.out.println("加密密文: "+cipherText);

        //解密
        plainText = new String(SM2Utils.decrypt(Util.hexToByte(prik), Util.hexToByte(cipherText),CIPHERMODE_1));
        System.out.println("解密: " + plainText);

	}
}
