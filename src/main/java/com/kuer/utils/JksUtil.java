package com.kuer.utils;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

/**
 * JksUtil
 *
 * @author wangkj
 * @date 2022/3/1 14:40
 */
public class JksUtil {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    /**
     *
     *  生成系统默认的keyStore
     *
     * @description:
     * @param
     * @return: KeyStore
     * @author: wangkj6
     * @time: 2022/3/1 15:52
     */
    public static KeyStore generateKeyStore() throws Exception{
        return generateKeyStore(KeyStore.getDefaultType());
    }

    /**
     *
     * 生成指定类型的keyStore
     *
     * @description:
     * @param storeType
     * @return:
     * @author: wangkj6
     * @time: 2022/3/1 15:55
     */
    public static KeyStore generateKeyStore(String storeType) throws Exception{
        return loadKeyStore(storeType, null, null);
    }

    /**
     *
     *  加载keyStore
     *
     * @param storeType 文件类型
     * @param inputStream 输入流
     * @param password  密码
     * @return: java.security.KeyStore
     * @author: wangkj6
     * @time: 2022/3/1 16:26
     */
    public static KeyStore loadKeyStore(String storeType, InputStream inputStream, String password)throws Exception{
        KeyStore keyStore = KeyStore.getInstance(storeType);
        keyStore.load(inputStream, StringUtils.isNotBlank(password) ? password.toCharArray() : null);
        return keyStore;
    }

    /**
     *
     *  生成EC加密的KeyStore
     *
     * @param
     * @return: java.security.KeyStore
     * @author: wangkj6
     * @time: 2022/3/1 15:08
     */
    public static KeyPair generateEcKeyPair() throws Exception {
        return generateKeyPair("EC", "BC", new ECGenParameterSpec("P-256"));
    }

    /**
     *
     *  生成指定参数的keystore
     *
     * @param algorithm
     * @param provider
     * @param param
     * @return: java.security.KeyStore
     * @author: wangkj6
     * @time: 2022/3/1 15:07
     */
    public static KeyPair generateKeyPair(String algorithm, String provider, AlgorithmParameterSpec param) throws Exception {
        // 使用secp256r1初始化
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm, provider);
        keyPairGenerator.initialize(param);
        return keyPairGenerator.genKeyPair();

    }

    /**
     *
     * 生成RSA加密的keystore
     *
     * @param
     * @return: java.security.KeyStore
     * @author: wangkj6
     * @time: 2022/3/1 15:06
     */
    public static KeyPair generateRsaKeyPair() throws Exception {
        return generateKeyPair("RSA", "BC", 2048);
    }

    /**
     *
     *  生成指定密钥长度的keyStore（jks）
     *
     * @param algorithm 加密算法
     * @param provider  提供者
     * @param keySize   密钥长度
     * @return: java.security.KeyStore
     * @author: wangkj6
     * @time: 2022/3/1 15:03
     */
    public static KeyPair generateKeyPair(String algorithm, String provider, int keySize) throws Exception{

        // 使用secp256r1初始化
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm, provider);
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.genKeyPair();
    }


    /**
     *
     * 创建持有人并根据持有人返回证书
     *
     * @param keyPair       密钥对
     * @param notBefore     生效时间
     * @param notAfter      失效时间
     * @param commonName    发布者信息
     * @return
     */
    public static X509Certificate createEcCertificate(KeyPair keyPair,
                                                    Date notBefore,
                                                    Date notAfter,
                                                    String commonName) throws Exception {

        return createCertificate(keyPair, "SHA256withECDSA", notBefore, notAfter, commonName, "BC");
    }

    /**
     *
     * 创建持有人并根据持有人返回证书
     *
     * @param keyPair       密钥对
     * @param notBefore     生效时间
     * @param notAfter      失效时间
     * @param commonName    发布者信息
     * @return
     */
    public static X509Certificate createRsaCertificate(KeyPair keyPair,
                                                      Date notBefore,
                                                      Date notAfter,
                                                      String commonName) throws Exception {

        return createCertificate(keyPair, "SHA256withRSA", notBefore, notAfter, commonName, "BC");
    }

    /**
     *
     * 创建持有人并根据持有人返回证书
     *
     * @param keyPair       密钥对
     * @param sigAlg        使用sigAlg来签名证书
     * @param notBefore     生效时间
     * @param notAfter      失效时间
     * @param commonName    发布者信息
     * @param provider      提供者
     * @return
     */
    public static X509Certificate createCertificate(KeyPair keyPair,
                                                    String sigAlg,
                                                    Date notBefore,
                                                    Date notAfter,
                                                    String commonName,
                                                    String provider) throws Exception {

        X500NameBuilder x500NameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        X500Name x500Name = x500NameBuilder
                .addRDN(BCStyle.CN, commonName)
                .build();
        // 公钥初始化构建器
        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                x500Name,
                BigInteger.valueOf(System.currentTimeMillis()),
                notBefore,
                notAfter,
                x500Name,
                keyPair.getPublic());

        ContentSigner contentSigner = new JcaContentSignerBuilder(sigAlg)
                .setProvider(provider)
                .build(keyPair.getPrivate());

        X509CertificateHolder x509CertificateHolder = certificateBuilder.build(contentSigner);
        return  new JcaX509CertificateConverter().setProvider(provider).getCertificate(x509CertificateHolder);
    }

    /**
     *
     * 将证书存入keyStore
     *
     * @param alias     证书别名
     * @param keyStore  要存入的证书仓库
     * @param keyPair   密钥对
     * @param password  证书仓库密码
     * @param certificate   被存入的证书
     * @return: void
     * @author: wangkj6
     * @time: 2022/3/1 15:28
     */
    public static void storeKeyEntry(String alias, KeyStore keyStore, KeyPair keyPair, String password, X509Certificate certificate) throws KeyStoreException {
        keyStore.setKeyEntry(alias, keyPair.getPrivate(), password.toCharArray(), new Certificate[]{certificate});
    }

    /**
     * 将仓库序列化为文件
     * @param keyStore 证书仓库
     * @param filePath 文件路径
     * @param password 仓库密码
     */
    public static void saveKeyStore(String filePath, KeyStore keyStore, String password) throws Exception {
        FileOutputStream fileOutputStream = new FileOutputStream(filePath);
        saveKeyStore(fileOutputStream, keyStore, password);
    }

    /**
     * 将仓库序列化为文件
     * @param keyStore 证书仓库
     * @param outputStream 输出流
     * @param password 仓库密码
     */
    public static void saveKeyStore(OutputStream outputStream, KeyStore keyStore, String password) throws Exception {
        keyStore.store(outputStream, password.toCharArray());
        outputStream.close();
    }
}
