package com.company;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.crypto.Cipher;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

public class UtilTools {
    private static final String PKCS12 = "PKCS12";
    public final static String TrustStoreType = "JKS";

    //创建Socket
    public static Socket createSocket(){
        try {
            String serverHost = "127.0.0.1"; //服务端地址
            int serverPort = 8800; //服务端监听端口
            String clientPrivateKey = "D:\\ssl证书\\kclient.keystore";  //客户端私钥
            String clientKeyPassword = "longshine";  //客户端私钥密码
            String trustKey = "D:\\ssl证书\\tclient.keystore"; //客户端信任证书列表，即服务端证书
            String trustKeyPassword = "longshine";  //客户端信任证书密码

            SSLContext ctx = SSLContext.getInstance("SSL");
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            KeyStore ks = KeyStore.getInstance("JKS");
            KeyStore tks = KeyStore.getInstance("JKS");

            ks.load(new FileInputStream(clientPrivateKey), clientKeyPassword.toCharArray());
            tks.load(new FileInputStream(trustKey), trustKeyPassword.toCharArray());

            kmf.init(ks, clientKeyPassword.toCharArray());
            tmf.init(tks);

            ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

            return (SSLSocket) ctx.getSocketFactory().createSocket(serverHost, serverPort);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 将keystore转为pfx
     *
     * @param keyStoreFile 生成的文件名和路径
     * @param pfxPsw 密码
     * @param pfxFile 原文件路径及名称
     */
    public static void coverToPfx(String keyStoreFile, String pfxPsw, String pfxFile) throws Exception {
        KeyStore inputKeyStore = null;
        FileInputStream input = null;
        FileOutputStream output = null;
        String keyAlias = "";
        try {
            inputKeyStore = KeyStore.getInstance(TrustStoreType);
            input = new FileInputStream(keyStoreFile);
            char[] password = null;
            if ((pfxPsw == null) || pfxPsw.trim().equals("")) {
                password = null;
            } else {
                password = pfxPsw.toCharArray();
            }
            inputKeyStore.load(input, password);
            KeyStore outputKeyStore = KeyStore.getInstance(PKCS12);
            outputKeyStore.load(null, pfxPsw.toCharArray());
            Enumeration enums = inputKeyStore.aliases();
            while (enums.hasMoreElements()) {
                keyAlias = (String) enums.nextElement();
                System.out.println("alias=[" + keyAlias + "]");
                if (inputKeyStore.isKeyEntry(keyAlias)) {
                    Key key = inputKeyStore.getKey(keyAlias, password);
                    Certificate[] certChain = inputKeyStore.getCertificateChain(keyAlias);
                    outputKeyStore.setKeyEntry(keyAlias, key, pfxPsw.toCharArray(), certChain);
                }
            }
            output = new FileOutputStream(pfxFile);
            outputKeyStore.store(output, password);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (IOException e) {
                    System.out.println(e.getMessage());
                }
            }
            if (output != null) {
                try {
                    output.close();
                } catch (IOException e) {
                    System.out.println(e.getMessage());
                }
            }
        }
    }
}
