package com.company;

import java.io.DataInputStream;
import java.io.DataOutputStream;

public class Main {

    public static void main(String[] args) throws Exception {
        //UtilTools.coverToPfx("D:\\kclient.keystore","longshine","D:\\kclient.pfx");
        int i = 0;

        var socket = UtilTools.createSocket();
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
//        while(true){
//            Thread.sleep(100);
//            i++;
//            String s = String.valueOf(i);
//            out.write(s.getBytes());
//        }
        out.write("你好呀".getBytes());
        System.out.println("消息接收中");

        while (true){
            byte[] datas = new byte[2048];
            socket.getInputStream().read(datas);
            System.out.println(new String(datas));
        }
    }
}
