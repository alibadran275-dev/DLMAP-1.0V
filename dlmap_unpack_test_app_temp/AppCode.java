package com.example.testapp;

import java.security.MessageDigest;

public class AppCode {
    public static void main(String[] args) {
        try {
            // Weak Hash MD5
            MessageDigest md = MessageDigest.getInstance("MD5");
            
            // Hardcoded Key
            String key = "THIS_IS_A_STATIC_AES_KEY_12345";
            String password = "mysecretpassword123";
            
            // AWS credentials
            String awsKey = "AKIAI44QH83M52OQ3GPL";
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
