package com.test.app;

import java.security.MessageDigest;

public class AppCode {
    private static final String KEY = "THIS_IS_A_HARDCODED_AES_KEY_001";
    private static final String API_TOKEN = "pk_live_d0i2n9g5n9h4i8t1o4s4i5s4y7a2l9i8";

    void hashData(String data) {
        try {
             // Weak Cryptography: MD5
             MessageDigest.getInstance("MD5").digest(data.getBytes());
        } catch (Exception e) {}
    }
}

