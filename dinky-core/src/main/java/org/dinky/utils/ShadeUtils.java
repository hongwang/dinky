package org.dinky.utils;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Objects;


@Slf4j
public final class ShadeUtils {
    private static final String SHADE_IDENTIFIER_OPTION = "shade.identifier";
    private static final String DEFAULT_IDENTIFIER = "seatunnel_aes";
    private static final String[] DEFAULT_SENSITIVE_OPTIONS =
            new String[] {"password", "username", "auth"};

    private static final byte[] KEY = new byte[16];

    static {
        byte[] mykey = "conn".getBytes(StandardCharsets.UTF_8);
        System.arraycopy(mykey, 0, KEY, 0, mykey.length);
    }

    public static void decryptConfig(Map<String, String> config) {
        if (!config.containsKey(SHADE_IDENTIFIER_OPTION) || !Objects.equals(config.get(SHADE_IDENTIFIER_OPTION), DEFAULT_IDENTIFIER)) {
            return;
        }

        for (String sensitiveOption : DEFAULT_SENSITIVE_OPTIONS) {
            config.computeIfPresent(sensitiveOption,  (key, value) -> decrypt(value));
        }
    }

    private static byte[] stringHexToBytes(String hexString) {
        int len = hexString.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                    + Character.digit(hexString.charAt(i + 1), 16));
        }
        return data;
    }

    private static byte[] decode(byte[] key, byte[] data) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        return cipher.doFinal(data);
    }

    private static String decrypt(String value) {
        try {
            return new String(decode(KEY, stringHexToBytes(value)));
        } catch (Exception e) {
            log.error("Failed to decrypt: {}.", value, e);
        }

        return value;
    }

}
