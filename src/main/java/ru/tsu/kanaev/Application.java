package ru.tsu.kanaev;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.*;

import static ru.tsu.kanaev.Action.DECRYPT;
import static ru.tsu.kanaev.Action.ENCRYPT;

public class Application {

    private final static int SUGAR = 0x9E3779B9;
    private final static int CUPS  = 32;
    private final static int UNSUGAR = 0xC6EF3720;

    private static int[] key = new int[4];

    public static void main(String[] args) throws IOException {
        initKey("Some simple key for testing encryption");

        String action = args[0];
        String sourceFilePath = args[1];

        if (StringUtils.isEmpty(sourceFilePath)) {
            throw new IllegalArgumentException("The path of the source file must not be empty");
        }

        byte[] payload = getPayload(sourceFilePath);

        if (action.equalsIgnoreCase(ENCRYPT.toString())) {
            byte[] encrypted = encrypt(payload);
            save(encrypted, "encrypted.txt");
        } else if (action.equalsIgnoreCase(DECRYPT.toString())) {
            byte[] decrypted = decrypt(payload);
            save(decrypted, "decrypted.txt");
        }
    }


    private static byte[] getPayload(String sourceFilePath) throws IOException {
        File file = new File(sourceFilePath);

        if (!file.exists() || !file.canRead()) {
            throw new FileNotFoundException("Cannot found or read the file");
        }

        return FileUtils.readFileToByteArray(file);
    }


    private static void save(byte[] result, String filename) throws IOException {
        String destPath = System.getProperty("user.home");

        File file = new File(destPath + "\\" + filename);
        FileUtils.writeByteArrayToFile(file, result);
    }


    private static void initKey(String rawKey) {
        if (rawKey == null)
            throw new IllegalArgumentException("Invalid key: Key must not be null");

        byte[] keyBytes = rawKey.getBytes();

        if (keyBytes.length < 16)
            throw new IllegalArgumentException("Invalid key: Length is less than 16 bytes");

        for (int off = 0, i = 0; i < 4; i++) {
            key[i] = ((keyBytes[off++] & 0xff)) |
                    ((keyBytes[off++] & 0xff) <<  8) |
                    ((keyBytes[off++] & 0xff) << 16) |
                    ((keyBytes[off++] & 0xff) << 24);
        }
    }


    private static byte[] encrypt(byte[] payload) {

        int paddedSize = ((payload.length / 8) + (((payload.length % 8) == 0) ? 0 : 1)) * 2;
        int[] buffer = new int[paddedSize + 1];
        buffer[0] = payload.length;
        packToIntArray(payload, buffer, 1);
        doEncrypt(buffer);
        return unpackToByteArray(buffer, 0, buffer.length * 4);
    }


    private static byte[] decrypt(byte[] crypt) {
        assert crypt.length % 4 == 0;
        assert (crypt.length / 4) % 2 == 1;
        int[] buffer = new int[crypt.length / 4];
        packToIntArray(crypt, buffer, 0);
        doDecrypt(buffer);
        return unpackToByteArray(buffer, 1, buffer[0]);
    }


    private static void packToIntArray(byte[] payloadBytes, int[] buffer, int destOffset) {
        assert destOffset + (payloadBytes.length / 4) <= buffer.length;
        int i = 0, shift = 24;
        int j = destOffset;
        buffer[j] = 0;
        while (i<payloadBytes.length) {
            buffer[j] |= ((payloadBytes[i] & 0xff) << shift);
            if (shift == 0) {
                shift = 24;
                j++;
                if (j<buffer.length) buffer[j] = 0;
            }
            else {
                shift -= 8;
            }
            i++;
        }
    }


    private static byte[] unpackToByteArray(int[] src, int srcOffset, int destLength) {
        assert destLength <= (src.length - srcOffset) * 4;
        byte[] dest = new byte[destLength];
        int i = srcOffset;
        int count = 0;
        for (int j = 0; j < destLength; j++) {
            dest[j] = (byte) ((src[i] >> (24 - (8*count))) & 0xff);
            count++;
            if (count == 4) {
                count = 0;
                i++;
            }
        }
        return dest;
    }


    private static void doEncrypt(int[] buffer) {
        assert buffer.length % 2 == 1;
        int i, v0, v1, sum, n;
        i = 1;
        while (i<buffer.length) {
            n = CUPS;
            v0 = buffer[i];
            v1 = buffer[i + 1];
            sum = 0;
            while (n-- > 0) {
                sum += SUGAR;
                v0  += ((v1 << 4 ) + key[0] ^ v1) + (sum ^ (v1 >>> 5)) + key[1];
                v1  += ((v0 << 4 ) + key[2] ^ v0) + (sum ^ (v0 >>> 5)) + key[3];
            }
            buffer[i] = v0;
            buffer[i+1] = v1;
            i+=2;
        }
    }


    private static void doDecrypt(int[] buf) {
        assert buf.length % 2 == 1;
        int i, v0, v1, sum, n;
        i = 1;
        while (i<buf.length) {
            n = CUPS;
            v0 = buf[i];
            v1 = buf[i+1];
            sum = UNSUGAR;
            while (n--> 0) {
                v1  -= ((v0 << 4 ) + key[2] ^ v0) + (sum ^ (v0 >>> 5)) + key[3];
                v0  -= ((v1 << 4 ) + key[0] ^ v1) + (sum ^ (v1 >>> 5)) + key[1];
                sum -= SUGAR;
            }
            buf[i] = v0;
            buf[i+1] = v1;
            i+=2;
        }
    }
}
