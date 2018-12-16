package ru.tsu.kanaev;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.*;
import java.util.Scanner;

import static ru.tsu.kanaev.Action.DECRYPT;
import static ru.tsu.kanaev.Action.ENCRYPT;

public class Application {

    private final static int SUGAR = 0x9E3779B9;
    private final static int CUPS  = 32;
    private final static int UNSUGAR = 0xC6EF3720;

    private static int[] key = new int[4];

    public static void main(String[] args) throws IOException {
        initKey("Some simple key for testing encryption");

        printApplicationInfo();
        String action = getAction();
        String sourceFilePath = getFilePath();

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
        } else {
            throw new IllegalArgumentException("Action can be either \"encrypt\" or \"decrypt\"");
        }
    }


    private static byte[] getPayload(String sourceFilePath) throws IOException {
        File file = new File(sourceFilePath);

        if (!file.exists() || !file.canRead()) {
            throw new FileNotFoundException("Cannot find or read the source file");
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


    private static String getAction() {
        System.out.println("Specify the action. Possible variants: encrypt, decrypt.");
        System.out.print("Action: ");

        return scanArgument();
    }


    private static String getFilePath() {
        System.out.println("Specify the path to the source file.");
        System.out.print("Path: ");

        return scanArgument();
    }

    private static String scanArgument() {
        Scanner scanner = new Scanner(System.in);
        String arg = "";
        if (scanner.hasNextLine()) {
            arg = scanner.nextLine();
        }

        return StringUtils.trim(arg);
    }


    private static void printApplicationInfo() {
        printBanner();
        System.out.println("Welcome to the TEA encryptor application!");
        System.out.println("The result of the application work will be stored to the user's home root");
        System.out.println("encrypted.txt is the result of the encryption action.");
        System.out.println("decrypted.txt is the result of the decryption action.");
    }

    private static void printBanner() {
        System.out.println("  _______ ______            ______                             _             \n" +
                " |__   __|  ____|   /\\     |  ____|                           | |            \n" +
                "    | |  | |__     /  \\    | |__   _ __   ___ _ __ _   _ _ __ | |_ ___  _ __ \n" +
                "    | |  |  __|   / /\\ \\   |  __| | '_ \\ / __| '__| | | | '_ \\| __/ _ \\| '__|\n" +
                "    | |  | |____ / ____ \\  | |____| | | | (__| |  | |_| | |_) | || (_) | |   \n" +
                "    |_|  |______/_/    \\_\\ |______|_| |_|\\___|_|   \\__, | .__/ \\__\\___/|_|   \n" +
                "                                                    __/ | |                  \n" +
                "                                                   |___/|_|                 ");
        System.out.println();
    }
}