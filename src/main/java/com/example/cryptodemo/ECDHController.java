package com.example.cryptodemo;

import jakarta.annotation.PostConstruct;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

@RestController
public class ECDHController {

    private static final Logger log = LoggerFactory.getLogger(ECDHController.class);
    private static final String AES_GCM = "AES/GCM/NoPadding";
    private KeyPair keyPair;
    private SecretKey aesKeySpec;

    @PostConstruct
    public void init() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        keyPair = kpg.generateKeyPair();
        String publicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        log.info("serverPublicKey: {}", publicKey);
        String privateKey = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        log.info("serverPrivateKey: {}", privateKey);
    }

    @GetMapping("/publicKey")
    public String getPublicKey() {
        byte[] encoded = keyPair.getPublic().getEncoded();
        return Base64.getEncoder().encodeToString(encoded);
    }

    @PostMapping("/exchangeKey")
    public String exchangeKey(@RequestBody String clientPublicKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        log.info("clientPublicKey: {}", clientPublicKey);
        byte[] clientPublicKeyBytes = Base64.getDecoder().decode(clientPublicKey);
        KeyFactory keyFactory = KeyFactory.getInstance("ECDH", "BC");
        PublicKey clientPubKey = keyFactory.generatePublic(new X509EncodedKeySpec(clientPublicKeyBytes));
        try {
            byte[] sharedSecret = generateSecret(clientPubKey);
            aesKeySpec = new SecretKeySpec(sharedSecret, 0, 32, AES_GCM);
        } catch (InvalidKeyException e) {
            log.error("generate secret error", e);
        }
        return Base64.getEncoder().encodeToString(aesKeySpec.getEncoded());
    }

    private byte[] generateSecret(PublicKey clientPubKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
        ka.init(keyPair.getPrivate());
        ka.doPhase(clientPubKey, true);
        return ka.generateSecret();
    }

    @PostMapping("/encrypt")
    public String encrypt(@RequestBody Map<String, String> data) {
        String iv = data.get("iv");
        String text = data.get("text");
        return encrypt(iv, text);
    }

    private String encrypt(String ivStr, String text) {
        try {
            IvParameterSpec ivSpec = new IvParameterSpec(hexStringToByteArray(ivStr));
            Cipher cipher = Cipher.getInstance(AES_GCM, "BC");
            cipher.init(Cipher.ENCRYPT_MODE, aesKeySpec, ivSpec);
            byte[] encryptedBytes = cipher.doFinal(text.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            log.error("Error occurred during encryption", e);
            return "error";
        }
    }

    @PostMapping("/decrypt")
    public String decrypt(@RequestBody Map<String, String> encryptedData) {
        String iv = encryptedData.get("iv");
        String ciphertext = encryptedData.get("ciphertext");
        return decrypt(iv, ciphertext);
    }

    public String decrypt(String ivStr, String encryptedText) {
        try {
            byte[] iv = hexStringToByteArray(ivStr);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance(AES_GCM, "BC");
            cipher.init(Cipher.DECRYPT_MODE, aesKeySpec, ivSpec);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
            return new String(decryptedBytes);
        } catch (Exception e) {
            log.error("Error occurred during decryption", e);
            return "error";
        }
    }

    private byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}
