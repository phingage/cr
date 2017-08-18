package io.armanini;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static javax.crypto.Cipher.ENCRYPT_MODE;

public class Util {

    public String generatRandomByteSequence(int length){
        SecureRandom secureRandom = new SecureRandom();
        byte bytes[] = new byte[length];
        secureRandom.nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }
    public String convertBytesArrayToBase64(byte bytes[]){
        try {
            return  new String(bytes, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return "";
        }
    }

    public String signStringWithPubKey(String string, String pubKey) throws
            NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException,
            UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException {
        byte keyByte[] = Base64.getDecoder().decode(pubKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyByte);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(ENCRYPT_MODE,publicKey); //63
        byte string_byte[] = string.getBytes("UTF-8");
        byte final_bytes[] = cipher.doFinal(string_byte);
        return Base64.getEncoder().encodeToString(final_bytes);
    }


    public String HashStringWithRandomString(String inputStrin, String RandomString, int length) throws NoSuchPaddingException, NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {



        String cuttedRandom = RandomString.substring(0,length);
        Cipher instance = Cipher.getInstance("AES/ECB/PKCS5Padding");
        byte randomByte[] = cuttedRandom.getBytes("UTF-8");
        byte passwordByte[] = inputStrin.getBytes("UTF-8");
        SecretKeySpec keySpec = new SecretKeySpec(randomByte,"AES");
        instance.init(1,keySpec);
        byte hashed_bytes[] = instance.doFinal(passwordByte);
        return Base64.getEncoder().encodeToString(hashed_bytes);
    }

    public String craeteDigest(String startString, int times) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        byte startBytes[] = startString.getBytes("UTF-8");
        byte returnBytes[] = startBytes;
        int now=0;
        while(now<times){
            MessageDigest instance = MessageDigest.getInstance("SHA-256");
            instance.reset();
            instance.update(returnBytes);
            returnBytes =instance.digest();
            now++;
        }
        String fullSign = Base64.getEncoder().encodeToString(returnBytes);
        return fullSign;
    }

    public String createValidVerificaRequest(String username, String password) throws NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException,
            IllegalBlockSizeException, UnsupportedEncodingException, InvalidKeyException, InvalidKeySpecException {
        String pubkey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuP/zmF8ZrnJnGNWK1Do4/Kv9lXdnwooCNp+dqrN7SCWi9X4RXjzIx+WACdPmNDqazu7VPnYHgSIXhoujvVtu0bVqcu0XoVhdbfuHhKVLhi9rqXUhfGfHdPOFy06p3cY63d3gbCyeFcPuwwU5uxIZImfxtZoFlfz2PoxeMrsR8116Vxd3UYaClUvorDML3KpntlBut+EysL9SPAE5VRvlBuRA8oWMx5918ukWYxib5YqQInhkO14KJ5X9wCubzlwH7hXK4eAZE4nQpbK6eY13g4CeyKKYvk7AuWGWDk9puakPJ+ba8QIipACVSCW+Gmrkx1kaeZvF6Q3KJAoIlP4svwIDAQAB";
        String randomString = generatRandomByteSequence(32);
        String codice = signStringWithPubKey(randomString,pubkey);
        String hashPasswrod = HashStringWithRandomString(password,randomString,16);
        String startRequest = "\"buildNumber\":\"376\",\"codice\":\"%s\",\"dispositivoApp\":{\"codiceUnivocoDisp\":\"4a1f2b754e0ed363\",\"so\":\"Google_Android\",\"versioneApp\":\"3.2.0.0\"},\"lingua\":\"it\",\"password\":\"%s\",\"prodotto\":\"I\",\"userId\":\"%s\",\"pos\":0";
        String firstPart = String.format(startRequest,codice,hashPasswrod,username);
        String preHash = firstPart+","+randomString;
        String signature = craeteDigest(preHash,5);
        String finalRequest = String.format("{\"signature\":\"%s\",%s}",signature,firstPart);
        return finalRequest;
    }
}
