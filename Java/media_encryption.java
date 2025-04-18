//HKDF Key Derivation Function

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

public class HKDF {
    
    public static byte[] hkdf(byte[] key, int length, byte[] info, byte[] salt, String algorithm) 
            throws NoSuchAlgorithmException, InvalidKeyException {
        
        final String hashAlgorithm = "Hmac" + algorithm.toUpperCase();
        
        // If salt is not provided, use zeros
        if (salt == null || salt.length == 0) {
            salt = new byte[Mac.getInstance(hashAlgorithm).getMacLength()];
            Arrays.fill(salt, (byte) 0);
        }
        
        // Extract
        Mac mac = Mac.getInstance(hashAlgorithm);
        mac.init(new SecretKeySpec(salt, hashAlgorithm));
        byte[] prk = mac.doFinal(key);
        
        // Expand
        byte[][] blocks = new byte[length / mac.getMacLength() + 1][];
        byte[] block = new byte[0];
        
        for (int i = 0; i < blocks.length; i++) {
            mac = Mac.getInstance(hashAlgorithm);
            mac.init(new SecretKeySpec(prk, hashAlgorithm));
            mac.update(block);
            if (info != null) {
                mac.update(info);
            }
            mac.update((byte) (i + 1));
            block = mac.doFinal();
            blocks[i] = block;
        }
        
        // Combine blocks and truncate to desired length
        byte[] result = new byte[length];
        int resultOffset = 0;
        for (byte[] b : blocks) {
            if (resultOffset + b.length <= length) {
                System.arraycopy(b, 0, result, resultOffset, b.length);
                resultOffset += b.length;
            } else {
                System.arraycopy(b, 0, result, resultOffset, length - resultOffset);
                break;
            }
        }
        
        return result;
    }
}

// Download Media

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

public class MediaDownloader {
    
    public static byte[] downloadFile(String url, Map debug) {
        try {
            HttpClient client = HttpClient.newBuilder()
                    .followRedirects(HttpClient.Redirect.NORMAL)
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();
                    
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .GET()
                    .build();
                    
            HttpResponse response = client.send(request, 
                    HttpResponse.BodyHandlers.ofByteArray());
            
            debug.put("http_code", response.statusCode());
            debug.put("downloaded_size", response.body().length);
            
            return response.body();
        } catch (IOException | InterruptedException e) {
            debug.put("error", e.getMessage());
            return null;
        }
    }
}


// Decrypt Media
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.util.Map;

public class MediaDecryptor {
    
    public static byte[] tryDecrypt(byte[] encrypted, byte[] cipherKey, byte[] iv, Map debug) {
        int[] truncLengths = new int[] {0, 10, 16, 32};
        
        for (int len : truncLengths) {
            try {
                byte[] cut = len > 0 ? 
                        Arrays.copyOf(encrypted, encrypted.length - len) : 
                        encrypted;
                
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                SecretKeySpec keySpec = new SecretKeySpec(cipherKey, "AES");
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                
                cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
                byte[] decrypted = cipher.doFinal(cut);
                
                debug.put("decrypted_size", decrypted.length);
                debug.put("truncate_bytes", len);
                
                return decrypted;
            } catch (Exception e) {
                // Try next truncation length
            }
        }
        
        debug.put("decrypt_error", "Decryption failed for all truncation attempts");
        return null;
    }
}

// Usage example

import java.io.*;
import java.net.*;
import java.util.Base64;

public class WhatsAppMediaDecryptor {

    public static void main(String[] args) {
        String url = "https://mmg.whatsapp.net/d/f/example-image-url.enc";
        String mediaKey = "ExAmPleB@s364+EnC0d3dM3dIaK3y=";

        byte[] encrypted = downloadFile(url);

        if (encrypted != null) {
            byte[] decrypted = decryptMedia(encrypted, mediaKey, "Image");

            if (decrypted != null) {
                String base64Data = Base64.getEncoder().encodeToString(decrypted);
                String dataUri = "data:image/jpeg;base64," + base64Data;
                System.out.println("Decryption successful! Data URI length: " + dataUri.length());
            } else {
                System.out.println("Decryption failed: decryptMedia not implemented");
            }
        } else {
            System.out.println("Download failed.");
        }
    }

    private static byte[] downloadFile(String fileUrl) {
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            URL url = new URL(fileUrl);
            InputStream in = url.openStream();
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
            return out.toByteArray();
        } catch (IOException e) {
            System.out.println("Download error: " + e.getMessage());
            return null;
        }
    }

    private static byte[] decryptMedia(byte[] encrypted, String mediaKey, String mediaType) {
        // You need to implement this based on WhatsApp's spec
        // Placeholder
        return null;
    }
}
