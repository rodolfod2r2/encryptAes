import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Encrypt {

    static String IV = "AAAAAAAAAAAAAAAA";
    static String keyEncrypt = "0123456789101112";

    public static void main(String[] args)  {

        System.out.println("Texto Puro: 5215615460832095");

        String textoencriptado = encryptString("5215615460832095");

        System.out.print("Texto Encriptado: ");

        System.out.println(textoencriptado);

        String textodecriptado = decrypt(textoencriptado);

        System.out.println("Texto Decriptado: " + textodecriptado);
    }


    public static String encryptString(String textopuro)  {
        try {
        Cipher encripta = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
        SecretKeySpec key = new SecretKeySpec(keyEncrypt.getBytes("UTF-8"), "AES");
        encripta.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));
        return Base64.getEncoder().withoutPadding().encodeToString(encripta.doFinal(textopuro.getBytes()));
        } catch (NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException | InvalidKeyException ex) {
            Logger.getLogger(EncryptA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnsupportedEncodingException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decrypt(String textoencriptado)  {
        try {
        Cipher decripta = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
        SecretKeySpec key = new SecretKeySpec(keyEncrypt.getBytes("UTF-8"), "AES");
        decripta.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));
        byte[] decodedValue = Base64.getDecoder().decode(textoencriptado);
        byte[] decValue = decripta.doFinal(decodedValue);
        return new String(decValue);
        } catch (NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException | InvalidKeyException ex) {
            Logger.getLogger(EncryptA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnsupportedEncodingException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return null;
    }

}
