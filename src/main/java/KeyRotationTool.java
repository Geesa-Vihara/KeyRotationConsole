import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class KeyRotationTool {

    public static final  String AES="AES";
    private static final String AES_CIPHER_ALGORITHM
            = "AES/CBC/PKCS5PADDING";
    public static byte[] initializationVector
            = createInitializationVector();
    public static Map<String,String> dataStore = new HashMap<String, String>();

    public static void main(String[] args) throws Exception {
        int n;
        System.out.print("Welcome to the Key Rotation Tool\nPlease select an option\n1. Create key\n" +
                "2. Encrypt Text with key\n3. Decrypt Text with key\n4. Show Data Store\n5. Rotate a key\n" +
                "6. Exit\nEnter your option: ");
        Scanner input = new Scanner(System.in);
        try {
            while ((n = input.nextInt()) != 6) {
                switch (n) {
                    case 1:
                        createKey();
                        break;
                    case 2:
                        encryptText();
                        break;
                    case 3:
                        decryptText();
                        break;
                    case 4:
                        showDataStore();
                        break;
                    case 5:
                        rotateKey();
                        break;

                }
                System.out.print("Welcome to the Key Rotation Tool\nPlease select an option\n1. Create key\n" +
                        "2. Encrypt Text with key\n3. Decrypt Text with key\n4. Show Data Store\n5. Rotate a key\n" +
                        "6. Exit\nEnter your option: ");
            }
        } catch (Exception e){
            System.out.println("ERROR: "+e);
        }
    }

    public static SecretKey createKey() throws Exception {
        System.out.println("Welcome, let's create a new encryption key");
        SecureRandom securerandom = new SecureRandom();
        KeyGenerator keygenerator = KeyGenerator.getInstance(AES);
        keygenerator.init(256,securerandom);
        SecretKey key = keygenerator.generateKey();
        System.out.println("Your new key: "+Base64.getEncoder().encodeToString(key.getEncoded())+"\n");
        return key;
    }

    public static void encryptText() throws Exception {
        System.out.println("Welcome, let's encrypt your text with the key you generated in step 1");
        Scanner plainText= new Scanner(System.in);
        System.out.print("Enter Text: ");
        String PlainText= plainText.nextLine();
        System.out.print("Enter Key: ");
        byte[] decodedKey = Base64.getDecoder().decode(plainText.nextLine());
        SecretKey Key=  new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        IvParameterSpec ivParameterSpec
                = new IvParameterSpec(
                initializationVector);
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE,Key,ivParameterSpec);
        dataStore.put(Base64.getEncoder().encodeToString(Key.getEncoded()),Base64.getEncoder().
                encodeToString(cipher.doFinal(PlainText.getBytes())));
        System.out.println("Your cipher text: "+Base64.getEncoder().
                encodeToString(cipher.doFinal(PlainText.getBytes())));
    }

    public static void decryptText() throws Exception{
        System.out.println("Welcome, let's decrypt the cipher text you got in step 2");
        Scanner cipherText= new Scanner(System.in);
        System.out.print("Enter Cipher Text: ");
        byte[] CipherText= Base64.getDecoder().decode(cipherText.nextLine());
        System.out.print("Enter Key: ");
        byte[] decodedKey = Base64.getDecoder().decode(cipherText.nextLine());
        SecretKey Key=  new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        IvParameterSpec ivParameterSpec
                = new IvParameterSpec(
                initializationVector);
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE,Key,ivParameterSpec);
        System.out.println("Your Decrypted Text: "+new String(cipher.doFinal(CipherText)));
    }

    public static String decryptText(SecretKey key, byte[] cipherText) throws Exception{
        IvParameterSpec ivParameterSpec
                = new IvParameterSpec(
                initializationVector);
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE,key,ivParameterSpec);
        System.out.println("Your Decrypted Text: "+new String(cipher.doFinal(cipherText)));
        return new String(cipher.doFinal(cipherText));
    }

    public static String encryptText(SecretKey key, String plainText) throws Exception {
        IvParameterSpec ivParameterSpec
                = new IvParameterSpec(
                initializationVector);
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE,key,ivParameterSpec);
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
    }

    public static void showDataStore() {
        System.out.println("Your Data Store");
        for(Map.Entry m:dataStore.entrySet()){
            System.out.println("Key: "+m.getKey()+" CipherText: "+m.getValue());
        }
    }

    public static void rotateKey() throws Exception {
        showDataStore();
        System.out.print("Let's rotate a key. Enter the key to rotate.\nEnter Key: ");
        Scanner cipherText= new Scanner(System.in);
        String myOldKey = cipherText.nextLine();
        for(Map.Entry m:dataStore.entrySet()){
            if(m.getKey().equals(myOldKey)){
                byte[] decodedKey = Base64.getDecoder().decode((String) m.getKey());
                SecretKey Key=  new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
                byte[] cipherTxt = Base64.getDecoder().decode((String) m.getValue());
                String dText = decryptText(Key,cipherTxt);
                SecretKey newKey = createKey();
                String newEncrypted = encryptText(newKey,dText);
                dataStore.remove(m.getKey());
                dataStore.put(Base64.getEncoder().encodeToString(newKey.getEncoded()),newEncrypted);
            }
        }
        showDataStore();
    }

    public static byte[] createInitializationVector() {
        byte[] initializationVector
                = new byte[16];
        SecureRandom secureRandom
                = new SecureRandom();
        secureRandom.nextBytes(initializationVector);
        return initializationVector;
    }
}
