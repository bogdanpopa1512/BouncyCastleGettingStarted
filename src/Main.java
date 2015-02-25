import crypto.Crypto;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by bpopa on 2/25/2015.
 */

public class Main {
    public static void main(String[] args) throws InvalidCipherTextException {

        String key = "ohmygodthiskeyisthemostcomplicat";
        String data = "Let's see if this encrption works";

        byte[] ecryptedData = Crypto.encryptAES256(data.getBytes(), key.getBytes());

        String decryptedData = new String(Crypto.decryptAES256(ecryptedData,key.getBytes()));

        System.out.println(decryptedData);
    }
}
