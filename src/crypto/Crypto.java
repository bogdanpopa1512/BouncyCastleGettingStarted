package crypto;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.paddings.ZeroBytePadding;
import org.bouncycastle.crypto.params.KeyParameter;

import java.util.Arrays;

/**
 * Created by bpopa on 2/25/2015.
 */
public class Crypto {

    private static final boolean DECRYPT_MODE = false;

    private static final boolean ENCRYPT_MODE = true;

    public static byte[] encryptAES256(byte[] dataToEncrypt , byte[] key) throws InvalidCipherTextException {

        /*
            Key as cipher parameter
         */

        assert key.length == 32;

        CipherParameters cipherParameters = new KeyParameter(key);

        /*
         * Initialisation of the block cypher
         */

        BlockCipher blockCipher = new AESEngine();

        /*
         * Padding
         */

        BlockCipherPadding blockCipherPadding = new ZeroBytePadding();

        BufferedBlockCipher bufferedBlockCipher = new PaddedBufferedBlockCipher(blockCipher,blockCipherPadding);

        /*
            Encryption
         */

        return process(dataToEncrypt, bufferedBlockCipher, cipherParameters, ENCRYPT_MODE);
    }

    public static byte[] decryptAES256(byte[] dataToDecrypt , byte[] key) throws InvalidCipherTextException {

        /*
            Key as cipher parameter
         */

        assert key.length == 32;

        CipherParameters cipherParameters = new KeyParameter(key);

        /*
         * Initialisation of the block cypher
         */

        BlockCipher blockCipher = new AESEngine();

        /*
         * Padding
         */

        BlockCipherPadding blockCipherPadding = new ZeroBytePadding();

        BufferedBlockCipher bufferedBlockCipher = new PaddedBufferedBlockCipher(blockCipher,blockCipherPadding);

        /*
            Decryption
         */

        return process(dataToDecrypt,bufferedBlockCipher,cipherParameters,DECRYPT_MODE);

    }

    private static byte[] process(byte[] data ,BufferedBlockCipher bufferedBlockCipher , CipherParameters cipherParameters , boolean mode) throws InvalidCipherTextException {

        /*
            Init
         */
        System.out.println(data.length + " l");
        bufferedBlockCipher.init(mode,cipherParameters);

        int maxOutputSize = bufferedBlockCipher.getOutputSize(data.length);

        byte[] processedData = new byte[maxOutputSize];

        System.out.println(maxOutputSize);

        /*
            Processing
         */

        int bytesProcessed = bufferedBlockCipher.processBytes(data,0,data.length,processedData,0);

        bytesProcessed += bufferedBlockCipher.doFinal(processedData,bytesProcessed);

        /*
           Check if the final array has more elements than it should
         */
        System.out.println(bytesProcessed);
        if(bytesProcessed == processedData.length)
            return processedData;

        return Arrays.copyOfRange(processedData,0,bytesProcessed);
    }
}
