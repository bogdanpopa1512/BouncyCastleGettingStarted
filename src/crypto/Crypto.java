package crypto;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.ISO10126d2Padding;
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
         * Available Ciphers:
         * - AESEngine
         * - AESFastEngine
         * - AESLightEngine
         * - BlowfishEngine
         * - CamelliaEngine
         * - CAST5Engine
         * - CAST6Engine
         * - CBCBlockCipher
         * - CFBBlockCipher
         * - DESedeEngine
         * - DESEngine
         * - GOFBBlockCipher
         * - GOST28147Engine
         * - IDEAEngine
         * - NoekeonEngine
         * - NullEngine
         * - OFBBlockCipher
         * - OpenPGPCFBBlockCipher
         * - PGPCFBBlockCipher
         * - RC2Engine
         * - RC532Engine
         * - RC564Engine
         * - RC6Engine
         * - RijndaelEngine
         * - SEEDEngine
         * - SerpentEngine
         * - SICBlockCipher
         * - SkipjackEngine
         * - TEAEngine
         * - TwofishEngine
         * - XTEAEngine
         */

        BlockCipher blockCipher = new AESEngine();

        /*
         * Padding
         * In some cases padding is necessary because some algorithms requires
         * the input to be an exact multiple of the block size.
         */

        BlockCipherPadding blockCipherPadding = new ISO10126d2Padding();

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
         * In some cases padding is necessary because some algorithms requires
         * the input to be an exact multiple of the block size.
         */

        BlockCipherPadding blockCipherPadding = new ISO10126d2Padding();

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

        bufferedBlockCipher.init(mode,cipherParameters);

        int maxOutputSize = bufferedBlockCipher.getOutputSize(data.length);

        byte[] processedData = new byte[maxOutputSize];


        /*
            Processing
         */

        int bytesProcessed = bufferedBlockCipher.processBytes(data,0,data.length,processedData,0);

        bytesProcessed += bufferedBlockCipher.doFinal(processedData,bytesProcessed);

        /*
           Check if the final array has more elements than it should
         */

        if(bytesProcessed == processedData.length)
            return processedData;

        return Arrays.copyOfRange(processedData,0,bytesProcessed);
    }
}
