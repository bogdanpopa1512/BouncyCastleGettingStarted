package crypto.exceptions;

/**
 * Created by bogdan on 08.05.2015.
 */
public class KeyNotReadyException extends Exception{

    private static final int KEY_LEN = 32;

    public KeyNotReadyException(final int keyTempSize){

        super("The key for the AES chipher is not ready!! Only " + KEY_LEN + " bytes of the " + KEY_LEN + "required");

    }

}
