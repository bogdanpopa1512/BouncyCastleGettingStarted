package crypto.exceptions;

/**
 * Created by bogdan on 08.05.2015.
 */
public class NoMoreSpaceException extends Exception {

    public NoMoreSpaceException(String text) {
        super(text);
    }

    public NoMoreSpaceException(int toPut, int actual) {

        super("There is no more space for the key material.You tried to introduce " + toPut + " bytes but the key already has " + actual + " bytes");

    }

}
