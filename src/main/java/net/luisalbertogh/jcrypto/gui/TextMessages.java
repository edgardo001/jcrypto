/**
 * © 2009-2012 Tex Toll Services, LLC
 */
package net.luisalbertogh.jcrypto.gui;

/**
 * Text messages.
 * 
 * @author lagarcia
 */
public enum TextMessages {
    /** Message digest form title. */
    MD_FORM_TITLE("Message Digest"),
    /** Select algorithm. */
    SEL_ALGORITHM("Select algorithm"),
    /** Enter text. */
    ENTER_TEXT("Enter text"),
    /** Digested text. */
    DIGESTED("Digested"),
    /** Submit. */
    SUBMIT("Submit"),
    /** Reset. */
    RESET("Reset"),
    /** Crypto form title. */
    CRYPT_FORM_TITLE("Encrypt/Decrypt"),
    /** Password. */
    PASSWORD("Password"),
    /** Text. */
    TEXT("Text"),
    /** Text encryp. */
    TEXT_ENC("Text to encrypt"),
    /** Text decrypt. */
    TEXT_DEC("Text to decrypt"),
    /** Encrypt. */
    ENC_DEC("Encrypt or Decrypt"),
    /** Encrypt. */
    ENC("Encrypt"),
    /** Decrypt. */
    DEC("Decrypt"),
    /** Module. */
    MOD("Module"),
    /** File. */
    FILE("File"),
    /** Select. */
    SELECT("Select..."),
    /** Save. */
    SAVE("Save..."),
    /** Password or keystore. */
    PASS_KEYSTORE("Password or keystore"),
    /** Keystore. */
    KEYSTORE("Keystore file"),
    /** About. */
    ABOUT("About..."),
    /** Providers. */
    PROVIDERS("Providers");

    /** Message string. */
    private String msg;

    /**
     * Constructor.
     * 
     * @param msg
     */
    TextMessages(String msg) {
        this.msg = msg;
    }

    /**
     * Get message string.
     * 
     * @return The message string
     */
    public String getMsg() {
        return this.msg;
    }
}
