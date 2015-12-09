package org.aakimov.security.crypto.password;

import org.springframework.security.crypto.password.PasswordEncoder;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.xml.bind.DatatypeConverter;

/**
 * Password encoder based on PBKDF2 key derivation function
 *
 * @author Alexander Akimov
 * @version 1.0
 */
public class PBKDF2PasswordEncoder implements PasswordEncoder {

    /**
     * Number of iterations to perform
     */
    private final int iterationCount;

    /**
     * Derived key length in bits
     */
    private final int derivedKeyLength;

    /**
     * Salt length in bytes
     */
    private final int saltLength;

    /**
     * Secret key algorithm (this implementation uses PBKDF2WithHmacSHA1)
     */
    private final String secretKeyAlgorithm;

    /**
     * Instance of secure random
     */
    private final SecureRandom secureRandom;

    /**
     * Create instance that performs 10000 iterations and uses SHA1PRNG random generator
     */
    public PBKDF2PasswordEncoder() {
        this(10000, null, 8, 512);
    }

    /**
     * Create instance that uses SHA1PRNG random generator
     *
     * @param iterationCount number of iterations to perform
     */
    public PBKDF2PasswordEncoder(int iterationCount) {
        this(iterationCount, null, 8, 512);
    }

    /**
     * Create instance that uses given random generator or SHA1PRNG random generator if null is given
     *
     * @param iterationCount number of iterations to perform
     * @param secureRandom the secure random instance to use
     */
    public PBKDF2PasswordEncoder(int iterationCount, SecureRandom secureRandom) {
        this(iterationCount, secureRandom, 8, 512);
    }

    /**
     * Create instance that uses given random generator or SHA1PRNG random generator if null is given
     *
     * @param iterationCount number of iterations to perform
     * @param secureRandom the secure random instance to use
     * @param saltLength the length of salt in bytes to use
     * @param derivedKeyLength the length of derived key (encoded password) in bits
     */
    public PBKDF2PasswordEncoder(int iterationCount, SecureRandom secureRandom, int saltLength, int derivedKeyLength) {
        this.iterationCount = iterationCount;
        this.saltLength = saltLength;
        this.derivedKeyLength = derivedKeyLength;
        this.secretKeyAlgorithm = "PBKDF2WithHmacSHA512";
        if (secureRandom == null) {
            try {
                secureRandom = SecureRandom.getInstance("SHA1PRNG");
            } catch (NoSuchAlgorithmException exception) {
                throw new RuntimeException(exception);
            }
        }
        this.secureRandom = secureRandom;
    }

    /**
     * Encode the raw password
     *
     * @param rawPassword the raw password to encode
     * @return the encoded password
     */
    @Override
    public String encode(CharSequence rawPassword) {
        // Generate salt
        byte[] salt = new byte[this.saltLength];
        this.secureRandom.nextBytes(salt);
        return this.encode(rawPassword, salt);
    }

    /**
     * Verify the encoded password obtained from storage matches the submitted raw password after it too is encoded
     *
     * @param rawPassword the raw password to encode and match
     * @param encodedPassword the encoded password from storage to compare with
     * @return true if the raw password, after encoding, matches the encoded password from storage
     */
    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        String[] parts = encodedPassword.split(":");
        if (parts.length != 2) {
            return false;
        }
        byte[] salt = DatatypeConverter.parseHexBinary(parts[0]);
        return this.encode(rawPassword, salt).equals(encodedPassword);
    }

    /**
     * Encode the raw password using given salt
     *
     * @param rawPassword the raw password to encode
     * @param salt the salt to use during encoding
     * @return the encoded password
     */
    private String encode(CharSequence rawPassword, byte[] salt) {
        try {
            // Generate secret
            PBEKeySpec keySpecification = new PBEKeySpec(
                rawPassword.toString().toCharArray(),
                salt,
                this.iterationCount,
                this.derivedKeyLength
            );
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(this.secretKeyAlgorithm);
            byte[] hash = secretKeyFactory.generateSecret(keySpecification).getEncoded();
            return DatatypeConverter.printHexBinary(salt) + ':' + DatatypeConverter.printHexBinary(hash);
        } catch (NoSuchAlgorithmException|InvalidKeySpecException exception) {
            throw new RuntimeException(exception);
        }
    }
}
