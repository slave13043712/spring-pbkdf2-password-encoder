package org.aakimov.security.crypto.password;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collection;
import javax.xml.bind.DatatypeConverter;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import static org.junit.Assert.*;
import static org.junit.runners.Parameterized.Parameters;
import static org.mockito.Mockito.*;

/**
 * This test uses test vectors described in https://www.ietf.org/rfc/rfc6070.txt
 *
 * @author Alexander Akimov
 * @version 1.0
 */
@RunWith(Parameterized.class)
public class PBKDF2PasswordEncoderTest {
    @Mock
    private SecureRandom secureRandom;
    private final int iterationCount;
    private final int derivedKeyLength;
    private final CharSequence rawPassword;
    private final byte[] salt;
    private final String expectedDerivedKey;

    /**
     * Test instance of password encoder
     */
    private PBKDF2PasswordEncoder passwordEncoder;

    /**
     * This constructor is used by Parametrized test runner
     *
     * @param iterationCount number of iterations to perform
     * @param derivedKeyLength derived key length in bits
     * @param rawPassword password to encode
     * @param salt salt to use
     * @param expectedDerivedKey expected encoded password
     */
    public PBKDF2PasswordEncoderTest(
        int iterationCount,
        int derivedKeyLength,
        CharSequence rawPassword,
        byte[] salt,
        String expectedDerivedKey
    ) {
        this.iterationCount = iterationCount;
        this.derivedKeyLength = derivedKeyLength;
        this.rawPassword = rawPassword;
        this.salt = salt;
        this.expectedDerivedKey = expectedDerivedKey;
    }

    @Parameters
    public static Collection<Object[]> data() {
        /**
         * The following data was taken from test vectors described in https://www.ietf.org/rfc/rfc6070.txt
         * Derived key values were converted to upper case format to comply with xsd:hexBinary type
         */
        return Arrays.asList(new Object[][] {
            {1, 160, "password", "salt".getBytes(), "0C60C80F961F0E71F3A9B524AF6012062FE037A6"},
            {2, 160, "password", "salt".getBytes(), "EA6C014DC72D6F8CCD1ED92ACE1D41F0D8DE8957"},
            {4096, 160, "password", "salt".getBytes(), "4B007901B765489ABEAD49D926F721D065A429C1"},
            {16777216, 160, "password", "salt".getBytes(), "EEFE3D61CD4DA4E4E9945B3D6BA2158C2634E984"},
            {4096, 200, "passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt".getBytes(), "3D2EEC4FE41C849B80C8D83662C0E44A8B291A964CF2F07038"},
            {4096, 128, "pass\0word", "sa\0lt".getBytes(), "56FA6AA75548099DCC37D7F03425E0C3"},
        });
    }

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        this.passwordEncoder = new PBKDF2PasswordEncoder(
            this.iterationCount,
            this.secureRandom,
            this.salt.length,
            this.derivedKeyLength
        );
    }

    @Test
    public void testPasswordEncoderEncodesPasswordCorrectly() {
        doAnswer(invocationOnMock -> {
            Object[] arguments = invocationOnMock.getArguments();
            System.arraycopy(this.salt, 0, arguments[0], 0, this.salt.length);
            return null;
        }).when(this.secureRandom).nextBytes(any(byte[].class));

        assertEquals(
            DatatypeConverter.printHexBinary(this.salt) + ":" + this.expectedDerivedKey,
            this.passwordEncoder.encode(this.rawPassword)
        );
    }

    @Test
    public void testPasswordEncoderMatchesPasswordCorrectly() {
        assertTrue(this.passwordEncoder.matches(
            this.rawPassword,
            DatatypeConverter.printHexBinary(this.salt) + ":" + this.expectedDerivedKey
        ));
        // check that salt is taken into account and expected to be present in encoded password
        assertFalse(this.passwordEncoder.matches(this.rawPassword, this.expectedDerivedKey));
    }
}
