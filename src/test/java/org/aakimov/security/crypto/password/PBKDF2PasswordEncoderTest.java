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
         * The following data was taken from test vectors described in http://stackoverflow.com/questions/15593184/pbkdf2-hmac-sha-512-test-vectors
         * Derived key values were converted to upper case format to comply with xsd:hexBinary type
         */
        return Arrays.asList(new Object[][] {
            {1, 512, "password", "salt".getBytes(), "867F70CF1ADE02CFF3752599A3A53DC4AF34C7A669815AE5D513554E1C8CF252C02D470A285A0501BAD999BFE943C08F050235D7D68B1DA55E63F73B60A57FCE"},
            {2, 512, "password", "salt".getBytes(), "E1D9C16AA681708A45F5C7C4E215CEB66E011A2E9F0040713F18AEFDB866D53CF76CAB2868A39B9F7840EDCE4FEF5A82BE67335C77A6068E04112754F27CCF4E"},
            {4096, 512, "password", "salt".getBytes(), "D197B1B33DB0143E018B12F3D1D1479E6CDEBDCC97C5C0F87F6902E072F457B5143F30602641B3D55CD335988CB36B84376060ECD532E039B742A239434AF2D5"},
            {4096, 512, "passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt".getBytes(), "8C0511F4C6E597C6AC6315D8F0362E225F3C501495BA23B868C005174DC4EE71115B59F9E60CD9532FA33E0F75AEFE30225C583A186CD82BD4DAEA9724A3D3B8"},
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
