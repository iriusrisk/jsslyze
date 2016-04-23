package net.continuumsecurity.jsslyze;

import org.apache.commons.io.FileUtils;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertEquals;

/**
 * Created by stephen on 18/01/15.
 */
public class SSLyzeParserBasicTest {
    String output;
    SSLyzeParser parser;

    @Before
    public void setup() throws IOException {
        output = FileUtils.readFileToString(new File("src/test/resources/sslyze.example"));
        parser = new SSLyzeParser(output);
    }

    @Test
    public void testListPreferredCipherSuites() {
        List<String> ciphers = parser.listPreferredCipherSuiteNamesFor("TLSV1_2");
        assertEquals("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", ciphers.get(0));
        assertEquals(1, ciphers.size());

        assertEquals(0, parser.listPreferredCipherSuiteNamesFor("TLSV1_1").size());
        assertEquals(0, parser.listPreferredCipherSuitesFor("SSLV2").size());
    }

    @Test
    public void testListAcceptedCipherSuites() {
        List<String> ciphers = parser.listAcceptedCipherSuiteNamesFor("TLSV1_2");
        assertEquals("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", ciphers.get(0));
        assertEquals(4, ciphers.size());

        assertEquals(0, parser.listAcceptedCipherSuiteNamesFor("TLSV1_1").size());
        assertEquals(0, parser.listAcceptedCipherSuitesFor("SSLV2").size());
    }

    @Test
    public void testListAllSupportedProtocols() {
        List<String> suites = parser.listAllSupportedProtocols();
        assertEquals(1, suites.size());
        assertEquals("TLSV1_2", suites.get(0));
    }

    @Test
    public void testFindSmallestAcceptedKeySize() {
        assertEquals(128, parser.findSmallestAcceptedKeySize());
    }

    @Test
    public void testDoesAnyLineMatch() {
        assertThat(parser.doesAnyLineMatch(".*Client-initiated Renegotiation:\\s+OK\\s+-\\s+Rejected.*"), equalTo(true));
    }
}

