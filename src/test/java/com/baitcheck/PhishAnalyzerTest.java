package com.baitcheck;

import com.baitcheck.analysis.AnalysisResult;
import com.baitcheck.analysis.PhishAnalyzer;
import com.baitcheck.analysis.Severity;
import com.baitcheck.analysis.Verdict;
import com.baitcheck.parser.EmlParser;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PhishAnalyzerTest {

    private final EmlParser parser = new EmlParser();
    private final PhishAnalyzer analyzer = new PhishAnalyzer();

    private AnalysisResult analyze(String sample) throws IOException {
        return analyzer.analyze(parser.parse(Path.of("samples", sample)));
    }

    private static boolean hasFinding(AnalysisResult r, String titleFragment) {
        return r.findings().stream().anyMatch(f -> f.title().contains(titleFragment));
    }

    @Test
    void legitimateNewsletterIsSafe() throws IOException {
        AnalysisResult r = analyze("01-legit-newsletter.eml");
        assertEquals(Verdict.LIKELY_SAFE, r.verdict());
        assertEquals(0, r.count(Severity.HIGH));
    }

    @Test
    void paypalPhishIsCaught() throws IOException {
        AnalysisResult r = analyze("02-paypal-account-limited.eml");
        assertEquals(Verdict.LIKELY_PHISHING, r.verdict());
        assertTrue(hasFinding(r, "Link text doesn't match"));
        assertTrue(hasFinding(r, "raw IP address"));
        assertTrue(hasFinding(r, "free email account"));
        assertTrue(hasFinding(r, "SPF failed"));
    }

    @Test
    void sarsRefundScamIsCaught() throws IOException {
        AnalysisResult r = analyze("03-sars-tax-refund.eml");
        assertEquals(Verdict.LIKELY_PHISHING, r.verdict());
        assertTrue(hasFinding(r, "Double file extension"));
        assertTrue(hasFinding(r, "URL shortener"));
        assertTrue(hasFinding(r, "imitates SARS"));
    }

    @Test
    void lookalikeDomainIsCaughtEvenWhenAuthenticationPasses() throws IOException {
        AnalysisResult r = analyze("04-microsoft-invoice.eml");
        assertEquals(Verdict.LIKELY_PHISHING, r.verdict());
        assertTrue(hasFinding(r, "Sender domain imitates Microsoft"));
        assertTrue(hasFinding(r, "Macro-enabled"));
        assertTrue(hasFinding(r, "punycode"));
    }

    @Test
    void marketingEmailWithShortLinkIsOnlySuspicious() throws IOException {
        AnalysisResult r = analyze("05-student-club-event.eml");
        assertEquals(Verdict.SUSPICIOUS, r.verdict());
    }
}
