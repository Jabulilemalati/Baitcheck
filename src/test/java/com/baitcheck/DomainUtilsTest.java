package com.baitcheck;

import com.baitcheck.util.DomainUtils;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DomainUtilsTest {

    @Test
    void registrableDomainHandlesSouthAfricanSuffixes() {
        assertEquals("absa.co.za", DomainUtils.registrableDomain("online.absa.co.za"));
        assertEquals("sars.gov.za", DomainUtils.registrableDomain("www.sars.gov.za"));
        assertEquals("paypal.com", DomainUtils.registrableDomain("login.secure.paypal.com"));
        assertEquals("refund-claim.top", DomainUtils.registrableDomain("sars.gov.za.refund-claim.top"));
    }

    @Test
    void realBrandDomainsAreNotFlagged() {
        assertFalse(DomainUtils.findImpersonation("www.paypal.com").isPresent());
        assertFalse(DomainUtils.findImpersonation("login.microsoftonline.com").isPresent());
        assertFalse(DomainUtils.findImpersonation("www.fnb.co.za").isPresent());
    }

    @Test
    void unrelatedDomainsAreNotFlagged() {
        assertFalse(DomainUtils.findImpersonation("example.org").isPresent());
        assertFalse(DomainUtils.findImpersonation("github.com").isPresent());
        assertFalse(DomainUtils.findImpersonation("wits.ac.za").isPresent());
    }

    @Test
    void lookAlikeCharactersAreCaught() {
        assertTrue(DomainUtils.findImpersonation("paypa1.com").isPresent());
        assertTrue(DomainUtils.findImpersonation("rnicrosoft.com").isPresent());
        assertTrue(DomainUtils.findImpersonation("g00gle.com").isPresent());
    }

    @Test
    void typoSquatsAndBrandInSubdomainAreCaught() {
        assertTrue(DomainUtils.findImpersonation("amazom.com").isPresent());
        assertTrue(DomainUtils.findImpersonation("paypal.com.account-check.net").isPresent());
        assertTrue(DomainUtils.findImpersonation("absa-secure.co").isPresent());
        assertTrue(DomainUtils.findImpersonation("netflix.xyz").isPresent());
    }

    @Test
    void urlParsingSpotsTheAtSignTrick() {
        var parts = DomainUtils.parseUrl("https://www.fnb.co.za@203.0.113.9/login").orElseThrow();
        assertTrue(parts.hasUserInfo());
        assertEquals("203.0.113.9", parts.host());
        assertTrue(DomainUtils.isIpAddress(parts.host()));
    }

    @Test
    void levenshteinDistance() {
        assertEquals(0, DomainUtils.levenshtein("paypal", "paypal"));
        assertEquals(1, DomainUtils.levenshtein("amazom", "amazon"));
        assertEquals(3, DomainUtils.levenshtein("kitten", "sitting"));
    }
}
