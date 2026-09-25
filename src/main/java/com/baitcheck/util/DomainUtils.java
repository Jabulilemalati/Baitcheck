package com.baitcheck.util;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class DomainUtils {

    private static final Set<String> MULTI_PART_SUFFIXES = Set.of(
            "co.za", "org.za", "gov.za", "ac.za", "net.za", "web.za",
            "co.uk", "org.uk", "ac.uk", "gov.uk",
            "com.au", "net.au", "co.nz", "com.br", "co.in", "co.jp");

    public static final Set<String> SUSPICIOUS_TLDS = Set.of(
            "xyz", "top", "tk", "ml", "ga", "cf", "gq", "zip", "mov", "click",
            "country", "work", "loan", "rest", "support", "cam", "icu", "buzz");

    public static final Set<String> URL_SHORTENERS = Set.of(
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly",
            "rebrand.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id");

    public static final Set<String> FREE_MAIL = Set.of(
            "gmail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com", "icloud.com",
            "aol.com", "gmx.com", "mail.com", "proton.me", "protonmail.com", "yandex.com");

    private static final Pattern IPV4 = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");
    private static final Pattern URL_AUTHORITY =
            Pattern.compile("^[a-zA-Z][a-zA-Z0-9+.-]*://([^/?#\\s]*)");

    private DomainUtils() {
    }

    public record UrlParts(String scheme, String host, boolean hasUserInfo) {
    }

    public record Impersonation(Brand brand, String reason) {
    }

    public static Optional<UrlParts> parseUrl(String url) {
        if (url == null) {
            return Optional.empty();
        }
        Matcher m = URL_AUTHORITY.matcher(url.trim());
        if (!m.find()) {
            return Optional.empty();
        }
        String scheme = url.trim().substring(0, url.trim().indexOf(':')).toLowerCase(Locale.ROOT);
        String authority = m.group(1);
        boolean userInfo = authority.contains("@");
        String host = authority.substring(authority.lastIndexOf('@') + 1);
        if (!host.startsWith("[")) {
            int colon = host.lastIndexOf(':');
            if (colon >= 0) {
                host = host.substring(0, colon);
            }
        }
        host = host.toLowerCase(Locale.ROOT);
        if (host.endsWith(".")) {
            host = host.substring(0, host.length() - 1);
        }
        return host.isEmpty() ? Optional.empty() : Optional.of(new UrlParts(scheme, host, userInfo));
    }

    public static boolean isIpAddress(String host) {
        return IPV4.matcher(host).matches() || host.startsWith("[");
    }

    public static String registrableDomain(String host) {
        if (host == null) {
            return "";
        }
        String h = host.toLowerCase(Locale.ROOT);
        if (isIpAddress(h)) {
            return h;
        }
        String[] labels = h.split("\\.");
        if (labels.length <= 2) {
            return h;
        }
        String lastTwo = labels[labels.length - 2] + "." + labels[labels.length - 1];
        int keep = MULTI_PART_SUFFIXES.contains(lastTwo) ? 3 : 2;
        return String.join(".", Arrays.copyOfRange(labels, labels.length - keep, labels.length));
    }

    public static String tld(String host) {
        int dot = host.lastIndexOf('.');
        return dot < 0 ? "" : host.substring(dot + 1).toLowerCase(Locale.ROOT);
    }

    public static String normalizeHomoglyphs(String label) {
        return label.toLowerCase(Locale.ROOT)
                .replace("rn", "m")
                .replace("vv", "w")
                .replace('0', 'o')
                .replace('1', 'l')
                .replace('3', 'e')
                .replace('4', 'a')
                .replace('5', 's')
                .replace('7', 't')
                .replace('8', 'b')
                .replace("-", "");
    }

    public static Optional<Impersonation> findImpersonation(String host) {
        return findImpersonation(host, Brand.CATALOG);
    }

    public static Optional<Impersonation> findImpersonation(String host, List<Brand> brands) {
        if (host == null || host.isBlank() || isIpAddress(host)) {
            return Optional.empty();
        }
        for (Brand brand : brands) {
            if (brand.owns(host)) {
                return Optional.empty();
            }
        }

        String registrable = registrableDomain(host);
        String label = registrable.split("\\.")[0];
        String normalized = normalizeHomoglyphs(label);
        List<String> tokens = Arrays.asList(label.split("-"));

        String sub = host.length() > registrable.length()
                ? host.substring(0, host.length() - registrable.length() - 1)
                : "";
        List<String> subLabels = sub.isEmpty() ? List.of() : Arrays.asList(sub.split("[.-]"));

        for (Brand brand : brands) {
            for (String domain : brand.domains()) {
                String brandLabel = domain.split("\\.")[0];

                if (label.equals(brandLabel)) {
                    return hit(brand, registrable + " uses the " + brand.name()
                            + " name on a domain " + brand.name() + " doesn't own (real: " + domain + ")");
                }
                if (normalized.equals(brandLabel)) {
                    return hit(brand, "'" + label + "' is '" + brandLabel
                            + "' with look-alike characters swapped in");
                }
                if (tokens.contains(brandLabel)
                        || (brandLabel.length() >= 5 && normalized.startsWith(brandLabel))) {
                    return hit(brand, registrable + " contains the brand name '" + brandLabel
                            + "' but isn't " + domain);
                }
                int maxEdits = brandLabel.length() >= 8 ? 2 : 1;
                if (brandLabel.length() >= 6 && levenshtein(normalized, brandLabel) <= maxEdits) {
                    return hit(brand, "'" + label + "' is a typo-squat of '" + brandLabel + "'");
                }
                if (subLabels.contains(brandLabel)) {
                    return hit(brand, "'" + brandLabel + "' appears in the subdomain, but the real domain is "
                            + registrable);
                }
            }
        }
        return Optional.empty();
    }

    private static Optional<Impersonation> hit(Brand brand, String reason) {
        return Optional.of(new Impersonation(brand, reason));
    }

    public static int levenshtein(String a, String b) {
        int[] prev = new int[b.length() + 1];
        int[] cur = new int[b.length() + 1];
        for (int j = 0; j <= b.length(); j++) {
            prev[j] = j;
        }
        for (int i = 1; i <= a.length(); i++) {
            cur[0] = i;
            for (int j = 1; j <= b.length(); j++) {
                int cost = a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1;
                cur[j] = Math.min(Math.min(cur[j - 1] + 1, prev[j] + 1), prev[j - 1] + cost);
            }
            int[] tmp = prev;
            prev = cur;
            cur = tmp;
        }
        return prev[b.length()];
    }
}
