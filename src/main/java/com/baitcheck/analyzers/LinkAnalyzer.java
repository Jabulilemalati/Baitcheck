package com.baitcheck.analyzers;

import com.baitcheck.analysis.Analyzer;
import com.baitcheck.analysis.Finding;
import com.baitcheck.model.Email;
import com.baitcheck.util.DomainUtils;
import com.baitcheck.util.DomainUtils.UrlParts;
import com.baitcheck.util.HtmlUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class LinkAnalyzer implements Analyzer {

    private static final String CAT = "Links";
    private static final Pattern PLAIN_URL = Pattern.compile("(?i)\\bhttps?://[^\\s<>\"')\\]]+");
    private static final Pattern LOOKS_LIKE_DOMAIN =
            Pattern.compile("(?i)^(?:https?://)?((?:[a-z0-9-]+\\.)+[a-z]{2,})(?:[/:?#].*)?$");
    private static final Pattern CREDENTIAL_PATH =
            Pattern.compile("(?i)(login|signin|sign-in|verify|account|password|secure|update|webscr)");

    @Override
    public List<Finding> analyze(Email email) {
        Map<String, String> links = collectLinks(email);
        List<Finding> out = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();

        if (!links.isEmpty()) {
            out.add(Finding.info(CAT, links.size() + " unique link(s) found",
                    String.join(", ", links.keySet().stream().limit(5).toList())
                            + (links.size() > 5 ? ", ..." : "")));
        }

        for (Map.Entry<String, String> entry : links.entrySet()) {
            String url = entry.getKey();
            Optional<UrlParts> parsed = DomainUtils.parseUrl(url);
            if (parsed.isEmpty()) {
                continue;
            }
            UrlParts p = parsed.get();
            String host = p.host();

            if (p.hasUserInfo()) {
                add(out, seen, Finding.high(CAT, "Link hides its real destination with '@'",
                        url + " - browsers ignore everything before '@', so this really goes to " + host));
            }
            if (DomainUtils.isIpAddress(host)) {
                add(out, seen, Finding.high(CAT, "Link points to a raw IP address",
                        url + " - real companies link to their domain name, not a bare IP"));
            }
            if (host.startsWith("xn--") || host.contains(".xn--")) {
                add(out, seen, Finding.high(CAT, "Link uses a punycode (internationalised) domain",
                        host + " can render with foreign letters that look identical to English ones"));
            }
            DomainUtils.findImpersonation(host).ifPresent(imp -> add(out, seen,
                    Finding.high(CAT, "Link domain imitates " + imp.brand().name(),
                            url + " - " + imp.reason())));

            if (DomainUtils.URL_SHORTENERS.contains(DomainUtils.registrableDomain(host))
                    || DomainUtils.URL_SHORTENERS.contains(host)) {
                add(out, seen, Finding.medium(CAT, "Link uses a URL shortener",
                        url + " - shorteners hide where the link really goes"));
            }
            if (DomainUtils.SUSPICIOUS_TLDS.contains(DomainUtils.tld(host))) {
                add(out, seen, Finding.low(CAT, "Link uses a TLD popular with scammers",
                        host + " (." + DomainUtils.tld(host) + " domains are cheap and heavily abused)"));
            }
            if (host.split("\\.").length > 4) {
                add(out, seen, Finding.low(CAT, "Link has an unusually deep subdomain",
                        host + " - long hostnames are used to push the real domain out of view"));
            }
            if (p.scheme().equals("http") && CREDENTIAL_PATH.matcher(url).find()) {
                add(out, seen, Finding.medium(CAT, "Login-style link is not encrypted (http)",
                        url + " - anything typed on this page travels in plain text"));
            }

            checkAnchorMismatch(url, host, entry.getValue()).ifPresent(f -> add(out, seen, f));
        }

        if (email.htmlBody().toLowerCase(Locale.ROOT).contains("<form")) {
            add(out, seen, Finding.high(CAT, "Email contains an HTML form",
                    "Forms inside emails are used to collect passwords or card details directly"));
        }
        return out;
    }

    private Optional<Finding> checkAnchorMismatch(String url, String host, String anchorText) {
        if (anchorText == null || anchorText.isBlank()) {
            return Optional.empty();
        }
        Matcher m = LOOKS_LIKE_DOMAIN.matcher(anchorText.trim());
        if (!m.matches()) {
            return Optional.empty();
        }
        String shownReg = DomainUtils.registrableDomain(m.group(1).toLowerCase(Locale.ROOT));
        String realReg = DomainUtils.registrableDomain(host);
        if (shownReg.equals(realReg)) {
            return Optional.empty();
        }
        return Optional.of(Finding.high(CAT, "Link text doesn't match where it goes",
                "Shows \"" + anchorText.trim() + "\" but actually opens " + url));
    }

    private Map<String, String> collectLinks(Email email) {
        Map<String, String> links = new LinkedHashMap<>();
        for (HtmlUtils.Anchor a : HtmlUtils.anchors(email.htmlBody())) {
            if (a.href().toLowerCase(Locale.ROOT).startsWith("http")) {
                links.putIfAbsent(a.href(), a.text());
            }
        }
        Matcher m = PLAIN_URL.matcher(email.textBody() + "\n" + email.htmlBody());
        while (m.find()) {
            links.putIfAbsent(HtmlUtils.decodeEntities(m.group()), null);
        }
        return links;
    }

    private static void add(List<Finding> out, Set<String> seen, Finding f) {
        String key = f.title() + "|" + DomainUtils.parseUrl(f.detail().split(" ")[0])
                .map(UrlParts::host).orElse(f.detail());
        if (seen.add(key)) {
            out.add(f);
        }
    }
}
