package com.baitcheck.analyzers;

import com.baitcheck.analysis.Analyzer;
import com.baitcheck.analysis.Finding;
import com.baitcheck.model.Email;
import com.baitcheck.util.DomainUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class AuthenticationAnalyzer implements Analyzer {

    private static final String CAT = "Authentication";
    private static final Pattern RESULT = Pattern.compile("(?i)\\b(spf|dkim|dmarc)\\s*=\\s*([a-z]+)");
    private static final Pattern DKIM_DOMAIN = Pattern.compile("(?i)\\bd=([^;\\s]+)");

    @Override
    public List<Finding> analyze(Email email) {
        List<Finding> out = new ArrayList<>();
        Map<String, String> results = new LinkedHashMap<>();

        for (String header : email.headers().all("Authentication-Results")) {
            Matcher m = RESULT.matcher(header);
            while (m.find()) {
                results.putIfAbsent(m.group(1).toLowerCase(Locale.ROOT), m.group(2).toLowerCase(Locale.ROOT));
            }
        }
        if (!results.containsKey("spf")) {
            email.headers().first("Received-SPF").ifPresent(v -> {
                String word = v.trim().split("\\s+")[0].toLowerCase(Locale.ROOT);
                results.put("spf", word);
            });
        }

        if (results.isEmpty()) {
            out.add(Finding.low(CAT, "No SPF/DKIM/DMARC results found",
                    "The message has no Authentication-Results header, so the sender can't be verified. "
                            + "Export the email with full headers for a better check."));
        } else {
            for (String mech : List.of("spf", "dkim", "dmarc")) {
                String res = results.get(mech);
                if (res == null) {
                    out.add(Finding.low(CAT, mech.toUpperCase(Locale.ROOT) + " result missing",
                            "No " + mech.toUpperCase(Locale.ROOT) + " verdict in the headers."));
                } else {
                    out.add(judge(mech.toUpperCase(Locale.ROOT), res));
                }
            }
        }

        email.headers().first("DKIM-Signature").ifPresent(sig -> {
            Matcher m = DKIM_DOMAIN.matcher(sig);
            String fromDomain = email.from().domain();
            if (m.find() && !fromDomain.isEmpty()) {
                String signer = DomainUtils.registrableDomain(m.group(1).toLowerCase(Locale.ROOT));
                if (!signer.equals(DomainUtils.registrableDomain(fromDomain))) {
                    out.add(Finding.low(CAT, "DKIM signature is from a different domain",
                            "Signed by " + signer + " but From is " + fromDomain + " (not aligned)"));
                }
            }
        });
        return out;
    }

    private Finding judge(String mech, String result) {
        String detail = mech + "=" + result;
        return switch (result) {
            case "pass" -> Finding.info(CAT, mech + " passed", detail);
            case "fail", "hardfail" -> Finding.high(CAT, mech + " failed", detail
                    + " - the receiving server could not confirm this sender is genuine");
            case "softfail" -> Finding.medium(CAT, mech + " soft-failed", detail
                    + " - the domain says this server probably shouldn't be sending its mail");
            default -> Finding.low(CAT, mech + " inconclusive", detail);
        };
    }
}
