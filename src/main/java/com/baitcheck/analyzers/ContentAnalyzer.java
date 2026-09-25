package com.baitcheck.analyzers;

import com.baitcheck.analysis.Analyzer;
import com.baitcheck.analysis.Finding;
import com.baitcheck.analysis.Severity;
import com.baitcheck.model.Email;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

public final class ContentAnalyzer implements Analyzer {

    private static final String CAT = "Content";

    private record Rule(String name, Severity severity, String why, List<String> phrases) {
    }

    private static final List<Rule> RULES = List.of(
            new Rule("Urgency / time pressure", Severity.LOW,
                    "Rushing people stops them from thinking carefully",
                    List.of("urgent", "immediately", "within 24 hours", "within 48 hours", "act now",
                            "as soon as possible", "final notice", "last warning", "expires today",
                            "action required", "right away")),
            new Rule("Threat of account loss or penalty", Severity.LOW,
                    "Fear is used to push people into clicking",
                    List.of("suspended", "will be closed", "locked", "unauthorized", "unauthorised",
                            "unusual activity", "suspicious activity", "legal action", "deactivated",
                            "penalty", "blocked")),
            new Rule("Asks for credentials or personal data", Severity.MEDIUM,
                    "Legitimate companies don't ask for these over email",
                    List.of("verify your account", "confirm your identity", "update your payment",
                            "password", "login details", "one-time pin", "otp", "card number", "cvv",
                            "pin", "id number", "banking details", "security question")),
            new Rule("Money, refund or prize bait", Severity.LOW,
                    "Unexpected money is a classic hook",
                    List.of("refund", "you have won", "gift card", "prize", "claim your", "lottery",
                            "inheritance", "bitcoin", "crypto", "cash reward")),
            new Rule("Generic greeting", Severity.LOW,
                    "Services you actually use normally know your name",
                    List.of("dear customer", "dear user", "dear client", "dear account holder",
                            "dear valued", "dear taxpayer", "dear member"))
    );

    @Override
    public List<Finding> analyze(Email email) {
        String text = email.readableText().toLowerCase(Locale.ROOT);
        List<Finding> out = new ArrayList<>();
        Set<String> triggered = new LinkedHashSet<>();

        for (Rule rule : RULES) {
            List<String> hits = rule.phrases().stream()
                    .filter(p -> Pattern.compile("\\b" + Pattern.quote(p) + "\\b").matcher(text).find())
                    .toList();
            if (!hits.isEmpty()) {
                triggered.add(rule.name());
                out.add(new Finding(rule.severity(), CAT, rule.name(),
                        rule.why() + ". Matched: " + String.join(", ", hits.stream().map(h -> "\"" + h + "\"").toList())));
            }
        }

        boolean pressure = triggered.contains("Urgency / time pressure")
                || triggered.contains("Threat of account loss or penalty");
        if (pressure && triggered.contains("Asks for credentials or personal data")) {
            out.add(Finding.high(CAT, "Classic phishing pattern: pressure + credential request",
                    "The email combines urgency or threats with a request for sensitive information"));
        }

        if (email.htmlBody().toLowerCase(Locale.ROOT).contains("<script")) {
            out.add(Finding.medium(CAT, "HTML contains JavaScript",
                    "Normal email clients strip scripts; senders who include them are up to something"));
        }
        return out;
    }
}
