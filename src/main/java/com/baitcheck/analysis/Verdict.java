package com.baitcheck.analysis;

public enum Verdict {
    LIKELY_SAFE("Likely safe"),
    SUSPICIOUS("Suspicious"),
    LIKELY_PHISHING("Likely phishing");

    private final String label;

    Verdict(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }

    public static Verdict forScore(int score) {
        if (score >= 60) {
            return LIKELY_PHISHING;
        }
        if (score >= 25) {
            return SUSPICIOUS;
        }
        return LIKELY_SAFE;
    }
}
