package com.baitcheck.analysis;

public record Finding(Severity severity, String category, String title, String detail) {

    public static Finding info(String category, String title, String detail) {
        return new Finding(Severity.INFO, category, title, detail);
    }

    public static Finding low(String category, String title, String detail) {
        return new Finding(Severity.LOW, category, title, detail);
    }

    public static Finding medium(String category, String title, String detail) {
        return new Finding(Severity.MEDIUM, category, title, detail);
    }

    public static Finding high(String category, String title, String detail) {
        return new Finding(Severity.HIGH, category, title, detail);
    }
}
