package com.baitcheck.analysis;

public enum Severity {
    INFO(0),
    LOW(5),
    MEDIUM(12),
    HIGH(25);

    private final int points;

    Severity(int points) {
        this.points = points;
    }

    public int points() {
        return points;
    }
}
