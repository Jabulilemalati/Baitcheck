package com.baitcheck.report;

import com.baitcheck.analysis.AnalysisResult;
import com.baitcheck.analysis.Finding;
import com.baitcheck.analysis.Severity;
import com.baitcheck.analysis.Verdict;

import java.io.PrintStream;
import java.util.List;

public final class ConsoleReport {

    private static final String RESET = "\u001B[0m";
    private static final String RED = "\u001B[31m";
    private static final String YELLOW = "\u001B[33m";
    private static final String GREEN = "\u001B[32m";
    private static final String CYAN = "\u001B[36m";
    private static final String DIM = "\u001B[2m";
    private static final String BOLD = "\u001B[1m";
    private static final String LINE = "-".repeat(72);

    private final PrintStream out;
    private final boolean color;
    private final boolean verbose;

    public ConsoleReport(PrintStream out, boolean color, boolean verbose) {
        this.out = out;
        this.color = color;
        this.verbose = verbose;
    }

    public void print(AnalysisResult r) {
        out.println("=".repeat(72));
        out.println(c(BOLD, " BaitCheck report: " + r.email().source()));
        out.println("=".repeat(72));
        out.println(" From    : " + r.email().from());
        out.println(" Subject : " + r.email().subject());
        out.println(" Score   : " + c(BOLD, r.score() + "/100") + "  ->  "
                + c(verdictColor(r.verdict()), r.verdict().label().toUpperCase()));
        out.println(LINE);

        List<Finding> shown = r.findings().stream()
                .filter(f -> verbose || f.severity() != Severity.INFO)
                .toList();
        if (shown.isEmpty()) {
            out.println(" No warning signs found.");
        }
        for (Finding f : shown) {
            String tag = String.format("%-8s", "[" + f.severity() + "]");
            out.println(" " + c(severityColor(f.severity()), tag) + " "
                    + String.format("%-15s", f.category()) + f.title());
            out.println("          " + c(DIM, wrap(f.detail(), 60, "          ")));
        }
        long hidden = r.findings().size() - shown.size();
        if (hidden > 0) {
            out.println(c(DIM, " (" + hidden + " informational finding(s) hidden, use --verbose to show)"));
        }
        out.println();
    }

    public void printSummary(List<AnalysisResult> results) {
        out.println(c(BOLD, " Summary"));
        out.println(LINE);
        out.println(String.format(" %-34s %6s  %-16s %s", "File", "Score", "Verdict", "High/Med/Low"));
        for (AnalysisResult r : results) {
            String name = r.email().source();
            if (name.length() > 34) {
                name = name.substring(0, 31) + "...";
            }
            out.println(String.format(" %-34s %6d  %s %d/%d/%d", name, r.score(),
                    c(verdictColor(r.verdict()), String.format("%-16s", r.verdict().label())),
                    r.count(Severity.HIGH), r.count(Severity.MEDIUM), r.count(Severity.LOW)));
        }
        out.println();
    }

    private String c(String code, String text) {
        return color ? code + text + RESET : text;
    }

    private static String verdictColor(Verdict v) {
        return switch (v) {
            case LIKELY_PHISHING -> RED;
            case SUSPICIOUS -> YELLOW;
            case LIKELY_SAFE -> GREEN;
        };
    }

    private static String severityColor(Severity s) {
        return switch (s) {
            case HIGH -> RED;
            case MEDIUM -> YELLOW;
            case LOW -> CYAN;
            case INFO -> DIM;
        };
    }

    private static String wrap(String text, int width, String indent) {
        StringBuilder sb = new StringBuilder();
        int col = 0;
        for (String word : text.split(" ")) {
            if (col > 0 && col + word.length() + 1 > width) {
                sb.append('\n').append(indent);
                col = 0;
            } else if (col > 0) {
                sb.append(' ');
                col++;
            }
            sb.append(word);
            col += word.length();
        }
        return sb.toString();
    }
}
