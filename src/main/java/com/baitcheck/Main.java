package com.baitcheck;

import com.baitcheck.analysis.AnalysisResult;
import com.baitcheck.analysis.PhishAnalyzer;
import com.baitcheck.analysis.Verdict;
import com.baitcheck.parser.EmlParser;
import com.baitcheck.report.ConsoleReport;
import com.baitcheck.report.HtmlReport;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

public final class Main {

    public static void main(String[] args) {
        System.exit(run(args));
    }

    static int run(String[] args) {
        Path input = null;
        Path htmlOut = null;
        boolean verbose = false;
        boolean color = System.console() != null && System.getenv("NO_COLOR") == null;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--html" -> {
                    if (i + 1 >= args.length) {
                        return usage("--html needs a file name");
                    }
                    htmlOut = Path.of(args[++i]);
                }
                case "--verbose", "-v" -> verbose = true;
                case "--no-color" -> color = false;
                case "--help", "-h" -> {
                    usage(null);
                    return 0;
                }
                default -> {
                    if (args[i].startsWith("-")) {
                        return usage("Unknown option " + args[i]);
                    }
                    input = Path.of(args[i]);
                }
            }
        }
        if (input == null) {
            return usage("Please give an .eml file or a folder of them");
        }
        if (!Files.exists(input)) {
            return usage("Not found: " + input);
        }

        List<Path> files;
        try {
            files = collect(input);
        } catch (IOException e) {
            System.err.println("Could not read " + input + ": " + e.getMessage());
            return 3;
        }
        if (files.isEmpty()) {
            return usage("No .eml files in " + input);
        }

        EmlParser parser = new EmlParser();
        PhishAnalyzer analyzer = new PhishAnalyzer();
        ConsoleReport console = new ConsoleReport(System.out, color, verbose);
        List<AnalysisResult> results = new ArrayList<>();

        for (Path file : files) {
            try {
                AnalysisResult result = analyzer.analyze(parser.parse(file));
                results.add(result);
                console.print(result);
            } catch (IOException e) {
                System.err.println("Skipping " + file + ": " + e.getMessage());
            }
        }
        if (results.size() > 1) {
            console.printSummary(results);
        }
        if (htmlOut != null) {
            try {
                new HtmlReport().write(results, htmlOut);
                System.out.println(" HTML report written to " + htmlOut.toAbsolutePath());
            } catch (IOException e) {
                System.err.println("Could not write HTML report: " + e.getMessage());
            }
        }

        Verdict worst = results.stream().map(AnalysisResult::verdict)
                .max(Enum::compareTo).orElse(Verdict.LIKELY_SAFE);
        return worst.ordinal();
    }

    private static List<Path> collect(Path input) throws IOException {
        if (Files.isRegularFile(input)) {
            return List.of(input);
        }
        try (Stream<Path> s = Files.list(input)) {
            return s.filter(p -> p.getFileName().toString().toLowerCase().endsWith(".eml"))
                    .sorted()
                    .toList();
        }
    }

    private static int usage(String error) {
        if (error != null) {
            System.err.println("Error: " + error + "\n");
        }
        System.err.println("""
                BaitCheck - phishing email analyser

                Usage:
                  java -jar baitcheck.jar <file.eml | folder> [options]

                Options:
                  --html <file>   also write an HTML report
                  --verbose, -v   show informational findings too
                  --no-color      plain output (no ANSI colours)
                  --help, -h      show this help

                Exit codes: 0 safe, 1 suspicious, 2 likely phishing, 3 error
                """);
        return error == null ? 0 : 3;
    }
}
