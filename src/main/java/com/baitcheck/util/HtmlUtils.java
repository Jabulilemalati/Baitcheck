package com.baitcheck.util;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class HtmlUtils {

    private static final Pattern SCRIPT_STYLE =
            Pattern.compile("(?is)<(script|style)[^>]*>.*?</\\1>");
    private static final Pattern TAG = Pattern.compile("(?s)<[^>]+>");
    private static final Pattern ANCHOR =
            Pattern.compile("(?is)<a\\s[^>]*?href\\s*=\\s*([\"'])(.*?)\\1[^>]*>(.*?)</a>");

    private HtmlUtils() {
    }

    public record Anchor(String href, String text) {
    }

    public static String stripTags(String html) {
        if (html == null || html.isEmpty()) {
            return "";
        }
        String noScripts = SCRIPT_STYLE.matcher(html).replaceAll(" ");
        String noTags = TAG.matcher(noScripts).replaceAll(" ");
        return decodeEntities(noTags).replaceAll("[ \\t\\x0B\\f]+", " ").trim();
    }

    public static List<Anchor> anchors(String html) {
        List<Anchor> result = new ArrayList<>();
        if (html == null) {
            return result;
        }
        Matcher m = ANCHOR.matcher(html);
        while (m.find()) {
            String href = decodeEntities(m.group(2).trim());
            String text = stripTags(m.group(3));
            result.add(new Anchor(href, text));
        }
        return result;
    }

    public static String decodeEntities(String s) {
        return s.replace("&nbsp;", " ")
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", "\"")
                .replace("&#39;", "'")
                .replace("&amp;", "&");
    }

    public static String escape(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }
}
