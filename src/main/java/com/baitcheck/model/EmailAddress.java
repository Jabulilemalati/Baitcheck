package com.baitcheck.model;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public record EmailAddress(String displayName, String address, String domain) {

    private static final Pattern ANGLE = Pattern.compile("^(.*?)<([^>]*)>");

    public static EmailAddress parse(String raw) {
        if (raw == null) {
            return new EmailAddress("", "", "");
        }
        String value = raw.trim();
        String display = "";
        String address = value;

        Matcher m = ANGLE.matcher(value);
        if (m.find()) {
            display = m.group(1).trim().replaceAll("^\"|\"$", "").trim();
            address = m.group(2).trim();
        }
        address = address.toLowerCase(Locale.ROOT);
        int at = address.lastIndexOf('@');
        String domain = at >= 0 ? address.substring(at + 1) : "";
        return new EmailAddress(display, address, domain);
    }

    public boolean isEmpty() {
        return address.isBlank();
    }

    @Override
    public String toString() {
        return displayName.isBlank() ? address : displayName + " <" + address + ">";
    }
}
