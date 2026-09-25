package com.baitcheck.parser;

import com.baitcheck.model.Attachment;
import com.baitcheck.model.Email;
import com.baitcheck.model.Headers;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class EmlParser {

    private static final int MAX_DEPTH = 10;
    private static final Pattern ENCODED_WORD =
            Pattern.compile("=\\?([^?]+)\\?([bBqQ])\\?([^?]*)\\?=");

    private record Part(Headers headers, String body) {
    }

    public Email parse(Path path) throws IOException {
        return parse(path.getFileName().toString(), Files.readAllBytes(path));
    }

    public Email parse(String sourceName, byte[] raw) {
        String text = new String(raw, StandardCharsets.ISO_8859_1)
                .replace("\r\n", "\n")
                .replace('\r', '\n');
        Part root = parsePart(text);
        Email email = new Email(sourceName, root.headers());
        walk(root, email, 0);
        return email;
    }

    private Part parsePart(String text) {
        if (text.startsWith("\n")) {
            return new Part(new Headers(), text.substring(1));
        }
        int split = text.indexOf("\n\n");
        if (split < 0) {
            return new Part(parseHeaders(text), "");
        }
        return new Part(parseHeaders(text.substring(0, split)), text.substring(split + 2));
    }

    private Headers parseHeaders(String block) {
        Headers headers = new Headers();
        String name = null;
        StringBuilder value = new StringBuilder();

        for (String line : block.split("\n")) {
            if ((line.startsWith(" ") || line.startsWith("\t")) && name != null) {
                value.append(' ').append(line.trim());
                continue;
            }
            if (name != null) {
                headers.add(name, cleanHeaderValue(value.toString()));
            }
            int colon = line.indexOf(':');
            if (colon > 0) {
                name = line.substring(0, colon).trim();
                value = new StringBuilder(line.substring(colon + 1).trim());
            } else {
                name = null;
            }
        }
        if (name != null) {
            headers.add(name, cleanHeaderValue(value.toString()));
        }
        return headers;
    }

    private String cleanHeaderValue(String isoValue) {
        String utf8 = new String(isoValue.getBytes(StandardCharsets.ISO_8859_1), StandardCharsets.UTF_8);
        return decodeEncodedWords(utf8);
    }

    private void walk(Part part, Email email, int depth) {
        ContentType type = ContentType.parse(part.headers().first("Content-Type").orElse("text/plain"));
        String mime = type.value().isEmpty() ? "text/plain" : type.value();

        if (mime.startsWith("multipart/") && type.param("boundary") != null && depth < MAX_DEPTH) {
            for (String child : splitMultipart(part.body(), type.param("boundary"))) {
                walk(parsePart(child), email, depth + 1);
            }
            return;
        }

        ContentType disposition = ContentType.parse(part.headers().first("Content-Disposition").orElse(""));
        String filename = disposition.param("filename");
        if (filename == null) {
            filename = type.param("name");
        }
        String encoding = part.headers().first("Content-Transfer-Encoding").orElse("7bit");
        byte[] decoded = decodeTransfer(part.body(), encoding);

        boolean isAttachment = filename != null || "attachment".equals(disposition.value());
        if (isAttachment) {
            String name = filename == null ? "(unnamed)" : decodeEncodedWords(filename);
            email.addAttachment(new Attachment(name, mime, decoded.length));
        } else if (mime.equals("text/html")) {
            email.appendHtml(new String(decoded, charset(type.param("charset"))));
        } else if (mime.startsWith("text/")) {
            email.appendText(new String(decoded, charset(type.param("charset"))));
        }
    }

    private List<String> splitMultipart(String body, String boundary) {
        List<String> parts = new ArrayList<>();
        String delimiter = "--" + boundary;
        String closing = delimiter + "--";
        StringBuilder current = null;

        for (String line : body.split("\n", -1)) {
            String trimmed = line.trim();
            if (trimmed.equals(closing)) {
                if (current != null) {
                    parts.add(current.toString());
                }
                return parts;
            }
            if (trimmed.equals(delimiter)) {
                if (current != null) {
                    parts.add(current.toString());
                }
                current = new StringBuilder();
                continue;
            }
            if (current != null) {
                current.append(line).append('\n');
            }
        }
        if (current != null) {
            parts.add(current.toString());
        }
        return parts;
    }

    static byte[] decodeTransfer(String body, String encoding) {
        String enc = encoding.trim().toLowerCase(Locale.ROOT);
        byte[] rawBytes = body.getBytes(StandardCharsets.ISO_8859_1);
        try {
            if (enc.equals("base64")) {
                return Base64.getMimeDecoder().decode(body.replaceAll("\\s", ""));
            }
            if (enc.equals("quoted-printable")) {
                return decodeQuotedPrintable(body);
            }
        } catch (IllegalArgumentException badInput) {
        }
        return rawBytes;
    }

    static byte[] decodeQuotedPrintable(String body) {
        String s = body.replace("=\n", "");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '=' && i + 2 < s.length() && isHex(s.charAt(i + 1)) && isHex(s.charAt(i + 2))) {
                out.write(Integer.parseInt(s.substring(i + 1, i + 3), 16));
                i += 2;
            } else {
                out.write((byte) c);
            }
        }
        return out.toByteArray();
    }

    static String decodeEncodedWords(String value) {
        if (value == null || !value.contains("=?")) {
            return value;
        }
        String joined = value.replaceAll("\\?=\\s+=\\?", "?==?");
        Matcher m = ENCODED_WORD.matcher(joined);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            Charset cs = charset(m.group(1));
            String payload = m.group(3);
            String decoded;
            try {
                if (m.group(2).equalsIgnoreCase("B")) {
                    decoded = new String(Base64.getDecoder().decode(payload), cs);
                } else {
                    decoded = new String(decodeQuotedPrintable(payload.replace('_', ' ')), cs);
                }
            } catch (IllegalArgumentException e) {
                decoded = m.group();
            }
            m.appendReplacement(sb, Matcher.quoteReplacement(decoded));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private static Charset charset(String name) {
        if (name == null || name.isBlank()) {
            return StandardCharsets.UTF_8;
        }
        try {
            return Charset.forName(name.trim());
        } catch (Exception e) {
            return StandardCharsets.UTF_8;
        }
    }

    private static boolean isHex(char c) {
        return Character.digit(c, 16) >= 0;
    }
}
