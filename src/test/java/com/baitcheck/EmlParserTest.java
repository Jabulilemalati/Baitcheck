package com.baitcheck;

import com.baitcheck.model.Email;
import com.baitcheck.parser.EmlParser;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EmlParserTest {

    private final EmlParser parser = new EmlParser();

    private Email parse(String raw) {
        return parser.parse("test.eml", raw.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void unfoldsHeadersAndDecodesEncodedSubject() {
        Email email = parse("""
                From: "Bank" <alerts@bank.example>
                Subject: =?UTF-8?B?SGVsbG8gV29ybGQ=?=
                Received: from a.example
                  by b.example; Mon, 1 Jan 2026 10:00:00 +0200

                body
                """);
        assertEquals("Hello World", email.subject());
        assertEquals("bank.example", email.from().domain());
        assertEquals("Bank", email.from().displayName());
        assertTrue(email.headers().first("Received").orElseThrow().contains("by b.example"));
    }

    @Test
    void readsMultipartBodiesAndAttachments() {
        Email email = parse("""
                From: a@b.example
                Content-Type: multipart/mixed; boundary="XYZ"

                --XYZ
                Content-Type: text/plain; charset=utf-8

                plain part
                --XYZ
                Content-Type: text/html; charset=utf-8
                Content-Transfer-Encoding: quoted-printable

                <a href=3D"https://example.org">click</a>
                --XYZ
                Content-Type: application/octet-stream
                Content-Disposition: attachment; filename="notes.txt"
                Content-Transfer-Encoding: base64

                aGVsbG8=
                --XYZ--
                """);
        assertTrue(email.textBody().contains("plain part"));
        assertTrue(email.htmlBody().contains("href=\"https://example.org\""));
        assertEquals(1, email.attachments().size());
        assertEquals("notes.txt", email.attachments().get(0).filename());
        assertEquals(5, email.attachments().get(0).sizeBytes());
    }

    @Test
    void handlesWindowsLineEndings() {
        Email email = parse("From: x@y.example\r\nSubject: CRLF\r\n\r\nhi\r\n");
        assertEquals("CRLF", email.subject());
        assertTrue(email.textBody().contains("hi"));
    }
}
