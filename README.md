# BaitCheck

A command-line tool that reads an email file (`.eml`) and tells you how likely it is to be phishing, and why.

I built this because most phishing advice is "check the sender and don't click dodgy links", which is hard to do when you don't know what you're looking at. BaitCheck does those checks for you and explains each one, so it's also a decent way to learn what the warning signs actually are.

It's written in plain Java 17 with no external libraries (JUnit is only used for tests).

## What it checks

- **Sender:** display names pretending to be a brand ("PayPal Service" from a random domain), look-alike domains (`paypa1`, `rnicrosoft`), Reply-To sending your answer to a Gmail account, and mismatched Return-Path / Message-ID.
- **Authentication:** the SPF, DKIM and DMARC results that the mail server stamped on the message.
- **Links:** link text that says one site but opens another, raw IP addresses, the `user@host` trick, punycode domains, URL shorteners, cheap TLDs like `.xyz` and `.top`, and brand names hidden in subdomains (`sars.gov.za.refund-claim.top`).
- **Content:** urgency, threats, requests for passwords or banking details, refund/prize bait and "Dear Customer" greetings.
- **Attachments:** executables, macro-enabled Office files, HTML attachments and double extensions like `Refund_Form.pdf.html`.

Each finding is LOW, MEDIUM or HIGH and adds points to a score out of 100. Under 25 is *likely safe*, 25 to 59 is *suspicious*, and 60 or more is *likely phishing*.

## Running it

You need JDK 17 or newer.

```bash
mvn package
java -jar target/baitcheck.jar samples/
```

If you don't have Maven, `./build.sh` (or `build.bat` on Windows) compiles it with plain `javac` and makes the same jar.

Some useful options:

```bash
java -jar target/baitcheck.jar samples/02-paypal-account-limited.eml   # one email
java -jar target/baitcheck.jar samples/ --html report.html              # also save an HTML report
java -jar target/baitcheck.jar samples/ --verbose                       # include info-level findings
```

To test one of your own emails, save it as `.eml` (in Gmail: ⋮ → *Download message*; in Outlook: *File → Save As*) and point the tool at it. Saving it with full headers makes the checks much more accurate.

The exit code is 0 (safe), 1 (suspicious) or 2 (phishing), so you could use it in a script.

## Sample emails

The `samples/` folder has five made-up emails I used to test it:

| File | What it is | Result |
|---|---|---|
| `01-legit-newsletter.eml` | a normal store newsletter | Likely safe (0) |
| `02-paypal-account-limited.eml` | fake PayPal "account limited" email | Likely phishing (100) |
| `03-sars-tax-refund.eml` | fake SARS refund with a `.pdf.html` attachment | Likely phishing (100) |
| `04-microsoft-invoice.eml` | fake Microsoft invoice with a `.docm` macro file | Likely phishing (100) |
| `05-student-club-event.eml` | real-looking club email with a bit.ly link | Suspicious (27) |

Sample 04 is the one I find most interesting. SPF, DKIM and DMARC all **pass**, because the attacker owns `rnicrosoft.com` and set it up properly. Email authentication only proves the mail really came from that domain, not that the domain is who it claims to be. The look-alike domain check is what catches it.

All IP addresses in the samples come from the ranges reserved for documentation, and the attachments are harmless placeholder text.

## Project layout

```
src/main/java/com/baitcheck/
  parser/      EmlParser - reads headers, multipart bodies, base64 / quoted-printable
  analyzers/   HeaderAnalyzer, AuthenticationAnalyzer, LinkAnalyzer, ContentAnalyzer, AttachmentAnalyzer
  analysis/    scoring, severity, verdict
  util/        domain helpers (look-alike detection, Levenshtein distance) and the brand list
  report/      console and HTML output
src/test/java/ unit tests (run with: mvn test)
samples/       test emails
```

Adding a new check just means writing a class that implements `Analyzer` and adding it in `PhishAnalyzer`.

## Limitations

- It's rule-based, so it can miss clever phishing and flag some real marketing emails (sample 05 shows this). It's there to help you decide, not to decide for you.
- It never opens links or runs attachments. All the checks work on the text of the email only.
- The brand list is short (a few global brands plus South African banks, SARS and Takealot). You can add more in `Brand.java`.
- Working out the "real" domain uses a small hard-coded list of suffixes like `co.za` rather than the full Public Suffix List.

## Ideas for later

- Look up domain age with WHOIS (new domains are a big red flag)
- Check links against a threat feed such as PhishTank or Google Safe Browsing
- Parse `.msg` files from Outlook
- A small web UI where you can paste in raw headers
