//! SMTP enrichment provider — email verification via EHLO/RCPT TO handshake,
//! disposable domain detection, and email pattern generation.

use super::dns::DnsProvider;
use super::{EmailCandidate, EmailVerification, EnrichmentProvider, ProviderTier};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

const DISPOSABLE_DOMAINS: &[&str] = &[
    "mailinator.com",
    "guerrillamail.com",
    "tempmail.com",
    "throwaway.email",
    "yopmail.com",
    "10minutemail.com",
    "trashmail.com",
    "sharklasers.com",
    "guerrillamailblock.com",
    "grr.la",
    "dispostable.com",
    "mailnesia.com",
    "maildrop.cc",
    "discard.email",
    "fakeinbox.com",
    "getairmail.com",
    "mohmal.com",
    "tempail.com",
    "temp-mail.org",
    "getnada.com",
];

/// Max EHLO continuation lines before we bail (prevents infinite-loop from rogue servers).
const MAX_EHLO_LINES: usize = 50;

/// Max bytes per SMTP response line (prevents memory exhaustion from rogue servers).
const MAX_LINE_LEN: usize = 1024;

pub struct SmtpProvider;

impl SmtpProvider {
    pub fn new() -> Self {
        Self
    }

    pub fn is_disposable(domain: &str) -> bool {
        DISPOSABLE_DOMAINS.contains(&domain.to_lowercase().as_str())
    }

    /// Read a single SMTP response line with timeout and length guard.
    async fn read_line_safe(
        reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
        buf: &mut String,
        timeout: std::time::Duration,
    ) -> Result<(), String> {
        buf.clear();
        match tokio::time::timeout(timeout, reader.read_line(buf)).await {
            Ok(Ok(0)) => Err("connection closed".to_string()),
            Ok(Ok(_)) => {
                if buf.len() > MAX_LINE_LEN {
                    Err("response line too long".to_string())
                } else {
                    Ok(())
                }
            }
            Ok(Err(e)) => Err(format!("read error: {e}")),
            Err(_) => Err("read timeout".to_string()),
        }
    }

    /// Perform SMTP handshake against an MX host to verify deliverability.
    ///
    /// Protocol flow: banner → EHLO → MAIL FROM:<> → RCPT TO:<email> → QUIT.
    /// Returns (accepted, detail_string).
    pub async fn smtp_verify(email: &str, mx_host: &str) -> (bool, String) {
        // Guard: reject emails with CRLF to prevent SMTP command injection.
        if email.contains('\r') || email.contains('\n') {
            return (false, "email contains CR/LF".to_string());
        }

        let addr = format!("{mx_host}:25");
        let stream = match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            TcpStream::connect(&addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return (false, format!("connect failed: {e}")),
            Err(_) => return (false, "connect timeout".to_string()),
        };

        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        let timeout = std::time::Duration::from_secs(5);

        // Read 220 banner
        if let Err(e) = Self::read_line_safe(&mut reader, &mut line, timeout).await {
            return (false, format!("banner: {e}"));
        }
        if !line.starts_with("220") {
            return (false, format!("bad banner: {}", line.trim()));
        }

        // EHLO
        if writer
            .write_all(b"EHLO enrichment.dataxlr8.com\r\n")
            .await
            .is_err()
        {
            return (false, "EHLO write failed".to_string());
        }
        // Read multi-line EHLO response (250- continuation, 250<space> terminal).
        // Bounded to MAX_EHLO_LINES to prevent infinite loop from rogue servers.
        for _ in 0..MAX_EHLO_LINES {
            if let Err(e) = Self::read_line_safe(&mut reader, &mut line, timeout).await {
                return (false, format!("EHLO: {e}"));
            }
            if line.len() < 4 {
                break;
            }
            if line.as_bytes().get(3) == Some(&b' ') {
                break;
            }
        }

        // MAIL FROM:<> (null reverse-path, standard for verification probes)
        if writer
            .write_all(b"MAIL FROM:<>\r\n")
            .await
            .is_err()
        {
            return (false, "MAIL FROM write failed".to_string());
        }
        if let Err(e) = Self::read_line_safe(&mut reader, &mut line, timeout).await {
            return (false, format!("MAIL FROM: {e}"));
        }
        if !line.starts_with("250") {
            return (false, format!("MAIL FROM rejected: {}", line.trim()));
        }

        // RCPT TO — the actual verification step
        let rcpt = format!("RCPT TO:<{email}>\r\n");
        if writer.write_all(rcpt.as_bytes()).await.is_err() {
            return (false, "RCPT TO write failed".to_string());
        }
        if let Err(e) = Self::read_line_safe(&mut reader, &mut line, timeout).await {
            return (false, format!("RCPT TO: {e}"));
        }

        let accepted = line.starts_with("250");
        let detail = line.trim().to_string();

        // QUIT (best effort, don't care about response)
        let _ = writer.write_all(b"QUIT\r\n").await;

        (accepted, detail)
    }

    /// Full email verification using externally-provided MX records.
    pub async fn verify_with_mx(email: &str, mx_records: &[String]) -> EmailVerification {
        let parts: Vec<&str> = email.split('@').collect();
        let domain = if parts.len() == 2 { parts[1] } else { "" };
        let is_disposable = Self::is_disposable(domain);
        let mx_found = !mx_records.is_empty();

        let (smtp_valid, smtp_detail) = if let Some(mx_host) = mx_records.first() {
            Self::smtp_verify(email, mx_host).await
        } else {
            (false, "no MX records".to_string())
        };

        EmailVerification {
            email: email.to_string(),
            deliverable: smtp_valid,
            catch_all: false,
            disposable: is_disposable,
            mx_found,
            smtp_verified: smtp_valid,
            smtp_detail,
            confidence: if smtp_valid {
                0.9
            } else if mx_found {
                0.4
            } else {
                0.1
            },
            source: "smtp".to_string(),
        }
    }
}

#[async_trait::async_trait]
impl EnrichmentProvider for SmtpProvider {
    fn name(&self) -> &str {
        "smtp"
    }
    fn tier(&self) -> ProviderTier {
        ProviderTier::Free
    }

    async fn verify_email(&self, email: &str) -> Option<EmailVerification> {
        let parts: Vec<&str> = email.split('@').collect();
        if parts.len() != 2 {
            return None;
        }
        let mx_records = DnsProvider::mx_lookup(parts[1]).await;
        Some(Self::verify_with_mx(email, &mx_records).await)
    }

    async fn find_emails(
        &self,
        first_name: &str,
        last_name: &str,
        domain: &str,
    ) -> Vec<EmailCandidate> {
        let f = first_name.to_lowercase();
        let l = last_name.to_lowercase();
        if f.is_empty() || l.is_empty() {
            return vec![];
        }
        let fi: String = f.chars().next().unwrap().to_string();

        // Patterns ordered by commonality (first.last is most common across companies).
        let patterns = vec![
            (format!("{f}.{l}@{domain}"), "first.last"),
            (format!("{fi}.{l}@{domain}"), "fi.last"),
            (format!("{f}@{domain}"), "first"),
            (format!("{f}{l}@{domain}"), "firstlast"),
            (format!("{l}.{f}@{domain}"), "last.first"),
            (format!("{l}@{domain}"), "last"),
            (format!("{fi}{l}@{domain}"), "filast"),
        ];

        patterns
            .into_iter()
            .enumerate()
            .map(|(i, (email, pattern))| EmailCandidate {
                email,
                pattern: pattern.to_string(),
                verified: false,
                confidence: 0.5 - (i as f64 * 0.05),
            })
            .collect()
    }
}
