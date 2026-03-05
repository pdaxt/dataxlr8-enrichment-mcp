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

pub struct SmtpProvider;

impl SmtpProvider {
    pub fn new() -> Self {
        Self
    }

    pub fn is_disposable(domain: &str) -> bool {
        DISPOSABLE_DOMAINS.contains(&domain.to_lowercase().as_str())
    }

    /// Perform SMTP handshake against an MX host to verify deliverability.
    pub async fn smtp_verify(email: &str, mx_host: &str) -> (bool, String) {
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
        let read_timeout = std::time::Duration::from_secs(5);

        // Read banner
        match tokio::time::timeout(read_timeout, reader.read_line(&mut line)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return (false, format!("read banner failed: {e}")),
            Err(_) => return (false, "read banner timeout".to_string()),
        }
        if !line.starts_with("220") {
            return (false, format!("bad banner: {}", line.trim()));
        }

        // EHLO
        line.clear();
        if writer
            .write_all(b"EHLO enrichment.dataxlr8.com\r\n")
            .await
            .is_err()
        {
            return (false, "EHLO write failed".to_string());
        }
        loop {
            line.clear();
            match tokio::time::timeout(read_timeout, reader.read_line(&mut line)).await {
                Ok(Ok(_)) => {}
                Ok(Err(_)) => return (false, "EHLO read failed".to_string()),
                Err(_) => return (false, "EHLO read timeout".to_string()),
            }
            if line.len() < 4 {
                break;
            }
            if line.as_bytes().get(3) == Some(&b' ') {
                break;
            }
        }

        // MAIL FROM
        line.clear();
        if writer
            .write_all(b"MAIL FROM:<>\r\n")
            .await
            .is_err()
        {
            return (false, "MAIL FROM write failed".to_string());
        }
        match tokio::time::timeout(read_timeout, reader.read_line(&mut line)).await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => return (false, "MAIL FROM read failed".to_string()),
            Err(_) => return (false, "MAIL FROM read timeout".to_string()),
        }
        if !line.starts_with("250") {
            return (false, format!("MAIL FROM rejected: {}", line.trim()));
        }

        // RCPT TO
        line.clear();
        let rcpt = format!("RCPT TO:<{email}>\r\n");
        if writer.write_all(rcpt.as_bytes()).await.is_err() {
            return (false, "RCPT TO write failed".to_string());
        }
        match tokio::time::timeout(read_timeout, reader.read_line(&mut line)).await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => return (false, "RCPT TO read failed".to_string()),
            Err(_) => return (false, "RCPT TO read timeout".to_string()),
        }

        let accepted = line.starts_with("250");
        let detail = line.trim().to_string();

        // QUIT (best effort)
        let _ = writer.write_all(b"QUIT\r\n").await;

        (accepted, detail)
    }

    /// Full email verification with MX records provided externally.
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
