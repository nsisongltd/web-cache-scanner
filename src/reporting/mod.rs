use anyhow::Result;
use serde::{Serialize, Deserialize};
use std::path::Path;
use std::fs::File;
use std::io::Write;
use chrono::{DateTime, Utc};
use crate::scanner::{ScanResult, Vulnerability, VulnerabilityType, Severity};

#[derive(Debug, Serialize, Deserialize)]
pub struct Report {
    pub scan_result: ScanResult,
    pub generated_at: DateTime<Utc>,
    pub report_version: String,
}

impl Report {
    pub fn new(scan_result: ScanResult) -> Self {
        Self {
            scan_result,
            generated_at: Utc::now(),
            report_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    pub async fn save_json(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        let mut file = File::create(path)?;
        file.write_all(json.as_bytes())?;
        Ok(())
    }

    pub async fn save_html(&self, path: &Path) -> Result<()> {
        let html = self.generate_html();
        let mut file = File::create(path)?;
        file.write_all(html.as_bytes())?;
        Ok(())
    }

    pub async fn save_markdown(&self, path: &Path) -> Result<()> {
        let markdown = self.generate_markdown();
        let mut file = File::create(path)?;
        file.write_all(markdown.as_bytes())?;
        Ok(())
    }

    fn generate_html(&self) -> String {
        let mut html = String::new();

        // HTML header
        html.push_str(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Cache Vulnerability Scan Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            color: #333;
        }
        .header {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .summary {
            background: #e9ecef;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .vulnerability {
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 15px;
        }
        .high { border-left: 4px solid #dc3545; }
        .medium { border-left: 4px solid #ffc107; }
        .low { border-left: 4px solid #28a745; }
        .metadata {
            font-size: 0.9em;
            color: #6c757d;
            margin-bottom: 10px;
        }
        .proof {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 3px;
            font-family: monospace;
            margin: 10px 0;
        }
        .references {
            margin-top: 10px;
        }
        .references a {
            color: #007bff;
            text-decoration: none;
        }
        .references a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Web Cache Vulnerability Scan Report</h1>
        <p>Generated on: {}</p>
        <p>Scanner Version: {}</p>
    </div>
"#);

        // Scan summary
        html.push_str(&format!(r#"
    <div class="summary">
        <h2>Scan Summary</h2>
        <p><strong>Target:</strong> {}</p>
        <p><strong>Duration:</strong> {:?}</p>
        <p><strong>Total Vulnerabilities:</strong> {}</p>
        <p><strong>Requests Sent:</strong> {}</p>
    </div>
"#,
            self.generated_at.format("%Y-%m-%d %H:%M:%S UTC"),
            self.report_version,
            self.scan_result.target,
            self.scan_result.scan_duration,
            self.scan_result.vulnerabilities.len(),
            self.scan_result.requests_sent
        ));

        // Vulnerabilities
        html.push_str("<h2>Vulnerabilities</h2>");
        for vuln in &self.scan_result.vulnerabilities {
            let severity_class = match vuln.severity {
                Severity::High => "high",
                Severity::Medium => "medium",
                Severity::Low => "low",
            };

            html.push_str(&format!(r#"
    <div class="vulnerability {}">
        <h3>{}</h3>
        <div class="metadata">
            <p><strong>Type:</strong> {:?}</p>
            <p><strong>Severity:</strong> {:?}</p>
            <p><strong>CVSS Score:</strong> {}</p>
            <p><strong>Discovered:</strong> {}</p>
        </div>
        <p><strong>Description:</strong> {}</p>
        <p><strong>URL:</strong> {}</p>
        <div class="proof">
            <strong>Proof of Concept:</strong><br>
            <code>{}</code>
        </div>
        <p><strong>Remediation:</strong> {}</p>
        <div class="references">
            <strong>References:</strong>
            <ul>
"#,
                severity_class,
                vuln.vulnerability_type,
                vuln.vulnerability_type,
                vuln.severity,
                vuln.cvss_score.unwrap_or(0.0),
                vuln.discovered_at.format("%Y-%m-%d %H:%M:%S UTC"),
                vuln.description,
                vuln.url,
                vuln.proof_of_concept,
                vuln.remediation
            ));

            for reference in &vuln.references {
                html.push_str(&format!("                <li><a href=\"{}\">{}</a></li>\n", reference, reference));
            }

            html.push_str("            </ul>\n        </div>\n    </div>\n");
        }

        // HTML footer
        html.push_str("</body>\n</html>");

        html
    }

    fn generate_markdown(&self) -> String {
        let mut markdown = String::new();

        // Header
        markdown.push_str(&format!("# Web Cache Vulnerability Scan Report\n\n"));
        markdown.push_str(&format!("- **Generated on:** {}\n", self.generated_at.format("%Y-%m-%d %H:%M:%S UTC")));
        markdown.push_str(&format!("- **Scanner Version:** {}\n\n", self.report_version));

        // Summary
        markdown.push_str("## Scan Summary\n\n");
        markdown.push_str(&format!("- **Target:** {}\n", self.scan_result.target));
        markdown.push_str(&format!("- **Duration:** {:?}\n", self.scan_result.scan_duration));
        markdown.push_str(&format!("- **Total Vulnerabilities:** {}\n", self.scan_result.vulnerabilities.len()));
        markdown.push_str(&format!("- **Requests Sent:** {}\n\n", self.scan_result.requests_sent));

        // Vulnerabilities
        markdown.push_str("## Vulnerabilities\n\n");
        for vuln in &self.scan_result.vulnerabilities {
            markdown.push_str(&format!("### {} - {:?} ({:?})\n\n", 
                vuln.vulnerability_type,
                vuln.severity,
                vuln.cvss_score.unwrap_or(0.0)
            ));

            markdown.push_str(&format!("**Description:** {}\n\n", vuln.description));
            markdown.push_str(&format!("**URL:** {}\n\n", vuln.url));
            markdown.push_str(&format!("**Proof of Concept:**\n```bash\n{}\n```\n\n", vuln.proof_of_concept));
            markdown.push_str(&format!("**Remediation:** {}\n\n", vuln.remediation));

            markdown.push_str("**References:**\n");
            for reference in &vuln.references {
                markdown.push_str(&format!("- [{}]({})\n", reference, reference));
            }
            markdown.push_str("\n---\n\n");
        }

        markdown
    }
} 