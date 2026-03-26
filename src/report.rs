use crate::config::Config;
use crate::modules::{ScanResult, Severity};
use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;

pub struct ReportGenerator {
    findings: Vec<ScanResult>,
    cfg: Config,
}

impl ReportGenerator {
    pub fn new(findings: Vec<ScanResult>, cfg: Config) -> Self {
        Self { findings, cfg }
    }

    pub fn export_json(&self, path: &str) -> Result<()> {
        let json = serde_json::to_string_pretty(&ReportOutput {
            generated_at: Utc::now().to_rfc3339(),
            total_findings: self.findings.len(),
            critical: self.count_severity(Severity::Critical),
            high: self.count_severity(Severity::High),
            medium: self.count_severity(Severity::Medium),
            low: self.count_severity(Severity::Low),
            findings: &self.findings,
        })?;
        let mut file = File::create(path)?;
        file.write_all(json.as_bytes())?;
        Ok(())
    }

    pub fn export_csv(&self, path: &str) -> Result<()> {
        let mut file = File::create(path)?;
        writeln!(file, "ID,Severity,ThreatScore,Category,Title,MITRE,Timestamp")?;
        for f in &self.findings {
            writeln!(
                file,
                "{},{},{},{},{},{},{}",
                f.id, f.severity, f.threat_score, f.category,
                f.title.replace(',', ";"),
                f.mitre_technique.as_deref().unwrap_or("-"),
                f.timestamp.to_rfc3339(),
            )?;
        }
        Ok(())
    }

    pub fn export_html(&self, path: &str) -> Result<()> {
        let critical = self.count_severity(Severity::Critical);
        let high = self.count_severity(Severity::High);
        let medium = self.count_severity(Severity::Medium);
        let low = self.count_severity(Severity::Low);
        let overall_risk = if critical > 0 { ("CRITICAL", "#ff4444") }
            else if high > 0 { ("HIGH", "#ff8800") }
            else if medium > 0 { ("MEDIUM", "#ffcc00") }
            else { ("LOW / CLEAN", "#44ff44") };
        let findings_rows: String = self.findings.iter().map(|f| {
            let (sev_color, bg_color) = match f.severity {
                Severity::Critical => ("#ff4444", "#1a0000"),
                Severity::High => ("#ff8800", "#1a0a00"),
                Severity::Medium => ("#ffcc00", "#1a1400"),
                Severity::Low => ("#6699ff", "#00001a"),
                Severity::Info => ("#888888", "#0a0a0a"),
            };
            let artifacts_html: String = f.artifacts.iter()
                .map(|a| format!("<li><code>{}</code></li>", html_escape(a)))
                .collect();
            let recs_html: String = f.recommendations.iter()
                .map(|r| format!("<li>{}</li>", html_escape(r)))
                .collect();
            format!(
                "<tr style='background:{bg};' onclick='toggleDetail(\"{id}\")'>\
                <td><span style='color:{sc};font-weight:bold;'>{sev}</span></td>\
                <td>{score}</td><td><code>{cat}</code></td><td>{title}</td><td>{mitre}</td></tr>\
                <tr id='{id}' class='detail-row'>\
                <td colspan='5'><div class='detail-box'>\
                <p>{desc}</p><ul>{art}</ul><ul>{recs}</ul></div></td></tr>",
                bg=bg_color, sc=sev_color, id=&f.id, sev=&f.severity,
                score=f.threat_score, cat=html_escape(&f.category),
                title=html_escape(&f.title),
                mitre=html_escape(f.mitre_technique.as_deref().unwrap_or("-")),
                desc=html_escape(&f.description),
                art=artifacts_html, recs=recs_html,
            )
        }).collect();
        let html = format!(
            "<!DOCTYPE html><html><head><meta charset='UTF-8'>\
            <title>LTHF Threat Report</title>\
            <style>body{{background:#0d1117;color:#e6edf3;font-family:monospace;padding:20px}}\
            h1{{color:#58a6ff}} table{{width:100%;border-collapse:collapse}}\
            th{{background:#21262d;padding:12px;text-align:left;color:#58a6ff}}\
            td{{padding:10px;border-top:1px solid #30363d}}\
            .detail-row{{display:none}} .detail-row.open{{display:table-row}}\
            .detail-box{{background:#1c1f26;padding:16px;border-radius:6px}}\
            code{{background:#21262d;padding:26px;border-radius:4px}}\
            </style></head><body>\
            <h1>⚩ Linux Threat Hunting Framework Report</h1>\
            <p>Generated: {ts} | Risk: <strong style='color:{risk_color}'>{risk_level}</strong></p>\
            <p>CRITICAL: {crit} | HIGH: {high} | MEDIUM: {med} | LOW: {low} | TOTAL: {total}</p>\
            <table><thead><tr><th>Severity</th><th>Score</th><th>Category</th><th>Title</th><th>MITRE </th></tr></thead>\
            <tbody>{rows}</tbody></table>\
            <script>function toggleDetail(id){{var r=document.getElementById(id);r.classList.toggle('open')}}</script>\
            </body></html>",
            ts=Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
            risk_level=overall_risk.0, risk_color=overall_risk.1,
            crit=critical, high=high, med=medium, low=low,
            total=self.findings.len(), rows=findings_rows,
        );
        let mut file = File::create(path)?;
        file.write_all(html.as_bytes())?;
        Ok(())
    }

    fn count_severity(&self, sev: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == sev).count()
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
        .replace('"', "&quot;").replace('\'', "&#39;")
}

#[derive(serde::Serialize)]
struct ReportOutput<'a> {
    generated_at: String, total_findings: usize,
    critical: usize, high: usize, medium: usize, low: usize,
    findings: &'a Vec<ScanResult>,
}
