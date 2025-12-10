#!/usr/bin/env node
/**
 * PentestAI Professional PDF Report Generator
 * Generates executive-quality penetration test reports
 */

const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');

// Professional color scheme
const colors = {
    primary: '#0f172a',      // Dark navy
    secondary: '#1e293b',    // Slate
    accent: '#3b82f6',       // Blue
    critical: '#dc2626',     // Red
    high: '#ea580c',         // Orange
    medium: '#ca8a04',       // Yellow/amber
    low: '#16a34a',          // Green
    info: '#0891b2',         // Cyan
    background: '#f8fafc',   // Light gray
    cardBg: '#ffffff',       // White
    text: '#1e293b',         // Dark text
    lightText: '#64748b',    // Gray text
    border: '#e2e8f0',       // Light border
    success: '#22c55e',      // Green
    danger: '#ef4444',       // Red
};

class ProfessionalReportGenerator {
    constructor(scanData, outputPath) {
        this.scanData = scanData;
        this.outputPath = outputPath;
        this.doc = new PDFDocument({
            size: 'A4',
            margins: { top: 40, bottom: 40, left: 50, right: 50 },
            bufferPages: true,
            info: {
                Title: `Penetration Test Report - ${scanData.target}`,
                Author: 'PentestAI',
                Subject: 'Security Assessment',
                Creator: 'PentestAI Report Generator'
            }
        });
        this.pageWidth = this.doc.page.width;
        this.pageHeight = this.doc.page.height;
        this.contentWidth = this.pageWidth - 100;
        this.currentY = 40;
    }

    generate() {
        const stream = fs.createWriteStream(this.outputPath);
        this.doc.pipe(stream);

        this.addCoverPage();
        this.addTableOfContents();
        this.addExecutiveSummary();
        this.addRiskOverview();
        this.addDetailedFindings();
        this.addTestResults();
        this.addCredentialsSection();
        this.addRecommendations();
        this.addAppendix();
        this.addPageNumbers();
        this.addFooters();

        this.doc.end();

        return new Promise((resolve, reject) => {
            stream.on('finish', () => resolve(this.outputPath));
            stream.on('error', reject);
        });
    }

    // ============================================
    // COVER PAGE
    // ============================================
    addCoverPage() {
        const { doc } = this;

        // Full page dark background
        doc.rect(0, 0, this.pageWidth, this.pageHeight).fill(colors.primary);

        // Decorative top accent line
        doc.rect(0, 0, this.pageWidth, 8).fill(colors.accent);

        // Geometric decoration
        doc.save();
        doc.opacity(0.1);
        for (let i = 0; i < 5; i++) {
            doc.circle(this.pageWidth - 100 + (i * 30), 200 + (i * 40), 80 + (i * 20))
               .stroke('#ffffff');
        }
        doc.restore();

        // Company/Tool branding
        doc.fontSize(14)
           .fillColor(colors.accent)
           .text('PENTESTAI', 50, 60)
           .fontSize(10)
           .fillColor('#94a3b8')
           .text('Autonomous Security Assessment Platform', 50, 78);

        // Main title
        doc.fontSize(42)
           .fillColor('#ffffff')
           .text('PENETRATION', 50, 200, { characterSpacing: 2 })
           .text('TEST REPORT', 50, 250, { characterSpacing: 2 });

        // Subtitle
        doc.fontSize(14)
           .fillColor(colors.accent)
           .text('SECURITY ASSESSMENT FINDINGS', 50, 320, { characterSpacing: 1 });

        // Target info box
        const boxY = 380;
        doc.roundedRect(50, boxY, this.contentWidth, 120, 5)
           .fillAndStroke(colors.secondary, colors.secondary);

        doc.fontSize(10)
           .fillColor('#94a3b8')
           .text('TARGET', 70, boxY + 20);
        doc.fontSize(18)
           .fillColor('#ffffff')
           .text(this.scanData.target || 'N/A', 70, boxY + 38);

        doc.fontSize(10)
           .fillColor('#94a3b8')
           .text('ASSESSMENT DATE', 70, boxY + 70);
        doc.fontSize(14)
           .fillColor('#ffffff')
           .text(this.scanData.date || new Date().toISOString().split('T')[0], 70, boxY + 88);

        // Stats row
        const statsY = boxY + 160;
        const stats = this.getStats();
        const statWidth = this.contentWidth / 4;

        [
            { label: 'TESTS RUN', value: stats.testsRun, color: colors.accent },
            { label: 'CRITICAL', value: stats.critical, color: colors.critical },
            { label: 'HIGH', value: stats.high, color: colors.high },
            { label: 'CREDENTIALS', value: stats.credentials, color: colors.danger }
        ].forEach((stat, i) => {
            const x = 50 + (i * statWidth);
            doc.roundedRect(x + 5, statsY, statWidth - 10, 80, 5)
               .fill(colors.secondary);
            doc.fontSize(28)
               .fillColor(stat.color)
               .text(stat.value.toString(), x + 5, statsY + 15, { width: statWidth - 10, align: 'center' });
            doc.fontSize(9)
               .fillColor('#94a3b8')
               .text(stat.label, x + 5, statsY + 52, { width: statWidth - 10, align: 'center' });
        });

        // Classification banner
        doc.fontSize(10)
           .fillColor(colors.critical)
           .text('CONFIDENTIAL - FOR AUTHORIZED USE ONLY', 50, this.pageHeight - 80, {
               width: this.contentWidth,
               align: 'center'
           });

        // Version/date footer
        doc.fontSize(9)
           .fillColor('#64748b')
           .text(`Generated: ${new Date().toLocaleString()}`, 50, this.pageHeight - 50, {
               width: this.contentWidth,
               align: 'center'
           });

        doc.addPage();
    }

    // ============================================
    // TABLE OF CONTENTS
    // ============================================
    addTableOfContents() {
        const { doc } = this;

        this.addPageHeader('TABLE OF CONTENTS');

        const items = [
            { title: 'Executive Summary', page: 3 },
            { title: 'Risk Overview', page: 4 },
            { title: 'Detailed Findings', page: 5 },
            { title: 'Test Results', page: 6 },
            { title: 'Extracted Credentials', page: 7 },
            { title: 'Recommendations', page: 8 },
            { title: 'Appendix', page: 9 }
        ];

        let y = 140;
        items.forEach((item, index) => {
            // Number
            doc.fontSize(12)
               .fillColor(colors.accent)
               .text(`${index + 1}.`, 50, y);

            // Title
            doc.fontSize(12)
               .fillColor(colors.text)
               .text(item.title, 80, y);

            // Dots
            const titleWidth = doc.widthOfString(item.title);
            const dotsStart = 85 + titleWidth;
            const dotsEnd = this.pageWidth - 80;
            let dots = '';
            let dotsWidth = 0;
            while (dotsWidth < (dotsEnd - dotsStart - 30)) {
                dots += ' .';
                dotsWidth = doc.widthOfString(dots);
            }
            doc.fillColor(colors.lightText)
               .text(dots, dotsStart, y);

            // Page number
            doc.fillColor(colors.text)
               .text(item.page.toString(), this.pageWidth - 70, y);

            y += 35;
        });

        doc.addPage();
    }

    // ============================================
    // EXECUTIVE SUMMARY
    // ============================================
    addExecutiveSummary() {
        const { doc, scanData } = this;

        this.addPageHeader('EXECUTIVE SUMMARY');

        const stats = this.getStats();
        let y = 130;

        // Overview paragraph
        const riskLevel = this.calculateOverallRisk();
        doc.fontSize(11)
           .fillColor(colors.text)
           .text(
               `This penetration test was conducted against ${scanData.target} on ${scanData.date || 'the assessment date'}. ` +
               `The assessment utilized automated security testing tools to identify vulnerabilities and security weaknesses. ` +
               `A total of ${stats.testsRun} security tests were performed, identifying ${stats.totalVulns} vulnerabilities ` +
               `and ${stats.credentials} exposed credentials.`,
               50, y, { width: this.contentWidth, align: 'justify', lineGap: 4 }
           );

        y += 80;

        // Risk rating box
        const riskColors = {
            'CRITICAL': colors.critical,
            'HIGH': colors.high,
            'MEDIUM': colors.medium,
            'LOW': colors.low
        };

        doc.roundedRect(50, y, this.contentWidth, 70, 5)
           .fill(colors.background);

        doc.fontSize(10)
           .fillColor(colors.lightText)
           .text('OVERALL RISK RATING', 70, y + 15);

        doc.fontSize(24)
           .fillColor(riskColors[riskLevel] || colors.info)
           .font('Helvetica-Bold')
           .text(riskLevel, 70, y + 35)
           .font('Helvetica');

        // Risk indicator bar
        const barX = 280;
        const barWidth = 200;
        const barHeight = 8;
        doc.roundedRect(barX, y + 40, barWidth, barHeight, 4).fill(colors.border);

        const riskPercent = { 'CRITICAL': 1, 'HIGH': 0.75, 'MEDIUM': 0.5, 'LOW': 0.25 }[riskLevel] || 0.1;
        doc.roundedRect(barX, y + 40, barWidth * riskPercent, barHeight, 4)
           .fill(riskColors[riskLevel] || colors.info);

        y += 100;

        // Key findings
        doc.fontSize(14)
           .fillColor(colors.primary)
           .font('Helvetica-Bold')
           .text('Key Findings', 50, y)
           .font('Helvetica');

        y += 25;

        const findings = this.generateKeyFindings();
        findings.forEach(finding => {
            doc.fontSize(10)
               .fillColor(colors.accent)
               .text('●', 60, y);
            doc.fillColor(colors.text)
               .text(finding, 80, y, { width: this.contentWidth - 30 });
            y += 25;
        });

        // Critical alert box if credentials found
        if (stats.credentials > 0) {
            y += 20;
            doc.roundedRect(50, y, this.contentWidth, 60, 5)
               .fillAndStroke('#fef2f2', colors.critical);

            doc.fontSize(11)
               .fillColor(colors.critical)
               .font('Helvetica-Bold')
               .text('⚠ CRITICAL ALERT', 70, y + 15)
               .font('Helvetica')
               .fontSize(10)
               .text(
                   `${stats.credentials} user credentials were extracted during this assessment. ` +
                   `Immediate password resets are required for all compromised accounts.`,
                   70, y + 32, { width: this.contentWidth - 40 }
               );
        }

        doc.addPage();
    }

    // ============================================
    // RISK OVERVIEW
    // ============================================
    addRiskOverview() {
        const { doc } = this;

        this.addPageHeader('RISK OVERVIEW');

        const stats = this.getStats();
        let y = 130;

        // Severity breakdown
        doc.fontSize(14)
           .fillColor(colors.primary)
           .font('Helvetica-Bold')
           .text('Vulnerability Distribution', 50, y)
           .font('Helvetica');

        y += 30;

        const severities = [
            { label: 'Critical', count: stats.critical, color: colors.critical, desc: 'Immediate exploitation possible' },
            { label: 'High', count: stats.high, color: colors.high, desc: 'Significant security impact' },
            { label: 'Medium', count: stats.medium, color: colors.medium, desc: 'Moderate security concern' },
            { label: 'Low', count: stats.low, color: colors.low, desc: 'Minor security issue' },
            { label: 'Info', count: stats.info, color: colors.info, desc: 'Informational finding' }
        ];

        const maxCount = Math.max(...severities.map(s => s.count), 1);

        severities.forEach(sev => {
            // Severity label
            doc.fontSize(11)
               .fillColor(colors.text)
               .text(sev.label, 50, y, { width: 70 });

            // Count
            doc.font('Helvetica-Bold')
               .fillColor(sev.color)
               .text(sev.count.toString(), 120, y, { width: 40 });

            // Bar
            const barWidth = (sev.count / maxCount) * 250;
            doc.roundedRect(170, y + 2, 250, 14, 3).fill(colors.border);
            if (barWidth > 0) {
                doc.roundedRect(170, y + 2, Math.max(barWidth, 10), 14, 3).fill(sev.color);
            }

            // Description
            doc.font('Helvetica')
               .fontSize(9)
               .fillColor(colors.lightText)
               .text(sev.desc, 430, y + 2);

            y += 35;
        });

        y += 30;

        // Test coverage
        doc.fontSize(14)
           .fillColor(colors.primary)
           .font('Helvetica-Bold')
           .text('Assessment Coverage', 50, y)
           .font('Helvetica');

        y += 30;

        // Coverage grid
        const tests = this.scanData.tests || [];
        const testTypes = {};
        tests.forEach(t => {
            const type = t.action || t.name || 'unknown';
            if (!testTypes[type]) testTypes[type] = { total: 0, success: 0 };
            testTypes[type].total++;
            if (t.success) testTypes[type].success++;
        });

        const cols = 3;
        const colWidth = this.contentWidth / cols;
        let col = 0;

        Object.entries(testTypes).forEach(([type, data]) => {
            const x = 50 + (col * colWidth);
            const successRate = data.total > 0 ? Math.round((data.success / data.total) * 100) : 0;

            doc.roundedRect(x, y, colWidth - 10, 50, 3)
               .fill(colors.background);

            doc.fontSize(9)
               .fillColor(colors.lightText)
               .text(this.formatTestName(type), x + 10, y + 10, { width: colWidth - 30 });

            doc.fontSize(14)
               .fillColor(data.success > 0 ? colors.success : colors.lightText)
               .text(`${successRate}%`, x + 10, y + 28);

            col++;
            if (col >= cols) {
                col = 0;
                y += 60;
            }
        });

        doc.addPage();
    }

    // ============================================
    // DETAILED FINDINGS
    // ============================================
    addDetailedFindings() {
        const { doc } = this;

        this.addPageHeader('DETAILED FINDINGS');

        const vulns = this.scanData.vulnerabilities || [];
        if (vulns.length === 0) {
            doc.fontSize(11)
               .fillColor(colors.text)
               .text('No vulnerabilities were identified during this assessment.', 50, 130);
            doc.addPage();
            return;
        }

        let y = 130;
        const grouped = this.groupBySeverity(vulns);

        ['critical', 'high', 'medium', 'low', 'info'].forEach(severity => {
            const items = grouped[severity] || [];
            if (items.length === 0) return;

            // Check page space
            if (y > this.pageHeight - 150) {
                doc.addPage();
                this.addPageHeader('DETAILED FINDINGS (CONTINUED)');
                y = 130;
            }

            // Severity header
            const sevColor = colors[severity] || colors.info;
            doc.roundedRect(50, y, this.contentWidth, 28, 3)
               .fill(sevColor);
            doc.fontSize(11)
               .fillColor('#ffffff')
               .font('Helvetica-Bold')
               .text(`${severity.toUpperCase()} SEVERITY (${items.length})`, 65, y + 8)
               .font('Helvetica');

            y += 40;

            items.forEach((vuln, index) => {
                if (y > this.pageHeight - 120) {
                    doc.addPage();
                    this.addPageHeader('DETAILED FINDINGS (CONTINUED)');
                    y = 130;
                }

                // Finding card
                doc.roundedRect(50, y, this.contentWidth, 70, 3)
                   .fillAndStroke(colors.background, colors.border);

                // Finding number
                doc.circle(65, y + 15, 10).fill(sevColor);
                doc.fontSize(9)
                   .fillColor('#ffffff')
                   .text((index + 1).toString(), 60, y + 11, { width: 10, align: 'center' });

                // Finding title
                doc.fontSize(11)
                   .fillColor(colors.primary)
                   .font('Helvetica-Bold')
                   .text(vuln.type || vuln.name || 'Unknown Vulnerability', 85, y + 10, { width: this.contentWidth - 50 })
                   .font('Helvetica');

                // Target
                doc.fontSize(9)
                   .fillColor(colors.lightText)
                   .text(`Target: ${vuln.target || 'N/A'}`, 85, y + 28);

                // Description
                if (vuln.description) {
                    doc.fontSize(9)
                       .fillColor(colors.text)
                       .text(vuln.description.substring(0, 150) + (vuln.description.length > 150 ? '...' : ''),
                             85, y + 45, { width: this.contentWidth - 50 });
                }

                y += 85;
            });

            y += 15;
        });

        doc.addPage();
    }

    // ============================================
    // TEST RESULTS
    // ============================================
    addTestResults() {
        const { doc } = this;

        this.addPageHeader('TEST RESULTS');

        const tests = this.scanData.tests || [];
        if (tests.length === 0) {
            doc.fontSize(11)
               .fillColor(colors.text)
               .text('No test results recorded.', 50, 130);
            doc.addPage();
            return;
        }

        let y = 130;

        // Summary stats
        const passed = tests.filter(t => t.success).length;
        const failed = tests.length - passed;

        doc.roundedRect(50, y, this.contentWidth / 2 - 10, 50, 3).fill(colors.background);
        doc.fontSize(20).fillColor(colors.success).text(passed.toString(), 70, y + 10);
        doc.fontSize(10).fillColor(colors.lightText).text('Tests Passed', 70, y + 32);

        doc.roundedRect(50 + this.contentWidth / 2, y, this.contentWidth / 2 - 10, 50, 3).fill(colors.background);
        doc.fontSize(20).fillColor(colors.danger).text(failed.toString(), 70 + this.contentWidth / 2, y + 10);
        doc.fontSize(10).fillColor(colors.lightText).text('Tests Failed', 70 + this.contentWidth / 2, y + 32);

        y += 70;

        // Test list
        tests.forEach((test, index) => {
            if (y > this.pageHeight - 100) {
                doc.addPage();
                this.addPageHeader('TEST RESULTS (CONTINUED)');
                y = 130;
            }

            const cardHeight = test.output && test.output.length > 0 ? 75 : 50;

            doc.roundedRect(50, y, this.contentWidth, cardHeight, 3)
               .fillAndStroke('#ffffff', colors.border);

            // Status indicator
            doc.rect(50, y, 4, cardHeight).fill(test.success ? colors.success : colors.danger);

            // Test name
            doc.fontSize(10)
               .fillColor(colors.primary)
               .font('Helvetica-Bold')
               .text(this.formatTestName(test.action || test.name), 65, y + 10)
               .font('Helvetica');

            // Target
            doc.fontSize(9)
               .fillColor(colors.lightText)
               .text(test.target || 'N/A', 65, y + 26);

            // Status badge
            const statusText = test.success ? 'PASSED' : 'FAILED';
            const statusColor = test.success ? colors.success : colors.danger;
            const badgeX = this.pageWidth - 120;
            doc.roundedRect(badgeX, y + 10, 60, 18, 9).fill(statusColor);
            doc.fontSize(8)
               .fillColor('#ffffff')
               .text(statusText, badgeX, y + 15, { width: 60, align: 'center' });

            // Output preview
            if (test.output && test.output.length > 0) {
                doc.fontSize(8)
                   .fillColor(colors.lightText)
                   .text(test.output.substring(0, 100) + (test.output.length > 100 ? '...' : ''),
                         65, y + 45, { width: this.contentWidth - 100 });
            }

            y += cardHeight + 8;
        });

        doc.addPage();
    }

    // ============================================
    // CREDENTIALS SECTION
    // ============================================
    addCredentialsSection() {
        const { doc } = this;

        this.addPageHeader('EXTRACTED CREDENTIALS');

        const creds = this.scanData.credentials || [];
        let y = 130;

        if (creds.length === 0) {
            doc.fontSize(11)
               .fillColor(colors.text)
               .text('No credentials were extracted during this assessment.', 50, y);
            doc.addPage();
            return;
        }

        // Warning banner
        doc.roundedRect(50, y, this.contentWidth, 60, 5)
           .fillAndStroke('#fef2f2', colors.critical);

        doc.fontSize(12)
           .fillColor(colors.critical)
           .font('Helvetica-Bold')
           .text('⚠ SECURITY BREACH - CREDENTIALS EXPOSED', 70, y + 12)
           .font('Helvetica');

        doc.fontSize(10)
           .fillColor(colors.text)
           .text(
               'The following credentials were extracted during testing. These accounts are compromised ' +
               'and passwords must be changed immediately. Enable MFA where possible.',
               70, y + 32, { width: this.contentWidth - 40 }
           );

        y += 80;

        // Table header
        doc.roundedRect(50, y, this.contentWidth, 30, 3).fill(colors.primary);
        doc.fontSize(9)
           .fillColor('#ffffff')
           .text('USERNAME', 65, y + 10)
           .text('PASSWORD', 200, y + 10)
           .text('TYPE', 380, y + 10)
           .text('SOURCE', 460, y + 10);

        y += 35;

        // Credentials rows
        creds.forEach((cred, index) => {
            if (y > this.pageHeight - 60) {
                doc.addPage();
                this.addPageHeader('EXTRACTED CREDENTIALS (CONTINUED)');
                y = 130;
            }

            const bgColor = index % 2 === 0 ? '#ffffff' : colors.background;
            doc.roundedRect(50, y, this.contentWidth, 28, 0).fill(bgColor);

            doc.fontSize(10)
               .fillColor(colors.primary)
               .font('Helvetica-Bold')
               .text(cred.username || 'N/A', 65, y + 8)
               .font('Helvetica');

            // Masked password
            const password = cred.password || cred.hash || 'N/A';
            const masked = password.length > 4
                ? password.substring(0, 2) + '••••' + password.substring(password.length - 2)
                : '••••';
            doc.fillColor(colors.text)
               .text(masked, 200, y + 8);

            doc.fillColor(colors.lightText)
               .text(cred.type || 'password', 380, y + 8)
               .text(cred.source || cred.service || 'N/A', 460, y + 8);

            y += 30;
        });

        doc.addPage();
    }

    // ============================================
    // RECOMMENDATIONS
    // ============================================
    addRecommendations() {
        const { doc } = this;

        this.addPageHeader('RECOMMENDATIONS');

        let y = 130;

        const recommendations = this.generateRecommendations();

        recommendations.forEach((rec, index) => {
            if (y > this.pageHeight - 120) {
                doc.addPage();
                this.addPageHeader('RECOMMENDATIONS (CONTINUED)');
                y = 130;
            }

            const priorityColors = {
                'Critical': colors.critical,
                'High': colors.high,
                'Medium': colors.medium,
                'Low': colors.low
            };

            // Card
            doc.roundedRect(50, y, this.contentWidth, 80, 5)
               .fillAndStroke('#ffffff', colors.border);

            // Priority badge
            doc.roundedRect(55, y + 5, 70, 20, 10)
               .fill(priorityColors[rec.priority] || colors.info);
            doc.fontSize(8)
               .fillColor('#ffffff')
               .text(rec.priority.toUpperCase(), 55, y + 11, { width: 70, align: 'center' });

            // Number
            doc.fontSize(20)
               .fillColor(colors.border)
               .text((index + 1).toString().padStart(2, '0'), this.pageWidth - 100, y + 10);

            // Title
            doc.fontSize(12)
               .fillColor(colors.primary)
               .font('Helvetica-Bold')
               .text(rec.title, 65, y + 32)
               .font('Helvetica');

            // Description
            doc.fontSize(9)
               .fillColor(colors.text)
               .text(rec.description, 65, y + 50, { width: this.contentWidth - 40 });

            y += 95;
        });

        doc.addPage();
    }

    // ============================================
    // APPENDIX
    // ============================================
    addAppendix() {
        const { doc } = this;

        this.addPageHeader('APPENDIX');

        let y = 130;

        // Methodology
        doc.fontSize(12)
           .fillColor(colors.primary)
           .font('Helvetica-Bold')
           .text('A. Testing Methodology', 50, y)
           .font('Helvetica');

        y += 25;

        doc.fontSize(10)
           .fillColor(colors.text)
           .text(
               'This assessment utilized PentestAI, an autonomous penetration testing platform that employs ' +
               'AI-driven decision making to identify and exploit vulnerabilities. The testing methodology includes:\n\n' +
               '• Port scanning and service enumeration\n' +
               '• Web application vulnerability scanning\n' +
               '• SSL/TLS configuration analysis\n' +
               '• API endpoint fuzzing\n' +
               '• SQL injection and command injection testing\n' +
               '• Authentication testing and credential extraction\n' +
               '• Automated exploitation of discovered vulnerabilities',
               50, y, { width: this.contentWidth, lineGap: 3 }
           );

        y += 160;

        // Disclaimer
        doc.fontSize(12)
           .fillColor(colors.primary)
           .font('Helvetica-Bold')
           .text('B. Disclaimer', 50, y)
           .font('Helvetica');

        y += 25;

        doc.fontSize(9)
           .fillColor(colors.lightText)
           .text(
               'This report is provided for informational purposes only. The findings represent the security ' +
               'posture at the time of testing and may not reflect current conditions. This assessment was ' +
               'conducted with proper authorization. The testing organization is not responsible for any ' +
               'actions taken based on this report.',
               50, y, { width: this.contentWidth, lineGap: 2 }
           );
    }

    // ============================================
    // HELPERS
    // ============================================
    addPageHeader(title) {
        const { doc } = this;

        // Header line
        doc.rect(50, 40, this.contentWidth, 3).fill(colors.accent);

        // Title
        doc.fontSize(18)
           .fillColor(colors.primary)
           .font('Helvetica-Bold')
           .text(title, 50, 60)
           .font('Helvetica');

        // Underline
        doc.rect(50, 90, 60, 3).fill(colors.accent);
    }

    addPageNumbers() {
        const { doc } = this;
        const pages = doc.bufferedPageRange();

        for (let i = 0; i < pages.count; i++) {
            doc.switchToPage(i);

            if (i === 0) continue; // Skip cover page

            doc.fontSize(9)
               .fillColor(colors.lightText)
               .text(
                   `Page ${i} of ${pages.count - 1}`,
                   50, this.pageHeight - 30,
                   { width: this.contentWidth, align: 'right' }
               );
        }
    }

    addFooters() {
        const { doc } = this;
        const pages = doc.bufferedPageRange();

        for (let i = 1; i < pages.count; i++) {
            doc.switchToPage(i);

            doc.fontSize(8)
               .fillColor(colors.lightText)
               .text('CONFIDENTIAL', 50, this.pageHeight - 30);

            doc.text(`PentestAI Report - ${this.scanData.target}`, 50, this.pageHeight - 30, {
                width: this.contentWidth,
                align: 'center'
            });
        }
    }

    getStats() {
        const vulns = this.scanData.vulnerabilities || [];
        const tests = this.scanData.tests || [];
        const creds = this.scanData.credentials || [];

        return {
            testsRun: tests.length,
            totalVulns: vulns.length,
            critical: vulns.filter(v => v.severity?.toLowerCase() === 'critical').length,
            high: vulns.filter(v => v.severity?.toLowerCase() === 'high').length,
            medium: vulns.filter(v => v.severity?.toLowerCase() === 'medium').length,
            low: vulns.filter(v => v.severity?.toLowerCase() === 'low').length,
            info: vulns.filter(v => v.severity?.toLowerCase() === 'info').length,
            credentials: creds.length
        };
    }

    calculateOverallRisk() {
        const stats = this.getStats();
        if (stats.critical > 0 || stats.credentials > 0) return 'CRITICAL';
        if (stats.high > 0) return 'HIGH';
        if (stats.medium > 0) return 'MEDIUM';
        if (stats.low > 0) return 'LOW';
        return 'LOW';
    }

    groupBySeverity(vulns) {
        return vulns.reduce((acc, vuln) => {
            const sev = (vuln.severity || 'info').toLowerCase();
            if (!acc[sev]) acc[sev] = [];
            acc[sev].push(vuln);
            return acc;
        }, {});
    }

    formatTestName(name) {
        if (!name) return 'Unknown Test';
        return name
            .replace(/_/g, ' ')
            .replace(/\b\w/g, l => l.toUpperCase());
    }

    generateKeyFindings() {
        const findings = [];
        const stats = this.getStats();

        if (stats.critical > 0) {
            findings.push(`${stats.critical} critical severity vulnerabilities requiring immediate attention`);
        }
        if (stats.credentials > 0) {
            findings.push(`${stats.credentials} user credentials were successfully extracted`);
        }
        if (stats.high > 0) {
            findings.push(`${stats.high} high severity vulnerabilities identified`);
        }

        const headerIssues = (this.scanData.vulnerabilities || [])
            .filter(v => v.type?.includes('header')).length;
        if (headerIssues > 0) {
            findings.push(`${headerIssues} security header misconfigurations detected`);
        }

        if (findings.length === 0) {
            findings.push('No critical security issues were identified during this assessment');
        }

        return findings;
    }

    generateRecommendations() {
        const recommendations = [];
        const stats = this.getStats();

        if (stats.credentials > 0) {
            recommendations.push({
                priority: 'Critical',
                title: 'Immediate Password Reset Required',
                description: 'Force password resets for all compromised accounts. Implement strong password policies and enable multi-factor authentication.'
            });
        }

        if (stats.critical > 0) {
            recommendations.push({
                priority: 'Critical',
                title: 'Patch Critical Vulnerabilities',
                description: 'Address all critical vulnerabilities within 24-48 hours. These issues can lead to complete system compromise.'
            });
        }

        if (stats.high > 0) {
            recommendations.push({
                priority: 'High',
                title: 'Remediate High-Risk Issues',
                description: 'Schedule remediation of high severity findings within 1-2 weeks. Implement compensating controls if immediate fixes are not possible.'
            });
        }

        const headerIssues = (this.scanData.vulnerabilities || [])
            .filter(v => v.type?.includes('header')).length;
        if (headerIssues > 0) {
            recommendations.push({
                priority: 'Medium',
                title: 'Implement Security Headers',
                description: 'Configure X-Frame-Options, Content-Security-Policy, X-XSS-Protection, X-Content-Type-Options, and Strict-Transport-Security headers.'
            });
        }

        recommendations.push({
            priority: 'Medium',
            title: 'Regular Security Assessments',
            description: 'Conduct penetration tests quarterly and after significant changes. Implement continuous vulnerability scanning.'
        });

        recommendations.push({
            priority: 'Low',
            title: 'Security Awareness Training',
            description: 'Provide security training to development and operations teams. Implement secure coding practices and code review processes.'
        });

        return recommendations;
    }
}

// Main execution
async function main() {
    const args = process.argv.slice(2);

    if (args.length < 1) {
        console.log('PentestAI Professional Report Generator');
        console.log('======================================\n');
        console.log('Usage: node generate-report.js <scan-results.json> [output.pdf]\n');
        console.log('Example:');
        console.log('  node generate-report.js results.json report.pdf\n');
        process.exit(1);
    }

    const inputFile = args[0];
    const outputFile = args[1] || inputFile.replace('.json', '') + '-report.pdf';

    try {
        console.log(`\n📄 Reading scan results from: ${inputFile}`);
        const scanData = JSON.parse(fs.readFileSync(inputFile, 'utf8'));

        console.log(`📊 Target: ${scanData.target}`);
        console.log(`📅 Date: ${scanData.date}`);
        console.log(`🔍 Tests: ${scanData.tests?.length || 0}`);
        console.log(`⚠️  Vulnerabilities: ${scanData.vulnerabilities?.length || 0}`);
        console.log(`🔑 Credentials: ${scanData.credentials?.length || 0}`);

        console.log(`\n📝 Generating professional PDF report...`);
        const generator = new ProfessionalReportGenerator(scanData, outputFile);
        await generator.generate();

        console.log(`\n✅ Report generated successfully: ${outputFile}\n`);
    } catch (error) {
        console.error('❌ Error generating report:', error.message);
        process.exit(1);
    }
}

main();
