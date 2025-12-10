#!/usr/bin/env node
/**
 * PentestAI Simple PDF Report Generator
 * No auto page breaks - explicit control only
 */

const PDFDocument = require('pdfkit');
const fs = require('fs');

const colors = {
    primary: '#0f172a',
    accent: '#3b82f6',
    critical: '#dc2626',
    high: '#ea580c',
    medium: '#ca8a04',
    low: '#16a34a',
    info: '#0891b2',
    text: '#1e293b',
    lightText: '#64748b',
    background: '#f8fafc',
    border: '#e2e8f0',
};

function generateReport(scanData, outputPath) {
    const doc = new PDFDocument({
        size: 'A4',
        margins: { top: 50, bottom: 50, left: 50, right: 50 },
        bufferPages: true
    });
    
    const stream = fs.createWriteStream(outputPath);
    doc.pipe(stream);
    
    const pageWidth = doc.page.width;
    const pageHeight = doc.page.height;
    const contentWidth = pageWidth - 100;
    
    // Helper to add text without auto page break
    const safeText = (text, x, y, options = {}) => {
        doc.text(text, x, y, { ...options, lineBreak: false });
    };
    
    // ============ COVER PAGE ============
    doc.rect(0, 0, pageWidth, pageHeight).fill(colors.primary);
    doc.rect(0, 0, pageWidth, 8).fill(colors.accent);
    
    doc.fontSize(14).fillColor(colors.accent);
    safeText('PENTESTAI', 50, 60);
    
    doc.fontSize(42).fillColor('#ffffff');
    safeText('PENETRATION', 50, 200);
    safeText('TEST REPORT', 50, 250);
    
    doc.fontSize(18).fillColor('#ffffff');
    safeText(`Target: ${scanData.target}`, 50, 350);
    safeText(`Date: ${scanData.date}`, 50, 380);
    
    const stats = getStats(scanData);
    doc.fontSize(14);
    safeText(`Tests: ${stats.testsRun}`, 50, 450);
    safeText(`Vulnerabilities: ${stats.totalVulns}`, 50, 475);
    safeText(`Critical: ${stats.critical}`, 50, 500);
    safeText(`High: ${stats.high}`, 50, 525);
    safeText(`Credentials Found: ${stats.credentials}`, 50, 550);
    
    // ============ EXECUTIVE SUMMARY ============
    doc.addPage();
    doc.rect(50, 40, contentWidth, 3).fill(colors.accent);
    doc.fontSize(18).fillColor(colors.primary);
    safeText('EXECUTIVE SUMMARY', 50, 55);
    
    let y = 100;
    doc.fontSize(11).fillColor(colors.text);
    const summaryLines = [
        `This penetration test was conducted against ${scanData.target}.`,
        `A total of ${stats.testsRun} security tests were performed.`,
        `${stats.totalVulns} vulnerabilities were identified.`,
        `${stats.credentials} credentials were extracted.`,
        '',
        `Overall Risk: ${stats.critical > 0 ? 'CRITICAL' : stats.high > 0 ? 'HIGH' : 'MEDIUM'}`
    ];
    summaryLines.forEach(line => {
        safeText(line, 50, y);
        y += 20;
    });
    
    // ============ VULNERABILITIES ============
    doc.addPage();
    doc.rect(50, 40, contentWidth, 3).fill(colors.accent);
    doc.fontSize(18).fillColor(colors.primary);
    safeText('VULNERABILITIES', 50, 55);
    
    y = 100;
    const vulns = scanData.vulnerabilities || [];
    vulns.forEach((vuln, i) => {
        if (y > pageHeight - 100) {
            doc.addPage();
            y = 50;
        }
        
        const sevColor = colors[vuln.severity?.toLowerCase()] || colors.info;
        doc.roundedRect(50, y, contentWidth, 50, 3).fillAndStroke(colors.background, colors.border);
        doc.roundedRect(55, y + 5, 60, 16, 8).fill(sevColor);
        doc.fontSize(8).fillColor('#ffffff');
        safeText((vuln.severity || 'INFO').toUpperCase(), 55, y + 9, { width: 60, align: 'center' });
        
        doc.fontSize(10).fillColor(colors.primary);
        safeText((vuln.type || 'Unknown').substring(0, 50), 125, y + 8);
        
        doc.fontSize(8).fillColor(colors.lightText);
        safeText((vuln.target || '').substring(0, 60), 125, y + 22);
        safeText((vuln.description || '').substring(0, 80) + '...', 55, y + 36);
        
        y += 58;
    });
    
    // ============ TEST RESULTS ============
    doc.addPage();
    doc.rect(50, 40, contentWidth, 3).fill(colors.accent);
    doc.fontSize(18).fillColor(colors.primary);
    safeText('TEST RESULTS', 50, 55);
    
    y = 100;
    const tests = scanData.tests || [];
    tests.forEach((test, i) => {
        if (y > pageHeight - 60) {
            doc.addPage();
            y = 50;
        }
        
        const statusColor = test.success ? colors.low : colors.critical;
        doc.roundedRect(50, y, contentWidth, 30, 2).fillAndStroke('#ffffff', colors.border);
        doc.rect(50, y, 4, 30).fill(statusColor);
        
        doc.fontSize(9).fillColor(colors.primary);
        safeText((test.name || test.action || 'Test').substring(0, 30), 62, y + 8);
        
        doc.fontSize(8).fillColor(colors.lightText);
        safeText((test.target || '').substring(0, 40), 200, y + 8);
        
        doc.roundedRect(pageWidth - 100, y + 7, 40, 16, 8).fill(statusColor);
        doc.fontSize(7).fillColor('#ffffff');
        safeText(test.success ? 'PASS' : 'FAIL', pageWidth - 100, y + 11, { width: 40, align: 'center' });
        
        y += 35;
    });
    
    // ============ CREDENTIALS ============
    if (stats.credentials > 0) {
        doc.addPage();
        doc.rect(50, 40, contentWidth, 3).fill(colors.accent);
        doc.fontSize(18).fillColor(colors.primary);
        safeText('EXTRACTED CREDENTIALS', 50, 55);
        
        doc.roundedRect(50, 85, contentWidth, 40, 3).fillAndStroke('#fef2f2', colors.critical);
        doc.fontSize(10).fillColor(colors.critical);
        safeText('WARNING: These accounts are compromised. Reset passwords immediately.', 60, 100);
        
        y = 140;
        doc.roundedRect(50, y, contentWidth, 25, 2).fill(colors.primary);
        doc.fontSize(9).fillColor('#ffffff');
        safeText('USERNAME', 60, y + 8);
        safeText('TYPE', 200, y + 8);
        safeText('SOURCE', 300, y + 8);
        
        y += 30;
        const creds = scanData.credentials || [];
        creds.forEach((cred, i) => {
            if (y > pageHeight - 50) {
                doc.addPage();
                y = 50;
            }
            
            doc.roundedRect(50, y, contentWidth, 22, 0).fill(i % 2 === 0 ? '#ffffff' : colors.background);
            doc.fontSize(9).fillColor(colors.primary);
            safeText((cred.username || 'N/A').substring(0, 20), 60, y + 6);
            doc.fillColor(colors.lightText);
            safeText(cred.type || 'password', 200, y + 6);
            safeText((cred.source || '').substring(0, 30), 300, y + 6);
            
            y += 25;
        });
    }
    
    // ============ RECOMMENDATIONS ============
    doc.addPage();
    doc.rect(50, 40, contentWidth, 3).fill(colors.accent);
    doc.fontSize(18).fillColor(colors.primary);
    safeText('RECOMMENDATIONS', 50, 55);
    
    y = 100;
    const recs = [
        { priority: 'Critical', title: 'Reset compromised passwords immediately' },
        { priority: 'Critical', title: 'Patch critical vulnerabilities within 24 hours' },
        { priority: 'High', title: 'Fix high severity issues within 1 week' },
        { priority: 'Medium', title: 'Implement security headers' },
        { priority: 'Low', title: 'Schedule regular security assessments' }
    ];
    
    recs.forEach((rec, i) => {
        const prioColor = colors[rec.priority.toLowerCase()] || colors.info;
        doc.roundedRect(50, y, contentWidth, 35, 3).fillAndStroke('#ffffff', colors.border);
        doc.roundedRect(55, y + 8, 55, 16, 8).fill(prioColor);
        doc.fontSize(7).fillColor('#ffffff');
        safeText(rec.priority.toUpperCase(), 55, y + 12, { width: 55, align: 'center' });
        doc.fontSize(10).fillColor(colors.primary);
        safeText(rec.title, 120, y + 12);
        y += 42;
    });
    
    // Add page numbers
    const pages = doc.bufferedPageRange();
    for (let i = 0; i < pages.count; i++) {
        doc.switchToPage(i);
        if (i > 0) { // Skip cover
            doc.fontSize(8).fillColor(colors.lightText);
            safeText(`Page ${i} of ${pages.count - 1}`, pageWidth - 100, pageHeight - 30);
            safeText('CONFIDENTIAL', 50, pageHeight - 30);
        }
    }
    
    doc.end();
    
    return new Promise((resolve, reject) => {
        stream.on('finish', () => resolve(outputPath));
        stream.on('error', reject);
    });
}

function getStats(data) {
    const vulns = data.vulnerabilities || [];
    const tests = data.tests || [];
    const creds = data.credentials || [];
    
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

// Main
async function main() {
    const args = process.argv.slice(2);
    if (args.length < 1) {
        console.log('Usage: node generate-report-simple.js <scan.json> [output.pdf]');
        process.exit(1);
    }
    
    const inputFile = args[0];
    const outputFile = args[1] || inputFile.replace('.json', '-report.pdf');
    
    try {
        console.log(`Reading: ${inputFile}`);
        const scanData = JSON.parse(fs.readFileSync(inputFile, 'utf8'));
        console.log(`Generating report...`);
        await generateReport(scanData, outputFile);
        console.log(`Done: ${outputFile}`);
    } catch (err) {
        console.error('Error:', err.message);
        process.exit(1);
    }
}

main();
