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

    // ============ RECONNAISSANCE ============
    const recon = scanData.recon || {};
    if (Object.keys(recon).length > 0) {
        doc.addPage();
        doc.rect(50, 40, contentWidth, 3).fill(colors.accent);
        doc.fontSize(18).fillColor(colors.primary);
        safeText('RECONNAISSANCE', 50, 55);

        y = 95;

        // Target Information Box
        doc.roundedRect(50, y, contentWidth, 85, 3).fillAndStroke(colors.background, colors.border);
        doc.fontSize(10).fillColor(colors.primary).font('Helvetica-Bold');
        safeText('TARGET INFORMATION', 60, y + 10);
        doc.font('Helvetica');

        doc.fontSize(9).fillColor(colors.text);
        safeText(`Domain: ${scanData.target}`, 60, y + 28);

        const geo = recon.geolocation || {};
        if (geo.country) {
            safeText(`Location: ${geo.city || ''}, ${geo.region || ''}, ${geo.country || ''}`, 60, y + 42);
            safeText(`ISP: ${geo.isp || 'N/A'}`, 300, y + 42);
        }
        if (geo.asn) {
            safeText(`ASN: ${geo.asn}`, 60, y + 56);
            safeText(`Organization: ${geo.org || 'N/A'}`, 300, y + 56);
        }
        if (geo.latitude && geo.longitude) {
            safeText(`Coordinates: ${geo.latitude}, ${geo.longitude}`, 60, y + 70);
        }

        y += 95;

        // IP Addresses
        const ips = recon.ip_addresses || [];
        if (ips.length > 0) {
            doc.roundedRect(50, y, contentWidth / 2 - 5, 20 + (ips.length * 18), 3).fillAndStroke(colors.background, colors.border);
            doc.fontSize(10).fillColor(colors.primary).font('Helvetica-Bold');
            safeText('IP ADDRESSES', 60, y + 8);
            doc.font('Helvetica').fontSize(8).fillColor(colors.text);

            let ipY = y + 25;
            ips.forEach(ip => {
                safeText(`${ip.type}: ${ip.ip}`, 60, ipY);
                if (ip.provider) {
                    doc.fillColor(colors.lightText);
                    safeText(`(${ip.provider})`, 220, ipY);
                    doc.fillColor(colors.text);
                }
                ipY += 18;
            });
        }

        // DNS Records (right column)
        const dns = recon.dns_records || [];
        if (dns.length > 0) {
            const dnsHeight = 20 + Math.min(dns.length, 5) * 18;
            doc.roundedRect(50 + contentWidth / 2 + 5, y, contentWidth / 2 - 5, dnsHeight, 3).fillAndStroke(colors.background, colors.border);
            doc.fontSize(10).fillColor(colors.primary).font('Helvetica-Bold');
            safeText('DNS RECORDS', 60 + contentWidth / 2, y + 8);
            doc.font('Helvetica').fontSize(8).fillColor(colors.text);

            let dnsY = y + 25;
            dns.slice(0, 5).forEach(rec => {
                safeText(`${rec.type}: ${(rec.value || '').substring(0, 35)}`, 60 + contentWidth / 2, dnsY);
                dnsY += 18;
            });
        }

        y += Math.max(20 + (ips.length * 18), 20 + Math.min(dns.length, 5) * 18) + 10;

        // Open Ports
        const ports = recon.open_ports || [];
        if (ports.length > 0) {
            doc.addPage();
            doc.rect(50, 40, contentWidth, 3).fill(colors.accent);
            doc.fontSize(18).fillColor(colors.primary);
            safeText('OPEN PORTS & SERVICES', 50, 55);

            y = 90;
            doc.roundedRect(50, y, contentWidth, 25, 2).fill(colors.primary);
            doc.fontSize(9).fillColor('#ffffff');
            safeText('PORT', 60, y + 8);
            safeText('PROTOCOL', 120, y + 8);
            safeText('SERVICE', 190, y + 8);
            safeText('VERSION', 300, y + 8);
            safeText('STATE', 450, y + 8);

            y += 28;
            ports.forEach((port, i) => {
                doc.roundedRect(50, y, contentWidth, 22, 0).fill(i % 2 === 0 ? '#ffffff' : colors.background);
                doc.fontSize(9).fillColor(colors.primary);
                safeText(port.port.toString(), 60, y + 6);
                doc.fillColor(colors.text);
                safeText(port.protocol || 'tcp', 120, y + 6);
                safeText(port.service || 'unknown', 190, y + 6);
                doc.fillColor(colors.lightText);
                safeText((port.version || '').substring(0, 25), 300, y + 6);

                const stateColor = port.state === 'open' ? colors.low : colors.critical;
                doc.roundedRect(445, y + 3, 45, 16, 8).fill(stateColor);
                doc.fontSize(7).fillColor('#ffffff');
                safeText(port.state || 'open', 445, y + 7, { width: 45, align: 'center' });

                y += 25;
            });
        }

        // WHOIS Information
        const whois = recon.whois || {};
        if (Object.keys(whois).length > 0) {
            y += 15;
            if (y > pageHeight - 200) {
                doc.addPage();
                y = 50;
            }

            doc.roundedRect(50, y, contentWidth, 110, 3).fillAndStroke(colors.background, colors.border);
            doc.fontSize(10).fillColor(colors.primary).font('Helvetica-Bold');
            safeText('WHOIS INFORMATION', 60, y + 10);
            doc.font('Helvetica').fontSize(9).fillColor(colors.text);

            safeText(`Domain: ${whois.domain || scanData.target}`, 60, y + 30);
            safeText(`Registrar: ${whois.registrar || 'N/A'}`, 300, y + 30);
            safeText(`Created: ${whois.created || 'N/A'}`, 60, y + 48);
            safeText(`Expires: ${whois.expires || 'N/A'}`, 200, y + 48);
            safeText(`Updated: ${whois.updated || 'N/A'}`, 340, y + 48);

            if (whois.nameservers) {
                safeText(`Nameservers: ${whois.nameservers.join(', ')}`, 60, y + 66);
            }
            if (whois.registrant) {
                safeText(`Registrant: ${whois.registrant.organization || 'N/A'}`, 60, y + 84);
                safeText(`Country: ${whois.registrant.country || 'N/A'}`, 400, y + 84);
            }

            y += 120;
        }

        // SSL Certificate
        const ssl = recon.ssl_certificate || {};
        if (Object.keys(ssl).length > 0) {
            if (y > pageHeight - 150) {
                doc.addPage();
                y = 50;
            }

            doc.roundedRect(50, y, contentWidth, 95, 3).fillAndStroke(colors.background, colors.border);
            doc.fontSize(10).fillColor(colors.primary).font('Helvetica-Bold');
            safeText('SSL/TLS CERTIFICATE', 60, y + 10);
            doc.font('Helvetica').fontSize(9).fillColor(colors.text);

            safeText(`Subject: ${ssl.subject || 'N/A'}`, 60, y + 30);
            safeText(`Issuer: ${ssl.issuer || 'N/A'}`, 300, y + 30);
            safeText(`Valid From: ${ssl.valid_from || 'N/A'}`, 60, y + 48);
            safeText(`Valid To: ${ssl.valid_to || 'N/A'}`, 200, y + 48);
            safeText(`Protocol: ${ssl.protocol || 'N/A'}`, 340, y + 48);
            safeText(`Cipher: ${ssl.cipher_suite || 'N/A'}`, 60, y + 66);
            if (ssl.san) {
                safeText(`SANs: ${ssl.san.slice(0, 3).join(', ')}`, 60, y + 82);
            }

            y += 105;
        }

        // Technologies Detected
        const techs = recon.technologies || [];
        if (techs.length > 0) {
            if (y > pageHeight - 150) {
                doc.addPage();
                y = 50;
            }

            doc.roundedRect(50, y, contentWidth, 25 + Math.ceil(techs.length / 3) * 25, 3).fillAndStroke(colors.background, colors.border);
            doc.fontSize(10).fillColor(colors.primary).font('Helvetica-Bold');
            safeText('TECHNOLOGIES DETECTED', 60, y + 10);
            doc.font('Helvetica').fontSize(8);

            let techY = y + 30;
            let techCol = 0;
            techs.forEach((tech, i) => {
                const x = 60 + (techCol * (contentWidth / 3));
                doc.fillColor(colors.text);
                safeText(`${tech.name}${tech.version ? ' ' + tech.version : ''}`, x, techY);
                doc.fillColor(colors.lightText);
                safeText(`(${tech.category || 'Other'})`, x + 100, techY);

                techCol++;
                if (techCol >= 3) {
                    techCol = 0;
                    techY += 25;
                }
            });

            y += 35 + Math.ceil(techs.length / 3) * 25;
        }

        // Subdomains
        const subs = recon.subdomains || [];
        if (subs.length > 0) {
            if (y > pageHeight - 120) {
                doc.addPage();
                y = 50;
            }

            doc.roundedRect(50, y, contentWidth, 25 + subs.length * 20, 3).fillAndStroke(colors.background, colors.border);
            doc.fontSize(10).fillColor(colors.primary).font('Helvetica-Bold');
            safeText('SUBDOMAINS DISCOVERED', 60, y + 10);
            doc.font('Helvetica').fontSize(9);

            let subY = y + 30;
            subs.forEach(sub => {
                doc.fillColor(colors.text);
                safeText(sub.name, 60, subY);
                doc.fillColor(colors.lightText);
                safeText(sub.ip || 'N/A', 280, subY);
                subY += 20;
            });
        }
    }

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
