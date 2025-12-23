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
    
    // ============ CVE INTELLIGENCE ============
    const cves = scanData.cves || [];
    if (cves.length > 0) {
        doc.addPage();
        doc.rect(50, 40, contentWidth, 3).fill(colors.critical);
        doc.fontSize(18).fillColor(colors.primary);
        safeText('CVE INTELLIGENCE', 50, 55);

        doc.fontSize(9).fillColor(colors.lightText);
        safeText('Known vulnerabilities identified from NVD and Exploit-DB databases', 50, 78);

        y = 100;
        cves.forEach((cve, i) => {
            if (y > pageHeight - 150) {
                doc.addPage();
                y = 50;
            }

            // CVE card
            const cardHeight = 110;
            doc.roundedRect(50, y, contentWidth, cardHeight, 5).fillAndStroke('#ffffff', colors.border);

            // Severity badge
            const sevColor = cve.severity?.toLowerCase() === 'critical' ? colors.critical :
                            cve.severity?.toLowerCase() === 'high' ? colors.high :
                            cve.severity?.toLowerCase() === 'medium' ? colors.medium : colors.low;
            doc.roundedRect(55, y + 8, 80, 20, 10).fill(sevColor);
            doc.fontSize(9).fillColor('#ffffff');
            safeText((cve.severity || 'UNKNOWN').toUpperCase(), 55, y + 13, { width: 80, align: 'center' });

            // CVE ID and CVSS
            doc.fontSize(14).fillColor(colors.primary);
            safeText(cve.id || 'Unknown CVE', 145, y + 10);

            doc.fontSize(11).fillColor(sevColor);
            safeText(`CVSS: ${cve.cvss_score?.toFixed(1) || 'N/A'}`, pageWidth - 130, y + 10);

            // Title
            doc.fontSize(10).fillColor(colors.text);
            safeText((cve.title || 'Untitled').substring(0, 70), 55, y + 35);

            // Description (truncated)
            doc.fontSize(8).fillColor(colors.lightText);
            const desc = (cve.description || 'No description available').substring(0, 200);
            doc.text(desc, 55, y + 52, { width: contentWidth - 20, height: 30, lineBreak: true, ellipsis: true });

            // Remediation
            doc.fontSize(8).fillColor(colors.primary);
            safeText('Remediation:', 55, y + 85);
            doc.fillColor(colors.text);
            safeText((cve.remediation || 'Apply vendor patches').substring(0, 80), 115, y + 85);

            // Patch URLs (if any)
            if (cve.patch_urls && cve.patch_urls.length > 0) {
                doc.fontSize(7).fillColor(colors.accent);
                safeText(`Patch: ${cve.patch_urls[0].substring(0, 60)}`, 55, y + 98);
            }

            y += cardHeight + 10;
        });
    }

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
    
    // ============ CREDENTIALS - FEAR FACTOR SECTION ============
    if (stats.credentials > 0) {
        doc.addPage();

        // Red danger header
        doc.rect(0, 0, pageWidth, 120).fill(colors.critical);
        doc.fontSize(12).fillColor('#ffffff');
        safeText('⚠ SECURITY BREACH ⚠', 50, 30);
        doc.fontSize(28).fillColor('#ffffff');
        safeText('COMPROMISED CREDENTIALS', 50, 50);
        doc.fontSize(11).fillColor('#ffcccc');
        safeText('The following credentials were extracted during this penetration test.', 50, 90);
        safeText('An attacker with this access can fully compromise your systems.', 50, 105);

        y = 140;

        // Scary warning box
        doc.roundedRect(50, y, contentWidth, 60, 5).fillAndStroke('#2d0a0a', colors.critical);
        doc.fontSize(14).fillColor(colors.critical);
        safeText('IMMEDIATE ACTION REQUIRED', 60, y + 12);
        doc.fontSize(9).fillColor('#ff6666');
        safeText('• All passwords shown below must be changed IMMEDIATELY', 60, y + 30);
        safeText('• Any SSH keys displayed are now considered PUBLIC - regenerate them', 60, y + 42);
        safeText('• Audit all systems these credentials may have accessed', 60, y + 54);

        y += 75;

        const creds = scanData.credentials || [];

        // Separate SSH keys from regular credentials
        const sshKeys = creds.filter(c => c.service === 'ssh_key_extracted' || (c.password && c.password.includes('BEGIN')));
        const regularCreds = creds.filter(c => c.service !== 'ssh_key_extracted' && !(c.password && c.password.includes('BEGIN')));
        const hashCreds = creds.filter(c => c.source === 'sqli_dump' || c.source === 'shadow_hash' || (c.hash && c.hash.length > 0));

        // Regular credentials section
        if (regularCreds.length > 0) {
            doc.roundedRect(50, y, contentWidth, 25, 2).fill('#1a1a1a');
            doc.fontSize(10).fillColor(colors.critical);
            safeText('PLAINTEXT PASSWORDS EXTRACTED', 60, y + 8);
            y += 30;

            doc.roundedRect(50, y, contentWidth, 22, 2).fill(colors.primary);
            doc.fontSize(8).fillColor('#ffffff');
            safeText('USERNAME', 60, y + 7);
            safeText('PASSWORD', 180, y + 7);
            safeText('SOURCE', 380, y + 7);
            y += 25;

            regularCreds.forEach((cred, i) => {
                if (y > pageHeight - 50) {
                    doc.addPage();
                    y = 50;
                }

                doc.roundedRect(50, y, contentWidth, 26, 0).fill(i % 2 === 0 ? '#fff5f5' : '#ffe5e5');
                doc.rect(50, y, 4, 26).fill(colors.critical);

                doc.fontSize(10).fillColor('#1a1a1a').font('Helvetica-Bold');
                safeText(cred.username || 'N/A', 62, y + 8);

                doc.font('Courier').fillColor(colors.critical);
                // Show full password - this is the fear factor
                const pass = cred.password || cred.hash || 'N/A';
                safeText(pass.substring(0, 35), 180, y + 8);

                doc.font('Helvetica').fontSize(8).fillColor(colors.lightText);
                safeText(cred.source || cred.service || '', 380, y + 8);

                y += 28;
            });

            y += 15;
        }

        // Password hashes section
        const pureHashes = hashCreds.filter(c => !regularCreds.includes(c));
        if (pureHashes.length > 0) {
            if (y > pageHeight - 100) {
                doc.addPage();
                y = 50;
            }

            doc.roundedRect(50, y, contentWidth, 25, 2).fill('#1a1a1a');
            doc.fontSize(10).fillColor('#ff9900');
            safeText('PASSWORD HASHES (Can be cracked offline)', 60, y + 8);
            y += 30;

            pureHashes.forEach((cred, i) => {
                if (y > pageHeight - 60) {
                    doc.addPage();
                    y = 50;
                }

                doc.roundedRect(50, y, contentWidth, 40, 3).fillAndStroke('#1a1a1a', '#ff9900');
                doc.fontSize(9).fillColor('#ff9900');
                safeText(`User: ${cred.username || 'extracted'}`, 60, y + 8);
                doc.fontSize(8).fillColor('#cccccc');
                safeText(`Source: ${cred.source || 'database'}`, 300, y + 8);

                doc.font('Courier').fontSize(7).fillColor('#ffcc00');
                const hashValue = cred.hash || cred.password || '';
                safeText(hashValue.substring(0, 70), 60, y + 24);
                doc.font('Helvetica');

                y += 45;
            });

            y += 15;
        }

        // SSH PRIVATE KEYS - Maximum fear factor
        if (sshKeys.length > 0) {
            doc.addPage();

            // Full page red warning for SSH keys
            doc.rect(0, 0, pageWidth, 80).fill('#8b0000');
            doc.fontSize(10).fillColor('#ffffff');
            safeText('⚠ CRITICAL SECURITY BREACH ⚠', 50, 20);
            doc.fontSize(22).fillColor('#ffffff');
            safeText('SSH PRIVATE KEYS EXTRACTED', 50, 40);
            doc.fontSize(9).fillColor('#ffaaaa');
            safeText('These keys provide COMPLETE SERVER ACCESS without passwords', 50, 65);

            y = 100;

            doc.roundedRect(50, y, contentWidth, 50, 5).fillAndStroke('#2d0a0a', '#ff0000');
            doc.fontSize(11).fillColor('#ff4444');
            safeText('THESE PRIVATE KEYS MUST BE REVOKED IMMEDIATELY', 60, y + 10);
            doc.fontSize(8).fillColor('#ff8888');
            safeText('1. Remove corresponding public keys from all ~/.ssh/authorized_keys files', 60, y + 25);
            safeText('2. Generate new key pairs for all affected users', 60, y + 36);
            safeText('3. Audit all systems these keys may have accessed', 60, y + 47);

            y += 65;

            sshKeys.forEach((key, i) => {
                if (y > pageHeight - 250) {
                    doc.addPage();
                    y = 50;
                }

                const keyContent = key.password || '';
                const keyLines = keyContent.split('\n');
                const boxHeight = Math.min(keyLines.length * 10 + 30, 200);

                doc.roundedRect(50, y, contentWidth, boxHeight, 3).fillAndStroke('#0a0a0a', colors.critical);

                doc.fontSize(9).fillColor(colors.critical);
                safeText(`SSH PRIVATE KEY #${i + 1}`, 60, y + 8);
                doc.fontSize(7).fillColor('#888888');
                safeText(`Target: ${key.target || key.source || 'unknown'}`, 250, y + 8);

                // Display the actual key content - THIS IS THE FEAR FACTOR
                doc.font('Courier').fontSize(6).fillColor('#00ff00');
                let keyY = y + 22;
                keyLines.slice(0, 15).forEach(line => {
                    safeText(line.substring(0, 85), 60, keyY);
                    keyY += 10;
                });
                if (keyLines.length > 15) {
                    doc.fillColor('#888888');
                    safeText(`... ${keyLines.length - 15} more lines ...`, 60, keyY);
                }
                doc.font('Helvetica');

                y += boxHeight + 15;
            });
        }

        // Final scary summary
        if (y > pageHeight - 100) {
            doc.addPage();
            y = 50;
        }

        doc.roundedRect(50, y, contentWidth, 70, 5).fillAndStroke('#1a0000', colors.critical);
        doc.fontSize(12).fillColor(colors.critical);
        safeText('EXPOSURE SUMMARY', 60, y + 12);
        doc.fontSize(10).fillColor('#ff6666');
        safeText(`Total Credentials Exposed: ${creds.length}`, 60, y + 30);
        safeText(`Plaintext Passwords: ${regularCreds.length}`, 60, y + 44);
        safeText(`Password Hashes: ${pureHashes.length}`, 250, y + 44);
        safeText(`SSH Private Keys: ${sshKeys.length}`, 400, y + 44);
        doc.fontSize(8).fillColor('#cc4444');
        safeText('With these credentials, an attacker has the same access as your legitimate users.', 60, y + 58);
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
