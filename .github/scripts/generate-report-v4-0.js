// Generate Report v4.0 - Added support for Apex projects (PL/SQL, JavaScript, CSS)
const fs = require('fs');
const path = require('path');
const { mapRuleSeverity, getRuleDescription, getRuleRecommendation } = require('./vulnerability');
const { parseZpaResults, mapZpaSeverity, parsePlsqlPatterns } = require('./zpa-parser');
const { getPlsqlRuleInfo } = require('./metadata/plsql-metadata');

function normalizeSeverity(severity) {
	if (!severity) return 'low';
	const s = severity.toLowerCase();
	if (s === 'moderate') return 'medium';
	if (s === 'warning') return 'medium';
	if (s === 'note') return 'low';
	return ['critical', 'high', 'medium', 'low', 'info'].includes(s) ? s : 'info';
}

function getSeverityOrder(severity) {
	const severityOrder = {
		critical: 0,
		high: 1,
		medium: 2,
		moderate: 2,
		low: 3,
		info: 4,
	};

	const normalizedSeverity = (severity || '').toLowerCase();
	return severityOrder[normalizedSeverity] !== undefined ? severityOrder[normalizedSeverity] : 999;
}

function getSeverityColor(severity) {
	const severityColors = {
		critical: '#d32f2f',
		high: '#f57c00',
		medium: '#fbc02d',
		low: '#388e3c',
		info: '#0288d1'
	};
	return severityColors[severity.toLowerCase()] || '#0288d1';
}

function createSeverityBadge(severity, displayText) {
	const bgColor = getSeverityColor(severity);
	return `<span style="display: inline-block; padding: 4px 10px; border-radius: 3px; font-weight: bold; color: white; background-color: ${bgColor}; min-width: 90px; text-align: center;">${displayText || severity.toUpperCase()}</span>`;
}

function createSeveritySummary(criticalCount, highCount, mediumCount, lowCount, infoCount) {
	return `
    <table width="100%" cellpadding="8" cellspacing="0" style="margin: 15px 0; background-color: #f8f9fa; border-radius: 6px;">
      <tr>
        <td width="20%" align="center" style="padding: 10px; background-color: #d32f2f; color: white; border-radius: 4px;">
          <div style="font-size: 20px; font-weight: bold; margin-bottom: 4px;">${criticalCount}</div>
          <div style="font-size: 14px;">Critical</div>
        </td>
        <td width="20%" align="center" style="padding: 10px; background-color: #f57c00; color: white; border-radius: 4px;">
          <div style="font-size: 20px; font-weight: bold; margin-bottom: 4px;">${highCount}</div>
          <div style="font-size: 14px;">High</div>
        </td>
        <td width="20%" align="center" style="padding: 10px; background-color: #fbc02d; color: white; border-radius: 4px;">
          <div style="font-size: 20px; font-weight: bold; margin-bottom: 4px;">${mediumCount}</div>
          <div style="font-size: 14px;">Medium</div>
        </td>
        <td width="20%" align="center" style="padding: 10px; background-color: #388e3c; color: white; border-radius: 4px;">
          <div style="font-size: 20px; font-weight: bold; margin-bottom: 4px;">${lowCount}</div>
          <div style="font-size: 14px;">Low</div>
        </td>
        <td width="20%" align="center" style="padding: 10px; background-color: #0288d1; color: white; border-radius: 4px;">
          <div style="font-size: 20px; font-weight: bold; margin-bottom: 4px;">${infoCount}</div>
          <div style="font-size: 14px;">Info</div>
        </td>
      </tr>
    </table>
  `;
}

const generateReport = () => {
	const repoName = process.argv[2] || 'Security Scan Report';
	const projectType = process.argv[3] || 'Full-Stack'; // New: project type parameter
	const isApex = projectType === 'Apex';

	console.log(`Generating report for ${repoName} (${projectType})...`);

	// Initialize global issue counters
	let totalIssues = {
		critical: 0,
		high: 0,
		medium: 0,
		low: 0,
		info: 0,
	};

	// Object to store summaries for each directory
	let directorySummaries = {};

	let reportContent = `
    <html>
      <head>
        <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
        <style>
          body {
            font-family: Arial, sans-serif;
            margin: 20px;
          }
          table {
            border-collapse: collapse;
            width: 100%;
            margin: 20px 0;
          }
          th, td {
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
          }
          th {
            background-color: #f5f5f5;
            font-weight: bold;
          }
          h2 {
            color: #2c3e50;
          }
          h3 {
            color: #34495e;
            border-bottom: 2px solid #eee;
            padding-bottom: 8px;
          }
        </style>
      </head>
      <body style="font-family: Arial, sans-serif; margin: 20px;">
        <h1 style="color: #2c3e50;">Security Scan Report - ${repoName}</h1>
  `;

	console.log('Starting report generation...');

	const walkDir = (dir) => {
		let results = [];
		const list = fs.readdirSync(dir);
		list.forEach((file) => {
			const filePath = path.join(dir, file);
			const stat = fs.statSync(filePath);
			if (stat && stat.isDirectory()) {
				results = results.concat(walkDir(filePath));
			} else {
				results.push(filePath);
			}
		});
		return results;
	};

	console.log('Searching for files in all-reports directory...');
	const files = walkDir('all-reports');
	console.log('Found files:', files);

	// Find unique directories from file paths
	const directories = new Set();
	files.forEach((file) => {
		// Updated to include ZPA and PL/SQL pattern files for Apex projects
		if (file.includes('npm-audit-') || file.includes('trivy-') || file.includes('zpa-') || file.includes('plsql-patterns-')) {
			const dirMatch = file.match(/(npm-audit-|trivy-|zpa-|plsql-patterns-)(.+?)\./);
			if (dirMatch && dirMatch[2]) {
				directories.add(dirMatch[2]);
			}
		}
	});

	console.log('Detected directories:', Array.from(directories));

	// Initialize summary for each directory
	directories.forEach((directory) => {
		directorySummaries[directory] = {
			codeql: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
			npm: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
			trivy: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
			// Add ZPA and pattern summaries for Apex projects
			...(isApex && {
				zpa: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
				plsqlPatterns: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
			})
		};
	});

	// First pass: collect all issues for summary
	directories.forEach((directory) => {
		// Process CodeQL results for summary
		const codeqlPath = `all-reports/codeql-results-${directory}`;
		if (fs.existsSync(codeqlPath)) {
			const codeqlFiles = fs
				.readdirSync(codeqlPath)
				.filter((f) => f.endsWith('.sarif'))
				.map((f) => path.join(codeqlPath, f));

			for (const sarifFile of codeqlFiles) {
				try {
					const content = fs.readFileSync(sarifFile, 'utf8');
					const results = JSON.parse(content);

					if (results && results.runs) {
						results.runs.forEach((run) => {
							if (run.results && run.results.length > 0) {
								run.results.forEach((finding) => {
									const ruleSeverity = mapRuleSeverity(finding.ruleId);

									if (ruleSeverity === 'critical') {
										directorySummaries[directory].codeql.critical++;
										totalIssues.critical++;
									} else if (ruleSeverity === 'high') {
										directorySummaries[directory].codeql.high++;
										totalIssues.high++;
									} else if (ruleSeverity === 'medium' || ruleSeverity === 'warning' || ruleSeverity === 'moderate') {
										directorySummaries[directory].codeql.medium++;
										totalIssues.medium++;
									} else if (ruleSeverity === 'low' || ruleSeverity === 'note') {
										directorySummaries[directory].codeql.low++;
										totalIssues.low++;
									} else {
										directorySummaries[directory].codeql.info++;
										totalIssues.info++;
									}
								});
							}
						});
					}
				} catch (error) {
					console.error(`Error pre-processing SARIF file ${sarifFile}:`, error);
				}
			}
		}

		// Process npm audit results for summary
		const npmAuditFiles = files.filter((f) => f.includes(`npm-audit-${directory}`));
		if (npmAuditFiles.length > 0) {
			try {
				const results = JSON.parse(fs.readFileSync(npmAuditFiles[0], 'utf8'));

				if (results.vulnerabilities) {
					const vulns = Object.entries(results.vulnerabilities);

					vulns.forEach(([pkg, vuln]) => {
						if (vuln.severity && vuln.severity.toLowerCase() === 'moderate') {
							vuln.displaySeverity = 'Medium';
						} else {
							vuln.displaySeverity = vuln.severity;
						}

						const severity = (vuln.severity || '').toLowerCase();
						if (severity === 'critical') {
							directorySummaries[directory].npm.critical++;
							totalIssues.critical++;
						} else if (severity === 'high') {
							directorySummaries[directory].npm.high++;
							totalIssues.high++;
						} else if (severity === 'moderate' || severity === 'medium') {
							directorySummaries[directory].npm.medium++;
							totalIssues.medium++;
						} else if (severity === 'low') {
							directorySummaries[directory].npm.low++;
							totalIssues.low++;
						} else {
							directorySummaries[directory].npm.info++;
							totalIssues.info++;
						}
					});
				}
			} catch (error) {
				console.error(`Error pre-processing npm audit for ${directory}:`, error);
			}
		}

		// Process Trivy results for summary
		const trivyFiles = files.filter((f) => f.includes(`trivy-${directory}`));
		if (trivyFiles.length > 0) {
			try {
				const results = JSON.parse(fs.readFileSync(trivyFiles[0], 'utf8'));

				if (results.Results && Array.isArray(results.Results)) {
					const vulns = results.Results.flatMap((r) => r.Vulnerabilities || []);

					vulns.forEach((vuln) => {
						if (vuln.Severity && vuln.Severity.toLowerCase() === 'medium') {
							vuln.DisplaySeverity = 'Medium';
						} else {
							vuln.DisplaySeverity = vuln.Severity;
						}

						const severity = (vuln.Severity || '').toLowerCase();
						if (severity === 'critical') {
							directorySummaries[directory].trivy.critical++;
							totalIssues.critical++;
						} else if (severity === 'high') {
							directorySummaries[directory].trivy.high++;
							totalIssues.high++;
						} else if (severity === 'medium') {
							directorySummaries[directory].trivy.medium++;
							totalIssues.medium++;
						} else if (severity === 'low') {
							directorySummaries[directory].trivy.low++;
							totalIssues.low++;
						} else {
							directorySummaries[directory].trivy.info++;
							totalIssues.info++;
						}
					});
				}
			} catch (error) {
				console.error(`Error pre-processing Trivy for ${directory}:`, error);
			}
		}

		// ===== APEX PROJECT SCANNING =====
		if (isApex) {
			// Process ZPA results for summary (Apex only)
			const zpaFiles = files.filter((f) => f.includes(`zpa-${directory}`));
			if (zpaFiles.length > 0) {
				try {
					const content = fs.readFileSync(zpaFiles[0], 'utf8');
					const issues = parseZpaResults(content);

					issues.forEach((issue) => {
						const severity = mapZpaSeverity(issue.severity);
						if (directorySummaries[directory].zpa[severity] !== undefined) {
							directorySummaries[directory].zpa[severity]++;
							totalIssues[severity]++;
						}
					});

					console.log(`Processed ${issues.length} ZPA issues for ${directory}`);
				} catch (error) {
					console.error(`Error pre-processing ZPA for ${directory}:`, error);
				}
			}

			// Process PL/SQL pattern detection results (Apex only)
			const patternFiles = files.filter((f) => f.includes(`plsql-patterns-${directory}`));
			if (patternFiles.length > 0) {
				try {
					const content = fs.readFileSync(patternFiles[0], 'utf8');
					const patterns = parsePlsqlPatterns(content);

					patterns.forEach((pattern) => {
						const severity = pattern.severity || 'info';
						if (directorySummaries[directory].plsqlPatterns[severity] !== undefined) {
							directorySummaries[directory].plsqlPatterns[severity]++;
							totalIssues[severity]++;
						}
					});

					console.log(`Processed ${patterns.length} PL/SQL patterns for ${directory}`);
				} catch (error) {
					console.error(`Error pre-processing PL/SQL patterns for ${directory}:`, error);
				}
			}
		}
	});

	// Add executive summary to the report
	reportContent += `
    <div style="background-color: #fff; padding: 20px; margin-bottom: 30px; border-radius: 8px; border: 2px solid #e0e0e0;">
      <h2 style="color: #2c3e50; margin-top: 0;">Summary</h2>
      ${createSeveritySummary(totalIssues.critical, totalIssues.high, totalIssues.medium, totalIssues.low, totalIssues.info)}
      <div style="margin-top: 15px;">
        <p style="margin: 10px 0;">Security scan for <strong>${repoName}</strong> found:</p>
        <ul style="margin: 10px 0; padding-left: 20px;">
          <li style="margin: 5px 0;"><strong>${totalIssues.critical}</strong> Critical issues</li>
          <li style="margin: 5px 0;"><strong>${totalIssues.high}</strong> High issues</li>
          <li style="margin: 5px 0;"><strong>${totalIssues.medium}</strong> Medium issues</li>
          <li style="margin: 5px 0;"><strong>${totalIssues.low}</strong> Low issues</li>
          <li style="margin: 5px 0;"><strong>${totalIssues.info}</strong> Info issues</li>
        </ul>
        ${totalIssues.critical + totalIssues.high > 0 ? `<p style="margin: 10px 0; color: #d32f2f;"><strong>Action Required:</strong> Please address Critical and High issues as soon as possible.</p>` : `<p style="margin: 10px 0; color: #388e3c;"><strong>No Critical or High issues found.</strong> Good job!</p>`}
      </div>
    </div>
  `;

	// Second pass: generate detailed report for each directory
	directories.forEach((directory) => {
		reportContent += `
      <div style="margin-top: 40px; padding: 20px; border: 1px solid #ddd; border-radius: 8px; background-color: #fafafa;">
        <h2 style="color: #2c3e50; margin-top: 0;">Directory: ${directory}</h2>
    `;

		// Find SARIF files in the directory-specific results folder
		const codeqlPath = `all-reports/codeql-results-${directory}`;
		console.log(`Looking for SARIF files in: ${codeqlPath}`);

		let codeqlFiles = [];
		if (fs.existsSync(codeqlPath)) {
			codeqlFiles = fs
				.readdirSync(codeqlPath)
				.filter((f) => f.endsWith('.sarif'))
				.map((f) => path.join(codeqlPath, f));
		}

		if (codeqlFiles.length > 0) {
			console.log(`Found CodeQL files for ${directory}:`, codeqlFiles);
			try {
				reportContent += `<div style="margin-top: 30px; background: #fff; padding: 20px; border-radius: 8px; border: 1px solid #e0e0e0;"><h3 style="color: #34495e; border-bottom: 2px solid #eee; padding-bottom: 8px; margin-top: 0;">CodeQL Results</h3>`;
				let hasResults = false;

				let criticalCount = 0;
				let highCount = 0;
				let mediumCount = 0;
				let lowCount = 0;
				let infoCount = 0;

				let allFindings = [];

				for (const sarifFile of codeqlFiles) {
					console.log(`Processing SARIF file: ${sarifFile}`);

					let results;
					try {
						const content = fs.readFileSync(sarifFile, 'utf8');
						results = JSON.parse(content);
						console.log(`Successfully parsed SARIF file: ${sarifFile}`);
					} catch (error) {
						console.error(`Error reading/parsing SARIF file ${sarifFile}:`, error);
						continue;
					}

					if (results && results.runs) {
						console.log(`Found ${results.runs.length} runs in ${sarifFile}`);

						results.runs.forEach((run) => {
							if (run.results && run.results.length > 0) {
								console.log(`Found ${run.results.length} results in run`);
								hasResults = true;

								run.results.forEach((finding) => {
									const ruleSeverity = mapRuleSeverity(finding.ruleId);

									finding.mappedSeverity = ruleSeverity;

									if (ruleSeverity === 'critical') criticalCount++;
									else if (ruleSeverity === 'high') highCount++;
									else if (ruleSeverity === 'medium' || ruleSeverity === 'warning' || ruleSeverity === 'moderate') mediumCount++;
									else if (ruleSeverity === 'low' || ruleSeverity === 'note') lowCount++;
									else infoCount++;

									allFindings.push(finding);
								});
							}
						});
					}
				}

				// Always add severity summary
				reportContent += createSeveritySummary(criticalCount, highCount, mediumCount, lowCount, infoCount);

				if (allFindings.length > 0) {
					reportContent += `
            <table>
              <tr>
                <th>Severity</th>
                <th>Rule</th>
                <th>Location</th>
                <th>Message</th>
              </tr>
          `;

					const severityOrder = {
						critical: 0,
						high: 1,
						medium: 2,
						moderate: 2,
						warning: 2,
						low: 3,
						note: 3,
						info: 4,
					};

					allFindings.sort((a, b) => {
						return severityOrder[a.mappedSeverity] - severityOrder[b.mappedSeverity];
					});

					allFindings.forEach((finding) => {
						const severity = finding.mappedSeverity;
						const location = finding.locations?.[0]?.physicalLocation;
						const filePath = location?.artifactLocation?.uri || 'N/A';
						const region = location?.region || {};
						const startLine = region.startLine;
						const startColumn = region.startColumn;
						const endLine = region.endLine;
						const endColumn = region.endColumn;

						let locationDetails = 'N/A';
						if (startLine) {
							if (endLine && endLine !== startLine) {
								locationDetails = `Lines ${startLine}:${startColumn || 1}-${endLine}:${endColumn || 1}`;
							} else {
								locationDetails = `Line ${startLine}${startColumn ? `:${startColumn}` : ''}`;
								if (endColumn && endColumn !== startColumn) {
									locationDetails += `-${endColumn}`;
								}
							}
						}

						const ruleDescription = getRuleDescription(finding.ruleId);
						const recommendation = getRuleRecommendation(finding.ruleId);

						reportContent += `
              <tr>
                <td>${createSeverityBadge(severity)}</td>
                <td>${finding.ruleId || 'N/A'}</td>
                <td>
                  <div style="font-family: monospace; background-color: #f8f9fa; padding: 2px 4px; border-radius: 3px; font-size: 0.9em; margin: 2px 0;">${filePath}</div>
                  <div style="font-family: monospace; background-color: #f8f9fa; padding: 2px 4px; border-radius: 3px; font-size: 0.9em; margin: 2px 0;">${locationDetails}</div>
                </td>
                <td>
                  <div style="margin-bottom: 10px;">${finding.message?.text || 'N/A'}</div>
                  <div style="margin: 5px 0; background-color: #f8f9fa; border-radius: 4px; padding: 10px;">
                    <div style="font-style: italic; color: #666; margin-top: 5px;">${ruleDescription}</div>
                    <div style="margin-top: 8px; font-weight: bold; color: #2c3e50;"><strong>Recommendation:</strong> ${recommendation}</div>
                  </div>
                </td>
              </tr>
            `;
					});

					reportContent += '</table>';
				} else {
					reportContent += '<p>No CodeQL issues found.</p>';
				}
				reportContent += '</div>';
			} catch (error) {
				console.error(`Error processing CodeQL results for ${directory}:`, error);
				console.error('Error details:', error.stack);
				reportContent += `<p>Error processing CodeQL results: ${error.message}</p>`;
			}
		} else {
			console.log(`No CodeQL files found for ${directory}`);
			reportContent += `<div style="margin-top: 30px; background: #fff; padding: 20px; border-radius: 8px; border: 1px solid #e0e0e0;"><h3 style="color: #34495e; border-bottom: 2px solid #eee; padding-bottom: 8px; margin-top: 0;">CodeQL Results</h3>`;
			reportContent += createSeveritySummary(0, 0, 0, 0, 0);
			reportContent += `<p>No CodeQL issues found. No CodeQL analysis results available.</p></div>`;
		}

		// Process npm audit results
		const npmAuditFiles = files.filter((f) => f.includes(`npm-audit-${directory}`));
		if (npmAuditFiles.length > 0) {
			try {
				const results = JSON.parse(fs.readFileSync(npmAuditFiles[0], 'utf8'));
				reportContent += `<div style="margin-top: 30px; background: #fff; padding: 20px; border-radius: 8px; border: 1px solid #e0e0e0;"><h3 style="color: #34495e; border-bottom: 2px solid #eee; padding-bottom: 8px; margin-top: 0;">Dependency Scanning Results</h3>`;

				if (results.vulnerabilities) {
					const vulns = Object.entries(results.vulnerabilities);

					// Count issues by severity
					let criticalCount = 0;
					let highCount = 0;
					let mediumCount = 0;
					let lowCount = 0;
					let infoCount = 0;

					vulns.forEach(([pkg, vuln]) => {
						const severity = (vuln.severity || '').toLowerCase();
						if (severity === 'critical') criticalCount++;
						else if (severity === 'high') highCount++;
						else if (severity === 'moderate' || severity === 'medium') mediumCount++;
						else if (severity === 'low') lowCount++;
						else infoCount++;
					});

					// Add severity summary chart
					reportContent += createSeveritySummary(criticalCount, highCount, mediumCount, lowCount, infoCount);

					if (vulns.length > 0) {
						reportContent += `
              <table>
                <tr>
                  <th>Severity</th>
                  <th>Package</th>
                  <th>Vulnerable Versions</th>
                  <th>Affected Nodes</th>
                </tr>
            `;

						const sortedVulns = [...vulns].sort(([, a], [, b]) => {
							return getSeverityOrder(a.severity) - getSeverityOrder(b.severity);
						});

						sortedVulns.forEach(([pkg, vuln]) => {
							let displaySeverity = vuln.severity;
							if (vuln.severity && vuln.severity.toLowerCase() === 'moderate') {
								displaySeverity = 'Medium';
							}

							const normalizedSev = normalizeSeverity(vuln.severity);

							reportContent += `
                <tr>
                  <td>${createSeverityBadge(normalizedSev, displaySeverity || 'Low')}</td>
                  <td>${pkg}</td>
                  <td>${vuln.range || vuln.version || 'N/A'}</td>
                  <td>${vuln.nodes ? vuln.nodes.join(', ') : 'N/A'}</td>
                </tr>
              `;
						});
						reportContent += '</table>';
					} else {
						reportContent += '<p>No vulnerabilities found.</p>';
					}
				} else {
					// Ensure consistent "No vulnerabilities found" message
					reportContent += createSeveritySummary(0, 0, 0, 0, 0);
					reportContent += '<p>No vulnerabilities found.</p>';
				}
				reportContent += '</div>';
			} catch (error) {
				console.error(`Error processing npm audit for ${directory}:`, error);
				reportContent += `<p>Error processing npm audit results: ${error.message}</p>`;
			}
		} else {
			// Handle case where no npm audit files exist
			reportContent += `<div style="margin-top: 30px; background: #fff; padding: 20px; border-radius: 8px; border: 1px solid #e0e0e0;"><h3 style="color: #34495e; border-bottom: 2px solid #eee; padding-bottom: 8px; margin-top: 0;">Dependency Scanning Results</h3>`;
			reportContent += createSeveritySummary(0, 0, 0, 0, 0);
			reportContent += '<p>No vulnerabilities found.</p></div>';
		}

		// Process Trivy results
		const trivyFiles = files.filter((f) => f.includes(`trivy-${directory}`));
		if (trivyFiles.length > 0) {
			try {
				const results = JSON.parse(fs.readFileSync(trivyFiles[0], 'utf8'));
				reportContent += `<div style="margin-top: 30px; background: #fff; padding: 20px; border-radius: 8px; border: 1px solid #e0e0e0;"><h3 style="color: #34495e; border-bottom: 2px solid #eee; padding-bottom: 8px; margin-top: 0;">Trivy Results</h3>`;

				if (results.Results && Array.isArray(results.Results)) {
					const vulns = results.Results.flatMap((r) => r.Vulnerabilities || []);

					// Count issues by severity
					let criticalCount = 0;
					let highCount = 0;
					let mediumCount = 0;
					let lowCount = 0;
					let infoCount = 0;

					vulns.forEach((vuln) => {
						const severity = (vuln.Severity || '').toLowerCase();
						if (severity === 'critical') criticalCount++;
						else if (severity === 'high') highCount++;
						else if (severity === 'medium') mediumCount++;
						else if (severity === 'low') lowCount++;
						else infoCount++;
					});

					// Add severity summary chart
					reportContent += createSeveritySummary(criticalCount, highCount, mediumCount, lowCount, infoCount);

					if (vulns.length > 0) {
						reportContent += `
              <table>
                <tr>
                  <th>Severity</th>
                  <th>Package</th>
                  <th>Current Version</th>
                  <th>Fixed Version</th>
                  <th>Details</th>
                </tr>
            `;

						const sortedVulns = [...vulns].sort((a, b) => {
							return getSeverityOrder(a.Severity) - getSeverityOrder(b.Severity);
						});

						sortedVulns.forEach((vuln) => {
							let displaySeverity = vuln.Severity;
							if (vuln.Severity && vuln.Severity.toLowerCase() === 'medium') {
								displaySeverity = 'Medium';
							}

							const normalizedSev = normalizeSeverity(vuln.Severity);

							reportContent += `
                <tr>
                  <td>${createSeverityBadge(normalizedSev, displaySeverity || 'Low')}</td>
                  <td>${vuln.PkgName || 'N/A'}</td>
                  <td>${vuln.InstalledVersion || 'N/A'}</td>
                  <td>${vuln.FixedVersion || 'Not available'}</td>
                  <td>
                    <details>
                      <summary style="cursor: pointer; color: #2c3e50; font-weight: bold;">View Details</summary>
                      <div style="margin-top: 10px; padding: 10px; background-color: #f8f9fa; border-radius: 4px;">
                        <p style="margin: 5px 0;"><strong>Title:</strong> ${vuln.Title || 'N/A'}</p>
                        <p style="margin: 5px 0;"><strong>Description:</strong> ${vuln.Description || 'N/A'}</p>
                        ${vuln.References ? `<p style="margin: 5px 0;"><strong>References:</strong> ${vuln.References.join(', ')}</p>` : ''}
                        ${vuln.CweIDs ? `<p style="margin: 5px 0;"><strong>CWE IDs:</strong> ${vuln.CweIDs.join(', ')}</p>` : ''}
                      </div>
                    </details>
                  </td>
                </tr>
              `;
						});
						reportContent += '</table>';
					} else {
						// Ensure consistent "No vulnerabilities found" message
						reportContent += '<p>No vulnerabilities found.</p>';
					}
				} else if (results.Message) {
					reportContent += createSeveritySummary(0, 0, 0, 0, 0);
					reportContent += `<p>${results.Message}</p>`;
				} else {
					reportContent += createSeveritySummary(0, 0, 0, 0, 0);
					reportContent += '<p>No vulnerabilities found.</p>';
				}
				reportContent += '</div>';
			} catch (error) {
				console.error(`Error processing Trivy for ${directory}:`, error);
				reportContent += `<p>Error processing Trivy results: ${error.message}</p>`;
			}
		} else {
			// Handle case where no Trivy files exist
			reportContent += `<div style="margin-top: 30px; background: #fff; padding: 20px; border-radius: 8px; border: 1px solid #e0e0e0;"><h3 style="color: #34495e; border-bottom: 2px solid #eee; padding-bottom: 8px; margin-top: 0;">Trivy Results</h3>`;
			reportContent += createSeveritySummary(0, 0, 0, 0, 0);
			reportContent += '<p>No vulnerabilities found.</p></div>';
		}

		// Process ZPA results (for Apex projects only)
		if (isApex) {
			const zpaFiles = files.filter((f) => f.includes(`zpa-${directory}`));
			if (zpaFiles.length > 0) {
				try {
					const content = fs.readFileSync(zpaFiles[0], 'utf8');
					const issues = parseZpaResults(content);

					reportContent += `<div style="margin-top: 30px; background: #fff; padding: 20px; border-radius: 8px; border: 1px solid #e0e0e0;"><h3 style="color: #34495e; border-bottom: 2px solid #eee; padding-bottom: 8px; margin-top: 0;">🔍 PL/SQL Security Analysis (ZPA)</h3>`;

					if (issues && issues.length > 0) {
						// Count issues by severity
						let criticalCount = 0;
						let highCount = 0;
						let mediumCount = 0;
						let lowCount = 0;
						let infoCount = 0;

						issues.forEach((issue) => {
							const severity = mapZpaSeverity(issue.severity);
							if (severity === 'critical') criticalCount++;
							else if (severity === 'high') highCount++;
							else if (severity === 'medium') mediumCount++;
							else if (severity === 'low') lowCount++;
							else infoCount++;
						});

						// Add severity summary chart
						reportContent += createSeveritySummary(criticalCount, highCount, mediumCount, lowCount, infoCount);

						reportContent += `
              <table>
                <tr>
                  <th>Severity</th>
                  <th>Rule ID</th>
                  <th>Location</th>
                  <th>Description</th>
                </tr>
            `;

						// Sort by severity
						const sortedIssues = [...issues].sort((a, b) => {
							return getSeverityOrder(mapZpaSeverity(a.severity)) - getSeverityOrder(mapZpaSeverity(b.severity));
						});

						sortedIssues.forEach((issue) => {
							const severity = mapZpaSeverity(issue.severity);
							// Strip "zpa:" prefix from ruleId if present
							const cleanRuleId = issue.ruleId ? issue.ruleId.replace(/^zpa:/, '') : 'unknown';
							const ruleInfo = getPlsqlRuleInfo(cleanRuleId);
							const primaryLocation = issue.primaryLocation || {};
							const filePath = primaryLocation.filePath || 'N/A';
							const startLine = primaryLocation.textRange?.startLine || 'N/A';

							reportContent += `
                <tr>
                  <td>${createSeverityBadge(severity)}</td>
                  <td>${issue.ruleId || 'N/A'}</td>
                  <td>
                    <div style="font-family: monospace; background-color: #f8f9fa; padding: 2px 4px; border-radius: 3px; font-size: 0.9em; margin: 2px 0;">${filePath}</div>
                    <div style="font-family: monospace; background-color: #f8f9fa; padding: 2px 4px; border-radius: 3px; font-size: 0.9em; margin: 2px 0;">Line ${startLine}</div>
                  </td>
                  <td>
                    <div style="margin-bottom: 10px;">${issue.message || 'No message provided'}</div>
                    <div style="margin: 5px 0; background-color: #f8f9fa; border-radius: 4px; padding: 10px;">
                      <div style="font-style: italic; color: #666; margin-top: 5px;">${ruleInfo.description}</div>
                      <div style="margin-top: 8px; font-weight: bold; color: #2c3e50;"><strong>Recommendation:</strong> ${ruleInfo.recommendation}</div>
                    </div>
                  </td>
                </tr>
              `;
						});

						reportContent += '</table>';
					} else {
						reportContent += createSeveritySummary(0, 0, 0, 0, 0);
						reportContent += '<p>No PL/SQL security issues found.</p>';
					}
					reportContent += '</div>';
				} catch (error) {
					console.error(`Error processing ZPA results for ${directory}:`, error);
					reportContent += `<div style="margin-top: 30px; background: #fff; padding: 20px; border-radius: 8px; border: 1px solid #e0e0e0;"><h3 style="color: #34495e; border-bottom: 2px solid #eee; padding-bottom: 8px; margin-top: 0;">🔍 PL/SQL Security Analysis (ZPA)</h3>`;
					reportContent += `<p>Error processing ZPA results: ${error.message}</p></div>`;
				}
			} else {
				console.log(`No ZPA files found for ${directory}`);
				reportContent += `<div style="margin-top: 30px; background: #fff; padding: 20px; border-radius: 8px; border: 1px solid #e0e0e0;"><h3 style="color: #34495e; border-bottom: 2px solid #eee; padding-bottom: 8px; margin-top: 0;">🔍 PL/SQL Security Analysis (ZPA)</h3>`;
				reportContent += createSeveritySummary(0, 0, 0, 0, 0);
				reportContent += `<p>No PL/SQL security issues found. No ZPA analysis results available.</p></div>`;
			}

			// Process PL/SQL Pattern Detection results (for Apex projects only)
			const patternFiles = files.filter((f) => f.includes(`plsql-patterns-${directory}`));
			if (patternFiles.length > 0) {
				try {
					const content = fs.readFileSync(patternFiles[0], 'utf8');
					const patterns = parsePlsqlPatterns(content);

					reportContent += `<div style="margin-top: 30px; background: #fff; padding: 20px; border-radius: 8px; border: 1px solid #e0e0e0;"><h3 style="color: #34495e; border-bottom: 2px solid #eee; padding-bottom: 8px; margin-top: 0;">🔎 PL/SQL Pattern Detection</h3>`;

					if (patterns && patterns.length > 0) {
						// Count patterns by severity
						let criticalCount = 0;
						let highCount = 0;
						let mediumCount = 0;
						let lowCount = 0;
						let infoCount = 0;

						patterns.forEach((pattern) => {
							const severity = pattern.severity || 'info';
							if (severity === 'critical') criticalCount++;
							else if (severity === 'high') highCount++;
							else if (severity === 'medium') mediumCount++;
							else if (severity === 'low') lowCount++;
							else infoCount++;
						});

						// Add severity summary chart
						reportContent += createSeveritySummary(criticalCount, highCount, mediumCount, lowCount, infoCount);

						reportContent += `
              <table>
                <tr>
                  <th>Severity</th>
                  <th>Pattern Type</th>
                  <th>Location</th>
                  <th>Description</th>
                </tr>
            `;

						// Sort by severity
						const sortedPatterns = [...patterns].sort((a, b) => {
							return getSeverityOrder(a.severity || 'info') - getSeverityOrder(b.severity || 'info');
						});

						sortedPatterns.forEach((pattern) => {
							const severity = pattern.severity || 'info';
							const ruleInfo = getPlsqlRuleInfo(pattern.type);

							reportContent += `
                <tr>
                  <td>${createSeverityBadge(severity)}</td>
                  <td>${pattern.type || 'N/A'}</td>
                  <td>
                    <div style="font-family: monospace; background-color: #f8f9fa; padding: 2px 4px; border-radius: 3px; font-size: 0.9em; margin: 2px 0;">${pattern.file || 'N/A'}</div>
                    ${pattern.line ? `<div style="font-family: monospace; background-color: #f8f9fa; padding: 2px 4px; border-radius: 3px; font-size: 0.9em; margin: 2px 0;">Line ${pattern.line}</div>` : ''}
                    ${pattern.match ? `<div style="font-family: monospace; background-color: #f8f9fa; padding: 2px 4px; border-radius: 3px; font-size: 0.9em; margin: 2px 0;"><code>${pattern.match}</code></div>` : ''}
                  </td>
                  <td>
                    <div style="margin-bottom: 10px;">${pattern.description || ruleInfo.description}</div>
                    <div style="margin: 5px 0; background-color: #f8f9fa; border-radius: 4px; padding: 10px;">
                      <div style="margin-top: 8px; font-weight: bold; color: #2c3e50;"><strong>Recommendation:</strong> ${ruleInfo.recommendation}</div>
                    </div>
                  </td>
                </tr>
              `;
						});

						reportContent += '</table>';
					} else {
						reportContent += createSeveritySummary(0, 0, 0, 0, 0);
						reportContent += '<p>No PL/SQL security patterns detected.</p>';
					}
					reportContent += '</div>';
				} catch (error) {
					console.error(`Error processing PL/SQL patterns for ${directory}:`, error);
					reportContent += `<div style="margin-top: 30px; background: #fff; padding: 20px; border-radius: 8px; border: 1px solid #e0e0e0;"><h3 style="color: #34495e; border-bottom: 2px solid #eee; padding-bottom: 8px; margin-top: 0;">🔎 PL/SQL Pattern Detection</h3>`;
					reportContent += `<p>Error processing pattern results: ${error.message}</p></div>`;
				}
			} else {
				console.log(`No PL/SQL pattern files found for ${directory}`);
				reportContent += `<div style="margin-top: 30px; background: #fff; padding: 20px; border-radius: 8px; border: 1px solid #e0e0e0;"><h3 style="color: #34495e; border-bottom: 2px solid #eee; padding-bottom: 8px; margin-top: 0;">🔎 PL/SQL Pattern Detection</h3>`;
				reportContent += createSeveritySummary(0, 0, 0, 0, 0);
				reportContent += `<p>No PL/SQL security patterns detected. No pattern detection results available.</p></div>`;
			}
		}

		reportContent += '</div>';
	});

	reportContent += '</body></html>';
	fs.writeFileSync('combined-report.html', reportContent);
	console.log('Report generation completed.');
};

generateReport(process.argv[2]);
