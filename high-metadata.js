// Export Security Scan Results to CSV
// Supports both Full-Stack and Apex projects
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

function escapeCSV(field) {
	if (field === null || field === undefined) return '';
	const str = String(field);
	// Escape quotes and wrap in quotes if contains comma, newline, or quote
	if (str.includes(',') || str.includes('\n') || str.includes('"')) {
		return `"${str.replace(/"/g, '""')}"`;
	}
	return str;
}

function walkDir(dir) {
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
}

function exportToCSV() {
	const repoName = process.argv[2] || 'Security-Scan-Report';
	const projectType = process.argv[3] || 'Full-Stack';
	const isApex = projectType === 'Apex';

	console.log(`Exporting to CSV for ${repoName} (${projectType})...`);

	// Find all report files
	console.log('Searching for files in all-reports directory...');
	const files = walkDir('all-reports');
	console.log('Found files:', files);

	// Find unique directories
	const directories = new Set();
	files.forEach((file) => {
		if (file.includes('npm-audit-') || file.includes('trivy-') || file.includes('zpa-') || file.includes('plsql-patterns-')) {
			const dirMatch = file.match(/(npm-audit-|trivy-|zpa-|plsql-patterns-)(.+?)\./);
			if (dirMatch && dirMatch[2]) {
				directories.add(dirMatch[2]);
			}
		}
	});

	console.log('Detected directories:', Array.from(directories));

	// Collect all issues
	let allIssues = [];

	// Process each directory
	for (const directory of directories) {
		console.log(`Processing directory: ${directory}`);

		// ===== CODEQL RESULTS =====
		const codeqlPath = `all-reports/codeql-results-${directory}`;

		if (fs.existsSync(codeqlPath)) {
			const codeqlFiles = fs.readdirSync(codeqlPath)
				.filter(f => f.endsWith('.sarif'))
				.map(f => path.join(codeqlPath, f));

			for (const sarifFile of codeqlFiles) {
				try {
					const content = fs.readFileSync(sarifFile, 'utf8');
					const results = JSON.parse(content);

					if (results && results.runs) {
						results.runs.forEach(run => {
							if (run.results && run.results.length > 0) {
								run.results.forEach(finding => {
									const severity = mapRuleSeverity(finding.ruleId);
									const location = finding.locations?.[0]?.physicalLocation;
									const filePath = location?.artifactLocation?.uri || 'N/A';
									const region = location?.region || {};

									allIssues.push({
										directory,
										scanType: 'CodeQL',
										severity,
										ruleId: finding.ruleId || 'N/A',
										file: filePath,
										line: region.startLine || 'N/A',
										message: finding.message?.text || 'N/A',
										description: getRuleDescription(finding.ruleId),
										recommendation: getRuleRecommendation(finding.ruleId),
										package: '',
										version: '',
										fixedVersion: ''
									});
								});
							}
						});
					}
				} catch (error) {
					console.error(`Error processing CodeQL file ${sarifFile}:`, error);
				}
			}
		}

		// ===== NPM AUDIT RESULTS =====
		const npmAuditFiles = files.filter(f => f.includes(`npm-audit-${directory}`));

		if (npmAuditFiles.length > 0) {
			try {
				const results = JSON.parse(fs.readFileSync(npmAuditFiles[0], 'utf8'));

				if (results.vulnerabilities) {
					Object.entries(results.vulnerabilities).forEach(([pkg, vuln]) => {
						const severity = normalizeSeverity(vuln.severity);
						const via = Array.isArray(vuln.via)
							? vuln.via.map(v => typeof v === 'object' ? v.title || v.source : v).join('; ')
							: String(vuln.via || 'N/A');

						allIssues.push({
							directory,
							scanType: 'npm audit',
							severity,
							ruleId: 'npm-vulnerability',
							file: 'package.json',
							line: 'N/A',
							message: via,
							description: `Vulnerability in ${pkg}`,
							recommendation: 'Update to a secure version',
							package: pkg,
							version: vuln.range || vuln.version || 'N/A',
							fixedVersion: 'See npm audit fix'
						});
					});
				}
			} catch (error) {
				console.error(`Error processing npm audit for ${directory}:`, error);
			}
		}

		// ===== TRIVY RESULTS =====
		const trivyFiles = files.filter(f => f.includes(`trivy-${directory}`));

		if (trivyFiles.length > 0) {
			try {
				const results = JSON.parse(fs.readFileSync(trivyFiles[0], 'utf8'));

				if (results.Results && Array.isArray(results.Results)) {
					results.Results.forEach(result => {
						if (result.Vulnerabilities) {
							result.Vulnerabilities.forEach(vuln => {
								const severity = normalizeSeverity(vuln.Severity);

								allIssues.push({
									directory,
									scanType: 'Trivy',
									severity,
									ruleId: vuln.VulnerabilityID || 'N/A',
									file: result.Target || 'N/A',
									line: 'N/A',
									message: vuln.Title || 'N/A',
									description: vuln.Description || 'N/A',
									recommendation: vuln.FixedVersion ? `Update to version ${vuln.FixedVersion}` : 'No fix available',
									package: vuln.PkgName || 'N/A',
									version: vuln.InstalledVersion || 'N/A',
									fixedVersion: vuln.FixedVersion || 'Not available'
								});
							});
						}
					});
				}
			} catch (error) {
				console.error(`Error processing Trivy for ${directory}:`, error);
			}
		}

		// ===== APEX-SPECIFIC SCANS =====
		if (isApex) {
			// ZPA Results
			const zpaFiles = files.filter(f => f.includes(`zpa-${directory}`));

			if (zpaFiles.length > 0) {
				try {
					const content = fs.readFileSync(zpaFiles[0], 'utf8');
					const issues = parseZpaResults(content);

					issues.forEach(issue => {
						const severity = mapZpaSeverity(issue.severity);
						const cleanRuleId = issue.ruleId ? issue.ruleId.replace(/^zpa:/, '') : 'unknown';
						const ruleInfo = getPlsqlRuleInfo(cleanRuleId);
						const primaryLocation = issue.primaryLocation || {};

						allIssues.push({
							directory,
							scanType: 'ZPA (PL/SQL)',
							severity,
							ruleId: issue.ruleId || 'N/A',
							file: primaryLocation.filePath || 'N/A',
							line: primaryLocation.textRange?.startLine || 'N/A',
							message: issue.message || 'No message provided',
							description: ruleInfo.description,
							recommendation: ruleInfo.recommendation,
							package: '',
							version: '',
							fixedVersion: ''
						});
					});

					console.log(`Processed ${issues.length} ZPA issues for ${directory}`);
				} catch (error) {
					console.error(`Error processing ZPA for ${directory}:`, error);
				}
			}

			// PL/SQL Pattern Detection
			const patternFiles = files.filter(f => f.includes(`plsql-patterns-${directory}`));

			if (patternFiles.length > 0) {
				try {
					const content = fs.readFileSync(patternFiles[0], 'utf8');
					const patterns = parsePlsqlPatterns(content);

					patterns.forEach(pattern => {
						const severity = pattern.severity || 'info';
						const ruleInfo = getPlsqlRuleInfo(pattern.type);

						allIssues.push({
							directory,
							scanType: 'PL/SQL Patterns',
							severity,
							ruleId: pattern.type || 'N/A',
							file: pattern.file || 'N/A',
							line: pattern.line || 'N/A',
							message: pattern.match || 'Pattern detected',
							description: pattern.description || ruleInfo.description,
							recommendation: ruleInfo.recommendation,
							package: '',
							version: '',
							fixedVersion: ''
						});
					});

					console.log(`Processed ${patterns.length} PL/SQL patterns for ${directory}`);
				} catch (error) {
					console.error(`Error processing PL/SQL patterns for ${directory}:`, error);
				}
			}
		}
	}

	// Sort by severity
	allIssues.sort((a, b) => {
		const severityCompare = getSeverityOrder(a.severity) - getSeverityOrder(b.severity);
		if (severityCompare !== 0) return severityCompare;
		// Secondary sort by directory
		return a.directory.localeCompare(b.directory);
	});

	// Create CSV content
	const headers = [
		'Directory',
		'Scan Type',
		'Severity',
		'Rule/Vulnerability ID',
		'File',
		'Line',
		'Package',
		'Current Version',
		'Fixed Version',
		'Message',
		'Description',
		'Recommendation'
	];

	let csvContent = headers.join(',') + '\n';

	allIssues.forEach(issue => {
		const row = [
			escapeCSV(issue.directory),
			escapeCSV(issue.scanType),
			escapeCSV(issue.severity.toUpperCase()),
			escapeCSV(issue.ruleId),
			escapeCSV(issue.file),
			escapeCSV(issue.line),
			escapeCSV(issue.package),
			escapeCSV(issue.version),
			escapeCSV(issue.fixedVersion),
			escapeCSV(issue.message),
			escapeCSV(issue.description),
			escapeCSV(issue.recommendation)
		];
		csvContent += row.join(',') + '\n';
	});

	// Save CSV file
	const fileName = `security-scan-${repoName.toLowerCase()}.csv`;
	fs.writeFileSync(fileName, csvContent, 'utf8');
	console.log(`CSV report saved: ${fileName}`);
	console.log(`Total issues exported: ${allIssues.length}`);

	// Create summary CSV
	const summaryData = {};
	allIssues.forEach(issue => {
		const key = `${issue.directory}|${issue.scanType}`;
		if (!summaryData[key]) {
			summaryData[key] = {
				directory: issue.directory,
				scanType: issue.scanType,
				critical: 0,
				high: 0,
				medium: 0,
				low: 0,
				info: 0,
				total: 0
			};
		}
		summaryData[key][issue.severity]++;
		summaryData[key].total++;
	});

	const summaryHeaders = ['Directory', 'Scan Type', 'Critical', 'High', 'Medium', 'Low', 'Info', 'Total'];
	let summaryContent = summaryHeaders.join(',') + '\n';

	Object.values(summaryData).forEach(row => {
		summaryContent += [
			escapeCSV(row.directory),
			escapeCSV(row.scanType),
			row.critical,
			row.high,
			row.medium,
			row.low,
			row.info,
			row.total
		].join(',') + '\n';
	});

	// Add total row
	const totals = {
		critical: 0,
		high: 0,
		medium: 0,
		low: 0,
		info: 0,
		total: 0
	};

	Object.values(summaryData).forEach(row => {
		totals.critical += row.critical;
		totals.high += row.high;
		totals.medium += row.medium;
		totals.low += row.low;
		totals.info += row.info;
		totals.total += row.total;
	});

	summaryContent += [
		'TOTAL',
		'All Scans',
		totals.critical,
		totals.high,
		totals.medium,
		totals.low,
		totals.info,
		totals.total
	].join(',') + '\n';

	const summaryFileName = `security-scan-summary-${repoName.toLowerCase()}.csv`;
	fs.writeFileSync(summaryFileName, summaryContent, 'utf8');
	console.log(`Summary CSV saved: ${summaryFileName}`);
}

// Run export
exportToCSV();
