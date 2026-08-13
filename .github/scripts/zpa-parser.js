/**
 * Parser for ZPA (Z PL/SQL Analyzer) SonarQube Generic Issue format
 * Used for Apex project scanning
 */

function parseZpaResults(jsonContent) {
  try {
    const data = JSON.parse(jsonContent);
    return data.issues || [];
  } catch (error) {
    console.error('Error parsing ZPA results:', error);
    return [];
  }
}

function mapZpaSeverity(zpaSeverity) {
  const mapping = {
    'BLOCKER': 'critical',
    'CRITICAL': 'high',
    'MAJOR': 'medium',
    'MINOR': 'low',
    'INFO': 'info'
  };
  return mapping[zpaSeverity] || 'info';
}

function parsePlsqlPatterns(jsonContent) {
  try {
    const data = JSON.parse(jsonContent);
    return data.patterns || [];
  } catch (error) {
    console.error('Error parsing PL/SQL patterns:', error);
    return [];
  }
}

module.exports = {
  parseZpaResults,
  mapZpaSeverity,
  parsePlsqlPatterns
};
