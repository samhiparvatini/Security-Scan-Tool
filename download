const { criticalRules, criticalSeverityRules, criticalDescriptions, criticalRecommendations } = require('./metadata/critical-metadata');
const { highRules, highSeverityRules, highDescriptions, highRecommendations } = require('./metadata/high-metadata');
const { mediumRules, mediumSeverityRules, mediumDescriptions, mediumRecommendations } = require('./metadata/medium-metadata');
const { lowRules, lowSeverityRules, lowDescriptions, lowRecommendations } = require('./metadata/low-metadata');

function mapRuleSeverity(ruleId) {
	if (criticalSeverityRules.some((rule) => ruleId && ruleId.includes(rule))) {
		return 'critical';
	} else if (highSeverityRules.some((rule) => ruleId && ruleId.includes(rule))) {
		return 'high';
	} else if (mediumSeverityRules.some((rule) => ruleId && ruleId.includes(rule))) {
		return 'medium';
	} else if (lowSeverityRules.some((rule) => ruleId && ruleId.includes(rule))) {
		return 'low';
	}

	if (ruleId) {
		if (criticalRules.some((rule) => ruleId.includes(rule))) {
			return 'critical';
		} else if (highRules.some((rule) => ruleId.includes(rule))) {
			return 'high';
		} else if (mediumRules.some((rule) => ruleId.includes(rule))) {
			return 'medium';
		} else if (lowRules.some((rule) => ruleId.includes(rule))) {
			return 'low';
		}
	}

	return 'warning';
}

function getRuleDescription(ruleId) {
	return criticalDescriptions[ruleId] || highDescriptions[ruleId] || mediumDescriptions[ruleId] || lowDescriptions[ruleId] || 'Unknown vulnerability detected without detailed description.';
}

function getRuleRecommendation(ruleId) {
	return criticalRecommendations[ruleId] || highRecommendations[ruleId] || mediumRecommendations[ruleId] || lowRecommendations[ruleId] || 'Review the code carefully and implement security best practices relevant to this type of vulnerability.';
}

module.exports = {
	mapRuleSeverity,
	getRuleDescription,
	getRuleRecommendation,
};
