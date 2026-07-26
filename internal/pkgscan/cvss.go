package pkgscan

import (
	"math"
	"strings"
)

// cvssBaseScore computes the CVSS 3.0/3.1 base score from a vector string
// such as CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H. It returns 0 and
// false when the vector is not a parseable CVSS 3.x vector.
func cvssBaseScore(vector string) (float64, bool) {
	vector = strings.TrimSpace(vector)
	if !strings.HasPrefix(vector, "CVSS:3") {
		return 0, false
	}

	metrics := make(map[string]string)
	for _, part := range strings.Split(vector, "/")[1:] {
		key, value, ok := strings.Cut(part, ":")
		if !ok {
			continue
		}
		metrics[key] = value
	}

	scopeChanged := metrics["S"] == "C"

	attackVector, ok := metricWeight(metrics["AV"], map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2})
	if !ok {
		return 0, false
	}
	attackComplexity, ok := metricWeight(metrics["AC"], map[string]float64{"L": 0.77, "H": 0.44})
	if !ok {
		return 0, false
	}
	privilegesRequired, ok := privilegesWeight(metrics["PR"], scopeChanged)
	if !ok {
		return 0, false
	}
	userInteraction, ok := metricWeight(metrics["UI"], map[string]float64{"N": 0.85, "R": 0.62})
	if !ok {
		return 0, false
	}
	impactWeights := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	confidentiality, ok := metricWeight(metrics["C"], impactWeights)
	if !ok {
		return 0, false
	}
	integrity, ok := metricWeight(metrics["I"], impactWeights)
	if !ok {
		return 0, false
	}
	availability, ok := metricWeight(metrics["A"], impactWeights)
	if !ok {
		return 0, false
	}

	impactSubScore := 1 - (1-confidentiality)*(1-integrity)*(1-availability)
	var impact float64
	if scopeChanged {
		impact = 7.52*(impactSubScore-0.029) - 3.25*math.Pow(impactSubScore-0.02, 15)
	} else {
		impact = 6.42 * impactSubScore
	}
	if impact <= 0 {
		return 0, true
	}

	exploitability := 8.22 * attackVector * attackComplexity * privilegesRequired * userInteraction

	score := impact + exploitability
	if scopeChanged {
		score = 1.08 * score
	}
	if score > 10 {
		score = 10
	}

	return roundUpOneDecimal(score), true
}

func metricWeight(value string, weights map[string]float64) (float64, bool) {
	weight, ok := weights[value]
	return weight, ok
}

func privilegesWeight(value string, scopeChanged bool) (float64, bool) {
	switch value {
	case "N":
		return 0.85, true
	case "L":
		if scopeChanged {
			return 0.68, true
		}
		return 0.62, true
	case "H":
		if scopeChanged {
			return 0.5, true
		}
		return 0.27, true
	}
	return 0, false
}

func roundUpOneDecimal(value float64) float64 {
	rounded := math.Ceil(value*100000) / 100000
	return math.Ceil(rounded*10) / 10
}

func severityFromScore(score float64) string {
	switch {
	case score >= 9:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	case score > 0:
		return "low"
	default:
		return ""
	}
}
