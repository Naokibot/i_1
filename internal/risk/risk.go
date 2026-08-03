package risk

import (
	"fmt"
	"strings"
	"time"

	"github.com/Naokibot/i_1/internal/model"
)

func Evaluate(a model.Asset) model.RiskAssessment {
	factors := map[string]int{}
	notes := []string{}
	factors["dataSensitivity"] = sensitivity(a.Context.DataClassification)
	factors["retentionPeriod"] = retention(a.Context.RetentionDays)
	if a.Context.InternetExposed {
		factors["harvestNowExposure"] = 15
		notes = append(notes, "Internet exposure increases harvest-now-decrypt-later risk")
	}
	if a.Context.HarvestNowRisk == "high" {
		factors["harvestNowExposure"] = max(factors["harvestNowExposure"], 15)
	}
	if a.Context.HarvestNowRisk == "medium" {
		factors["harvestNowExposure"] = max(factors["harvestNowExposure"], 9)
	}
	legacy := 0
	for _, c := range a.Crypto {
		if c.PQCStatus == "legacy" {
			legacy++
		}
	}
	if legacy > 0 {
		factors["classicalDependency"] = min(15, 5+legacy*2)
		notes = append(notes, fmt.Sprintf("%d classical public-key or weak cryptographic dependencies found", legacy))
	}
	crit := a.Context.BusinessCriticality
	if crit < 1 {
		crit = 1
	}
	if crit > 5 {
		crit = 5
	}
	factors["businessCriticality"] = crit * 3
	switch strings.ToLower(a.Context.Updateability) {
	case "impossible", "immutable":
		factors["migrationDifficulty"] = 10
	case "difficult":
		factors["migrationDifficulty"] = 8
	case "moderate":
		factors["migrationDifficulty"] = 5
	case "easy":
		factors["migrationDifficulty"] = 1
	default:
		factors["migrationDifficulty"] = 6
	}
	if !a.Context.HasAlternative {
		factors["lackOfAlternative"] = 5
	}
	score := 0
	for _, v := range factors {
		score += v
	}
	if score > 100 {
		score = 100
	}
	level := "low"
	if score >= 80 {
		level = "critical"
	} else if score >= 60 {
		level = "high"
	} else if score >= 35 {
		level = "medium"
	}
	if a.Context.RetentionDays >= 3650 {
		notes = append(notes, "Long-lived data should be prioritized even when the service is not public")
	}
	return model.RiskAssessment{Score: score, Level: level, Factors: factors, Explanation: notes, EvaluatedAt: time.Now().UTC()}
}

func Recommend(a model.Asset) model.MigrationRecommendation {
	legacy, hybrid, native := 0, 0, 0
	for _, c := range a.Crypto {
		switch c.PQCStatus {
		case "legacy":
			legacy++
		case "hybrid":
			hybrid++
		case "native":
			native++
		}
	}
	r := model.MigrationRecommendation{Stage: 0, StageName: "Observe", PathStatus: "Classical / unknown", Rationale: []string{}, NextActions: []string{}}
	if len(a.Crypto) == 0 {
		r.Rationale = append(r.Rationale, "No cryptographic components have been confirmed")
		r.NextActions = append(r.NextActions, "Run protocol and source discovery")
		return r
	}
	if legacy > 0 {
		r.Stage = 1
		r.StageName = "Simulate"
		r.PathStatus = "Classical sections remain"
		r.Rationale = append(r.Rationale, "Legacy algorithms are still active")
		r.NextActions = append(r.NextActions, "Benchmark a hybrid path", "Record client and server capability", "Define rollback thresholds")
		if a.Context.Updateability == "impossible" || a.Context.Updateability == "immutable" {
			r.Blockers = append(r.Blockers, "Endpoint cannot be updated; a gateway only protects the segment beyond it")
		}
		if a.Risk.Score >= 60 {
			r.Stage = 2
			r.StageName = "Shadow"
			r.NextActions = append(r.NextActions, "Run parallel PQC operations without changing production traffic")
		}
	}
	if hybrid > 0 && legacy == 0 {
		r.Stage = 4
		r.StageName = "PQC Preferred"
		r.PathStatus = "Hybrid PQC"
		r.Rationale = append(r.Rationale, "Hybrid algorithms are available without a detected legacy-only dependency")
		r.NextActions = append(r.NextActions, "Canary PQC-preferred policy", "Alert on capability regression")
	}
	if native > 0 && legacy == 0 && hybrid == 0 {
		r.Stage = 5
		r.StageName = "PQC Required"
		r.PathStatus = "End-to-End PQC candidate"
		r.Rationale = append(r.Rationale, "Only PQC-native cryptographic components were observed")
		r.NextActions = append(r.NextActions, "Verify every path segment", "Prepare legacy key destruction plan")
	}
	return r
}

func sensitivity(v string) int {
	switch strings.ToLower(v) {
	case "medical", "medical-record", "restricted", "secret":
		return 20
	case "confidential":
		return 14
	case "internal":
		return 7
	case "public":
		return 0
	default:
		return 8
	}
}
func retention(d int) int {
	switch {
	case d >= 3650:
		return 20
	case d >= 1825:
		return 15
	case d >= 365:
		return 10
	case d >= 30:
		return 5
	default:
		return 1
	}
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
