package risk

import (
	"github.com/Naokibot/i_1/internal/model"
	"testing"
)

func TestLongLivedMedicalAssetIsHighRisk(t *testing.T) {
	a := model.Asset{Context: model.RiskContext{DataClassification: "medical-record", RetentionDays: 7300, InternetExposed: true, BusinessCriticality: 5, Updateability: "difficult", HasAlternative: false}, Crypto: []model.CryptoComponent{{Algorithm: "RSA", PQCStatus: "legacy"}}}
	r := Evaluate(a)
	if r.Score < 60 {
		t.Fatalf("expected high risk, got %d", r.Score)
	}
}
