package policy

import "testing"

func TestCompileGatewayWarning(t *testing.T) {
	p := Policy{DataClassification: "medical-record", RetentionPeriod: "20-years", Requirements: Requirements{KeyExchange: Minimum{Minimum: "hybrid-pqc"}, Signature: Minimum{Minimum: "dual-signature"}, Storage: Storage{PQCKeyWrapping: "required"}}, Exceptions: Exceptions{LegacyDevices: LegacyDevices{TemporaryGateway: "allowed", Deadline: "2028-03-31"}}}
	c, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !c.GatewayAllowed || len(c.Warnings) == 0 {
		t.Fatal("expected explicit gateway limitation warning")
	}
}
