package main

import "testing"

func TestValidateRequiresBothLiveConfigValuesAndEchoIdentity(t *testing.T) {
	good := []byte(`{"role":"spring-a","greeting":"v2","downstream":{"role":"spring-b","greeting":"v2","request_id":"id-20","echo":"hello"}}`)
	if err := validate(good, "v2", "id-20", "hello"); err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct{ g, id, body string }{{"v1", "id-20", "hello"}, {"v2", "wrong", "hello"}, {"v2", "id-20", "wrong"}} {
		if validate(good, v.g, v.id, v.body) == nil {
			t.Fatal("stale config or mismatched request accepted", v)
		}
	}
	if validate([]byte(`{}`), "v2", "id-20", "hello") == nil {
		t.Fatal("empty response accepted")
	}
}

func TestNacosReplyMustMatchActualConfiguration(t *testing.T) {
	if err := validateNacosReply([]byte(`{"downstream":{"nacos_content":"greeting=version-two\n"}}`), "version-two"); err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{`{}`, `{"downstream":{"nacos_content":"greeting=old\n"}}`} {
		if validateNacosReply([]byte(b), "version-two") == nil {
			t.Fatal("missing/stale Nacos reply accepted")
		}
	}
}
