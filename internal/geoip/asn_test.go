package geoip

import (
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func writeTestASNDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ip2asn-v4.tsv.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(f)
	_, err = zw.Write([]byte(
		"1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET Cloudflare, Inc.\n" +
			"1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n" +
			"1.0.4.0\t1.0.7.255\t38803\tAU\tGTELECOM-AS-AP Gtelecom Pty Ltd\n",
	))
	if err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLookupWithASNOnly(t *testing.T) {
	s := New()
	if err := s.LoadASN(writeTestASNDB(t)); err != nil {
		t.Fatal(err)
	}
	info := s.Lookup("1.0.0.1")
	if info == nil {
		t.Fatal("expected ASN-only lookup result")
	}
	if info.ASN != "AS13335" || info.ASNOrg == "" || info.ISOCode != "US" {
		t.Fatalf("unexpected ASN enrichment: %+v", info)
	}
	if info.ISP == "" || info.CloudProvider != "cloudflare" {
		t.Fatalf("unexpected ISP/cloud enrichment: %+v", info)
	}
	if info.UsageType != "CDN" || info.UsageTypeSource != "inferred" {
		t.Fatalf("unexpected usage inference: %+v", info)
	}
	if info := s.Lookup("1.0.1.1"); info != nil {
		t.Fatalf("not-routed range should not produce ASN data: %+v", info)
	}
}

func TestInferUsageType(t *testing.T) {
	cases := []struct {
		name string
		info Info
		want string
	}{
		{name: "cdn", info: Info{ASNOrg: "Fastly, Inc."}, want: "CDN"},
		{name: "hosting", info: Info{ASNOrg: "Example Hosting LLC"}, want: "IDC"},
		{name: "mobile", info: Info{ISP: "China Mobile"}, want: "MOB"},
		{name: "broadband", info: Info{ISP: "中国电信"}, want: "DYN"},
		{name: "education", info: Info{ASNOrg: "Example University"}, want: "EDU"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, source := inferUsageType(&tc.info)
			if got != tc.want || source != "inferred" {
				t.Fatalf("got (%q, %q), want (%q, inferred)", got, source, tc.want)
			}
		})
	}
}
