package geoip

import (
	"bufio"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
)

type ASNInfo struct {
	ASN          string `json:"asn"`
	CountryCode  string `json:"country_code"`
	Organization string `json:"organization"`
}

type asnRange struct {
	start        uint32
	end          uint32
	number       uint32
	countryCode  string
	organization string
}

type asnSnapshot struct {
	ranges []asnRange
}

func loadASNSnapshot(path string) (*asnSnapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var reader io.Reader = f
	if strings.HasSuffix(strings.ToLower(path), ".gz") {
		zr, err := gzip.NewReader(f)
		if err != nil {
			return nil, fmt.Errorf("open gzip: %w", err)
		}
		defer zr.Close()
		reader = zr
	}

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	ranges := make([]asnRange, 0, 550000)
	organizations := make(map[uint32]string, 100000)
	countries := make(map[string]string, 256)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		fields := strings.SplitN(scanner.Text(), "\t", 5)
		if len(fields) != 5 {
			return nil, fmt.Errorf("line %d: expected 5 TSV fields", lineNo)
		}
		start, ok := ipv4Uint32(fields[0])
		if !ok {
			return nil, fmt.Errorf("line %d: invalid start IP %q", lineNo, fields[0])
		}
		end, ok := ipv4Uint32(fields[1])
		if !ok || end < start {
			return nil, fmt.Errorf("line %d: invalid end IP %q", lineNo, fields[1])
		}
		number, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("line %d: invalid ASN %q", lineNo, fields[2])
		}
		asnNumber := uint32(number)
		organization := organizations[asnNumber]
		if organization == "" {
			organization = strings.TrimSpace(fields[4])
			organizations[asnNumber] = organization
		}
		countryCode := strings.TrimSpace(fields[3])
		if interned, ok := countries[countryCode]; ok {
			countryCode = interned
		} else {
			countries[countryCode] = countryCode
		}
		ranges = append(ranges, asnRange{
			start: start, end: end, number: asnNumber,
			countryCode: countryCode, organization: organization,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(ranges) == 0 {
		return nil, fmt.Errorf("ASN database is empty")
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start < ranges[j].start })
	return &asnSnapshot{ranges: ranges}, nil
}

func (s *asnSnapshot) lookup(ip net.IP) *ASNInfo {
	if s == nil {
		return nil
	}
	v4 := ip.To4()
	if v4 == nil {
		return nil
	}
	n := binary.BigEndian.Uint32(v4)
	i := sort.Search(len(s.ranges), func(i int) bool { return s.ranges[i].start > n }) - 1
	if i < 0 || n > s.ranges[i].end || s.ranges[i].number == 0 {
		return nil
	}
	r := s.ranges[i]
	return &ASNInfo{
		ASN:          "AS" + strconv.FormatUint(uint64(r.number), 10),
		CountryCode:  r.countryCode,
		Organization: r.organization,
	}
}

func ipv4Uint32(s string) (uint32, bool) {
	ip := net.ParseIP(strings.TrimSpace(s)).To4()
	if ip == nil {
		return 0, false
	}
	return binary.BigEndian.Uint32(ip), true
}

func inferUsageType(info *Info) (string, string) {
	text := strings.ToLower(strings.Join([]string{
		info.ISP, info.ASNOrg, info.CloudProvider,
	}, " "))
	if strings.TrimSpace(text) == "" {
		return "", ""
	}
	containsAny := func(words ...string) bool {
		for _, word := range words {
			if strings.Contains(text, word) {
				return true
			}
		}
		return false
	}
	switch {
	case containsAny("cloudflare", "akamai", "fastly", "cdn", "edgecast", "cloudfront"):
		return "CDN", "inferred"
	case info.CloudProvider != "" || containsAny("hosting", "data center", "datacenter", "cloud", "server", "vps"):
		return "IDC", "inferred"
	case containsAny("mobile", "cellular", "wireless", "telecom mobile", "中国移动", "china mobile"):
		return "MOB", "inferred"
	case containsAny("university", "college", "education", "research", "教育", "大学"):
		return "EDU", "inferred"
	case containsAny("government", "ministry", "municipal", "政府"):
		return "GOV", "inferred"
	case containsAny("backbone", "internet exchange", "network information center", "transit"):
		return "NET", "inferred"
	case containsAny("broadband", "cable", "fiber", "fibre", "dsl", "residential", "电信", "联通", "广电"):
		return "DYN", "inferred"
	case info.ASN != "":
		return "NET", "inferred"
	default:
		return "", ""
	}
}
