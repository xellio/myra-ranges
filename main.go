// myra-ranges keeps an nginx allow-list snippet in sync with the Myra CDN's
// published IP ranges.
//
// It fetches the ranges via the Myra API (myrasec-go), renders them as
// `allow <cidr>;` lines (plus configured extra allows and a final `deny all;`),
// compares the result with the snippet currently on disk and — unless
// --dry-run — replaces it, runs `nginx -t` and reloads nginx. If the test
// fails the previous snippet is restored.
//
// Exit codes: 0 = no change, 3 = changed (applied, or would be with --dry-run),
// 1 = error. The exit code lets a cron wrapper decide whether to notify.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	yaml "gopkg.in/yaml.v2"
)

const (
	exitUnchanged = 0
	exitError     = 1
	exitChanged   = 3

	pageSize = 100
	maxPages = 50
)

type configuration struct {
	APIKey      string   `yaml:"apikey"`
	Secret      string   `yaml:"secret"`
	Token       string   `yaml:"token"`
	Snippet     string   `yaml:"snippet"`
	NginxTest   string   `yaml:"nginx_test"`
	NginxReload string   `yaml:"nginx_reload"`
	ExtraAllow  []string `yaml:"extra_allow"`
	MinRanges   int      `yaml:"min_ranges"`
}

var (
	configFile string
	dryRun     bool
	printOnly  bool
)

func init() {
	flag.StringVar(&configFile, "c", "./config.yml", "path to config.yml")
	flag.StringVar(&configFile, "config", "./config.yml", "path to config.yml")
	flag.BoolVar(&dryRun, "dry-run", false, "render + diff only, never write or reload")
	flag.BoolVar(&printOnly, "print", false, "print the current Myra ranges (one CIDR per line) and exit")
}

func main() {
	flag.Parse()
	os.Exit(run())
}

func run() int {
	cfg, err := loadConfig(configFile)
	if err != nil {
		fail("config: %v", err)
		return exitError
	}

	api, err := newAPI(cfg)
	if err != nil {
		fail("api: %v", err)
		return exitError
	}

	ranges, skipped, err := fetchRanges(api)
	if err != nil {
		fail("fetch: %v", err)
		return exitError
	}
	if printOnly {
		for _, r := range ranges {
			fmt.Println(r)
		}
		return exitUnchanged
	}
	if len(ranges) < cfg.MinRanges {
		fail("only %d ranges returned (min_ranges=%d) — refusing to touch %s", len(ranges), cfg.MinRanges, cfg.Snippet)
		return exitError
	}

	rendered := render(cfg, ranges)

	current, err := os.ReadFile(cfg.Snippet)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		fail("read %s: %v", cfg.Snippet, err)
		return exitError
	}

	added, removed := diffAllows(current, rendered)
	if len(added) == 0 && len(removed) == 0 && bytes.Equal(normalize(current), normalize(rendered)) {
		fmt.Printf("✅ myra-ranges: unchanged — %d Myra ranges (%d skipped: disabled/expired)\n", len(ranges), skipped)
		return exitUnchanged
	}

	fmt.Printf("🔄 myra-ranges: allow-list differs — %d Myra ranges now (%d skipped)\n", len(ranges), skipped)
	for _, a := range added {
		fmt.Printf("  + %s\n", a)
	}
	for _, r := range removed {
		fmt.Printf("  - %s\n", r)
	}

	if dryRun {
		fmt.Println("dry-run: nothing written, nginx untouched")
		return exitChanged
	}

	if err := apply(cfg, current, rendered); err != nil {
		fail("apply: %v", err)
		return exitError
	}
	fmt.Printf("applied to %s, nginx tested + reloaded (%s)\n", cfg.Snippet, time.Now().Format(time.RFC3339))
	return exitChanged
}

func loadConfig(path string) (*configuration, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &configuration{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	if cfg.Token == "" && (cfg.APIKey == "" || cfg.Secret == "") {
		return nil, errors.New("need either token or apikey+secret")
	}
	if cfg.Snippet == "" {
		cfg.Snippet = "/etc/nginx/snippets/myra-only.conf"
	}
	if cfg.NginxTest == "" {
		cfg.NginxTest = "nginx -t"
	}
	if cfg.NginxReload == "" {
		cfg.NginxReload = "systemctl reload nginx"
	}
	if cfg.MinRanges <= 0 {
		cfg.MinRanges = 8
	}
	for _, e := range cfg.ExtraAllow {
		if _, err := parseCIDR(e); err != nil {
			return nil, fmt.Errorf("extra_allow %q: %v", e, err)
		}
	}
	return cfg, nil
}

func newAPI(cfg *configuration) (*myrasec.API, error) {
	var (
		api *myrasec.API
		err error
	)
	if cfg.Token != "" {
		api, err = myrasec.NewWithToken(cfg.Token)
	} else {
		api, err = myrasec.New(cfg.APIKey, cfg.Secret)
	}
	if err != nil {
		return nil, err
	}
	api.UserAgent = "myra-ranges"
	return api, nil
}

// fetchRanges returns the enabled, currently valid Myra ranges as normalized,
// sorted, de-duplicated CIDR strings (IPv4 first), plus the number skipped.
func fetchRanges(api *myrasec.API) ([]string, int, error) {
	now := time.Now()
	seen := map[netip.Prefix]bool{}
	skipped := 0
	var prefixes []netip.Prefix

	for page := 1; page <= maxPages; page++ {
		params := map[string]string{
			"page":     strconv.Itoa(page),
			"pageSize": strconv.Itoa(pageSize),
		}
		list, err := api.ListIPRanges(params)
		if err != nil {
			return nil, 0, fmt.Errorf("page %d: %v", page, err)
		}
		for _, r := range list {
			if !r.Enabled {
				skipped++
				continue
			}
			if r.ValidFrom != nil && now.Before(r.ValidFrom.Time) {
				skipped++
				continue
			}
			if r.ValidTo != nil && now.After(r.ValidTo.Time) {
				skipped++
				continue
			}
			p, err := parseCIDR(r.Network)
			if err != nil {
				return nil, 0, fmt.Errorf("range %q (id %d): %v", r.Network, r.ID, err)
			}
			if !seen[p] {
				seen[p] = true
				prefixes = append(prefixes, p)
			}
		}
		if len(list) < pageSize {
			break
		}
	}
	if len(prefixes) == 0 {
		return nil, skipped, errors.New("Myra returned no usable ranges")
	}

	sort.Slice(prefixes, func(i, j int) bool {
		a, b := prefixes[i], prefixes[j]
		if a.Addr().Is4() != b.Addr().Is4() {
			return a.Addr().Is4()
		}
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c < 0
		}
		return a.Bits() < b.Bits()
	})

	out := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		out = append(out, p.String())
	}
	return out, skipped, nil
}

// parseCIDR accepts "a.b.c.d/nn", "a.b.c.d" (→ /32) and IPv6 equivalents,
// and normalizes to the masked network address.
func parseCIDR(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return p.Masked(), nil
}

func render(cfg *configuration, ranges []string) []byte {
	var b strings.Builder
	b.WriteString("# GENERATED by myra-ranges — do not edit by hand, edits are overwritten.\n")
	b.WriteString("# Origin lock-down: only the Myra CDN (and the extra_allow entries) may talk\n")
	b.WriteString("# to the public vhosts; everything else gets 403. Source: Myra API\n")
	b.WriteString("# (ListIPRanges, enabled + currently valid). Docs: home-setup/network/myra-ip-ranges.md\n")
	fmt.Fprintf(&b, "# %d Myra ranges.\n\n", len(ranges))

	if len(cfg.ExtraAllow) > 0 {
		b.WriteString("# extra_allow (config): local / LAN\n")
		for _, e := range cfg.ExtraAllow {
			p, _ := parseCIDR(e)
			fmt.Fprintf(&b, "allow %s;\n", cidrForNginx(p))
		}
		b.WriteString("\n")
	}

	b.WriteString("# Myra CDN\n")
	for _, r := range ranges {
		p, _ := netip.ParsePrefix(r)
		fmt.Fprintf(&b, "allow %s;\n", cidrForNginx(p))
	}
	b.WriteString("\ndeny all;\n")
	return []byte(b.String())
}

// cidrForNginx renders single hosts without the /32 or /128 suffix (nginx
// accepts both, but "allow 127.0.0.1;" reads better and matches the old file).
func cidrForNginx(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

// allowSet extracts the effective allow/deny lines (no comments, no blanks).
func allowSet(data []byte) map[string]bool {
	set := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		set[line] = true
	}
	return set
}

func normalize(data []byte) []byte {
	set := allowSet(data)
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return []byte(strings.Join(keys, "\n"))
}

func diffAllows(current, rendered []byte) (added, removed []string) {
	old, new := allowSet(current), allowSet(rendered)
	for k := range new {
		if !old[k] {
			added = append(added, k)
		}
	}
	for k := range old {
		if !new[k] {
			removed = append(removed, k)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return
}

func apply(cfg *configuration, current, rendered []byte) error {
	dir := filepath.Dir(cfg.Snippet)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	prev := cfg.Snippet + ".prev"
	if len(current) > 0 {
		if err := os.WriteFile(prev, current, 0o644); err != nil {
			return fmt.Errorf("write %s: %v", prev, err)
		}
	}

	tmp := cfg.Snippet + ".tmp"
	if err := os.WriteFile(tmp, rendered, 0o644); err != nil {
		return fmt.Errorf("write %s: %v", tmp, err)
	}
	if err := os.Rename(tmp, cfg.Snippet); err != nil {
		return fmt.Errorf("rename: %v", err)
	}

	if out, err := runCmd(cfg.NginxTest); err != nil {
		// roll back before reporting
		if len(current) > 0 {
			_ = os.WriteFile(cfg.Snippet, current, 0o644)
		} else {
			_ = os.Remove(cfg.Snippet)
		}
		return fmt.Errorf("%q failed, previous snippet restored:\n%s", cfg.NginxTest, out)
	}
	if out, err := runCmd(cfg.NginxReload); err != nil {
		return fmt.Errorf("%q failed (snippet already in place, config tested OK):\n%s", cfg.NginxReload, out)
	}
	return nil
}

func runCmd(cmdline string) (string, error) {
	parts := strings.Fields(cmdline)
	if len(parts) == 0 {
		return "", errors.New("empty command")
	}
	cmd := exec.Command(parts[0], parts[1:]...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func fail(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "❌ myra-ranges: "+format+"\n", args...)
}
