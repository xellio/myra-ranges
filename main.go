// myra-ranges keeps a web server's IP allow-list in sync with the Myra CDN's
// published IP ranges. Supported servers are listed in serverTypes (currently
// nginx and HAProxy).
//
// It fetches the ranges via the Myra API (myrasec-go), renders them (plus
// configured extra allows) in the format of the configured server, compares
// the result with the file currently on disk and - unless --dry-run -
// replaces it, runs the server's config test and reloads it. If the test
// fails the previous file is restored.
//
// Exit codes: 0 = no change, 3 = changed (applied or would be with --dry-run),
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
	APIKey     string   `yaml:"apikey"`
	Secret     string   `yaml:"secret"`
	Token      string   `yaml:"token"`
	Server     string   `yaml:"server"`
	Output     string   `yaml:"output"`
	Test       string   `yaml:"test"`
	Reload     string   `yaml:"reload"`
	ExtraAllow []string `yaml:"extra_allow"`
	MinRanges  int      `yaml:"min_ranges"`
}

// serverType describes one supported web server: the defaults for output,
// test and reload, and how the allow-list file is rendered. Adding a server
// means adding an entry to serverTypes (and, if its file format is new, teaching
// canonicalRule to read it back).
type serverType struct {
	output, test, reload string

	// entry renders one allowed network as a line of the file.
	entry func(netip.Prefix) string
	// footer is appended after the last entry.
	footer string
}

var serverTypes = map[string]serverType{
	// nginx: snippet included in each server {} block.
	"nginx": {
		output: "/etc/nginx/snippets/myra-only.conf",
		test:   "nginx -t",
		reload: "systemctl reload nginx",
		entry:  func(p netip.Prefix) string { return "allow " + formatCIDR(p) + ";" },
		footer: "\ndeny all;\n",
	},
	// HAProxy: ACL pattern file, the deny is done by the ACL in haproxy.cfg.
	"haproxy": {
		output: "/etc/haproxy/myra-only.lst",
		test:   "haproxy -c -f /etc/haproxy/haproxy.cfg",
		reload: "systemctl reload haproxy",
		entry:  formatCIDR,
	},
}

func serverNames() []string {
	names := make([]string, 0, len(serverTypes))
	for name := range serverTypes {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

var (
	configFile string
	dryRun     bool
	printOnly  bool
	force      bool
)

func init() {
	flag.StringVar(&configFile, "c", "./config.yml", "path to config.yml")
	flag.StringVar(&configFile, "config", "./config.yml", "path to config.yml")
	flag.BoolVar(&dryRun, "dry-run", false, "render + diff only, never write or reload")
	flag.BoolVar(&printOnly, "print", false, "print the current Myra ranges (one CIDR per line) and exit")
	flag.BoolVar(&force, "force", false, "write + test + reload even if the effective rules are unchanged (e.g. to replace a hand-written file)")
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
		fail("only %d ranges returned (min_ranges=%d) - refusing to touch %s", len(ranges), cfg.MinRanges, cfg.Output)
		return exitError
	}

	rendered := render(cfg, ranges)

	current, err := os.ReadFile(cfg.Output)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		fail("read %s: %v", cfg.Output, err)
		return exitError
	}

	added, removed := diffAllows(current, rendered)
	unchanged := len(added) == 0 && len(removed) == 0 && bytes.Equal(normalize(current), normalize(rendered))
	if unchanged && !force {
		fmt.Printf("myra-ranges: unchanged - %d Myra ranges (%d skipped: disabled/expired)\n", len(ranges), skipped)
		return exitUnchanged
	}

	if unchanged {
		fmt.Printf("myra-ranges: --force - rules unchanged, rewriting file anyway (%d Myra ranges, %d skipped)\n", len(ranges), skipped)
	} else {
		fmt.Printf("myra-ranges: allow-list differs - %d Myra ranges now (%d skipped)\n", len(ranges), skipped)
	}
	for _, a := range added {
		fmt.Printf("  + %s\n", a)
	}
	for _, r := range removed {
		fmt.Printf("  - %s\n", r)
	}

	if dryRun {
		fmt.Printf("dry-run: nothing written, %s untouched\n", cfg.Server)
		return exitChanged
	}

	if err := apply(cfg, current, rendered); err != nil {
		fail("apply: %v", err)
		return exitError
	}
	fmt.Printf("applied to %s, %s tested + reloaded (%s)\n", cfg.Output, cfg.Server, time.Now().Format(time.RFC3339))
	return exitChanged
}

func loadConfig(path string) (*configuration, error) {
	if info, err := os.Stat(path); err == nil && info.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(os.Stderr, "warning: %s is readable by group/others (mode %04o) and holds API credentials, chmod 600 recommended\n", path, info.Mode().Perm())
	}
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
	if cfg.Server == "" {
		cfg.Server = "nginx"
	}
	defaults, ok := serverTypes[cfg.Server]
	if !ok {
		return nil, fmt.Errorf("server %q: must be one of %s", cfg.Server, strings.Join(serverNames(), ", "))
	}
	if cfg.Output == "" {
		cfg.Output = defaults.output
	}
	if cfg.Test == "" {
		cfg.Test = defaults.test
	}
	if cfg.Reload == "" {
		cfg.Reload = defaults.reload
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
		if len(list) == 0 {
			break
		}
		newOnPage := 0
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
				newOnPage++
			}
		}
		// Stop on a short page (normal end) or when a page brought nothing new
		// (an API that ignores the page parameter would otherwise loop to maxPages).
		if len(list) < pageSize || (page > 1 && newOnPage == 0) {
			break
		}
		if page == maxPages {
			fmt.Fprintf(os.Stderr, "warning: stopped after %d pages, list may be incomplete\n", maxPages)
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

// parseCIDR accepts "a.b.c.d/nn", "a.b.c.d" (-> /32) and IPv6 equivalents,
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

// render produces the allow-list file in the format of cfg.Server
// (which loadConfig has validated).
func render(cfg *configuration, ranges []string) []byte {
	server := serverTypes[cfg.Server]

	var b strings.Builder
	b.WriteString("# GENERATED by myra-ranges - do not edit by hand, edits are overwritten.\n")
	b.WriteString("# Origin lock-down: only the Myra CDN (and the extra_allow entries) may talk\n")
	b.WriteString("# to the public frontends. Source: Myra API\n")
	b.WriteString("# (ListIPRanges, enabled + currently valid). https://github.com/xellio/myra-ranges\n")
	fmt.Fprintf(&b, "# %d Myra ranges.\n\n", len(ranges))

	if len(cfg.ExtraAllow) > 0 {
		b.WriteString("# extra_allow (config): local / LAN\n")
		for _, e := range cfg.ExtraAllow {
			p, _ := parseCIDR(e)
			b.WriteString(server.entry(p) + "\n")
		}
		b.WriteString("\n")
	}

	b.WriteString("# Myra CDN\n")
	for _, r := range ranges {
		p, _ := netip.ParsePrefix(r)
		b.WriteString(server.entry(p) + "\n")
	}
	b.WriteString(server.footer)
	return []byte(b.String())
}

// formatCIDR renders single hosts without the /32 or /128 suffix (nginx and
// HAProxy accept both, but "127.0.0.1" reads better and matches the old file).
func formatCIDR(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

// allowSet extracts the effective rules (no comments, no blanks): nginx
// allow/deny lines or bare HAProxy pattern lines, with the address part
// canonicalized so "allow 1.2.3.4/32;" and "allow 1.2.3.4;" (or masked/unmasked
// prefixes) compare equal.
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
		set[canonicalRule(line)] = true
	}
	return set
}

// canonicalRule normalizes "allow X;" / "deny X;" (nginx) and a bare "X"
// (HAProxy pattern file) to a single spelling of X.
func canonicalRule(line string) string {
	fields := strings.Fields(strings.TrimSuffix(line, ";"))
	if len(fields) == 1 && !strings.HasSuffix(line, ";") {
		if p, err := parseCIDR(fields[0]); err == nil {
			return formatCIDR(p)
		}
	}
	if len(fields) == 2 && (fields[0] == "allow" || fields[0] == "deny") && fields[1] != "all" {
		if p, err := parseCIDR(fields[1]); err == nil {
			return fields[0] + " " + formatCIDR(p) + ";"
		}
	}
	return strings.Join(fields, " ") + ";"
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
	before, after := allowSet(current), allowSet(rendered)
	for k := range after {
		if !before[k] {
			added = append(added, k)
		}
	}
	for k := range before {
		if !after[k] {
			removed = append(removed, k)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return
}

func apply(cfg *configuration, current, rendered []byte) error {
	dir := filepath.Dir(cfg.Output)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	prev := cfg.Output + ".prev"
	if len(current) > 0 {
		if err := os.WriteFile(prev, current, 0o644); err != nil {
			return fmt.Errorf("write %s: %v", prev, err)
		}
	}

	tmp := cfg.Output + ".tmp"
	if err := os.WriteFile(tmp, rendered, 0o644); err != nil {
		return fmt.Errorf("write %s: %v", tmp, err)
	}
	if err := os.Rename(tmp, cfg.Output); err != nil {
		return fmt.Errorf("rename: %v", err)
	}

	if out, err := runCmd(cfg.Test); err != nil {
		// roll back before reporting
		if len(current) > 0 {
			_ = os.WriteFile(cfg.Output, current, 0o644)
		} else {
			_ = os.Remove(cfg.Output)
		}
		return fmt.Errorf("%q failed, previous file restored:\n%s", cfg.Test, out)
	}
	if out, err := runCmd(cfg.Reload); err != nil {
		return fmt.Errorf("%q failed (file already in place, config tested OK):\n%s", cfg.Reload, out)
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
	fmt.Fprintf(os.Stderr, "myra-ranges: "+format+"\n", args...)
}
