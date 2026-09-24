// Command gen refreshes ieee.csv from the IEEE MA-L (24-bit OUI) registry,
// keeping only "PREFIX,Organization" rows so the embedded file stays small.
//
//	go run ./internal/oui/gen            # download
//	go run ./internal/oui/gen -from f    # use an already downloaded oui.csv
package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

const sourceURL = "https://standards-oui.ieee.org/oui/oui.csv"

func main() {
	from := flag.String("from", "", "read the IEEE CSV from this file instead of downloading it")
	out := flag.String("out", "internal/oui/ieee.csv", "output path")
	flag.Parse()
	if err := run(*from, *out); err != nil {
		fmt.Fprintln(os.Stderr, "oui gen:", err)
		os.Exit(1)
	}
}

func run(from, out string) error {
	src, err := open(from)
	if err != nil {
		return err
	}
	defer src.Close()

	r := csv.NewReader(src)
	r.FieldsPerRecord = -1
	header, err := r.Read()
	if err != nil {
		return err
	}
	if len(header) < 3 || header[0] != "Registry" || header[1] != "Assignment" {
		return fmt.Errorf("unexpected header %q", header)
	}

	rows := map[string]string{}
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if len(rec) < 3 || rec[0] != "MA-L" {
			continue
		}
		prefix := strings.ToUpper(strings.TrimSpace(rec[1]))
		org := strings.Join(strings.Fields(rec[2]), " ")
		if len(prefix) == 6 && org != "" {
			rows[prefix] = org
		}
	}
	if len(rows) < 10000 {
		return fmt.Errorf("only %d MA-L rows; refusing to overwrite %s", len(rows), out)
	}
	prefixes := make([]string, 0, len(rows))
	for p := range rows {
		prefixes = append(prefixes, p)
	}
	sort.Strings(prefixes)

	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()
	fmt.Fprintf(f, "# IEEE MA-L registry from %s, fetched %s. Regenerate: make oui\n", sourceURL, time.Now().UTC().Format("2006-01-02"))
	w := csv.NewWriter(f)
	for _, p := range prefixes {
		if err := w.Write([]string{p, rows[p]}); err != nil {
			return err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return err
	}
	fmt.Printf("wrote %d MA-L prefixes to %s\n", len(prefixes), out)
	return nil
}

func open(from string) (io.ReadCloser, error) {
	if from != "" {
		return os.Open(from)
	}
	req, err := http.NewRequest(http.MethodGet, sourceURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "network-sweeper-oui-gen (+https://github.com/BVisagie/network-sweeper)")
	resp, err := (&http.Client{Timeout: 2 * time.Minute}).Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("download %s: %s", sourceURL, resp.Status)
	}
	return resp.Body, nil
}
