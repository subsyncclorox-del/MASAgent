// Package spider crawls the in-scope attack surface: pages, forms, parameters,
// and referenced JavaScript bundles. All fetching happens through the
// scopeguard proxy client, so the spider physically cannot leave scope.
package spider

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"golang.org/x/net/html"

	"github.com/masagent/recon/internal/client"
)

// Form is a discovered HTML form (a candidate injection surface).
type Form struct {
	Action string   `json:"action"`
	Method string   `json:"method"`
	Inputs []string `json:"inputs"`
}

// Page is one crawled URL and what was found on it.
type Page struct {
	URL     string   `json:"url"`
	Status  int      `json:"status"`
	Title   string   `json:"title"`
	Links   []string `json:"links"`
	Scripts []string `json:"scripts"`
	Forms   []Form   `json:"forms"`
	Params  []string `json:"params"`
}

// Result is the crawl output: a map of the surface the planner will read.
type Result struct {
	Seed    string          `json:"seed"`
	Pages   []Page          `json:"pages"`
	Scripts []string        `json:"scripts"`
	Params  map[string]bool `json:"-"`
}

// Crawler performs a same-origin BFS crawl bounded by MaxPages and Depth.
type Crawler struct {
	Client   *http.Client
	MaxPages int
	Depth    int
}

// New builds a Crawler with a scope-guarded client. It returns client.ErrNoProxy
// if no proxy is configured (fail closed).
func New(maxPages, depth int) (*Crawler, error) {
	c, err := client.New(0)
	if err != nil {
		return nil, err
	}
	return &Crawler{Client: c, MaxPages: maxPages, Depth: depth}, nil
}

// Crawl runs the BFS from seed. Only same-registrable-origin links are followed;
// out-of-scope links are recorded but the scopeguard would refuse them anyway.
func (c *Crawler) Crawl(ctx context.Context, seed string) (*Result, error) {
	base, err := url.Parse(seed)
	if err != nil {
		return nil, err
	}
	res := &Result{Seed: seed, Params: map[string]bool{}}
	seen := map[string]bool{}
	scripts := map[string]bool{}

	type item struct {
		u string
		d int
	}
	queue := []item{{seed, 0}}
	var mu sync.Mutex // guards res in case this is parallelized later

	for len(queue) > 0 && len(res.Pages) < c.MaxPages {
		it := queue[0]
		queue = queue[1:]
		if seen[it.u] || it.d > c.Depth {
			continue
		}
		seen[it.u] = true

		resp, err := client.Get(ctx, c.Client, it.u)
		if err != nil {
			continue
		}
		page := parsePage(it.u, resp, base)
		resp.Body.Close()

		mu.Lock()
		res.Pages = append(res.Pages, page)
		for _, s := range page.Scripts {
			if !scripts[s] {
				scripts[s] = true
				res.Scripts = append(res.Scripts, s)
			}
		}
		for _, p := range page.Params {
			res.Params[p] = true
		}
		mu.Unlock()

		for _, l := range page.Links {
			lu, err := url.Parse(l)
			if err != nil {
				continue
			}
			if sameOrigin(base, lu) && !seen[lu.String()] {
				queue = append(queue, item{lu.String(), it.d + 1})
			}
		}
	}
	return res, nil
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Hostname(), b.Hostname())
}

func parsePage(pageURL string, resp *http.Response, base *url.URL) Page {
	p := Page{URL: pageURL, Status: resp.StatusCode}
	u, _ := url.Parse(pageURL)
	if u != nil {
		for k := range u.Query() {
			p.Params = append(p.Params, k)
		}
	}
	doc, err := html.Parse(resp.Body)
	if err != nil {
		return p
	}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "title":
				if n.FirstChild != nil {
					p.Title = strings.TrimSpace(n.FirstChild.Data)
				}
			case "a":
				if href := attr(n, "href"); href != "" {
					if abs := resolve(base, href); abs != "" {
						p.Links = append(p.Links, abs)
					}
				}
			case "script":
				if src := attr(n, "src"); src != "" {
					if abs := resolve(base, src); abs != "" {
						p.Scripts = append(p.Scripts, abs)
					}
				}
			case "form":
				f := Form{Action: resolve(base, attr(n, "action")), Method: strings.ToUpper(attr(n, "method"))}
				if f.Method == "" {
					f.Method = "GET"
				}
				collectInputs(n, &f)
				p.Forms = append(p.Forms, f)
			}
		}
		for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
			walk(ch)
		}
	}
	walk(doc)
	return p
}

func collectInputs(form *html.Node, f *Form) {
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && (n.Data == "input" || n.Data == "textarea" || n.Data == "select") {
			if name := attr(n, "name"); name != "" {
				f.Inputs = append(f.Inputs, name)
			}
		}
		for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
			walk(ch)
		}
	}
	walk(form)
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func resolve(base *url.URL, ref string) string {
	if ref == "" || strings.HasPrefix(ref, "javascript:") || strings.HasPrefix(ref, "mailto:") || strings.HasPrefix(ref, "#") {
		return ""
	}
	u, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return base.ResolveReference(u).String()
}
