package himama

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

const DefaultHost = "www.himama.com" // default original host
const BaseURL = "https://" + DefaultHost
const LoginURL = BaseURL + "/login"

type Client struct {
	client *http.Client
	Hostname string
}

func NewClient(username, password, hostname string) (*Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize cookie jar: %w", err)
	}

	client := http.Client{
		Jar: jar,
	}
	
	// Use Lillio/Himama tenant URL if provided; otherwise use LoginURL default
	loginUrlToUse, err := determineLoginUrlToUse(hostname)
	if err != nil {
		return nil, fmt.Errorf("unable to determine login URL to use - loginUrlToUse: %s , error: %w", loginUrlToUse, err)
	}
	
	if csrfToken, err := getLoginForm(&client, loginUrlToUse); err != nil {
		return nil, err
	} else if err := postLoginForm(&client, csrfToken, username, password, loginUrlToUse); err != nil {
		return nil, err
	}

	return &Client{
		client: &client,
		// Use Lillio/Himama tenant URL if provided instead of BaseURL later
		Hostname: hostname,
	}, nil
}

func (c *Client) FetchChildren() ([]Child, error) {
	baseUrlToUse, err := determineBaseUrlToUse(c.Hostname)
		if err != nil {
		return nil, fmt.Errorf("unable to determine base URL to use - baseUrlToUse: %s , error: %w", baseUrlToUse, err)
	}
	
	re := regexp.MustCompile(`^/accounts/\d+$`)
	res, err := c.client.Get(baseUrlToUse + "/headlines")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch children: %w", err)
	}
	defer res.Body.Close()

	results, err := filterTags(res.Body, func(node *html.Node) bool {
		if node.Type == html.ElementNode && node.Data == "a" {
			for _, attr := range node.Attr {
				if attr.Key == "href" && re.MatchString(attr.Val) {
					return true
				}
			}
		}
		return false
	})

	if err != nil {
		return nil, fmt.Errorf("failed to fetch children: %w", err)
	}

	children := []Child{}

	for _, result := range results {
		// find the href attribute and extract the account ID
		var id string
		for _, attr := range result.Attr {
			if attr.Key == "href" {
				parts := strings.Split(attr.Val, "/")
				id = parts[len(parts)-1]
				break
			}
		}
		children = append(children, Child{
			Name: strings.TrimSpace(result.FirstChild.Data),
			ID:   id,
		})
	}

	return children, nil
}

func (c *Client) Activities(child Child, page int) ([]Activity, error) {

	results := []Activity{}

	baseUrlToUse, err := determineBaseUrlToUse(c.Hostname)
		if err != nil {
		return nil, fmt.Errorf("unable to determine base URL to use - baseUrlToUse: %s , error: %w", baseUrlToUse, err)
	}

	url := fmt.Sprintf("%s/accounts/%s/activities?page=%d", baseUrlToUse, child.ID, page)
	res, err := c.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	rows, err := filterTags(res.Body, func(n *html.Node) bool {
		return n.Type == html.ElementNode && n.Data == "tr"
	})
	if err != nil {
		return nil, err
	}

	for _, row := range rows {
		addedBy := nodeText(nthChild(row, 1))
		date := nodeText(nthChild(row, 3))
		title := ""
		if n := nthChild(row, 5).FirstChild.NextSibling; n != nil {
			title = n.FirstChild.Data
		}
		url := ""
		if n := nthChild(row, 17); n != nil && n.FirstChild != nil {
			n = n.FirstChild.NextSibling

			if n != nil && n.Data == "a" {
				for _, attr := range n.Attr {
					if attr.Key == "href" {
						url = attr.Val
						break
					}
				}
			}
		}

		if url != "" {
			results = append(results, Activity{
				AddedBy:  addedBy,
				Date:     date,
				Title:    title,
				MediaURL: url,
			})
		}
	}

	return results, nil
}

// getLoginForm fetches the login form, decorates client (via its cookiejar) with a session cookie,
// and extracts the csrf-token from the response body so it can be used in postLoginForm to submit credentials
func getLoginForm(client *http.Client, loginUrlToUse string) (csrfToken []byte, err error) {
	// First, fetch the login form so we can extract the cookie and authenticity token
	res, err := client.Get(loginUrlToUse)
	if err != nil {
		return nil, fmt.Errorf("unable to get %s: %w", loginUrlToUse, err)
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("GET %s: Unxpected response %d (want 200)", loginUrlToUse, res.StatusCode)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("GET %s: Failed reading response body: %w", loginUrlToUse, err)
	}

	// TODO: Using regex to parse HTML? Why not.
	re := regexp.MustCompile(`<meta name=csrf-token content=([a-zA-Z0-9\/+_-]+) *\/>`)
	match := re.FindSubmatch(body)
	if len(match) != 2 {
		//return nil, fmt.Errorf("GET %s in %s: Cannot find authenticity token in response", loginUrlToUse, body)
		return nil, fmt.Errorf("GET %s: Cannot find authenticity token in response", loginUrlToUse)
	}

	csrfToken = match[1]

	return csrfToken, nil
}

// postLoginForm submits the login request and decorates the given client (via its cookie jar) with authentication
func postLoginForm(client *http.Client, csrfToken []byte, username, password, loginUrlToUse string) error {
	data := url.Values{}
	data.Set("authenticity_token", string(csrfToken))
	data.Set("utf8", "✓")
	data.Set("user[login]", username)
	data.Set("user[password]", password)
	data.Set("user[remember_me]", "0")
	res, err := client.PostForm(loginUrlToUse, data)
	if err != nil {
		return fmt.Errorf("POST %s Error: %w", loginUrlToUse, err)
	}

	// TODO: Detect login failure

	defer res.Body.Close()

	return nil
}

func filterTags(htmlDoc io.Reader, filter func(*html.Node) bool) ([]*html.Node, error) {
	doc, err := html.Parse(htmlDoc)
	if err != nil {
		return nil, fmt.Errorf("error parsing HTML: %w", err)
	}

	results := []*html.Node{}

	// Recurisively scans the document for any tags for which the given filter function return true
	var f func(*html.Node)
	f = func(n *html.Node) {
		if filter(n) {
			results = append(results, n)
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	return results, nil
}

func nodeText(n *html.Node) string {
	child := n.FirstChild
	if child == nil {
		return ""
	}
	if child.Type == html.TextNode {
		return strings.TrimSpace(child.Data)
	} else {
		return ""
	}
}

func nthChild(n *html.Node, index int) *html.Node {
	c := n.FirstChild
	for i := 0; i < index; i++ {
		c = c.NextSibling
		if c == nil {
			break
		}
	}
	return c
}

func determineBaseUrlToUse(hostname string) (baseUrlToUse string, err error) {
	if hostname == "" {
		return BaseURL, nil
	}
	
	return "https://" + hostname, nil
}

func determineLoginUrlToUse(hostname string) (loginUrlToUse string, err error) {
	if hostname == "" {
		return LoginURL, nil
	}
	
	return "https://" + hostname + "/login", nil
}