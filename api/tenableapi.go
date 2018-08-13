package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"strconv"
)

const baseURL string = "https://cloud.tenable.com/"

type Client struct {
	UserAgent  string
	httpClient *http.Client
	AccessKey  string
	SecretKey  string
}

func NewClient(httpClient *http.Client, accessKey string, secretKey string) *Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	return &Client{
		httpClient: httpClient,
		AccessKey:  accessKey,
		SecretKey:  secretKey,
	}
}

func (c *Client) AssetInfo(id string) (*AssetInfo, error) {
	fmt.Println("THREE!")
	path := "/workbenches/assets/" + id + "/info"
	req, err := c.newRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	result, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var assetInfo AssetInfo
	err = json.Unmarshal(result, &assetInfo)

	if err != nil {
		return nil, err
	}
	return &assetInfo, err
}

func (c *Client) ListVulnerabilities(days int)(*VulnerabilitiesList, error) {
	path := "/workbenches/vulnerabilities/"
	req, err := c.newRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	q := req.URL.Query()
	q.Add("date_range", strconv.Itoa(days))
	req.URL.RawQuery = q.Encode()

	result, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var assetVulnerabilitiesList VulnerabilitiesList
	err = json.Unmarshal(result, &assetVulnerabilitiesList)

	if err != nil {
		return nil, err
	}
	return &assetVulnerabilitiesList, err
}

func (c *Client) ListVulnerabilitiesBySeverity(severity Severity, state string, days int)(*VulnerabilitiesList, error) {
	path := "/workbenches/vulnerabilities"
	req, err := c.newRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	q := req.URL.Query()
	q.Add("severity", severity.String())
	q.Add("date_range", strconv.Itoa(days))

	if (state != ""){
		q.Add("filter.1.quality", "eq")
		q.Add("filter.1.filter", "tracking.state")
		q.Add("filter.1.value", state)
	}

	req.URL.RawQuery = q.Encode()
	fmt.Println(req.URL)
	result, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var assetVulnerabilitiesList VulnerabilitiesList
	err = json.Unmarshal(result, &assetVulnerabilitiesList)

	if err != nil {
		return nil, err
	}
	return &assetVulnerabilitiesList, err
}

func (c *Client) AssetVulnerabilityInfo(assetId string, vulnId string) (*AssetVulnerabilityInfo, error) {
	path := "/workbenches/assets/" + assetId + "/vulnerabilities/" + vulnId + "/info"
	fmt.Println(path)
	req, err := c.newRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	result, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var assetVulnerabilityInfo AssetVulnerabilityInfo
	err = json.Unmarshal(result, &assetVulnerabilityInfo)

	if err != nil {
		return nil, err
	}
	return &assetVulnerabilityInfo, err
}

func (c *Client) ListAssetVulnerabilities(id string) (*VulnerabilitiesList, error) {
	path := "/workbenches/assets/" + id + "/vulnerabilities"
	req, err := c.newRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	result, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var assetVulnerabilitiesList VulnerabilitiesList
	err = json.Unmarshal(result, &assetVulnerabilitiesList)

	if err != nil {
		return nil, err
	}
	return &assetVulnerabilitiesList, err
}

func (c *Client) ListScans() (*ScansList, error) {
	path := "/scans"
	req, err := c.newRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	result, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var scansList ScansList
	err = json.Unmarshal(result, &scansList)

	if err != nil {
		return nil, err
	}

	return &scansList, err
}

func (c *Client) ScanDetails(id string) (*ScanDetails, error) {
	path := "/scans/" + id
	req, err := c.newRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	result, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var scanDetails ScanDetails
	err = json.Unmarshal(result, &scanDetails)

	if err != nil {
		return nil, err
	}
	return &scanDetails, err
}

func (c *Client) ScanDetailsWithChannel(id string, ch chan<- *ScanDetails) {
	path := "/scans/" + id
	req, err := c.newRequest("GET", path, nil)
	if err != nil {
		log.Fatal(err)
	}

	result, err := c.do(req)
	if err != nil {
		log.Fatal(err)
	}
	var scanDetails ScanDetails
	err = json.Unmarshal(result, &scanDetails)

	if err != nil {
		log.Fatal(err)
	}
	ch <- &scanDetails
}

func (c *Client) ListAssets() (*AssetsList, error) {
	req, err := c.newRequest("GET", "/assets", nil)
	if err != nil {
		return nil, err
	}

	result, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var assetsList AssetsList
	err = json.Unmarshal(result, &assetsList)

	if err != nil {
		return nil, err
	}
	return &assetsList, err
}

func (c *Client) ListTargetGroups() (*TargetGroupsList, error) {
	req, err := c.newRequest("GET", "/target-groups", nil)
	if err != nil {
		return nil, err
	}

	result, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var targetGroupList TargetGroupsList
	err = json.Unmarshal(result, &targetGroupList)
	//fmt.Println(result)
	if err != nil {
		return nil, err
	}
	return &targetGroupList, err
}

func (c *Client) newRequest(method, path string, body interface{}) (*http.Request, error) {
	rel := &url.URL{Path: path}
	b, err := url.Parse(baseURL)
	u := b.ResolveReference(rel)

	var buf io.ReadWriter
	if body != nil {
		buf = new(bytes.Buffer)
		err := json.NewEncoder(buf).Encode(body)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequest(method, u.String(), buf)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	var keysHeader = fmt.Sprintf("accessKey=%s;secretKey=%s", c.AccessKey, c.SecretKey)
	req.Header.Add("X-ApiKeys", keysHeader)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)

	return req, nil
}

func (c *Client) do(req *http.Request) ([]byte, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if strings.Contains(string(body), `"statusCode":401`) {
		log.Fatal("ERROR: Your secretKey and accessKey (credentials) are invalid. ")
	}

	if 200 != resp.StatusCode {
		return nil, fmt.Errorf("%s", body)
	}
	//err = json.NewDecoder(resp.Body).Decode(v)
	return body, err
}
