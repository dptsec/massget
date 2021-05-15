package main

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Task struct {
	Mode              int
	MatchCode         string
	FindFuzz          bool
	FollowRedirect    bool
	URL               string
	Method            string
	Header            string
	Timeout           int
	PathNormalization bool
	IgnoreExt         bool
        FileList        string
}

var defaultHeaders = []string{"Content-Type", "Server", "X-Powered-By", "Location"}
var ignoreExtensions = []string{"jpg", "jpeg", "gif", "bmp", "tiff", "ttf", "tif", "ico", "svg", "png", "woff", "woff2", "mp3", "mp4", "mpg", "css", "txt"}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func ignoreExtension(path string) bool {
	u, _ := url.Parse(path)
	ext := filepath.Ext(u.Path)
	for _, v := range ignoreExtensions {
		if strings.Contains(ext, v) {
			return true
		}
	}
	return false
}

/* TODO: establish baseline request for "/..;/" payload to prevent legitimate 200 response from providing false positive */
func tryNormalize(endpoint string, task Task) {
	u, _ := url.Parse(endpoint)
	levels := strings.Count(u.Path, "/")
	attemptUrl := endpoint + ";/" + strings.Repeat("../", levels) + strings.TrimPrefix(u.Path, "/")
	if fetch(attemptUrl, task) == 404 {
		fmt.Printf("[*] Potential hit: %s\n", attemptUrl)
	}

	/*
		attemptUrl = endpoint + "/..;/"
		if fetch(attemptUrl, task) == 200 {
			fmt.Printf("[*] Potential hit: %s\n", attemptUrl)
		}
	*/
}
func randomPath() string {
	const possible = "abcdefghijklmnopqrstuvwxyz0123456789"

	b := make([]byte, 16)
	for i := range b {
		b[i] = possible[rand.Int63()%int64(len(possible))]
	}

	return "/" + string(b)
}

/* Try to find a candidate for discovery fuzzing */
func findFuzzTarget(url string, task Task, respCode int) bool {
	var codes = []int{301, 302, 303, 304, 305, 401, 403, 404}

	for _, v := range codes {
		if respCode == v {
			if fetch(url+randomPath(), task) == 404 {
				return true
			}
		}
	}
	return false
}

func matchCodes(match string, status string) bool {
	for _, code := range strings.Split(match, ",") {
		if code == "" {
			continue
		}

		if code == "all" || strings.Contains(status, code) {
			return true
		}
	}

	return false
}

func getHeaders(headers http.Header) []string {
	var found []string
	for _, h := range defaultHeaders {
		v := headers.Get(h)
		if v == "" {
			v = "UNKNOWN"
		}
		found = append(
			found,
			strings.Split(v, ";")[0],
		)
	}

	return found
}

func fetch(host string, task Task) int {
	var client *http.Client

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(task.Timeout)*time.Second)
	defer cancel()

	client = &http.Client{CheckRedirect: nil}
	if task.FollowRedirect == false {
		client = &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	req, err := http.NewRequestWithContext(ctx, task.Method, host, nil)
	if err != nil {
		return -1
	}

	if task.Header != "" {
		req.Header.Set("Host", task.Header)
	}

	resp, err := client.Do(req)
	if err != nil {
		return -1
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Printf("[-] Error: %v\n", err)
		}
	}(resp.Body)

        /* just return the status code if we're using any special scan modes */
	if matchCodes(task.MatchCode, resp.Status) && resp.StatusCode != http.StatusSwitchingProtocols && !task.FindFuzz && !task.PathNormalization {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("[-] Error: %v\n", err)
			return resp.StatusCode
		}
		fmt.Printf("%d %d %s %s %s %x\n", resp.StatusCode, len(bodyBytes), host, resp.Proto, strings.Join(getHeaders(resp.Header), " "), md5.Sum(bodyBytes))
	}

	return resp.StatusCode
}

func main() {
	var concurrency int
	var task Task
	var probe bool
	ports := []string{"81", "300", "591", "593", "832", "981", "1010", "1311", "2082", "2087", "2095", "2096", "2480", "3000", "3128", "3333", "4243", "4567", "4711", "4712", "4993", "5000", "5104", "5108", "5800", "6543", "7000", "7396", "7474", "8000", "8001", "8008", "8014", "8042", "8069", "8080", "8081", "8088", "8090", "8091", "8118", "8123", "8172", "8222", "8243", "8280", "8281", "8333", "8443", "8500", "8834", "8880", "8888", "8983", "9000", "9043", "9060", "9080", "9090", "9091", "9200", "9443", "9800", "9981", "12443", "16080", "18091", "18092", "20720", "28017"}

	flag.StringVar(&task.Method, "X", "GET", "HTTP method")
	flag.IntVar(&concurrency, "c", 60, "Number of concurrent requests")
	flag.IntVar(&task.Timeout, "t", 5, "Timeout (seconds)")
	flag.StringVar(&task.MatchCode, "mc", "all", "Return only URL's matching HTTP response code")
	flag.StringVar(&task.Header, "H", "", "Host header")
        flag.StringVar(&task.FileList, "F", "", "File containing paths to grab")
	flag.BoolVar(&task.FollowRedirect, "f", false, "Follow redirects")
	flag.BoolVar(&probe, "p", false, "Use httprobe mode")
	flag.BoolVar(&task.FindFuzz, "fz", false, "Find fuzzing targets (403/redirect on root, 404/200 on /random_file)")
	flag.BoolVar(&task.PathNormalization, "P", false, "Check for path normalization issues")
	flag.BoolVar(&task.IgnoreExt, "I", false, "Ignore common file extensions")
	flag.Parse()

	timeout := time.Duration(task.Timeout) * time.Second
	http.DefaultTransport = &http.Transport{
		IdleConnTimeout:       time.Second,
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ForceAttemptHTTP2:     false,
		DisableCompression:    true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: time.Second,
		}).DialContext,
	}

	tasks := make(chan string, concurrency*20)
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for originalUrl := range tasks {
				respCode := fetch(originalUrl, task)
				if respCode == -1 {
					continue
				}
				if task.PathNormalization && respCode != 404 {
					tryNormalize(originalUrl, task)
					continue
				}
				if task.FindFuzz && findFuzzTarget(originalUrl, task, respCode) {
					fmt.Printf("[*] %s is fuzzable for discovery\n", originalUrl)
				}
			}
		}()
	}

	input := bufio.NewScanner(os.Stdin)
	for input.Scan() {
		current := input.Text()
		if probe {
			tasks <- "http://" + current
			tasks <- "https://" + current
			for _, port := range ports {
				tasks <- "https://" + current + ":" + port
			}
		} else {
			if !strings.HasPrefix(current, "http://") && !strings.HasPrefix(current, "https://") {
				current = "https://" + current
			}
			if task.IgnoreExt && ignoreExtension(current) {
				continue
			}
			tasks <- current
                        if task.FileList != "" {
                                file, err := os.Open(task.FileList)
                                if err != nil {
                                        fmt.Printf("[!] Unable to open file %s. Skipping.\n", task.FileList)
                                        task.FileList = ""
                                        continue
                                }

                                defer file.Close()
                                fileInput := bufio.NewScanner(file)
                                for fileInput.Scan() {
                                        tasks <- current + fileInput.Text()
                                }
                        }
		}
	}

	close(tasks)
	wg.Wait()
}
