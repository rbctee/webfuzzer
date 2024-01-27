package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

const (
	MISSING_WORDLIST    = 1
	MISSING_URL         = 2
	MISSING_FUZZ        = 3
	FILE_NOT_EXISTS     = 4
	ERR_CREATE_HTTP_REQ = 5
	ERR_SEND_HTTP_REQ   = 6
	ERR_READ_HTTP_RESP  = 7
)

var (
	WarningLog *log.Logger
	InfoLog    *log.Logger
	ErrorLog   *log.Logger
)

func main() {
	InfoLog = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime)
	WarningLog = log.New(os.Stdout, "WARNING: ", log.Ldate|log.Ltime)
	ErrorLog = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime)

	wordlist := flag.String("wordlist", "/usr/share/wordlists/common.txt", "Wordlist to use for Fuzzing")
	// url := flag.String("url", "", "URL with FUZZ keywords. Examples:\n\thttp://example.com/FUZZ\n\thttp://example.com/search?key=FUZZ\n\thttp://example.com/admin.php?FUZZ=FUZZ2")
	url := flag.String("url", "", "URL with FUZZ keywords. Examples:\n\thttp://example.com/FUZZ")
	httpMethod := flag.String("method", "GET", "HTTP Method")
	excludeSize := flag.Int("exclude-size", -1, "Exclude HTTP responses with this size")
	excludeLines := flag.Int("exclude-lines", -1, "Exclude HTTP responses with this num. of lines")
	// excludeRegex := flag.Int("exclude-regex", -1, "Exclude HTTP responses including this regex")

	flag.Parse()

	if *wordlist == "" {
		WarningLog.Printf("Missing wordlist\n")
		flag.Usage()
		os.Exit(MISSING_WORDLIST)
	}

	if *url == "" {
		WarningLog.Printf("Missing URL")
		flag.Usage()
		os.Exit(MISSING_URL)
	} else if !strings.Contains(*url, "FUZZ") {
		WarningLog.Printf("URL is missing FUZZ keyword")
		os.Exit(MISSING_FUZZ)
	}

	serverURL := *url

	InfoLog.Printf("Attacking URL: %s\n", serverURL)

	file, err := os.Open(*wordlist)
	if err != nil {
		ErrorLog.Printf("Error opening file\n\t%s\n", err)
		os.Exit(FILE_NOT_EXISTS)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if scanner.Err() != nil {
		ErrorLog.Printf("Error reading file\n\t%s\n", scanner.Err())
	}

	InfoLog.Printf("Using wordlist %s\n", *wordlist)

	/*
	   Iterate through the wordlist lines and send HTTP requests
	*/

	for _, v := range lines {
		newURL := strings.ReplaceAll(serverURL, "FUZZ", v)

		req, err := http.NewRequest(*httpMethod, newURL, nil)
		if err != nil {
			ErrorLog.Printf("Failed to create HTTP request: %s\n", err)
			os.Exit(ERR_CREATE_HTTP_REQ)
		}

		res, err := http.DefaultClient.Do(req)
		if err != nil {
			ErrorLog.Printf("Failed to send HTTP request: %s\n", err)
			os.Exit(ERR_SEND_HTTP_REQ)
		}

		var respLines []string
		scanner := bufio.NewScanner(res.Body)

		for scanner.Scan() {
			respLines = append(respLines, scanner.Text())
		}
		if scanner.Err() != nil {
			ErrorLog.Printf("Error reading file\n\t%s\n", scanner.Err())
		}

		showResp := true
		if *excludeSize == int(res.ContentLength) {
			showResp = false
		}

		if *excludeLines == len(respLines) {
			showResp = false
		}

		if showResp {
			fmt.Printf("%s\t\t\t%d\t%d\n", v, res.ContentLength, len(respLines))
		}
	}
}
