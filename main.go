package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
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

func getStats(r io.Reader) (numChars int, numLines int, err error) {
	bufSize := 32 * 1024
	buf := make([]byte, bufSize)

	lineSep := []byte{'\n'}

	numChars = 0
	numLines = 0

	for {
		c, err := r.Read(buf)
		numChars += c
		numLines += bytes.Count(buf[:c], lineSep)

		switch {
		case err == io.EOF:
			return numChars, numLines, nil

		case err != nil:
			return numChars, numLines, err
		}
	}
}

// Presume that the regex does NOT span over 2 kilobytes
func searchRegex(excludeRegex string, r io.Reader) (foundMatch bool, numChars int, numLines int, err error) {
	bufSize := 32 * 1024
	buf := make([]byte, bufSize)
	rollingBufSize := 4096
	var rollingBuf bytes.Buffer

	lineSep := []byte{'\n'}

	foundMatch = false
	numChars = 0
	numLines = 0

	regex := regexp.MustCompile(excludeRegex)

	for {
		c, err := r.Read(buf)
		numChars += c
		numLines += bytes.Count(buf[:c], lineSep)

		if c <= bufSize {
			if regex.FindIndex(buf) != nil {
				foundMatch = true
			}

			return foundMatch, numChars, numLines, nil
		}

		if rollingBuf.Len() == rollingBufSize {
			rollingBuf.Reset()
		} else if rollingBuf.Len() == 0 {
			startIndex := c - (rollingBufSize / 2)
			rollingBuf.Write(buf[startIndex:])
		} else if rollingBuf.Len() == (rollingBufSize / 2) {
			endIndex := c - 1
			if c >= (rollingBufSize / 2) {
				endIndex = (rollingBufSize / 2) - 1
			}

			rollingBuf.Write(buf[:endIndex])
		}

		if rollingBuf.Len() == rollingBufSize {
			if regex.FindIndex(buf) != nil {
				foundMatch = true
			}

			if c < bufSize {
				return foundMatch, numChars, numLines, nil
			}

			switch {
			case err == io.EOF:
				return foundMatch, numChars, numLines, nil

			case err != nil:
				return foundMatch, numChars, numLines, err
			}
		}
	}
}

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
	excludeRegex := flag.String("exclude-regex", "", "Exclude HTTP responses including this regex")

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

	if *excludeRegex != "" {
		_, err := regexp.Compile(*excludeRegex)
		if err != nil {
			ErrorLog.Printf("Invalid regex: %s\n", err)
		}
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

	fmt.Printf("Word\t\t\tSize\tLines\n")
	for _, v := range lines {
		newURL := strings.ReplaceAll(serverURL, "FUZZ", v)

		req, err := http.NewRequest(*httpMethod, newURL, nil)
		if err != nil {
			ErrorLog.Printf("Failed to create HTTP request: %s\n", err)
			os.Exit(ERR_CREATE_HTTP_REQ)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			ErrorLog.Printf("Failed to send HTTP request: %s\n", err)
			os.Exit(ERR_SEND_HTTP_REQ)
		}

		numChars := -1
		numLines := -1
		foundMatch := false
		if *excludeRegex != "" {
			foundMatch, numChars, numLines, err = searchRegex(*excludeRegex, resp.Body)
		} else {
			numChars, numLines, err = getStats(resp.Body)
		}

		if err != nil {
			ErrorLog.Printf("Error while analyzing HTTP response body. Error:\n\t%s\n", err)
		}

		showResp := true
		if *excludeSize == numChars {
			showResp = false
		}

		if *excludeLines == numLines {
			showResp = false
		}

		if foundMatch {
			showResp = false
		}

		if showResp {
			fmt.Printf("%s\t\t\t%d\t%d\n", v, numChars, numLines)
		}
	}
}
