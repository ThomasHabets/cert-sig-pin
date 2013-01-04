/*
Copyright 2012 Google Inc. All Rights Reserved.

	Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"regexp"
)

func GetPEMFromHost(host string) string {
	var buf bytes.Buffer
	command := exec.Command("openssl", "s_client", "-connect", host)
	command.Stdin = nil
	command.Stdout = &buf
	err := command.Run()
	if err != nil {
		fmt.Println("Exit status != 0 for " + host + ", may not work")
	}
	return buf.String()
}

func GetPEM(from string) string {
	re := regexp.MustCompile("^[a-zA-Z0-9.-]+:[0-9]+$")

	if re.MatchString(from) {
		return GetPEMFromHost(from)
	}

	pemBytes, err := ioutil.ReadFile(from)
	if err != nil {
		log.Fatal(err)
	}
	return string(pemBytes)
}

func GetDigest(host string) (digest string) {
	pemBytes := GetPEM(host)
	block, _ := pem.Decode([]uint8(pemBytes))
	if block == nil {
		panic("Unable to decode PEM")
	}
	derBytes := block.Bytes
	certs, err := x509.ParseCertificates(derBytes)
	if err != nil {
		log.Fatal(err)
	}
	cert := certs[0]
	h := sha1.New()
	h.Write(cert.RawSubjectPublicKeyInfo)

	return "sha1/" + base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <PEM filename | host:port>\n",
			os.Args[0])
		os.Exit(1)
	}
	for i := 1; i < len(os.Args); i++ {
		host := os.Args[i]
		fmt.Printf("%s %s\n", host, GetDigest(host))
	}
}
