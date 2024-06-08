// 将docx文件进行精简
// 可以接受xml文件，也可以接受docx文件
// 返回精简后的主文档xml

package main

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

// Slimmer 精简器
type Slim struct {
}

func (Slim) MakeReader(url string) (*zip.ReadCloser, error) {
	// download file
	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
		resp, err := http.Get(url)
		if err != nil {
			log.Fatalf("error downloading file: %v", err)
			return nil, err
		}
		defer resp.Body.Close()

		reader, err := zip.NewReader(resp.Body.(io.ReaderAt), resp.ContentLength)
		if err != nil {
			log.Fatalf("error reading zip file: %v", err)
			return nil, err
		}

		return &zip.ReadCloser{Reader: *reader}, nil
	} else {
		// open file
		return zip.OpenReader(url)
	}
}

func (s Slim) Process(url string) (string, error) {
	// open or download file
	if url == "" {
		return "", errors.New("url is empty")
	}

	r, err := s.MakeReader(url)
	if err != nil {
		log.Fatal("error opening zip file: %v", err)
		return "", err
	}

	for _, f := range r.File {
		log.Printf("File: %s\n", f.Name)
		if f.Name == "word/document.xml" {
			rc, err := f.Open()
			if err != nil {
				log.Fatal("error opening file: %v", err)
				return "", err
			}
			defer rc.Close()
			contents, err := ioutil.ReadAll(rc)
			// process xml
			// slim xml
			// return slimed xml
			return string(contents), nil
		}
	}

	return "", nil
}

func main() {
	s := Slim{}
	f := "test.docx"
	if len(os.Args) > 1 {
		f = os.Args[1]
	}
	xml, err := s.Process(f)
	if err != nil {
		log.Fatalf("error processing file: %v", err)
	}
	fmt.Println(xml)
}
