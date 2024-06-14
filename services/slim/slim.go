// 将docx文件进行精简
// 可以接受xml文件，也可以接受docx文件
// 返回精简后的主文档xml

package main

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/nbio/xml"
	//"encoding/xml"
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

func (s Slim) xmlNodeToJson(node *Node) (map[string]interface{}, error) {
	jsonObj := make(map[string]interface{})
	for _, attr := range node.Attrs {
		jsonObj[attr.Name.Local] = attr.Value
	}

	textContent := strings.TrimSpace(string(node.Content))
	if textContent != "" {
		jsonObj["_byT"] = textContent
	}

	if len(node.Children) > 0 {
		childrenList := []interface{}{}
		names := []string{}
		for _, child := range node.Children {
			childJSON, _ := s.xmlNodeToJson(child)

			if strings.HasSuffix(child.XMLName.Local, "Pr") {
				delete(childJSON, "_byN")
				jsonObj[child.XMLName.Local] = childJSON
			} else {
				childrenList = append(childrenList, childJSON)
				names = append(names, child.XMLName.Local)
			}
		}

		// 将子节点添加到json对象中
		switch len(childrenList) {
		case 0:
			break
		case 1:
			delete(childrenList[0].(map[string]interface{}), "_byN")
			jsonObj[names[0]] = childrenList[0]
		default:
			if strings.HasSuffix(node.XMLName.Local, "Pr") {
				for i, child := range childrenList {
					delete(child.(map[string]interface{}), "_byN")
					jsonObj[names[i]] = child
				}
			} else {
				jsonObj["_byC"] = childrenList
			}
		}
	}
	jsonObj["_byN"] = node.XMLName.Local

	return jsonObj, nil
}

type Node struct {
	XMLName  xml.Name
	Attrs    []xml.Attr `xml:",any,attr"`
	Content  []byte     `xml:",chardata"`
	Children []*Node    `xml:",any"`

	hash     uint64
	refCount int
	isCompat bool
}

func (node *Node) ComputeHash(dict map[uint64]*Node) uint64 {

	hash := fnv.New64a()
	for _, child := range node.Children {
		child.ComputeHash(dict)
		childHash := []byte(strconv.FormatUint(child.hash, 16)) // Convert child.hash to []byte
		hash.Write(childHash)
	}
	hash.Write(node.Content)
	for _, attr := range node.Attrs {
		hash.Write([]byte(attr.Name.Local))
		hash.Write([]byte(attr.Value))
	}

	hash.Write([]byte(node.XMLName.Local))

	node.hash = hash.Sum64()
	if exist, ok := dict[node.hash]; ok {
		exist.refCount++
		node.isCompat = true
		return node.hash
	}
	dict[node.hash] = node
	return node.hash
}

func (node *Node) Compact() error {
	if node.isCompat {
		refAttr := xml.Attr{
			Name:  xml.Name{Local: "hash"},
			Value: strconv.FormatUint(node.hash, 16),
		}
		node.Attrs = []xml.Attr{}
		node.Attrs = append(node.Attrs, refAttr)
		node.Content = []byte{}
		node.Children = []*Node{}

		fmt.Sprintf("COMPACTED: %s", node.XMLName.Local)

		return nil
	} else if node.refCount > 0 {
		refAttr := xml.Attr{
			Name:  xml.Name{Local: "hash"},
			Value: strconv.FormatUint(node.hash, 16),
		}
		node.Attrs = append(node.Attrs, refAttr)
	}

	for i := range node.Children {
		node.Children[i].Compact()
	}

	return nil
}

func (node *Node) Marshal() ([]byte, error) {
	return xml.Marshal(node)
}

// convert ooxml to json for slimming
// convert rule:
// 1. each xml element is a json object
// 2. each xml attribute is a json property
// 3. each xml text is a json property named "byTEXT"
// 4. each xml element with children is a json object with a property named "children"
// 5. each xml element with multiple children is a json array
// 6. each xml element with same name is a json array
func (s Slim) XmlToJson(xmlData io.ReadCloser) string {
	decoder := xml.NewDecoder(xmlData)
	var root Node
	if err := decoder.Decode(&root); err != nil {
		log.Fatalf("error decoding xml: %v", err)
		return ""
	}

	jsonObj, err := s.xmlNodeToJson(&root)
	jsonData, err := json.Marshal(jsonObj)
	if err != nil {
		log.Fatalf("error encoding json: %v", err)
		return ""
	}
	return string(jsonData)
}

func (s Slim) JsonToXml(json string) string {

	return json
}

func (s Slim) XmlRef(xmlData io.ReadCloser) string {
	var dict = make(map[uint64]*Node)
	decoder := xml.NewDecoder(xmlData)
	var root Node
	if err := decoder.Decode(&root); err != nil {
		log.Fatalf("error decoding xml: %v", err)
		return ""
	}

	root.ComputeHash(dict)
	root.Compact()
	xml, _ := root.Marshal()
	fmt.Println(string(xml))

	return ""
}

func main() {
	s := Slim{}
	f := "test.docx"
	if len(os.Args) > 1 {
		f = os.Args[1]
	}

	if strings.HasSuffix(f, ".docx") {
		xml, err := s.Process(f)
		if err != nil {
			log.Fatalf("error processing file: %v", err)
		}
		fmt.Println(xml)
	} else if strings.HasSuffix(f, ".xml") {
		xmlFile, err := os.Open(f)
		if err != nil {
			log.Fatalf("error reading file: %v", err)
		}
		// json := s.XmlToJson(xmlFile)
		// fmt.Println(json)
		s.XmlRef(xmlFile)
	} else {
		log.Fatalf("unsupported file type: %s", f)
	}

}
