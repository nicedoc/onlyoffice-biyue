/**
 *
 * (c) Copyright Ascensio System SIA 2023
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"github.com/go-resty/resty/v2"
	"github.com/nicedoc/onlyoffice-biyue/services/shared"
	"github.com/nicedoc/onlyoffice-biyue/services/shared/response"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/oauth2"

	minio "github.com/minio/minio-go/v6"
)

var ErrInvalidResponsePayload = errors.New("invalid response payload")

type DropboxClient struct {
	client      *resty.Client
	s3client    *minio.Client
	credentials *oauth2.Config
	logger      log.Logger
	s3Config    *shared.S3Config
}

func NewDropboxAuthClient(
	credentials *oauth2.Config,
	s3Config *shared.S3Config,
	logger log.Logger,
) DropboxClient {
	otelClient := otelhttp.DefaultClient
	otelClient.Transport = otelhttp.NewTransport(&http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second,
		ExpectContinueTimeout: 4 * time.Second,
	})

	s3Client, _ := minio.New(s3Config.S3.Url, s3Config.S3.AccessKey, s3Config.S3.SecretKey, false)

	return DropboxClient{
		client: resty.NewWithClient(otelClient).
			SetRedirectPolicy(resty.RedirectPolicyFunc(func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			})).
			SetRetryCount(3).
			SetTimeout(10 * time.Second).
			SetRetryWaitTime(120 * time.Millisecond).
			SetRetryMaxWaitTime(900 * time.Millisecond).
			SetLogger(log.NewEmptyLogger()).
			AddRetryCondition(func(r *resty.Response, err error) bool {
				return r.StatusCode() == http.StatusTooManyRequests
			}),
		credentials: credentials,
		logger:      logger,
		s3Config:    s3Config,
		s3client:    s3Client,
	}
}

func (c DropboxClient) GetUser(ctx context.Context, token string) (response.BiyueUserResponse, error) {
	const url = "http://keycloak.localtest.me:8080/realms/biyue/protocol/openid-connect/userinfo?client_id=biyue&username=biyue"
	var res response.BiyueUserResponse
	if _, err := c.client.R().
		SetAuthToken(token).
		SetResult(&res).
		Get(url); err != nil {
		return res, err
	}

	if res.AccountID == "" {
		return res, ErrInvalidResponsePayload
	}

	return res, nil
}

func (c DropboxClient) GetFile(ctx context.Context, path, token string) (response.BiyueFileResponse, error) {
	var res response.BiyueFileResponse

	if c.s3client == nil {
		minioClient, err := minio.New(c.s3Config.S3.Url,
			c.s3Config.S3.AccessKey, c.s3Config.S3.SecretKey,
			false,
		)
		if err != nil {
			c.logger.Errorf("could not create minio client: %s, url=[%s]", err, c.s3Config.S3.Url)
			return res, err
		}

		c.s3client = minioClient
	}

	// TODO 中文文件名字处理
	key, _ := url.QueryUnescape(path)

	info, err := c.s3client.StatObject(c.s3Config.S3.Bucket, key, minio.StatObjectOptions{})
	if err != nil {
		c.logger.Debugf("could not get file stat info: [%s], path=[%s]", err, path)
		return res, err
	}

	c.logger.Debug("file meta info : ", info)
	res.ID = info.Key
	res.CModified = info.LastModified.String()
	res.SModified = info.LastModified.String()
	res.PathDisplay = "/" + c.s3Config.S3.Bucket + "/" + info.Key
	res.PathLower = res.PathDisplay
	res.Rev = ""
	res.Name = info.Key
	res.Size = int(info.Size)

	return res, nil
}

func (c DropboxClient) GetDownloadLink(ctx context.Context, path, token string) (response.BiyueDownloadResponse, error) {
	var res response.BiyueDownloadResponse

	if c.s3client == nil {
		minioClient, err := minio.New(c.s3Config.S3.Url,
			c.s3Config.S3.AccessKey, c.s3Config.S3.SecretKey,
			false,
		)
		if err != nil {
			return res, err
		}

		c.s3client = minioClient
	}

	expiresIn := time.Minute * 15
	objectName := path
	bucketName := c.s3Config.S3.Bucket
	reqParams := make(url.Values)
	presignedUrl, err := c.s3client.PresignedGetObject(bucketName, objectName, expiresIn, reqParams)
	if err != nil {
		return res, err
	}

	// TODO 暂时设置成public的bucket
	presignedUrl.RawQuery = ""
	res.Link = presignedUrl.String()

	c.logger.Debug("presigned url: ", res.Link)

	return res, nil
}

func (c DropboxClient) uploadFile(ctx context.Context, path, token, mode string, file io.Reader) (response.BiyueFileResponse, error) {
	var res response.BiyueFileResponse

	if c.s3client == nil {
		minioClient, err := minio.New(c.s3Config.S3.Url,
			c.s3Config.S3.AccessKey, c.s3Config.S3.SecretKey,
			false,
		)
		if err != nil {
			return res, err
		}

		c.s3client = minioClient
	}

	n, err := c.s3client.PutObject(c.s3Config.S3.Bucket, path, file, -1, minio.PutObjectOptions{})
	if err != nil {
		return res, err
	}

	// req, err := http.NewRequest("POST", "https://content.dropboxapi.com/2/files/upload", file)
	// if err != nil {
	// 	return res, fmt.Errorf("could not build a request: %w", err)
	// }

	// req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	// req.Header.Set("Content-Type", "application/octet-stream")
	// req.Header.Set("Dropbox-API-Arg", fmt.Sprintf("{\"autorename\":true,\"mode\":\"%s\",\"mute\":false,\"path\":\"%s\",\"strict_conflict\":false}", mode, path))
	// resp, err := otelhttp.DefaultClient.Do(req)
	// if err != nil {
	// 	return res, fmt.Errorf("could not send a request: %w", err)
	// }

	// defer resp.Body.Close()
	// if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
	// 	return res, fmt.Errorf("could not decode response: %w", err)
	// }

	// if res.ID == "" {
	// 	return res, ErrInvalidResponsePayload
	// }

	res.ID = path
	res.CModified = time.Now().String()
	res.SModified = time.Now().String()
	res.PathDisplay = "/" + c.s3Config.S3.Bucket + "/" + path
	res.PathLower = res.PathDisplay
	res.Rev = ""
	res.Name = path
	res.Size = int(n)

	return res, nil
}

func (c DropboxClient) CreateFile(ctx context.Context, path, token string, file io.Reader) (response.BiyueFileResponse, error) {
	return c.uploadFile(ctx, path, token, "add", file)
}

func (c DropboxClient) UploadFile(ctx context.Context, path, token string, file io.Reader) (response.BiyueFileResponse, error) {
	return c.uploadFile(ctx, path, token, "overwrite", file)
}

func (c DropboxClient) SaveFileFromURL(ctx context.Context, path, url, token string) error {
	if _, err := c.client.R().
		SetBody(map[string]string{
			"path": path,
			"url":  url,
		}).
		SetAuthToken(token).
		Post("https://api.dropboxapi.com/2/files/save_url"); err != nil {
		return fmt.Errorf("could not save dropbox file from url: %w", err)
	}

	return nil
}
