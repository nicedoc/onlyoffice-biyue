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
	"time"

	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"github.com/go-resty/resty/v2"
	"github.com/nicedoc/onlyoffice-biyue/services/shared"
	"github.com/nicedoc/onlyoffice-biyue/services/shared/response"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/oauth2"
)

var ErrInvalidResponsePayload = errors.New("invalid response payload")
var ErrUnauthorized = errors.New("unauthorized")

type MinioClient struct {
	client      *resty.Client
	credentials *oauth2.Config
	logger      log.Logger
	s3Config    *shared.BiyueConfig
}

func NewMinioAuthClient(
	credentials *oauth2.Config,
	s3Config *shared.BiyueConfig,
	logger log.Logger,
) MinioClient {
	otelClient := otelhttp.DefaultClient
	otelClient.Transport = otelhttp.NewTransport(&http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second,
		ExpectContinueTimeout: 4 * time.Second,
	})

	return MinioClient{
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
	}
}

func (c MinioClient) GetUser(ctx context.Context, token string) (response.BiyueUserResponse, error) {
	url := c.s3Config.Biyue.ApiEndPoint + "/get/user"

	type UserResponse struct {
		Code int                        `json:"code"`
		User response.BiyueUserResponse `json:"data"`
	}
	var res UserResponse

	rsp, err := c.client.R().
		SetHeader("X-Token", token).
		SetResult(&res).
		Get(url)
	if err != nil {
		return res.User, err
	}

	// if http return 401 then we need to refresh token
	if rsp.StatusCode() == http.StatusUnauthorized {
		return res.User, ErrUnauthorized
	}

	c.logger.Debug("get user response: ", res, rsp)
	if res.User.UserID == "" {
		return res.User, ErrInvalidResponsePayload
	}

	return res.User, nil
}

type FileResponse struct {
	Code    int                        `json:"code"`
	File    response.BiyueFileResponse `json:"data"`
	Message string                     `json:"message"`
}

func (c MinioClient) GetFile(ctx context.Context, path, token string) (response.BiyueFileResponse, error) {
	var res FileResponse

	// TODO 中文文件名字处理
	//key, _ := url.QueryUnescape(path)
	rsp, err := c.client.R().
		SetHeader("X-Token", token).
		SetQueryParam("paper_uuid", path).
		SetResult(&res).
		Get(c.s3Config.Biyue.ApiEndPoint + "/get/file")

	c.logger.Debug("get file response: ", res, rsp)
	if err != nil {
		return res.File, err
	}

	return res.File, nil
}

func (c MinioClient) GetDownloadLink(ctx context.Context, path, token string) (response.BiyueDownloadResponse, error) {

	type DownloadResponse struct {
		Code     int                            `json:"code"`
		Download response.BiyueDownloadResponse `json:"data"`
	}

	var res DownloadResponse

	rsp, err := c.client.R().
		SetHeader("X-Token", token).
		SetQueryParam("paper_uuid", path).
		SetResult(&res).
		Get(c.s3Config.Biyue.ApiEndPoint + "/get/url")

	c.logger.Debug("presigned url: ", res, rsp)

	if err != nil {
		return res.Download, err
	}

	if res.Download.Link == "" {
		return res.Download, ErrInvalidResponsePayload
	}

	return res.Download, nil
}

func (c MinioClient) uploadFile(ctx context.Context, uuid, path, token, rev, mode string, file io.Reader) (response.BiyueFileResponse, error) {

	// otel trace

	var res FileResponse

	url := c.s3Config.Biyue.ApiEndPoint + "/upload"

	c.logger.Debugf("upload file: [%s], [%s], [%s]", path, token, rev)

	rsp, err := c.client.R().
		SetHeader("X-Token", token).
		SetFileReader("file", path, file).
		SetResult(&res).
		SetFormData(map[string]string{
			"paper_uuid":      uuid,
			"client_modified": time.Now().Format("2006-01-02 15:04:05"),
			"rev":             rev,
			"mode":            mode,
		}).Post(url)

	c.logger.Debug("upload file response: ", res, rsp)
	if err != nil {
		return res.File, err
	}

	if res.Code == 0 {
		return res.File, errors.New(res.Message)
	}

	return res.File, nil
}

func (c MinioClient) CreateFile(ctx context.Context, uuid, path, token, rev string, file io.Reader) (response.BiyueFileResponse, error) {
	return c.uploadFile(ctx, uuid, path, token, rev, "add", file)
}

func (c MinioClient) UploadFile(ctx context.Context, uuid, path, token, rev string, file io.Reader) (response.BiyueFileResponse, error) {
	return c.uploadFile(ctx, uuid, path, token, rev, "overwrite", file)
}

func (c MinioClient) SaveFileFromURL(ctx context.Context, path, url, token string) error {
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
