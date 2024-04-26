package cmd

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/config"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"github.com/gorilla/mux"
	"github.com/nicedoc/onlyoffice-biyue/services/gateway/web/embeddable"
	"golang.org/x/oauth2"

	shttp "github.com/ONLYOFFICE/onlyoffice-integration-adapters/service/http"

	//"log"

	"github.com/nsqio/go-nsq"
)

type Runner struct {
	nsqConfig *NsqAddrConfig
	logger    log.Logger
	consumer  *nsq.Consumer
	producer  *nsq.Producer

	running bool
}

func newRunner(nsqConfig *NsqAddrConfig, logger log.Logger) *Runner {
	return &Runner{
		nsqConfig: nsqConfig,
		logger:    logger,
	}
}

func BuildNewRunner(nsqConfig *NsqAddrConfig, logger log.Logger) (*Runner, error) {
	return newRunner(nsqConfig, logger), nil
}

func (r *Runner) HandleMessage(msg *nsq.Message) error {
	// handle the message
	//r.logger.Debug("message received", msg)

	var req Request
	err := json.Unmarshal(msg.Body, &req)
	if err != nil {
		// handle the error
		r.logger.Errorf("could not unmarshal the message: %w", err)
		return nil
	}

	r.logger.Debug("handle task", req.Uuid)
	return r.Execute(&req)

	return nil
}

func (r *Runner) Execute(req *Request) error {
	tmpScript, err := os.CreateTemp("./", "chrome-headless-script-*.js")
	if err != nil {
		r.logger.Error("error creating tmp file", err)
		return err
	}

	if req.Script == "" {
		r.logger.Error("empty script!!!")
		return nil
	}

	// write all data from file to tmpScriptName
	_, err = io.WriteString(tmpScript, req.Script)
	if err != nil {
		r.logger.Error("error copying file to tmp file", err)
		return err
	}

	tmpScriptName := tmpScript.Name()
	tmpScript.Close()
	defer os.Remove(tmpScriptName)

	// run an chrome headless instance
	var wg sync.WaitGroup
	wg.Add(1)
	errChan := make(chan error, 1)
	resultChan := make(chan string, 1)
	go func() {

		defer wg.Done()

		// record the time
		start := time.Now()
		defer func() {
			r.logger.Info("chrome headless instance finished", time.Since(start))
		}()

		// run the script
		cmd := exec.Command("node", tmpScriptName)

		// get the result
		output, err := cmd.Output()
		if err != nil {
			r.logger.Error("error running chrome headless instance", err, output)
			errChan <- err
			return
		}

		// send the result to the resultChan
		resultChan <- string(output)
	}()

	// wait for the goroutine to finish
	wg.Wait()

	response := Response{
		Uuid: req.Uuid,
	}

	// get the result from the resultChan
	select {
	case result := <-resultChan:
		// do something with the result
		r.logger.Info("chrome headless instance finished", result)
		response.Result = result
	case err := <-errChan:
		// handle the error
		r.logger.Error("error running chrome headless instance", err)
		return err
	}
	return nil
}

func (r *Runner) PublishMessage(request Request) {
	// publish a message
	body, err := json.Marshal(request)
	if err != nil {
		// handle the error
		r.logger.Errorf("could not marshal the message: %w", err)
		return
	}
	r.producer.Publish(r.nsqConfig.NsqTopic, body)
}

func (r *Runner) Shutdown(ctx context.Context) error {
	// shutdown the runner
	r.consumer.Stop()
	r.producer.Stop()

	r.consumer.DisconnectFromNSQLookupd(r.nsqConfig.NsqLookupDS)
	r.consumer = nil
	r.producer = nil
	return nil
}

func (r *Runner) Run() {
	// run the runner
	producer, err := nsq.NewProducer(r.nsqConfig.NsqAddress, nsq.NewConfig())
	if err != nil {
		// handle the error
		r.logger.Errorf("could not create a new producer: %w", err)
	}
	r.producer = producer
	// send an empty message to the queue to create a topic
	r.PublishMessage(Request{})
	r.logger.Debug("empty message sent")

	consumer, err := nsq.NewConsumer(r.nsqConfig.NsqTopic, r.nsqConfig.NsqChannel, nsq.NewConfig())
	if err != nil {
		// handle the error
		r.logger.Errorf("could not create a new consumer: %w", err)
	}

	consumer.AddHandler(r)

	err = consumer.ConnectToNSQLookupd(r.nsqConfig.NsqLookupDS)
	if err != nil {
		// handle the error
		r.logger.Errorf("could not connect to nsqlookupd: %w", err)
	}

	r.consumer = consumer
	r.producer = producer
	r.logger.Debug("runner started")
}

type GdriveHTTPService struct {
	mux            *mux.Router
	taskController TaskController
	credentials    *oauth2.Config
	corsConfig     *config.CORSConfig
	logger         log.Logger
}

// NewService initializes http server with options.
func BuildNewServer(
	taskController TaskController,
	corsConfig *config.CORSConfig,
	logger log.Logger,
) shttp.ServerEngine {
	service := GdriveHTTPService{
		mux:            mux.NewRouter(),
		taskController: taskController,
		corsConfig:     corsConfig,
		logger:         logger,
	}

	return service
}

func (s GdriveHTTPService) ApplyMiddleware(middlewares ...func(http.Handler) http.Handler) {
	for _, middleware := range middlewares {
		s.mux.Use(middleware)
	}
}

func (s GdriveHTTPService) NewHandler() interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request)
} {
	return s.InitializeServer()
}

func (s *GdriveHTTPService) InitializeServer() *mux.Router {
	s.InitializeRoutes()
	s.logger.Info("Server initialized", s.corsConfig)
	return s.mux
}

func (s *GdriveHTTPService) InitializeRoutes() {
	root := s.mux.NewRoute().PathPrefix("/").Subrouter()
	root.Handle("/enqueue", s.taskController.BuildEnquePage()).Methods(http.MethodPost)

	var staticFS = http.FS(embeddable.IconFiles)
	s.mux.NotFoundHandler = http.FileServer(staticFS)

	// Add Access-Control-Allow-Headers header
	// s.mux.Use(accessControlMiddleWare)
}
