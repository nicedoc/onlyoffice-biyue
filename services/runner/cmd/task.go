package cmd

import (
	"io"
	"net/http"

	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"github.com/hashicorp/go-uuid"
)

type TaskController struct {
	logger log.Logger
	runner *Runner
}

func NewTaskController(
	logger log.Logger,
	runner *Runner,
) TaskController {
	return TaskController{
		logger: logger,
		runner: runner,
	}
}

func (tc TaskController) BuildEnquePage() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			rw.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		err := r.ParseMultipartForm(10 << 20)
		if err != nil {
			tc.logger.Error("error parsing form", err)
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}

		// get the script from the form
		file, _, err := r.FormFile("file")
		if err != nil {
			tc.logger.Error("error getting file from form", err)
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}

		msg := Request{}
		b, err := io.ReadAll(file)
		msg.Script = string(b)
		msg.Uuid = r.FormValue("uuid")

		if msg.Uuid == "" {
			msg.Uuid, _ = uuid.GenerateUUID()
		}

		tc.runner.PublishMessage(msg)
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("{ \"uuid\": \"" + msg.Uuid + "\" }"))
		tc.logger.Debug("message published", msg.Uuid)
	}
}
