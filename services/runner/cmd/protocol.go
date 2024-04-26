package cmd

type Request struct {
	Uuid    string
	Options map[string]string
	Script  string
}

type Response struct {
	Uuid   string
	Result string
}
