package tools

import (
	"bytes"
	"context"
	"log/slog"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/vmihailenco/msgpack/v5"
	"redrecon/internal/config"
	"redrecon/pkg/types"
)

type Metasploit struct {
	client *http.Client // O client já tem timeout
	token  string
	logger *slog.Logger
}

type authReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string   `msgpack:"method"`
	Params   []string `msgpack:"params"`
}

type authRes struct {
	Result map[string]interface{} `msgpack:"result"`
}

// NewMetasploit conecta via MSGRPC (herda config.Cfg.Metasploit)
func NewMetasploit(ctx context.Context, logger *slog.Logger) (*Metasploit, error) {
	cfg := config.Cfg.Metasploit
	if !cfg.Enabled {
		return nil, fmt.Errorf("metasploit disabled")
	}
	timeout, _ := time.ParseDuration(cfg.Timeout)
	client := &http.Client{Timeout: timeout}

	req := authReq{Method: "auth.login", Params: []string{cfg.User, cfg.Pass}}
	b, _ := msgpack.Marshal(req)

	httpReq, err := http.NewRequestWithContext(ctx, "POST", cfg.Host, bytes.NewBuffer(b))
	if err != nil {
		return nil, fmt.Errorf("failed to create metasploit auth request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "binary/message-pack")

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var res authRes
	msgpack.NewDecoder(resp.Body).Decode(&res)

	var token string
	if t, ok := res.Result["token"].(string); ok && t != "" {
		token = t
	} else {
		return nil, fmt.Errorf("auth failed")
	}
	logger.Info("MSF connected", "host", cfg.Host)
	return &Metasploit{client: client, token: token, logger: logger}, nil
}

// Close destrói o console do Metasploit para liberar recursos.
func (msf *Metasploit) Close() error {
	if msf == nil || msf.token == "" {
		return nil
	}
	// O comando para destruir o console é 'console.destroy'
	_, err := msf.executeCmd(context.Background(), fmt.Sprintf("console.destroy %s", msf.token))
	return err
}

// RunExploit executa módulo MSF (paraleliza set/run; retry resiliente)
func (msf *Metasploit) RunExploit(host string, module string, options map[string]string) (types.URLFindings, error) {
	ctx, cancel := context.WithTimeout(context.Background(), parseDuration(config.Cfg.Metasploit.Timeout))
	defer cancel()

	// 1. Decide módulo por tech (inteligência)
	if module == "" {
		module = decideMSFModule(options["tech"]) // Chama pkg/ai ou map config
	}

	// 2. Comandos: use, set (herda WAF: RHOSTS com proxy se stealth)
	commands := []string{fmt.Sprintf("use %s", module)}
	options["RHOSTS"] = host
	if config.Cfg.Engine.WAF.Enabled {
		options["Proxy"] = config.Cfg.Engine.WAF.Profiles[config.Cfg.Engine.WAF.DefaultProfile].Proxy
	}
	for k, v := range options {
		commands = append(commands, fmt.Sprintf("set %s %s", k, v))
	}
	commands = append(commands, "run")

	// 3. Paralelize comandos (goroutines por cmd)
	var wg sync.WaitGroup
	outputs := make(chan string, len(commands))
	for _, cmd := range commands {
		wg.Add(1)
		go func(c string) {
			defer wg.Done()
			out, err := msf.executeCmd(ctx, c)
			if err != nil {
				msf.logger.Warn("MSF partial fail", "cmd", c, "err", err)
				out = fmt.Sprintf("[ERR] %v", err)
			}
			outputs <- out
		}(cmd)
	}
	wg.Wait()
	close(outputs)

	// 4. Agrega output + parsed
	var fullOut string
	for out := range outputs {
		fullOut += out + "\n"
	}

	// Adapta a saída para a estrutura de 'Finding' existente.
	// Tratamos o resultado do exploit como um achado de "segredo" para fins de relatório.
	exploitFinding := types.Finding{
		Pattern: fmt.Sprintf("Metasploit Exploit: %s", module),
		Matches: map[string]int{strings.TrimSpace(fullOut): 1},
	}

	urlFinding := types.URLFindings{
		URL:     host,
		Secrets: []types.Finding{exploitFinding},
	}
	return urlFinding, nil
}

func (msf *Metasploit) executeCmd(ctx context.Context, cmd string) (string, error) {
	cfg := config.Cfg.Metasploit
	for i := 0; i < cfg.Retry; i++ {
		req := struct {
			_msgpack struct{} `msgpack:",asArray"`
			Method   string   `msgpack:"method"`
			Params   []interface{} `msgpack:"params"`
		}{Method: "console.write", Params: []interface{}{msf.token, cmd + "\n"}}
		b, _ := msgpack.Marshal(req)

		httpReq, err := http.NewRequestWithContext(ctx, "POST", cfg.Host, bytes.NewBuffer(b))
		if err != nil {
			return "", err
		}
		httpReq.Header.Set("Content-Type", "binary/message-pack")

		resp, err := msf.client.Do(httpReq)
		if err != nil {
			time.Sleep(time.Second * time.Duration(i+1)) // Backoff
			continue
		}
		defer resp.Body.Close()

		// Read output
		readReq := struct {
			_msgpack struct{} `msgpack:",asArray"`
			Method   string   `msgpack:"method"`
			Params   []string `msgpack:"params"`
		}{Method: "console.read", Params: []string{msf.token}}

		rb, _ := msgpack.Marshal(readReq)
		httpReadReq, rerr := http.NewRequestWithContext(ctx, "POST", cfg.Host, bytes.NewBuffer(rb))
		if rerr != nil {
			continue
		}
		httpReadReq.Header.Set("Content-Type", "binary/message-pack")

		rresp, rerr := msf.client.Do(httpReadReq)
		if rerr != nil {
			continue
		}
		defer rresp.Body.Close()

		var readRes struct{ Data string `msgpack:"data"` }
		msgpack.NewDecoder(rresp.Body).Decode(&readRes)
		return readRes.Data, nil
	}
	return "", fmt.Errorf("max retries exceeded")
}

func decideMSFModule(tech string) string {
	cfg := config.Cfg.Metasploit
	modules := cfg.Modules
	if m, ok := modules[tech]; ok {
		return m[0] // Primeiro match
	}
	return cfg.Modules["default"][0]
}

func parseDuration(s string) time.Duration {
	d, _ := time.ParseDuration(s)
	return d
}
