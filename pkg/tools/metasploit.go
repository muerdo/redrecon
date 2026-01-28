package tools

import (
	"bytes"
	"context"
	"log/slog"
	"fmt"
	"net/http"
	"strings"
	"net/url"
	"time"

	"github.com/vmihailenco/msgpack/v5"
	"redrecon/internal/config"
	"redrecon/pkg/types"
)

type Metasploit struct {
	client *http.Client // O client já tem timeout
	token  string
	logger *slog.Logger
	msfURL *url.URL // Armazena a URL base do Metasploit parseada
}

type authReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string   `msgpack:"method"`
	Params   []string `msgpack:"params"`
}

type authRes struct {
	Result map[string]interface{} `msgpack:"result"`
}

func NewMetasploit(ctx context.Context, logger *slog.Logger) (*Metasploit, error) {
	cfg := config.Cfg.Metasploit
	if !cfg.Enabled {
		return nil, fmt.Errorf("metasploit is disabled in the configuration")
	}
	timeout, err := time.ParseDuration(cfg.Timeout)
	if err != nil {
		return nil, fmt.Errorf("invalid metasploit timeout duration: %w", err)
	}

	logger.Debug("Metasploit config host (raw from config)", "host", cfg.Host)
	metasploitHost := cfg.Host
	if !strings.HasPrefix(metasploitHost, "http://") && !strings.HasPrefix(metasploitHost, "https://") {
		metasploitHost = "http://" + metasploitHost
	}
	logger.Debug("Metasploit host after prefix check", "host", metasploitHost)

	parsedURL, err := url.Parse(metasploitHost)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Metasploit host URL: %w", err)
	}

	// Tenta autenticar no MSGRPC
	req := authReq{Method: "auth.login", Params: []string{cfg.User, cfg.Pass}}
	b, err := msgpack.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create metasploit auth request: %w", err)
	}
	client := &http.Client{Timeout: timeout}

	// CORREÇÃO: Usa a mesma lógica de reconstrução de URL da função executeCmd
	// para garantir que a URL de autenticação também seja sempre válida.
	fullAuthURL := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, parsedURL.Path)
	if parsedURL.Scheme == "" {
		fullAuthURL = "http://" + parsedURL.Host + parsedURL.Path
	}
	httpReq, err := http.NewRequestWithContext(ctx, "POST", fullAuthURL, bytes.NewBuffer(b))
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
	if err := msgpack.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("failed to decode metasploit auth response: %w", err)
	}

	var token string
	resultStatus, _ := res.Result["result"].(string)

	if resultStatus == "success" {
		t, ok := res.Result["token"].(string)
		if !ok || t == "" {
			return nil, fmt.Errorf("auth successful but no token received from metasploit")
		}
		token = t
	} else {
		return nil, fmt.Errorf("metasploit auth failed, status: '%s', response: %+v", resultStatus, res.Result)
	}
	logger.Info("MSF connected", "host", parsedURL.String())
	return &Metasploit{client: client, token: token, logger: logger, msfURL: parsedURL}, nil
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
	// TODO: Esta função está temporariamente desativada para resolver erros de compilação.
	msf.logger.Warn("Metasploit RunExploit is temporarily disabled.")
	return types.URLFindings{}, nil
	/*
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
	// Define o LHOST a partir da configuração para o handler do payload
	if config.Cfg.Metasploit.LHost != "" {
		options["LHOST"] = config.Cfg.Metasploit.LHost
	}
	if config.Cfg.Metasploit.LPort != "" {
		options["LPORT"] = config.Cfg.Metasploit.LPort
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
	exploitFinding := &types.MetasploitFinding{
		Tool:     "metasploit",
		Target:   host,
		Module:   module,
		Evidence: strings.TrimSpace(fullOut), // O resultado do exploit é a evidência.
		Severity: "critical", // Assume-se que um exploit bem-sucedido é crítico.
	}

	urlFinding := types.URLFindings{
		URL:     host,
		Secrets: []types.Finding{exploitFinding}, // Válido porque *MetasploitFinding implementa a interface Finding.
	}
	return urlFinding, nil
	*/
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

		// CORREÇÃO: Reconstrói a URL completa a partir das partes parseadas para garantir que o esquema (http://) esteja sempre presente.
		fullURL := fmt.Sprintf("%s://%s%s", msf.msfURL.Scheme, msf.msfURL.Host, msf.msfURL.Path)
		if msf.msfURL.Scheme == "" {
			fullURL = "http://" + msf.msfURL.Host + msf.msfURL.Path
		}

		httpReq, err := http.NewRequestWithContext(ctx, "POST", fullURL, bytes.NewBuffer(b))
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
		httpReadReq, rerr := http.NewRequestWithContext(ctx, "POST", fullURL, bytes.NewBuffer(rb)) // Reutiliza a fullURL corrigida
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
