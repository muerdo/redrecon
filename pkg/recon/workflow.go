package recon

import "sync"

func RunWorkflow(state *reconState) error {
	// Atualizado para refletir a nova estrutura de etapas do recon.
	steps := []reconStep{
		stepRunPassiveEnum, // Etapa que executa subfinder, amass, etc.
		func(s *reconState) error { // Wrapper para a nova função bbot
			return stepRunBBot(s, nil, nil) // Usa módulos padrão do bbot
		},
		stepRunWebEnum,           // Katana
		stepRunMantra,            // Mantra
		stepRunSubdomainTakeover, // Subzy
		stepRunParamSpider,       // ParamSpider
		stepRunDalfox,            // Dalfox
		stepRunArjun,             // Arjun
		stepRunSqlmap,            // Sqlmap
		stepRunCVESearch,         // CVE Search
		stepRunEnum4linuxNG,      // Enum4linuxNG
		stepRunVulnTests,         // Expanded vulnerability tests
		stepRunPortScan,          // Naabu
	}

	var wg sync.WaitGroup
	errs := make(chan error, len(steps))

	for _, s := range steps {
		wg.Add(1)
		go func(step reconStep) {
			defer wg.Done()
			if err := step(state); err != nil {
				errs <- err
			}
		}(s)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		state.logger.Warn("Step error (continuando)", "err", err)
	}
	return nil
}