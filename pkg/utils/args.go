package utils

// ArgBuilder é um utilitário para construir listas de argumentos de linha de comando de forma segura.
type ArgBuilder struct {
	args []string
}

// NewArgBuilder cria uma nova instância de ArgBuilder.
func NewArgBuilder() *ArgBuilder {
	return &ArgBuilder{args: []string{}}
}

// AddFlagIf adiciona uma flag e seu valor somente se a condição for verdadeira.
// Ex: AddFlagIf(rate > 0, "--rate", fmt.Sprintf("%d", rate))
func (b *ArgBuilder) AddFlagIf(condition bool, flag, value string) *ArgBuilder {
	if condition {
		// Adiciona a flag apenas se não for vazia.
		if flag != "" {
			b.args = append(b.args, flag)
		}
		// Adiciona o valor apenas se não for uma string vazia.
		if value != "" {
			b.args = append(b.args, value)
		}
	}
	return b
}

// AddFlagIfNotEmpty adiciona uma flag e seu valor somente se o valor não for uma string vazia.
// Ex: AddFlagIfNotEmpty("--proxy", proxyURL)
func (b *ArgBuilder) AddFlagIfNotEmpty(flag, value string) *ArgBuilder {
	return b.AddFlagIf(value != "", flag, value)
}

// AddSlice adiciona uma slice de strings aos argumentos.
// Ex: AddSlice(config.ExtraArgs)
func (b *ArgBuilder) AddSlice(values []string) *ArgBuilder {
	b.args = append(b.args, values...)
	return b
}

// Build retorna a slice de argumentos final.
func (b *ArgBuilder) Build() []string {
	return b.args
}
