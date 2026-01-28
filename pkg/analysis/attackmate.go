package analysis

import (
    "encoding/json"
    "fmt"
    "os"
    "redrecon/pkg/types"
)

// amFinding representa a estrutura de um achado bruto do AttackMate.
type amFinding struct {
    ID       string `json:"id"`
    Target   string `json:"target"`
    Evidence string `json:"evidence"`
    Severity string `json:"severity"`
    // Adicione outros campos relevantes se o AttackMate os fornecer
}

// ParseAttackMate lê um arquivo JSON de resultados do AttackMate e o converte em uma fatia de types.Finding.
func ParseAttackMate(file string) ([]types.Finding, error) {
    data, err := os.ReadFile(file)
    if err != nil {
        return nil, fmt.Errorf("failed to read AttackMate output file %s: %w", file, err)
    }

    var raw []amFinding
    // AttackMate pode gerar um array de objetos JSON ou objetos separados por linha (NDJSON).
    // Para simplificar, tentamos decodificar como um array. Se falhar, podemos adicionar lógica para NDJSON.
    if err := json.Unmarshal(data, &raw); err != nil {
        // Se não for um array JSON, pode ser NDJSON.
        // Para este exemplo, vamos assumir que é um array.
        // Se o AttackMate gerar NDJSON, esta parte precisaria de um scanner de linha.
        return nil, fmt.Errorf("failed to unmarshal AttackMate JSON output: %w", err)
    }

    var out []types.Finding
    for _, f := range raw {
        finding := &types.AttackMateFinding{
            Tool:     "attackmate",
            Target:   f.Target,
            Evidence: f.Evidence,
            Severity: f.Severity,
        }
        out = append(out, finding)
    }
    return out, nil
}
