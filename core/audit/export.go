package audit

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
)

// ExportEvents encodes audit events in a supported portable format.
func ExportEvents(events []AuditEvent, format ExportFormat) (io.Reader, error) {
	var buf bytes.Buffer
	switch format {
	case ExportJSON:
		if err := json.NewEncoder(&buf).Encode(events); err != nil {
			return nil, fmt.Errorf("audit: encode JSON export: %w", err)
		}
	case ExportCSV:
		writer := csv.NewWriter(&buf)
		rows := [][]string{{"id", "type", "actor_id", "subject_id", "status", "message", "created_at"}}
		for _, event := range events {
			rows = append(rows, []string{
				event.ID, event.Type, event.ActorID, event.SubjectID, event.Status,
				event.Message, event.CreatedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
			})
		}
		if err := writer.WriteAll(rows); err != nil {
			return nil, fmt.Errorf("audit: encode CSV export: %w", err)
		}
	default:
		return nil, fmt.Errorf("audit: unsupported export format %q", format)
	}
	return bytes.NewReader(buf.Bytes()), nil
}
