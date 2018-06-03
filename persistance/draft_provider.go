package persistance

import (
	"database/sql"

	"fmt"

	"github.com/community-announcer/announcer-service/model"
)

type DraftProvider interface {
	All() ([]model.Draft, error)
}

type PostgreSqlDraftProvider struct {
	db *sql.DB
}

func (p *PostgreSqlDraftProvider) All() ([]model.Draft, error) {
	query := "SELECT * FROM drafts"
	rows, err := p.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("Error reading drafts: %q", err)
	}
	defer rows.Close()
	drafts := []model.Draft{}
	for rows.Next() {
		var draft model.Draft
		if err := rows.Scan(&draft); err != nil {
			return nil, fmt.Errorf("Error scanning drafts: %q", err)
		}
		drafts = append(drafts, draft)
	}
	return drafts, nil
}
