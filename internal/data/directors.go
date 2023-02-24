package data

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"
)

type Director struct {
	ID      int64    `json:"id"`
	Name    string   `json:"name"`
	Surname string   `json:"surname"`
	Awards  []string `json:"awards,omitempty"`
}

// Define a MovieModel struct type which wraps a sql.DB connection pool.
type DirectorModel struct {
	DB *sql.DB
}

// method for inserting a new record in the movies table.
func (d DirectorModel) Insert(director *Director) error {
	query := `
		INSERT INTO directors(name, surname, awards)
		VALUES ($1, $2, $3)
		RETURNING id`

	return d.DB.QueryRow(query, &director.Name, &director.Surname, pq.Array(&director.Awards)).Scan(&director.ID)
}

func (d DirectorModel) GetAll(name, surname string, awards []string, filters Filters) ([]*Director, Metadata, error) {
	query := fmt.Sprintf(`
		SELECT count(*) OVER(), id, name, surname, awards
		FROM directors
		WHERE (to_tsvector('simple', name) @@ plainto_tsquery('simple', $1) OR $1 = '')
		AND (to_tsvector('simple', surname) @@ plainto_tsquery('simple', $2) OR $2 = '')
		AND (awards @> $3 OR $3 = '{}')
		ORDER BY %s %s, id ASC
		LIMIT $4 OFFSET $5`, filters.sortColumn(), filters.sortDirection())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)

	defer cancel()

	args := []any{name, surname, pq.Array(awards), filters.limit(), filters.offset()}

	rows, err := d.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, Metadata{}, err // Update this to return an empty Metadata struct.
	}

	defer rows.Close()
	// Declare a totalRecords variable.
	totalRecords := 0

	directors := []*Director{}

	for rows.Next() {
		var director Director
		err := rows.Scan(
			&totalRecords, // Scan the count from the window function into totalRecords.
			&director.ID,
			&director.Name,
			&director.Surname,
			pq.Array(&director.Awards),
		)
		if err != nil {
			return nil, Metadata{}, err // Update this to return an empty Metadata struct.
		}
		directors = append(directors, &director)
	}

	if err = rows.Err(); err != nil {
		return nil, Metadata{}, err // Update this to return an empty Metadata struct.
	}
	// Generate a Metadata struct, passing in the total record count and pagination
	// parameters from the client.
	metadata := calculateMetadata(totalRecords, filters.Page, filters.PageSize)
	// Include the metadata struct when returning.
	return directors, metadata, nil
}
func (d DirectorModel) Get(id int64) (*Director, error) {
	if id < 1 {
		return nil, ErrRecordNotFound
	}

	query := `
		SELECT *
		FROM directors
		WHERE id = $1`

	var director Director

	err := d.DB.QueryRow(query, id).Scan(
		&director.ID,
		&director.Name,
		&director.Surname,
		pq.Array(&director.Awards),
	)

	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, ErrRecordNotFound
		default:
			return nil, err
		}
	}

	return &director, nil
}
