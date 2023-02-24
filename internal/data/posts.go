package data

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type Post struct {
	ID     int64     `json:"id"`
	Text   string    `json:"text"`
	UserID int       `json:"user_id"`
	Date   time.Time `json:"date"`
}

type PostModel struct {
	DB *sql.DB
}

func (m PostModel) Insert(post *Post) error {
	query := `
	INSERT INTO posts (user_id, text, date)
	VALUES ($1, $2,$3)
	RETURNING id`
	args := []any{post.UserID, post.Text, time.Now()}
	// If the table already contains a record with this email address, then when we try
	// to perform the insert there will be a violation of the UNIQUE "users_email_key"
	// constraint that we set up in the previous chapter. We check for this error
	// specifically, and return custom ErrDuplicateEmail error instead.
	err := m.DB.QueryRow(query, args...).Scan(&post.ID)
	if err != nil {
		return err
	}
	return nil
}

func (m PostModel) Get(id int64) (*Post, error) {
	if id < 1 {
		return nil, ErrRecordNotFound
	}

	query := `SELECT id, user_id, text, date
		FROM posts
		WHERE id = $1`

	var post Post

	err := m.DB.QueryRow(query, id).Scan(
		&post.ID,
		&post.UserID,
		&post.Text,
		&post.Date,
	)

	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, ErrRecordNotFound
		default:
			return nil, err
		}
	}

	return &post, nil
}

// Update the function signature to return a Metadata struct.
func (m PostModel) GetAll(user_id int) ([]*Post, error) {
	query := `
		SELECT id, text, date
		FROM posts
		WHERE user_id = $1`

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)

	defer cancel()

	rows, err := m.DB.QueryContext(ctx, query, user_id)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	posts := []*Post{}

	for rows.Next() {
		var post Post
		err := rows.Scan(
			&post.ID,
			&post.Text,
			&post.Date,
		)
		post.UserID = user_id
		if err != nil {
			return nil, err
		}
		posts = append(posts, &post)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}
	return posts, nil
}

func (m PostModel) Delete(id int64) error {
	if id < 1 {
		return ErrRecordNotFound
	}

	query := `DELETE FROM posts
		WHERE id = $1`

	result, err := m.DB.Exec(query, id)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrRecordNotFound
	}
	return nil
}
