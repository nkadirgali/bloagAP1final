package data

import (
	"database/sql"
	"fmt"
	"strings"
)

type Role struct {
	ID        int64  `json:"id"`
	Role_Name string `json:"role_name"`
	UserID    int    `json:"user_id"`
}

type RoleModel struct {
	DB *sql.DB
}

func (m RoleModel) Insert(role *Role) error {
	query := `
	INSERT INTO roles (role_name, user_id)
	VALUES ($1, $2)
	RETURNING id`
	args := []any{role.Role_Name, role.UserID}
	// If the table already contains a record with this email address, then when we try
	// to perform the insert there will be a violation of the UNIQUE "users_email_key"
	// constraint that we set up in the previous chapter. We check for this error
	// specifically, and return custom ErrDuplicateEmail error instead.
	err := m.DB.QueryRow(query, args...).Scan(&role.ID)
	if err != nil {
		return err
	}
	return nil
}

func (m RoleModel) GetByUserID(r *Role) bool {
	query := `
	select id, role_name from roles
	where user_id = $1`
	// args := []any{&r.UserID}
	// If the table already contains a record with this email address, then when we try
	// to perform the insert there will be a violation of the UNIQUE "users_email_key"
	// constraint that we set up in the previous chapter. We check for this error
	// specifically, and return custom ErrDuplicateEmail error instead.
	var role_name string
	err := m.DB.QueryRow(query, &r.UserID).Scan(&r.ID, &r.Role_Name)
	if err != nil {
		fmt.Printf("ERROR IS role name %s %d", err, r.UserID)
		return false
	}
	role_name = r.Role_Name
	//	fmt.Println("x ", role_name, " ", strings.EqualFold(role_name, "admin"), " x")
	if strings.EqualFold(role_name, "admin") {
		return true
	} else {
		return false
	}
}
