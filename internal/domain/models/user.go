package models

import "time"

type User struct {
	ID           uint64
	Email        string
	PasswordHash string
	Username     string
	Firstname    string
	LastName     string
	IsActive     bool
	CreatedAt    time.Time
}
