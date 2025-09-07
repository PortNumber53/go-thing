package utility

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

// IsUniqueViolation returns true when err is a Postgres unique constraint
// violation (SQLSTATE 23505). Use this helper from all call sites to
// avoid duplicating PG error handling logic across packages.
func IsUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}
