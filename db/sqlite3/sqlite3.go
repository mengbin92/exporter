package sqlite3

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func InitDB(source string) (*gorm.DB, error) {
	return gorm.Open(sqlite.Open(source), &gorm.Config{SkipDefaultTransaction: true})
}
