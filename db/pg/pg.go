package pg

import (
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func InitDB(source string) (*gorm.DB, error) {
	return gorm.Open(postgres.Open(source), &gorm.Config{SkipDefaultTransaction: true})
}
