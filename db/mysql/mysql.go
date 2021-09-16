package mysql

import (
	"gorm.io/driver/mysql"

	"gorm.io/gorm"
)

func InitDB(source string) (*gorm.DB, error) {
	return gorm.Open(mysql.Open(source), &gorm.Config{
		SkipDefaultTransaction:                   true,
		AllowGlobalUpdate:                        false,
		DisableForeignKeyConstraintWhenMigrating: true,
	})
}
