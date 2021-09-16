package db

import (
	"sync"

	"github.com/monstermeng92/exporter/db/mysql"
	"github.com/monstermeng92/exporter/db/pg"
	"github.com/monstermeng92/exporter/db/sqlite3"
	"gorm.io/gorm"
)

var (
	gdb      *gorm.DB
	initOnce sync.Once
)

type DBType uint

const (
	MySQL DBType = iota
	PostgreSQL
	Sqlite
)

// Init inits the database connection only once
func Init(dbType DBType, source string) error {
	var err error

	initOnce.Do(func() {
		switch dbType {
		case PostgreSQL:
			gdb, err = pg.InitDB(source)
		case Sqlite:
			gdb, err = sqlite3.InitDB(source)
		default:
			gdb, err = mysql.InitDB(source) // MySQL is default
		}
	})
	return err
}

func Get() *gorm.DB {
	if gdb == nil {
		panic("db is nil")
	}
	return gdb
}
