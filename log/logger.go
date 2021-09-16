package log

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// DefaultLogger,stdout
func DefaultLogger() *zap.Logger {
	var coreArr []zapcore.Core

	//获取编码器
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout("2006-01-02 15:04:05") //指定时间格式
	encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder                  //按级别显示不同颜色
	encoderConfig.EncodeCaller = zapcore.FullCallerEncoder                        //显示完整文件路径
	encoder := zapcore.NewConsoleEncoder(encoderConfig)                           //NewJSONEncoder()输出json格式，NewConsoleEncoder()输出普通文本格式

	//日志级别
	highPriority := zap.LevelEnablerFunc(func(lev zapcore.Level) bool { //error级别
		return lev >= zap.ErrorLevel
	})
	lowPriority := zap.LevelEnablerFunc(func(lev zapcore.Level) bool { //info和debug级别,debug级别是最低的
		return lev < zap.ErrorLevel && lev >= zap.DebugLevel
	})

	infoCore := zapcore.NewCore(encoder, zapcore.NewMultiWriteSyncer(zapcore.AddSync(os.Stdout)), lowPriority)   //第三个及之后的参数为写入文件的日志级别,ErrorLevel模式只记录error级别的日志
	errorCore := zapcore.NewCore(encoder, zapcore.NewMultiWriteSyncer(zapcore.AddSync(os.Stdout)), highPriority) //第三个及之后的参数为写入文件的日志级别,ErrorLevel模式只记录error级别的日志

	coreArr = append(coreArr, infoCore)
	coreArr = append(coreArr, errorCore)
	return zap.New(zapcore.NewTee(coreArr...), zap.AddCaller())
}

// func NewLogger(infoConfig, errorConfig *models.LogConfig) (*zap.Logger, error) {
// 	if _, err := os.Stat(infoConfig.LogPath); os.IsNotExist(err) {
// 		if err := os.MkdirAll(infoConfig.LogPath, 0755); err != nil {
// 			return nil, err
// 		}
// 	}
// 	if _, err := os.Stat(errorConfig.LogPath); os.IsNotExist(err) {
// 		if err := os.MkdirAll(errorConfig.LogPath, 0755); err != nil {
// 			return nil, err
// 		}
// 	}

// 	var coreArr []zapcore.Core

// 	//获取编码器
// 	encoderConfig := zap.NewProductionEncoderConfig()
// 	encoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout("2006-01-02 15:04:05") //指定时间格式
// 	// encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder                  //按级别显示不同颜色
// 	encoderConfig.EncodeCaller = zapcore.FullCallerEncoder //显示完整文件路径
// 	encoder := zapcore.NewJSONEncoder(encoderConfig)       //NewJSONEncoder()输出json格式，NewConsoleEncoder()输出普通文本格式

// 	//日志级别
// 	highPriority := zap.LevelEnablerFunc(func(lev zapcore.Level) bool { //error级别
// 		return lev >= zap.ErrorLevel
// 	})
// 	lowPriority := zap.LevelEnablerFunc(func(lev zapcore.Level) bool { //info和debug级别,debug级别是最低的
// 		return lev < zap.ErrorLevel && lev >= zap.DebugLevel
// 	})

// 	//info文件writeSyncer
// 	infoFileWriteSyncer := zapcore.AddSync(&lumberjack.Logger{
// 		Filename:   path.Join(infoConfig.LogPath, "info.log"), //日志文件存放目录，如果文件夹不存在会自动创建
// 		MaxSize:    infoConfig.MaxSize,                        //文件大小限制,单位MB，默认大小 100M
// 		MaxBackups: infoConfig.MaxBackups,                     //最大保留日志文件数量，默认永久保留
// 		MaxAge:     infoConfig.MaxAge,                         //日志文件保留天数，默认永久保留
// 		Compress:   false,                                     //是否压缩处理
// 	})
// 	infoFileCore := zapcore.NewCore(encoder, zapcore.NewMultiWriteSyncer(infoFileWriteSyncer, zapcore.AddSync(os.Stdout)), lowPriority) //第三个及之后的参数为写入文件的日志级别,ErrorLevel模式只记录error级别的日志
// 	//error文件writeSyncer
// 	errorFileWriteSyncer := zapcore.AddSync(&lumberjack.Logger{
// 		Filename:   path.Join(errorConfig.LogPath, "error.log"), //日志文件存放目录
// 		MaxSize:    errorConfig.MaxSize,                         //文件大小限制,单位MB，默认大小 100M
// 		MaxBackups: errorConfig.MaxBackups,                      //最大保留日志文件数量，默认永久保留
// 		MaxAge:     errorConfig.MaxAge,                          //日志文件保留天数
// 		Compress:   false,                                       //是否压缩处理
// 	})
// 	errorFileCore := zapcore.NewCore(encoder, zapcore.NewMultiWriteSyncer(errorFileWriteSyncer, zapcore.AddSync(os.Stdout)), highPriority) //第三个及之后的参数为写入文件的日志级别,ErrorLevel模式只记录error级别的日志

// 	coreArr = append(coreArr, infoFileCore)
// 	coreArr = append(coreArr, errorFileCore)
// 	log := zap.New(zapcore.NewTee(coreArr...), zap.AddCaller()) //zap.AddCaller()为显示文件名和行号，可省略

// 	return log, nil
// }
