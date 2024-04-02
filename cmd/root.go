package cmd

import (
	"encoding/json"
	"fmt"
	logger "github.com/alecthomas/log4go"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/spf13/cobra"
	"sitescan/internal/utils"
	"time"
)

type CommonOptions struct {
	Input     string
	InputFile string

	OutputFile string
	ResultFile string

	NoColor bool
	Debug   bool
}

var (
	commonOptions CommonOptions
	targets       []string
)

var rootCmd = &cobra.Command{
	Use:               "sitescan",
	Short:             "网站一体化信息收集工具 by yueji0j1anke",
	CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		commonOptions.configureOutput()

		if err := commonOptions.validateOptions(); err != nil {
			gologger.Fatal().Msgf("Program exiting: %v", err)
		}

		if err := commonOptions.configureOptions(); err != nil {
			gologger.Fatal().Msgf("Program exiting: %v", err)
		}

	},
}

func (o *CommonOptions) validateOptions() error {
	if o.Input == "" && o.InputFile == "" {
		return fmt.Errorf("no input provided")
	}
	if o.InputFile != "" && !utils.FileExists(o.InputFile) {
		return fmt.Errorf("file %v does not exist", o.InputFile)
	}

	return nil
}

func (o *CommonOptions) configureOutput() {
	if o.NoColor {
		gologger.DefaultLogger.SetFormatter(formatter.NewCLI(true))
	}
	if o.Debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	}
	gologger.DefaultLogger.SetWriter(utils.NewCLI(o.OutputFile))

}

func (o *CommonOptions) configureOptions() error {
	if o.Input != "" {
		targets = append(targets, o.Input)
	} else {
		lines, err := utils.ReadLines(o.InputFile)
		if err != nil {
			return err
		}
		targets = append(targets, lines...)
	}

	targets = utils.RemoveDuplicate(targets)

	opt, _ := json.Marshal(o)
	gologger.Debug().Msgf("commonOptions: %v", string(opt))
	//opt, _ = json.Marshal(config.Worker)
	//gologger.Debug().Msgf("Worker: %v", string(opt))

	return nil
}

func Execute() {
	rootCmd.PersistentFlags().StringVarP(&commonOptions.Input, "input", "i", "", "single input(example: -i 'xxx')")
	rootCmd.PersistentFlags().StringVarP(&commonOptions.InputFile, "input-file", "f", "", "inputs file(example: -f 'xxx.txt')")

	rootCmd.PersistentFlags().StringVar(&commonOptions.ResultFile, "result", "", "output file to write found results")
	rootCmd.PersistentFlags().StringVarP(&commonOptions.OutputFile, "output", "o", "result.txt", "output file to write log and results")

	rootCmd.PersistentFlags().BoolVar(&commonOptions.NoColor, "no-color", false, "disable colors in output")
	rootCmd.PersistentFlags().BoolVar(&commonOptions.Debug, "debug", false, "show debug output")

	start := time.Now()

	cobra.CheckErr(rootCmd.Execute())

	gologger.Info().Msgf("运行时间: %v", time.Since(start))

}

func InitLog(Logger logger.Logger, loggerFile string) {
	rotateStatus := false
	logger.NewConsoleLogWriter()
	log := logger.NewConsoleLogWriter()
	//可以定义输出格式
	//log.SetFormat("")
	Logger.AddFilter("stdout", logger.INFO, log)
	Logger.AddFilter("file", logger.DEBUG, logger.NewFileLogWriter(loggerFile, rotateStatus))

}
