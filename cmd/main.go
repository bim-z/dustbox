package main

import (
	"os"
	"os/user"
	"time"

	"github.com/minio/sio"
	"github.com/spf13/cobra"
	"github.com/zalando/go-keyring"
	"resty.dev/v3"
)

func main() {}

func up(rest *resty.Client) *cobra.Command {
	return &cobra.Command{
		Use:   "up [...name]",
		Args:  cobra.MinimumNArgs(1),
		Short: "",
		RunE: func(cmd *cobra.Command, names []string) (err error) {
			user, err := user.Current()
			if err != nil {
				return
			}

			secret, err := keyring.Get("dustbox", user.Name)
			if err != nil {
				return
			}

			for _, name := range names {
				go func() {
					file, err := os.Open(name)
					if err != nil {
						return
					}
					defer file.Close()

					if _, err = rest.R().SetTimeout(10 * time.Second).SetBody(file.Name()).Post(""); err != nil {
						return
					}

					encrypted, err := sio.EncryptReader(file, sio.Config{
						Key: []byte(secret),
					})

					if err != nil {
						return
					}

					if _, err = rest.R().SetTimeout(10 * time.Second).SetBody(encrypted).Put(""); err != nil {
						return
					}
				}()
			}

			return
		},
	}
}
