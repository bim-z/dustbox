package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"github.com/labstack/echo/v5"
)

func up(db *sql.DB, box *s3.Client) echo.HandlerFunc {
	return func(c *echo.Context) (err error) {
		var name string

		if err = c.Bind(name); err != nil {
			return
		}

		if _, err := box.HeadObject(c.Request().Context(), &s3.HeadObjectInput{
			Bucket: aws.String("main"),
			Key:    aws.String(fmt.Sprintf("chunks/%s", name)),
		}); err != nil {
			return echo.NewHTTPError(http.StatusConflict, "")
		}

		if _, err = sq.Insert("files").Columns("id", "name", "user_email", "current_version").Values(uuid.NewString(), name, current(c), 1).
			RunWith(db).ExecContext(c.Request().Context()); err != nil {
			return
		}

		sq.Insert("versions").Columns("id","version","file_id")

		return c.NoContent(http.StatusOK)
	}
}

func sign(db *sql.DB, pre *s3.PresignClient, bucket string) echo.HandlerFunc {
	return func(c *echo.Context) (err error) {
		var name string

		if err = c.Bind(name); err != nil {
			return
		}

		var id string
		if err = sq.Select("name").From("files").Where(sq.Eq{"name": name}).
			QueryRowContext(c.Request().Context()).Scan(id); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				presign, err := pre.PresignPutObject(context.TODO(), &s3.PutObjectInput{
					Bucket: aws.String(bucket),
					Key:    aws.String(fmt.Sprintf("chunks/%s", name)),
				}, func(opts *s3.PresignOptions) {
					opts.Expires = 15 * time.Minute
				})

				if err != nil {
					return err
				}

				return c.String(http.StatusOK, presign.URL)
			} else if !errors.Is(err, sql.ErrNoRows) {
				return echo.NewHTTPError(http.StatusNotAcceptable, "")
			}

			return
		}

		return
	}
}
